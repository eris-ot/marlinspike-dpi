//! OPC Classic (DA / HDA / AE) decoder.
//!
//! Layers OPC-specific semantics on top of the DCE/RPC BIND and ALTER_CONTEXT
//! PDU shapes. When a BIND carried on TCP/135 contains at least one recognized
//! OPC Classic interface UUID, this decoder emits:
//!   - A `ProtocolTransaction` annotating the OPC family and interface names.
//!   - An `AssetObservation` for the destination (server-side) IP.
//!   - A `ParseAnomaly` (severity="low") for a malformed p_context_elem list.
//!
//! If the BIND carries no OPC UUID no event is emitted; the generic DCE/RPC
//! decoder handles that case.
//!
//! # Scope limitation
//!
//! OPC Classic typically uses the endpoint mapper on TCP/135 only briefly, then
//! moves to dynamic high ports negotiated via EPM responses. This decoder only
//! catches BINDs that happen on TCP/135 itself. Tracking EPM-negotiated dynamic
//! ports is future work.
//!
//! # UUID mixed-endian encoding
//!
//! DCE/RPC UUID wire layout (MS-RPCE §2.2.2.10) on a little-endian host:
//!   Data1:  4 bytes little-endian u32 — bytes must be byte-swapped to recover
//!           the canonical big-endian printed form (e.g. `39c13a4d`).
//!   Data2:  2 bytes little-endian u16 — same swap needed.
//!   Data3:  2 bytes little-endian u16 — same swap needed.
//!   Data4:  8 bytes verbatim (big-endian / opaque byte array — no swap).
//!
//! Wire example for IOPCServer (`39c13a4d-011e-11d0-9675-0020afd8adb3`):
//!   4D 3A C1 39 | 1E 01 | D0 11 | 96 75 00 20 AF D8 AD B3

use std::collections::{BTreeMap, HashSet};
use chrono::{DateTime, Utc};
use crate::bronze::{
    AssetObservation, BronzeEvent, BronzeEventFamily, EventEnvelope, ProtocolTransaction,
    TransportProtocol,
};
use crate::engine::{
    build_envelope, new_event, parse_anomaly_event, DecoderInterest, SessionDecoder, StreamChunk,
};

// ── DCE/RPC constants (intentionally duplicated — keeps this decoder
//    self-contained without importing private items from dcerpc.rs) ───────────
const HDR_LEN: usize = 16;
const PTYPE_BIND: u8 = 0x0B;
const PTYPE_ALTER_CONTEXT: u8 = 0x0E;

// ── OPC Classic interface table ───────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum OpcFamily { Da, Hda, Ae }

struct OpcIface { uuid: &'static str, name: &'static str, family: OpcFamily }

static OPC_INTERFACES: &[OpcIface] = &[
    // OPC DA (Data Access)
    OpcIface { uuid: "39c13a4d-011e-11d0-9675-0020afd8adb3", name: "IOPCServer",                   family: OpcFamily::Da },
    OpcIface { uuid: "39c13a4e-011e-11d0-9675-0020afd8adb3", name: "IOPCServerPublicGroups",       family: OpcFamily::Da },
    OpcIface { uuid: "39c13a4f-011e-11d0-9675-0020afd8adb3", name: "IOPCBrowseServerAddressSpace", family: OpcFamily::Da },
    OpcIface { uuid: "39c13a50-011e-11d0-9675-0020afd8adb3", name: "IOPCGroupStateMgt",            family: OpcFamily::Da },
    OpcIface { uuid: "39c13a51-011e-11d0-9675-0020afd8adb3", name: "IOPCPublicGroupStateMgt",      family: OpcFamily::Da },
    OpcIface { uuid: "39c13a52-011e-11d0-9675-0020afd8adb3", name: "IOPCSyncIO",                   family: OpcFamily::Da },
    OpcIface { uuid: "39c13a53-011e-11d0-9675-0020afd8adb3", name: "IOPCAsyncIO",                  family: OpcFamily::Da },
    OpcIface { uuid: "39c13a54-011e-11d0-9675-0020afd8adb3", name: "IOPCItemMgt",                  family: OpcFamily::Da },
    OpcIface { uuid: "39c13a55-011e-11d0-9675-0020afd8adb3", name: "IEnumOPCItemAttributes",       family: OpcFamily::Da },
    OpcIface { uuid: "39c13a70-011e-11d0-9675-0020afd8adb3", name: "IOPCDataCallback",             family: OpcFamily::Da },
    OpcIface { uuid: "39c13a71-011e-11d0-9675-0020afd8adb3", name: "IOPCAsyncIO2",                 family: OpcFamily::Da },
    OpcIface { uuid: "39c13a72-011e-11d0-9675-0020afd8adb3", name: "IOPCItemProperties",           family: OpcFamily::Da },
    // OPC HDA (Historical Data Access)
    OpcIface { uuid: "1f1217b1-deef-11d1-b04d-00c04fa31a86", name: "IOPCHDA_Server",               family: OpcFamily::Hda },
    OpcIface { uuid: "1f1217b2-deef-11d1-b04d-00c04fa31a86", name: "IOPCHDA_Browser",              family: OpcFamily::Hda },
    // OPC AE (Alarms & Events)
    OpcIface { uuid: "65168851-5783-11d1-84a0-00608cb8a7e9", name: "IOPCEventServer",              family: OpcFamily::Ae },
    OpcIface { uuid: "65168852-5783-11d1-84a0-00608cb8a7e9", name: "IOPCEventSubscriptionMgt",     family: OpcFamily::Ae },
];

fn resolve_opc(uuid: &str) -> Option<&'static OpcIface> {
    OPC_INTERFACES.iter().find(|i| i.uuid == uuid)
}

// ── DCE/RPC PDU parsing ───────────────────────────────────────────────────────

struct Hdr { ptype: u8, le: bool, call_id: u32 }

fn parse_hdr(d: &[u8]) -> Option<Hdr> {
    if d.len() < HDR_LEN || d[0] != 5 { return None; }
    let le = (d[4] & 0x10) != 0;
    let call_id = if le { u32::from_le_bytes([d[12],d[13],d[14],d[15]]) }
                  else  { u32::from_be_bytes([d[12],d[13],d[14],d[15]]) };
    Some(Hdr { ptype: d[2], le, call_id })
}

/// Decode 16 on-wire bytes to canonical UUID string (little-endian PDU).
/// See module-level comment for the full mixed-endian convention.
fn decode_uuid_le(b: &[u8]) -> String {
    let d1 = u32::from_le_bytes([b[0],b[1],b[2],b[3]]);
    let d2 = u16::from_le_bytes([b[4],b[5]]);
    let d3 = u16::from_le_bytes([b[6],b[7]]);
    format!(
        "{d1:08x}-{d2:04x}-{d3:04x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        b[8], b[9], b[10], b[11], b[12], b[13], b[14], b[15]
    )
}

/// Walk the p_context_elem list from a BIND / ALTER_CONTEXT body.
///
/// Body layout (after the 16-byte common header):
///   +0  max_xmit_frag u16 | +2 max_recv_frag u16 | +4 assoc_group_id u32
///   +8  p_ctx_elem_cnt u8 | +9 reserved [3]
///   +12 p_context_elem[] each: p_cont_id u16, n_transfer_syn u8, reserved u8,
///       abstract_syntax uuid[16]+version u32,
///       transfer_syntax[] n_transfer_syn × (uuid[16]+version u32)
///
/// Returns `None` for hard truncation (body < 12 bytes after header).
/// Returns `Some((hits, truncated))` where `truncated` signals a soft overrun
/// mid-list (emit ParseAnomaly, but still report accumulated hits).
fn parse_bind_opc(d: &[u8], le: bool) -> Option<(Vec<&'static OpcIface>, bool)> {
    let b = d.get(HDR_LEN..)?;
    if b.len() < 12 { return None; }
    let n_ctx = b[8] as usize;
    let mut pos = 12usize;
    let mut hits: Vec<&'static OpcIface> = Vec::new();
    let mut truncated = false;
    for _ in 0..n_ctx {
        if b.len() < pos + 4 { truncated = true; break; }
        let n_syn = b[pos + 2] as usize;
        pos += 4;
        if b.len() < pos + 20 { truncated = true; break; }
        let uuid = if le { decode_uuid_le(&b[pos..pos+16]) } else {
            let raw = &b[pos..pos+16];
            format!(
                "{:08x}-{:04x}-{:04x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
                u32::from_be_bytes([raw[0],raw[1],raw[2],raw[3]]),
                u16::from_be_bytes([raw[4],raw[5]]),
                u16::from_be_bytes([raw[6],raw[7]]),
                raw[8],raw[9],raw[10],raw[11],raw[12],raw[13],raw[14],raw[15]
            )
        };
        if let Some(iface) = resolve_opc(&uuid) { hits.push(iface); }
        pos += 20 + n_syn * 20; // abstract syntax (already consumed) + transfer syntaxes
    }
    Some((hits, truncated))
}

// ── Decoder ──────────────────────────────────────────────────────────────────

#[derive(Default)]
pub(crate) struct OpcClassicDecoder;

impl SessionDecoder for OpcClassicDecoder {
    fn name(&self) -> &'static str { "opc_classic" }

    fn interest(&self) -> &'static [DecoderInterest] {
        &[DecoderInterest::TcpPort(135)]
    }

    fn on_stream_chunk(&mut self, chunk: &StreamChunk<'_>, out: &mut Vec<BronzeEvent>) {
        let d = chunk.payload;
        let hdr = match parse_hdr(d) {
            Some(h) => h,
            None => return, // not a valid DCE/RPC PDU — ignore silently
        };
        match hdr.ptype {
            PTYPE_BIND | PTYPE_ALTER_CONTEXT => {}
            _ => return,
        }
        let op = if hdr.ptype == PTYPE_BIND { "opc_classic_bind" } else { "opc_classic_alter_context" };

        match parse_bind_opc(d, hdr.le) {
            None => {
                out.push(anomaly(chunk, "low", "opc_classic: truncated BIND/ALTER_CONTEXT body"));
            }
            Some((hits, truncated)) => {
                if truncated {
                    out.push(anomaly(chunk, "low", "opc_classic: truncated p_context_elem list"));
                }
                if hits.is_empty() { return; } // no OPC UUID — DCE/RPC decoder handles this

                let has_da  = hits.iter().any(|i| i.family == OpcFamily::Da);
                let has_hda = hits.iter().any(|i| i.family == OpcFamily::Hda);
                let has_ae  = hits.iter().any(|i| i.family == OpcFamily::Ae);
                let mut families = Vec::new();
                if has_da  { families.push("da");  }
                if has_hda { families.push("hda"); }
                if has_ae  { families.push("ae");  }
                let opc_family = families.join(",");

                let mut seen = HashSet::new();
                let opc_interfaces = hits.iter()
                    .filter_map(|i| if seen.insert(i.name) { Some(i.name) } else { None })
                    .collect::<Vec<_>>()
                    .join(",");

                let mut attrs = BTreeMap::new();
                attrs.insert("opc_family".into(),     opc_family.clone());
                attrs.insert("opc_interfaces".into(), opc_interfaces.clone());
                attrs.insert("call_id".into(),         hdr.call_id.to_string());

                out.push(new_event(
                    chunk.capture_id.to_string(),
                    envelope(chunk),
                    BronzeEventFamily::ProtocolTransaction(ProtocolTransaction {
                        operation: op.to_string(),
                        status: "observed".to_string(),
                        request_summary: Some(format!(
                            "OPC BIND family=[{opc_family}] interfaces=[{opc_interfaces}]"
                        )),
                        response_summary: None,
                        object_refs: Vec::new(), values: Vec::new(),
                        attributes: attrs, modbus: None, protocol_fields: None,
                    }),
                ));

                // AssetObservation targeting the server (BIND destination)
                let server_ip = chunk.context.dst_ip.to_string();
                let mut ids = BTreeMap::new();
                ids.insert("ip".into(),           server_ip.clone());
                ids.insert("opc_families".into(), opc_family);
                out.push(new_event(
                    chunk.capture_id.to_string(),
                    envelope(chunk),
                    BronzeEventFamily::AssetObservation(AssetObservation {
                        asset_key: server_ip,
                        role: Some("opc_classic_server".to_string()),
                        vendor: None, model: None, firmware: None,
                        hostnames: Vec::new(),
                        protocols: vec!["opc_classic".into()],
                        identifiers: ids,
                    }),
                ));
            }
        }
    }

    fn on_idle_flush(&mut self, _timestamp: DateTime<Utc>, _out: &mut Vec<BronzeEvent>) {
        // Stateless — emit immediately on BIND observation; nothing to flush.
    }
}

// ── Event helpers ─────────────────────────────────────────────────────────────

fn envelope(chunk: &StreamChunk<'_>) -> EventEnvelope {
    build_envelope(&chunk.context, chunk.interface_id, chunk.frame_index,
        chunk.timestamp, chunk.segment_hash, TransportProtocol::Tcp,
        Some("opc_classic"), chunk.captured_len, chunk.session_key.clone())
}

fn anomaly(chunk: &StreamChunk<'_>, severity: &str, reason: &str) -> BronzeEvent {
    parse_anomaly_event(chunk.capture_id.to_string(), envelope(chunk),
        "opc_classic", severity, reason, chunk.payload)
}

// ── Self-registration ─────────────────────────────────────────────────────────

inventory::submit!(crate::engine::decoders::DecoderRegistration {
    name: "opc_classic",
    factory: || Box::new(OpcClassicDecoder::default()),
});

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};
    use chrono::Utc;
    use super::*;
    use crate::bronze::BronzeEventFamily;
    use crate::engine::StreamChunk;
    use crate::registry::PacketContext;

    fn ctx() -> PacketContext {
        PacketContext {
            src_mac: [0;6], dst_mac: [0;6],
            src_ip: IpAddr::V4(Ipv4Addr::new(10,0,0,1)),
            dst_ip: IpAddr::V4(Ipv4Addr::new(10,0,0,2)),
            src_port: 49152, dst_port: 135, vlan_id: None, timestamp: 0,
        }
    }

    fn mk<'a>(payload: &'a [u8], session: &'a str) -> StreamChunk<'a> {
        StreamChunk {
            capture_id: "t", segment_hash: "s", interface_id: 0, frame_index: 0,
            timestamp: Utc::now(), context: ctx(), ethertype: 0x0800, ip_proto: Some(6),
            llc: None, transport: TransportProtocol::Tcp,
            payload, session_key: session.to_string(), captured_len: payload.len() as u64,
        }
    }

    fn txns(ev: &[BronzeEvent]) -> Vec<&ProtocolTransaction> {
        ev.iter().filter_map(|e|
            if let BronzeEventFamily::ProtocolTransaction(ref t) = e.family { Some(t) } else { None }
        ).collect()
    }
    fn obs(ev: &[BronzeEvent]) -> Vec<&AssetObservation> {
        ev.iter().filter_map(|e|
            if let BronzeEventFamily::AssetObservation(ref a) = e.family { Some(a) } else { None }
        ).collect()
    }
    fn anoms(ev: &[BronzeEvent]) -> Vec<&crate::bronze::ParseAnomaly> {
        ev.iter().filter_map(|e|
            if let BronzeEventFamily::ParseAnomaly(ref a) = e.family { Some(a) } else { None }
        ).collect()
    }

    /// 16-byte LE DCE/RPC common header. rpc_vers=5, LE data representation.
    fn hdr(ptype: u8, call_id: u32) -> Vec<u8> {
        let mut v = vec![5, 0, ptype, 0x03, 0x10, 0, 0, 0, 0, 0, 0, 0];
        v.extend_from_slice(&call_id.to_le_bytes());
        v
    }

    /// Encode canonical UUID string to LE wire bytes.
    ///
    /// "d1d1d1d1-d2d2-d3d3-d4d4-d4d4d4d4d4d4" →
    ///   Data1 u32 LE | Data2 u16 LE | Data3 u16 LE | Data4[8] verbatim (BE)
    fn uuid_le(s: &str) -> [u8; 16] {
        let hex: String = s.chars().filter(|c| *c != '-').collect();
        let b: Vec<u8> = (0..16).map(|i| u8::from_str_radix(&hex[i*2..i*2+2], 16).unwrap()).collect();
        let mut out = [0u8; 16];
        out[0..4].copy_from_slice(&u32::from_be_bytes([b[0],b[1],b[2],b[3]]).to_le_bytes());
        out[4..6].copy_from_slice(&u16::from_be_bytes([b[4],b[5]]).to_le_bytes());
        out[6..8].copy_from_slice(&u16::from_be_bytes([b[6],b[7]]).to_le_bytes());
        out[8..16].copy_from_slice(&b[8..16]);
        out
    }

    const NDR_UUID: &str = "8a885d04-1ceb-11c9-9fe8-08002b104860";

    fn bind_pdu_multi(call_id: u32, iface_uuids: &[&str]) -> Vec<u8> {
        let ndr = uuid_le(NDR_UUID);
        let mut body: Vec<u8> = Vec::new();
        body.extend_from_slice(&4280u16.to_le_bytes()); // max_xmit_frag
        body.extend_from_slice(&4280u16.to_le_bytes()); // max_recv_frag
        body.extend_from_slice(&0u32.to_le_bytes());    // assoc_group_id
        body.push(iface_uuids.len() as u8);
        body.extend_from_slice(&[0,0,0]);               // reserved
        for (i, uuid) in iface_uuids.iter().enumerate() {
            body.extend_from_slice(&(i as u16).to_le_bytes()); // p_cont_id
            body.push(1); body.push(0);                         // n_transfer_syn, reserved
            body.extend_from_slice(&uuid_le(uuid));             // abstract syntax uuid
            body.extend_from_slice(&1u32.to_le_bytes());       // abstract version
            body.extend_from_slice(&ndr);                       // transfer syntax
            body.extend_from_slice(&2u32.to_le_bytes());       // transfer version
        }
        let mut pdu = hdr(PTYPE_BIND, call_id);
        pdu.extend_from_slice(&body);
        pdu
    }

    fn bind_pdu(call_id: u32, uuid: &str) -> Vec<u8> { bind_pdu_multi(call_id, &[uuid]) }

    // ── Test 1: BIND with IOPCServer → ProtocolTransaction op=opc_classic_bind,
    //           opc_family=da, opc_interfaces contains IOPCServer ─────────────
    #[test]
    fn bind_iopc_server_emits_da_transaction() {
        let mut dec = OpcClassicDecoder::default();
        let mut out = Vec::new();
        dec.on_stream_chunk(&mk(&bind_pdu(1, "39c13a4d-011e-11d0-9675-0020afd8adb3"), "s1"), &mut out);
        let txs = txns(&out);
        assert_eq!(txs.len(), 1);
        assert_eq!(txs[0].operation, "opc_classic_bind");
        assert_eq!(txs[0].status,    "observed");
        assert_eq!(txs[0].attributes["opc_family"], "da");
        assert!(txs[0].attributes["opc_interfaces"].contains("IOPCServer"));
        assert_eq!(txs[0].attributes["call_id"], "1");
    }

    // ── Test 2: BIND with IOPCAsyncIO2 → opc_interfaces contains IOPCAsyncIO2 ─
    #[test]
    fn bind_iopc_async_io2() {
        let mut dec = OpcClassicDecoder::default();
        let mut out = Vec::new();
        dec.on_stream_chunk(&mk(&bind_pdu(7, "39c13a71-011e-11d0-9675-0020afd8adb3"), "s2"), &mut out);
        let txs = txns(&out);
        assert_eq!(txs.len(), 1);
        assert!(txs[0].attributes["opc_interfaces"].contains("IOPCAsyncIO2"));
        assert_eq!(txs[0].attributes["opc_family"], "da");
    }

    // ── Test 3: BIND with IOPCHDA_Server → opc_family=hda ────────────────────
    #[test]
    fn bind_hda_server() {
        let mut dec = OpcClassicDecoder::default();
        let mut out = Vec::new();
        dec.on_stream_chunk(&mk(&bind_pdu(42, "1f1217b1-deef-11d1-b04d-00c04fa31a86"), "s3"), &mut out);
        let txs = txns(&out);
        assert_eq!(txs.len(), 1);
        assert_eq!(txs[0].attributes["opc_family"], "hda");
        assert!(txs[0].attributes["opc_interfaces"].contains("IOPCHDA_Server"));
    }

    // ── Test 4: BIND with DA + HDA → opc_family contains both ────────────────
    #[test]
    fn bind_mixed_da_hda() {
        let mut dec = OpcClassicDecoder::default();
        let mut out = Vec::new();
        let pdu = bind_pdu_multi(99, &[
            "39c13a4d-011e-11d0-9675-0020afd8adb3", // IOPCServer (DA)
            "1f1217b2-deef-11d1-b04d-00c04fa31a86", // IOPCHDA_Browser (HDA)
        ]);
        dec.on_stream_chunk(&mk(&pdu, "s4"), &mut out);
        let txs = txns(&out);
        assert_eq!(txs.len(), 1);
        let fam = &txs[0].attributes["opc_family"];
        assert!(fam.contains("da"),  "expected 'da' in opc_family, got: {fam}");
        assert!(fam.contains("hda"), "expected 'hda' in opc_family, got: {fam}");
        let ifaces = &txs[0].attributes["opc_interfaces"];
        assert!(ifaces.contains("IOPCServer"));
        assert!(ifaces.contains("IOPCHDA_Browser"));
    }

    // ── Test 5: BIND with non-OPC UUID (samr) → no event ─────────────────────
    #[test]
    fn bind_non_opc_uuid_no_event() {
        let mut dec = OpcClassicDecoder::default();
        let mut out = Vec::new();
        dec.on_stream_chunk(&mk(&bind_pdu(5, "12345778-1234-abcd-ef00-0123456789ac"), "s5"), &mut out);
        assert!(out.is_empty(), "non-OPC BIND must produce no events, got {}", out.len());
    }

    // ── Test 6: Truncated context list → ParseAnomaly severity=low ───────────
    #[test]
    fn bind_truncated_context_list_anomaly() {
        let mut dec = OpcClassicDecoder::default();
        let mut out = Vec::new();
        // n_ctx=2 but only one complete element provided — second is truncated
        let mut pdu = hdr(PTYPE_BIND, 3);
        pdu.extend_from_slice(&4280u16.to_le_bytes()); // max_xmit_frag
        pdu.extend_from_slice(&4280u16.to_le_bytes()); // max_recv_frag
        pdu.extend_from_slice(&0u32.to_le_bytes());    // assoc_group_id
        pdu.push(2); pdu.extend_from_slice(&[0,0,0]); // n_ctx=2 (lie), reserved
        // First element (IOPCServer — complete)
        pdu.extend_from_slice(&0u16.to_le_bytes());
        pdu.push(1); pdu.push(0);
        pdu.extend_from_slice(&uuid_le("39c13a4d-011e-11d0-9675-0020afd8adb3"));
        pdu.extend_from_slice(&1u32.to_le_bytes());
        pdu.extend_from_slice(&uuid_le(NDR_UUID));
        pdu.extend_from_slice(&2u32.to_le_bytes());
        // Second element: absent (truncated)
        dec.on_stream_chunk(&mk(&pdu, "s6"), &mut out);
        assert!(anoms(&out).iter().any(|a| a.severity == "low"), "expected low anomaly");
        // Partial parse should still emit a transaction for the valid first element
        let txs = txns(&out);
        assert_eq!(txs.len(), 1, "expected 1 transaction from partial parse");
        assert!(txs[0].attributes["opc_interfaces"].contains("IOPCServer"));
    }

    // ── Test 7: AssetObservation targets destination IP with correct role ──────
    #[test]
    fn bind_emits_asset_observation_for_server() {
        let mut dec = OpcClassicDecoder::default();
        let mut out = Vec::new();
        dec.on_stream_chunk(&mk(&bind_pdu(1, "39c13a4d-011e-11d0-9675-0020afd8adb3"), "s7"), &mut out);
        let observations = obs(&out);
        assert_eq!(observations.len(), 1);
        assert_eq!(observations[0].asset_key, "10.0.0.2");
        assert_eq!(observations[0].role.as_deref(), Some("opc_classic_server"));
        assert_eq!(observations[0].identifiers["opc_families"], "da");
    }
}
