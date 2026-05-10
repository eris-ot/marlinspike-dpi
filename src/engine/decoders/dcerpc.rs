//! DCE/RPC decoder (MS-RPCE / DCE 1.1).
//!
//! Decodes BIND/ALTER_CONTEXT and REQUEST PDUs over TCP, pairing each with its
//! ACK/response by call_id. Extracts interface UUIDs from p_context_elem arrays
//! and resolves them to well-known names (samr, lsarpc, srvsvc, winreg, …).

use std::collections::{BTreeMap, HashMap};
use chrono::{DateTime, Utc};
use crate::bronze::{
    AssetObservation, BronzeEvent, BronzeEventFamily, EventEnvelope, ProtocolTransaction,
    TransportProtocol,
};
use crate::engine::{
    build_envelope, new_event, parse_anomaly_event, DecoderInterest, SessionDecoder, StreamChunk,
};

const HDR_LEN: usize = 16;
const PTYPE_REQUEST: u8 = 0x00;
const PTYPE_RESPONSE: u8 = 0x02;
const PTYPE_FAULT: u8 = 0x03;
const PTYPE_BIND: u8 = 0x0B;
const PTYPE_BIND_ACK: u8 = 0x0C;
const PTYPE_BIND_NAK: u8 = 0x0D;
const PTYPE_ALTER_CONTEXT: u8 = 0x0E;
const PTYPE_ALTER_CONTEXT_RESP: u8 = 0x0F;

/// Well-known interface UUIDs → names (lowercase canonical 8-4-4-4-12).
static KNOWN: &[(&str, &str)] = &[
    ("12345778-1234-abcd-ef00-0123456789ac", "samr"),
    ("12345778-1234-abcd-ef00-0123456789ab", "lsarpc"),
    ("4b324fc8-1670-01d3-1278-5a47bf6ee188", "srvsvc"),
    ("338cd001-2244-31f1-aaaa-900038001003", "winreg"),
    ("1ff70682-0a51-30e8-076d-740be8cee98b", "atsvc"),
    ("82273fdc-e32a-18c3-3f78-827929dc23ea", "eventlog"),
    ("e1af8308-5d1f-11c9-91a4-08002b14a0fa", "epmapper"),
    ("367abb81-9844-35f1-ad32-98f038001003", "svcctl"),
    ("12345678-1234-abcd-ef00-0123456789ab", "winspool"),
    ("3919286a-b10c-11d0-9ba8-00c04fd92ef5", "drsuapi"),
    ("c681d488-d850-11d0-8c52-00c04fd90f7e", "efsrpc"),
];

/// Decode 16 on-wire bytes to canonical UUID string (little-endian PDU).
///
/// DCE/RPC UUID wire layout (MS-RPCE §2.2.2.10) when data representation is LE:
///   Data1: 4 bytes LE u32  — swap bytes to recover canonical value
///   Data2: 2 bytes LE u16  — swap bytes
///   Data3: 2 bytes LE u16  — swap bytes
///   Data4: 8 bytes big-endian verbatim (no swap; treated as opaque byte array)
///
/// Wire example — srvsvc:  C8 4F 32 4B | 70 16 | D3 01 | 12 78 5A 47 BF 6E E1 88
///   → d1=0x4b324fc8 d2=0x1670 d3=0x01d3 d4[0..]=12 78 5a 47 bf 6e e1 88
///   → "4b324fc8-1670-01d3-1278-5a47bf6ee188"
fn decode_uuid_le(b: &[u8]) -> String {
    let d1 = u32::from_le_bytes([b[0], b[1], b[2], b[3]]);
    let d2 = u16::from_le_bytes([b[4], b[5]]);
    let d3 = u16::from_le_bytes([b[6], b[7]]);
    format!(
        "{d1:08x}-{d2:04x}-{d3:04x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        b[8], b[9], b[10], b[11], b[12], b[13], b[14], b[15]
    )
}

fn resolve(uuid: &str) -> &str {
    KNOWN.iter().find(|(k, _)| *k == uuid).map_or(uuid, |(_, v)| v)
}

struct Hdr { ptype: u8, le: bool, call_id: u32 }

fn parse_hdr(d: &[u8]) -> Option<Hdr> {
    if d.len() < HDR_LEN || d[0] != 5 { return None; }
    let le = (d[4] & 0x10) != 0;
    let call_id = if le { u32::from_le_bytes([d[12],d[13],d[14],d[15]]) }
                  else  { u32::from_be_bytes([d[12],d[13],d[14],d[15]]) };
    Some(Hdr { ptype: d[2], le, call_id })
}

/// Parse BIND / ALTER_CONTEXT body (after the 16-byte common header).
///
/// Body layout:
///   +0  max_xmit_frag   u16
///   +2  max_recv_frag   u16
///   +4  assoc_group_id  u32
///   +8  p_ctx_elem_cnt  u8
///   +9  reserved        [3]
///   +12 p_context_elem[]  (variable)
///       each: p_cont_id u16, n_transfer_syn u8, reserved u8,
///             abstract_syntax uuid[16] + version u32,
///             transfer_syntax[] n_transfer_syn × (uuid[16] + version u32)
fn parse_bind(d: &[u8], le: bool) -> Option<(u16, u16, Vec<String>, bool)> {
    let b = d.get(HDR_LEN..)?;
    if b.len() < 12 { return None; }
    let (mx, mr) = if le {
        (u16::from_le_bytes([b[0],b[1]]), u16::from_le_bytes([b[2],b[3]]))
    } else {
        (u16::from_be_bytes([b[0],b[1]]), u16::from_be_bytes([b[2],b[3]]))
    };
    let n_ctx = b[8] as usize;
    let mut pos = 12usize;
    let mut names = Vec::new();
    let mut has_epm = false;
    for _ in 0..n_ctx {
        if b.len() < pos + 4 { break; }
        let n_syn = b[pos + 2] as usize;
        pos += 4;
        if b.len() < pos + 20 { break; }
        let raw = &b[pos..pos + 16];
        let uuid = if le { decode_uuid_le(raw) } else {
            format!(
                "{:08x}-{:04x}-{:04x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
                u32::from_be_bytes([raw[0],raw[1],raw[2],raw[3]]),
                u16::from_be_bytes([raw[4],raw[5]]),
                u16::from_be_bytes([raw[6],raw[7]]),
                raw[8],raw[9],raw[10],raw[11],raw[12],raw[13],raw[14],raw[15]
            )
        };
        let name = resolve(&uuid).to_string();
        if name == "epmapper" { has_epm = true; }
        names.push(name);
        pos += 20 + n_syn * 20; // skip abstract syntax (already consumed) + transfer syntaxes
    }
    Some((mx, mr, names, has_epm))
}

/// opnum lives at PDU offset 22: HDR(16) + alloc_hint(4) + p_cont_id(2).
fn parse_opnum(d: &[u8], le: bool) -> Option<u16> {
    if d.len() < 24 { return None; }
    Some(if le { u16::from_le_bytes([d[22],d[23]]) } else { u16::from_be_bytes([d[22],d[23]]) })
}

struct PendingBind {
    capture_id: String, envelope: EventEnvelope,
    op: &'static str, ifaces: Vec<String>,
    max_xmit: u16, max_recv: u16, call_id: u32, ts: DateTime<Utc>,
}

struct PendingReq {
    capture_id: String, envelope: EventEnvelope,
    call_id: u32, opnum: u16, ts: DateTime<Utc>,
}

#[derive(Default)]
pub(crate) struct DceRpcDecoder {
    binds: HashMap<(String, u32), PendingBind>,
    reqs:  HashMap<(String, u32), PendingReq>,
}

impl SessionDecoder for DceRpcDecoder {
    fn name(&self) -> &'static str { "dcerpc" }

    fn interest(&self) -> &'static [DecoderInterest] {
        &[DecoderInterest::TcpPort(135)]
    }

    fn on_stream_chunk(&mut self, chunk: &StreamChunk<'_>, out: &mut Vec<BronzeEvent>) {
        let d = chunk.payload;
        let hdr = match parse_hdr(d) {
            Some(h) => h,
            None => {
                out.push(anomaly(chunk, "medium", "dcerpc: truncated or invalid PDU header"));
                return;
            }
        };
        // Flag big-endian PDUs — uncommon in practice, worth visibility.
        if !hdr.le {
            out.push(anomaly(chunk, "medium", "dcerpc: big-endian data representation (unusual)"));
        }
        match hdr.ptype {
            PTYPE_BIND | PTYPE_ALTER_CONTEXT        => self.on_bind(chunk, &hdr, out),
            PTYPE_BIND_ACK | PTYPE_ALTER_CONTEXT_RESP => self.on_bind_ack(chunk, &hdr, out),
            PTYPE_BIND_NAK                          => self.on_bind_nak(chunk, &hdr, out),
            PTYPE_REQUEST                           => self.on_request(chunk, &hdr),
            PTYPE_RESPONSE                          => self.on_response(chunk, &hdr, out),
            PTYPE_FAULT                             => self.on_fault(chunk, &hdr, out),
            0x01 | 0x10 | 0x11                     => {} // PING, AUTH3, SHUTDOWN — ignore
            unknown => out.push(anomaly(chunk, "low",
                &format!("dcerpc: unknown PTYPE 0x{unknown:02x}"))),
        }
    }

    fn on_idle_flush(&mut self, timestamp: DateTime<Utc>, out: &mut Vec<BronzeEvent>) {
        let eb: Vec<_> = self.binds.iter()
            .filter(|(_, p)| (timestamp - p.ts).num_seconds() >= 0)
            .map(|(k, _)| k.clone()).collect();
        for k in eb {
            if let Some(p) = self.binds.remove(&k) {
                out.push(bind_txn(p.capture_id, p.envelope, p.op, &p.ifaces,
                    p.call_id, p.max_xmit, p.max_recv, "request_only"));
            }
        }
        let er: Vec<_> = self.reqs.iter()
            .filter(|(_, p)| (timestamp - p.ts).num_seconds() >= 0)
            .map(|(k, _)| k.clone()).collect();
        for k in er {
            if let Some(p) = self.reqs.remove(&k) {
                out.push(req_txn(p.capture_id, p.envelope, p.call_id, p.opnum, "request_only"));
            }
        }
    }
}

impl DceRpcDecoder {
    fn on_bind(&mut self, chunk: &StreamChunk<'_>, hdr: &Hdr, out: &mut Vec<BronzeEvent>) {
        let (mx, mr, ifaces, has_epm) = match parse_bind(chunk.payload, hdr.le) {
            Some(v) => v,
            None => { out.push(anomaly(chunk, "medium", "dcerpc: malformed BIND body")); return; }
        };
        if has_epm { out.push(asset_obs(chunk, "dcerpc_endpoint_mapper_client")); }
        let op = if hdr.ptype == PTYPE_BIND { "dcerpc_bind" } else { "dcerpc_alter_context" };
        self.binds.insert((chunk.session_key.clone(), hdr.call_id), PendingBind {
            capture_id: chunk.capture_id.to_string(), envelope: envelope(chunk),
            op, ifaces, max_xmit: mx, max_recv: mr, call_id: hdr.call_id, ts: chunk.timestamp,
        });
    }

    fn on_bind_ack(&mut self, chunk: &StreamChunk<'_>, hdr: &Hdr, out: &mut Vec<BronzeEvent>) {
        if let Some(p) = self.binds.remove(&(chunk.session_key.clone(), hdr.call_id)) {
            if p.ifaces.iter().any(|n| n == "epmapper") {
                out.push(asset_obs(chunk, "dcerpc_endpoint_mapper_server"));
            }
            let mut env = p.envelope.clone();
            env.bytes_count += chunk.payload.len() as u64;
            env.packet_count += 1;
            out.push(bind_txn(p.capture_id, env, p.op, &p.ifaces,
                p.call_id, p.max_xmit, p.max_recv, "ok"));
        }
    }

    fn on_bind_nak(&mut self, chunk: &StreamChunk<'_>, hdr: &Hdr, out: &mut Vec<BronzeEvent>) {
        if let Some(p) = self.binds.remove(&(chunk.session_key.clone(), hdr.call_id)) {
            let mut env = p.envelope.clone();
            env.bytes_count += chunk.payload.len() as u64;
            env.packet_count += 1;
            out.push(bind_txn(p.capture_id, env, p.op, &p.ifaces,
                p.call_id, p.max_xmit, p.max_recv, "failed"));
        }
    }

    fn on_request(&mut self, chunk: &StreamChunk<'_>, hdr: &Hdr) {
        let opnum = parse_opnum(chunk.payload, hdr.le).unwrap_or(0);
        self.reqs.insert((chunk.session_key.clone(), hdr.call_id), PendingReq {
            capture_id: chunk.capture_id.to_string(), envelope: envelope(chunk),
            call_id: hdr.call_id, opnum, ts: chunk.timestamp,
        });
    }

    fn on_response(&mut self, chunk: &StreamChunk<'_>, hdr: &Hdr, out: &mut Vec<BronzeEvent>) {
        self.complete_req(chunk, hdr, "ok", out);
    }

    fn on_fault(&mut self, chunk: &StreamChunk<'_>, hdr: &Hdr, out: &mut Vec<BronzeEvent>) {
        self.complete_req(chunk, hdr, "fault", out);
    }

    fn complete_req(
        &mut self, chunk: &StreamChunk<'_>, hdr: &Hdr, status: &str, out: &mut Vec<BronzeEvent>,
    ) {
        if let Some(p) = self.reqs.remove(&(chunk.session_key.clone(), hdr.call_id)) {
            let mut env = p.envelope.clone();
            env.bytes_count += chunk.payload.len() as u64;
            env.packet_count += 1;
            out.push(req_txn(p.capture_id, env, p.call_id, p.opnum, status));
        }
    }
}

// ── Event constructors ────────────────────────────────────────────────────────

fn envelope(chunk: &StreamChunk<'_>) -> EventEnvelope {
    build_envelope(&chunk.context, chunk.interface_id, chunk.frame_index,
        chunk.timestamp, chunk.segment_hash, TransportProtocol::Tcp,
        Some("dcerpc"), chunk.captured_len, chunk.session_key.clone())
}

fn anomaly(chunk: &StreamChunk<'_>, severity: &str, reason: &str) -> BronzeEvent {
    parse_anomaly_event(chunk.capture_id.to_string(), envelope(chunk),
        "dcerpc", severity, reason, chunk.payload)
}

fn bind_txn(
    capture_id: String, env: EventEnvelope, op: &str, ifaces: &[String],
    call_id: u32, max_xmit: u16, max_recv: u16, status: &str,
) -> BronzeEvent {
    let iface_str = ifaces.join(",");
    let mut attrs = BTreeMap::new();
    attrs.insert("interfaces".into(), iface_str.clone());
    attrs.insert("call_id".into(), call_id.to_string());
    attrs.insert("max_xmit_frag".into(), max_xmit.to_string());
    attrs.insert("max_recv_frag".into(), max_recv.to_string());
    new_event(capture_id, env, BronzeEventFamily::ProtocolTransaction(ProtocolTransaction {
        operation: op.to_string(), status: status.to_string(),
        request_summary: Some(format!("BIND interfaces=[{iface_str}]")),
        response_summary: None, object_refs: Vec::new(), values: Vec::new(),
        attributes: attrs, modbus: None, protocol_fields: None,
    }))
}

fn req_txn(
    capture_id: String, env: EventEnvelope, call_id: u32, opnum: u16, status: &str,
) -> BronzeEvent {
    let mut attrs = BTreeMap::new();
    attrs.insert("call_id".into(), call_id.to_string());
    attrs.insert("opnum".into(), opnum.to_string());
    new_event(capture_id, env, BronzeEventFamily::ProtocolTransaction(ProtocolTransaction {
        operation: "dcerpc_request".into(), status: status.to_string(),
        request_summary: None, response_summary: None,
        object_refs: Vec::new(), values: Vec::new(),
        attributes: attrs, modbus: None, protocol_fields: None,
    }))
}

fn asset_obs(chunk: &StreamChunk<'_>, role: &str) -> BronzeEvent {
    let ip = chunk.context.src_ip.to_string();
    let mut ids = BTreeMap::new();
    ids.insert("ip".into(), ip.clone());
    new_event(chunk.capture_id.to_string(), envelope(chunk),
        BronzeEventFamily::AssetObservation(AssetObservation {
            asset_key: ip, role: Some(role.to_string()),
            vendor: None, model: None, firmware: None,
            hostnames: Vec::new(), protocols: vec!["dcerpc".into()],
            identifiers: ids,
        }))
}

inventory::submit!(crate::engine::decoders::DecoderRegistration {
    name: "dcerpc",
    factory: || Box::new(DceRpcDecoder::default()),
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
            src_mac: [0; 6], dst_mac: [0; 6],
            src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            dst_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
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
        ev.iter().filter_map(|e| if let BronzeEventFamily::ProtocolTransaction(ref t) = e.family { Some(t) } else { None }).collect()
    }
    fn obs(ev: &[BronzeEvent]) -> Vec<&AssetObservation> {
        ev.iter().filter_map(|e| if let BronzeEventFamily::AssetObservation(ref a) = e.family { Some(a) } else { None }).collect()
    }
    fn anoms(ev: &[BronzeEvent]) -> Vec<&crate::bronze::ParseAnomaly> {
        ev.iter().filter_map(|e| if let BronzeEventFamily::ParseAnomaly(ref a) = e.family { Some(a) } else { None }).collect()
    }

    /// 16-byte LE common header (frag_length field left 0 — decoder doesn't validate it).
    fn hdr(ptype: u8, call_id: u32) -> Vec<u8> {
        let mut v = vec![5, 0, ptype, 0x03, 0x10, 0, 0, 0, 0, 0, 0, 0];
        v.extend_from_slice(&call_id.to_le_bytes());
        v
    }

    /// Encode canonical UUID string to LE wire bytes.
    ///
    /// canonical "d1d1d1d1-d2d2-d3d3-d4d4-d4d4d4d4d4d4" →
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

    fn bind_pdu(call_id: u32, iface: &str) -> Vec<u8> {
        let ndr = uuid_le("8a885d04-1ceb-11c9-9fe8-08002b104860"); // NDR 32-bit transfer syntax
        let mut body = Vec::new();
        body.extend_from_slice(&4280u16.to_le_bytes()); // max_xmit_frag
        body.extend_from_slice(&4280u16.to_le_bytes()); // max_recv_frag
        body.extend_from_slice(&0u32.to_le_bytes());    // assoc_group
        body.push(1); body.extend_from_slice(&[0,0,0]); // ctx count + reserved
        body.extend_from_slice(&0u16.to_le_bytes());    // p_cont_id
        body.push(1); body.push(0);                      // n_transfer_syn, reserved
        body.extend_from_slice(&uuid_le(iface));          // abstract syntax uuid
        body.extend_from_slice(&1u32.to_le_bytes());    // abstract syntax version
        body.extend_from_slice(&ndr);                    // transfer syntax uuid
        body.extend_from_slice(&2u32.to_le_bytes());    // transfer syntax version
        let mut pdu = hdr(PTYPE_BIND, call_id);
        pdu.extend_from_slice(&body);
        pdu
    }

    fn bare_pdu(ptype: u8, call_id: u32) -> Vec<u8> {
        let mut pdu = hdr(ptype, call_id);
        pdu.extend_from_slice(&[0u8; 20]);
        pdu
    }

    fn req_pdu(call_id: u32, opnum: u16) -> Vec<u8> {
        // alloc_hint(4) + p_cont_id(2) + opnum(2)
        let mut pdu = hdr(PTYPE_REQUEST, call_id);
        pdu.extend_from_slice(&0u32.to_le_bytes());
        pdu.extend_from_slice(&0u16.to_le_bytes());
        pdu.extend_from_slice(&opnum.to_le_bytes());
        pdu
    }

    /// 1. BIND with srvsvc — no transaction until BIND_ACK arrives.
    #[test]
    fn bind_alone_no_event() {
        let mut dec = DceRpcDecoder::default();
        let mut out = Vec::new();
        dec.on_stream_chunk(&mk(&bind_pdu(1, "4b324fc8-1670-01d3-1278-5a47bf6ee188"), "s1"), &mut out);
        assert!(txns(&out).is_empty(), "BIND alone must not emit a transaction");
    }

    /// 2. BIND + BIND_ACK → status="ok", interfaces="srvsvc".
    #[test]
    fn bind_ack_pairs_ok() {
        let mut dec = DceRpcDecoder::default();
        let mut out = Vec::new();
        dec.on_stream_chunk(&mk(&bind_pdu(42, "4b324fc8-1670-01d3-1278-5a47bf6ee188"), "s1"), &mut out);
        dec.on_stream_chunk(&mk(&bare_pdu(PTYPE_BIND_ACK, 42), "s1"), &mut out);
        let txs = txns(&out);
        assert_eq!(txs.len(), 1);
        assert_eq!(txs[0].operation, "dcerpc_bind");
        assert_eq!(txs[0].status, "ok");
        assert_eq!(txs[0].attributes["interfaces"], "srvsvc");
        assert_eq!(txs[0].attributes["call_id"], "42");
    }

    /// 3. BIND with samr → interface resolved to "samr".
    #[test]
    fn bind_samr_resolved() {
        let mut dec = DceRpcDecoder::default();
        let mut out = Vec::new();
        dec.on_stream_chunk(&mk(&bind_pdu(7, "12345778-1234-abcd-ef00-0123456789ac"), "s2"), &mut out);
        dec.on_stream_chunk(&mk(&bare_pdu(PTYPE_BIND_ACK, 7), "s2"), &mut out);
        assert!(txns(&out)[0].attributes["interfaces"].contains("samr"));
    }

    /// 4. REQUEST + RESPONSE → dcerpc_request, opnum=5, status="ok".
    #[test]
    fn request_response_ok() {
        let mut dec = DceRpcDecoder::default();
        let mut out = Vec::new();
        dec.on_stream_chunk(&mk(&req_pdu(99, 5), "s3"), &mut out);
        assert!(txns(&out).is_empty());
        dec.on_stream_chunk(&mk(&bare_pdu(PTYPE_RESPONSE, 99), "s3"), &mut out);
        let txs = txns(&out);
        assert_eq!(txs.len(), 1);
        assert_eq!(txs[0].operation, "dcerpc_request");
        assert_eq!(txs[0].status, "ok");
        assert_eq!(txs[0].attributes["opnum"], "5");
        assert_eq!(txs[0].attributes["call_id"], "99");
    }

    /// 5. BIND with epmapper → AssetObservation role="dcerpc_endpoint_mapper_client".
    #[test]
    fn epmapper_bind_asset_obs() {
        let mut dec = DceRpcDecoder::default();
        let mut out = Vec::new();
        dec.on_stream_chunk(&mk(&bind_pdu(3, "e1af8308-5d1f-11c9-91a4-08002b14a0fa"), "s4"), &mut out);
        let os = obs(&out);
        assert_eq!(os.len(), 1);
        assert_eq!(os[0].role.as_deref(), Some("dcerpc_endpoint_mapper_client"));
    }

    /// 6. Unknown PTYPE 0x42 → ParseAnomaly severity="low".
    #[test]
    fn unknown_ptype_low_anomaly() {
        let mut dec = DceRpcDecoder::default();
        let mut out = Vec::new();
        dec.on_stream_chunk(&mk(&hdr(0x42, 1), "s5"), &mut out);
        let a = anoms(&out);
        assert!(!a.is_empty());
        assert!(a.iter().any(|x| x.severity == "low"), "expected 'low' anomaly");
    }
}
