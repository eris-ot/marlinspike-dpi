//! Diameter (RFC 6733) session decoder — AAA protocol used in telecom/5G OT.
//!
//! Header (20 bytes, all big-endian):
//!   byte 0: version(=1) | bytes 1..4: message_length u24 BE (incl. header)
//!   byte 4: flags(R=b7,P=b6,E=b5,T=b4) | bytes 5..8: command_code u24 BE
//!   bytes 8..12: application_id u32 | 12..16: hop_by_hop_id u32 | 16..20: end_to_end_id u32
//!
//! AVP (4-byte-padded): code u32 | flags u8 | length u24 BE (incl. header)
//!   [vendor_id u32 — only when V flag set] | data bytes

use std::collections::BTreeMap;
use std::collections::HashMap;

use crate::bronze::{
    AssetObservation, BronzeEvent, BronzeEventFamily, ProtocolTransaction, TransportProtocol,
};
use crate::engine::{
    build_envelope, new_event, parse_anomaly_event, DecoderInterest, SessionDecoder, StreamChunk,
};

// ── Constants ─────────────────────────────────────────────────────────────────

const DIAMETER_HEADER_LEN: usize = 20;
const DIAMETER_VERSION: u8 = 1;

// Command codes (RFC 6733 + extension RFCs)
const CMD_CAPABILITIES_EXCHANGE: u32 = 257;
const CMD_DEVICE_WATCHDOG: u32 = 280;
const CMD_DISCONNECT_PEER: u32 = 282;
const CMD_RE_AUTH: u32 = 258;
const CMD_ACCOUNTING: u32 = 271;
const CMD_ABORT_SESSION: u32 = 274;
const CMD_SESSION_TERMINATION: u32 = 275;
const CMD_EAP: u32 = 268;
// AVP codes of interest
const AVP_USER_NAME: u32 = 1;
const AVP_SESSION_ID: u32 = 263;
const AVP_ORIGIN_HOST: u32 = 264;
const AVP_RESULT_CODE: u32 = 268;
const AVP_AUTH_SESSION_STATE: u32 = 277;
const AVP_ORIGIN_REALM: u32 = 296;

// Command flag bitmasks
const FLAG_REQUEST: u8 = 0x80;
const FLAG_ERROR: u8 = 0x20;

// AVP flag bitmasks
const AVP_FLAG_VENDOR: u8 = 0x80;

// ── Parsed Diameter message ────────────────────────────────────────────────────

#[derive(Debug, Clone)]
struct DiameterMessage {
    version: u8,
    message_length: u32,
    command_flags: u8,
    command_code: u32,
    application_id: u32,
    hop_by_hop_id: u32,
    end_to_end_id: u32,
    // Extracted AVP values
    avp_user_name: Option<String>,
    avp_session_id: Option<String>,
    avp_origin_host: Option<String>,
    avp_origin_realm: Option<String>,
    avp_result_code: Option<u32>,
}

impl DiameterMessage {
    fn is_request(&self) -> bool {
        self.command_flags & FLAG_REQUEST != 0
    }
    fn is_error(&self) -> bool {
        self.command_flags & FLAG_ERROR != 0
    }
}

/// Read a 24-bit big-endian unsigned integer from 3 bytes.
/// `message_length` (bytes 1..4) and `avp_length` (bytes 5..8) are both u24 BE.
#[inline]
fn read_u24_be(buf: &[u8]) -> u32 {
    (u32::from(buf[0]) << 16) | (u32::from(buf[1]) << 8) | u32::from(buf[2])
}

/// Parse a Diameter message from a byte slice. Returns `None` on truncation.
fn parse_diameter(data: &[u8]) -> Option<DiameterMessage> {
    if data.len() < DIAMETER_HEADER_LEN {
        return None;
    }

    let version = data[0];
    // message_length is u24 BE in bytes 1..4
    let message_length = read_u24_be(&data[1..4]);
    let command_flags = data[4];
    // command_code is u24 BE in bytes 5..8
    let command_code = read_u24_be(&data[5..8]);
    let application_id = u32::from_be_bytes(data[8..12].try_into().ok()?);
    let hop_by_hop_id = u32::from_be_bytes(data[12..16].try_into().ok()?);
    let end_to_end_id = u32::from_be_bytes(data[16..20].try_into().ok()?);

    // Parse AVPs from the payload region
    let avp_data_end = (message_length as usize).min(data.len());
    let avps = parse_avps(&data[DIAMETER_HEADER_LEN..avp_data_end]);

    Some(DiameterMessage {
        version,
        message_length,
        command_flags,
        command_code,
        application_id,
        hop_by_hop_id,
        end_to_end_id,
        avp_user_name: avps.get(&AVP_USER_NAME).and_then(|b| decode_utf8_string(b)),
        avp_session_id: avps.get(&AVP_SESSION_ID).and_then(|b| decode_utf8_string(b)),
        avp_origin_host: avps.get(&AVP_ORIGIN_HOST).and_then(|b| decode_utf8_string(b)),
        avp_origin_realm: avps.get(&AVP_ORIGIN_REALM).and_then(|b| decode_utf8_string(b)),
        avp_result_code: avps.get(&AVP_RESULT_CODE).and_then(|b| {
            if b.len() >= 4 {
                Some(u32::from_be_bytes(b[..4].try_into().unwrap()))
            } else {
                None
            }
        }),
    })
}

/// Walk AVPs, return map from avp_code to raw data bytes (first occurrence).
/// Vendor AVPs (V flag) have a 12-byte header; non-vendor have 8 bytes.
fn parse_avps(mut buf: &[u8]) -> HashMap<u32, Vec<u8>> {
    let mut avps: HashMap<u32, Vec<u8>> = HashMap::new();

    while buf.len() >= 8 {
        let avp_code = u32::from_be_bytes(buf[0..4].try_into().unwrap());
        let avp_flags = buf[4];
        // avp_length is u24 BE in bytes 5..8, includes the AVP header itself
        let avp_length = read_u24_be(&buf[5..8]) as usize;

        if avp_length < 8 || avp_length > buf.len() {
            break;
        }

        let has_vendor = avp_flags & AVP_FLAG_VENDOR != 0;
        let data_offset = if has_vendor { 12 } else { 8 };

        if data_offset <= avp_length {
            let data = &buf[data_offset..avp_length];
            avps.entry(avp_code).or_insert_with(|| data.to_vec());
        }

        // Advance past this AVP, padded to 4-byte boundary
        let padded = (avp_length + 3) & !3;
        if padded > buf.len() {
            break;
        }
        buf = &buf[padded..];
    }

    avps
}

fn decode_utf8_string(bytes: &[u8]) -> Option<String> {
    String::from_utf8(bytes.to_vec()).ok()
}

/// Map command code + request flag to the operation name string.
fn command_operation(cmd: u32, is_request: bool) -> String {
    match (cmd, is_request) {
        (CMD_CAPABILITIES_EXCHANGE, true) => "diameter_capabilities_exchange_request".into(),
        (CMD_CAPABILITIES_EXCHANGE, false) => "diameter_capabilities_exchange_answer".into(),
        (CMD_DEVICE_WATCHDOG, true) => "diameter_device_watchdog_request".into(),
        (CMD_DEVICE_WATCHDOG, false) => "diameter_device_watchdog_answer".into(),
        (CMD_DISCONNECT_PEER, true) => "diameter_disconnect_peer_request".into(),
        (CMD_DISCONNECT_PEER, false) => "diameter_disconnect_peer_answer".into(),
        (CMD_RE_AUTH, true) => "diameter_re_auth_request".into(),
        (CMD_RE_AUTH, false) => "diameter_re_auth_answer".into(),
        (CMD_ACCOUNTING, true) => "diameter_accounting_request".into(),
        (CMD_ACCOUNTING, false) => "diameter_accounting_answer".into(),
        (CMD_ABORT_SESSION, true) => "diameter_abort_session_request".into(),
        (CMD_ABORT_SESSION, false) => "diameter_abort_session_answer".into(),
        (CMD_SESSION_TERMINATION, true) => "diameter_session_termination_request".into(),
        (CMD_SESSION_TERMINATION, false) => "diameter_session_termination_answer".into(),
        (CMD_EAP, true) => "diameter_eap_request".into(),
        (CMD_EAP, false) => "diameter_eap_answer".into(),
        (n, _) => format!("diameter_unknown_cmd_{n}"),
    }
}

// ── Pending-request state (for pairing req→answer) ────────────────────────────

#[derive(Debug)]
struct PendingRequest {
    operation: String,
}

// ── Decoder ───────────────────────────────────────────────────────────────────

/// Diameter (RFC 6733) TCP stream decoder.
/// Port 3868: plaintext — parse + pair by hop_by_hop_id.
/// Port 5868: TLS-wrapped — emit single session marker.
#[derive(Default)]
pub(crate) struct DiameterDecoder {
    pending: HashMap<u32, PendingRequest>,
    tls_session_emitted: bool,
    asset_emitted: bool,
}

inventory::submit!(crate::engine::decoders::DecoderRegistration {
    name: "diameter",
    factory: || Box::new(DiameterDecoder::default()),
});

impl SessionDecoder for DiameterDecoder {
    fn name(&self) -> &'static str {
        "diameter"
    }

    fn interest(&self) -> &'static [DecoderInterest] {
        &[
            DecoderInterest::TcpPort(3868), // plaintext Diameter
            DecoderInterest::TcpPort(5868), // Diameter over TLS/DTLS (opaque)
        ]
    }

    fn on_stream_chunk(&mut self, chunk: &StreamChunk<'_>, out: &mut Vec<BronzeEvent>) {
        // ── Port 5868: TLS-wrapped Diameter — emit one session marker ──────────
        if chunk.context.dst_port == 5868 || chunk.context.src_port == 5868 {
            if !self.tls_session_emitted {
                self.tls_session_emitted = true;
                let envelope = build_envelope(
                    &chunk.context,
                    chunk.interface_id,
                    chunk.frame_index,
                    chunk.timestamp,
                    chunk.segment_hash,
                    TransportProtocol::Tcp,
                    Some("diameter"),
                    chunk.captured_len,
                    chunk.session_key.clone(),
                );
                // Server-side asset for the TLS endpoint.
                let dst_ip_str = chunk.context.dst_ip.to_string();
                out.push(new_event(
                    chunk.capture_id.to_string(),
                    envelope.clone(),
                    BronzeEventFamily::AssetObservation(AssetObservation {
                        asset_key: dst_ip_str,
                        role: Some("diameter_server".to_string()),
                        vendor: None,
                        model: None,
                        firmware: None,
                        hostnames: vec![],
                        protocols: vec!["diameter".to_string()],
                        identifiers: BTreeMap::new(),
                    }),
                ));
                out.push(new_event(
                    chunk.capture_id.to_string(),
                    envelope,
                    BronzeEventFamily::ProtocolTransaction(ProtocolTransaction {
                        operation: "diameter_tls_session".to_string(),
                        status: "observed".to_string(),
                        request_summary: None,
                        response_summary: None,
                        object_refs: vec![],
                        values: vec![],
                        attributes: BTreeMap::new(),
                        modbus: None,
                        protocol_fields: None,
                    }),
                ));
            }
            return;
        }

        // ── Port 3868: plaintext Diameter ─────────────────────────────────────
        self.decode_plaintext(chunk, out);
    }
}

impl DiameterDecoder {
    fn decode_plaintext(&mut self, chunk: &StreamChunk<'_>, out: &mut Vec<BronzeEvent>) {
        let data = chunk.payload;

        // Version sanity check (first byte must be 1).
        if data.is_empty() {
            return;
        }
        if data[0] != DIAMETER_VERSION {
            out.push(parse_anomaly_event(
                chunk.capture_id.to_string(),
                build_envelope(
                    &chunk.context,
                    chunk.interface_id,
                    chunk.frame_index,
                    chunk.timestamp,
                    chunk.segment_hash,
                    TransportProtocol::Tcp,
                    Some("diameter"),
                    chunk.captured_len,
                    chunk.session_key.clone(),
                ),
                self.name(),
                "low",
                "diameter version field is not 1",
                data,
            ));
            return;
        }

        let Some(msg) = parse_diameter(data) else {
            out.push(parse_anomaly_event(
                chunk.capture_id.to_string(),
                build_envelope(
                    &chunk.context,
                    chunk.interface_id,
                    chunk.frame_index,
                    chunk.timestamp,
                    chunk.segment_hash,
                    TransportProtocol::Tcp,
                    Some("diameter"),
                    chunk.captured_len,
                    chunk.session_key.clone(),
                ),
                self.name(),
                "medium",
                "truncated diameter message — message_length exceeds available bytes",
                data,
            ));
            return;
        };

        // Length cross-check: message_length must match available data.
        if msg.message_length as usize > data.len() {
            out.push(parse_anomaly_event(
                chunk.capture_id.to_string(),
                build_envelope(
                    &chunk.context,
                    chunk.interface_id,
                    chunk.frame_index,
                    chunk.timestamp,
                    chunk.segment_hash,
                    TransportProtocol::Tcp,
                    Some("diameter"),
                    chunk.captured_len,
                    chunk.session_key.clone(),
                ),
                self.name(),
                "medium",
                "diameter message_length disagrees with available bytes",
                data,
            ));
            // Still continue to emit a best-effort transaction below.
        }

        let envelope = build_envelope(
            &chunk.context,
            chunk.interface_id,
            chunk.frame_index,
            chunk.timestamp,
            chunk.segment_hash,
            TransportProtocol::Tcp,
            Some("diameter"),
            chunk.captured_len,
            chunk.session_key.clone(),
        );

        // Determine transaction status and update pending-request table.
        let operation = command_operation(msg.command_code, msg.is_request());
        let status = if msg.is_error() {
            "error".to_string()
        } else if msg.is_request() {
            self.pending.insert(
                msg.hop_by_hop_id,
                PendingRequest {
                    operation: operation.clone(),
                },
            );
            "request_only".to_string() // updated to "ok" when answer arrives
        } else {
            // Answer: check if a matching request exists.
            if self.pending.remove(&msg.hop_by_hop_id).is_some() {
                "ok".to_string()
            } else {
                "request_only".to_string()
            }
        };

        // Build attributes map.
        let mut attributes: BTreeMap<String, String> = BTreeMap::new();
        attributes.insert("command_code".to_string(), msg.command_code.to_string());
        attributes.insert("application_id".to_string(), msg.application_id.to_string());
        attributes.insert(
            "hop_by_hop_id".to_string(),
            format!("{:#010x}", msg.hop_by_hop_id),
        );
        attributes.insert(
            "end_to_end_id".to_string(),
            format!("{:#010x}", msg.end_to_end_id),
        );
        attributes.insert(
            "flags_hex".to_string(),
            format!("{:#04x}", msg.command_flags),
        );
        attributes.insert(
            "is_request".to_string(),
            if msg.is_request() { "true" } else { "false" }.to_string(),
        );
        attributes.insert(
            "is_error".to_string(),
            if msg.is_error() { "true" } else { "false" }.to_string(),
        );

        // Optional AVP values.
        if let Some(ref v) = msg.avp_user_name {
            attributes.insert("avp_user_name".to_string(), v.clone());
        }
        if let Some(ref v) = msg.avp_session_id {
            attributes.insert("avp_session_id".to_string(), v.clone());
        }
        if let Some(ref v) = msg.avp_origin_host {
            attributes.insert("avp_origin_host".to_string(), v.clone());
        }
        if let Some(ref v) = msg.avp_origin_realm {
            attributes.insert("avp_origin_realm".to_string(), v.clone());
        }
        if let Some(rc) = msg.avp_result_code {
            attributes.insert("avp_result_code".to_string(), rc.to_string());
        }

        out.push(new_event(
            chunk.capture_id.to_string(),
            envelope.clone(),
            BronzeEventFamily::ProtocolTransaction(ProtocolTransaction {
                operation: operation.clone(),
                status,
                request_summary: Some(format!(
                    "cmd={} app={} hbh={:#010x}",
                    msg.command_code, msg.application_id, msg.hop_by_hop_id
                )),
                response_summary: None,
                object_refs: msg.avp_session_id.clone().into_iter().collect(),
                values: vec![],
                attributes,
                modbus: None,
                protocol_fields: None,
            }),
        ));

        // On CER (cmd=257, Request flag set): emit AssetObservation for src.
        if msg.command_code == CMD_CAPABILITIES_EXCHANGE && msg.is_request() && !self.asset_emitted
        {
            self.asset_emitted = true;
            let src_ip_str = chunk.context.src_ip.to_string();
            let mut identifiers: BTreeMap<String, String> = BTreeMap::new();
            if let Some(ref oh) = msg.avp_origin_host {
                identifiers.insert("origin_host".to_string(), oh.clone());
            }
            if let Some(ref or_) = msg.avp_origin_realm {
                identifiers.insert("origin_realm".to_string(), or_.clone());
            }
            out.push(new_event(
                chunk.capture_id.to_string(),
                envelope,
                BronzeEventFamily::AssetObservation(AssetObservation {
                    asset_key: src_ip_str,
                    role: Some("diameter_peer".to_string()),
                    vendor: None,
                    model: None,
                    firmware: None,
                    hostnames: vec![],
                    protocols: vec!["diameter".to_string()],
                    identifiers,
                }),
            ));
        }
    }
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};
    use chrono::{TimeZone, Utc};
    use super::*;
    use crate::bronze::BronzeEventFamily;
    use crate::engine::StreamChunk;
    use crate::registry::PacketContext;

    fn ctx(sp: u16, dp: u16) -> PacketContext {
        PacketContext {
            src_mac: [0u8; 6], dst_mac: [0u8; 6],
            src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            dst_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            src_port: sp, dst_port: dp, vlan_id: None,
            timestamp: 1_700_000_000_000_000,
        }
    }

    fn chunk<'a>(payload: &'a [u8], context: PacketContext) -> StreamChunk<'a> {
        StreamChunk {
            capture_id: "test", segment_hash: "seg",
            interface_id: 0, frame_index: 0,
            timestamp: Utc.timestamp_opt(1_700_000_000, 0).unwrap(),
            context, ethertype: 0x0800, ip_proto: Some(6), llc: None,
            transport: TransportProtocol::Tcp,
            payload, session_key: "sk".to_string(),
            captured_len: payload.len() as u64,
        }
    }

    fn get_tx(evs: &[BronzeEvent]) -> Option<&ProtocolTransaction> {
        evs.iter().find_map(|e| if let BronzeEventFamily::ProtocolTransaction(ref t) = e.family { Some(t) } else { None })
    }
    fn get_asset(evs: &[BronzeEvent]) -> Option<&AssetObservation> {
        evs.iter().find_map(|e| if let BronzeEventFamily::AssetObservation(ref a) = e.family { Some(a) } else { None })
    }

    /// Build a 20-byte Diameter header. message_length and command_code are u24 BE;
    /// total_len must include the 20-byte header itself.
    fn hdr(flags: u8, cmd: u32, app: u32, hbh: u32, e2e: u32, tlen: u32) -> Vec<u8> {
        let mut h = vec![
            DIAMETER_VERSION,
            ((tlen >> 16) & 0xFF) as u8, ((tlen >> 8) & 0xFF) as u8, (tlen & 0xFF) as u8,
            flags,
            ((cmd >> 16) & 0xFF) as u8, ((cmd >> 8) & 0xFF) as u8, (cmd & 0xFF) as u8,
        ];
        h.extend_from_slice(&app.to_be_bytes());
        h.extend_from_slice(&hbh.to_be_bytes());
        h.extend_from_slice(&e2e.to_be_bytes());
        h
    }

    /// Encode a non-vendor AVP. avp_length (u24 BE) = 8 + data.len(); padded to 4 bytes.
    fn avp(code: u32, flags: u8, data: &[u8]) -> Vec<u8> {
        let alen = 8 + data.len();
        let mut a = code.to_be_bytes().to_vec();
        a.push(flags);
        a.push(((alen >> 16) & 0xFF) as u8);
        a.push(((alen >> 8) & 0xFF) as u8);
        a.push((alen & 0xFF) as u8);
        a.extend_from_slice(data);
        let pad = (4 - (alen % 4)) % 4;
        a.extend(std::iter::repeat(0u8).take(pad));
        a
    }

    fn avp_u32(code: u32, flags: u8, v: u32) -> Vec<u8> { avp(code, flags, &v.to_be_bytes()) }

    fn hl() -> u32 { DIAMETER_HEADER_LEN as u32 }

    // ── 1: CER with Origin-Host AVP ──────────────────────────────────────────

    #[test]
    fn test_cer_with_origin_host() {
        let a = avp(AVP_ORIGIN_HOST, 0x40, b"dra1.example.com");
        let mut pkt = hdr(FLAG_REQUEST, CMD_CAPABILITIES_EXCHANGE, 0, 0xABCDEF01, 0x12345678, hl() + a.len() as u32);
        pkt.extend_from_slice(&a);
        let mut evs = Vec::new();
        DiameterDecoder::default().on_stream_chunk(&chunk(&pkt, ctx(49152, 3868)), &mut evs);
        let tx = get_tx(&evs).unwrap();
        assert_eq!(tx.operation, "diameter_capabilities_exchange_request");
        assert_eq!(tx.attributes.get("avp_origin_host").map(String::as_str), Some("dra1.example.com"));
        assert_eq!(tx.attributes.get("is_request").map(String::as_str), Some("true"));
    }

    // ── 2: CER + CEA pair → status "ok" on answer ────────────────────────────

    #[test]
    fn test_cer_cea_pair_status_ok() {
        let hbh = 0xDEAD_BEEFu32;
        let cer = hdr(FLAG_REQUEST, CMD_CAPABILITIES_EXCHANGE, 0, hbh, 1, hl());
        let cea = hdr(0x00,         CMD_CAPABILITIES_EXCHANGE, 0, hbh, 1, hl());
        let mut dec = DiameterDecoder::default();
        let mut evs = Vec::new();
        dec.on_stream_chunk(&chunk(&cer, ctx(49152, 3868)), &mut evs);
        dec.on_stream_chunk(&chunk(&cea, ctx(3868, 49152)), &mut evs);
        let txns: Vec<_> = evs.iter().filter_map(|e| {
            if let BronzeEventFamily::ProtocolTransaction(ref t) = e.family { Some(t) } else { None }
        }).collect();
        assert_eq!(txns.len(), 2);
        assert_eq!(txns[1].operation, "diameter_capabilities_exchange_answer");
        assert_eq!(txns[1].status, "ok");
    }

    // ── 3: Device-Watchdog Request ────────────────────────────────────────────

    #[test]
    fn test_device_watchdog_request() {
        let pkt = hdr(FLAG_REQUEST, CMD_DEVICE_WATCHDOG, 0, 1, 1, hl());
        let mut evs = Vec::new();
        DiameterDecoder::default().on_stream_chunk(&chunk(&pkt, ctx(49152, 3868)), &mut evs);
        let tx = get_tx(&evs).unwrap();
        assert_eq!(tx.operation, "diameter_device_watchdog_request");
        assert_eq!(tx.attributes.get("is_request").map(String::as_str), Some("true"));
    }

    // ── 4: Accounting answer with E flag + Result-Code 3001 ───────────────────

    #[test]
    fn test_accounting_answer_error_with_result_code() {
        let rc = avp_u32(AVP_RESULT_CODE, 0x40, 3001);
        let mut pkt = hdr(FLAG_ERROR, CMD_ACCOUNTING, 3, 0xCAFEBABE, 2, hl() + rc.len() as u32);
        pkt.extend_from_slice(&rc);
        let mut evs = Vec::new();
        DiameterDecoder::default().on_stream_chunk(&chunk(&pkt, ctx(3868, 49153)), &mut evs);
        let tx = get_tx(&evs).unwrap();
        assert_eq!(tx.operation, "diameter_accounting_answer");
        assert_eq!(tx.status, "error");
        assert_eq!(tx.attributes.get("avp_result_code").map(String::as_str), Some("3001"));
        assert_eq!(tx.attributes.get("is_error").map(String::as_str), Some("true"));
    }

    // ── 5: Port 5868 TLS session marker ──────────────────────────────────────

    #[test]
    fn test_tls_session_on_port_5868() {
        let tls = vec![0x16, 0x03, 0x03, 0x00, 0x01, 0x01];
        let mut evs = Vec::new();
        DiameterDecoder::default().on_stream_chunk(&chunk(&tls, ctx(49152, 5868)), &mut evs);
        let tx = get_tx(&evs).unwrap();
        assert_eq!(tx.operation, "diameter_tls_session");
        assert_eq!(tx.status, "observed");
        assert_eq!(get_asset(&evs).unwrap().role.as_deref(), Some("diameter_server"));
    }

    // ── 6: Unknown command code ───────────────────────────────────────────────

    #[test]
    fn test_unknown_command_code() {
        let pkt = hdr(FLAG_REQUEST, 9999, 0, 1, 1, hl());
        let mut evs = Vec::new();
        DiameterDecoder::default().on_stream_chunk(&chunk(&pkt, ctx(49152, 3868)), &mut evs);
        assert_eq!(get_tx(&evs).unwrap().operation, "diameter_unknown_cmd_9999");
    }

    // ── 7: CER AssetObservation identifiers ──────────────────────────────────

    #[test]
    fn test_cer_asset_observation_identifiers() {
        let mut avps = avp(AVP_ORIGIN_HOST, 0x40, b"dra2.corp.net");
        avps.extend_from_slice(&avp(AVP_ORIGIN_REALM, 0x40, b"corp.net"));
        let mut pkt = hdr(FLAG_REQUEST, CMD_CAPABILITIES_EXCHANGE, 0, 0x1111, 0x2222, hl() + avps.len() as u32);
        pkt.extend_from_slice(&avps);
        let mut evs = Vec::new();
        DiameterDecoder::default().on_stream_chunk(&chunk(&pkt, ctx(49152, 3868)), &mut evs);
        let asset = get_asset(&evs).unwrap();
        assert_eq!(asset.role.as_deref(), Some("diameter_peer"));
        assert_eq!(asset.identifiers.get("origin_host").map(String::as_str), Some("dra2.corp.net"));
        assert_eq!(asset.identifiers.get("origin_realm").map(String::as_str), Some("corp.net"));
    }
}
