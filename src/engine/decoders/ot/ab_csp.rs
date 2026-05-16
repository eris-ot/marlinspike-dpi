//! Allen-Bradley CSP (Client/Server Protocol) decoder.
//!
//! CSP is the legacy AB Ethernet protocol for PLC-5E, SLC 5/05, and
//! MicroLogix 1100/1400 controllers. It pre-dates EtherNet/IP and tunnels
//! DH+ (Data Highway Plus) over TCP/2222. Many NA manufacturing sites have
//! not migrated to CIP/EtherNet/IP.
//!
//! Protocol documentation: CSP framing is only partially documented in
//! public sources. The primary reference is the Wireshark dissector
//! `packet-cspv4.c` (epan/dissectors/). Field offsets below reflect that
//! dissector; where the dissector is ambiguous or contradicts other sources,
//! this implementation makes a best-effort interpretation — such locations
//! are flagged with `// BEST-EFFORT:` comments.
//!
//! Wire format — CSP frame header (28 bytes, little-endian unless noted):
//!   offset  0..2   command      u16 LE  — top-level command code
//!   offset  2..4   status       u16 LE  — 0 = success; non-zero on replies
//!   offset  4..6   packet_size  u16 LE  — total frame byte count (incl. hdr)
//!   offset  6..10  reserved     u32     — ignored
//!   offset 10..14  client_handle u32 LE — identifies the originating client
//!   offset 14..18  target_addr_hi u32 LE — DH+ routing: high address word
//!   offset 18..22  target_addr_lo u32 LE — DH+ routing: low address word
//!   offset 22..24  transaction_id u16 LE — used to pair request/response
//!   offset 24..26  tns           u16 LE — PCCC transaction number (same role
//!                                          as PCCC TNS in EtherNet/IP usage)
//!   offset 26..28  function      u16 LE — CSP-level function code
//!
//! After the 28-byte header: optional PCCC PDU payload.

use std::collections::BTreeMap;

use crate::bronze::{
    AssetObservation, BronzeEvent, BronzeEventFamily, ProtocolTransaction, TransportProtocol,
};
use crate::engine::{
    DecoderInterest, SessionDecoder, StreamChunk, build_envelope, new_event, parse_anomaly_event,
};

// ── Wire constants ────────────────────────────────────────────────────────────

/// Minimum valid CSP frame — the header is always 28 bytes.
const CSP_HEADER_LEN: usize = 28;

// Header field byte offsets (all little-endian u16/u32).
const OFF_COMMAND: usize = 0;
const OFF_STATUS: usize = 2;
const OFF_PACKET_SIZE: usize = 4;
// 6..10 reserved
const OFF_CLIENT_HANDLE: usize = 10;
const OFF_TARGET_ADDR_HI: usize = 14;
const OFF_TARGET_ADDR_LO: usize = 18;
const OFF_TRANSACTION_ID: usize = 22;
const OFF_TNS: usize = 24;
const OFF_FUNCTION: usize = 26;

// ── Command codes ─────────────────────────────────────────────────────────────
// Source: Wireshark packet-cspv4.c command table.
// BEST-EFFORT: command and function code namespaces overlap in some
// documentation; the mapping below follows the Wireshark dissector.

const CMD_REGISTER_SESSION: u16 = 0x0001;
const CMD_UNREGISTER_SESSION: u16 = 0x0002;
const CMD_PCCC_REPLY: u16 = 0x0003;
const CMD_READ_WITH_OFFSET: u16 = 0x0007;
const CMD_WRITE_WITH_OFFSET: u16 = 0x0008;
const CMD_PCCC_REQUEST: u16 = 0x00A1;

// ── Decoder state ─────────────────────────────────────────────────────────────

/// Stateless decoder — CSP frames carry enough context per-frame that we
/// emit events immediately without buffering pending requests. The spec
/// transaction_id could be used for pairing but CSP is commonly seen in
/// passive captures where both directions are observed; we emit one event
/// per frame rather than holding state.
#[derive(Default)]
pub(crate) struct AbCspDecoder;

// ── Helper: parse a CSP header ────────────────────────────────────────────────

#[derive(Debug)]
struct CspHeader {
    command: u16,
    status: u16,
    /// Value of the packet_size field on the wire (may differ from buf.len()).
    packet_size: u16,
    client_handle: u32,
    target_addr_hi: u32,
    target_addr_lo: u32,
    transaction_id: u16,
    tns: u16,
    function: u16,
}

fn read_u16_le(buf: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes([buf[offset], buf[offset + 1]])
}

fn read_u32_le(buf: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes([
        buf[offset],
        buf[offset + 1],
        buf[offset + 2],
        buf[offset + 3],
    ])
}

fn parse_header(buf: &[u8]) -> Option<CspHeader> {
    if buf.len() < CSP_HEADER_LEN {
        return None;
    }
    Some(CspHeader {
        command: read_u16_le(buf, OFF_COMMAND),
        status: read_u16_le(buf, OFF_STATUS),
        packet_size: read_u16_le(buf, OFF_PACKET_SIZE),
        client_handle: read_u32_le(buf, OFF_CLIENT_HANDLE),
        target_addr_hi: read_u32_le(buf, OFF_TARGET_ADDR_HI),
        target_addr_lo: read_u32_le(buf, OFF_TARGET_ADDR_LO),
        transaction_id: read_u16_le(buf, OFF_TRANSACTION_ID),
        tns: read_u16_le(buf, OFF_TNS),
        function: read_u16_le(buf, OFF_FUNCTION),
    })
}

fn command_operation(command: u16) -> String {
    match command {
        CMD_REGISTER_SESSION => "csp_register_session".to_string(),
        CMD_UNREGISTER_SESSION => "csp_unregister_session".to_string(),
        CMD_PCCC_REPLY => "csp_pccc_reply".to_string(),
        CMD_READ_WITH_OFFSET => "csp_read".to_string(),
        CMD_WRITE_WITH_OFFSET => "csp_write".to_string(),
        CMD_PCCC_REQUEST => "csp_pccc_request".to_string(),
        other => format!("csp_unknown_cmd_0x{other:04x}"),
    }
}

fn status_string(status: u16) -> String {
    if status == 0 {
        "ok".to_string()
    } else {
        format!("csp_status_0x{status:04x}")
    }
}

// ── SessionDecoder impl ───────────────────────────────────────────────────────

impl SessionDecoder for AbCspDecoder {
    fn name(&self) -> &'static str {
        "ab_csp"
    }

    fn interest(&self) -> &'static [DecoderInterest] {
        // CSP uses TCP/2222. Note: EtherNet/IP later reused UDP/2222 for
        // class-1 I/O; CSP is the legacy TCP variant exclusively.
        &[DecoderInterest::TcpPort(2222)]
    }

    fn on_stream_chunk(&mut self, chunk: &StreamChunk<'_>, out: &mut Vec<BronzeEvent>) {
        let buf = chunk.payload;

        // ── Validate minimum header length ────────────────────────────────────
        if buf.len() < CSP_HEADER_LEN {
            out.push(parse_anomaly_event(
                chunk.capture_id.to_string(),
                build_envelope(
                    &chunk.context,
                    chunk.interface_id,
                    chunk.frame_index,
                    chunk.timestamp,
                    chunk.segment_hash,
                    TransportProtocol::Tcp,
                    Some("ab_csp"),
                    chunk.captured_len,
                    chunk.session_key.clone(),
                ),
                self.name(),
                "medium",
                "csp frame shorter than 28-byte header minimum",
                buf,
            ));
            return;
        }

        let hdr = parse_header(buf).expect("length checked above");
        let envelope = build_envelope(
            &chunk.context,
            chunk.interface_id,
            chunk.frame_index,
            chunk.timestamp,
            chunk.segment_hash,
            TransportProtocol::Tcp,
            Some("ab_csp"),
            chunk.captured_len,
            chunk.session_key.clone(),
        );

        // ── Validate packet_size field against actual buffer length ───────────
        // BEST-EFFORT: the packet_size field meaning (header-inclusive vs.
        // payload-only) varies by version; we treat it as total frame bytes
        // matching packet-cspv4.c behaviour.
        let declared_len = hdr.packet_size as usize;
        if declared_len != buf.len() {
            let reason = format!(
                "csp packet_size field ({declared_len}) does not match buffer length ({})",
                buf.len()
            );
            out.push(parse_anomaly_event(
                chunk.capture_id.to_string(),
                envelope.clone(),
                self.name(),
                "medium",
                &reason,
                buf,
            ));
            // Emit anomaly and continue — we can still decode the header fields.
        }

        // ── ParseAnomaly for unknown command codes ────────────────────────────
        let is_known_command = matches!(
            hdr.command,
            CMD_REGISTER_SESSION
                | CMD_UNREGISTER_SESSION
                | CMD_PCCC_REPLY
                | CMD_READ_WITH_OFFSET
                | CMD_WRITE_WITH_OFFSET
                | CMD_PCCC_REQUEST
        );
        if !is_known_command {
            out.push(parse_anomaly_event(
                chunk.capture_id.to_string(),
                envelope.clone(),
                self.name(),
                "low",
                &format!("unknown csp command code 0x{:04x}", hdr.command),
                buf,
            ));
        }

        // ── Build ProtocolTransaction ─────────────────────────────────────────
        let operation = command_operation(hdr.command);
        let status = status_string(hdr.status);

        let mut attributes = BTreeMap::new();
        attributes.insert("command".to_string(), format!("0x{:04x}", hdr.command));
        attributes.insert("function".to_string(), format!("0x{:04x}", hdr.function));
        attributes.insert("packet_size".to_string(), hdr.packet_size.to_string());
        attributes.insert(
            "target_addr_hi".to_string(),
            format!("0x{:08x}", hdr.target_addr_hi),
        );
        attributes.insert(
            "target_addr_lo".to_string(),
            format!("0x{:08x}", hdr.target_addr_lo),
        );
        attributes.insert(
            "client_handle".to_string(),
            format!("0x{:08x}", hdr.client_handle),
        );
        attributes.insert("transaction_id".to_string(), hdr.transaction_id.to_string());
        attributes.insert("tns".to_string(), format!("0x{:04x}", hdr.tns));

        out.push(new_event(
            chunk.capture_id.to_string(),
            envelope.clone(),
            BronzeEventFamily::ProtocolTransaction(ProtocolTransaction {
                operation: operation.clone(),
                status,
                request_summary: Some(format!(
                    "{operation} txn={} cli=0x{:08x}",
                    hdr.transaction_id, hdr.client_handle
                )),
                response_summary: None,
                object_refs: Vec::new(),
                values: Vec::new(),
                attributes,
                modbus: None,
                protocol_fields: None,
            }),
        ));

        // ── AssetObservation for register-session responses ───────────────────
        // When we observe a register-session command (status=0, implies the
        // device accepted a session), record the *destination* IP as an AB
        // PLC asset using the DH+ address fields as identifiers.
        // BEST-EFFORT: we use dst_ip as the "PLC that replied" on the
        // assumption that register-session requests flow client→PLC. Passive
        // captures may see either direction first; emitting on any cmd=0x0001
        // with status=0 gives the best coverage without session-state tracking.
        if hdr.command == CMD_REGISTER_SESSION
            && hdr.status == 0
            && let Some(dst_ip) = envelope.dst_ip.clone()
        {
            let mut identifiers = BTreeMap::new();
            identifiers.insert(
                "csp_addr_hi".to_string(),
                format!("0x{:08x}", hdr.target_addr_hi),
            );
            identifiers.insert(
                "csp_addr_lo".to_string(),
                format!("0x{:08x}", hdr.target_addr_lo),
            );
            identifiers.insert("ip".to_string(), dst_ip.clone());
            out.push(new_event(
                chunk.capture_id.to_string(),
                envelope,
                BronzeEventFamily::AssetObservation(AssetObservation {
                    asset_key: dst_ip,
                    role: Some("ab_csp_plc".to_string()),
                    vendor: Some("Allen-Bradley".to_string()),
                    model: None,
                    firmware: None,
                    hostnames: Vec::new(),
                    protocols: vec!["ab_csp".to_string()],
                    identifiers,
                }),
            ));
        }
    }
}

// ── Self-registration ─────────────────────────────────────────────────────────

inventory::submit!(crate::engine::decoders::DecoderRegistration {
    name: "ab_csp",
    factory: || Box::new(AbCspDecoder),
});

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use std::net::{IpAddr, Ipv4Addr};

    use crate::registry::PacketContext;

    /// Build a hand-crafted 28-byte CSP header. All reserved/unused bytes
    /// are zeroed. `packet_size` is set to `buf_total_len` unless overridden.
    #[allow(clippy::too_many_arguments)]
    fn make_csp_frame(
        command: u16,
        status: u16,
        packet_size_override: Option<u16>,
        function: u16,
        transaction_id: u16,
        target_addr_hi: u32,
        target_addr_lo: u32,
        extra_payload: &[u8],
    ) -> Vec<u8> {
        let total = CSP_HEADER_LEN + extra_payload.len();
        let declared = packet_size_override.unwrap_or(total as u16);

        let mut buf = vec![0u8; total];
        buf[OFF_COMMAND..OFF_COMMAND + 2].copy_from_slice(&command.to_le_bytes());
        buf[OFF_STATUS..OFF_STATUS + 2].copy_from_slice(&status.to_le_bytes());
        buf[OFF_PACKET_SIZE..OFF_PACKET_SIZE + 2].copy_from_slice(&declared.to_le_bytes());
        // client_handle = 0xCAFEBABE for easy identification in assertions
        buf[OFF_CLIENT_HANDLE..OFF_CLIENT_HANDLE + 4]
            .copy_from_slice(&0xCAFEBABE_u32.to_le_bytes());
        buf[OFF_TARGET_ADDR_HI..OFF_TARGET_ADDR_HI + 4]
            .copy_from_slice(&target_addr_hi.to_le_bytes());
        buf[OFF_TARGET_ADDR_LO..OFF_TARGET_ADDR_LO + 4]
            .copy_from_slice(&target_addr_lo.to_le_bytes());
        buf[OFF_TRANSACTION_ID..OFF_TRANSACTION_ID + 2]
            .copy_from_slice(&transaction_id.to_le_bytes());
        buf[OFF_TNS..OFF_TNS + 2].copy_from_slice(&0x0042_u16.to_le_bytes());
        buf[OFF_FUNCTION..OFF_FUNCTION + 2].copy_from_slice(&function.to_le_bytes());
        if !extra_payload.is_empty() {
            buf[CSP_HEADER_LEN..].copy_from_slice(extra_payload);
        }
        buf
    }

    fn feed(dec: &mut AbCspDecoder, payload: &[u8], out: &mut Vec<BronzeEvent>) {
        let context = PacketContext {
            src_ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10)),
            dst_ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 20)),
            src_port: 54321,
            dst_port: 2222,
            src_mac: [0u8; 6],
            dst_mac: [0u8; 6],
            vlan_id: None,
            timestamp: 0,
        };
        let chunk = StreamChunk {
            capture_id: "cap-test",
            segment_hash: "seg-ab-csp",
            interface_id: 0,
            frame_index: 1,
            timestamp: Utc::now(),
            context,
            ethertype: 0x0800,
            ip_proto: Some(6),
            llc: None,
            transport: TransportProtocol::Tcp,
            payload,
            session_key: "192.168.1.10-192.168.1.20-54321-2222".to_string(),
            captured_len: payload.len() as u64,
        };
        dec.on_stream_chunk(&chunk, out);
    }

    /// 1. CSP Register Session (cmd=0x0001, status=0) →
    ///    operation="csp_register_session", status="ok", + AssetObservation.
    #[test]
    fn test_register_session_ok() {
        let mut dec = AbCspDecoder;
        let mut out = Vec::new();
        let frame = make_csp_frame(
            CMD_REGISTER_SESSION,
            0,
            None,
            0x01,
            1,
            0xDEAD0001,
            0xBEEF0002,
            &[],
        );
        feed(&mut dec, &frame, &mut out);

        // Expect a ProtocolTransaction and an AssetObservation.
        let txns: Vec<_> = out
            .iter()
            .filter(|e| matches!(e.family, BronzeEventFamily::ProtocolTransaction(_)))
            .collect();
        assert_eq!(txns.len(), 1, "expected one ProtocolTransaction");
        let BronzeEventFamily::ProtocolTransaction(ref txn) = txns[0].family else {
            panic!("expected ProtocolTransaction");
        };
        assert_eq!(txn.operation, "csp_register_session");
        assert_eq!(txn.status, "ok");
        assert_eq!(txn.attributes["command"], "0x0001");

        let assets: Vec<_> = out
            .iter()
            .filter(|e| matches!(e.family, BronzeEventFamily::AssetObservation(_)))
            .collect();
        assert_eq!(assets.len(), 1, "expected one AssetObservation");
        let BronzeEventFamily::AssetObservation(ref obs) = assets[0].family else {
            panic!("expected AssetObservation");
        };
        assert_eq!(obs.role.as_deref(), Some("ab_csp_plc"));
        assert_eq!(obs.vendor.as_deref(), Some("Allen-Bradley"));
        assert!(obs.identifiers.contains_key("csp_addr_hi"));
        assert!(obs.identifiers.contains_key("csp_addr_lo"));
    }

    /// 2. CSP PCCC Request (cmd=0x00A1, status=0) →
    ///    operation="csp_pccc_request", status="ok".
    #[test]
    fn test_pccc_request_ok() {
        let mut dec = AbCspDecoder;
        let mut out = Vec::new();
        let pccc_payload = [0x0F, 0x00, 0x01, 0x00, 0x01, 0x00]; // dummy PCCC bytes
        let frame = make_csp_frame(CMD_PCCC_REQUEST, 0, None, 0x06, 42, 0, 0, &pccc_payload);
        feed(&mut dec, &frame, &mut out);

        let txns: Vec<_> = out
            .iter()
            .filter(|e| matches!(e.family, BronzeEventFamily::ProtocolTransaction(_)))
            .collect();
        assert_eq!(txns.len(), 1);
        let BronzeEventFamily::ProtocolTransaction(ref txn) = txns[0].family else {
            panic!();
        };
        assert_eq!(txn.operation, "csp_pccc_request");
        assert_eq!(txn.status, "ok");
        // No anomalies expected.
        let anomalies: Vec<_> = out
            .iter()
            .filter(|e| matches!(e.family, BronzeEventFamily::ParseAnomaly(_)))
            .collect();
        assert!(
            anomalies.is_empty(),
            "no anomalies expected for valid PCCC request"
        );
    }

    /// 3. CSP PCCC Reply (cmd=0x0003, status=0x0010) →
    ///    operation="csp_pccc_reply", status="csp_status_0x0010".
    #[test]
    fn test_pccc_reply_error_status() {
        let mut dec = AbCspDecoder;
        let mut out = Vec::new();
        let frame = make_csp_frame(CMD_PCCC_REPLY, 0x0010, None, 0x06, 42, 0, 0, &[]);
        feed(&mut dec, &frame, &mut out);

        let txns: Vec<_> = out
            .iter()
            .filter(|e| matches!(e.family, BronzeEventFamily::ProtocolTransaction(_)))
            .collect();
        assert_eq!(txns.len(), 1);
        let BronzeEventFamily::ProtocolTransaction(ref txn) = txns[0].family else {
            panic!();
        };
        assert_eq!(txn.operation, "csp_pccc_reply");
        assert_eq!(txn.status, "csp_status_0x0010");
    }

    /// 4. Unknown command 0xFFFF → operation="csp_unknown_cmd_0xffff" +
    ///    exactly one ParseAnomaly with severity="low".
    #[test]
    fn test_unknown_command_anomaly_low() {
        let mut dec = AbCspDecoder;
        let mut out = Vec::new();
        let frame = make_csp_frame(0xFFFF, 0, None, 0x00, 1, 0, 0, &[]);
        feed(&mut dec, &frame, &mut out);

        let anomalies: Vec<_> = out
            .iter()
            .filter(|e| matches!(e.family, BronzeEventFamily::ParseAnomaly(_)))
            .collect();
        assert_eq!(anomalies.len(), 1, "expected one low-severity ParseAnomaly");
        let BronzeEventFamily::ParseAnomaly(ref a) = anomalies[0].family else {
            panic!();
        };
        assert_eq!(a.severity, "low");
        assert!(
            a.reason.contains("0xffff"),
            "reason should mention the code: {}",
            a.reason
        );

        let txns: Vec<_> = out
            .iter()
            .filter(|e| matches!(e.family, BronzeEventFamily::ProtocolTransaction(_)))
            .collect();
        assert_eq!(txns.len(), 1);
        let BronzeEventFamily::ProtocolTransaction(ref txn) = txns[0].family else {
            panic!();
        };
        assert_eq!(txn.operation, "csp_unknown_cmd_0xffff");
    }

    /// 5. packet_size field (200) disagrees with actual buffer length (50) →
    ///    ParseAnomaly with severity="medium".
    #[test]
    fn test_packet_size_mismatch_medium_anomaly() {
        let mut dec = AbCspDecoder;
        let mut out = Vec::new();
        // Build a 50-byte buffer but declare packet_size=200.
        let extra = vec![0u8; 50 - CSP_HEADER_LEN]; // 22 bytes of payload
        let frame = make_csp_frame(
            CMD_PCCC_REQUEST,
            0,
            Some(200), // declared size intentionally wrong
            0x06,
            7,
            0,
            0,
            &extra,
        );
        assert_eq!(frame.len(), 50);
        feed(&mut dec, &frame, &mut out);

        let anomalies: Vec<_> = out
            .iter()
            .filter(|e| matches!(e.family, BronzeEventFamily::ParseAnomaly(_)))
            .collect();
        assert_eq!(
            anomalies.len(),
            1,
            "expected exactly one medium ParseAnomaly"
        );
        let BronzeEventFamily::ParseAnomaly(ref a) = anomalies[0].family else {
            panic!();
        };
        assert_eq!(a.severity, "medium");
        assert!(
            a.reason.contains("200") && a.reason.contains("50"),
            "reason should mention both sizes: {}",
            a.reason
        );
    }

    /// Bonus: CSP Read With Offset (cmd=0x0007) → operation="csp_read".
    #[test]
    fn test_read_with_offset() {
        let mut dec = AbCspDecoder;
        let mut out = Vec::new();
        let frame = make_csp_frame(CMD_READ_WITH_OFFSET, 0, None, 0x01, 5, 0, 0, &[]);
        feed(&mut dec, &frame, &mut out);

        let txns: Vec<_> = out
            .iter()
            .filter(|e| matches!(e.family, BronzeEventFamily::ProtocolTransaction(_)))
            .collect();
        assert_eq!(txns.len(), 1);
        let BronzeEventFamily::ProtocolTransaction(ref txn) = txns[0].family else {
            panic!();
        };
        assert_eq!(txn.operation, "csp_read");
        assert_eq!(txn.status, "ok");
    }

    /// Truncated below 28 bytes → medium anomaly, no transaction.
    #[test]
    fn test_truncated_frame_below_header() {
        let mut dec = AbCspDecoder;
        let mut out = Vec::new();
        let short = vec![0x01, 0x00, 0x00, 0x00, 0x10, 0x00]; // 6 bytes — far too short
        feed(&mut dec, &short, &mut out);

        assert_eq!(out.len(), 1);
        let BronzeEventFamily::ParseAnomaly(ref a) = out[0].family else {
            panic!("expected ParseAnomaly for truncated frame");
        };
        assert_eq!(a.severity, "medium");
    }
}
