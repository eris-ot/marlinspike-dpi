//! TFTP (RFC 1350) session decoder — UDP port 69.
//!
//! Catches RRQ/WRQ request openers on port 69. Per-block DATA/ACK noise on
//! ephemeral ports is intentionally out of scope; those are not visible here
//! and would flood telemetry with no diagnostic value.

use std::collections::BTreeMap;

use crate::bronze::{
    AssetObservation, BronzeEvent, BronzeEventFamily, ProtocolTransaction, TransportProtocol,
};
use crate::engine::{
    DecoderInterest, SessionDecoder, StreamChunk, build_envelope, new_event, parse_anomaly_event,
};

const OP_RRQ: u16 = 1;
const OP_WRQ: u16 = 2;
const OP_DATA: u16 = 3;
const OP_ACK: u16 = 4;
const OP_ERROR: u16 = 5;

/// Filename substrings that signal a firmware payload in a WRQ.
///
/// Unauthorized firmware substitution via TFTP is a documented OT attack
/// technique: a WRQ with no authentication can silently overwrite PLC or
/// switch firmware. We emit a high-severity ParseAnomaly so analysts can
/// correlate with approved change windows and investigate unexpected writes.
const FIRMWARE_SIGNALS: &[&str] = &[".bin", ".hex", ".elf", ".fw", "firmware", ".rom", ".img"];

// ── Decoder ───────────────────────────────────────────────────────────────────

#[derive(Default)]
pub(crate) struct TftpDecoder;

impl SessionDecoder for TftpDecoder {
    fn name(&self) -> &'static str {
        "tftp"
    }

    fn interest(&self) -> &'static [DecoderInterest] {
        &[DecoderInterest::UdpPort(69)]
    }

    fn on_datagram(&mut self, chunk: &StreamChunk<'_>, out: &mut Vec<BronzeEvent>) {
        let p = chunk.payload;
        if p.len() < 2 {
            out.push(anomaly(chunk, "low", "tftp packet too short", p));
            return;
        }
        let opcode = u16::from_be_bytes([p[0], p[1]]);
        match opcode {
            OP_RRQ | OP_WRQ => decode_request(chunk, opcode, out),
            OP_ERROR => decode_error(chunk, out),
            OP_DATA | OP_ACK => out.push(anomaly(
                chunk,
                "low",
                "tftp DATA/ACK unexpected on port 69",
                p,
            )),
            n => {
                let env = envelope(chunk);
                out.push(new_event(
                    chunk.capture_id.to_string(),
                    env,
                    BronzeEventFamily::ProtocolTransaction(ProtocolTransaction {
                        operation: format!("tftp_unknown_opcode_{n}"),
                        status: "observed".to_string(),
                        request_summary: Some(format!("Unknown TFTP opcode {n}")),
                        response_summary: None,
                        object_refs: vec![],
                        values: vec![],
                        attributes: BTreeMap::new(),
                        modbus: None,
                        protocol_fields: None,
                    }),
                ));
            }
        }
    }
}

// ── RRQ / WRQ ────────────────────────────────────────────────────────────────

fn decode_request(chunk: &StreamChunk<'_>, opcode: u16, out: &mut Vec<BronzeEvent>) {
    let body = &chunk.payload[2..];

    let (filename, rest) = match cstr(body) {
        Some(v) => v,
        None => {
            out.push(anomaly(
                chunk,
                "low",
                "tftp RRQ/WRQ missing null terminator on filename",
                chunk.payload,
            ));
            return;
        }
    };
    let (mode, _) = match cstr(rest) {
        Some(v) => v,
        None => {
            out.push(anomaly(
                chunk,
                "low",
                "tftp RRQ/WRQ missing null terminator on mode",
                chunk.payload,
            ));
            return;
        }
    };

    let is_write = opcode == OP_WRQ;
    let operation = if is_write { "tftp_write" } else { "tftp_read" }.to_string();
    let mut attrs = BTreeMap::new();
    attrs.insert("filename".to_string(), filename.clone());
    attrs.insert("mode".to_string(), mode.clone());
    let env = envelope(chunk);

    out.push(new_event(
        chunk.capture_id.to_string(),
        env.clone(),
        BronzeEventFamily::ProtocolTransaction(ProtocolTransaction {
            operation,
            status: "observed".to_string(),
            request_summary: Some(format!(
                "TFTP {} {} mode={}",
                if is_write { "WRQ" } else { "RRQ" },
                filename,
                mode
            )),
            response_summary: None,
            object_refs: vec![filename.clone()],
            values: vec![],
            attributes: attrs,
            modbus: None,
            protocol_fields: None,
        }),
    ));

    // Firmware-push heuristic: WRQ → firmware-shaped filename.
    // See FIRMWARE_SIGNALS doc for threat context.
    if is_write && looks_like_firmware(&filename) {
        out.push(anomaly(
            chunk,
            "high",
            "TFTP firmware-shaped WRQ observed — potential unauthorized firmware push",
            chunk.payload,
        ));
    }

    // The destination is the TFTP server (accepts the RRQ/WRQ).
    let server_ip = chunk.context.dst_ip.to_string();
    out.push(new_event(
        chunk.capture_id.to_string(),
        env,
        BronzeEventFamily::AssetObservation(AssetObservation {
            asset_key: server_ip.clone(),
            role: Some("tftp_server".to_string()),
            vendor: None,
            model: None,
            firmware: None,
            hostnames: vec![],
            protocols: vec!["tftp".to_string()],
            identifiers: BTreeMap::from([("ip".to_string(), server_ip)]),
        }),
    ));
}

// ── ERROR ─────────────────────────────────────────────────────────────────────

fn decode_error(chunk: &StreamChunk<'_>, out: &mut Vec<BronzeEvent>) {
    let p = chunk.payload;
    if p.len() < 5 {
        out.push(anomaly(chunk, "low", "tftp ERROR packet too short", p));
        return;
    }
    let error_code = u16::from_be_bytes([p[2], p[3]]);
    let msg = cstr(&p[4..])
        .map(|(s, _)| s)
        .unwrap_or_else(|| String::from_utf8_lossy(&p[4..]).into_owned());

    let mut attrs = BTreeMap::new();
    attrs.insert("error_code".to_string(), error_code.to_string());
    attrs.insert("error_message".to_string(), msg.clone());

    out.push(new_event(
        chunk.capture_id.to_string(),
        envelope(chunk),
        BronzeEventFamily::ProtocolTransaction(ProtocolTransaction {
            operation: "tftp_error".to_string(),
            status: format!("tftp_error_{error_code}"),
            request_summary: Some(format!("TFTP ERROR {error_code}: {msg}")),
            response_summary: None,
            object_refs: vec![],
            values: vec![],
            attributes: attrs,
            modbus: None,
            protocol_fields: None,
        }),
    ));
}

// ── Helpers ───────────────────────────────────────────────────────────────────

fn cstr(buf: &[u8]) -> Option<(String, &[u8])> {
    let n = buf.iter().position(|&b| b == 0)?;
    Some((
        String::from_utf8_lossy(&buf[..n]).into_owned(),
        &buf[n + 1..],
    ))
}

fn looks_like_firmware(name: &str) -> bool {
    let l = name.to_lowercase();
    FIRMWARE_SIGNALS.iter().any(|s| l.contains(s))
}

fn envelope(chunk: &StreamChunk<'_>) -> crate::bronze::EventEnvelope {
    build_envelope(
        &chunk.context,
        chunk.interface_id,
        chunk.frame_index,
        chunk.timestamp,
        chunk.segment_hash,
        TransportProtocol::Udp,
        Some("tftp"),
        chunk.captured_len,
        chunk.session_key.clone(),
    )
}

fn anomaly(chunk: &StreamChunk<'_>, severity: &str, reason: &str, raw: &[u8]) -> BronzeEvent {
    parse_anomaly_event(
        chunk.capture_id.to_string(),
        envelope(chunk),
        "tftp",
        severity,
        reason,
        raw,
    )
}

// ── Registration ──────────────────────────────────────────────────────────────

inventory::submit!(crate::engine::decoders::DecoderRegistration {
    name: "tftp",
    factory: || Box::new(TftpDecoder),
});

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bronze::BronzeEventFamily;
    use crate::engine::{DecoderInterest, SessionDecoder, StreamChunk};
    use crate::registry::PacketContext;
    use chrono::Utc;
    use std::net::{IpAddr, Ipv4Addr};

    const CLIENT: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 5);
    const SERVER: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 1);

    fn chunk(payload: &[u8]) -> StreamChunk<'_> {
        StreamChunk {
            capture_id: "cap",
            segment_hash: "seg",
            interface_id: 0,
            frame_index: 1,
            timestamp: Utc::now(),
            context: PacketContext {
                src_mac: [0u8; 6],
                dst_mac: [0u8; 6],
                src_ip: IpAddr::V4(CLIENT),
                dst_ip: IpAddr::V4(SERVER),
                src_port: 49152,
                dst_port: 69,
                vlan_id: None,
                timestamp: 0,
            },
            ethertype: 0x0800,
            ip_proto: Some(17),
            llc: None,
            transport: TransportProtocol::Udp,
            payload,
            session_key: "s".into(),
            captured_len: payload.len() as u64,
        }
    }

    fn req(op: u16, file: &str, mode: &str) -> Vec<u8> {
        let mut b = op.to_be_bytes().to_vec();
        b.extend_from_slice(file.as_bytes());
        b.push(0);
        b.extend_from_slice(mode.as_bytes());
        b.push(0);
        b
    }

    fn err_pkt(code: u16, msg: &str) -> Vec<u8> {
        let mut b = 5u16.to_be_bytes().to_vec();
        b.extend_from_slice(&code.to_be_bytes());
        b.extend_from_slice(msg.as_bytes());
        b.push(0);
        b
    }

    fn run(payload: &[u8]) -> Vec<BronzeEvent> {
        let c = chunk(payload);
        let mut d = TftpDecoder;
        let mut out = Vec::new();
        d.on_datagram(&c, &mut out);
        out
    }

    fn find_tx(events: &[BronzeEvent]) -> Option<&crate::bronze::ProtocolTransaction> {
        events.iter().find_map(|e| {
            if let BronzeEventFamily::ProtocolTransaction(t) = &e.family {
                Some(t)
            } else {
                None
            }
        })
    }

    fn find_anomaly(events: &[BronzeEvent]) -> Option<&crate::bronze::ParseAnomaly> {
        events.iter().find_map(|e| {
            if let BronzeEventFamily::ParseAnomaly(a) = &e.family {
                Some(a)
            } else {
                None
            }
        })
    }

    // 1. RRQ "config.txt" octet → tftp_read, filename+mode attributes, object_refs
    #[test]
    fn rrq_config_txt() {
        let events = run(&req(OP_RRQ, "config.txt", "octet"));
        let tx = find_tx(&events).expect("ProtocolTransaction");
        assert_eq!(tx.operation, "tftp_read");
        assert_eq!(tx.status, "observed");
        assert_eq!(
            tx.attributes.get("filename").map(String::as_str),
            Some("config.txt")
        );
        assert_eq!(tx.attributes.get("mode").map(String::as_str), Some("octet"));
        assert_eq!(tx.object_refs, vec!["config.txt"]);
    }

    // 2. WRQ "firmware.bin" → tftp_write + high ParseAnomaly with firmware reason
    #[test]
    fn wrq_firmware_bin_triggers_anomaly() {
        let events = run(&req(OP_WRQ, "firmware.bin", "octet"));
        assert_eq!(find_tx(&events).expect("tx").operation, "tftp_write");
        let a = find_anomaly(&events).expect("ParseAnomaly");
        assert_eq!(a.severity, "high");
        assert!(a.reason.contains("firmware"), "reason: {}", a.reason);
    }

    // 3. ERROR code 1 → tftp_error, status="tftp_error_1", attributes set
    #[test]
    fn error_packet() {
        let events = run(&err_pkt(1, "File not found"));
        let tx = find_tx(&events).expect("tx");
        assert_eq!(tx.operation, "tftp_error");
        assert_eq!(tx.status, "tftp_error_1");
        assert_eq!(
            tx.attributes.get("error_code").map(String::as_str),
            Some("1")
        );
        assert_eq!(
            tx.attributes.get("error_message").map(String::as_str),
            Some("File not found")
        );
    }

    // 4. WRQ "report.txt" → tftp_write, no firmware anomaly
    #[test]
    fn wrq_report_txt_no_firmware_alert() {
        let events = run(&req(OP_WRQ, "report.txt", "octet"));
        assert_eq!(find_tx(&events).expect("tx").operation, "tftp_write");
        assert!(
            !events.iter().any(|e| {
                matches!(&e.family, BronzeEventFamily::ParseAnomaly(a) if a.severity == "high")
            }),
            "report.txt must not trigger firmware alert"
        );
    }

    // 5. AssetObservation for server IP with role="tftp_server"
    #[test]
    fn asset_observation_for_server() {
        let events = run(&req(OP_RRQ, "config.txt", "octet"));
        let asset = events
            .iter()
            .find_map(|e| {
                if let BronzeEventFamily::AssetObservation(a) = &e.family {
                    Some(a)
                } else {
                    None
                }
            })
            .expect("AssetObservation");
        assert_eq!(asset.role.as_deref(), Some("tftp_server"));
        assert_eq!(asset.asset_key, SERVER.to_string());
    }

    // 6. Malformed RRQ (no null terminator) → low-severity ParseAnomaly
    #[test]
    fn malformed_rrq_no_null() {
        let mut p = OP_RRQ.to_be_bytes().to_vec();
        p.extend_from_slice(b"config.txt_no_null"); // no null — malformed
        let events = run(&p);
        assert_eq!(find_anomaly(&events).expect("ParseAnomaly").severity, "low");
    }

    // 7. Decoder interest must include UDP/69
    #[test]
    fn interest_udp_69() {
        assert!(
            TftpDecoder
                .interest()
                .contains(&DecoderInterest::UdpPort(69))
        );
    }
}
