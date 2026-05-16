//! MELSEC SLMP (Seamless Message Protocol) — 4E binary frame decoder.
//!
//! Targets Mitsubishi iQ-R / iQ-F / Q series PLCs on TCP port 5007.
//!
//! **Subheader byte-order note:** the spec documents the subheader as a u16 LE
//! value, so `[0x54, 0x00]` on the wire reads as `0x0054` in code (request),
//! and `[0xD4, 0x00]` as `0x00D4` (response). SLMP is little-endian throughout,
//! which surprises readers expecting big-endian network order.

use std::collections::{BTreeMap, HashMap, HashSet};

use chrono::{DateTime, Utc};

use crate::bronze::{
    AssetObservation, BronzeEvent, BronzeEventFamily, EventEnvelope, MelsecBronzeFields,
    ProtocolFields, ProtocolTransaction, TransportProtocol,
};
use crate::engine::{
    DecoderInterest, SessionDecoder, StreamChunk, build_envelope, new_event, parse_anomaly_event,
};

// Wire-format constants — all u16 values are little-endian throughout SLMP.
const SUBHEADER_REQUEST: u16 = 0x0054; // wire: [0x54, 0x00]
const SUBHEADER_RESPONSE: u16 = 0x00D4; // wire: [0xD4, 0x00]
// Minimum frame: subheader(2)+serial(2)+reserved(2)+net(1)+pc(1)+io(2)+stn(1)+len(2) = 13.
const MIN_FRAME_LEN: usize = 13;
const OFF_SUBHEADER: usize = 0;
const OFF_SERIAL: usize = 2;
const OFF_NETWORK: usize = 6;
const OFF_PC: usize = 7;
// OFF_VARIABLE = 13: monitoring timer on request, end code on response.
const OFF_VARIABLE: usize = 13;
// Within request variable region: timer(2) | cmd(2) | subcmd(2).
const OFF_CMD_REL: usize = 2;
const OFF_SUBCMD_REL: usize = 4;

#[derive(Clone)]
struct PendingRequest {
    envelope: EventEnvelope,
    capture_id: String,
    serial_number: u16,
    network_number: u8,
    pc_number: u8,
    command: u16,
    subcommand: u16,
    operation: String,
    last_seen: DateTime<Utc>,
}

#[derive(Default)]
pub(crate) struct MelsecDecoder {
    /// Keyed by `"{session_key}:{serial_number}"` for request/response pairing.
    pending: HashMap<String, PendingRequest>,
    /// Tracks source IPs already emitted an AssetObservation for (dedup).
    observed_assets: HashSet<String>,
}

impl SessionDecoder for MelsecDecoder {
    fn name(&self) -> &'static str {
        "melsec"
    }

    fn interest(&self) -> &'static [DecoderInterest] {
        &[DecoderInterest::TcpPort(5007)]
    }

    fn on_stream_chunk(&mut self, chunk: &StreamChunk<'_>, out: &mut Vec<BronzeEvent>) {
        self.handle(chunk, out);
    }

    fn on_idle_flush(&mut self, timestamp: DateTime<Utc>, out: &mut Vec<BronzeEvent>) {
        // Flush unpaired requests on session teardown / timeout as "request_only".
        let expired: Vec<String> = self
            .pending
            .iter()
            .filter_map(|(k, req)| {
                if (timestamp - req.last_seen).num_seconds() >= 0 {
                    Some(k.clone())
                } else {
                    None
                }
            })
            .collect();

        for key in expired {
            if let Some(req) = self.pending.remove(&key) {
                out.push(new_event(
                    req.capture_id,
                    req.envelope,
                    BronzeEventFamily::ProtocolTransaction(ProtocolTransaction {
                        operation: req.operation,
                        status: "request_only".to_string(),
                        request_summary: None,
                        response_summary: None,
                        object_refs: Vec::new(),
                        values: Vec::new(),
                        attributes: base_attrs(
                            req.command,
                            req.subcommand,
                            req.serial_number,
                            req.network_number,
                            req.pc_number,
                        ),
                        modbus: None,
                        protocol_fields: Some(ProtocolFields::Melsec(MelsecBronzeFields {
                            serial_number: req.serial_number,
                            network_number: req.network_number,
                            pc_number: req.pc_number,
                            command: req.command,
                            subcommand: req.subcommand,
                            end_code: None,
                            direction: "request_only".to_string(),
                        })),
                    }),
                ));
            }
        }
    }
}

impl MelsecDecoder {
    fn handle(&mut self, chunk: &StreamChunk<'_>, out: &mut Vec<BronzeEvent>) {
        let payload = chunk.payload;
        if payload.len() < MIN_FRAME_LEN {
            // Too short for a valid SLMP header — common for TCP reassembly
            // fragments; discard silently rather than flood with anomalies.
            return;
        }

        // Read subheader as u16 LE. Bytes [0x54, 0x00] on the wire → 0x0054 in
        // code. See the module-level doc for why this isn't 0x5400.
        let subheader = u16::from_le_bytes([payload[OFF_SUBHEADER], payload[OFF_SUBHEADER + 1]]);
        let serial_number = u16::from_le_bytes([payload[OFF_SERIAL], payload[OFF_SERIAL + 1]]);
        let network_number = payload[OFF_NETWORK];
        let pc_number = payload[OFF_PC];

        match subheader {
            SUBHEADER_REQUEST => {
                self.handle_request(chunk, serial_number, network_number, pc_number, out);
            }
            SUBHEADER_RESPONSE => {
                self.handle_response(chunk, serial_number, network_number, pc_number, out);
            }
            _ => {
                // Could be a 3E frame, ASCII-mode frame, or corruption. Emit
                // medium severity because a valid SLMP binary client on port 5007
                // should never produce this.
                out.push(parse_anomaly_event(
                    chunk.capture_id.to_string(),
                    make_envelope(chunk),
                    "melsec",
                    "medium",
                    &format!(
                        "invalid SLMP subheader 0x{subheader:04x} (expected 0x0054 or 0x00D4)"
                    ),
                    payload,
                ));
            }
        }
    }

    fn handle_request(
        &mut self,
        chunk: &StreamChunk<'_>,
        serial_number: u16,
        network_number: u8,
        pc_number: u8,
        out: &mut Vec<BronzeEvent>,
    ) {
        let payload = chunk.payload;
        // Variable region must contain: timer(2) + command(2) + subcommand(2).
        if payload.len() < OFF_VARIABLE + 6 {
            out.push(parse_anomaly_event(
                chunk.capture_id.to_string(),
                make_envelope(chunk),
                "melsec",
                "medium",
                "SLMP request frame truncated before command field",
                payload,
            ));
            return;
        }

        let command = u16::from_le_bytes([
            payload[OFF_VARIABLE + OFF_CMD_REL],
            payload[OFF_VARIABLE + OFF_CMD_REL + 1],
        ]);
        let subcommand = u16::from_le_bytes([
            payload[OFF_VARIABLE + OFF_SUBCMD_REL],
            payload[OFF_VARIABLE + OFF_SUBCMD_REL + 1],
        ]);

        let operation = slmp_operation_name(command, subcommand);

        // Low-severity anomaly for unrecognised commands. We still store pending
        // state so the response can pair and carry the "unknown" operation label.
        if operation.contains("unknown") {
            out.push(parse_anomaly_event(
                chunk.capture_id.to_string(),
                make_envelope(chunk),
                "melsec",
                "low",
                &format!("unknown SLMP command 0x{command:04x} subcommand 0x{subcommand:04x}"),
                payload,
            ));
        }

        let key = pending_key(&chunk.session_key, serial_number);
        self.pending.insert(
            key,
            PendingRequest {
                envelope: make_envelope(chunk),
                capture_id: chunk.capture_id.to_string(),
                serial_number,
                network_number,
                pc_number,
                command,
                subcommand,
                operation,
                last_seen: chunk.timestamp,
            },
        );
    }

    fn handle_response(
        &mut self,
        chunk: &StreamChunk<'_>,
        serial_number: u16,
        network_number: u8,
        pc_number: u8,
        out: &mut Vec<BronzeEvent>,
    ) {
        let payload = chunk.payload;
        // Variable region on a response starts with the 2-byte end code.
        if payload.len() < OFF_VARIABLE + 2 {
            out.push(parse_anomaly_event(
                chunk.capture_id.to_string(),
                make_envelope(chunk),
                "melsec",
                "medium",
                "SLMP response frame truncated before end code",
                payload,
            ));
            return;
        }

        let end_code = u16::from_le_bytes([payload[OFF_VARIABLE], payload[OFF_VARIABLE + 1]]);
        let key = pending_key(&chunk.session_key, serial_number);

        if let Some(req) = self.pending.remove(&key) {
            let status = if end_code == 0 {
                "ok".to_string()
            } else {
                format!("slmp_error_0x{end_code:04x}")
            };

            let mut attrs = base_attrs(
                req.command,
                req.subcommand,
                req.serial_number,
                req.network_number,
                req.pc_number,
            );
            attrs.insert("end_code".to_string(), format!("0x{end_code:04x}"));

            // Merge byte counts from both directions into a single envelope.
            let mut envelope = req.envelope.clone();
            envelope.bytes_count += make_envelope(chunk).bytes_count;
            envelope.packet_count += 1;

            let melsec_direction = status.clone();
            out.push(new_event(
                req.capture_id.clone(),
                envelope.clone(),
                BronzeEventFamily::ProtocolTransaction(ProtocolTransaction {
                    operation: req.operation.clone(),
                    status,
                    request_summary: None,
                    response_summary: None,
                    object_refs: Vec::new(),
                    values: Vec::new(),
                    attributes: attrs,
                    modbus: None,
                    protocol_fields: Some(ProtocolFields::Melsec(MelsecBronzeFields {
                        serial_number: req.serial_number,
                        network_number: req.network_number,
                        pc_number: req.pc_number,
                        command: req.command,
                        subcommand: req.subcommand,
                        end_code: Some(end_code),
                        direction: melsec_direction,
                    })),
                }),
            ));

            // For a successful Read CPU Model (0x0101) response, emit an
            // AssetObservation once per source IP. The response payload after the
            // end code holds a 16-byte null-padded ASCII CPU model name.
            if req.command == 0x0101 && end_code == 0 {
                let src_ip = chunk.context.src_ip.to_string();
                if self.observed_assets.insert(src_ip.clone()) {
                    let model = parse_cpu_model_name(payload);
                    out.push(emit_asset_observation(
                        req.capture_id,
                        envelope,
                        src_ip,
                        model,
                    ));
                }
            }
        } else {
            // No matching request — mid-stream capture or retransmit.
            let mut attrs = BTreeMap::new();
            attrs.insert("serial_number".to_string(), serial_number.to_string());
            attrs.insert("network_number".to_string(), network_number.to_string());
            attrs.insert("pc_number".to_string(), pc_number.to_string());
            attrs.insert("end_code".to_string(), format!("0x{end_code:04x}"));

            out.push(new_event(
                chunk.capture_id.to_string(),
                make_envelope(chunk),
                BronzeEventFamily::ProtocolTransaction(ProtocolTransaction {
                    operation: "slmp_response".to_string(),
                    status: "response_only".to_string(),
                    request_summary: None,
                    response_summary: None,
                    object_refs: Vec::new(),
                    values: Vec::new(),
                    attributes: attrs,
                    modbus: None,
                    protocol_fields: Some(ProtocolFields::Melsec(MelsecBronzeFields {
                        serial_number,
                        network_number,
                        pc_number,
                        command: 0,
                        subcommand: 0,
                        end_code: Some(end_code),
                        direction: "response_only".to_string(),
                    })),
                }),
            ));
        }
    }
}

// ── Helpers ───────────────────────────────────────────────────────────────────

fn pending_key(session_key: &str, serial_number: u16) -> String {
    format!("{session_key}:{serial_number}")
}

fn make_envelope(chunk: &StreamChunk<'_>) -> EventEnvelope {
    build_envelope(
        &chunk.context,
        chunk.interface_id,
        chunk.frame_index,
        chunk.timestamp,
        chunk.segment_hash,
        TransportProtocol::Tcp,
        Some("melsec"),
        chunk.captured_len,
        chunk.session_key.clone(),
    )
}

fn base_attrs(
    command: u16,
    subcommand: u16,
    serial_number: u16,
    network_number: u8,
    pc_number: u8,
) -> BTreeMap<String, String> {
    let mut m = BTreeMap::new();
    m.insert("command".to_string(), format!("0x{command:04x}"));
    m.insert("subcommand".to_string(), format!("0x{subcommand:04x}"));
    m.insert("serial_number".to_string(), serial_number.to_string());
    m.insert("network_number".to_string(), network_number.to_string());
    m.insert("pc_number".to_string(), pc_number.to_string());
    m
}

/// Map (command, subcommand) → stable snake_case operation label.
///
/// Subcommand 0x0001 = word units, 0x0003 = bit units. Commands that don't
/// use subcommands (remote operations, CPU model read) wildcard-match on `_`.
fn slmp_operation_name(command: u16, subcommand: u16) -> String {
    match (command, subcommand) {
        (0x0401, 0x0001) => "slmp_batch_read_word".to_string(),
        (0x0401, 0x0003) => "slmp_batch_read_bit".to_string(),
        (0x1401, 0x0001) => "slmp_batch_write_word".to_string(),
        (0x1401, 0x0003) => "slmp_batch_write_bit".to_string(),
        (0x0403, _) => "slmp_random_read".to_string(),
        (0x1402, _) => "slmp_random_write".to_string(),
        (0x041C, _) => "slmp_block_read".to_string(),
        (0x141C, _) => "slmp_block_write".to_string(),
        (0x1810, _) => "slmp_remote_run".to_string(),
        (0x1811, _) => "slmp_remote_stop".to_string(),
        (0x1812, _) => "slmp_remote_pause".to_string(),
        (0x1813, _) => "slmp_remote_latch_clear".to_string(),
        (0x1814, _) => "slmp_remote_reset".to_string(),
        (0x0101, _) => "slmp_read_cpu_model".to_string(),
        _ => format!("slmp_unknown_0x{command:04x}_sub_0x{subcommand:04x}"),
    }
}

/// Extract the CPU model name from a Read CPU Model (0x0101) response payload.
///
/// Payload layout after the end code: 16-byte ASCII model name (null-padded),
/// then a 2-byte model code (ignored here). We strip null bytes and trim
/// surrounding whitespace.
fn parse_cpu_model_name(payload: &[u8]) -> String {
    let start = OFF_VARIABLE + 2; // skip end code
    let end = (start + 16).min(payload.len());
    if start >= end {
        return "unknown".to_string();
    }
    let s: Vec<u8> = payload[start..end]
        .iter()
        .copied()
        .take_while(|&b| b != 0)
        .collect();
    String::from_utf8_lossy(&s).trim().to_string()
}

fn emit_asset_observation(
    capture_id: String,
    envelope: EventEnvelope,
    asset_ip: String,
    model: String,
) -> BronzeEvent {
    let mut identifiers = BTreeMap::new();
    identifiers.insert("ip".to_string(), asset_ip.clone());

    new_event(
        capture_id,
        envelope,
        BronzeEventFamily::AssetObservation(AssetObservation {
            asset_key: asset_ip,
            role: Some("mitsubishi_plc".to_string()),
            vendor: Some("Mitsubishi".to_string()),
            model: Some(model),
            firmware: None,
            hostnames: Vec::new(),
            protocols: vec!["melsec".to_string()],
            identifiers,
        }),
    )
}

// ── Registration ──────────────────────────────────────────────────────────────

inventory::submit!(crate::engine::decoders::DecoderRegistration {
    name: "melsec",
    factory: || Box::new(MelsecDecoder::default()),
});

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use std::net::{IpAddr, Ipv4Addr};

    use crate::registry::PacketContext;

    // ── Frame builders ────────────────────────────────────────────────────────

    // Builds a minimal 4E request: subheader|serial|reserved|net|pc|io|stn|len|timer|cmd|sub|extra
    fn make_request(serial: u16, net: u8, pc: u8, cmd: u16, sub: u16, extra: &[u8]) -> Vec<u8> {
        let data_len = 6u16 + extra.len() as u16;
        let mut buf = Vec::with_capacity(19 + extra.len());
        buf.extend_from_slice(&SUBHEADER_REQUEST.to_le_bytes());
        buf.extend_from_slice(&serial.to_le_bytes());
        buf.extend_from_slice(&0x0000u16.to_le_bytes()); // reserved
        buf.push(net);
        buf.push(pc);
        buf.extend_from_slice(&0x03FFu16.to_le_bytes()); // module I/O
        buf.push(0x00); // station
        buf.extend_from_slice(&data_len.to_le_bytes());
        buf.extend_from_slice(&0x0010u16.to_le_bytes()); // monitoring timer
        buf.extend_from_slice(&cmd.to_le_bytes());
        buf.extend_from_slice(&sub.to_le_bytes());
        buf.extend_from_slice(extra);
        buf
    }

    // Builds a minimal 4E response: same header fields, then end_code(2) + extra.
    fn make_response(serial: u16, net: u8, pc: u8, end_code: u16, extra: &[u8]) -> Vec<u8> {
        let data_len = 2u16 + extra.len() as u16;
        let mut buf = Vec::with_capacity(15 + extra.len());
        buf.extend_from_slice(&SUBHEADER_RESPONSE.to_le_bytes());
        buf.extend_from_slice(&serial.to_le_bytes());
        buf.extend_from_slice(&0x0000u16.to_le_bytes());
        buf.push(net);
        buf.push(pc);
        buf.extend_from_slice(&0x03FFu16.to_le_bytes());
        buf.push(0x00);
        buf.extend_from_slice(&data_len.to_le_bytes());
        buf.extend_from_slice(&end_code.to_le_bytes());
        buf.extend_from_slice(extra);
        buf
    }

    fn make_chunk<'a>(
        payload: &'a [u8],
        src_port: u16,
        dst_port: u16,
        session: &str,
    ) -> StreamChunk<'a> {
        StreamChunk {
            capture_id: "test_cap",
            segment_hash: "deadbeef",
            interface_id: 0,
            frame_index: 1,
            timestamp: Utc::now(),
            context: PacketContext {
                src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
                dst_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
                src_port,
                dst_port,
                src_mac: [0u8; 6],
                dst_mac: [0u8; 6],
                vlan_id: None,
                timestamp: 0,
            },
            ethertype: 0x0800,
            ip_proto: Some(6),
            llc: None,
            transport: TransportProtocol::Tcp,
            payload,
            session_key: session.to_string(),
            captured_len: payload.len() as u64,
        }
    }

    // ── Test 1: request alone → no events ────────────────────────────────────

    #[test]
    fn test_batch_read_word_request_alone_no_event() {
        let mut dec = MelsecDecoder::default();
        let mut out = Vec::new();
        let frame = make_request(0x0001, 0x00, 0xFF, 0x0401, 0x0001, &[]);
        dec.on_stream_chunk(&make_chunk(&frame, 55000, 5007, "sess-1"), &mut out);
        assert!(
            out.is_empty(),
            "request alone must not emit; got {} events",
            out.len()
        );
        assert_eq!(dec.pending.len(), 1);
    }

    // ── Test 2: Batch Read request + response end_code=0 → ok ────────────────

    #[test]
    fn test_batch_read_word_paired_ok() {
        let mut dec = MelsecDecoder::default();
        let mut out = Vec::new();
        let sess = "sess-2";
        let req = make_request(0x0002, 0x00, 0xFF, 0x0401, 0x0001, &[]);
        dec.on_stream_chunk(&make_chunk(&req, 55000, 5007, sess), &mut out);
        assert!(out.is_empty());

        let resp = make_response(0x0002, 0x00, 0xFF, 0x0000, &[0x01, 0x00, 0x02, 0x00]);
        dec.on_stream_chunk(&make_chunk(&resp, 5007, 55000, sess), &mut out);

        assert_eq!(out.len(), 1);
        let BronzeEventFamily::ProtocolTransaction(ref txn) = out[0].family else {
            panic!("expected ProtocolTransaction");
        };
        assert_eq!(txn.operation, "slmp_batch_read_word");
        assert_eq!(txn.status, "ok");
        assert!(dec.pending.is_empty());
    }

    // ── Test 3: Batch Write + end_code=0xC059 → error status ─────────────────

    #[test]
    fn test_batch_write_word_error_status() {
        let mut dec = MelsecDecoder::default();
        let mut out = Vec::new();
        let sess = "sess-3";
        let req = make_request(0x0003, 0x00, 0xFF, 0x1401, 0x0001, &[]);
        dec.on_stream_chunk(&make_chunk(&req, 55001, 5007, sess), &mut out);
        let resp = make_response(0x0003, 0x00, 0xFF, 0xC059, &[]);
        dec.on_stream_chunk(&make_chunk(&resp, 5007, 55001, sess), &mut out);

        assert_eq!(out.len(), 1);
        let BronzeEventFamily::ProtocolTransaction(ref txn) = out[0].family else {
            panic!("expected ProtocolTransaction");
        };
        assert_eq!(txn.operation, "slmp_batch_write_word");
        assert_eq!(txn.status, "slmp_error_0xc059");
    }

    // ── Test 4: Read CPU Model → AssetObservation with model name ─────────────

    #[test]
    fn test_read_cpu_model_emits_asset_observation() {
        let mut dec = MelsecDecoder::default();
        let mut out = Vec::new();
        let sess = "sess-4";

        let req = make_request(0x0004, 0x00, 0xFF, 0x0101, 0x0000, &[]);
        dec.on_stream_chunk(&make_chunk(&req, 55002, 5007, sess), &mut out);
        assert!(out.is_empty());

        // 16-byte null-padded model name + 2-byte model code.
        let mut model_data = b"Q03UDV CPU\x00\x00\x00\x00\x00\x00".to_vec();
        model_data.extend_from_slice(&[0x04, 0x00]); // model code (ignored)
        let resp = make_response(0x0004, 0x00, 0xFF, 0x0000, &model_data);
        dec.on_stream_chunk(&make_chunk(&resp, 5007, 55002, sess), &mut out);

        assert_eq!(out.len(), 2, "expected transaction + asset observation");
        let obs_ev = out
            .iter()
            .find(|e| matches!(e.family, BronzeEventFamily::AssetObservation(_)))
            .expect("AssetObservation missing");
        let BronzeEventFamily::AssetObservation(ref obs) = obs_ev.family else {
            unreachable!()
        };
        assert_eq!(obs.vendor.as_deref(), Some("Mitsubishi"));
        assert_eq!(obs.role.as_deref(), Some("mitsubishi_plc"));
        let model = obs.model.as_deref().unwrap_or("");
        assert!(
            model.starts_with("Q03UDV"),
            "expected 'Q03UDV...', got '{model}'"
        );
    }

    // ── Test 5: Remote Run → operation="slmp_remote_run" ─────────────────────

    #[test]
    fn test_remote_run_operation_name() {
        let mut dec = MelsecDecoder::default();
        let mut out = Vec::new();
        let sess = "sess-5";
        let req = make_request(0x0005, 0x00, 0xFF, 0x1810, 0x0000, &[]);
        dec.on_stream_chunk(&make_chunk(&req, 55003, 5007, sess), &mut out);
        let resp = make_response(0x0005, 0x00, 0xFF, 0x0000, &[]);
        dec.on_stream_chunk(&make_chunk(&resp, 5007, 55003, sess), &mut out);

        assert_eq!(out.len(), 1);
        let BronzeEventFamily::ProtocolTransaction(ref txn) = out[0].family else {
            panic!("expected ProtocolTransaction");
        };
        assert_eq!(txn.operation, "slmp_remote_run");
        assert_eq!(txn.status, "ok");
    }

    // ── Test 6: Unknown command → ParseAnomaly(low) + operation has "unknown" ─

    #[test]
    fn test_unknown_command_emits_anomaly_and_unknown_operation() {
        let mut dec = MelsecDecoder::default();
        let mut out = Vec::new();
        let sess = "sess-6";

        let req = make_request(0x0006, 0x00, 0xFF, 0x9999, 0x0000, &[]);
        dec.on_stream_chunk(&make_chunk(&req, 55004, 5007, sess), &mut out);

        assert_eq!(out.len(), 1, "anomaly expected after unknown request");
        let BronzeEventFamily::ParseAnomaly(ref a) = out[0].family else {
            panic!("expected ParseAnomaly");
        };
        assert_eq!(a.severity, "low");
        assert!(
            a.reason.contains("unknown") || a.reason.contains("0x9999"),
            "reason should mention unknown command: {}",
            a.reason
        );

        let resp = make_response(0x0006, 0x00, 0xFF, 0x0000, &[]);
        dec.on_stream_chunk(&make_chunk(&resp, 5007, 55004, sess), &mut out);

        let txn_ev = out
            .iter()
            .find(|e| matches!(e.family, BronzeEventFamily::ProtocolTransaction(_)))
            .expect("ProtocolTransaction missing");
        let BronzeEventFamily::ProtocolTransaction(ref txn) = txn_ev.family else {
            unreachable!()
        };
        assert!(
            txn.operation.contains("unknown"),
            "operation must contain 'unknown', got '{}'",
            txn.operation
        );
    }
}
