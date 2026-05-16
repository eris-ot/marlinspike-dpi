//! AMQP 1.0 session decoder (OASIS standard).
//!
//! Covers plaintext port 5672 and TLS-wrapped port 5671. Used in OT for:
//! OPC UA PubSub broker fan-out, Azure IoT Hub, AWS IoT Core, Solace appliances.
//!
//! # Wire format summary
//!
//! **Protocol header** (8 bytes, sent first by each peer):
//!   `b"AMQP" | protocol_id(1) | major(1) | minor(1) | revision(1)`
//!
//! **Frame layout** (after the protocol header):
//!   `size(4 BE) | doff(1) | type(1) | channel_or_reserved(2) | extended_hdr(doff*4-8) | body`
//!
//! **Performative encoding** — AMQP uses the "described type" encoding from the
//! AMQP type system. Every performative body starts with the three-byte sequence:
//!   `0x00          ` — format code: descriptor follows
//!   `0x53          ` — small ulong (1-byte value)
//!   `0x<code>      ` — performative code (e.g. 0x10 = OPEN, 0x14 = TRANSFER)
//!
//! SASL performatives use the same described-type prefix but different codes
//! (0x40–0x44) and appear in type=1 frames.

use std::collections::BTreeMap;

use crate::bronze::TransportProtocol;
use crate::bronze::{AssetObservation, BronzeEvent, BronzeEventFamily, ProtocolTransaction};
use crate::engine::{
    DecoderInterest, SessionDecoder, StreamChunk, build_envelope, new_event, parse_anomaly_event,
};

// ── Performative code constants ───────────────────────────────────────────────

/// AMQP performative codes (byte following `0x00 0x53` in frame body).
const PERF_OPEN: u8 = 0x10;
const PERF_BEGIN: u8 = 0x11;
const PERF_ATTACH: u8 = 0x12;
const PERF_FLOW: u8 = 0x13;
const PERF_TRANSFER: u8 = 0x14;
const PERF_DISPOSITION: u8 = 0x15;
const PERF_DETACH: u8 = 0x16;
const PERF_END: u8 = 0x17;
const PERF_CLOSE: u8 = 0x18;

/// SASL performative codes (frame type=1).
const SASL_MECHANISMS: u8 = 0x40;
const SASL_INIT: u8 = 0x41;
const SASL_CHALLENGE: u8 = 0x42;
const SASL_RESPONSE: u8 = 0x43;
const SASL_OUTCOME: u8 = 0x44;

// ── Decoder state ─────────────────────────────────────────────────────────────

#[derive(Default)]
pub(crate) struct AmqpDecoder {
    /// True once the first OPEN performative has been emitted for this session,
    /// so we emit the broker AssetObservation only once.
    open_emitted: bool,
}

impl SessionDecoder for AmqpDecoder {
    fn name(&self) -> &'static str {
        "amqp"
    }

    fn interest(&self) -> &'static [DecoderInterest] {
        &[
            DecoderInterest::TcpPort(5672), // AMQP plaintext
            DecoderInterest::TcpPort(5671), // AMQP over TLS
        ]
    }

    fn on_stream_chunk(&mut self, chunk: &StreamChunk<'_>, out: &mut Vec<BronzeEvent>) {
        let payload = chunk.payload;
        if payload.is_empty() {
            return;
        }

        // ── TLS port (5671): payload is opaque, emit a single session record ──
        if chunk.context.dst_port == 5671 || chunk.context.src_port == 5671 {
            if !self.open_emitted {
                self.open_emitted = true;
                let mut attributes = BTreeMap::new();
                attributes.insert(
                    "note".to_string(),
                    "TLS-encrypted, payload opaque".to_string(),
                );
                let envelope = build_envelope(
                    &chunk.context,
                    chunk.interface_id,
                    chunk.frame_index,
                    chunk.timestamp,
                    chunk.segment_hash,
                    TransportProtocol::Tcp,
                    Some("amqp"),
                    chunk.captured_len,
                    chunk.session_key.clone(),
                );
                out.push(new_event(
                    chunk.capture_id.to_string(),
                    envelope,
                    BronzeEventFamily::ProtocolTransaction(ProtocolTransaction {
                        operation: "amqp_tls_session".to_string(),
                        status: "observed".to_string(),
                        request_summary: None,
                        response_summary: None,
                        object_refs: Vec::new(),
                        values: Vec::new(),
                        attributes,
                        modbus: None,
                        protocol_fields: None,
                    }),
                ));
            }
            return;
        }

        // ── Plaintext port 5672 ───────────────────────────────────────────────

        // Check for 8-byte AMQP protocol header: b"AMQP" | proto_id | 1 | 0 | 0
        if payload.len() >= 8 && &payload[0..4] == b"AMQP" {
            let proto_id = payload[4];
            let major = payload[5];
            let minor = payload[6];
            let revision = payload[7];

            // Validate version bytes; emit anomaly if major != 1 (AMQP 1.0)
            if major != 1 {
                let envelope = build_envelope(
                    &chunk.context,
                    chunk.interface_id,
                    chunk.frame_index,
                    chunk.timestamp,
                    chunk.segment_hash,
                    TransportProtocol::Tcp,
                    Some("amqp"),
                    chunk.captured_len,
                    chunk.session_key.clone(),
                );
                out.push(parse_anomaly_event(
                    chunk.capture_id.to_string(),
                    envelope,
                    self.name(),
                    "medium",
                    "AMQP magic matched but version major byte unexpected",
                    &payload[..8.min(payload.len())],
                ));
                return;
            }

            let proto_id_name = match proto_id {
                0 => "amqp",
                2 => "tls",
                3 => "sasl",
                _ => "unknown",
            };
            let mut attributes = BTreeMap::new();
            attributes.insert("protocol_id".to_string(), proto_id.to_string());
            attributes.insert("protocol_id_name".to_string(), proto_id_name.to_string());
            attributes.insert(
                "version".to_string(),
                format!("{}.{}.{}", major, minor, revision),
            );

            let envelope = build_envelope(
                &chunk.context,
                chunk.interface_id,
                chunk.frame_index,
                chunk.timestamp,
                chunk.segment_hash,
                TransportProtocol::Tcp,
                Some("amqp"),
                chunk.captured_len,
                chunk.session_key.clone(),
            );
            out.push(new_event(
                chunk.capture_id.to_string(),
                envelope,
                BronzeEventFamily::ProtocolTransaction(ProtocolTransaction {
                    operation: "amqp_protocol_header".to_string(),
                    status: "observed".to_string(),
                    request_summary: None,
                    response_summary: None,
                    object_refs: Vec::new(),
                    values: Vec::new(),
                    attributes,
                    modbus: None,
                    protocol_fields: None,
                }),
            ));
            // The rest of this chunk may contain frames; fall through.
            let remaining = &payload[8..];
            if !remaining.is_empty() {
                self.decode_frames(chunk, remaining, out);
            }
            return;
        }

        // Magic bytes not present — common when this chunk is a frame
        // continuation past the protocol-header preamble. decode_frames has
        // its own DOFF / frame_size guards and will no-op on bad bytes, so
        // we fall through rather than emitting a false-positive anomaly.

        // Attempt frame decode directly (continuation segment, no header)
        self.decode_frames(chunk, payload, out);
    }
}

impl AmqpDecoder {
    /// Parse one or more AMQP 1.0 frames from `data`, emitting events for each.
    fn decode_frames(&mut self, chunk: &StreamChunk<'_>, data: &[u8], out: &mut Vec<BronzeEvent>) {
        let mut cursor = 0usize;

        while cursor + 8 <= data.len() {
            // Frame header: size(4) | doff(1) | type(1) | channel/reserved(2)
            let frame_size = u32::from_be_bytes([
                data[cursor],
                data[cursor + 1],
                data[cursor + 2],
                data[cursor + 3],
            ]) as usize;
            let doff = data[cursor + 4];
            let frame_type = data[cursor + 5];
            let channel = u16::from_be_bytes([data[cursor + 6], data[cursor + 7]]);

            // DOFF < 2 means a header shorter than 8 bytes — malformed.
            if doff < 2 {
                let envelope = build_envelope(
                    &chunk.context,
                    chunk.interface_id,
                    chunk.frame_index,
                    chunk.timestamp,
                    chunk.segment_hash,
                    TransportProtocol::Tcp,
                    Some("amqp"),
                    chunk.captured_len,
                    chunk.session_key.clone(),
                );
                out.push(parse_anomaly_event(
                    chunk.capture_id.to_string(),
                    envelope,
                    self.name(),
                    "low",
                    "AMQP frame DOFF < 2 (minimum is 2, equals 8-byte header)",
                    &data[cursor..cursor.saturating_add(8).min(data.len())],
                ));
                break;
            }

            // Guard: frame_size must be at least the 8-byte header.
            if frame_size < 8 || cursor + frame_size > data.len() {
                // Truncated or corrupt frame — stop processing this chunk.
                break;
            }

            let frame_data = &data[cursor..cursor + frame_size];
            // body_offset = doff * 4 (doff is in 4-byte words)
            let body_offset = (doff as usize) * 4;

            if body_offset <= frame_size {
                let body = &frame_data[body_offset..];
                self.decode_performative(chunk, frame_type, channel, frame_size, body, out);
            }

            cursor += frame_size;
        }
    }

    /// Identify and emit a single performative from a frame body.
    ///
    /// AMQP described-type prefix:
    ///   `0x00` — format code indicating a described value
    ///   `0x53` — small ulong constructor (1-byte unsigned long value)
    ///   `0xNN` — the actual descriptor / performative code
    fn decode_performative(
        &mut self,
        chunk: &StreamChunk<'_>,
        frame_type: u8,
        channel: u16,
        frame_size: usize,
        body: &[u8],
        out: &mut Vec<BronzeEvent>,
    ) {
        // Need at least 3 bytes for the described-type prefix.
        if body.len() < 3 {
            return;
        }

        // Validate described-type header: must start with 0x00 0x53
        if body[0] != 0x00 || body[1] != 0x53 {
            let envelope = build_envelope(
                &chunk.context,
                chunk.interface_id,
                chunk.frame_index,
                chunk.timestamp,
                chunk.segment_hash,
                TransportProtocol::Tcp,
                Some("amqp"),
                chunk.captured_len,
                chunk.session_key.clone(),
            );
            out.push(parse_anomaly_event(
                chunk.capture_id.to_string(),
                envelope,
                self.name(),
                "low",
                "AMQP frame body missing expected 0x00 0x53 described-type prefix",
                &body[..body.len().min(8)],
            ));
            return;
        }

        let descriptor_code = body[2];
        let frame_type_name = if frame_type == 0 { "amqp" } else { "sasl" };

        let operation = performative_operation(frame_type, descriptor_code);

        let mut attributes = BTreeMap::new();
        attributes.insert("frame_type".to_string(), frame_type_name.to_string());
        attributes.insert("frame_size".to_string(), frame_size.to_string());
        attributes.insert(
            "descriptor_code_hex".to_string(),
            format!("0x{:02x}", descriptor_code),
        );
        // Channel is meaningful only for AMQP frames (type=0); SASL frames use
        // the field as reserved.
        if frame_type == 0 {
            attributes.insert("channel".to_string(), channel.to_string());
        }

        let envelope = build_envelope(
            &chunk.context,
            chunk.interface_id,
            chunk.frame_index,
            chunk.timestamp,
            chunk.segment_hash,
            TransportProtocol::Tcp,
            Some("amqp"),
            chunk.captured_len,
            chunk.session_key.clone(),
        );

        out.push(new_event(
            chunk.capture_id.to_string(),
            envelope.clone(),
            BronzeEventFamily::ProtocolTransaction(ProtocolTransaction {
                operation: operation.to_string(),
                status: "observed".to_string(),
                request_summary: None,
                response_summary: None,
                object_refs: Vec::new(),
                values: Vec::new(),
                attributes,
                modbus: None,
                protocol_fields: None,
            }),
        ));

        // OPEN performative: emit an AssetObservation for the destination IP,
        // which is the broker endpoint. Emit once per session.
        if descriptor_code == PERF_OPEN && frame_type == 0 && !self.open_emitted {
            self.open_emitted = true;
            let dst_ip = chunk.context.dst_ip.to_string();
            out.push(new_event(
                chunk.capture_id.to_string(),
                envelope,
                BronzeEventFamily::AssetObservation(AssetObservation {
                    asset_key: dst_ip.clone(),
                    role: Some("amqp_broker".to_string()),
                    vendor: None,
                    model: None,
                    firmware: None,
                    hostnames: Vec::new(),
                    protocols: vec!["amqp".to_string()],
                    identifiers: BTreeMap::from([("ip".to_string(), dst_ip)]),
                }),
            ));
        }
    }
}

/// Map (frame_type, descriptor_code) to the operation string for a
/// `ProtocolTransaction`. Unknown codes are rendered as hex.
fn performative_operation(frame_type: u8, code: u8) -> String {
    match (frame_type, code) {
        // AMQP connection/session/link performatives (type=0)
        (0, PERF_OPEN) => "amqp_open".to_string(),
        (0, PERF_BEGIN) => "amqp_begin".to_string(),
        (0, PERF_ATTACH) => "amqp_attach".to_string(),
        (0, PERF_FLOW) => "amqp_flow".to_string(),
        (0, PERF_TRANSFER) => "amqp_transfer".to_string(),
        (0, PERF_DISPOSITION) => "amqp_disposition".to_string(),
        (0, PERF_DETACH) => "amqp_detach".to_string(),
        (0, PERF_END) => "amqp_end".to_string(),
        (0, PERF_CLOSE) => "amqp_close".to_string(),
        // SASL performatives (type=1)
        (1, SASL_MECHANISMS) => "amqp_sasl_mechanisms".to_string(),
        (1, SASL_INIT) => "amqp_sasl_init".to_string(),
        (1, SASL_CHALLENGE) => "amqp_sasl_challenge".to_string(),
        (1, SASL_RESPONSE) => "amqp_sasl_response".to_string(),
        (1, SASL_OUTCOME) => "amqp_sasl_outcome".to_string(),
        // Unknown descriptor on either frame type
        (_, c) => format!("amqp_unknown_descriptor_0x{:02x}", c),
    }
}

// ── Inventory registration ────────────────────────────────────────────────────

inventory::submit!(crate::engine::decoders::DecoderRegistration {
    name: "amqp",
    factory: || Box::new(AmqpDecoder::default()),
});

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    use chrono::{TimeZone, Utc};

    use crate::registry::PacketContext;

    // ── Helpers ───────────────────────────────────────────────────────────────

    fn ctx(src_port: u16, dst_port: u16) -> PacketContext {
        PacketContext {
            src_mac: [0u8; 6],
            dst_mac: [0u8; 6],
            src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            dst_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            src_port,
            dst_port,
            vlan_id: None,
            timestamp: 1_700_000_000_000_000_u64,
        }
    }

    fn chunk<'a>(payload: &'a [u8], context: PacketContext) -> StreamChunk<'a> {
        StreamChunk {
            capture_id: "test",
            segment_hash: "seg",
            interface_id: 0,
            frame_index: 1,
            timestamp: Utc.timestamp_opt(1_700_000_000, 0).unwrap(),
            context,
            ethertype: 0x0800,
            ip_proto: Some(6),
            llc: None,
            transport: TransportProtocol::Tcp,
            payload,
            session_key: "sk".to_string(),
            captured_len: payload.len() as u64,
        }
    }

    /// Build a minimal AMQP frame containing a performative.
    ///
    /// Layout: size(4 BE) | doff=2(1) | frame_type(1) | channel(2 BE) | 0x00 0x53 code | padding
    fn make_frame(frame_type: u8, channel: u16, descriptor_code: u8) -> Vec<u8> {
        let mut frame = Vec::new();
        // Total frame size = 8-byte header + 3-byte described-type prefix = 11
        let size: u32 = 11;
        frame.extend_from_slice(&size.to_be_bytes()); // size
        frame.push(2); // doff = 2 (8-byte header)
        frame.push(frame_type); // type: 0=AMQP, 1=SASL
        frame.extend_from_slice(&channel.to_be_bytes()); // channel / reserved
        // Performative body: described-type prefix 0x00 0x53 <code>
        frame.push(0x00); // described-type marker
        frame.push(0x53); // small ulong constructor
        frame.push(descriptor_code);
        frame
    }

    // ── Test 1: AMQP protocol header ─────────────────────────────────────────

    #[test]
    fn test_protocol_header_emits_transaction() {
        // "AMQP\x00\x01\x00\x00" — protocol_id=0 (amqp), version 1.0.0
        let payload = b"AMQP\x00\x01\x00\x00";
        let mut decoder = AmqpDecoder::default();
        let mut events: Vec<BronzeEvent> = Vec::new();
        decoder.on_stream_chunk(&chunk(payload, ctx(12345, 5672)), &mut events);

        assert!(!events.is_empty(), "should emit at least one event");
        let tx = events.iter().find_map(|e| {
            if let BronzeEventFamily::ProtocolTransaction(ref t) = e.family {
                (t.operation == "amqp_protocol_header").then_some(t)
            } else {
                None
            }
        });
        let tx = tx.expect("expected amqp_protocol_header transaction");
        assert_eq!(tx.status, "observed");
        assert_eq!(
            tx.attributes.get("protocol_id").map(String::as_str),
            Some("0")
        );
        assert_eq!(
            tx.attributes.get("version").map(String::as_str),
            Some("1.0.0")
        );
    }

    // ── Test 2: AMQP frame with OPEN descriptor ───────────────────────────────

    #[test]
    fn test_open_frame_emits_amqp_open() {
        // AMQP frame type=0, channel=0, descriptor=0x10 (OPEN)
        let frame = make_frame(0, 0, PERF_OPEN);
        let mut decoder = AmqpDecoder::default();
        let mut events: Vec<BronzeEvent> = Vec::new();
        decoder.on_stream_chunk(&chunk(&frame, ctx(12345, 5672)), &mut events);

        let tx = events.iter().find_map(|e| {
            if let BronzeEventFamily::ProtocolTransaction(ref t) = e.family {
                (t.operation == "amqp_open").then_some(t)
            } else {
                None
            }
        });
        let tx = tx.expect("expected amqp_open transaction");
        assert_eq!(tx.status, "observed");
        assert_eq!(
            tx.attributes.get("descriptor_code_hex").map(String::as_str),
            Some("0x10")
        );

        // OPEN should also emit an AssetObservation for the broker
        let asset = events.iter().find_map(|e| {
            if let BronzeEventFamily::AssetObservation(ref a) = e.family {
                Some(a)
            } else {
                None
            }
        });
        let asset = asset.expect("expected AssetObservation for broker");
        assert_eq!(asset.role.as_deref(), Some("amqp_broker"));
    }

    // ── Test 3: AMQP frame with TRANSFER descriptor ───────────────────────────

    #[test]
    fn test_transfer_frame_emits_amqp_transfer() {
        let frame = make_frame(0, 1, PERF_TRANSFER);
        let mut decoder = AmqpDecoder::default();
        let mut events: Vec<BronzeEvent> = Vec::new();
        decoder.on_stream_chunk(&chunk(&frame, ctx(12345, 5672)), &mut events);

        let tx = events.iter().find_map(|e| {
            if let BronzeEventFamily::ProtocolTransaction(ref t) = e.family {
                (t.operation == "amqp_transfer").then_some(t)
            } else {
                None
            }
        });
        assert!(tx.is_some(), "expected amqp_transfer transaction");
        let tx = tx.unwrap();
        assert_eq!(
            tx.attributes.get("frame_type").map(String::as_str),
            Some("amqp")
        );
        assert_eq!(tx.attributes.get("channel").map(String::as_str), Some("1"));
    }

    // ── Test 4: SASL frame with SASL-INIT descriptor ──────────────────────────

    #[test]
    fn test_sasl_init_frame_type_and_operation() {
        // SASL frame: type=1, descriptor=0x41 (SASL-INIT)
        let frame = make_frame(1, 0, SASL_INIT);
        let mut decoder = AmqpDecoder::default();
        let mut events: Vec<BronzeEvent> = Vec::new();
        decoder.on_stream_chunk(&chunk(&frame, ctx(12345, 5672)), &mut events);

        let tx = events.iter().find_map(|e| {
            if let BronzeEventFamily::ProtocolTransaction(ref t) = e.family {
                (t.operation == "amqp_sasl_init").then_some(t)
            } else {
                None
            }
        });
        let tx = tx.expect("expected amqp_sasl_init transaction");
        assert_eq!(
            tx.attributes.get("frame_type").map(String::as_str),
            Some("sasl")
        );
        // SASL frames should not expose a channel attribute
        assert!(
            !tx.attributes.contains_key("channel"),
            "SASL frames must not carry channel"
        );
    }

    // ── Test 5: TLS port (5671) emits amqp_tls_session ───────────────────────

    #[test]
    fn test_tls_port_emits_session_record() {
        // Any payload — TLS content is opaque
        let payload = b"\x16\x03\x01\x00\x28some tls bytes";
        let mut decoder = AmqpDecoder::default();
        let mut events: Vec<BronzeEvent> = Vec::new();
        decoder.on_stream_chunk(&chunk(payload, ctx(54321, 5671)), &mut events);

        let tx = events.iter().find_map(|e| {
            if let BronzeEventFamily::ProtocolTransaction(ref t) = e.family {
                (t.operation == "amqp_tls_session").then_some(t)
            } else {
                None
            }
        });
        let tx = tx.expect("expected amqp_tls_session transaction");
        assert_eq!(tx.status, "observed");
        assert_eq!(
            tx.attributes.get("note").map(String::as_str),
            Some("TLS-encrypted, payload opaque")
        );
    }

    // ── Test 6: Frame with DOFF=1 (invalid) emits ParseAnomaly severity=low ──

    #[test]
    fn test_invalid_doff_emits_parse_anomaly() {
        // Build a frame where doff=1 (minimum valid is 2).
        let mut frame = Vec::new();
        let size: u32 = 11;
        frame.extend_from_slice(&size.to_be_bytes()); // size
        frame.push(1); // doff = 1 — INVALID (minimum is 2)
        frame.push(0); // frame type = AMQP
        frame.extend_from_slice(&0u16.to_be_bytes()); // channel = 0
        frame.push(0x00); // described-type marker
        frame.push(0x53);
        frame.push(PERF_OPEN);

        let mut decoder = AmqpDecoder::default();
        let mut events: Vec<BronzeEvent> = Vec::new();
        decoder.on_stream_chunk(&chunk(&frame, ctx(12345, 5672)), &mut events);

        let anomaly = events.iter().find_map(|e| {
            if let BronzeEventFamily::ParseAnomaly(ref a) = e.family {
                Some(a)
            } else {
                None
            }
        });
        let anomaly = anomaly.expect("expected ParseAnomaly for DOFF < 2");
        assert_eq!(anomaly.severity, "low");
        assert!(
            anomaly.reason.contains("DOFF"),
            "reason should mention DOFF"
        );
    }

    // ── Test 7: TLS session record emitted only once per session ─────────────

    #[test]
    fn test_tls_session_emitted_once() {
        let payload = b"\x16\x03\x01hello";
        let mut decoder = AmqpDecoder::default();
        let mut events: Vec<BronzeEvent> = Vec::new();
        // Two chunks on the same session
        decoder.on_stream_chunk(&chunk(payload, ctx(54321, 5671)), &mut events);
        decoder.on_stream_chunk(&chunk(payload, ctx(54321, 5671)), &mut events);

        let count = events
            .iter()
            .filter(|e| {
                matches!(
                    &e.family,
                    BronzeEventFamily::ProtocolTransaction(t) if t.operation == "amqp_tls_session"
                )
            })
            .count();
        assert_eq!(count, 1, "amqp_tls_session should be emitted exactly once");
    }
}
