//! OPC UA Binary (TCP) decoder — session-level decoder for the OPC UA binary
//! transport on ports 4840 and 12001.
//!
//! # Typed surface
//!
//! Every [`ProtocolTransaction`] emitted here carries
//! `protocol_fields: Some(ProtocolFields::OpcUa(OpcUaBronzeFields { .. }))`.
//! The typed struct captures the message-type code, chunk type, secure-channel
//! and request identifiers, sequence number, service name / node-id, status
//! code, and direction label — everything needed for policy evaluation without
//! string-map lookups.
//!
//! The legacy `attributes` map is still populated for backward compatibility
//! through the v1.x line and will be removed in v2.0.

use std::collections::BTreeMap;

use crate::bronze::{
    BronzeEvent, BronzeEventFamily, OpcUaBronzeFields, ProtocolFields, ProtocolTransaction,
    TransportProtocol,
};
use crate::dissectors::opc_ua::OpcUaDissector;
use crate::engine::{
    build_envelope, new_event, parse_anomaly_event, DecoderInterest, SessionDecoder, StreamChunk,
};
use crate::registry::{OpcUaFields, ProtocolData, ProtocolDissector};

use super::normalize_operation_name;

pub(crate) struct OpcUaDecoderWrapper {
    dissector: OpcUaDissector,
    service_decoder: crate::opc_ua::OpcUaServiceDecoder,
    event_id_counter: u64,
}

impl Default for OpcUaDecoderWrapper {
    fn default() -> Self {
        Self {
            dissector: OpcUaDissector,
            service_decoder: crate::opc_ua::OpcUaServiceDecoder::new(),
            event_id_counter: 0,
        }
    }
}

impl SessionDecoder for OpcUaDecoderWrapper {
    fn name(&self) -> &'static str {
        "opc_ua"
    }

    fn interest(&self) -> &'static [DecoderInterest] {
        &[
            DecoderInterest::TcpPort(4840),
            DecoderInterest::TcpPort(12001),
        ]
    }

    fn on_stream_chunk(&mut self, chunk: &StreamChunk<'_>, out: &mut Vec<BronzeEvent>) {
        if !self.dissector.can_parse(
            chunk.payload,
            chunk.context.src_port,
            chunk.context.dst_port,
        ) {
            return;
        }

        match self.dissector.parse(chunk.payload, &chunk.context) {
            Some(ProtocolData::OpcUa(OpcUaFields {
                message_type,
                request_id,
                service_type,
            })) => {
                // --- Direction heuristic ---
                let is_server_port = matches!(chunk.context.dst_port, 4840 | 12001);
                let is_request = is_server_port;
                let is_response = !is_server_port
                    && matches!(chunk.context.src_port, 4840 | 12001);

                // --- Extended header fields extracted from raw payload ---
                let chunk_type_char = if chunk.payload.len() > 3 {
                    (chunk.payload[3] as char).to_string()
                } else {
                    "F".to_string()
                };

                let secure_channel_id: Option<u32> =
                    match message_type.as_str() {
                        "MSG" | "OPN" | "CLO" if chunk.payload.len() >= 12 => Some(
                            u32::from_le_bytes([
                                chunk.payload[8],
                                chunk.payload[9],
                                chunk.payload[10],
                                chunk.payload[11],
                            ]),
                        ),
                        _ => None,
                    };

                let sequence_number: Option<u32> =
                    if message_type == "MSG" && chunk.payload.len() >= 20 {
                        Some(u32::from_le_bytes([
                            chunk.payload[16],
                            chunk.payload[17],
                            chunk.payload[18],
                            chunk.payload[19],
                        ]))
                    } else {
                        None
                    };

                let request_id_opt: Option<u32> = if request_id != 0 {
                    Some(request_id)
                } else {
                    None
                };

                // Status code for ERR frames (bytes 8–11).
                let status_code: Option<u32> = if message_type == "ERR"
                    && chunk.payload.len() >= 12
                {
                    Some(u32::from_le_bytes([
                        chunk.payload[8],
                        chunk.payload[9],
                        chunk.payload[10],
                        chunk.payload[11],
                    ]))
                } else {
                    None
                };

                // Service name derived from the dissector's service_type string.
                let service_name: Option<String> = match message_type.as_str() {
                    "HEL" | "ACK" | "OPN" | "CLO" | "ERR" | "RHE" => {
                        Some(service_type_to_name(&service_type))
                    }
                    "MSG" => service_name_from_msg_service_type(&service_type),
                    _ => None,
                };

                // Direction label.
                let direction = match message_type.as_str() {
                    "HEL" | "ACK" | "OPN" | "CLO" | "RHE" => "session",
                    "ERR" => "error",
                    _ if is_request => "request",
                    _ => "response",
                }
                .to_string();

                // --- Legacy attributes (backward compat) ---
                let mut attributes = BTreeMap::new();
                attributes.insert("message_type".to_string(), message_type.clone());
                attributes.insert("service_type".to_string(), service_type.clone());
                if let Some(rid) = request_id_opt {
                    attributes.insert("request_id".to_string(), rid.to_string());
                }

                let envelope = build_envelope(
                    &chunk.context,
                    chunk.interface_id,
                    chunk.frame_index,
                    chunk.timestamp,
                    chunk.segment_hash,
                    TransportProtocol::Tcp,
                    Some("opc_ua"),
                    chunk.captured_len,
                    chunk.session_key.clone(),
                );

                out.push(new_event(
                    chunk.capture_id.to_string(),
                    envelope.clone(),
                    BronzeEventFamily::ProtocolTransaction(ProtocolTransaction {
                        operation: opc_ua_operation_name(&service_type),
                        status: if service_type.starts_with("Error") {
                            "error".to_string()
                        } else if is_request {
                            "request".to_string()
                        } else {
                            "response".to_string()
                        },
                        request_summary: Some(format!("{message_type} {service_type}")),
                        response_summary: None,
                        object_refs: if request_id == 0 {
                            vec![format!("opcua_message:{message_type}")]
                        } else {
                            vec![format!("opcua_request:{request_id}")]
                        },
                        values: Vec::new(),
                        attributes,
                        modbus: None,
                        protocol_fields: Some(ProtocolFields::OpcUa(OpcUaBronzeFields {
                            message_type: message_type.clone(),
                            chunk_type: chunk_type_char,
                            secure_channel_id,
                            request_id: request_id_opt,
                            sequence_number,
                            service_node_id: None,
                            service_name,
                            status_code,
                            is_request,
                            is_response,
                            direction,
                        })),
                    }),
                ));

                // For MSG chunks with the full 24-byte secure header, hand
                // the body to the OPC UA service decoder. Read* services
                // produce ProcessReading events; others are ignored.
                if message_type == "MSG" && chunk.payload.len() >= 24 {
                    let sc_id = secure_channel_id.unwrap_or(0);
                    let body = &chunk.payload[24..];
                    let now_us = chunk.context.timestamp / 1_000;
                    let counter = &mut self.event_id_counter;
                    let mut next_id = || {
                        *counter = counter.wrapping_add(1);
                        format!("opcua-{}", *counter)
                    };
                    let mut events = self.service_decoder.handle_msg_body(
                        body,
                        sc_id,
                        request_id,
                        &envelope,
                        now_us,
                        &mut next_id,
                        chunk.capture_id,
                    );
                    out.append(&mut events);
                }
            }
            _ => out.push(parse_anomaly_event(
                chunk.capture_id.to_string(),
                build_envelope(
                    &chunk.context,
                    chunk.interface_id,
                    chunk.frame_index,
                    chunk.timestamp,
                    chunk.segment_hash,
                    TransportProtocol::Tcp,
                    Some("opc_ua"),
                    chunk.captured_len,
                    chunk.session_key.clone(),
                ),
                self.name(),
                "medium",
                "failed to parse opc ua payload",
                chunk.payload,
            )),
        }
    }
}

fn opc_ua_operation_name(service_type: &str) -> String {
    normalize_operation_name(service_type, "opc_ua_message")
}

/// Convert the dissector's `service_type` string to a clean service name for
/// HEL/ACK/OPN/CLO/ERR/RHE frame types.
fn service_type_to_name(service_type: &str) -> String {
    // Strip trailing " (truncated)" or error-code suffixes before returning.
    service_type
        .split_once(" (")
        .map(|(base, _)| base)
        .unwrap_or(service_type)
        .to_string()
}

/// For MSG frames the dissector returns "MSG chunk=F"; the actual service name
/// is only known after decoding the body. Return None here; higher-level callers
/// may enrich this once the body is decoded.
fn service_name_from_msg_service_type(_service_type: &str) -> Option<String> {
    None
}

inventory::submit!(crate::engine::decoders::DecoderRegistration {
    name: "opc_ua",
    factory: || Box::new(OpcUaDecoderWrapper::default()),
});

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bronze::{BronzeEventFamily, ProtocolFields};
    use crate::engine::{SessionDecoder, StreamChunk};
    use crate::registry::PacketContext;
    use chrono::TimeZone as _;
    use std::net::{IpAddr, Ipv4Addr};

    fn client_ctx() -> PacketContext {
        PacketContext {
            src_mac: [0; 6],
            dst_mac: [0; 6],
            src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            dst_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            src_port: 49500,
            dst_port: 4840,
            vlan_id: None,
            timestamp: 1_700_000_000_000_000,
        }
    }

    fn server_ctx() -> PacketContext {
        PacketContext {
            src_mac: [0; 6],
            dst_mac: [0; 6],
            src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            dst_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            src_port: 4840,
            dst_port: 49500,
            vlan_id: None,
            timestamp: 1_700_000_001_000_000,
        }
    }

    fn chunk<'a>(
        payload: &'a [u8],
        ctx: &'a PacketContext,
        session_key: &'a str,
    ) -> StreamChunk<'a> {
        StreamChunk {
            capture_id: "cap1",
            interface_id: 0,
            frame_index: 0,
            timestamp: chrono::Utc.timestamp_opt(1_700_000_000, 0).unwrap(),
            segment_hash: "seg",
            session_key: session_key.to_string(),
            captured_len: payload.len() as u64,
            payload,
            context: ctx.clone(),
            ethertype: 0x0800,
            ip_proto: Some(6),
            llc: None,
            transport: TransportProtocol::Tcp,
        }
    }

    fn build_hdr(msg_type: &[u8; 3], chunk_type: u8, size: u32) -> Vec<u8> {
        let mut p = Vec::new();
        p.extend_from_slice(msg_type);
        p.push(chunk_type);
        p.extend_from_slice(&size.to_le_bytes());
        p
    }

    fn extract_opc_ua_fields(events: &[BronzeEvent]) -> &OpcUaBronzeFields {
        for ev in events {
            if let BronzeEventFamily::ProtocolTransaction(tx) = &ev.family {
                if let Some(ProtocolFields::OpcUa(f)) = &tx.protocol_fields {
                    return f;
                }
            }
        }
        panic!("no OpcUa ProtocolFields found in events");
    }

    // --- HEL/ACK handshake ---

    #[test]
    fn hel_ack_handshake_typed_fields() {
        let mut decoder = OpcUaDecoderWrapper::default();
        let ctx = client_ctx();

        // HEL — client sends to server port 4840
        let mut hel = build_hdr(b"HEL", b'F', 64);
        hel.extend_from_slice(&[0u8; 24]); // Hello body padding
        let mut out = Vec::new();
        decoder.on_stream_chunk(&chunk(&hel, &ctx, "sess1"), &mut out);
        let f = extract_opc_ua_fields(&out);
        assert_eq!(f.message_type, "HEL");
        assert_eq!(f.chunk_type, "F");
        assert_eq!(f.direction, "session");
        assert!(f.is_request); // dst_port 4840
        assert!(!f.is_response);
        assert_eq!(f.service_name.as_deref(), Some("Hello"));
        assert!(f.secure_channel_id.is_none());
        assert!(f.status_code.is_none());

        // ACK — server responds from port 4840
        let ack_ctx = server_ctx();
        let ack = build_hdr(b"ACK", b'F', 28);
        let mut out2 = Vec::new();
        decoder.on_stream_chunk(&chunk(&ack, &ack_ctx, "sess1"), &mut out2);
        let f2 = extract_opc_ua_fields(&out2);
        assert_eq!(f2.message_type, "ACK");
        assert_eq!(f2.direction, "session");
        assert!(!f2.is_request);
        assert!(f2.is_response); // src_port 4840
        assert_eq!(f2.service_name.as_deref(), Some("Acknowledge"));
    }

    // --- OPN OpenSecureChannelRequest ---

    #[test]
    fn opn_open_secure_channel_typed_fields() {
        let mut decoder = OpcUaDecoderWrapper::default();
        let ctx = client_ctx();

        let mut opn = build_hdr(b"OPN", b'F', 132);
        opn.extend_from_slice(&7u32.to_le_bytes()); // secure_channel_id
        opn.extend_from_slice(&[0u8; 64]); // body padding

        let mut out = Vec::new();
        decoder.on_stream_chunk(&chunk(&opn, &ctx, "sess1"), &mut out);
        let f = extract_opc_ua_fields(&out);
        assert_eq!(f.message_type, "OPN");
        assert_eq!(f.secure_channel_id, Some(7));
        assert_eq!(f.direction, "session");
        assert_eq!(f.service_name.as_deref(), Some("OpenSecureChannel"));
        assert!(f.request_id.is_none()); // OPN has no request_id in dissector
    }

    // --- MSG ReadRequest with secure_channel_id + request_id ---

    #[test]
    fn msg_read_request_typed_fields() {
        let mut decoder = OpcUaDecoderWrapper::default();
        let ctx = client_ctx();

        let mut msg = build_hdr(b"MSG", b'F', 100);
        msg.extend_from_slice(&42u32.to_le_bytes()); // secure_channel_id
        msg.extend_from_slice(&3u32.to_le_bytes()); // security_token_id
        msg.extend_from_slice(&11u32.to_le_bytes()); // sequence_number
        msg.extend_from_slice(&99u32.to_le_bytes()); // request_id
        // body: fill enough bytes that service decoder can try to parse
        msg.extend_from_slice(&[0u8; 64]);

        let mut out = Vec::new();
        decoder.on_stream_chunk(&chunk(&msg, &ctx, "sess1"), &mut out);
        let f = extract_opc_ua_fields(&out);
        assert_eq!(f.message_type, "MSG");
        assert_eq!(f.chunk_type, "F");
        assert_eq!(f.secure_channel_id, Some(42));
        assert_eq!(f.sequence_number, Some(11));
        assert_eq!(f.request_id, Some(99));
        assert!(f.is_request);
        assert!(!f.is_response);
        assert_eq!(f.direction, "request");
    }

    // --- ERR with status_code ---

    #[test]
    fn err_frame_status_code_typed_fields() {
        let mut decoder = OpcUaDecoderWrapper::default();
        let ctx = server_ctx(); // ERR can come from either side

        let mut err = build_hdr(b"ERR", b'F', 16);
        err.extend_from_slice(&0x800D0000u32.to_le_bytes()); // error code
        err.extend_from_slice(&[0u8; 4]); // reason string length

        let mut out = Vec::new();
        decoder.on_stream_chunk(&chunk(&err, &ctx, "sess1"), &mut out);
        let f = extract_opc_ua_fields(&out);
        assert_eq!(f.message_type, "ERR");
        assert_eq!(f.status_code, Some(0x800D0000));
        assert_eq!(f.direction, "error");
    }

    // --- MSG response (server→client direction) ---

    #[test]
    fn msg_response_direction() {
        let mut decoder = OpcUaDecoderWrapper::default();
        let ctx = server_ctx();

        let mut msg = build_hdr(b"MSG", b'F', 100);
        msg.extend_from_slice(&42u32.to_le_bytes()); // secure_channel_id
        msg.extend_from_slice(&3u32.to_le_bytes()); // security_token_id
        msg.extend_from_slice(&12u32.to_le_bytes()); // sequence_number
        msg.extend_from_slice(&99u32.to_le_bytes()); // request_id
        msg.extend_from_slice(&[0u8; 64]);

        let mut out = Vec::new();
        decoder.on_stream_chunk(&chunk(&msg, &ctx, "sess1"), &mut out);
        let f = extract_opc_ua_fields(&out);
        assert!(!f.is_request);
        assert!(f.is_response);
        assert_eq!(f.direction, "response");
    }

    // --- Backward compat: attributes still populated ---

    #[test]
    fn attributes_still_populated_for_backward_compat() {
        let mut decoder = OpcUaDecoderWrapper::default();
        let ctx = client_ctx();

        let mut msg = build_hdr(b"MSG", b'F', 100);
        msg.extend_from_slice(&5u32.to_le_bytes()); // secure_channel_id
        msg.extend_from_slice(&1u32.to_le_bytes()); // security_token_id
        msg.extend_from_slice(&2u32.to_le_bytes()); // sequence_number
        msg.extend_from_slice(&77u32.to_le_bytes()); // request_id
        msg.extend_from_slice(&[0u8; 64]);

        let mut out = Vec::new();
        decoder.on_stream_chunk(&chunk(&msg, &ctx, "sess1"), &mut out);
        for ev in &out {
            if let BronzeEventFamily::ProtocolTransaction(tx) = &ev.family {
                assert!(
                    tx.attributes.contains_key("message_type"),
                    "attributes.message_type missing"
                );
                assert!(
                    tx.attributes.contains_key("service_type"),
                    "attributes.service_type missing"
                );
                assert!(
                    tx.attributes.contains_key("request_id"),
                    "attributes.request_id missing"
                );
                return;
            }
        }
        panic!("no ProtocolTransaction event found");
    }

    // --- OpcUaBronzeFields serde round-trip ---

    #[test]
    fn opc_ua_bronze_fields_serde_roundtrip() {
        let fields = OpcUaBronzeFields {
            message_type: "MSG".to_string(),
            chunk_type: "F".to_string(),
            secure_channel_id: Some(42),
            request_id: Some(99),
            sequence_number: Some(11),
            service_node_id: Some(629),
            service_name: Some("ReadRequest".to_string()),
            status_code: None,
            is_request: true,
            is_response: false,
            direction: "request".to_string(),
        };
        let pf = ProtocolFields::OpcUa(fields.clone());
        let json = serde_json::to_string(&pf).expect("serialize");
        let back: ProtocolFields = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(pf, back);

        // None fields must be absent from the JSON output.
        assert!(!json.contains("\"status_code\""));
        assert!(!json.contains("\"service_node_id\"") || json.contains("629"));
    }
}
