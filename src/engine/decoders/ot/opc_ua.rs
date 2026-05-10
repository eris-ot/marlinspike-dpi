use std::collections::BTreeMap;

use crate::bronze::{BronzeEvent, BronzeEventFamily, ProtocolTransaction, TransportProtocol};
use crate::dissectors::opc_ua::OpcUaDissector;
use crate::engine::{
    build_envelope, new_event, parse_anomaly_event, DecoderInterest, SessionDecoder,
    StreamChunk,
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
                let mut attributes = BTreeMap::new();
                attributes.insert("message_type".to_string(), message_type.clone());
                attributes.insert("service_type".to_string(), service_type.clone());
                if request_id != 0 {
                    attributes.insert("request_id".to_string(), request_id.to_string());
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
                        } else if matches!(chunk.context.dst_port, 4840 | 12001) {
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
                                        protocol_fields: None,
}),
                ));

                // For MSG chunks with the full 24-byte secure header, hand
                // the body to the OPC UA service decoder. Read* services
                // produce ProcessReading events; others are ignored.
                if message_type == "MSG" && chunk.payload.len() >= 24 {
                    let secure_channel_id = u32::from_le_bytes([
                        chunk.payload[8],
                        chunk.payload[9],
                        chunk.payload[10],
                        chunk.payload[11],
                    ]);
                    let body = &chunk.payload[24..];
                    let now_us = chunk.context.timestamp / 1_000;
                    let counter = &mut self.event_id_counter;
                    let mut next_id = || {
                        *counter = counter.wrapping_add(1);
                        format!("opcua-{}", *counter)
                    };
                    let mut events = self.service_decoder.handle_msg_body(
                        body,
                        secure_channel_id,
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

inventory::submit!(crate::engine::decoders::DecoderRegistration {
    name: "opc_ua",
    factory: || Box::new(OpcUaDecoderWrapper::default()),
});
