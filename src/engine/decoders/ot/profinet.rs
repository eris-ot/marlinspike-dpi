use std::collections::BTreeMap;

use crate::bronze::{BronzeEvent, BronzeEventFamily, ProtocolTransaction};
use crate::dissectors::profinet::ProfinetDissector;
use crate::engine::{
    artifact_event, build_envelope, new_event, parse_anomaly_event, DecoderInterest,
    SessionDecoder, StreamChunk,
};
use crate::registry::{ProtocolData, ProtocolDissector, ProfinetFields};

use super::normalize_operation_name;

pub(crate) struct ProfinetDecoderWrapper {
    dissector: ProfinetDissector,
}

impl Default for ProfinetDecoderWrapper {
    fn default() -> Self {
        Self {
            dissector: ProfinetDissector,
        }
    }
}

impl SessionDecoder for ProfinetDecoderWrapper {
    fn name(&self) -> &'static str {
        "profinet"
    }

    fn interest(&self) -> &'static [DecoderInterest] {
        &[
            DecoderInterest::UdpPort(34964),
            DecoderInterest::EtherType(0x8892),
        ]
    }

    fn on_datagram(&mut self, chunk: &StreamChunk<'_>, out: &mut Vec<BronzeEvent>) {
        if !self.dissector.can_parse(
            chunk.payload,
            chunk.context.src_port,
            chunk.context.dst_port,
        ) {
            return;
        }

        match self.dissector.parse(chunk.payload, &chunk.context) {
            Some(ProtocolData::Profinet(ProfinetFields {
                frame_id,
                service_type,
                payload,
            })) => {
                let transport = chunk.transport;
                let mut attributes = BTreeMap::new();
                attributes.insert("frame_id".to_string(), format!("{frame_id:#06x}"));
                attributes.insert("service_type".to_string(), service_type.clone());
                attributes.insert("payload_length".to_string(), payload.len().to_string());

                let envelope = build_envelope(
                    &chunk.context,
                    chunk.interface_id,
                    chunk.frame_index,
                    chunk.timestamp,
                    chunk.segment_hash,
                    transport,
                    Some("profinet"),
                    chunk.captured_len,
                    chunk.session_key.clone(),
                );

                out.push(new_event(
                    chunk.capture_id.to_string(),
                    envelope.clone(),
                    BronzeEventFamily::ProtocolTransaction(ProtocolTransaction {
                        operation: profinet_operation_name(&service_type),
                        status: if service_type.contains("Response") {
                            "response".to_string()
                        } else if service_type.contains("Request")
                            || chunk.context.dst_port == 34964
                        {
                            "request".to_string()
                        } else {
                            "observed".to_string()
                        },
                        request_summary: Some(format!("{service_type} frame={frame_id:#06x}")),
                        response_summary: None,
                        object_refs: vec![format!("profinet_frame:{frame_id:#06x}")],
                        values: Vec::new(),
                        attributes,
                                        modbus: None,
                                        protocol_fields: None,
}),
                ));

                if !payload.is_empty() {
                    out.push(artifact_event(
                        chunk.capture_id.to_string(),
                        envelope,
                        "profinet_payload",
                        &format!("{frame_id:#06x}:{}", chunk.frame_index),
                        Some("application/octet-stream"),
                        Some("PROFINET payload"),
                        &payload,
                    ));
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
                    chunk.transport,
                    Some("profinet"),
                    chunk.captured_len,
                    chunk.session_key.clone(),
                ),
                self.name(),
                "medium",
                "failed to parse profinet payload",
                chunk.payload,
            )),
        }
    }
}

fn profinet_operation_name(service_type: &str) -> String {
    normalize_operation_name(service_type, "profinet_frame")
}

inventory::submit!(crate::engine::decoders::DecoderRegistration {
    name: "profinet",
    factory: || Box::new(ProfinetDecoderWrapper::default()),
});
