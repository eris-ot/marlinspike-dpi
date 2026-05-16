use std::collections::BTreeMap;

use crate::bronze::{
    BronzeEvent, BronzeEventFamily, ProfinetBronzeFields, ProtocolFields, ProtocolTransaction,
};
use crate::dissectors::profinet::ProfinetDissector;
use crate::engine::{
    DecoderInterest, SessionDecoder, StreamChunk, artifact_event, build_envelope, new_event,
    parse_anomaly_event,
};
use crate::registry::{ProfinetFields, ProtocolData, ProtocolDissector};

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

fn profinet_direction(service_type: &str, dst_port: u16) -> &'static str {
    if service_type.contains("Response") || service_type.contains("_con") {
        "response"
    } else if service_type.contains("Request") || service_type.contains("_req") || dst_port == 34964
    {
        "request"
    } else {
        "observed"
    }
}

fn profinet_bronze_fields(fields: &ProfinetFields, direction: &str) -> ProfinetBronzeFields {
    ProfinetBronzeFields {
        frame_id: fields.frame_id,
        service_type: fields.service_type.clone(),
        payload_length: fields.payload.len() as u32,
        direction: direction.to_string(),
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
            Some(ProtocolData::Profinet(fields)) => {
                let transport = chunk.transport;
                let direction = profinet_direction(&fields.service_type, chunk.context.dst_port);
                let mut attributes = BTreeMap::new();
                attributes.insert("frame_id".to_string(), format!("{:#06x}", fields.frame_id));
                attributes.insert("service_type".to_string(), fields.service_type.clone());
                attributes.insert(
                    "payload_length".to_string(),
                    fields.payload.len().to_string(),
                );

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
                        operation: profinet_operation_name(&fields.service_type),
                        status: direction.to_string(),
                        request_summary: Some(format!(
                            "{} frame={:#06x}",
                            fields.service_type, fields.frame_id
                        )),
                        response_summary: None,
                        object_refs: vec![format!("profinet_frame:{:#06x}", fields.frame_id)],
                        values: Vec::new(),
                        attributes,
                        modbus: None,
                        protocol_fields: Some(ProtocolFields::Profinet(profinet_bronze_fields(
                            &fields, direction,
                        ))),
                    }),
                ));

                if !fields.payload.is_empty() {
                    out.push(artifact_event(
                        chunk.capture_id.to_string(),
                        envelope,
                        "profinet_payload",
                        &format!("{:#06x}:{}", fields.frame_id, chunk.frame_index),
                        Some("application/octet-stream"),
                        Some("PROFINET payload"),
                        &fields.payload,
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
