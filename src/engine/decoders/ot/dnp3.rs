use std::collections::BTreeMap;

use crate::bronze::{
    AssetObservation, BronzeEvent, BronzeEventFamily, ProtocolTransaction, TopologyObservation,
    TransportProtocol,
};
use crate::dissectors::dnp3::Dnp3Dissector;
use crate::engine::{
    artifact_event, build_envelope, new_event, parse_anomaly_event, DecoderInterest,
    SessionDecoder, StreamChunk,
};
use crate::registry::{Dnp3Fields, PacketContext, ProtocolData, ProtocolDissector};

use crate::bronze::EventEnvelope;

#[derive(Default)]
pub(crate) struct Dnp3DecoderWrapper {
    dissector: Dnp3Dissector,
}

impl SessionDecoder for Dnp3DecoderWrapper {
    fn name(&self) -> &'static str {
        "dnp3"
    }

    fn interest(&self) -> &'static [DecoderInterest] {
        &[DecoderInterest::TcpPort(20000)]
    }

    fn on_stream_chunk(&mut self, chunk: &StreamChunk<'_>, out: &mut Vec<BronzeEvent>) {
        match self.dissector.parse(chunk.payload, &chunk.context) {
            Some(ProtocolData::Dnp3(Dnp3Fields {
                source_address,
                destination_address,
                function_code,
                application_data,
            })) => {
                let operation = dnp3_function_name(function_code);
                let envelope = build_envelope(
                    &chunk.context,
                    chunk.interface_id,
                    chunk.frame_index,
                    chunk.timestamp,
                    chunk.segment_hash,
                    TransportProtocol::Tcp,
                    Some("dnp3"),
                    chunk.captured_len,
                    chunk.session_key.clone(),
                );
                let mut attributes = BTreeMap::new();
                attributes.insert("source_address".to_string(), source_address.to_string());
                attributes.insert(
                    "destination_address".to_string(),
                    destination_address.to_string(),
                );
                out.push(new_event(
                    chunk.capture_id.to_string(),
                    envelope.clone(),
                    BronzeEventFamily::ProtocolTransaction(ProtocolTransaction {
                        operation: operation.to_string(),
                        status: if function_code >= 0x80 {
                            "response".to_string()
                        } else {
                            "request".to_string()
                        },
                        request_summary: Some(format!(
                            "{operation} {source_address}->{destination_address}"
                        )),
                        response_summary: None,
                        object_refs: vec![format!("dnp3_fc:{function_code:#04x}")],
                        values: Vec::new(),
                        attributes,
                                        modbus: None,
                                        protocol_fields: None,
}),
                ));
                for event in dnp3_role_observations(
                    chunk.capture_id,
                    &envelope,
                    &chunk.context,
                    source_address,
                    destination_address,
                    function_code,
                ) {
                    out.push(event);
                }
                if is_dnp3_artifact(function_code) && !application_data.is_empty() {
                    out.push(artifact_event(
                        chunk.capture_id.to_string(),
                        envelope,
                        "dnp3_application_data",
                        &format!("{}:{function_code:#04x}", chunk.session_key),
                        Some("application/octet-stream"),
                        Some("DNP3 application payload"),
                        &application_data,
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
                    TransportProtocol::Tcp,
                    Some("dnp3"),
                    chunk.captured_len,
                    chunk.session_key.clone(),
                ),
                self.name(),
                "medium",
                "failed to parse dnp3 payload",
                chunk.payload,
            )),
        }
    }
}

fn dnp3_function_name(code: u8) -> &'static str {
    match code {
        0x01 => "read",
        0x02 => "write",
        0x03 => "select",
        0x04 => "operate",
        0x05 => "direct_operate",
        0x06 => "direct_operate_no_ack",
        0x81 => "response",
        0x82 => "unsolicited_response",
        _ => "dnp3_message",
    }
}

fn is_dnp3_artifact(code: u8) -> bool {
    matches!(code, 0x02 | 0x03 | 0x04 | 0x05 | 0x06)
}

fn dnp3_role_observations(
    capture_id: &str,
    envelope: &EventEnvelope,
    context: &PacketContext,
    source_address: u16,
    destination_address: u16,
    function_code: u8,
) -> Vec<BronzeEvent> {
    let (src_role, dst_role, observation_type) =
        if function_code >= 0x80 || context.src_port == 20000 {
            ("outstation", "master", "dnp3_response")
        } else {
            ("master", "outstation", "dnp3_request")
        };

    vec![
        new_event(
            capture_id.to_string(),
            envelope.clone(),
            BronzeEventFamily::AssetObservation(AssetObservation {
                asset_key: context.src_ip.to_string(),
                role: Some(src_role.to_string()),
                vendor: None,
                model: None,
                firmware: None,
                hostnames: Vec::new(),
                protocols: vec!["dnp3".to_string()],
                identifiers: BTreeMap::from([
                    ("ip".to_string(), context.src_ip.to_string()),
                    ("dnp3_address".to_string(), source_address.to_string()),
                ]),
            }),
        ),
        new_event(
            capture_id.to_string(),
            envelope.clone(),
            BronzeEventFamily::AssetObservation(AssetObservation {
                asset_key: context.dst_ip.to_string(),
                role: Some(dst_role.to_string()),
                vendor: None,
                model: None,
                firmware: None,
                hostnames: Vec::new(),
                protocols: vec!["dnp3".to_string()],
                identifiers: BTreeMap::from([
                    ("ip".to_string(), context.dst_ip.to_string()),
                    ("dnp3_address".to_string(), destination_address.to_string()),
                ]),
            }),
        ),
        new_event(
            capture_id.to_string(),
            envelope.clone(),
            BronzeEventFamily::TopologyObservation(TopologyObservation {
                observation_type: observation_type.to_string(),
                local_id: source_address.to_string(),
                remote_id: Some(destination_address.to_string()),
                description: Some(dnp3_function_name(function_code).to_string()),
                capabilities: Vec::new(),
                metadata: BTreeMap::from([
                    ("src_ip".to_string(), context.src_ip.to_string()),
                    ("dst_ip".to_string(), context.dst_ip.to_string()),
                ]),
            }),
        ),
    ]
}

inventory::submit!(crate::engine::decoders::DecoderRegistration {
    name: "dnp3",
    factory: || Box::new(Dnp3DecoderWrapper::default()),
});
