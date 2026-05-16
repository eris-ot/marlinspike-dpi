use std::collections::BTreeMap;

use crate::bronze::{
    AssetObservation, BronzeEvent, BronzeEventFamily, ProtocolTransaction, TopologyObservation,
    TransportProtocol,
};
use crate::dissectors::bacnet::BacnetDissector;
use crate::engine::{
    DecoderInterest, SessionDecoder, StreamChunk, artifact_event, build_envelope, new_event,
    parse_anomaly_event,
};
use crate::registry::{BacnetFields, ProtocolData, ProtocolDissector};

use super::normalize_operation_name;

#[derive(Default)]
pub(crate) struct BacnetDecoder {
    dissector: BacnetDissector,
}

impl SessionDecoder for BacnetDecoder {
    fn name(&self) -> &'static str {
        "bacnet"
    }

    fn interest(&self) -> &'static [DecoderInterest] {
        static INTERESTS: [DecoderInterest; 2] = [
            DecoderInterest::UdpPort(47808),
            DecoderInterest::Llc {
                dsap: 0x82,
                ssap: 0x82,
            },
        ];
        &INTERESTS
    }

    fn on_datagram(&mut self, chunk: &StreamChunk<'_>, out: &mut Vec<BronzeEvent>) {
        match self.dissector.parse(chunk.payload, &chunk.context) {
            Some(ProtocolData::Bacnet(BacnetFields {
                link_variant,
                bvlc_function,
                npdu_control,
                apdu_type,
                service,
                invoke_id,
                device_instance,
                vendor_id,
                payload,
            })) => {
                let transport = if chunk.transport == TransportProtocol::Udp {
                    TransportProtocol::Udp
                } else {
                    TransportProtocol::Ethernet
                };
                let envelope = build_envelope(
                    &chunk.context,
                    chunk.interface_id,
                    chunk.frame_index,
                    chunk.timestamp,
                    chunk.segment_hash,
                    transport,
                    Some("bacnet"),
                    chunk.captured_len,
                    chunk.session_key.clone(),
                );
                let mut attributes = BTreeMap::new();
                attributes.insert("link_variant".to_string(), link_variant.clone());
                attributes.insert("npdu_control".to_string(), format!("{npdu_control:#04x}"));
                attributes.insert("apdu_type".to_string(), apdu_type.clone());
                if let Some(function) = &bvlc_function {
                    attributes.insert("bvlc_function".to_string(), function.clone());
                }
                if let Some(invoke_id) = invoke_id {
                    attributes.insert("invoke_id".to_string(), invoke_id.to_string());
                }
                if let Some(vendor_id) = vendor_id {
                    attributes.insert("vendor_id".to_string(), vendor_id.to_string());
                }
                if let Some(device_instance) = device_instance {
                    attributes.insert("device_instance".to_string(), device_instance.to_string());
                }

                out.push(new_event(
                    chunk.capture_id.to_string(),
                    envelope.clone(),
                    BronzeEventFamily::ProtocolTransaction(ProtocolTransaction {
                        operation: normalize_operation_name(&service, "bacnet_message"),
                        status: bacnet_status(&apdu_type).to_string(),
                        request_summary: Some(format!("{apdu_type} {service}")),
                        response_summary: None,
                        object_refs: bacnet_object_refs(device_instance, invoke_id),
                        values: Vec::new(),
                        attributes,
                        modbus: None,
                        protocol_fields: None,
                    }),
                ));

                if let Some(device_instance) = device_instance {
                    let mut identifiers = BTreeMap::from([
                        ("ip".to_string(), chunk.context.src_ip.to_string()),
                        (
                            "bacnet_device_instance".to_string(),
                            device_instance.to_string(),
                        ),
                    ]);
                    if let Some(vendor_id) = vendor_id {
                        identifiers.insert("bacnet_vendor_id".to_string(), vendor_id.to_string());
                    }
                    out.push(new_event(
                        chunk.capture_id.to_string(),
                        envelope.clone(),
                        BronzeEventFamily::AssetObservation(AssetObservation {
                            asset_key: chunk.context.src_ip.to_string(),
                            role: Some("device".to_string()),
                            vendor: None,
                            model: None,
                            firmware: None,
                            hostnames: Vec::new(),
                            protocols: vec!["bacnet".to_string()],
                            identifiers,
                        }),
                    ));
                }

                out.push(new_event(
                    chunk.capture_id.to_string(),
                    envelope.clone(),
                    BronzeEventFamily::TopologyObservation(TopologyObservation {
                        observation_type: "bacnet_transaction".to_string(),
                        local_id: chunk.context.src_ip.to_string(),
                        remote_id: Some(chunk.context.dst_ip.to_string()),
                        description: Some(service.clone()),
                        capabilities: Vec::new(),
                        metadata: BTreeMap::from([
                            ("link_variant".to_string(), link_variant),
                            ("apdu_type".to_string(), apdu_type.clone()),
                        ]),
                    }),
                ));

                if !payload.is_empty() {
                    out.push(artifact_event(
                        chunk.capture_id.to_string(),
                        envelope,
                        "bacnet_apdu",
                        &format!("{}:{}", service, chunk.frame_index),
                        Some("application/octet-stream"),
                        Some("BACnet APDU payload"),
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
                    Some("bacnet"),
                    chunk.captured_len,
                    chunk.session_key.clone(),
                ),
                self.name(),
                "medium",
                "failed to parse bacnet payload",
                chunk.payload,
            )),
        }
    }
}

fn bacnet_status(apdu_type: &str) -> &'static str {
    match apdu_type {
        "confirmed_request" | "unconfirmed_request" => "request",
        "simple_ack" | "complex_ack" => "response",
        "error" | "reject" | "abort" => "error",
        _ => "observed",
    }
}

fn bacnet_object_refs(device_instance: Option<u32>, invoke_id: Option<u8>) -> Vec<String> {
    let mut refs = Vec::new();
    if let Some(device_instance) = device_instance {
        refs.push(format!("bacnet_device:{device_instance}"));
    }
    if let Some(invoke_id) = invoke_id {
        refs.push(format!("bacnet_invoke:{invoke_id}"));
    }
    refs
}

inventory::submit!(crate::engine::decoders::DecoderRegistration {
    name: "bacnet",
    factory: || Box::new(BacnetDecoder::default()),
});
