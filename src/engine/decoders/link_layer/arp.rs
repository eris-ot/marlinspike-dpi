use std::collections::BTreeMap;

use crate::bronze::{
    AssetObservation, BronzeEvent, BronzeEventFamily, TopologyObservation, TransportProtocol,
};
use crate::dissectors::arp::ArpDissector;
use crate::engine::{
    DecoderInterest, SessionDecoder, StreamChunk, build_envelope, new_event, parse_anomaly_event,
};
use crate::registry::{ArpFields, ProtocolData, ProtocolDissector, format_mac};

#[derive(Default)]
pub(crate) struct ArpDecoder {
    dissector: ArpDissector,
}

impl SessionDecoder for ArpDecoder {
    fn name(&self) -> &'static str {
        "arp"
    }

    fn interest(&self) -> &'static [DecoderInterest] {
        &[DecoderInterest::EtherType(0x0806)]
    }

    fn on_datagram(&mut self, chunk: &StreamChunk<'_>, out: &mut Vec<BronzeEvent>) {
        match self.dissector.parse(chunk.payload, &chunk.context) {
            Some(ProtocolData::Arp(ArpFields {
                sender_mac,
                sender_ip,
                target_mac,
                target_ip,
                operation,
            })) => {
                let envelope = build_envelope(
                    &chunk.context,
                    chunk.interface_id,
                    chunk.frame_index,
                    chunk.timestamp,
                    chunk.segment_hash,
                    TransportProtocol::Arp,
                    Some("arp"),
                    chunk.captured_len,
                    chunk.session_key.clone(),
                );
                let sender_ip = format!(
                    "{}.{}.{}.{}",
                    sender_ip[0], sender_ip[1], sender_ip[2], sender_ip[3]
                );
                let target_ip = format!(
                    "{}.{}.{}.{}",
                    target_ip[0], target_ip[1], target_ip[2], target_ip[3]
                );
                out.push(new_event(
                    chunk.capture_id.to_string(),
                    envelope.clone(),
                    BronzeEventFamily::AssetObservation(AssetObservation {
                        asset_key: format_mac(&sender_mac),
                        role: None,
                        vendor: None,
                        model: None,
                        firmware: None,
                        hostnames: Vec::new(),
                        protocols: vec!["arp".to_string()],
                        identifiers: BTreeMap::from([
                            ("mac".to_string(), format_mac(&sender_mac)),
                            ("ip".to_string(), sender_ip.clone()),
                        ]),
                    }),
                ));
                out.push(new_event(
                    chunk.capture_id.to_string(),
                    envelope,
                    BronzeEventFamily::TopologyObservation(TopologyObservation {
                        observation_type: if operation == 2 {
                            "arp_reply".to_string()
                        } else {
                            "arp_request".to_string()
                        },
                        local_id: sender_ip,
                        remote_id: Some(target_ip),
                        description: Some(format!(
                            "ARP op={operation} {} -> {}",
                            format_mac(&sender_mac),
                            format_mac(&target_mac)
                        )),
                        capabilities: Vec::new(),
                        metadata: BTreeMap::new(),
                    }),
                ));
            }
            _ => out.push(parse_anomaly_event(
                chunk.capture_id.to_string(),
                build_envelope(
                    &chunk.context,
                    chunk.interface_id,
                    chunk.frame_index,
                    chunk.timestamp,
                    chunk.segment_hash,
                    TransportProtocol::Arp,
                    Some("arp"),
                    chunk.captured_len,
                    chunk.session_key.clone(),
                ),
                self.name(),
                "medium",
                "failed to parse arp payload",
                chunk.payload,
            )),
        }
    }
}

inventory::submit!(crate::engine::decoders::DecoderRegistration {
    name: "arp",
    factory: || Box::new(ArpDecoder::default()),
});
