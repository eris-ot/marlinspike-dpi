use std::collections::BTreeMap;

use crate::bronze::{
    AssetObservation, BronzeEvent, BronzeEventFamily, TopologyObservation, TransportProtocol,
};
use crate::dissectors::lldp::LldpDissector;
use crate::engine::{
    DecoderInterest, SessionDecoder, StreamChunk, build_envelope, new_event, parse_anomaly_event,
};
use crate::registry::{LldpFields, ProtocolData, ProtocolDissector, format_mac};

#[derive(Default)]
pub(crate) struct LldpDecoder {
    dissector: LldpDissector,
}

impl SessionDecoder for LldpDecoder {
    fn name(&self) -> &'static str {
        "lldp"
    }

    fn interest(&self) -> &'static [DecoderInterest] {
        &[DecoderInterest::EtherType(0x88CC)]
    }

    fn on_datagram(&mut self, chunk: &StreamChunk<'_>, out: &mut Vec<BronzeEvent>) {
        match self.dissector.parse(chunk.payload, &chunk.context) {
            Some(ProtocolData::Lldp(LldpFields {
                chassis_id,
                port_id,
                system_name,
                system_description,
                capabilities,
                ..
            })) => {
                let envelope = build_envelope(
                    &chunk.context,
                    chunk.interface_id,
                    chunk.frame_index,
                    chunk.timestamp,
                    chunk.segment_hash,
                    TransportProtocol::Ethernet,
                    Some("lldp"),
                    chunk.captured_len,
                    chunk.session_key.clone(),
                );
                out.push(new_event(
                    chunk.capture_id.to_string(),
                    envelope.clone(),
                    BronzeEventFamily::AssetObservation(AssetObservation {
                        asset_key: chassis_id.clone(),
                        role: Some("switch".to_string()),
                        vendor: (!system_name.is_empty()).then_some(system_name.clone()),
                        model: (!system_description.is_empty())
                            .then_some(system_description.clone()),
                        firmware: None,
                        hostnames: Vec::new(),
                        protocols: vec!["lldp".to_string()],
                        identifiers: BTreeMap::from([
                            ("chassis_id".to_string(), chassis_id.clone()),
                            ("port_id".to_string(), port_id.clone()),
                        ]),
                    }),
                ));
                out.push(new_event(
                    chunk.capture_id.to_string(),
                    envelope,
                    BronzeEventFamily::TopologyObservation(TopologyObservation {
                        observation_type: "lldp_neighbor".to_string(),
                        local_id: format_mac(&chunk.context.src_mac),
                        remote_id: Some(chassis_id),
                        description: Some(port_id),
                        capabilities,
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
                    TransportProtocol::Ethernet,
                    Some("lldp"),
                    chunk.captured_len,
                    chunk.session_key.clone(),
                ),
                self.name(),
                "medium",
                "failed to parse lldp payload",
                chunk.payload,
            )),
        }
    }
}

inventory::submit!(crate::engine::decoders::DecoderRegistration {
    name: "lldp",
    factory: || Box::new(LldpDecoder::default()),
});
