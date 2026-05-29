use std::collections::BTreeMap;

use crate::bronze::{
    AssetObservation, BronzeEvent, BronzeEventFamily, TopologyObservation, TransportProtocol,
};
use crate::dissectors::stp::StpDissector;
use crate::engine::{
    DecoderInterest, SessionDecoder, StreamChunk, build_envelope, new_event, parse_anomaly_event,
};
use crate::registry::{ProtocolData, ProtocolDissector, StpFields, format_mac};

#[derive(Default)]
pub(crate) struct StpDecoder {
    dissector: StpDissector,
}

impl SessionDecoder for StpDecoder {
    fn name(&self) -> &'static str {
        "stp"
    }

    fn interest(&self) -> &'static [DecoderInterest] {
        &[DecoderInterest::Llc {
            dsap: 0x42,
            ssap: 0x42,
        }]
    }

    fn on_datagram(&mut self, chunk: &StreamChunk<'_>, out: &mut Vec<BronzeEvent>) {
        match self.dissector.parse(chunk.payload, &chunk.context) {
            Some(ProtocolData::Stp(StpFields {
                protocol_version,
                bpdu_type,
                flags,
                root_id,
                root_path_cost,
                bridge_id,
                port_id,
                ..
            })) => {
                let envelope = build_envelope(
                    &chunk.context,
                    chunk.interface_id,
                    chunk.frame_index,
                    chunk.timestamp,
                    chunk.segment_hash,
                    TransportProtocol::Ethernet,
                    Some("stp"),
                    chunk.captured_len,
                    chunk.session_key.clone(),
                );
                let mut identifiers = BTreeMap::from([
                    ("mac".to_string(), format_mac(&chunk.context.src_mac)),
                    ("bridge_id".to_string(), bridge_id.clone()),
                    ("root_id".to_string(), root_id.clone()),
                    ("port_id".to_string(), format!("{port_id:#06x}")),
                ]);
                identifiers.insert("root_path_cost".to_string(), root_path_cost.to_string());
                out.push(new_event(
                    chunk.capture_id.to_string(),
                    envelope.clone(),
                    BronzeEventFamily::AssetObservation(AssetObservation {
                        asset_key: bridge_id.clone(),
                        role: Some("switch".to_string()),
                        vendor: None,
                        model: None,
                        firmware: None,
                        hostnames: Vec::new(),
                        protocols: vec!["stp".to_string()],
                        identifiers,
                    }),
                ));

                let mut metadata = BTreeMap::new();
                metadata.insert("protocol_version".to_string(), protocol_version.to_string());
                metadata.insert("bpdu_type".to_string(), format!("{bpdu_type:#04x}"));
                metadata.insert("flags".to_string(), format!("{flags:#04x}"));
                metadata.insert("root_path_cost".to_string(), root_path_cost.to_string());
                metadata.insert("port_id".to_string(), format!("{port_id:#06x}"));
                out.push(new_event(
                    chunk.capture_id.to_string(),
                    envelope,
                    BronzeEventFamily::TopologyObservation(TopologyObservation {
                        observation_type: "stp_topology".to_string(),
                        local_id: bridge_id,
                        remote_id: Some(root_id),
                        description: Some("spanning_tree_bpdu".to_string()),
                        capabilities: Vec::new(),
                        metadata,
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
                    Some("stp"),
                    chunk.captured_len,
                    chunk.session_key.clone(),
                ),
                self.name(),
                "medium",
                "failed to parse stp payload",
                chunk.payload,
            )),
        }
    }
}

inventory::submit!(crate::engine::decoders::DecoderRegistration {
    name: "stp",
    factory: || Box::new(StpDecoder::default()),
});
