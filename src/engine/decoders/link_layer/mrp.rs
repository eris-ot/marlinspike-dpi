use std::collections::BTreeMap;

use crate::bronze::{
    AssetObservation, BronzeEvent, BronzeEventFamily, TopologyObservation, TransportProtocol,
};
use crate::dissectors::mrp::MrpDissector;
use crate::engine::{DecoderInterest, SessionDecoder, StreamChunk, build_envelope, new_event};
use crate::registry::{MrpFields, ProtocolData, ProtocolDissector, format_mac};

#[derive(Default)]
pub(crate) struct MrpDecoder {
    dissector: MrpDissector,
}

impl SessionDecoder for MrpDecoder {
    fn name(&self) -> &'static str {
        "mrp"
    }

    fn interest(&self) -> &'static [DecoderInterest] {
        &[DecoderInterest::EtherType(0x88E3)]
    }

    fn on_datagram(&mut self, chunk: &StreamChunk<'_>, out: &mut Vec<BronzeEvent>) {
        if let Some(ProtocolData::Mrp(MrpFields {
            version: _,
            frame_type: _,
            frame_type_name,
            domain_uuid,
            ring_state,
            priority,
            source_mac,
        })) = self.dissector.parse(chunk.payload, &chunk.context)
        {
            let envelope = build_envelope(
                &chunk.context,
                chunk.interface_id,
                chunk.frame_index,
                chunk.timestamp,
                chunk.segment_hash,
                TransportProtocol::Ethernet,
                Some("mrp"),
                chunk.captured_len,
                chunk.session_key.clone(),
            );

            let mut metadata = BTreeMap::new();
            if let Some(ref uuid) = domain_uuid {
                metadata.insert("domain_uuid".to_string(), uuid.clone());
            }
            if let Some(ref state) = ring_state {
                metadata.insert("ring_state".to_string(), state.clone());
            }
            if let Some(prio) = priority {
                metadata.insert("priority".to_string(), prio.to_string());
            }

            let local_id = source_mac
                .clone()
                .unwrap_or_else(|| format_mac(&chunk.context.src_mac));

            out.push(new_event(
                chunk.capture_id.to_string(),
                envelope.clone(),
                BronzeEventFamily::TopologyObservation(TopologyObservation {
                    observation_type: format!("mrp_{}", frame_type_name.to_lowercase()),
                    local_id: local_id.clone(),
                    remote_id: domain_uuid,
                    description: ring_state.clone(),
                    capabilities: vec!["mrp".to_string()],
                    metadata,
                }),
            ));

            out.push(new_event(
                chunk.capture_id.to_string(),
                envelope,
                BronzeEventFamily::AssetObservation(AssetObservation {
                    asset_key: local_id,
                    role: Some("switch".to_string()),
                    vendor: None,
                    model: None,
                    firmware: None,
                    hostnames: vec![],
                    protocols: vec!["mrp".to_string()],
                    identifiers: BTreeMap::from([(
                        "mac".to_string(),
                        format_mac(&chunk.context.src_mac),
                    )]),
                }),
            ));
        }
    }
}

inventory::submit!(crate::engine::decoders::DecoderRegistration {
    name: "mrp",
    factory: || Box::new(MrpDecoder::default()),
});
