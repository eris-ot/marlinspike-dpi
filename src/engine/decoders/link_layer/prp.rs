use std::collections::BTreeMap;

use crate::bronze::{
    AssetObservation, BronzeEvent, BronzeEventFamily, TopologyObservation, TransportProtocol,
};
use crate::dissectors::prp::PrpDissector;
use crate::engine::{DecoderInterest, SessionDecoder, StreamChunk, build_envelope, new_event};
use crate::registry::{ProtocolData, ProtocolDissector, PrpFields, format_mac};

#[derive(Default)]
pub(crate) struct PrpDecoder {
    dissector: PrpDissector,
}

impl SessionDecoder for PrpDecoder {
    fn name(&self) -> &'static str {
        "prp"
    }

    fn interest(&self) -> &'static [DecoderInterest] {
        &[DecoderInterest::EtherType(0x88FB)]
    }

    fn on_datagram(&mut self, chunk: &StreamChunk<'_>, out: &mut Vec<BronzeEvent>) {
        if let Some(ProtocolData::Prp(PrpFields {
            supervision_type_name,
            source_mac,
            red_box_mac,
            sequence_nr,
            ..
        })) = self.dissector.parse(chunk.payload, &chunk.context)
        {
            let envelope = build_envelope(
                &chunk.context,
                chunk.interface_id,
                chunk.frame_index,
                chunk.timestamp,
                chunk.segment_hash,
                TransportProtocol::Ethernet,
                Some("prp"),
                chunk.captured_len,
                chunk.session_key.clone(),
            );

            let local_id = source_mac
                .clone()
                .unwrap_or_else(|| format_mac(&chunk.context.src_mac));

            let mut metadata = BTreeMap::new();
            if let Some(seq) = sequence_nr {
                metadata.insert("sequence_nr".to_string(), seq.to_string());
            }
            if let Some(ref rb) = red_box_mac {
                metadata.insert("red_box_mac".to_string(), rb.clone());
            }

            out.push(new_event(
                chunk.capture_id.to_string(),
                envelope.clone(),
                BronzeEventFamily::TopologyObservation(TopologyObservation {
                    observation_type: format!("prp_{}", supervision_type_name.to_lowercase()),
                    local_id: local_id.clone(),
                    remote_id: red_box_mac,
                    description: Some("PRP supervision".to_string()),
                    capabilities: vec!["prp".to_string()],
                    metadata,
                }),
            ));

            out.push(new_event(
                chunk.capture_id.to_string(),
                envelope,
                BronzeEventFamily::AssetObservation(AssetObservation {
                    asset_key: local_id,
                    role: Some("prp_node".to_string()),
                    vendor: None,
                    model: None,
                    firmware: None,
                    hostnames: vec![],
                    protocols: vec!["prp".to_string()],
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
    name: "prp",
    factory: || Box::new(PrpDecoder::default()),
});
