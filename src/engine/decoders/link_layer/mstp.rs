use std::collections::BTreeMap;

use crate::bronze::{
    AssetObservation, BronzeEvent, BronzeEventFamily, TopologyObservation, TransportProtocol,
};
use crate::dissectors::mstp::MstpDissector;
use crate::engine::{DecoderInterest, SessionDecoder, StreamChunk, build_envelope, new_event};
use crate::registry::{ProtocolData, ProtocolDissector, format_mac};

#[derive(Default)]
pub(crate) struct MstpDecoder {
    dissector: MstpDissector,
}

impl SessionDecoder for MstpDecoder {
    fn name(&self) -> &'static str {
        "mstp"
    }

    fn interest(&self) -> &'static [DecoderInterest] {
        &[DecoderInterest::Llc {
            dsap: 0x42,
            ssap: 0x42,
        }]
    }

    fn on_datagram(&mut self, chunk: &StreamChunk<'_>, out: &mut Vec<BronzeEvent>) {
        // Only handle version >= 3; regular STP/RSTP falls through to StpDecoder.
        let fields = match self.dissector.parse(chunk.payload, &chunk.context) {
            Some(ProtocolData::Mstp(f)) => f,
            _ => return,
        };

        let envelope = build_envelope(
            &chunk.context,
            chunk.interface_id,
            chunk.frame_index,
            chunk.timestamp,
            chunk.segment_hash,
            TransportProtocol::Ethernet,
            Some("mstp"),
            chunk.captured_len,
            chunk.session_key.clone(),
        );

        let mut metadata = BTreeMap::new();
        metadata.insert(
            "protocol_version".to_string(),
            fields.protocol_version.to_string(),
        );
        if let Some(ref name) = fields.config_name {
            metadata.insert("config_name".to_string(), name.clone());
        }
        if let Some(rev) = fields.revision_level {
            metadata.insert("revision_level".to_string(), rev.to_string());
        }
        metadata.insert(
            "msti_count".to_string(),
            fields.msti_records.len().to_string(),
        );

        out.push(new_event(
            chunk.capture_id.to_string(),
            envelope.clone(),
            BronzeEventFamily::TopologyObservation(TopologyObservation {
                observation_type: "mstp_bpdu".to_string(),
                local_id: fields.bridge_id.clone(),
                remote_id: Some(fields.root_id.clone()),
                description: fields.config_name.clone(),
                capabilities: vec!["mstp".to_string()],
                metadata,
            }),
        ));

        out.push(new_event(
            chunk.capture_id.to_string(),
            envelope,
            BronzeEventFamily::AssetObservation(AssetObservation {
                asset_key: fields.bridge_id.clone(),
                role: Some("switch".to_string()),
                vendor: None,
                model: None,
                firmware: None,
                hostnames: vec![],
                protocols: vec!["mstp".to_string()],
                identifiers: BTreeMap::from([
                    ("mac".to_string(), format_mac(&chunk.context.src_mac)),
                    ("bridge_id".to_string(), fields.bridge_id),
                ]),
            }),
        ));
    }
}

inventory::submit!(crate::engine::decoders::DecoderRegistration {
    name: "mstp",
    factory: || Box::new(MstpDecoder::default()),
});
