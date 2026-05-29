use std::collections::BTreeMap;

use crate::bronze::{
    AssetObservation, BronzeEvent, BronzeEventFamily, TopologyObservation, TransportProtocol,
};
use crate::dissectors::pvst::PvstDissector;
use crate::engine::{DecoderInterest, SessionDecoder, StreamChunk, build_envelope, new_event};
use crate::registry::{ProtocolData, ProtocolDissector, PvstFields, format_mac};

#[derive(Default)]
pub(crate) struct PvstDecoder {
    dissector: PvstDissector,
}

impl SessionDecoder for PvstDecoder {
    fn name(&self) -> &'static str {
        "pvst"
    }

    fn interest(&self) -> &'static [DecoderInterest] {
        &[DecoderInterest::Snap {
            oui: [0x00, 0x00, 0x0C],
            pid: 0x010B,
        }]
    }

    fn on_datagram(&mut self, chunk: &StreamChunk<'_>, out: &mut Vec<BronzeEvent>) {
        if let Some(ProtocolData::Pvst(PvstFields {
            protocol_version,
            bpdu_type: _,
            flags: _,
            root_id,
            root_path_cost,
            bridge_id,
            port_id,
            originating_vlan,
        })) = self.dissector.parse(chunk.payload, &chunk.context)
        {
            let envelope = build_envelope(
                &chunk.context,
                chunk.interface_id,
                chunk.frame_index,
                chunk.timestamp,
                chunk.segment_hash,
                TransportProtocol::Ethernet,
                Some("pvst"),
                chunk.captured_len,
                chunk.session_key.clone(),
            );

            let mut metadata = BTreeMap::new();
            metadata.insert("protocol_version".to_string(), protocol_version.to_string());
            metadata.insert("root_path_cost".to_string(), root_path_cost.to_string());
            metadata.insert("port_id".to_string(), format!("{port_id:#06x}"));
            if let Some(vlan) = originating_vlan {
                metadata.insert("originating_vlan".to_string(), vlan.to_string());
            }

            out.push(new_event(
                chunk.capture_id.to_string(),
                envelope.clone(),
                BronzeEventFamily::TopologyObservation(TopologyObservation {
                    observation_type: "pvst_bpdu".to_string(),
                    local_id: bridge_id.clone(),
                    remote_id: Some(root_id),
                    description: originating_vlan.map(|v| format!("VLAN {v}")),
                    capabilities: vec!["pvst".to_string()],
                    metadata,
                }),
            ));

            let mut identifiers = BTreeMap::from([
                ("mac".to_string(), format_mac(&chunk.context.src_mac)),
                ("bridge_id".to_string(), bridge_id.clone()),
            ]);
            if let Some(vlan) = originating_vlan {
                identifiers.insert("originating_vlan".to_string(), vlan.to_string());
            }

            out.push(new_event(
                chunk.capture_id.to_string(),
                envelope,
                BronzeEventFamily::AssetObservation(AssetObservation {
                    asset_key: bridge_id,
                    role: Some("switch".to_string()),
                    vendor: Some("Cisco".to_string()),
                    model: None,
                    firmware: None,
                    hostnames: vec![],
                    protocols: vec!["pvst".to_string()],
                    identifiers,
                }),
            ));
        }
    }
}

inventory::submit!(crate::engine::decoders::DecoderRegistration {
    name: "pvst",
    factory: || Box::new(PvstDecoder::default()),
});
