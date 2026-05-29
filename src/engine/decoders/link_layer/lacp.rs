use std::collections::BTreeMap;

use crate::bronze::{
    AssetObservation, BronzeEvent, BronzeEventFamily, TopologyObservation, TransportProtocol,
};
use crate::dissectors::lacp::LacpDissector;
use crate::engine::{DecoderInterest, SessionDecoder, StreamChunk, build_envelope, new_event};
use crate::registry::{LacpFields, ProtocolData, ProtocolDissector};

#[derive(Default)]
pub(crate) struct LacpDecoder {
    dissector: LacpDissector,
}

impl SessionDecoder for LacpDecoder {
    fn name(&self) -> &'static str {
        "lacp"
    }

    fn interest(&self) -> &'static [DecoderInterest] {
        &[DecoderInterest::EtherType(0x8809)]
    }

    fn on_datagram(&mut self, chunk: &StreamChunk<'_>, out: &mut Vec<BronzeEvent>) {
        if let Some(ProtocolData::Lacp(LacpFields {
            version: _,
            ref actor,
            ref partner,
            max_delay,
        })) = self.dissector.parse(chunk.payload, &chunk.context)
        {
            let envelope = build_envelope(
                &chunk.context,
                chunk.interface_id,
                chunk.frame_index,
                chunk.timestamp,
                chunk.segment_hash,
                TransportProtocol::Ethernet,
                Some("lacp"),
                chunk.captured_len,
                chunk.session_key.clone(),
            );

            let mut metadata = BTreeMap::new();
            metadata.insert("actor_system".to_string(), actor.system.clone());
            metadata.insert("actor_key".to_string(), actor.key.to_string());
            metadata.insert("actor_port".to_string(), actor.port.to_string());
            metadata.insert("partner_system".to_string(), partner.system.clone());
            metadata.insert("partner_key".to_string(), partner.key.to_string());
            metadata.insert("partner_port".to_string(), partner.port.to_string());
            if let Some(delay) = max_delay {
                metadata.insert("max_delay".to_string(), delay.to_string());
            }

            out.push(new_event(
                chunk.capture_id.to_string(),
                envelope.clone(),
                BronzeEventFamily::TopologyObservation(TopologyObservation {
                    observation_type: "lacp_bond".to_string(),
                    local_id: actor.system.clone(),
                    remote_id: Some(partner.system.clone()),
                    description: Some(format!(
                        "key={} port={} <-> key={} port={}",
                        actor.key, actor.port, partner.key, partner.port
                    )),
                    capabilities: actor.state_flags.clone(),
                    metadata,
                }),
            ));

            // Identify both actor and partner as switches.
            for (sys_mac, role_prefix) in [(&actor.system, "actor"), (&partner.system, "partner")] {
                out.push(new_event(
                    chunk.capture_id.to_string(),
                    envelope.clone(),
                    BronzeEventFamily::AssetObservation(AssetObservation {
                        asset_key: sys_mac.clone(),
                        role: Some("switch".to_string()),
                        vendor: None,
                        model: None,
                        firmware: None,
                        hostnames: vec![],
                        protocols: vec!["lacp".to_string()],
                        identifiers: BTreeMap::from([
                            ("system".to_string(), sys_mac.clone()),
                            ("lacp_role".to_string(), role_prefix.to_string()),
                        ]),
                    }),
                ));
            }
        }
    }
}

inventory::submit!(crate::engine::decoders::DecoderRegistration {
    name: "lacp",
    factory: || Box::new(LacpDecoder::default()),
});
