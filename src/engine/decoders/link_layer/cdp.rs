use std::collections::BTreeMap;

use crate::bronze::{
    AssetObservation, BronzeEvent, BronzeEventFamily, TopologyObservation, TransportProtocol,
};
use crate::dissectors::cdp::CdpDissector;
use crate::engine::{
    DecoderInterest, SessionDecoder, StreamChunk, build_envelope, new_event, parse_anomaly_event,
};
use crate::registry::{CdpFields, ProtocolData, ProtocolDissector, format_mac};

#[derive(Default)]
pub(crate) struct CdpDecoder {
    dissector: CdpDissector,
}

impl SessionDecoder for CdpDecoder {
    fn name(&self) -> &'static str {
        "cdp"
    }

    fn interest(&self) -> &'static [DecoderInterest] {
        &[DecoderInterest::Snap {
            oui: [0x00, 0x00, 0x0C],
            pid: 0x2000,
        }]
    }

    fn on_datagram(&mut self, chunk: &StreamChunk<'_>, out: &mut Vec<BronzeEvent>) {
        match self.dissector.parse(chunk.payload, &chunk.context) {
            Some(ProtocolData::Cdp(CdpFields {
                device_id,
                port_id,
                platform,
                software_version,
                capabilities,
                native_vlan,
                duplex,
                ..
            })) => {
                let envelope = build_envelope(
                    &chunk.context,
                    chunk.interface_id,
                    chunk.frame_index,
                    chunk.timestamp,
                    chunk.segment_hash,
                    TransportProtocol::Ethernet,
                    Some("cdp"),
                    chunk.captured_len,
                    chunk.session_key.clone(),
                );
                let role = if capabilities.iter().any(|c| c == "switch") {
                    Some("switch".to_string())
                } else if capabilities.iter().any(|c| c == "router") {
                    Some("router".to_string())
                } else {
                    None
                };
                let mut identifiers = BTreeMap::from([
                    ("mac".to_string(), format_mac(&chunk.context.src_mac)),
                    ("device_id".to_string(), device_id.clone()),
                ]);
                if !port_id.is_empty() {
                    identifiers.insert("port_id".to_string(), port_id.clone());
                }
                if let Some(vlan) = native_vlan {
                    identifiers.insert("native_vlan".to_string(), vlan.to_string());
                }
                out.push(new_event(
                    chunk.capture_id.to_string(),
                    envelope.clone(),
                    BronzeEventFamily::AssetObservation(AssetObservation {
                        asset_key: device_id.clone(),
                        role,
                        vendor: Some("Cisco".to_string()),
                        model: platform,
                        firmware: software_version,
                        hostnames: vec![device_id.clone()],
                        protocols: vec!["cdp".to_string()],
                        identifiers,
                    }),
                ));

                let mut metadata = BTreeMap::new();
                if let Some(vlan) = native_vlan {
                    metadata.insert("native_vlan".to_string(), vlan.to_string());
                }
                if let Some(duplex) = duplex {
                    metadata.insert("duplex".to_string(), duplex);
                }
                out.push(new_event(
                    chunk.capture_id.to_string(),
                    envelope,
                    BronzeEventFamily::TopologyObservation(TopologyObservation {
                        observation_type: "cdp_neighbor".to_string(),
                        local_id: format_mac(&chunk.context.src_mac),
                        remote_id: Some(device_id),
                        description: (!port_id.is_empty()).then_some(port_id),
                        capabilities,
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
                    Some("cdp"),
                    chunk.captured_len,
                    chunk.session_key.clone(),
                ),
                self.name(),
                "medium",
                "failed to parse cdp payload",
                chunk.payload,
            )),
        }
    }
}

inventory::submit!(crate::engine::decoders::DecoderRegistration {
    name: "cdp",
    factory: || Box::new(CdpDecoder::default()),
});
