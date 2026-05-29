use std::collections::BTreeMap;

use crate::bronze::{
    AssetObservation, BronzeEvent, BronzeEventFamily, ProtocolTransaction, TransportProtocol,
};
use crate::dissectors::vtp::VtpDissector;
use crate::engine::{DecoderInterest, SessionDecoder, StreamChunk, build_envelope, new_event};
use crate::registry::{ProtocolData, ProtocolDissector, VtpFields, format_mac};

#[derive(Default)]
pub(crate) struct VtpDecoder {
    dissector: VtpDissector,
}

impl SessionDecoder for VtpDecoder {
    fn name(&self) -> &'static str {
        "vtp"
    }

    fn interest(&self) -> &'static [DecoderInterest] {
        &[DecoderInterest::Snap {
            oui: [0x00, 0x00, 0x0C],
            pid: 0x2003,
        }]
    }

    fn on_datagram(&mut self, chunk: &StreamChunk<'_>, out: &mut Vec<BronzeEvent>) {
        if let Some(ProtocolData::Vtp(VtpFields {
            version,
            message_type: _,
            message_type_name,
            domain_name,
            revision,
            vlans,
        })) = self.dissector.parse(chunk.payload, &chunk.context)
        {
            let envelope = build_envelope(
                &chunk.context,
                chunk.interface_id,
                chunk.frame_index,
                chunk.timestamp,
                chunk.segment_hash,
                TransportProtocol::Ethernet,
                Some("vtp"),
                chunk.captured_len,
                chunk.session_key.clone(),
            );

            let mut attributes = BTreeMap::new();
            attributes.insert("version".to_string(), version.to_string());
            attributes.insert("domain_name".to_string(), domain_name.clone());
            if let Some(rev) = revision {
                attributes.insert("revision".to_string(), rev.to_string());
            }
            if !vlans.is_empty() {
                attributes.insert(
                    "vlans".to_string(),
                    vlans
                        .iter()
                        .map(|v| v.to_string())
                        .collect::<Vec<_>>()
                        .join(","),
                );
            }

            out.push(new_event(
                chunk.capture_id.to_string(),
                envelope.clone(),
                BronzeEventFamily::ProtocolTransaction(ProtocolTransaction {
                    operation: message_type_name,
                    status: "ok".to_string(),
                    request_summary: Some(format!("VTP domain={domain_name}")),
                    response_summary: None,
                    object_refs: vec![domain_name.clone()],
                    values: vec![],
                    attributes,
                    modbus: None,
                    protocol_fields: None,
                }),
            ));

            out.push(new_event(
                chunk.capture_id.to_string(),
                envelope,
                BronzeEventFamily::AssetObservation(AssetObservation {
                    asset_key: format_mac(&chunk.context.src_mac),
                    role: Some("switch".to_string()),
                    vendor: Some("Cisco".to_string()),
                    model: None,
                    firmware: None,
                    hostnames: vec![],
                    protocols: vec!["vtp".to_string()],
                    identifiers: BTreeMap::from([
                        ("mac".to_string(), format_mac(&chunk.context.src_mac)),
                        ("vtp_domain".to_string(), domain_name),
                    ]),
                }),
            ));
        }
    }
}

inventory::submit!(crate::engine::decoders::DecoderRegistration {
    name: "vtp",
    factory: || Box::new(VtpDecoder::default()),
});
