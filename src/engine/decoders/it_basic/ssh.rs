use std::collections::BTreeMap;

use crate::bronze::{
    AssetObservation, BronzeEvent, BronzeEventFamily, ProtocolFields, ProtocolTransaction,
    SshBronzeFields, TransportProtocol,
};
use crate::dissectors::ssh::SshDissector;
use crate::engine::{DecoderInterest, SessionDecoder, StreamChunk, build_envelope, new_event};
use crate::registry::{ProtocolData, ProtocolDissector, SshFields};

// ── SSH decoder ──────────────────────────────────────────────────

#[derive(Default)]
pub(crate) struct SshDecoder {
    dissector: SshDissector,
}

impl SessionDecoder for SshDecoder {
    fn name(&self) -> &'static str {
        "ssh"
    }

    fn interest(&self) -> &'static [DecoderInterest] {
        &[DecoderInterest::TcpPort(22)]
    }

    fn on_stream_chunk(&mut self, chunk: &StreamChunk<'_>, out: &mut Vec<BronzeEvent>) {
        // Only parse banner packets (contain "SSH-").
        if !chunk.payload.windows(4).any(|w| w == b"SSH-") {
            return;
        }
        if let Some(ProtocolData::Ssh(SshFields {
            protocol_version,
            software_version,
            comments,
            banner,
        })) = self.dissector.parse(chunk.payload, &chunk.context)
        {
            let envelope = build_envelope(
                &chunk.context,
                chunk.interface_id,
                chunk.frame_index,
                chunk.timestamp,
                chunk.segment_hash,
                TransportProtocol::Tcp,
                Some("ssh"),
                chunk.captured_len,
                chunk.session_key.clone(),
            );

            let mut attributes = BTreeMap::new();
            attributes.insert("protocol_version".to_string(), protocol_version.clone());
            attributes.insert("software_version".to_string(), software_version.clone());
            if let Some(ref c) = comments {
                attributes.insert("comments".to_string(), c.clone());
            }

            let ssh_pf = SshBronzeFields {
                protocol_version: protocol_version.clone(),
                software_version: software_version.clone(),
                comments: comments.clone(),
            };
            out.push(new_event(
                chunk.capture_id.to_string(),
                envelope.clone(),
                BronzeEventFamily::ProtocolTransaction(ProtocolTransaction {
                    operation: "banner".to_string(),
                    status: "ok".to_string(),
                    request_summary: Some(banner),
                    response_summary: None,
                    object_refs: vec![],
                    values: vec![],
                    attributes,
                    modbus: None,
                    protocol_fields: Some(ProtocolFields::Ssh(ssh_pf)),
                }),
            ));

            // The banner sender is the SSH server — identify it.
            let is_server = chunk.context.src_port == 22;
            let firmware = Some(software_version.clone());
            let role = if is_server {
                "ssh_server"
            } else {
                "ssh_client"
            };
            let ip = if is_server {
                chunk.context.src_ip.to_string()
            } else {
                chunk.context.dst_ip.to_string()
            };
            let mut identifiers = BTreeMap::from([("ip".to_string(), ip.clone())]);
            identifiers.insert("software_version".to_string(), software_version);
            if let Some(c) = comments {
                identifiers.insert("os_hint".to_string(), c);
            }

            out.push(new_event(
                chunk.capture_id.to_string(),
                envelope,
                BronzeEventFamily::AssetObservation(AssetObservation {
                    asset_key: ip,
                    role: Some(role.to_string()),
                    vendor: None,
                    model: None,
                    firmware,
                    hostnames: vec![],
                    protocols: vec!["ssh".to_string()],
                    identifiers,
                }),
            ));
        }
    }
}

// ── Inventory registration ──────────────────────────────────────
inventory::submit!(crate::engine::decoders::DecoderRegistration {
    name: "ssh",
    factory: || Box::new(SshDecoder::default()),
});
