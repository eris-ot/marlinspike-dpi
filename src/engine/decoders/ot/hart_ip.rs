use std::collections::BTreeMap;

use crate::bronze::{
    AssetObservation, BronzeEvent, BronzeEventFamily, ProtocolTransaction, TopologyObservation,
    TransportProtocol,
};
use crate::dissectors::hart_ip::{parse_hart_ip_frames, HartIpBody, HartIpDissector, HartIpFields};
use crate::engine::{
    artifact_event, build_envelope, new_event, parse_anomaly_event, DecoderInterest,
    SessionDecoder, StreamChunk,
};
use crate::registry::{PacketContext, ProtocolData, ProtocolDissector};

use super::{context_asset_key, context_remote_asset_key, normalize_operation_name};

#[derive(Default)]
pub(crate) struct HartIpDecoderWrapper {
    dissector: HartIpDissector,
}

impl SessionDecoder for HartIpDecoderWrapper {
    fn name(&self) -> &'static str {
        "hart_ip"
    }

    fn interest(&self) -> &'static [DecoderInterest] {
        static INTERESTS: [DecoderInterest; 2] = [
            DecoderInterest::TcpPort(5094),
            DecoderInterest::UdpPort(5094),
        ];
        &INTERESTS
    }

    fn on_datagram(&mut self, chunk: &StreamChunk<'_>, out: &mut Vec<BronzeEvent>) {
        if !self.dissector.can_parse(
            chunk.payload,
            chunk.context.src_port,
            chunk.context.dst_port,
        ) {
            return;
        }

        match self.dissector.parse(chunk.payload, &chunk.context) {
            Some(ProtocolData::HartIp(fields)) => {
                self.emit_frame(chunk, TransportProtocol::Udp, fields, out)
            }
            _ => out.push(parse_anomaly_event(
                chunk.capture_id.to_string(),
                build_envelope(
                    &chunk.context,
                    chunk.interface_id,
                    chunk.frame_index,
                    chunk.timestamp,
                    chunk.segment_hash,
                    TransportProtocol::Udp,
                    Some("hart_ip"),
                    chunk.captured_len,
                    chunk.session_key.clone(),
                ),
                self.name(),
                "medium",
                "failed to parse hart ip payload",
                chunk.payload,
            )),
        }
    }

    fn on_stream_chunk(&mut self, chunk: &StreamChunk<'_>, out: &mut Vec<BronzeEvent>) {
        if !self.dissector.can_parse(
            chunk.payload,
            chunk.context.src_port,
            chunk.context.dst_port,
        ) {
            return;
        }

        let frames = parse_hart_ip_frames(chunk.payload);
        if frames.is_empty() {
            out.push(parse_anomaly_event(
                chunk.capture_id.to_string(),
                build_envelope(
                    &chunk.context,
                    chunk.interface_id,
                    chunk.frame_index,
                    chunk.timestamp,
                    chunk.segment_hash,
                    TransportProtocol::Tcp,
                    Some("hart_ip"),
                    chunk.captured_len,
                    chunk.session_key.clone(),
                ),
                self.name(),
                "medium",
                "failed to parse hart ip payload",
                chunk.payload,
            ));
            return;
        }

        for fields in frames {
            self.emit_frame(chunk, TransportProtocol::Tcp, fields, out);
        }
    }
}

impl HartIpDecoderWrapper {
    fn emit_frame(
        &self,
        chunk: &StreamChunk<'_>,
        transport: TransportProtocol,
        fields: HartIpFields,
        out: &mut Vec<BronzeEvent>,
    ) {
        let envelope = build_envelope(
            &chunk.context,
            chunk.interface_id,
            chunk.frame_index,
            chunk.timestamp,
            chunk.segment_hash,
            transport,
            Some("hart_ip"),
            chunk.captured_len,
            chunk.session_key.clone(),
        );

        let mut attributes = BTreeMap::new();
        attributes.insert("version".to_string(), fields.version.to_string());
        attributes.insert("message_type".to_string(), fields.message_type.clone());
        attributes.insert("message_id".to_string(), fields.message_id.clone());
        attributes.insert("status".to_string(), format!("{:#04x}", fields.status));
        attributes.insert(
            "transaction_id".to_string(),
            fields.transaction_id.to_string(),
        );
        attributes.insert(
            "message_length".to_string(),
            fields.message_length.to_string(),
        );

        let mut object_refs = Vec::new();
        let mut device_identity = None;
        let mut device_tag = None;
        let body_summary = match &fields.body {
            HartIpBody::SessionInitiate {
                master_type,
                inactivity_close_timer,
            } => {
                attributes.insert("master_type".to_string(), master_type.clone());
                attributes.insert(
                    "inactivity_close_timer".to_string(),
                    inactivity_close_timer.to_string(),
                );
                Some(format!("session_initiate {master_type}"))
            }
            HartIpBody::SessionClose => Some("session_close".to_string()),
            HartIpBody::KeepAlive => Some("keep_alive".to_string()),
            HartIpBody::Error { error_code, .. } => {
                if let Some(error_code) = error_code {
                    attributes.insert("error_code".to_string(), format!("{error_code:#04x}"));
                }
                Some("error".to_string())
            }
            HartIpBody::PassThrough(pass) => {
                attributes.insert("frame_type".to_string(), pass.frame_type.clone());
                attributes.insert(
                    "physical_layer_type".to_string(),
                    pass.physical_layer_type.clone(),
                );
                attributes.insert("address_type".to_string(), pass.address_type.clone());
                attributes.insert("command".to_string(), pass.command.to_string());
                attributes.insert("payload_length".to_string(), pass.payload.len().to_string());
                object_refs.push(format!("hart_command:{}", pass.command));
                if let Some(identity) = &pass.identity {
                    if let Some(manufacturer_id) = identity.manufacturer_id {
                        object_refs.push(format!("hart_manufacturer:{manufacturer_id}"));
                    }
                    if let Some(device_type) = identity.device_type {
                        object_refs.push(format!("hart_device_type:{device_type}"));
                    }
                    device_tag = identity.tag.clone();
                    device_identity = Some(identity.clone());
                }
                Some(format!(
                    "{} {}",
                    pass.frame_type,
                    hart_passthrough_command_name(pass.command)
                ))
            }
            HartIpBody::Raw(body) => Some(format!("raw {} bytes", body.len())),
        };

        out.push(new_event(
            chunk.capture_id.to_string(),
            envelope.clone(),
            BronzeEventFamily::ProtocolTransaction(ProtocolTransaction {
                operation: hart_ip_operation_name(&fields),
                status: hart_ip_status(&fields).to_string(),
                request_summary: body_summary,
                response_summary: None,
                object_refs,
                values: Vec::new(),
                attributes,
                        modbus: None,
                                        protocol_fields: None,
}),
        ));

        if let Some(identity) = device_identity {
            let mut identifiers = BTreeMap::new();
            identifiers.insert(
                "ip".to_string(),
                hart_ip_device_asset_key(&chunk.context, &fields).to_string(),
            );
            if let Some(manufacturer_id) = identity.manufacturer_id {
                identifiers.insert(
                    "hart_manufacturer_id".to_string(),
                    manufacturer_id.to_string(),
                );
            }
            if let Some(device_type) = identity.device_type {
                identifiers.insert("hart_device_type".to_string(), device_type.to_string());
            }
            if let Some(tag) = &identity.tag {
                identifiers.insert("hart_tag".to_string(), tag.clone());
            }
            if let Some(revision) = identity.hart_universal_revision {
                identifiers.insert("hart_universal_revision".to_string(), revision.to_string());
            }
            if let Some(revision) = identity.device_revision {
                identifiers.insert("hart_device_revision".to_string(), revision.to_string());
            }
            if let Some(revision) = identity.software_revision {
                identifiers.insert("hart_software_revision".to_string(), revision.to_string());
            }
            if let Some(revision) = identity.hardware_revision {
                identifiers.insert("hart_hardware_revision".to_string(), revision.to_string());
            }
            if let Some(counter) = identity.configuration_change_counter {
                identifiers.insert(
                    "hart_configuration_change_counter".to_string(),
                    counter.to_string(),
                );
            }
            if let Some(status) = identity.extended_device_status {
                identifiers.insert(
                    "hart_extended_device_status".to_string(),
                    status.to_string(),
                );
            }
            if let Some(device_id) = identity.device_id {
                identifiers.insert("hart_device_id".to_string(), hex::encode(device_id));
            }
            out.push(new_event(
                chunk.capture_id.to_string(),
                envelope.clone(),
                BronzeEventFamily::AssetObservation(AssetObservation {
                    asset_key: hart_ip_device_asset_key(&chunk.context, &fields),
                    role: Some("field_device".to_string()),
                    vendor: None,
                    model: identity
                        .device_type
                        .map(|device_type| format!("device_type_{device_type}")),
                    firmware: identity
                        .software_revision
                        .map(|revision| revision.to_string()),
                    hostnames: device_tag.into_iter().collect(),
                    protocols: vec!["hart_ip".to_string()],
                    identifiers,
                }),
            ));
        }

        if matches!(fields.body, HartIpBody::SessionInitiate { .. }) {
            out.push(new_event(
                chunk.capture_id.to_string(),
                envelope.clone(),
                BronzeEventFamily::AssetObservation(AssetObservation {
                    asset_key: context_asset_key(&chunk.context),
                    role: Some("host".to_string()),
                    vendor: None,
                    model: None,
                    firmware: None,
                    hostnames: Vec::new(),
                    protocols: vec!["hart_ip".to_string()],
                    identifiers: BTreeMap::from([(
                        "ip".to_string(),
                        chunk.context.src_ip.to_string(),
                    )]),
                }),
            ));
        }

        out.push(new_event(
            chunk.capture_id.to_string(),
            envelope.clone(),
            BronzeEventFamily::TopologyObservation(TopologyObservation {
                observation_type: "hart_ip_transaction".to_string(),
                local_id: context_asset_key(&chunk.context),
                remote_id: Some(context_remote_asset_key(&chunk.context)),
                description: Some(fields.message_id.clone()),
                capabilities: Vec::new(),
                metadata: BTreeMap::from([(
                    "message_type".to_string(),
                    fields.message_type.clone(),
                )]),
            }),
        ));

        if !fields.payload.is_empty() {
            out.push(artifact_event(
                chunk.capture_id.to_string(),
                envelope,
                "hart_ip_payload",
                &format!("{}:{}", chunk.session_key, fields.transaction_id),
                Some("application/octet-stream"),
                Some("HART-IP message payload"),
                &fields.payload,
            ));
        }
    }
}

fn hart_ip_operation_name(fields: &HartIpFields) -> String {
    match &fields.body {
        HartIpBody::PassThrough(pass) => normalize_operation_name(
            hart_passthrough_command_name(pass.command),
            "hart_pass_through",
        ),
        _ => normalize_operation_name(&fields.message_id, "hart_ip"),
    }
}

fn hart_ip_status(fields: &HartIpFields) -> &'static str {
    match fields.message_type.as_str() {
        "request" => "request",
        "response" => "response",
        "publish" => "publish",
        "error" | "nak" => "error",
        _ => "observed",
    }
}

fn hart_passthrough_command_name(command: u8) -> &'static str {
    match command {
        0 => "read_unique_identifier",
        11 => "read_device_identity",
        20 => "read_long_tag",
        21 => "read_tag_descriptor",
        22 => "read_message",
        _ => "pass_through_command",
    }
}

fn hart_ip_device_asset_key(context: &PacketContext, fields: &HartIpFields) -> String {
    if hart_ip_status(fields) == "response" {
        context_asset_key(context)
    } else {
        context_remote_asset_key(context)
    }
}

inventory::submit!(crate::engine::decoders::DecoderRegistration {
    name: "hart_ip",
    factory: || Box::new(HartIpDecoderWrapper::default()),
});
