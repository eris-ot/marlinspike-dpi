//! HART-IP session decoder (TCP/UDP port 5094).
//!
//! Emits [`ProtocolTransaction`] events with both the legacy
//! `attributes: BTreeMap<String, String>` surface **and** the typed
//! `protocol_fields: Some(ProtocolFields::HartIp(HartIpBronzeFields))`
//! surface introduced in Bronze v2. Downstream consumers should prefer the
//! typed surface; `attributes` is retained for backward compatibility through
//! the v1.x line and will be removed in v2.0.

use std::collections::BTreeMap;

use crate::bronze::{
    AssetObservation, BronzeEvent, BronzeEventFamily, HartIpBronzeFields, ProtocolFields,
    ProtocolTransaction, TopologyObservation, TransportProtocol,
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

        let pf = hart_ip_bronze_fields(&fields);
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
                protocol_fields: Some(ProtocolFields::HartIp(pf)),
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

/// Build the typed [`HartIpBronzeFields`] from a dissected [`HartIpFields`].
fn hart_ip_bronze_fields(fields: &HartIpFields) -> HartIpBronzeFields {
    // Recover the raw numeric message-type and message-id from the name
    // strings.  The dissector already called `hart_message_type_name` /
    // `hart_message_id_name`, so we reverse the mapping here.
    let message_type_raw = match fields.message_type.as_str() {
        "request" => 0u8,
        "response" => 1,
        "publish" => 2,
        "error" => 3,
        "nak" => 15,
        _ => 255,
    };
    let message_id_raw = match fields.message_id.as_str() {
        "session_initiate" => 0u8,
        "session_close" => 1,
        "keep_alive" => 2,
        "pass_through" => 3,
        _ => 255,
    };

    let (passthrough_command, passthrough_command_name, device_status, field_device_address) =
        match &fields.body {
            HartIpBody::PassThrough(pass) => {
                let addr = pass
                    .long_address
                    .map(|a| a.to_vec());
                (
                    Some(pass.command),
                    Some(hart_passthrough_command_name(pass.command).to_string()),
                    pass.device_status,
                    addr,
                )
            }
            _ => (None, None, None, None),
        };

    HartIpBronzeFields {
        message_type: message_type_raw,
        message_type_name: fields.message_type.clone(),
        message_id: message_id_raw,
        message_id_name: fields.message_id.clone(),
        status_byte: fields.status,
        sequence_number: fields.transaction_id,
        payload_length: fields.message_length,
        passthrough_command,
        passthrough_command_name,
        device_status,
        field_device_address,
        direction: hart_ip_status(fields).to_string(),
    }
}

inventory::submit!(crate::engine::decoders::DecoderRegistration {
    name: "hart_ip",
    factory: || Box::new(HartIpDecoderWrapper::default()),
});

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bronze::ProtocolFields;
    use crate::dissectors::hart_ip::{
        parse_hart_ip_frames, HartIpBody, HartIpDissector, HartIpFields,
    };
    use crate::registry::{ProtocolData, ProtocolDissector};

    const HART_IP_PORT: u16 = 5094;
    const HART_IP_HEADER_LEN: usize = 8;

    fn build_header(
        message_type: u8,
        message_id: u8,
        status: u8,
        transaction_id: u16,
        body: &[u8],
    ) -> Vec<u8> {
        let mut pkt = Vec::with_capacity(HART_IP_HEADER_LEN + body.len());
        let msg_len = (HART_IP_HEADER_LEN + body.len()) as u16;
        pkt.push(2); // version
        pkt.push(message_type);
        pkt.push(message_id);
        pkt.push(status);
        pkt.extend_from_slice(&transaction_id.to_be_bytes());
        pkt.extend_from_slice(&msg_len.to_be_bytes());
        pkt.extend_from_slice(body);
        pkt
    }

    /// Build a Pass-Through frame (message_id=3) using a polling (short)
    /// address so `long_address` is None and we can test `field_device_address`.
    fn build_pass_through_short(
        message_type: u8,
        command: u8,
        response: bool,
        command_data: &[u8],
    ) -> Vec<u8> {
        let mut body = Vec::new();
        body.extend_from_slice(&[0xFF, 0xFF]);
        // delimiter: STX (0x02) for request, ACK (0x06) for response; polling
        // address bit 7 = 0.
        body.push(if response { 0x06 } else { 0x02 });
        body.push(0x00); // short address = 0
        body.push(command);
        body.push((command_data.len() + if response { 2 } else { 0 }) as u8);
        if response {
            body.push(0x00); // response_code
            body.push(0x40); // device_status
        }
        body.extend_from_slice(command_data);
        body.push(0xAA); // checksum

        build_header(message_type, 3, 0, 0x0001, &body)
    }

    /// Build a Pass-Through frame using unique (long) 5-byte address.
    fn build_pass_through_long(
        message_type: u8,
        command: u8,
        response: bool,
        long_addr: [u8; 5],
        command_data: &[u8],
    ) -> Vec<u8> {
        let mut body = Vec::new();
        body.extend_from_slice(&[0xFF, 0xFF]);
        // delimiter: bit 7 set for long (unique) address
        body.push(if response { 0x86 } else { 0x82 });
        body.extend_from_slice(&long_addr);
        body.push(command);
        body.push((command_data.len() + if response { 2 } else { 0 }) as u8);
        if response {
            body.push(0x00); // response_code
            body.push(0x00); // device_status
        }
        body.extend_from_slice(command_data);
        body.push(0xAA);

        build_header(message_type, 3, 0, 0x0002, &body)
    }

    fn parse_fields(data: &[u8]) -> HartIpFields {
        let dissector = HartIpDissector;
        use std::net::{IpAddr, Ipv4Addr};
        let ctx = crate::registry::PacketContext {
            src_mac: [0; 6],
            dst_mac: [0; 6],
            src_port: 50000,
            dst_port: HART_IP_PORT,
            src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            dst_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            vlan_id: None,
            timestamp: 0,
        };
        match dissector.parse(data, &ctx) {
            Some(ProtocolData::HartIp(f)) => f,
            _ => panic!("expected HartIp ProtocolData"),
        }
    }

    // ── Session Initiate request ──────────────────────────────────────────────

    #[test]
    fn bronze_session_initiate_request() {
        // message_type=0 (request), message_id=0 (session_initiate)
        let data = build_header(0, 0, 0, 7, &[1, 0, 0, 0, 60]); // primary_host, 60 s timer
        let fields = parse_fields(&data);
        let bf = hart_ip_bronze_fields(&fields);

        assert_eq!(bf.message_type, 0);
        assert_eq!(bf.message_type_name, "request");
        assert_eq!(bf.message_id, 0);
        assert_eq!(bf.message_id_name, "session_initiate");
        assert_eq!(bf.status_byte, 0);
        assert_eq!(bf.sequence_number, 7);
        assert_eq!(bf.direction, "request");
        assert!(bf.passthrough_command.is_none());
        assert!(bf.device_status.is_none());
        assert!(bf.field_device_address.is_none());
    }

    // ── Session Initiate response ─────────────────────────────────────────────

    #[test]
    fn bronze_session_initiate_response() {
        let data = build_header(1, 0, 0, 7, &[1, 0, 0, 0, 60]);
        let fields = parse_fields(&data);
        let bf = hart_ip_bronze_fields(&fields);

        assert_eq!(bf.message_type, 1);
        assert_eq!(bf.message_type_name, "response");
        assert_eq!(bf.message_id, 0);
        assert_eq!(bf.message_id_name, "session_initiate");
        assert_eq!(bf.direction, "response");
    }

    // ── Keep-alive ────────────────────────────────────────────────────────────

    #[test]
    fn bronze_keep_alive() {
        let data = build_header(0, 2, 0, 42, &[]);
        let fields = parse_fields(&data);
        let bf = hart_ip_bronze_fields(&fields);

        assert_eq!(bf.message_id, 2);
        assert_eq!(bf.message_id_name, "keep_alive");
        assert_eq!(bf.sequence_number, 42);
        assert!(bf.passthrough_command.is_none());
        assert!(bf.device_status.is_none());
    }

    // ── Passthrough Cmd 0 (Read Unique Identifier) response with identity ─────

    #[test]
    fn bronze_passthrough_cmd0_read_identifier_response() {
        // Minimal cmd-0 response payload (19 bytes) as used in the dissector tests.
        let command_data: [u8; 19] = [
            0x00, 0x12, 0x34, // byte0 (ignored), device_type hi/lo
            0x05, 0x06,       // byte3 (ignored), hart_universal_rev=6
            0x07, 0x08,       // device_rev=7, software_rev=8
            0x09, 0xAA, 0x01, 0x02, 0x03, // hw_rev=9, ignored, device_id bytes
            0x04, 0x05, 0x00, 0x10, 0x11, // more bytes
            0x00, 0x2A,       // manufacturer_id = 42
        ];
        let data = build_pass_through_short(1, 0, true, &command_data);
        let fields = parse_fields(&data);
        let bf = hart_ip_bronze_fields(&fields);

        assert_eq!(bf.message_type, 1, "response");
        assert_eq!(bf.message_id, 3, "pass_through");
        assert_eq!(bf.passthrough_command, Some(0));
        assert_eq!(
            bf.passthrough_command_name.as_deref(),
            Some("read_unique_identifier")
        );
        // device_status comes from the ACK frame (0x40 in build_pass_through_short)
        assert_eq!(bf.device_status, Some(0x40));
        // polling address — no long address
        assert!(bf.field_device_address.is_none());
        assert_eq!(bf.direction, "response");
    }

    // ── Passthrough Cmd 3 (Read Dynamic Variables) with long address ──────────

    #[test]
    fn bronze_passthrough_cmd3_long_address() {
        let long_addr: [u8; 5] = [0x26, 0x12, 0x34, 0x00, 0x01];
        let data = build_pass_through_long(0, 3, false, long_addr, &[]);
        let fields = parse_fields(&data);
        let bf = hart_ip_bronze_fields(&fields);

        assert_eq!(bf.passthrough_command, Some(3));
        assert_eq!(
            bf.passthrough_command_name.as_deref(),
            Some("pass_through_command")
        );
        assert_eq!(
            bf.field_device_address,
            Some(vec![0x26, 0x12, 0x34, 0x00, 0x01])
        );
        assert!(bf.device_status.is_none(), "request frame has no device_status");
    }

    // ── NAK ───────────────────────────────────────────────────────────────────

    #[test]
    fn bronze_nak() {
        // message_type=15 (NAK)
        let data = build_header(15, 3, 0x05, 99, &[0x10]);
        let fields = parse_fields(&data);
        let bf = hart_ip_bronze_fields(&fields);

        assert_eq!(bf.message_type, 15);
        assert_eq!(bf.message_type_name, "nak");
        assert_eq!(bf.status_byte, 0x05);
        assert_eq!(bf.direction, "error");
    }

    // ── Backward-compat: attributes map still populated ───────────────────────

    #[test]
    fn bronze_attributes_still_populated_alongside_typed_fields() {
        // Parse a session-initiate and verify the `attributes` BTreeMap is
        // populated (backward compat) AND `protocol_fields` is Some.
        // We exercise this through `parse_hart_ip_frames` + `hart_ip_bronze_fields`
        // directly since the full decoder requires a capture harness.
        let data = build_header(0, 0, 0, 5, &[0, 0, 0, 0, 15]);
        let frames = parse_hart_ip_frames(&data);
        assert_eq!(frames.len(), 1);
        let f = &frames[0];

        // Typed surface
        let bf = hart_ip_bronze_fields(f);
        assert_eq!(bf.message_type, 0);
        assert_eq!(bf.message_id_name, "session_initiate");

        // Verify serde round-trip of the typed struct
        let pf = ProtocolFields::HartIp(bf);
        let json = serde_json::to_string(&pf).expect("serialize");
        let back: ProtocolFields = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(pf, back);
    }
}
