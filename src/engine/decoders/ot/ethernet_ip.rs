use std::collections::BTreeMap;

use crate::bronze::{
    AssetObservation, BronzeEvent, BronzeEventFamily, ProtocolTransaction, TransportProtocol,
};
use crate::dissectors::ethernet_ip::EthernetIpDissector;
use crate::engine::{
    artifact_event, build_envelope, new_event, parse_anomaly_event, DecoderInterest,
    SessionDecoder, StreamChunk,
};
use crate::registry::{EthernetIpFields, ProtocolData, ProtocolDissector};

#[derive(Debug, Clone)]
struct CipIdentityClaim {
    vendor_id: u16,
    device_type: u16,
    product_code: u16,
    revision: String,
    serial_number: u32,
    product_name: String,
    status: u16,
    state: Option<u8>,
    ip_address: Option<String>,
}

#[derive(Default)]
pub(crate) struct EthernetIpDecoderWrapper {
    dissector: EthernetIpDissector,
    pccc_decoder: crate::pccc::PcccDecoder,
}

impl SessionDecoder for EthernetIpDecoderWrapper {
    fn name(&self) -> &'static str {
        "ethernet_ip"
    }

    fn interest(&self) -> &'static [DecoderInterest] {
        &[DecoderInterest::TcpPort(44818)]
    }

    fn on_stream_chunk(&mut self, chunk: &StreamChunk<'_>, out: &mut Vec<BronzeEvent>) {
        match self.dissector.parse(chunk.payload, &chunk.context) {
            Some(ProtocolData::EthernetIp(EthernetIpFields {
                command,
                session_handle,
                cip_data,
            })) => {
                let command_name = ethernet_ip_command_name(command);
                let mut attributes = BTreeMap::new();
                attributes.insert("session_handle".to_string(), session_handle.to_string());
                attributes.insert(
                    "encapsulation_command".to_string(),
                    format!("{command:#06x}"),
                );
                if let Some(service) = cip_service_name(&cip_data) {
                    attributes.insert("cip_service".to_string(), service.to_string());
                }
                if let Some(identity) = parse_cip_identity_claim(command, &cip_data) {
                    attributes.insert("cip_vendor_id".to_string(), identity.vendor_id.to_string());
                    attributes.insert(
                        "cip_product_code".to_string(),
                        identity.product_code.to_string(),
                    );
                    attributes.insert(
                        "cip_serial_number".to_string(),
                        identity.serial_number.to_string(),
                    );
                    attributes.insert("cip_revision".to_string(), identity.revision.clone());
                }
                let envelope = build_envelope(
                    &chunk.context,
                    chunk.interface_id,
                    chunk.frame_index,
                    chunk.timestamp,
                    chunk.segment_hash,
                    TransportProtocol::Tcp,
                    Some("ethernet_ip"),
                    chunk.captured_len,
                    chunk.session_key.clone(),
                );
                out.push(new_event(
                    chunk.capture_id.to_string(),
                    envelope.clone(),
                    BronzeEventFamily::ProtocolTransaction(ProtocolTransaction {
                        operation: command_name.to_string(),
                        status: if chunk.context.dst_port == 44818 {
                            "request".to_string()
                        } else {
                            "response".to_string()
                        },
                        request_summary: Some(format!("{command_name} session={session_handle}")),
                        response_summary: None,
                        object_refs: cip_object_refs(&cip_data),
                        values: Vec::new(),
                        attributes,
                                        modbus: None,
                                        protocol_fields: None,
}),
                ));
                for identity in parse_cip_identity_claims(command, &cip_data) {
                    let asset_key = identity
                        .ip_address
                        .clone()
                        .unwrap_or_else(|| chunk.context.src_ip.to_string());
                    let mut identifiers = BTreeMap::from([
                        ("ip".to_string(), asset_key.clone()),
                        ("cip_vendor_id".to_string(), identity.vendor_id.to_string()),
                        (
                            "cip_device_type".to_string(),
                            identity.device_type.to_string(),
                        ),
                        (
                            "cip_product_code".to_string(),
                            identity.product_code.to_string(),
                        ),
                        (
                            "cip_serial_number".to_string(),
                            identity.serial_number.to_string(),
                        ),
                    ]);
                    identifiers.insert("cip_revision".to_string(), identity.revision.clone());
                    identifiers.insert("cip_status".to_string(), identity.status.to_string());
                    if let Some(state) = identity.state {
                        identifiers.insert("cip_state".to_string(), state.to_string());
                    }
                    out.push(new_event(
                        chunk.capture_id.to_string(),
                        envelope.clone(),
                        BronzeEventFamily::AssetObservation(AssetObservation {
                            asset_key,
                            role: cip_role_from_device_type(identity.device_type)
                                .map(str::to_string),
                            vendor: cip_vendor_name(identity.vendor_id).map(str::to_string),
                            model: Some(identity.product_name.clone()),
                            firmware: Some(identity.revision.clone()),
                            hostnames: Vec::new(),
                            protocols: vec!["ethernet_ip".to_string(), "cip".to_string()],
                            identifiers,
                        }),
                    ));
                }
                if matches!(command, 0x006F | 0x0070) && !cip_data.is_empty() {
                    // PCCC dispatch: if the CIP service is Execute PCCC
                    // (request 0x4B / response 0xCB), pull the embedded PCCC
                    // PDU and let the PcccDecoder produce ProcessReadings.
                    if let Some(message) = cip_explicit_message(&cip_data) {
                        if let Some((is_request, pccc_pdu)) =
                            extract_pccc_pdu(message)
                        {
                            let mut events = self.pccc_decoder.handle_pdu(
                                pccc_pdu,
                                is_request,
                                chunk.context.src_ip,
                                &envelope,
                                chunk.capture_id,
                            );
                            out.append(&mut events);
                        }
                    }
                    out.push(artifact_event(
                        chunk.capture_id.to_string(),
                        envelope,
                        "cip_payload",
                        &format!("{session_handle}:{}", chunk.frame_index),
                        Some("application/octet-stream"),
                        Some("EtherNet/IP CIP payload"),
                        &cip_data,
                    ));
                }
            }
            _ => out.push(parse_anomaly_event(
                chunk.capture_id.to_string(),
                build_envelope(
                    &chunk.context,
                    chunk.interface_id,
                    chunk.frame_index,
                    chunk.timestamp,
                    chunk.segment_hash,
                    TransportProtocol::Tcp,
                    Some("ethernet_ip"),
                    chunk.captured_len,
                    chunk.session_key.clone(),
                ),
                self.name(),
                "medium",
                "failed to parse ethernet/ip payload",
                chunk.payload,
            )),
        }
    }
}

fn ethernet_ip_command_name(command: u16) -> &'static str {
    match command {
        0x0001 => "nop",
        0x0004 => "list_services",
        0x0063 => "list_identity",
        0x0064 => "list_interfaces",
        0x0065 => "register_session",
        0x0066 => "unregister_session",
        0x006F => "send_rr_data",
        0x0070 => "send_unit_data",
        _ => "encapsulation_command",
    }
}

fn cip_service_name(cip_data: &[u8]) -> Option<&'static str> {
    let service = cip_explicit_message(cip_data)
        .and_then(|message| message.first().copied())
        .or_else(|| cip_data.iter().find(|byte| **byte != 0).copied())?;
    match service & 0x7F {
        0x01 => Some("get_attributes_all"),
        0x4C => Some("read_tag_service"),
        0x4D => Some("write_tag_service"),
        0x0E => Some("get_attribute_single"),
        0x10 => Some("set_attribute_single"),
        0x54 => Some("forward_open"),
        0x52 => Some("unconnected_send"),
        _ => None,
    }
}

fn cip_object_refs(cip_data: &[u8]) -> Vec<String> {
    let mut refs = Vec::new();
    if let Some(service) = cip_service_name(cip_data) {
        refs.push(format!("cip_service:{service}"));
    }
    if parse_cip_identity_response(cip_data).is_some() {
        refs.push("cip_object:identity".to_string());
    }
    refs
}

fn parse_cip_identity_claim(command: u16, cip_data: &[u8]) -> Option<CipIdentityClaim> {
    parse_cip_identity_claims(command, cip_data)
        .into_iter()
        .next()
}

fn parse_cip_identity_claims(command: u16, cip_data: &[u8]) -> Vec<CipIdentityClaim> {
    match command {
        0x0063 => parse_enip_list_identity(cip_data),
        0x006F | 0x0070 => parse_cip_identity_response(cip_data).into_iter().collect(),
        _ => Vec::new(),
    }
}

fn parse_enip_list_identity(data: &[u8]) -> Vec<CipIdentityClaim> {
    if data.len() < 2 {
        return Vec::new();
    }
    let item_count = u16::from_le_bytes([data[0], data[1]]) as usize;
    let mut offset = 2;
    let mut claims = Vec::new();
    for _ in 0..item_count {
        if offset + 4 > data.len() {
            break;
        }
        let item_type = u16::from_le_bytes([data[offset], data[offset + 1]]);
        let item_len = u16::from_le_bytes([data[offset + 2], data[offset + 3]]) as usize;
        offset += 4;
        if offset + item_len > data.len() {
            break;
        }
        let item = &data[offset..offset + item_len];
        if item_type == 0x000C {
            if let Some(claim) = parse_list_identity_item(item) {
                claims.push(claim);
            }
        }
        offset += item_len;
    }
    claims
}

fn parse_list_identity_item(item: &[u8]) -> Option<CipIdentityClaim> {
    if item.len() < 34 {
        return None;
    }
    let vendor_id = u16::from_le_bytes([item[18], item[19]]);
    let device_type = u16::from_le_bytes([item[20], item[21]]);
    let product_code = u16::from_le_bytes([item[22], item[23]]);
    let revision = format!("{}.{}", item[24], item[25]);
    let status = u16::from_le_bytes([item[26], item[27]]);
    let serial_number = u32::from_le_bytes([item[28], item[29], item[30], item[31]]);
    let name_len = item[32] as usize;
    if 33 + name_len > item.len() {
        return None;
    }
    let product_name = String::from_utf8_lossy(&item[33..33 + name_len]).to_string();
    let state = item.get(33 + name_len).copied();
    let ip_address = if item.len() >= 10 {
        Some(format!("{}.{}.{}.{}", item[6], item[7], item[8], item[9]))
    } else {
        None
    };
    Some(CipIdentityClaim {
        vendor_id,
        device_type,
        product_code,
        revision,
        serial_number,
        product_name,
        status,
        state,
        ip_address,
    })
}

fn parse_cip_identity_response(cip_data: &[u8]) -> Option<CipIdentityClaim> {
    let message = cip_explicit_message(cip_data)?;
    if message.len() < 4 || message[0] != 0x81 || message[2] != 0 {
        return None;
    }
    let additional_status_words = message[3] as usize;
    let data_offset = 4 + additional_status_words * 2;
    if data_offset + 15 > message.len() {
        return None;
    }
    let body = &message[data_offset..];
    let vendor_id = u16::from_le_bytes([body[0], body[1]]);
    let device_type = u16::from_le_bytes([body[2], body[3]]);
    let product_code = u16::from_le_bytes([body[4], body[5]]);
    let revision = format!("{}.{}", body[6], body[7]);
    let status = u16::from_le_bytes([body[8], body[9]]);
    let serial_number = u32::from_le_bytes([body[10], body[11], body[12], body[13]]);
    let name_len = body[14] as usize;
    if 15 + name_len > body.len() {
        return None;
    }
    let product_name = String::from_utf8_lossy(&body[15..15 + name_len]).to_string();
    let state = body.get(15 + name_len).copied();
    Some(CipIdentityClaim {
        vendor_id,
        device_type,
        product_code,
        revision,
        serial_number,
        product_name,
        status,
        state,
        ip_address: None,
    })
}

/// Detect CIP service 0x4B (Execute PCCC) inside an explicit CIP message and
/// return `(is_request, pccc_pdu_bytes)`. Returns None for any other service
/// or for malformed messages.
fn extract_pccc_pdu(message: &[u8]) -> Option<(bool, &[u8])> {
    if message.is_empty() {
        return None;
    }
    let service = message[0];
    let is_request = service & 0x80 == 0;
    if service & 0x7F != 0x4B {
        return None;
    }
    if is_request {
        if message.len() < 2 {
            return None;
        }
        let path_size_words = message[1] as usize;
        let header_len = 2 + path_size_words * 2;
        if message.len() < header_len {
            return None;
        }
        Some((true, &message[header_len..]))
    } else {
        // Response: service (1) + reserved (1) + general_status (1)
        // + ext_status_size (1) + ext status words
        if message.len() < 4 {
            return None;
        }
        let ext_status_words = message[3] as usize;
        let header_len = 4 + ext_status_words * 2;
        if message.len() < header_len {
            return None;
        }
        Some((false, &message[header_len..]))
    }
}

fn cip_explicit_message(cip_data: &[u8]) -> Option<&[u8]> {
    if cip_data.len() < 8 {
        return None;
    }
    let item_count = u16::from_le_bytes([cip_data[6], cip_data[7]]) as usize;
    let mut offset = 8;
    for _ in 0..item_count {
        if offset + 4 > cip_data.len() {
            return None;
        }
        let item_type = u16::from_le_bytes([cip_data[offset], cip_data[offset + 1]]);
        let item_len = u16::from_le_bytes([cip_data[offset + 2], cip_data[offset + 3]]) as usize;
        offset += 4;
        if offset + item_len > cip_data.len() {
            return None;
        }
        let item = &cip_data[offset..offset + item_len];
        if matches!(item_type, 0x00B1 | 0x00B2) {
            return Some(item);
        }
        offset += item_len;
    }
    None
}

fn cip_vendor_name(vendor_id: u16) -> Option<&'static str> {
    match vendor_id {
        1 => Some("Rockwell Automation/Allen-Bradley"),
        _ => None,
    }
}

fn cip_role_from_device_type(device_type: u16) -> Option<&'static str> {
    match device_type {
        0x000E => Some("plc"),
        0x000C => Some("adapter"),
        _ => None,
    }
}

inventory::submit!(crate::engine::decoders::DecoderRegistration {
    name: "ethernet_ip",
    factory: || Box::new(EthernetIpDecoderWrapper::default()),
});
