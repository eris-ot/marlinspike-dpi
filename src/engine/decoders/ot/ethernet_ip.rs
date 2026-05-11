//! EtherNet/IP explicit-messaging decoder (TCP/44818) for the Bronze v2 event
//! model.
//!
//! Emits [`crate::bronze::ProtocolTransaction`] events with both the legacy
//! `attributes` map (backward-compatible) and the typed
//! [`crate::bronze::ProtocolFields::EthernetIp`] surface introduced in v1.14.
//! Downstream consumers should prefer the typed surface; `attributes` will be
//! removed in v2.0.
//!
//! Out of scope: Class 1 cyclic I/O (UDP/2222, `eip_io` decoder) and CIP
//! Safety (`cip_safety` decoder).

use std::collections::BTreeMap;

use crate::bronze::{
    AssetObservation, BronzeEvent, BronzeEventFamily, EthernetIpBronzeFields, ProtocolFields,
    ProtocolTransaction, TransportProtocol,
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
                encap_status,
                encap_options,
                cip_data,
            })) => {
                let command_name = ethernet_ip_command_name(command);
                let is_request = chunk.context.dst_port == 44818;
                let direction = if is_request { "request" } else { "response" }.to_string();

                // --- Legacy attributes (backward-compat through v1.x) ---
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

                // --- Typed surface ---
                let protocol_fields =
                    Some(ProtocolFields::EthernetIp(build_eip_bronze_fields(
                        command,
                        command_name,
                        session_handle,
                        encap_status,
                        encap_options,
                        &cip_data,
                        is_request,
                        &direction,
                    )));

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
                        status: direction.clone(),
                        request_summary: Some(format!("{command_name} session={session_handle}")),
                        response_summary: None,
                        object_refs: cip_object_refs(&cip_data),
                        values: Vec::new(),
                        attributes,
                        modbus: None,
                        protocol_fields,
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

/// Typed service-code lookup (covers more codes than the legacy name table).
fn cip_service_code_name(service: u8) -> Option<&'static str> {
    match service & 0x7F {
        0x01 => Some("get_attributes_all"),
        0x02 => Some("set_attributes_all"),
        0x03 => Some("get_attribute_list"),
        0x04 => Some("set_attribute_list"),
        0x05 => Some("reset"),
        0x09 => Some("delete"),
        0x0A => Some("multiple_service_packet"),
        0x0E => Some("get_attribute_single"),
        0x10 => Some("set_attribute_single"),
        0x4B => Some("execute_pccc"),
        0x4C => Some("read_tag"),
        0x4D => Some("write_tag"),
        0x4E => Some("forward_close"),
        0x52 => Some("unconnected_send"),
        0x54 => Some("forward_open"),
        0x5B => Some("large_forward_open"),
        0x81 => Some("get_attributes_all"),  // reply for 0x01
        _ => None,
    }
}

/// Parse a CIP logical path segment starting at `data[offset]`.
/// Returns `(class, instance, attribute)` where any missing segment is `None`.
/// The path is a sequence of segments; we scan until we run out of bytes.
fn parse_cip_path(data: &[u8]) -> (Option<u32>, Option<u32>, Option<u32>) {
    if data.len() < 1 {
        return (None, None, None);
    }
    // path_size is in 16-bit words
    let path_size_words = data[0] as usize;
    let path_bytes = path_size_words * 2;
    if data.len() < 1 + path_bytes {
        return (None, None, None);
    }
    let path = &data[1..1 + path_bytes];
    let mut class: Option<u32> = None;
    let mut instance: Option<u32> = None;
    let mut attribute: Option<u32> = None;
    let mut i = 0;
    while i < path.len() {
        let seg = path[i];
        let seg_type = (seg & 0b1110_0000) >> 5; // 3-bit segment type
        let seg_format = seg & 0b0001_1111;       // 5-bit format
        match seg_type {
            0b001 => {
                // Logical segment
                let logical_type = (seg_format & 0b11100) >> 2;
                let logical_format = seg_format & 0b00011;
                let value = match logical_format {
                    0b00 => {
                        // 8-bit value follows in next byte
                        if i + 1 >= path.len() {
                            break;
                        }
                        let v = path[i + 1] as u32;
                        i += 2;
                        v
                    }
                    0b01 => {
                        // 16-bit value follows (padded to 16-bit boundary)
                        if i + 3 >= path.len() {
                            break;
                        }
                        let v = u16::from_le_bytes([path[i + 2], path[i + 3]]) as u32;
                        i += 4;
                        v
                    }
                    0b10 => {
                        // 32-bit value follows (padded)
                        if i + 5 >= path.len() {
                            break;
                        }
                        let v =
                            u32::from_le_bytes([path[i + 2], path[i + 3], path[i + 4], path[i + 5]]);
                        i += 6;
                        v
                    }
                    _ => break,
                };
                match logical_type {
                    0b000 => class = Some(value),
                    0b001 => instance = Some(value),
                    0b100 => attribute = Some(value),
                    _ => {}
                }
            }
            0b100 => {
                // Data segment — skip: size byte + data
                if i + 1 >= path.len() {
                    break;
                }
                let data_words = path[i + 1] as usize;
                i += 2 + data_words * 2;
            }
            _ => {
                // Unknown / port segment — bail
                break;
            }
        }
    }
    (class, instance, attribute)
}

/// Extract CIP general_status and extended_status from a response message.
/// `message` is the raw CIP PDU (service byte first).
fn cip_response_status(message: &[u8]) -> (Option<u8>, Option<u16>) {
    // Response layout: service(1) | reserved(1) | general_status(1) |
    //                  ext_status_size(1) | ext_status_words(n*2)
    if message.len() < 4 || message[0] & 0x80 == 0 {
        return (None, None);
    }
    let general_status = message[2];
    let ext_size = message[3] as usize;
    let extended_status = if ext_size > 0 && message.len() >= 4 + ext_size * 2 {
        Some(u16::from_le_bytes([message[4], message[5]]))
    } else {
        None
    };
    (Some(general_status), extended_status)
}

/// Build the typed [`EthernetIpBronzeFields`] for a single EIP frame.
#[allow(clippy::too_many_arguments)]
fn build_eip_bronze_fields(
    command: u16,
    command_name: &str,
    session_handle: u32,
    encap_status: u32,
    encap_options: u32,
    cip_data: &[u8],
    is_request: bool,
    direction: &str,
) -> EthernetIpBronzeFields {
    // Derive CIP fields from the explicit message item.
    let message = cip_explicit_message(cip_data);

    let cip_service_raw: Option<u8> = message.and_then(|m| m.first().copied());
    let (cip_service, cip_service_name_val) = if let Some(raw) = cip_service_raw {
        let code = raw & 0x7F;
        (Some(code), cip_service_code_name(code).map(str::to_string))
    } else {
        (None, None)
    };

    // Path starts at byte 1 of the request message (after service byte).
    let (cip_class_id, cip_instance_id, cip_attribute_id) = if let Some(msg) = message {
        if is_request && msg.len() > 1 {
            parse_cip_path(&msg[1..])
        } else {
            (None, None, None)
        }
    } else {
        (None, None, None)
    };

    let (cip_general_status, cip_extended_status) = if let Some(msg) = message {
        cip_response_status(msg)
    } else {
        (None, None)
    };

    EthernetIpBronzeFields {
        encap_command: command,
        encap_command_name: command_name.to_string(),
        session_handle: if session_handle == 0 { None } else { Some(session_handle) },
        encap_status: Some(encap_status),
        encap_options: Some(encap_options),
        cip_service,
        cip_service_name: cip_service_name_val,
        cip_class_id,
        cip_instance_id,
        cip_attribute_id,
        cip_general_status,
        cip_extended_status,
        is_request,
        direction: direction.to_string(),
    }
}

inventory::submit!(crate::engine::decoders::DecoderRegistration {
    name: "ethernet_ip",
    factory: || Box::new(EthernetIpDecoderWrapper::default()),
});

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};

    use crate::bronze::{BronzeEventFamily, EthernetIpBronzeFields, ProtocolFields};
    use crate::engine::{SessionDecoder, StreamChunk};
    use crate::registry::PacketContext;

    use super::EthernetIpDecoderWrapper;

    // ── Frame builders ────────────────────────────────────────────────────────

    const ENCAP_HEADER_SIZE: usize = 24;

    /// Build a minimal EIP encapsulation header.
    fn build_encap(command: u16, encap_len: u16, session: u32) -> Vec<u8> {
        let mut pkt = Vec::with_capacity(ENCAP_HEADER_SIZE + encap_len as usize);
        pkt.extend_from_slice(&command.to_le_bytes());
        pkt.extend_from_slice(&encap_len.to_le_bytes());
        pkt.extend_from_slice(&session.to_le_bytes());
        pkt.extend_from_slice(&0u32.to_le_bytes()); // status
        pkt.extend_from_slice(&[0u8; 8]);           // sender_context
        pkt.extend_from_slice(&0u32.to_le_bytes()); // options
        pkt
    }

    /// Build the CIP common packet format (CPF) wrapping a single data item.
    ///
    /// `item_type`: 0x00B2 = unconnected data item.
    fn build_cpf(item_type: u16, data: &[u8]) -> Vec<u8> {
        // CPF: timeout(2) + null address item(4) + item header(4) + item data
        let mut cpf = Vec::new();
        cpf.extend_from_slice(&0u32.to_le_bytes()); // interface_handle (4 bytes for SendRRData)
        cpf.extend_from_slice(&0u16.to_le_bytes()); // timeout
        cpf.extend_from_slice(&2u16.to_le_bytes()); // item count = 2
        // null address item
        cpf.extend_from_slice(&0x0000u16.to_le_bytes()); // type: null address
        cpf.extend_from_slice(&0u16.to_le_bytes());       // length 0
        // data item
        cpf.extend_from_slice(&item_type.to_le_bytes());
        cpf.extend_from_slice(&(data.len() as u16).to_le_bytes());
        cpf.extend_from_slice(data);
        cpf
    }

    /// Build a CIP request message: service + path_size(words) + path + data.
    fn build_cip_request(service: u8, path: &[u8], extra: &[u8]) -> Vec<u8> {
        assert!(path.len() % 2 == 0, "path must be word-aligned");
        let mut msg = vec![service, (path.len() / 2) as u8];
        msg.extend_from_slice(path);
        msg.extend_from_slice(extra);
        msg
    }

    /// Build a CIP response message: (service | 0x80) + reserved + general_status + ext_size.
    fn build_cip_response(service: u8, general_status: u8, ext_status: Option<u16>) -> Vec<u8> {
        let mut msg = vec![service | 0x80, 0x00, general_status];
        if let Some(ext) = ext_status {
            msg.push(1); // ext_status_size = 1 word
            msg.extend_from_slice(&ext.to_le_bytes());
        } else {
            msg.push(0);
        }
        msg
    }

    /// 8-byte logical path: class (8-bit) + instance (8-bit).
    fn logical_path_class_instance(class: u8, instance: u8) -> Vec<u8> {
        // class segment: 0x20 (logical, class, 8-bit)
        // instance segment: 0x24 (logical, instance, 8-bit)
        vec![0x20, class, 0x24, instance]
    }

    /// 12-byte logical path: class + instance + attribute (all 8-bit).
    fn logical_path_class_instance_attr(class: u8, instance: u8, attr: u8) -> Vec<u8> {
        let mut p = logical_path_class_instance(class, instance);
        p.push(0x30); // logical, attribute, 8-bit
        p.push(attr);
        p
    }

    // ── PacketContext helpers ─────────────────────────────────────────────────

    fn ctx_request() -> PacketContext {
        PacketContext {
            src_mac: [0x00; 6],
            dst_mac: [0x00; 6],
            src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            dst_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            src_port: 49200,
            dst_port: 44818,
            vlan_id: None,
            timestamp: 0,
        }
    }

    fn ctx_response() -> PacketContext {
        PacketContext {
            src_mac: [0x00; 6],
            dst_mac: [0x00; 6],
            src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            dst_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            src_port: 44818,
            dst_port: 49200,
            vlan_id: None,
            timestamp: 0,
        }
    }

    fn chunk<'a>(payload: &'a [u8], ctx: &'a PacketContext) -> StreamChunk<'a> {
        StreamChunk {
            capture_id: "test",
            segment_hash: "hash",
            interface_id: 0,
            frame_index: 1,
            timestamp: chrono::Utc::now(),
            captured_len: payload.len() as u64,
            session_key: "sess".to_string(),
            payload,
            context: ctx.clone(),
            ethertype: 0x0800,
            ip_proto: Some(6),
            llc: None,
            transport: crate::bronze::TransportProtocol::Tcp,
        }
    }

    fn extract_tx(events: &[crate::bronze::BronzeEvent]) -> &EthernetIpBronzeFields {
        for ev in events {
            if let BronzeEventFamily::ProtocolTransaction(tx) = &ev.family {
                if let Some(ProtocolFields::EthernetIp(ref f)) = tx.protocol_fields {
                    return f;
                }
            }
        }
        panic!("no EthernetIp protocol_fields found in events");
    }

    // ── Tests ─────────────────────────────────────────────────────────────────

    /// RegisterSession request: cmd=0x65, session_handle=0, no CIP PDU.
    #[test]
    fn register_session_request_typed() {
        let mut pkt = build_encap(0x0065, 4, 0);
        pkt.extend_from_slice(&[0x01, 0x00, 0x00, 0x00]); // protocol_version + option_flags

        let ctx = ctx_request();
        let mut dec = EthernetIpDecoderWrapper::default();
        let mut out = Vec::new();
        dec.on_stream_chunk(&chunk(&pkt, &ctx), &mut out);

        let f = extract_tx(&out);
        assert_eq!(f.encap_command, 0x0065);
        assert_eq!(f.encap_command_name, "register_session");
        assert_eq!(f.session_handle, None); // handle is 0 on the request
        assert_eq!(f.encap_status, Some(0));
        assert!(f.is_request);
        assert_eq!(f.direction, "request");
        assert_eq!(f.cip_service, None);
    }

    /// RegisterSession response: cmd=0x65, session_handle non-zero assigned by target.
    #[test]
    fn register_session_response_typed() {
        let mut pkt = build_encap(0x0065, 4, 0x0000_ABCD); // target assigns handle
        pkt.extend_from_slice(&[0x01, 0x00, 0x00, 0x00]);

        let ctx = ctx_response();
        let mut dec = EthernetIpDecoderWrapper::default();
        let mut out = Vec::new();
        dec.on_stream_chunk(&chunk(&pkt, &ctx), &mut out);

        let f = extract_tx(&out);
        assert_eq!(f.encap_command, 0x0065);
        assert_eq!(f.session_handle, Some(0x0000_ABCD));
        assert!(!f.is_request);
        assert_eq!(f.direction, "response");
    }

    /// SendRRData carrying a CIP GetAttributeSingle request (service=0x0E,
    /// class=0x01 Identity, instance=1, attribute=7).
    #[test]
    fn send_rr_data_get_attribute_single_typed() {
        let path = logical_path_class_instance_attr(0x01, 0x01, 0x07);
        let cip_msg = build_cip_request(0x0E, &path, &[]);
        let cpf = build_cpf(0x00B2, &cip_msg);
        let mut pkt = build_encap(0x006F, cpf.len() as u16, 0x1234_5678);
        pkt.extend_from_slice(&cpf);

        let ctx = ctx_request();
        let mut dec = EthernetIpDecoderWrapper::default();
        let mut out = Vec::new();
        dec.on_stream_chunk(&chunk(&pkt, &ctx), &mut out);

        let f = extract_tx(&out);
        assert_eq!(f.encap_command, 0x006F);
        assert_eq!(f.encap_command_name, "send_rr_data");
        assert_eq!(f.session_handle, Some(0x1234_5678));
        assert_eq!(f.cip_service, Some(0x0E));
        assert_eq!(f.cip_service_name.as_deref(), Some("get_attribute_single"));
        assert_eq!(f.cip_class_id, Some(0x01));
        assert_eq!(f.cip_instance_id, Some(0x01));
        assert_eq!(f.cip_attribute_id, Some(0x07));
        assert!(f.is_request);
        assert_eq!(f.cip_general_status, None); // request has no status
    }

    /// Forward_Open request: service=0x54, class=0x06 (Connection Manager), instance=1.
    #[test]
    fn forward_open_request_typed() {
        let path = logical_path_class_instance(0x06, 0x01);
        // Forward_Open request body is longer but we only need enough for parsing
        let forward_open_body = vec![0u8; 36]; // minimal stub
        let cip_msg = build_cip_request(0x54, &path, &forward_open_body);
        let cpf = build_cpf(0x00B2, &cip_msg);
        let mut pkt = build_encap(0x006F, cpf.len() as u16, 0x0000_0001);
        pkt.extend_from_slice(&cpf);

        let ctx = ctx_request();
        let mut dec = EthernetIpDecoderWrapper::default();
        let mut out = Vec::new();
        dec.on_stream_chunk(&chunk(&pkt, &ctx), &mut out);

        let f = extract_tx(&out);
        assert_eq!(f.cip_service, Some(0x54));
        assert_eq!(f.cip_service_name.as_deref(), Some("forward_open"));
        assert_eq!(f.cip_class_id, Some(0x06));
        assert_eq!(f.cip_instance_id, Some(0x01));
        assert!(f.is_request);
    }

    /// Read Tag request: service=0x4C, class=0x6B (Symbol object), instance=1.
    #[test]
    fn read_tag_request_typed() {
        let path = logical_path_class_instance(0x6B, 0x01);
        // Read Tag body: element count (2 bytes)
        let cip_msg = build_cip_request(0x4C, &path, &[0x01, 0x00]);
        let cpf = build_cpf(0x00B2, &cip_msg);
        let mut pkt = build_encap(0x006F, cpf.len() as u16, 0x0000_0002);
        pkt.extend_from_slice(&cpf);

        let ctx = ctx_request();
        let mut dec = EthernetIpDecoderWrapper::default();
        let mut out = Vec::new();
        dec.on_stream_chunk(&chunk(&pkt, &ctx), &mut out);

        let f = extract_tx(&out);
        assert_eq!(f.cip_service, Some(0x4C));
        assert_eq!(f.cip_service_name.as_deref(), Some("read_tag"));
        assert_eq!(f.cip_class_id, Some(0x6B));
        assert_eq!(f.cip_instance_id, Some(0x01));
        assert!(f.is_request);
    }

    /// CIP error response: general_status non-zero (0x08 = Service not supported).
    #[test]
    fn cip_error_response_general_status_typed() {
        let cip_msg = build_cip_response(0x0E, 0x08, None);
        let cpf = build_cpf(0x00B2, &cip_msg);
        let mut pkt = build_encap(0x006F, cpf.len() as u16, 0x0000_0003);
        pkt.extend_from_slice(&cpf);

        let ctx = ctx_response();
        let mut dec = EthernetIpDecoderWrapper::default();
        let mut out = Vec::new();
        dec.on_stream_chunk(&chunk(&pkt, &ctx), &mut out);

        let f = extract_tx(&out);
        assert_eq!(f.cip_service, Some(0x0E)); // reply bit stripped
        assert_eq!(f.cip_general_status, Some(0x08));
        assert_eq!(f.cip_extended_status, None);
        assert!(!f.is_request);
    }

    /// CIP error response with extended status (general_status=0x1F).
    #[test]
    fn cip_error_response_with_extended_status_typed() {
        let cip_msg = build_cip_response(0x4C, 0x1F, Some(0x0012));
        let cpf = build_cpf(0x00B2, &cip_msg);
        let mut pkt = build_encap(0x006F, cpf.len() as u16, 0x0000_0004);
        pkt.extend_from_slice(&cpf);

        let ctx = ctx_response();
        let mut dec = EthernetIpDecoderWrapper::default();
        let mut out = Vec::new();
        dec.on_stream_chunk(&chunk(&pkt, &ctx), &mut out);

        let f = extract_tx(&out);
        assert_eq!(f.cip_general_status, Some(0x1F));
        assert_eq!(f.cip_extended_status, Some(0x0012));
    }

    /// Backward-compat: `attributes` map is still populated alongside `protocol_fields`.
    #[test]
    fn attributes_backward_compat() {
        let mut pkt = build_encap(0x0065, 4, 0);
        pkt.extend_from_slice(&[0x01, 0x00, 0x00, 0x00]);

        let ctx = ctx_request();
        let mut dec = EthernetIpDecoderWrapper::default();
        let mut out = Vec::new();
        dec.on_stream_chunk(&chunk(&pkt, &ctx), &mut out);

        for ev in &out {
            if let BronzeEventFamily::ProtocolTransaction(tx) = &ev.family {
                assert!(tx.attributes.contains_key("session_handle"),
                    "legacy attributes missing 'session_handle'");
                assert!(tx.attributes.contains_key("encapsulation_command"),
                    "legacy attributes missing 'encapsulation_command'");
                assert!(tx.protocol_fields.is_some(),
                    "protocol_fields should be populated");
                return;
            }
        }
        panic!("no ProtocolTransaction event found");
    }

    /// `ProtocolFields::EthernetIp` round-trips through serde cleanly.
    #[test]
    fn ethernet_ip_bronze_fields_serde_roundtrip() {
        use crate::bronze::ProtocolFields;

        let fields = EthernetIpBronzeFields {
            encap_command: 0x006F,
            encap_command_name: "send_rr_data".to_string(),
            session_handle: Some(0x1234),
            encap_status: Some(0),
            encap_options: Some(0),
            cip_service: Some(0x4C),
            cip_service_name: Some("read_tag".to_string()),
            cip_class_id: Some(0x6B),
            cip_instance_id: Some(1),
            cip_attribute_id: None,
            cip_general_status: None,
            cip_extended_status: None,
            is_request: true,
            direction: "request".to_string(),
        };
        let pf = ProtocolFields::EthernetIp(fields.clone());
        let json = serde_json::to_string(&pf).expect("serialize");
        let back: ProtocolFields = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(back, pf);
        // Verify the JSON tag is present
        assert!(json.contains("\"ethernet_ip\""), "expected protocol tag in JSON: {json}");
    }
}
