//! HART-IP dissector with header parsing and pass-through identity extraction.

use crate::registry::{PacketContext, ProtocolData, ProtocolDissector};

#[derive(Default)]
pub struct HartIpDissector;

const HART_IP_PORT: u16 = 5094;
const HART_IP_HEADER_LEN: usize = 8;

#[derive(Debug, Clone)]
pub struct HartIpFields {
    pub version: u8,
    pub message_type: String,
    pub message_id: String,
    pub status: u8,
    pub transaction_id: u16,
    pub message_length: u16,
    pub body: HartIpBody,
    pub payload: Vec<u8>,
}

#[derive(Debug, Clone)]
pub enum HartIpBody {
    SessionInitiate {
        master_type: String,
        inactivity_close_timer: u32,
    },
    SessionClose,
    KeepAlive,
    Error {
        error_code: Option<u8>,
        body: Vec<u8>,
    },
    PassThrough(HartPassThroughFields),
    Raw(Vec<u8>),
}

#[derive(Debug, Clone, Default)]
pub struct HartPassThroughFields {
    pub preambles: usize,
    pub delimiter: u8,
    pub frame_type: String,
    pub physical_layer_type: String,
    pub expansion_bytes: u8,
    pub address_type: String,
    pub short_address: Option<u8>,
    pub long_address: Option<[u8; 5]>,
    pub command: u8,
    pub length: u8,
    pub response_code: Option<u8>,
    pub device_status: Option<u8>,
    pub checksum: Option<u8>,
    pub payload: Vec<u8>,
    pub identity: Option<HartIdentityFields>,
}

#[derive(Debug, Clone, Default)]
pub struct HartIdentityFields {
    pub manufacturer_id: Option<u16>,
    pub device_type: Option<u16>,
    pub tag: Option<String>,
    pub hart_universal_revision: Option<u8>,
    pub device_revision: Option<u8>,
    pub software_revision: Option<u8>,
    pub hardware_revision: Option<u8>,
    pub configuration_change_counter: Option<u16>,
    pub extended_device_status: Option<u8>,
    pub device_id: Option<[u8; 3]>,
}

impl ProtocolDissector for HartIpDissector {
    fn name(&self) -> &str {
        "hart_ip"
    }

    fn can_parse(&self, data: &[u8], src_port: u16, dst_port: u16) -> bool {
        if src_port != HART_IP_PORT && dst_port != HART_IP_PORT {
            return false;
        }

        parse_hart_ip_frame(data).is_some()
    }

    fn parse(&self, data: &[u8], _context: &PacketContext) -> Option<ProtocolData> {
        parse_hart_ip_frames(data)
            .into_iter()
            .next()
            .map(ProtocolData::HartIp)
    }
}

pub fn parse_hart_ip_frames(data: &[u8]) -> Vec<HartIpFields> {
    let mut frames = Vec::new();
    let mut offset = 0usize;

    while offset + HART_IP_HEADER_LEN <= data.len() {
        let frame_len = u16::from_be_bytes([data[offset + 6], data[offset + 7]]) as usize;
        if frame_len < HART_IP_HEADER_LEN || offset + frame_len > data.len() {
            break;
        }

        let frame = &data[offset..offset + frame_len];
        if let Some(parsed) = parse_hart_ip_frame(frame) {
            frames.push(parsed);
        } else {
            break;
        }

        offset += frame_len;
    }

    frames
}

fn parse_hart_ip_frame(data: &[u8]) -> Option<HartIpFields> {
    if data.len() < HART_IP_HEADER_LEN {
        return None;
    }

    let version = data[0];
    let message_type = data[1];
    let message_id = data[2];
    let status = data[3];
    let transaction_id = u16::from_be_bytes([data[4], data[5]]);
    let message_length = u16::from_be_bytes([data[6], data[7]]);
    let total_len = message_length as usize;
    if total_len < HART_IP_HEADER_LEN || total_len > data.len() {
        return None;
    }

    let body = &data[HART_IP_HEADER_LEN..total_len];
    let parsed_body = parse_hart_body(message_type, message_id, body);

    Some(HartIpFields {
        version,
        message_type: hart_message_type_name(message_type).to_string(),
        message_id: hart_message_id_name(message_id).to_string(),
        status,
        transaction_id,
        message_length,
        body: parsed_body,
        payload: body.to_vec(),
    })
}

fn parse_hart_body(message_type: u8, message_id: u8, body: &[u8]) -> HartIpBody {
    match (message_type, message_id) {
        (0..=2, 0) => {
            parse_session_initiate(body).unwrap_or_else(|| HartIpBody::Raw(body.to_vec()))
        }
        (0..=2, 1) => HartIpBody::SessionClose,
        (0..=2, 2) => HartIpBody::KeepAlive,
        (3 | 15, _) => parse_error_body(body),
        (_, 3) => HartIpBody::PassThrough(parse_pass_through_body(body)),
        _ => HartIpBody::Raw(body.to_vec()),
    }
}

fn parse_session_initiate(body: &[u8]) -> Option<HartIpBody> {
    if body.len() != 5 {
        return None;
    }

    let master_type = hart_master_type_name(body[0]).to_string();
    let inactivity_close_timer = u32::from_be_bytes([body[1], body[2], body[3], body[4]]);

    Some(HartIpBody::SessionInitiate {
        master_type,
        inactivity_close_timer,
    })
}

fn parse_error_body(body: &[u8]) -> HartIpBody {
    let error_code = body.first().copied();
    HartIpBody::Error {
        error_code,
        body: body.to_vec(),
    }
}

fn parse_pass_through_body(body: &[u8]) -> HartPassThroughFields {
    let mut fields = HartPassThroughFields::default();
    let mut offset = 0usize;

    while offset < body.len() && body[offset] == 0xFF {
        fields.preambles += 1;
        offset += 1;
    }

    if offset >= body.len() {
        return fields;
    }

    fields.delimiter = body[offset];
    fields.frame_type = hart_frame_type_name(fields.delimiter & 0x07).to_string();
    fields.physical_layer_type =
        hart_physical_layer_type_name((fields.delimiter >> 3) & 0x03).to_string();
    fields.expansion_bytes = (fields.delimiter >> 5) & 0x03;
    fields.address_type = hart_address_type_name((fields.delimiter & 0x80) != 0).to_string();
    offset += 1;

    if fields.address_type == "polling" {
        if offset >= body.len() {
            return fields;
        }
        fields.short_address = Some(body[offset] & 0x3F);
        offset += 1;
    } else {
        if offset + 5 > body.len() {
            return fields;
        }
        fields.long_address = Some([
            body[offset],
            body[offset + 1],
            body[offset + 2],
            body[offset + 3],
            body[offset + 4],
        ]);
        offset += 5;
    }

    if fields.expansion_bytes > 0 {
        let bytes = fields.expansion_bytes as usize;
        if offset + bytes > body.len() {
            return fields;
        }
        offset += bytes;
    }

    if offset >= body.len() {
        return fields;
    }
    fields.command = body[offset];
    offset += 1;

    if offset >= body.len() {
        return fields;
    }
    fields.length = body[offset];
    offset += 1;

    if is_hart_response_delimiter(fields.delimiter) {
        if offset < body.len() {
            fields.response_code = Some(body[offset]);
            offset += 1;
        }
        if offset < body.len() {
            fields.device_status = Some(body[offset]);
            offset += 1;
        }
    }

    let checksum = body.last().copied();
    fields.checksum = checksum;

    if body.len() > offset {
        let payload_end = body.len().saturating_sub(1);
        if payload_end >= offset {
            fields.payload = body[offset..payload_end].to_vec();
        }
    }

    fields.identity = match fields.command {
        0 | 11 | 21 => parse_cmd0_identity(&fields.payload),
        20 | 22 => parse_tag_identity(&fields.payload),
        _ => None,
    };

    fields
}

fn parse_cmd0_identity(payload: &[u8]) -> Option<HartIdentityFields> {
    let mut identity = HartIdentityFields::default();
    let mut found = false;

    if payload.len() >= 3 {
        identity.device_type = Some(u16::from_be_bytes([payload[1], payload[2]]));
        found = true;
    }
    if payload.len() >= 5 {
        identity.hart_universal_revision = Some(payload[4]);
        found = true;
    }
    if payload.len() >= 6 {
        identity.device_revision = Some(payload[5]);
        found = true;
    }
    if payload.len() >= 7 {
        identity.software_revision = Some(payload[6]);
        found = true;
    }
    if payload.len() >= 8 {
        identity.hardware_revision = Some(payload[7]);
        found = true;
    }
    if payload.len() >= 12 {
        identity.device_id = Some([payload[9], payload[10], payload[11]]);
        found = true;
    }
    if payload.len() >= 17 {
        identity.configuration_change_counter =
            Some(u16::from_be_bytes([payload[14], payload[15]]));
        identity.extended_device_status = Some(payload[16]);
        found = true;
    }
    if payload.len() >= 19 {
        identity.manufacturer_id = Some(u16::from_be_bytes([payload[17], payload[18]]));
        found = true;
    }

    if found { Some(identity) } else { None }
}

fn parse_tag_identity(payload: &[u8]) -> Option<HartIdentityFields> {
    if payload.len() < 32 {
        return None;
    }

    let tag = decode_hart_ascii(&payload[..32]);
    Some(HartIdentityFields {
        tag: Some(tag),
        ..Default::default()
    })
}

fn decode_hart_ascii(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes)
        .trim_matches(char::from(0))
        .trim()
        .to_string()
}

fn is_hart_response_delimiter(delimiter: u8) -> bool {
    matches!(delimiter & 0x07, 1 | 6)
}

fn hart_message_type_name(code: u8) -> &'static str {
    match code {
        0 => "request",
        1 => "response",
        2 => "publish",
        3 => "error",
        15 => "nak",
        _ => "unknown",
    }
}

fn hart_message_id_name(code: u8) -> &'static str {
    match code {
        0 => "session_initiate",
        1 => "session_close",
        2 => "keep_alive",
        3 => "pass_through",
        _ => "unknown",
    }
}

fn hart_master_type_name(code: u8) -> &'static str {
    match code {
        0 => "secondary_host",
        1 => "primary_host",
        _ => "unknown",
    }
}

fn hart_frame_type_name(code: u8) -> &'static str {
    match code {
        1 => "back",
        2 => "stx",
        6 => "ack",
        _ => "unknown",
    }
}

fn hart_physical_layer_type_name(code: u8) -> &'static str {
    match code {
        0 => "asynchronous",
        1 => "synchronous",
        _ => "unknown",
    }
}

fn hart_address_type_name(is_long: bool) -> &'static str {
    if is_long { "unique" } else { "polling" }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::registry::PacketContext;

    fn ctx(port: u16) -> PacketContext {
        use std::net::{IpAddr, Ipv4Addr};
        PacketContext {
            src_mac: [0; 6],
            dst_mac: [0; 6],
            src_port: 50000,
            dst_port: port,
            src_ip: IpAddr::V4(Ipv4Addr::new(10, 20, 30, 1)),
            dst_ip: IpAddr::V4(Ipv4Addr::new(10, 20, 30, 2)),
            vlan_id: None,
            timestamp: 0,
        }
    }

    fn build_header(
        message_type: u8,
        message_id: u8,
        status: u8,
        transaction_id: u16,
        body: &[u8],
    ) -> Vec<u8> {
        let mut pkt = Vec::with_capacity(HART_IP_HEADER_LEN + body.len());
        let msg_len = (HART_IP_HEADER_LEN + body.len()) as u16;
        pkt.push(2);
        pkt.push(message_type);
        pkt.push(message_id);
        pkt.push(status);
        pkt.extend_from_slice(&transaction_id.to_be_bytes());
        pkt.extend_from_slice(&msg_len.to_be_bytes());
        pkt.extend_from_slice(body);
        pkt
    }

    fn build_pass_through(
        message_type: u8,
        command: u8,
        response: bool,
        command_data: &[u8],
    ) -> Vec<u8> {
        let mut body = Vec::new();
        body.extend_from_slice(&[0xFF, 0xFF]);
        body.push(if response { 0x06 } else { 0x02 });
        body.push(0x12);
        body.push(command);
        body.push((command_data.len() + if response { 2 } else { 0 }) as u8);
        if response {
            body.push(0x00);
            body.push(0x00);
        }
        body.extend_from_slice(command_data);
        body.push(0xAA);

        build_header(message_type, 3, 0, 0x1234, &body)
    }

    #[test]
    fn can_parse_tcp_or_udp_port() {
        let dissector = HartIpDissector;
        let data = build_header(0, 0, 0, 1, &[1, 0, 0, 0, 30]);
        assert!(dissector.can_parse(&data, 50000, HART_IP_PORT));
    }

    #[test]
    fn parse_session_initiate() {
        let dissector = HartIpDissector;
        let data = build_header(0, 0, 0, 9, &[1, 0, 0, 0, 30]);

        let result = dissector.parse(&data, &ctx(HART_IP_PORT));
        if let Some(ProtocolData::HartIp(fields)) = result {
            assert_eq!(fields.version, 2);
            assert_eq!(fields.message_type, "request");
            assert_eq!(fields.message_id, "session_initiate");
            match fields.body {
                HartIpBody::SessionInitiate {
                    ref master_type,
                    inactivity_close_timer,
                } => {
                    assert_eq!(master_type, "primary_host");
                    assert_eq!(inactivity_close_timer, 30);
                }
                _ => panic!("expected session initiate"),
            }
        } else {
            panic!("expected hart_ip fields");
        }
    }

    #[test]
    fn parse_pass_through_cmd0_identity() {
        let dissector = HartIpDissector;
        let command_data = [
            0x00, 0x12, 0x34, 0x05, 0x06, 0x07, 0x08, 0x09, 0xAA, 0x01, 0x02, 0x03, 0x04, 0x05,
            0x00, 0x10, 0x11, 0x00, 0x2A,
        ];
        let data = build_pass_through(1, 0, true, &command_data);

        let result = dissector.parse(&data, &ctx(HART_IP_PORT));
        if let Some(ProtocolData::HartIp(fields)) = result {
            assert_eq!(fields.message_id, "pass_through");
            match fields.body {
                HartIpBody::PassThrough(ref pass) => {
                    assert_eq!(pass.command, 0);
                    assert_eq!(pass.frame_type, "ack");
                    let identity = pass.identity.as_ref().expect("expected identity");
                    assert_eq!(identity.device_type, Some(0x1234));
                    assert_eq!(identity.manufacturer_id, Some(42));
                    assert_eq!(identity.hart_universal_revision, Some(6));
                    assert_eq!(identity.device_revision, Some(7));
                }
                _ => panic!("expected pass through"),
            }
        } else {
            panic!("expected hart_ip fields");
        }
    }

    #[test]
    fn parse_pass_through_tag_response() {
        let dissector = HartIpDissector;
        let mut tag = [0u8; 32];
        let tag_text = b"TX-1000-SENSOR-01";
        tag[..tag_text.len()].copy_from_slice(tag_text);
        let data = build_pass_through(1, 22, true, &tag);

        let result = dissector.parse(&data, &ctx(HART_IP_PORT));
        if let Some(ProtocolData::HartIp(fields)) = result {
            match fields.body {
                HartIpBody::PassThrough(ref pass) => {
                    let identity = pass.identity.as_ref().expect("expected tag identity");
                    assert_eq!(identity.tag.as_deref(), Some("TX-1000-SENSOR-01"));
                }
                _ => panic!("expected pass through"),
            }
        } else {
            panic!("expected hart_ip fields");
        }
    }

    #[test]
    fn parse_multiple_frames_from_chunk() {
        let first = build_header(0, 1, 0, 1, &[1, 0, 0, 0, 15]);
        let second = build_header(0, 2, 0, 2, &[]);
        let mut data = first;
        data.extend_from_slice(&second);

        let frames = parse_hart_ip_frames(&data);
        assert_eq!(frames.len(), 2);
        assert_eq!(frames[0].message_id, "session_close");
        assert_eq!(frames[1].message_id, "keep_alive");
    }
}
