//! OMRON FINS dissector with lightweight FINS/UDP and FINS/TCP parsing.

use crate::registry::{PacketContext, ProtocolData, ProtocolDissector};

#[derive(Default)]
pub struct OmronFinsDissector;

const FINS_PORT: u16 = 9600;
const FINS_TCP_MAGIC: &[u8; 4] = b"FINS";
const FINS_HEADER_LEN: usize = 10;
const FINS_TCP_HEADER_LEN: usize = 16;

impl ProtocolDissector for OmronFinsDissector {
    fn name(&self) -> &str {
        "omron_fins"
    }

    fn can_parse(&self, data: &[u8], src_port: u16, dst_port: u16) -> bool {
        if src_port != FINS_PORT && dst_port != FINS_PORT {
            return false;
        }

        if data.starts_with(FINS_TCP_MAGIC) {
            return data.len() >= FINS_TCP_HEADER_LEN;
        }

        data.len() >= FINS_HEADER_LEN && data[1] == 0x00 && data[2] <= 0x0F
    }

    fn parse(&self, data: &[u8], _context: &PacketContext) -> Option<ProtocolData> {
        Some(ProtocolData::OmronFins(parse_omron_fins(data)?))
    }
}

fn parse_omron_fins(data: &[u8]) -> Option<OmronFinsFields> {
    if data.starts_with(FINS_TCP_MAGIC) {
        parse_fins_tcp(data)
    } else {
        parse_fins_udp(data)
    }
}

fn parse_fins_udp(data: &[u8]) -> Option<OmronFinsFields> {
    let (header, payload) = parse_fins_header(data)?;
    let (command_code, command_payload) = parse_fins_command(payload)?;
    Some(build_fields(
        "fins_udp",
        None,
        None,
        header,
        command_code,
        command_payload,
    ))
}

fn parse_fins_tcp(data: &[u8]) -> Option<OmronFinsFields> {
    if data.len() < FINS_TCP_HEADER_LEN {
        return None;
    }

    let body_len = u32::from_be_bytes([data[4], data[5], data[6], data[7]]) as usize;
    if body_len < 8 {
        return None;
    }

    let total_len = 8 + body_len;
    if total_len > data.len() {
        return None;
    }

    let tcp_command = u32::from_be_bytes([data[8], data[9], data[10], data[11]]);
    let tcp_error_code = u32::from_be_bytes([data[12], data[13], data[14], data[15]]);
    let tcp_payload = &data[FINS_TCP_HEADER_LEN..total_len];

    if let Some((header, command_code, command_payload)) = parse_fins_frame(tcp_payload) {
        Some(build_fields(
            "fins_tcp",
            Some(tcp_command),
            Some(tcp_error_code),
            header,
            command_code,
            command_payload,
        ))
    } else {
        Some(OmronFinsFields {
            frame_variant: "fins_tcp_envelope".to_string(),
            tcp_command: Some(tcp_command),
            tcp_error_code: Some(tcp_error_code),
            icf: None,
            rsv: None,
            gateway_count: None,
            destination_network: None,
            destination_node: None,
            destination_unit: None,
            source_network: None,
            source_node: None,
            source_unit: None,
            service_id: None,
            command_code: None,
            command_name: None,
            memory_area: None,
            memory_word: None,
            memory_bit: None,
            item_count: None,
            payload: tcp_payload.to_vec(),
        })
    }
}

fn parse_fins_frame(data: &[u8]) -> Option<(FinsHeader, u16, &[u8])> {
    let (header, payload) = parse_fins_header(data)?;
    let (command_code, command_payload) = parse_fins_command(payload)?;
    Some((header, command_code, command_payload))
}

fn parse_fins_header(data: &[u8]) -> Option<(FinsHeader, &[u8])> {
    if data.len() < FINS_HEADER_LEN {
        return None;
    }

    let header = FinsHeader {
        icf: data[0],
        rsv: data[1],
        gateway_count: data[2],
        destination_network: data[3],
        destination_node: data[4],
        destination_unit: data[5],
        source_network: data[6],
        source_node: data[7],
        source_unit: data[8],
        service_id: data[9],
    };
    Some((header, &data[FINS_HEADER_LEN..]))
}

fn parse_fins_command(data: &[u8]) -> Option<(u16, &[u8])> {
    if data.len() < 2 {
        return None;
    }

    Some((u16::from_be_bytes([data[0], data[1]]), &data[2..]))
}

fn build_fields(
    frame_variant: &str,
    tcp_command: Option<u32>,
    tcp_error_code: Option<u32>,
    header: FinsHeader,
    command_code: u16,
    command_payload: &[u8],
) -> OmronFinsFields {
    let (memory_area, memory_word, memory_bit, item_count) =
        parse_memory_area_arguments(command_code, command_payload);

    OmronFinsFields {
        frame_variant: frame_variant.to_string(),
        tcp_command,
        tcp_error_code,
        icf: Some(header.icf),
        rsv: Some(header.rsv),
        gateway_count: Some(header.gateway_count),
        destination_network: Some(header.destination_network),
        destination_node: Some(header.destination_node),
        destination_unit: Some(header.destination_unit),
        source_network: Some(header.source_network),
        source_node: Some(header.source_node),
        source_unit: Some(header.source_unit),
        service_id: Some(header.service_id),
        command_code: Some(command_code),
        command_name: Some(fins_command_name(command_code).to_string()),
        memory_area,
        memory_word,
        memory_bit,
        item_count,
        payload: command_payload.to_vec(),
    }
}

fn parse_memory_area_arguments(
    command_code: u16,
    payload: &[u8],
) -> (Option<u8>, Option<u16>, Option<u8>, Option<u16>) {
    match command_code {
        0x0101..=0x0105 if payload.len() >= 6 => {
            let memory_area = Some(payload[0]);
            let memory_word = Some(u16::from_be_bytes([payload[1], payload[2]]));
            let memory_bit = Some(payload[3]);
            let item_count = Some(u16::from_be_bytes([payload[4], payload[5]]));
            (memory_area, memory_word, memory_bit, item_count)
        }
        _ => (None, None, None, None),
    }
}

fn fins_command_name(command_code: u16) -> &'static str {
    match command_code {
        0x0101 => "memory_area_read",
        0x0102 => "memory_area_write",
        0x0103 => "memory_area_fill",
        0x0104 => "memory_area_multi_read",
        0x0105 => "memory_area_transfer",
        0x0201 => "parameter_area_read",
        0x0202 => "parameter_area_write",
        0x0301 => "program_area_read",
        0x0302 => "program_area_write",
        0x0401 => "run",
        0x0402 => "stop",
        0x0501 => "cpu_unit_data_read",
        0x0601 => "clock_read",
        0x0602 => "clock_write",
        0x0701 => "error_log_read",
        _ => "fins_command",
    }
}

#[derive(Debug, Clone, Copy)]
struct FinsHeader {
    icf: u8,
    rsv: u8,
    gateway_count: u8,
    destination_network: u8,
    destination_node: u8,
    destination_unit: u8,
    source_network: u8,
    source_node: u8,
    source_unit: u8,
    service_id: u8,
}

#[derive(Debug, Clone)]
pub struct OmronFinsFields {
    pub frame_variant: String,
    pub tcp_command: Option<u32>,
    pub tcp_error_code: Option<u32>,
    pub icf: Option<u8>,
    pub rsv: Option<u8>,
    pub gateway_count: Option<u8>,
    pub destination_network: Option<u8>,
    pub destination_node: Option<u8>,
    pub destination_unit: Option<u8>,
    pub source_network: Option<u8>,
    pub source_node: Option<u8>,
    pub source_unit: Option<u8>,
    pub service_id: Option<u8>,
    pub command_code: Option<u16>,
    pub command_name: Option<String>,
    pub memory_area: Option<u8>,
    pub memory_word: Option<u16>,
    pub memory_bit: Option<u8>,
    pub item_count: Option<u16>,
    pub payload: Vec<u8>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::registry::PacketContext;

    fn ctx() -> PacketContext {
        use std::net::{IpAddr, Ipv4Addr};

        PacketContext {
            src_mac: [0; 6],
            dst_mac: [0; 6],
            src_port: 9600,
            dst_port: 9600,
            src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            dst_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            vlan_id: None,
            timestamp: 0,
        }
    }

    fn fins_udp_memory_read_frame() -> Vec<u8> {
        vec![
            0x80, // ICF
            0x00, // RSV
            0x02, // GCT
            0x00, // DNA
            0x64, // DA1
            0x00, // DA2
            0x00, // SNA
            0x01, // SA1
            0x00, // SA2
            0x11, // SID
            0x01, 0x01, // command = memory area read
            0x82, // DM area
            0x00, 0x10, // word address
            0x00, // bit
            0x00, 0x02, // item count
        ]
    }

    #[test]
    fn can_parse_udp_fins_frame_on_port_9600() {
        let dissector = OmronFinsDissector;
        let data = fins_udp_memory_read_frame();
        assert!(dissector.can_parse(&data, 9600, 30000));
    }

    #[test]
    fn parse_udp_memory_area_read() {
        let dissector = OmronFinsDissector;
        let data = fins_udp_memory_read_frame();

        let result = dissector.parse(&data, &ctx());
        if let Some(ProtocolData::OmronFins(fields)) = result {
            assert_eq!(fields.frame_variant, "fins_udp");
            assert_eq!(fields.destination_node, Some(0x64));
            assert_eq!(fields.source_node, Some(0x01));
            assert_eq!(fields.service_id, Some(0x11));
            assert_eq!(fields.command_code, Some(0x0101));
            assert_eq!(fields.command_name.as_deref(), Some("memory_area_read"));
            assert_eq!(fields.memory_area, Some(0x82));
            assert_eq!(fields.memory_word, Some(0x0010));
            assert_eq!(fields.memory_bit, Some(0x00));
            assert_eq!(fields.item_count, Some(0x0002));
        } else {
            panic!("expected omron fins fields");
        }
    }

    #[test]
    fn parse_tcp_envelope_with_inner_fins_frame() {
        let dissector = OmronFinsDissector;
        let inner = fins_udp_memory_read_frame();
        let body_len = (8 + inner.len()) as u32;

        let mut data = Vec::new();
        data.extend_from_slice(b"FINS");
        data.extend_from_slice(&body_len.to_be_bytes());
        data.extend_from_slice(&0x0000_0002u32.to_be_bytes());
        data.extend_from_slice(&0x0000_0000u32.to_be_bytes());
        data.extend_from_slice(&inner);

        assert!(dissector.can_parse(&data, 30000, 9600));

        let result = dissector.parse(&data, &ctx());
        if let Some(ProtocolData::OmronFins(fields)) = result {
            assert_eq!(fields.frame_variant, "fins_tcp");
            assert_eq!(fields.tcp_command, Some(0x0000_0002));
            assert_eq!(fields.tcp_error_code, Some(0x0000_0000));
            assert_eq!(fields.destination_node, Some(0x64));
            assert_eq!(fields.command_code, Some(0x0101));
            assert_eq!(fields.command_name.as_deref(), Some("memory_area_read"));
        } else {
            panic!("expected omron fins fields");
        }
    }
}
