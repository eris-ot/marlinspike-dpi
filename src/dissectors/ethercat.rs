//! EtherCAT dissector with lightweight datagram parsing.
//!
//! EtherCAT frames carry one or more 10-byte datagrams after the Ethernet
//! EtherType `0x88A4`. Each datagram contains a command, a master index,
//! addressing fields, a length/flag word, an event-request word, the data
//! payload, and a working counter.

use crate::registry::{PacketContext, ProtocolData, ProtocolDissector};

#[derive(Default)]
pub struct EthercatDissector;

#[allow(dead_code)]
const ETHERCAT_ETHERTYPE: u16 = 0x88A4;
const ETHERCAT_FRAME_HEADER_LEN: usize = 2;
const ETHERCAT_DATAGRAM_HEADER_LEN: usize = 10;
const ETHERCAT_WORKING_COUNTER_LEN: usize = 2;
const ETHERCAT_LENGTH_MASK: u16 = 0x07FF;
const ETHERCAT_CIRCULATING_FLAG: u16 = 0x4000;
const ETHERCAT_MORE_DATAGRAMS_FLAG: u16 = 0x8000;

impl ProtocolDissector for EthercatDissector {
    fn name(&self) -> &str {
        "ethercat"
    }

    fn can_parse(&self, data: &[u8], _src_port: u16, _dst_port: u16) -> bool {
        looks_like_ethercat_frame(data)
    }

    fn parse(&self, data: &[u8], _context: &PacketContext) -> Option<ProtocolData> {
        Some(ProtocolData::Ethercat(parse_ethercat_frame(data)?))
    }
}

#[derive(Debug, Clone, Default)]
pub struct EthercatFields {
    pub datagrams: Vec<EthercatDatagramFields>,
}

#[derive(Debug, Clone, Default)]
pub struct EthercatDatagramFields {
    pub command_code: u8,
    pub command: String,
    pub address_mode: String,
    pub index: u8,
    pub adp: u16,
    pub ado: u16,
    pub data_length: u16,
    pub circulating: bool,
    pub more_datagrams: bool,
    pub irq: u16,
    pub working_counter: u16,
    pub payload: Vec<u8>,
    pub identity: EthercatIdentityHints,
}

#[derive(Debug, Clone, Default)]
pub struct EthercatIdentityHints {
    pub alias_address: Option<u16>,
    pub vendor_id: Option<u32>,
    pub product_code: Option<u32>,
    pub revision: Option<u32>,
    pub serial_number: Option<u32>,
}

fn parse_ethercat_frame(data: &[u8]) -> Option<EthercatFields> {
    if data.len() >= ETHERCAT_FRAME_HEADER_LEN {
        let frame_info = u16::from_le_bytes([data[0], data[1]]);
        let payload_length = usize::from(frame_info & ETHERCAT_LENGTH_MASK);
        let frame_payload_end = ETHERCAT_FRAME_HEADER_LEN.checked_add(payload_length)?;
        if payload_length >= ETHERCAT_DATAGRAM_HEADER_LEN + ETHERCAT_WORKING_COUNTER_LEN
            && frame_payload_end <= data.len()
        {
            return parse_ethercat_payload(&data[ETHERCAT_FRAME_HEADER_LEN..frame_payload_end]);
        }
    }

    parse_ethercat_payload(data)
}

fn parse_ethercat_payload(data: &[u8]) -> Option<EthercatFields> {
    let mut datagrams = Vec::new();
    let mut offset = 0usize;

    while offset + ETHERCAT_DATAGRAM_HEADER_LEN + ETHERCAT_WORKING_COUNTER_LEN <= data.len() {
        let datagram = parse_ethercat_datagram(&data[offset..])?;
        offset += ETHERCAT_DATAGRAM_HEADER_LEN
            + usize::from(datagram.data_length)
            + ETHERCAT_WORKING_COUNTER_LEN;
        datagrams.push(datagram);
    }

    if datagrams.is_empty() || offset != data.len() {
        return None;
    }

    Some(EthercatFields { datagrams })
}

fn parse_ethercat_datagram(data: &[u8]) -> Option<EthercatDatagramFields> {
    if data.len() < ETHERCAT_DATAGRAM_HEADER_LEN + ETHERCAT_WORKING_COUNTER_LEN {
        return None;
    }

    let command_code = data[0];
    if !is_supported_command(command_code) {
        return None;
    }

    let index = data[1];
    let adp = u16::from_le_bytes([data[2], data[3]]);
    let ado = u16::from_le_bytes([data[4], data[5]]);
    let raw_len_flags = u16::from_le_bytes([data[6], data[7]]);
    let data_length = raw_len_flags & ETHERCAT_LENGTH_MASK;
    let data_length_usize = usize::from(data_length);
    let data_end = ETHERCAT_DATAGRAM_HEADER_LEN
        .checked_add(data_length_usize)?
        .checked_add(ETHERCAT_WORKING_COUNTER_LEN)?;

    if data.len() < data_end {
        return None;
    }

    let irq = u16::from_le_bytes([data[8], data[9]]);
    let payload = data
        [ETHERCAT_DATAGRAM_HEADER_LEN..ETHERCAT_DATAGRAM_HEADER_LEN + data_length_usize]
        .to_vec();
    let working_counter = u16::from_le_bytes([
        data[ETHERCAT_DATAGRAM_HEADER_LEN + data_length_usize],
        data[ETHERCAT_DATAGRAM_HEADER_LEN + data_length_usize + 1],
    ]);

    let identity = parse_identity_hints(ado, &payload);

    Some(EthercatDatagramFields {
        command_code,
        command: ethercat_command_name(command_code).to_string(),
        address_mode: ethercat_address_mode(command_code).to_string(),
        index,
        adp,
        ado,
        data_length,
        circulating: raw_len_flags & ETHERCAT_CIRCULATING_FLAG != 0,
        more_datagrams: raw_len_flags & ETHERCAT_MORE_DATAGRAMS_FLAG != 0,
        irq,
        working_counter,
        payload,
        identity,
    })
}

fn parse_identity_hints(ado: u16, payload: &[u8]) -> EthercatIdentityHints {
    let mut hints = EthercatIdentityHints::default();

    match ado {
        // EtherCAT slave controller register map.
        0x0004 if payload.len() >= 2 => {
            hints.alias_address = Some(u16::from_le_bytes([payload[0], payload[1]]));
        }
        0x0008 if payload.len() >= 4 => {
            hints.vendor_id = Some(u32::from_le_bytes([
                payload[0], payload[1], payload[2], payload[3],
            ]));
        }
        0x000C if payload.len() >= 4 => {
            hints.product_code = Some(u32::from_le_bytes([
                payload[0], payload[1], payload[2], payload[3],
            ]));
        }
        0x0010 if payload.len() >= 4 => {
            hints.revision = Some(u32::from_le_bytes([
                payload[0], payload[1], payload[2], payload[3],
            ]));
        }
        0x0014 if payload.len() >= 4 => {
            hints.serial_number = Some(u32::from_le_bytes([
                payload[0], payload[1], payload[2], payload[3],
            ]));
        }
        _ => {}
    }

    hints
}

fn looks_like_ethercat_frame(data: &[u8]) -> bool {
    if data.len() >= ETHERCAT_FRAME_HEADER_LEN {
        let frame_info = u16::from_le_bytes([data[0], data[1]]);
        let payload_length = usize::from(frame_info & ETHERCAT_LENGTH_MASK);
        let frame_payload_end = ETHERCAT_FRAME_HEADER_LEN + payload_length;
        if payload_length >= ETHERCAT_DATAGRAM_HEADER_LEN + ETHERCAT_WORKING_COUNTER_LEN
            && frame_payload_end <= data.len()
        {
            return is_supported_command(data[ETHERCAT_FRAME_HEADER_LEN]);
        }
    }

    data.len() >= ETHERCAT_DATAGRAM_HEADER_LEN + ETHERCAT_WORKING_COUNTER_LEN
        && is_supported_command(data[0])
}

fn is_supported_command(command_code: u8) -> bool {
    matches!(command_code, 0x00..=0x0E)
}

fn ethercat_command_name(command_code: u8) -> &'static str {
    match command_code {
        0x00 => "nop",
        0x01 => "aprd",
        0x02 => "apwr",
        0x03 => "aprw",
        0x04 => "fprd",
        0x05 => "fpwr",
        0x06 => "fprw",
        0x07 => "brd",
        0x08 => "bwr",
        0x09 => "brw",
        0x0A => "lrd",
        0x0B => "lwr",
        0x0C => "lrw",
        0x0D => "armw",
        0x0E => "frmw",
        _ => "cmd_unknown",
    }
}

fn ethercat_address_mode(command_code: u8) -> &'static str {
    match command_code {
        0x01..=0x03 => "auto_increment",
        0x04..=0x06 => "fixed",
        0x07..=0x09 => "broadcast",
        0x0A..=0x0C => "logical",
        0x0D | 0x0E => "read_modify_write",
        0x00 => "nop",
        _ => "unknown",
    }
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
            src_port: 0,
            dst_port: 0,
            src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            dst_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            vlan_id: None,
            timestamp: 0,
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn build_datagram(
        command_code: u8,
        index: u8,
        adp: u16,
        ado: u16,
        payload: &[u8],
        working_counter: u16,
        circulating: bool,
        more_datagrams: bool,
    ) -> Vec<u8> {
        let mut out = Vec::with_capacity(ETHERCAT_DATAGRAM_HEADER_LEN + payload.len() + 2);
        let mut raw_len_flags = payload.len() as u16 & ETHERCAT_LENGTH_MASK;
        if circulating {
            raw_len_flags |= ETHERCAT_CIRCULATING_FLAG;
        }
        if more_datagrams {
            raw_len_flags |= ETHERCAT_MORE_DATAGRAMS_FLAG;
        }

        out.push(command_code);
        out.push(index);
        out.extend_from_slice(&adp.to_le_bytes());
        out.extend_from_slice(&ado.to_le_bytes());
        out.extend_from_slice(&raw_len_flags.to_le_bytes());
        out.extend_from_slice(&0x0000u16.to_le_bytes());
        out.extend_from_slice(payload);
        out.extend_from_slice(&working_counter.to_le_bytes());
        out
    }

    #[test]
    fn can_parse_known_ethercat_payload() {
        let dissector = EthercatDissector;
        let frame = build_datagram(
            0x01,
            0x11,
            0x0001,
            0x0008,
            &[0x78, 0x56, 0x34, 0x12],
            1,
            false,
            false,
        );
        assert!(dissector.can_parse(&frame, 0, 0));
    }

    #[test]
    fn parse_single_datagram_with_vendor_id() {
        let dissector = EthercatDissector;
        let frame = build_datagram(
            0x01,
            0x11,
            0x0001,
            0x0008,
            &[0x78, 0x56, 0x34, 0x12],
            1,
            false,
            false,
        );

        let result = dissector.parse(&frame, &ctx());
        if let Some(ProtocolData::Ethercat(fields)) = result {
            assert_eq!(fields.datagrams.len(), 1);
            let datagram = &fields.datagrams[0];
            assert_eq!(datagram.command, "aprd");
            assert_eq!(datagram.address_mode, "auto_increment");
            assert_eq!(datagram.adp, 0x0001);
            assert_eq!(datagram.ado, 0x0008);
            assert_eq!(datagram.data_length, 4);
            assert_eq!(datagram.working_counter, 1);
            assert_eq!(datagram.identity.vendor_id, Some(0x12345678));
        } else {
            panic!("expected ethercat fields");
        }
    }

    #[test]
    fn parse_multiple_datagrams_and_alias_hint() {
        let first = build_datagram(0x07, 0x20, 0xFFFF, 0x0100, &[0xAA, 0xBB], 2, false, true);
        let second = build_datagram(0x02, 0x21, 0x0000, 0x0004, &[0x34, 0x12], 1, true, false);

        let mut frame = Vec::new();
        frame.extend_from_slice(&first);
        frame.extend_from_slice(&second);

        let dissector = EthercatDissector;
        let result = dissector.parse(&frame, &ctx());
        if let Some(ProtocolData::Ethercat(fields)) = result {
            assert_eq!(fields.datagrams.len(), 2);
            assert_eq!(fields.datagrams[0].command, "brd");
            assert_eq!(fields.datagrams[0].more_datagrams, true);
            assert_eq!(fields.datagrams[1].command, "apwr");
            assert_eq!(fields.datagrams[1].circulating, true);
            assert_eq!(fields.datagrams[1].identity.alias_address, Some(0x1234));
        } else {
            panic!("expected ethercat fields");
        }
    }

    #[test]
    fn rejects_truncated_datagram() {
        let dissector = EthercatDissector;
        let mut frame = build_datagram(
            0x0C,
            0x01,
            0x0000,
            0x0010,
            &[0x01, 0x02, 0x03],
            1,
            false,
            false,
        );
        frame.pop();

        assert!(dissector.parse(&frame, &ctx()).is_none());
    }
}
