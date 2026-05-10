//! EtherNet/IP protocol dissector with full encapsulation header and CIP payload parsing.

use crate::registry::{PacketContext, ProtocolData, ProtocolDissector};

#[derive(Default)]
pub struct EthernetIpDissector;

const ENIP_PORT: u16 = 44818;

/// Encapsulation header size: command(2) + length(2) + session_handle(4) + status(4) +
/// sender_context(8) + options(4) = 24 bytes.
const ENCAP_HEADER_SIZE: usize = 24;

/// Returns the human-readable name for an EtherNet/IP encapsulation command.
fn command_name(cmd: u16) -> &'static str {
    match cmd {
        0x0001 => "NOP",
        0x0004 => "ListServices",
        0x0063 => "ListIdentity",
        0x0064 => "ListInterfaces",
        0x0065 => "RegisterSession",
        0x0066 => "UnregisterSession",
        0x006F => "SendRRData",
        0x0070 => "SendUnitData",
        _ => "Unknown",
    }
}

impl ProtocolDissector for EthernetIpDissector {
    fn name(&self) -> &str {
        "ethernet_ip"
    }

    fn can_parse(&self, data: &[u8], src_port: u16, dst_port: u16) -> bool {
        if src_port != ENIP_PORT && dst_port != ENIP_PORT {
            return false;
        }
        if data.len() < ENCAP_HEADER_SIZE {
            return false;
        }
        // Validate command is a known value to reduce false positives.
        let command = u16::from_le_bytes([data[0], data[1]]);
        matches!(
            command,
            0x0001 | 0x0004 | 0x0063 | 0x0064 | 0x0065 | 0x0066 | 0x006F | 0x0070
        )
    }

    fn parse(&self, data: &[u8], _context: &PacketContext) -> Option<ProtocolData> {
        if data.len() < ENCAP_HEADER_SIZE {
            return None;
        }

        // --- Encapsulation Header ---
        let command = u16::from_le_bytes([data[0], data[1]]);
        let encap_length = u16::from_le_bytes([data[2], data[3]]) as usize;
        let session_handle = u32::from_le_bytes([data[4], data[5], data[6], data[7]]);
        let _status = u32::from_le_bytes([data[8], data[9], data[10], data[11]]);
        // sender_context: data[12..20], options: data[20..24]

        // --- CIP Data ---
        // CIP payload follows the encapsulation header for SendRRData / SendUnitData.
        let payload_end = ENCAP_HEADER_SIZE
            .checked_add(encap_length)
            .unwrap_or(data.len())
            .min(data.len());

        let cip_data = if command == 0x006F || command == 0x0070 {
            data[ENCAP_HEADER_SIZE..payload_end].to_vec()
        } else {
            data[ENCAP_HEADER_SIZE..payload_end].to_vec()
        };

        let _ = command_name(command); // ensure the function is used

        Some(ProtocolData::EthernetIp(EthernetIpFields {
            command,
            session_handle,
            cip_data,
        }))
    }
}

#[derive(Debug, Clone)]
pub struct EthernetIpFields {
    pub command: u16,
    pub session_handle: u32,
    pub cip_data: Vec<u8>,
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
            src_port: 49200,
            dst_port: ENIP_PORT,
            src_ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10)),
            dst_ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 20)),
            vlan_id: None,
            timestamp: 0,
        }
    }

    fn build_encap(command: u16, length: u16, session: u32) -> Vec<u8> {
        let mut pkt = Vec::with_capacity(ENCAP_HEADER_SIZE + length as usize);
        pkt.extend_from_slice(&command.to_le_bytes());
        pkt.extend_from_slice(&length.to_le_bytes());
        pkt.extend_from_slice(&session.to_le_bytes());
        pkt.extend_from_slice(&0u32.to_le_bytes()); // status
        pkt.extend_from_slice(&[0u8; 8]); // sender context
        pkt.extend_from_slice(&0u32.to_le_bytes()); // options
        pkt
    }

    #[test]
    fn can_parse_register_session() {
        let dissector = EthernetIpDissector;
        let data = build_encap(0x0065, 4, 0);
        assert!(dissector.can_parse(&data, 49200, ENIP_PORT));
    }

    #[test]
    fn can_parse_rejects_unknown_command() {
        let dissector = EthernetIpDissector;
        let data = build_encap(0xFFFF, 0, 0);
        assert!(!dissector.can_parse(&data, 49200, ENIP_PORT));
    }

    #[test]
    fn can_parse_wrong_port() {
        let dissector = EthernetIpDissector;
        let data = build_encap(0x0065, 0, 0);
        assert!(!dissector.can_parse(&data, 1234, 5678));
    }

    #[test]
    fn parse_register_session() {
        let dissector = EthernetIpDissector;
        let mut data = build_encap(0x0065, 4, 0);
        // RegisterSession payload: protocol_version(2) + option_flags(2)
        data.extend_from_slice(&[0x01, 0x00, 0x00, 0x00]);

        let result = dissector.parse(&data, &ctx());
        if let Some(ProtocolData::EthernetIp(fields)) = result {
            assert_eq!(fields.command, 0x0065);
            assert_eq!(command_name(fields.command), "RegisterSession");
            assert_eq!(fields.session_handle, 0);
            assert_eq!(fields.cip_data, vec![0x01, 0x00, 0x00, 0x00]);
        } else {
            panic!("Expected EthernetIp protocol data");
        }
    }

    #[test]
    fn parse_list_identity() {
        let dissector = EthernetIpDissector;
        let data = build_encap(0x0063, 0, 0);

        let result = dissector.parse(&data, &ctx());
        if let Some(ProtocolData::EthernetIp(fields)) = result {
            assert_eq!(fields.command, 0x0063);
            assert_eq!(command_name(fields.command), "ListIdentity");
            assert!(fields.cip_data.is_empty());
        } else {
            panic!("Expected EthernetIp protocol data");
        }
    }

    #[test]
    fn parse_send_rr_data() {
        let dissector = EthernetIpDissector;
        let mut data = build_encap(0x006F, 6, 0x0000_1234);
        // CIP payload bytes
        data.extend_from_slice(&[0x00, 0x00, 0x00, 0x00, 0x02, 0x00]);

        let result = dissector.parse(&data, &ctx());
        if let Some(ProtocolData::EthernetIp(fields)) = result {
            assert_eq!(fields.command, 0x006F);
            assert_eq!(command_name(fields.command), "SendRRData");
            assert_eq!(fields.session_handle, 0x1234);
            assert_eq!(fields.cip_data.len(), 6);
        } else {
            panic!("Expected EthernetIp protocol data");
        }
    }

    #[test]
    fn parse_send_unit_data() {
        let dissector = EthernetIpDissector;
        let mut data = build_encap(0x0070, 2, 0xABCD_0000);
        data.extend_from_slice(&[0xFF, 0xEE]);

        let result = dissector.parse(&data, &ctx());
        if let Some(ProtocolData::EthernetIp(fields)) = result {
            assert_eq!(fields.command, 0x0070);
            assert_eq!(command_name(fields.command), "SendUnitData");
            assert_eq!(fields.session_handle, 0xABCD_0000);
            assert_eq!(fields.cip_data, vec![0xFF, 0xEE]);
        } else {
            panic!("Expected EthernetIp protocol data");
        }
    }

    #[test]
    fn parse_unregister_session() {
        let dissector = EthernetIpDissector;
        let data = build_encap(0x0066, 0, 0x5678);

        let result = dissector.parse(&data, &ctx());
        if let Some(ProtocolData::EthernetIp(fields)) = result {
            assert_eq!(fields.command, 0x0066);
            assert_eq!(command_name(fields.command), "UnregisterSession");
            assert_eq!(fields.session_handle, 0x5678);
        } else {
            panic!("Expected EthernetIp protocol data");
        }
    }
}
