//! ARP dissector — parses ARP requests and replies (EtherType 0x0806).

use crate::registry::{PacketContext, ProtocolData, ProtocolDissector};

#[derive(Default)]
pub struct ArpDissector;

impl ProtocolDissector for ArpDissector {
    fn name(&self) -> &str {
        "arp"
    }

    /// ARP is identified by EtherType, not by port. The engine passes ARP
    /// frames with src_port=0, dst_port=0 when the EtherType is 0x0806.
    fn can_parse(&self, data: &[u8], src_port: u16, dst_port: u16) -> bool {
        // Ports are 0 when the engine identified this via EtherType.
        if src_port != 0 || dst_port != 0 {
            return false;
        }
        // ARP over Ethernet/IPv4: hardware_type=1, protocol_type=0x0800,
        // hlen=6, plen=4 → minimum 28 bytes.
        if data.len() < 28 {
            return false;
        }
        let hw_type = u16::from_be_bytes([data[0], data[1]]);
        let proto_type = u16::from_be_bytes([data[2], data[3]]);
        hw_type == 1 && proto_type == 0x0800
    }

    fn parse(&self, data: &[u8], _context: &PacketContext) -> Option<ProtocolData> {
        if data.len() < 28 {
            return None;
        }

        let operation = u16::from_be_bytes([data[6], data[7]]);

        let mut sender_mac = [0u8; 6];
        sender_mac.copy_from_slice(&data[8..14]);
        let mut sender_ip = [0u8; 4];
        sender_ip.copy_from_slice(&data[14..18]);
        let mut target_mac = [0u8; 6];
        target_mac.copy_from_slice(&data[18..24]);
        let mut target_ip = [0u8; 4];
        target_ip.copy_from_slice(&data[24..28]);

        Some(ProtocolData::Arp(ArpFields {
            operation,
            sender_mac,
            sender_ip,
            target_mac,
            target_ip,
        }))
    }
}

#[derive(Debug, Clone)]
pub struct ArpFields {
    pub operation: u16,
    pub sender_mac: [u8; 6],
    pub sender_ip: [u8; 4],
    pub target_mac: [u8; 6],
    pub target_ip: [u8; 4],
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    fn ctx() -> PacketContext {
        PacketContext {
            src_mac: [0; 6],
            dst_mac: [0xFF; 6],
            src_ip: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            dst_ip: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            src_port: 0,
            dst_port: 0,
            vlan_id: None,
            timestamp: 0,
        }
    }

    /// Build an ARP request: who-has 192.168.1.2, tell 192.168.1.1
    fn build_arp_request() -> Vec<u8> {
        let mut pkt = Vec::new();
        pkt.extend_from_slice(&[0x00, 0x01]); // hardware type: Ethernet
        pkt.extend_from_slice(&[0x08, 0x00]); // protocol type: IPv4
        pkt.push(6); // hardware size
        pkt.push(4); // protocol size
        pkt.extend_from_slice(&[0x00, 0x01]); // operation: request

        // Sender MAC + IP
        pkt.extend_from_slice(&[0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0x01]);
        pkt.extend_from_slice(&[192, 168, 1, 1]);

        // Target MAC + IP
        pkt.extend_from_slice(&[0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
        pkt.extend_from_slice(&[192, 168, 1, 2]);

        pkt
    }

    #[test]
    fn test_parse_arp_request() {
        let pkt = build_arp_request();
        let d = ArpDissector;
        assert!(d.can_parse(&pkt, 0, 0));

        let result = d.parse(&pkt, &ctx()).unwrap();
        match result {
            ProtocolData::Arp(arp) => {
                assert_eq!(arp.operation, 1); // request
                assert_eq!(arp.sender_mac, [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0x01]);
                assert_eq!(arp.sender_ip, [192, 168, 1, 1]);
                assert_eq!(arp.target_mac, [0; 6]);
                assert_eq!(arp.target_ip, [192, 168, 1, 2]);
            }
            _ => panic!("expected ARP"),
        }
    }

    #[test]
    fn test_arp_rejected_with_ports() {
        let pkt = build_arp_request();
        let d = ArpDissector;
        assert!(!d.can_parse(&pkt, 80, 443));
    }
}
