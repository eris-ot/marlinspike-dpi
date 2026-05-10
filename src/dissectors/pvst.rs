//! PVST+ dissector — Cisco Per-VLAN Spanning Tree Plus.
//!
//! SNAP OUI 00:00:0C, PID 0x010B. Standard STP/RSTP BPDU payload with an
//! originating-VLAN TLV appended (type=0x0000, length=0x0002, vlan_id).

use crate::registry::{PacketContext, ProtocolData, ProtocolDissector};

#[derive(Default)]
pub struct PvstDissector;

impl PvstDissector {
    pub fn parse_fields(&self, data: &[u8]) -> Option<PvstFields> {
        // Standard BPDU (35 bytes) + originating VLAN TLV (4 + 2 = 6 bytes).
        // Some frames omit the TLV, so 35 is the minimum.
        if data.len() < 35 {
            return None;
        }
        if u16::from_be_bytes([data[0], data[1]]) != 0x0000 {
            return None;
        }

        let protocol_version = data[2];
        let bpdu_type = data[3];
        let flags = data[4];

        let root_id = format_bridge_id(&data[5..13]);
        let root_path_cost = u32::from_be_bytes([data[13], data[14], data[15], data[16]]);
        let bridge_id = format_bridge_id(&data[17..25]);
        let port_id = u16::from_be_bytes([data[25], data[26]]);

        // Originating VLAN TLV: after the 35-byte BPDU or 36-byte RSTP BPDU.
        let mut originating_vlan = None;
        let tlv_offset = if protocol_version >= 2 && data.len() >= 36 {
            36 // RSTP has version_1_length byte at 35
        } else {
            35
        };

        if data.len() >= tlv_offset + 6 {
            let tlv_type = u16::from_be_bytes([data[tlv_offset], data[tlv_offset + 1]]);
            let tlv_len = u16::from_be_bytes([data[tlv_offset + 2], data[tlv_offset + 3]]);
            if tlv_type == 0x0000 && tlv_len == 0x0002 {
                originating_vlan = Some(u16::from_be_bytes([
                    data[tlv_offset + 4],
                    data[tlv_offset + 5],
                ]));
            }
        }

        Some(PvstFields {
            protocol_version,
            bpdu_type,
            flags,
            root_id,
            root_path_cost,
            bridge_id,
            port_id,
            originating_vlan,
        })
    }
}

fn format_bridge_id(bytes: &[u8]) -> String {
    if bytes.len() != 8 {
        return hex::encode(bytes);
    }
    let priority = u16::from_be_bytes([bytes[0], bytes[1]]);
    format!(
        "{priority}/{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7]
    )
}

impl ProtocolDissector for PvstDissector {
    fn name(&self) -> &str {
        "pvst"
    }

    fn can_parse(&self, data: &[u8], src_port: u16, dst_port: u16) -> bool {
        if src_port != 0 || dst_port != 0 {
            return false;
        }
        data.len() >= 35 && u16::from_be_bytes([data[0], data[1]]) == 0x0000
    }

    fn parse(&self, data: &[u8], _context: &PacketContext) -> Option<ProtocolData> {
        Some(ProtocolData::Pvst(self.parse_fields(data)?))
    }
}

#[derive(Debug, Clone)]
pub struct PvstFields {
    pub protocol_version: u8,
    pub bpdu_type: u8,
    pub flags: u8,
    pub root_id: String,
    pub root_path_cost: u32,
    pub bridge_id: String,
    pub port_id: u16,
    pub originating_vlan: Option<u16>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    fn ctx() -> PacketContext {
        PacketContext {
            src_mac: [0; 6],
            dst_mac: [0x01, 0x00, 0x0C, 0xCC, 0xCC, 0xCD],
            src_ip: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            dst_ip: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            src_port: 0,
            dst_port: 0,
            vlan_id: None,
            timestamp: 0,
        }
    }

    fn build_pvst_bpdu() -> Vec<u8> {
        let mut pkt = vec![0u8; 42]; // 36 (RSTP) + 6 (VLAN TLV)
        pkt[0] = 0x00;
        pkt[1] = 0x00; // protocol id
        pkt[2] = 0x02; // RSTP
        pkt[3] = 0x02; // BPDU type
        pkt[4] = 0x3C; // flags
        // Root ID
        pkt[5..13].copy_from_slice(&[0x80, 0x64, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
        // Root path cost
        pkt[13..17].copy_from_slice(&200u32.to_be_bytes());
        // Bridge ID
        pkt[17..25].copy_from_slice(&[0x80, 0x64, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]);
        // Port ID
        pkt[25..27].copy_from_slice(&0x8001u16.to_be_bytes());
        // Timers
        pkt[27..35].copy_from_slice(&[0x00, 0x00, 0x14, 0x00, 0x02, 0x00, 0x0F, 0x00]);
        // version_1_length = 0
        pkt[35] = 0;
        // Originating VLAN TLV: type=0, length=2, vlan=100
        pkt[36..38].copy_from_slice(&0x0000u16.to_be_bytes());
        pkt[38..40].copy_from_slice(&0x0002u16.to_be_bytes());
        pkt[40..42].copy_from_slice(&100u16.to_be_bytes());
        pkt
    }

    #[test]
    fn parses_pvst_bpdu_with_vlan() {
        let dissector = PvstDissector;
        let pkt = build_pvst_bpdu();
        let fields = dissector.parse_fields(&pkt).expect("pvst fields");
        assert_eq!(fields.protocol_version, 2);
        assert_eq!(fields.originating_vlan, Some(100));
        assert_eq!(fields.root_id, "32868/00:11:22:33:44:55");
        assert_eq!(fields.bridge_id, "32868/aa:bb:cc:dd:ee:ff");
    }

    #[test]
    fn rejects_port_bound() {
        let dissector = PvstDissector;
        assert!(!dissector.can_parse(&build_pvst_bpdu(), 80, 0));
    }

    #[test]
    fn trait_parse_returns_pvst_variant() {
        let dissector = PvstDissector;
        assert!(matches!(
            dissector.parse(&build_pvst_bpdu(), &ctx()),
            Some(ProtocolData::Pvst(_))
        ));
    }
}
