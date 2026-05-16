//! MRP dissector — IEC 62439-2 Media Redundancy Protocol for PROFINET rings.
//!
//! EtherType 0x88E3. TLV-based frames: MRP_Test, MRP_TopologyChange,
//! MRP_LinkDown, MRP_LinkUp, MRP_Common.

use crate::registry::{PacketContext, ProtocolData, ProtocolDissector};

pub const MRP_ETHERTYPE: u16 = 0x88E3;

#[derive(Default)]
pub struct MrpDissector;

fn frame_type_name(ftype: u16) -> &'static str {
    match ftype {
        0x0001 => "MRP_Test",
        0x0002 => "MRP_TopologyChange",
        0x0003 => "MRP_LinkDown",
        0x0004 => "MRP_LinkUp",
        0x0005 => "MRP_Common",
        _ => "unknown",
    }
}

impl MrpDissector {
    pub fn parse_fields(&self, data: &[u8]) -> Option<MrpFields> {
        // Minimum MRP TLV: version(2) + type(2) + length(1) + some value.
        if data.len() < 5 {
            return None;
        }

        let version = u16::from_be_bytes([data[0], data[1]]);

        // First TLV starts at offset 2 (after version).
        let mut offset = 2;
        let mut frame_type = 0u16;
        let mut domain_uuid = None;
        let mut ring_state = None;
        let mut priority = None;
        let mut source_mac = None;

        while offset + 4 <= data.len() {
            let tlv_type = u16::from_be_bytes([data[offset], data[offset + 1]]);
            let tlv_len = u16::from_be_bytes([data[offset + 2], data[offset + 3]]) as usize;
            let value_start = offset + 4;

            if tlv_type == 0x0000 {
                break; // End marker
            }

            if value_start + tlv_len > data.len() {
                break;
            }

            if frame_type == 0 {
                frame_type = tlv_type;
            }

            let value = &data[value_start..value_start + tlv_len];

            match tlv_type {
                0x0001 => {
                    // MRP_Test: prio(2) + sa(6) + port_role(2) + ring_state(2) + transition(2) + timestamp(4)
                    if value.len() >= 14 {
                        priority = Some(u16::from_be_bytes([value[0], value[1]]));
                        source_mac = Some(format!(
                            "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
                            value[2], value[3], value[4], value[5], value[6], value[7]
                        ));
                        // port_role at [8..10], ring_state at [10..12]
                        ring_state = Some(match u16::from_be_bytes([value[10], value[11]]) {
                            0 => "open".to_string(),
                            1 => "closed".to_string(),
                            other => format!("{other}"),
                        });
                    }
                }
                0x0002..=0x0004 => {
                    // TopologyChange / LinkDown / LinkUp: sa(6) + port_role(2)
                    if value.len() >= 6 {
                        source_mac = Some(format!(
                            "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
                            value[0], value[1], value[2], value[3], value[4], value[5]
                        ));
                    }
                }
                0x0005 => {
                    // MRP_Common: sequence_id(2) + domain_uuid(16)
                    if value.len() >= 18 {
                        domain_uuid = Some(format_uuid(&value[2..18]));
                    }
                }
                _ => {}
            }

            offset = value_start + tlv_len;
        }

        if frame_type == 0 {
            return None;
        }

        Some(MrpFields {
            version,
            frame_type,
            frame_type_name: frame_type_name(frame_type).to_string(),
            domain_uuid,
            ring_state,
            priority,
            source_mac,
        })
    }
}

fn format_uuid(bytes: &[u8]) -> String {
    format!(
        "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        bytes[0],
        bytes[1],
        bytes[2],
        bytes[3],
        bytes[4],
        bytes[5],
        bytes[6],
        bytes[7],
        bytes[8],
        bytes[9],
        bytes[10],
        bytes[11],
        bytes[12],
        bytes[13],
        bytes[14],
        bytes[15]
    )
}

impl ProtocolDissector for MrpDissector {
    fn name(&self) -> &str {
        "mrp"
    }

    fn can_parse(&self, data: &[u8], src_port: u16, dst_port: u16) -> bool {
        if src_port != 0 || dst_port != 0 {
            return false;
        }
        data.len() >= 5
    }

    fn parse(&self, data: &[u8], _context: &PacketContext) -> Option<ProtocolData> {
        Some(ProtocolData::Mrp(self.parse_fields(data)?))
    }
}

#[derive(Debug, Clone)]
pub struct MrpFields {
    pub version: u16,
    pub frame_type: u16,
    pub frame_type_name: String,
    pub domain_uuid: Option<String>,
    pub ring_state: Option<String>,
    pub priority: Option<u16>,
    pub source_mac: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    fn ctx() -> PacketContext {
        PacketContext {
            src_mac: [0; 6],
            dst_mac: [0x01, 0x15, 0x4E, 0x00, 0x00, 0x01],
            src_ip: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            dst_ip: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            src_port: 0,
            dst_port: 0,
            vlan_id: None,
            timestamp: 0,
        }
    }

    fn build_mrp_test() -> Vec<u8> {
        let mut pkt = Vec::new();
        // Version 1
        pkt.extend_from_slice(&1u16.to_be_bytes());
        // TLV: MRP_Test (0x0001), length=18
        pkt.extend_from_slice(&0x0001u16.to_be_bytes());
        pkt.extend_from_slice(&18u16.to_be_bytes());
        // priority=0x8000
        pkt.extend_from_slice(&0x8000u16.to_be_bytes());
        // source mac
        pkt.extend_from_slice(&[0xAA, 0xBB, 0xCC, 0x11, 0x22, 0x33]);
        // port role
        pkt.extend_from_slice(&0x0000u16.to_be_bytes());
        // ring state: 1 = closed
        pkt.extend_from_slice(&0x0001u16.to_be_bytes());
        // transition
        pkt.extend_from_slice(&0x0000u16.to_be_bytes());
        // timestamp
        pkt.extend_from_slice(&0u32.to_be_bytes());
        // End TLV
        pkt.extend_from_slice(&0x0000u16.to_be_bytes());
        pkt.extend_from_slice(&0x0000u16.to_be_bytes());
        pkt
    }

    #[test]
    fn parses_mrp_test_frame() {
        let dissector = MrpDissector;
        let pkt = build_mrp_test();
        let fields = dissector.parse_fields(&pkt).expect("mrp fields");
        assert_eq!(fields.version, 1);
        assert_eq!(fields.frame_type, 0x0001);
        assert_eq!(fields.frame_type_name, "MRP_Test");
        assert_eq!(fields.ring_state.as_deref(), Some("closed"));
        assert_eq!(fields.priority, Some(0x8000));
        assert_eq!(fields.source_mac.as_deref(), Some("aa:bb:cc:11:22:33"));
    }

    #[test]
    fn rejects_port_bound() {
        let dissector = MrpDissector;
        assert!(!dissector.can_parse(&build_mrp_test(), 80, 0));
    }

    #[test]
    fn trait_parse_returns_mrp_variant() {
        let dissector = MrpDissector;
        assert!(matches!(
            dissector.parse(&build_mrp_test(), &ctx()),
            Some(ProtocolData::Mrp(_))
        ));
    }
}
