//! PRP dissector — IEC 62439-3 Parallel Redundancy Protocol supervision frames.
//!
//! EtherType 0x88FB. Supervision frames are multicast announcements that
//! identify PRP nodes and their redundancy state. Data-frame trailers (RCT)
//! are parsed when detected at the end of payloads.

use crate::registry::{PacketContext, ProtocolData, ProtocolDissector};

pub const PRP_SUPERVISION_ETHERTYPE: u16 = 0x88FB;
pub const PRP_RCT_SUFFIX: u16 = 0x88FB;

#[derive(Default)]
pub struct PrpDissector;

fn supervision_type_name(stype: u16) -> &'static str {
    match stype {
        20 => "PRP_Node",
        21 => "PRP_RedBox",
        22 => "PRP_VDAN",
        23 => "HSR_Node",
        _ => "unknown",
    }
}

impl PrpDissector {
    pub fn parse_fields(&self, data: &[u8]) -> Option<PrpFields> {
        // Supervision frame: path(2) + version(2) + TLV(s).
        if data.len() < 6 {
            return None;
        }

        let sup_path = u16::from_be_bytes([data[0], data[1]]);
        let sup_version = u16::from_be_bytes([data[2], data[3]]);

        let mut supervision_type = None;
        let mut source_mac = None;
        let mut sequence_nr = None;
        let mut red_box_mac = None;

        // TLV parsing starting at offset 4.
        let mut offset = 4;
        while offset + 4 <= data.len() {
            let tlv_type = u16::from_be_bytes([data[offset], data[offset + 1]]);
            let tlv_len = u16::from_be_bytes([data[offset + 2], data[offset + 3]]) as usize;

            if tlv_type == 0 {
                break; // End marker
            }

            let value_start = offset + 4;
            if value_start + tlv_len > data.len() {
                break;
            }
            let value = &data[value_start..value_start + tlv_len];

            match tlv_type {
                20 | 21 | 22 | 23 => {
                    // Node TLV: mac(6)
                    supervision_type = Some(tlv_type);
                    if value.len() >= 6 {
                        source_mac = Some(format!(
                            "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
                            value[0], value[1], value[2], value[3], value[4], value[5]
                        ));
                    }
                }
                30 => {
                    // RedBox MAC TLV
                    if value.len() >= 6 {
                        red_box_mac = Some(format!(
                            "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
                            value[0], value[1], value[2], value[3], value[4], value[5]
                        ));
                    }
                }
                _ => {}
            }

            offset = value_start + tlv_len;
        }

        // Check for RCT trailer at end of data (6 bytes: seq(2) + lan_size(2) + suffix(2)).
        if data.len() >= 6 {
            let tail = &data[data.len() - 6..];
            let suffix = u16::from_be_bytes([tail[4], tail[5]]);
            if suffix == PRP_RCT_SUFFIX {
                sequence_nr = Some(u16::from_be_bytes([tail[0], tail[1]]));
            }
        }

        let sup_type = supervision_type.unwrap_or(0);

        Some(PrpFields {
            supervision_path: sup_path,
            supervision_version: sup_version,
            supervision_type: sup_type,
            supervision_type_name: supervision_type_name(sup_type).to_string(),
            source_mac,
            red_box_mac,
            sequence_nr,
        })
    }
}

impl ProtocolDissector for PrpDissector {
    fn name(&self) -> &str {
        "prp"
    }

    fn can_parse(&self, data: &[u8], src_port: u16, dst_port: u16) -> bool {
        if src_port != 0 || dst_port != 0 {
            return false;
        }
        data.len() >= 6
    }

    fn parse(&self, data: &[u8], _context: &PacketContext) -> Option<ProtocolData> {
        Some(ProtocolData::Prp(self.parse_fields(data)?))
    }
}

#[derive(Debug, Clone)]
pub struct PrpFields {
    pub supervision_path: u16,
    pub supervision_version: u16,
    pub supervision_type: u16,
    pub supervision_type_name: String,
    pub source_mac: Option<String>,
    pub red_box_mac: Option<String>,
    pub sequence_nr: Option<u16>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    fn ctx() -> PacketContext {
        PacketContext {
            src_mac: [0; 6],
            dst_mac: [0x01, 0x15, 0x4E, 0x00, 0x01, 0x00],
            src_ip: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            dst_ip: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            src_port: 0,
            dst_port: 0,
            vlan_id: None,
            timestamp: 0,
        }
    }

    fn build_prp_supervision() -> Vec<u8> {
        let mut pkt = Vec::new();
        // sup_path
        pkt.extend_from_slice(&0x0000u16.to_be_bytes());
        // sup_version = 1
        pkt.extend_from_slice(&0x0001u16.to_be_bytes());
        // TLV: PRP_Node (type=20, len=6, mac)
        pkt.extend_from_slice(&20u16.to_be_bytes());
        pkt.extend_from_slice(&6u16.to_be_bytes());
        pkt.extend_from_slice(&[0xAA, 0xBB, 0xCC, 0x11, 0x22, 0x33]);
        // End TLV
        pkt.extend_from_slice(&0u16.to_be_bytes());
        pkt.extend_from_slice(&0u16.to_be_bytes());
        pkt
    }

    #[test]
    fn parses_prp_supervision_frame() {
        let dissector = PrpDissector;
        let pkt = build_prp_supervision();
        let fields = dissector.parse_fields(&pkt).expect("prp fields");
        assert_eq!(fields.supervision_type, 20);
        assert_eq!(fields.supervision_type_name, "PRP_Node");
        assert_eq!(
            fields.source_mac.as_deref(),
            Some("aa:bb:cc:11:22:33")
        );
    }

    #[test]
    fn trait_parse_returns_prp_variant() {
        let dissector = PrpDissector;
        assert!(matches!(
            dissector.parse(&build_prp_supervision(), &ctx()),
            Some(ProtocolData::Prp(_))
        ));
    }
}
