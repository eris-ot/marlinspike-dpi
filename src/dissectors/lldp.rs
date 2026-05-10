//! LLDP dissector — parses Link Layer Discovery Protocol TLV chain
//! (EtherType 0x88CC, IEEE 802.1AB).

use crate::registry::{PacketContext, ProtocolData, ProtocolDissector};

#[derive(Default)]
pub struct LldpDissector;

impl ProtocolDissector for LldpDissector {
    fn name(&self) -> &str {
        "lldp"
    }

    /// LLDP is identified by EtherType 0x88CC; the engine passes it with
    /// ports = 0.
    fn can_parse(&self, data: &[u8], src_port: u16, dst_port: u16) -> bool {
        if src_port != 0 || dst_port != 0 {
            return false;
        }
        // At minimum we need a Chassis ID TLV (type 1).
        data.len() >= 2
    }

    fn parse(&self, data: &[u8], _context: &PacketContext) -> Option<ProtocolData> {
        let mut offset = 0;
        let mut chassis_id = String::new();
        let mut port_id = String::new();
        let mut ttl: u16 = 0;
        let mut system_name = String::new();
        let mut system_description = String::new();
        let mut capabilities = Vec::new();

        loop {
            if offset + 2 > data.len() {
                break;
            }

            let tlv_header = u16::from_be_bytes([data[offset], data[offset + 1]]);
            let tlv_type = (tlv_header >> 9) as u8;
            let tlv_len = (tlv_header & 0x01FF) as usize;
            offset += 2;

            if offset + tlv_len > data.len() {
                break;
            }

            let tlv_data = &data[offset..offset + tlv_len];

            match tlv_type {
                0 => break, // End of LLDPDU
                1 => {
                    // Chassis ID: first byte is subtype
                    if tlv_data.len() > 1 {
                        chassis_id = format_tlv_value(&tlv_data[1..], tlv_data[0]);
                    }
                }
                2 => {
                    // Port ID: first byte is subtype
                    if tlv_data.len() > 1 {
                        port_id = format_tlv_value(&tlv_data[1..], tlv_data[0]);
                    }
                }
                3 => {
                    // TTL
                    if tlv_data.len() >= 2 {
                        ttl = u16::from_be_bytes([tlv_data[0], tlv_data[1]]);
                    }
                }
                5 => {
                    // System Name
                    system_name = String::from_utf8_lossy(tlv_data).to_string();
                }
                6 => {
                    // System Description
                    system_description = String::from_utf8_lossy(tlv_data).to_string();
                }
                7 => {
                    // System Capabilities (4 bytes: 2 available + 2 enabled)
                    if tlv_data.len() >= 4 {
                        let enabled = u16::from_be_bytes([tlv_data[2], tlv_data[3]]);
                        decode_capabilities(enabled, &mut capabilities);
                    }
                }
                _ => { /* skip unknown TLVs */ }
            }

            offset += tlv_len;
        }

        // Must have at least a chassis ID to be valid LLDP.
        if chassis_id.is_empty() {
            return None;
        }

        Some(ProtocolData::Lldp(LldpFields {
            chassis_id,
            port_id,
            ttl,
            system_name,
            system_description,
            capabilities,
        }))
    }
}

fn format_tlv_value(value: &[u8], subtype: u8) -> String {
    match subtype {
        4 => {
            // MAC address
            if value.len() == 6 {
                return format!(
                    "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
                    value[0], value[1], value[2], value[3], value[4], value[5]
                );
            }
            hex::encode(value)
        }
        5 | 6 | 7 => {
            // Network address / string-like
            String::from_utf8_lossy(value).to_string()
        }
        _ => {
            // Try UTF-8, fall back to hex.
            match std::str::from_utf8(value) {
                Ok(s) => s.to_string(),
                Err(_) => hex::encode(value),
            }
        }
    }
}

fn decode_capabilities(bits: u16, out: &mut Vec<String>) {
    let names = [
        (0x0001, "Other"),
        (0x0002, "Repeater"),
        (0x0004, "Bridge"),
        (0x0008, "WLAN AP"),
        (0x0010, "Router"),
        (0x0020, "Telephone"),
        (0x0040, "DOCSIS"),
        (0x0080, "Station Only"),
    ];
    for (mask, name) in &names {
        if bits & mask != 0 {
            out.push(name.to_string());
        }
    }
}

#[derive(Debug, Clone)]
pub struct LldpFields {
    pub chassis_id: String,
    pub port_id: String,
    pub ttl: u16,
    pub system_name: String,
    pub system_description: String,
    pub capabilities: Vec<String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    fn ctx() -> PacketContext {
        PacketContext {
            src_mac: [0; 6],
            dst_mac: [0x01, 0x80, 0xC2, 0x00, 0x00, 0x0E],
            src_ip: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            dst_ip: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            src_port: 0,
            dst_port: 0,
            vlan_id: None,
            timestamp: 0,
        }
    }

    fn build_lldp_frame() -> Vec<u8> {
        let mut pkt = Vec::new();

        // Chassis ID TLV (type 1, subtype 4 = MAC)
        let chassis_mac = [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF];
        let chassis_len = 1 + chassis_mac.len(); // subtype + value
        let tlv_hdr = ((1u16) << 9) | chassis_len as u16;
        pkt.extend_from_slice(&tlv_hdr.to_be_bytes());
        pkt.push(4); // subtype: MAC
        pkt.extend_from_slice(&chassis_mac);

        // Port ID TLV (type 2, subtype 7 = local)
        let port_val = b"eth0";
        let port_len = 1 + port_val.len();
        let tlv_hdr = ((2u16) << 9) | port_len as u16;
        pkt.extend_from_slice(&tlv_hdr.to_be_bytes());
        pkt.push(7); // subtype: locally assigned
        pkt.extend_from_slice(port_val);

        // TTL TLV (type 3)
        let tlv_hdr = ((3u16) << 9) | 2u16;
        pkt.extend_from_slice(&tlv_hdr.to_be_bytes());
        pkt.extend_from_slice(&120u16.to_be_bytes()); // TTL = 120s

        // System Name TLV (type 5)
        let name = b"switch01";
        let tlv_hdr = ((5u16) << 9) | name.len() as u16;
        pkt.extend_from_slice(&tlv_hdr.to_be_bytes());
        pkt.extend_from_slice(name);

        // System Description TLV (type 6)
        let desc = b"Fathom test switch";
        let tlv_hdr = ((6u16) << 9) | desc.len() as u16;
        pkt.extend_from_slice(&tlv_hdr.to_be_bytes());
        pkt.extend_from_slice(desc);

        // System Capabilities TLV (type 7)
        let tlv_hdr = ((7u16) << 9) | 4u16;
        pkt.extend_from_slice(&tlv_hdr.to_be_bytes());
        pkt.extend_from_slice(&0x0014u16.to_be_bytes()); // available: Bridge + Router
        pkt.extend_from_slice(&0x0014u16.to_be_bytes()); // enabled: Bridge + Router

        // End of LLDPDU TLV (type 0, length 0)
        pkt.extend_from_slice(&[0x00, 0x00]);

        pkt
    }

    #[test]
    fn test_parse_lldp_frame() {
        let pkt = build_lldp_frame();
        let d = LldpDissector;
        assert!(d.can_parse(&pkt, 0, 0));

        let result = d.parse(&pkt, &ctx()).unwrap();
        match result {
            ProtocolData::Lldp(lldp) => {
                assert_eq!(lldp.chassis_id, "aa:bb:cc:dd:ee:ff");
                assert_eq!(lldp.port_id, "eth0");
                assert_eq!(lldp.ttl, 120);
                assert_eq!(lldp.system_name, "switch01");
                assert_eq!(lldp.system_description, "Fathom test switch");
                assert!(lldp.capabilities.contains(&"Bridge".to_string()));
                assert!(lldp.capabilities.contains(&"Router".to_string()));
            }
            _ => panic!("expected LLDP"),
        }
    }
}
