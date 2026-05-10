//! CDP dissector — enrichment-first parsing for Cisco Discovery Protocol TLVs.

use crate::registry::{PacketContext, ProtocolData, ProtocolDissector};

#[derive(Default)]
pub struct CdpDissector;

impl CdpDissector {
    pub fn parse_fields(&self, data: &[u8]) -> Option<CdpFields> {
        if data.len() < 4 {
            return None;
        }

        let version = data[0];
        let ttl = data[1];
        let checksum = u16::from_be_bytes([data[2], data[3]]);
        let mut offset = 4; // version(1) + ttl(1) + checksum(2)
        let mut device_id = String::new();
        let mut port_id = None;
        let mut platform = None;
        let mut software_version = None;
        let mut capabilities = Vec::new();
        let mut native_vlan = None;
        let mut duplex = None;

        while offset + 4 <= data.len() {
            let tlv_type = u16::from_be_bytes([data[offset], data[offset + 1]]);
            let tlv_len = u16::from_be_bytes([data[offset + 2], data[offset + 3]]) as usize;

            if tlv_len < 4 || offset + tlv_len > data.len() {
                break;
            }

            let value = &data[offset + 4..offset + tlv_len];

            match tlv_type {
                0x0001 => {
                    device_id = String::from_utf8_lossy(value)
                        .trim_end_matches('\0')
                        .to_string();
                }
                0x0003 => {
                    let parsed = String::from_utf8_lossy(value)
                        .trim_end_matches('\0')
                        .to_string();
                    if !parsed.is_empty() {
                        port_id = Some(parsed);
                    }
                }
                0x0004 => {
                    if value.len() >= 4 {
                        let bits = u32::from_be_bytes([value[0], value[1], value[2], value[3]]);
                        decode_capabilities(bits, &mut capabilities);
                    }
                }
                0x0005 => {
                    let parsed = String::from_utf8_lossy(value)
                        .trim_end_matches('\0')
                        .to_string();
                    if !parsed.is_empty() {
                        software_version = Some(parsed);
                    }
                }
                0x0006 => {
                    let parsed = String::from_utf8_lossy(value)
                        .trim_end_matches('\0')
                        .to_string();
                    if !parsed.is_empty() {
                        platform = Some(parsed);
                    }
                }
                0x000a => {
                    if value.len() >= 2 {
                        native_vlan = Some(u16::from_be_bytes([value[0], value[1]]));
                    }
                }
                0x000b => {
                    duplex = value.first().map(|b| match b {
                        0 => "half".to_string(),
                        1 => "full".to_string(),
                        other => format!("0x{other:02x}"),
                    });
                }
                _ => {}
            }

            offset += tlv_len;
        }

        if device_id.is_empty() {
            return None;
        }

        Some(CdpFields {
            version,
            ttl,
            checksum,
            device_id,
            port_id: port_id.unwrap_or_default(),
            platform,
            software_version,
            capabilities,
            native_vlan,
            duplex,
            management_addresses: Vec::new(),
        })
    }
}

impl ProtocolDissector for CdpDissector {
    fn name(&self) -> &str {
        "cdp"
    }

    fn can_parse(&self, data: &[u8], src_port: u16, dst_port: u16) -> bool {
        if src_port != 0 || dst_port != 0 {
            return false;
        }
        data.len() >= 4 && matches!(data[0], 1 | 2)
    }

    fn parse(&self, data: &[u8], _context: &PacketContext) -> Option<ProtocolData> {
        Some(ProtocolData::Cdp(self.parse_fields(data)?))
    }
}

fn decode_capabilities(bits: u32, out: &mut Vec<String>) {
    let names = [
        (0x0000_0001, "router"),
        (0x0000_0002, "transparent_bridge"),
        (0x0000_0004, "source_route_bridge"),
        (0x0000_0008, "switch"),
        (0x0000_0010, "host"),
        (0x0000_0020, "igmp"),
        (0x0000_0040, "repeater"),
        (0x0000_0080, "phone"),
        (0x0000_0100, "docsis_cable_device"),
        (0x0000_0200, "two_port_mac_relay"),
        (0x0000_0400, "wlan_access_point"),
        (0x0000_0800, "repeater_legacy"),
    ];

    for (mask, name) in names {
        if bits & mask != 0 {
            out.push(name.to_string());
        }
    }
}

#[derive(Debug, Clone)]
pub struct CdpFields {
    pub version: u8,
    pub ttl: u8,
    pub checksum: u16,
    pub device_id: String,
    pub port_id: String,
    pub platform: Option<String>,
    pub software_version: Option<String>,
    pub capabilities: Vec<String>,
    pub native_vlan: Option<u16>,
    pub duplex: Option<String>,
    pub management_addresses: Vec<String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    fn ctx() -> PacketContext {
        PacketContext {
            src_mac: [0; 6],
            dst_mac: [0x01, 0x00, 0x0C, 0xCC, 0xCC, 0xCC],
            src_ip: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            dst_ip: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            src_port: 0,
            dst_port: 0,
            vlan_id: None,
            timestamp: 0,
        }
    }

    fn push_tlv(pkt: &mut Vec<u8>, tlv_type: u16, value: &[u8]) {
        let len = (value.len() + 4) as u16;
        pkt.extend_from_slice(&tlv_type.to_be_bytes());
        pkt.extend_from_slice(&len.to_be_bytes());
        pkt.extend_from_slice(value);
    }

    fn build_cdp_payload() -> Vec<u8> {
        let mut pkt = vec![0x02, 0xB4, 0x00, 0x00]; // version 2, TTL 180, checksum ignored

        push_tlv(&mut pkt, 0x0001, b"dist-sw-01");
        push_tlv(&mut pkt, 0x0003, b"GigabitEthernet1/0/24");
        push_tlv(&mut pkt, 0x0004, &0x0000_0009u32.to_be_bytes());
        push_tlv(&mut pkt, 0x0005, b"Cisco IOS XE Software, Version 17.9.3");
        push_tlv(&mut pkt, 0x0006, b"Catalyst 9300");
        push_tlv(&mut pkt, 0x000a, &20u16.to_be_bytes());
        push_tlv(&mut pkt, 0x000b, &[1]);
        pkt
    }

    #[test]
    fn parses_core_cdp_enrichment_fields() {
        let dissector = CdpDissector;
        let pkt = build_cdp_payload();
        assert!(dissector.can_parse(&pkt, 0, 0));

        let fields = dissector.parse_fields(&pkt).expect("cdp fields");
        assert_eq!(fields.device_id, "dist-sw-01");
        assert_eq!(fields.port_id, "GigabitEthernet1/0/24");
        assert_eq!(fields.platform.as_deref(), Some("Catalyst 9300"));
        assert_eq!(
            fields.software_version.as_deref(),
            Some("Cisco IOS XE Software, Version 17.9.3")
        );
        assert_eq!(
            fields.capabilities,
            vec!["router".to_string(), "switch".to_string()]
        );
        assert_eq!(fields.native_vlan, Some(20));
        assert_eq!(fields.duplex.as_deref(), Some("full"));
    }

    #[test]
    fn rejects_short_or_port_bound_frames() {
        let dissector = CdpDissector;
        assert!(!dissector.can_parse(&[0x02, 0x01, 0x00], 0, 0));
        assert!(!dissector.can_parse(&build_cdp_payload(), 1000, 0));
        assert!(!dissector.can_parse(&build_cdp_payload(), 0, 1000));
    }

    #[test]
    fn ignores_missing_device_id() {
        let dissector = CdpDissector;
        let mut pkt = vec![0x02, 0xB4, 0x00, 0x00];
        push_tlv(&mut pkt, 0x0003, b"Gi1/0/1");
        assert!(dissector.parse_fields(&pkt).is_none());
    }

    #[test]
    fn trait_parse_returns_cdp_variant() {
        let dissector = CdpDissector;
        let pkt = build_cdp_payload();
        assert!(matches!(
            dissector.parse(&pkt, &ctx()),
            Some(ProtocolData::Cdp(_))
        ));
    }
}
