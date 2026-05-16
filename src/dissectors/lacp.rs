//! LACP dissector — IEEE 802.3ad Link Aggregation Control Protocol.
//!
//! EtherType 0x8809 (Slow Protocols), subtype 0x01.
//! Extracts actor and partner system identity, port, key, and state flags.

use crate::registry::{PacketContext, ProtocolData, ProtocolDissector};

#[derive(Debug, Clone)]
pub struct LacpPartner {
    pub system_priority: u16,
    pub system: String,
    pub key: u16,
    pub port_priority: u16,
    pub port: u16,
    pub state: u8,
    pub state_flags: Vec<String>,
}

pub const SLOW_PROTOCOLS_ETHERTYPE: u16 = 0x8809;

#[derive(Default)]
pub struct LacpDissector;

fn state_flags(state: u8) -> Vec<String> {
    let names = [
        (0x01, "activity"),
        (0x02, "timeout"),
        (0x04, "aggregation"),
        (0x08, "synchronization"),
        (0x10, "collecting"),
        (0x20, "distributing"),
        (0x40, "defaulted"),
        (0x80, "expired"),
    ];
    names
        .iter()
        .filter(|(mask, _)| state & mask != 0)
        .map(|(_, name)| name.to_string())
        .collect()
}

fn format_mac(bytes: &[u8]) -> String {
    format!(
        "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5]
    )
}

fn parse_partner_tlv(data: &[u8]) -> Option<LacpPartner> {
    // TLV value (after type+length): system_priority(2) + system(6) + key(2) + port_priority(2) + port(2) + state(1) + reserved(3) = 18 bytes.
    if data.len() < 18 {
        return None;
    }
    Some(LacpPartner {
        system_priority: u16::from_be_bytes([data[0], data[1]]),
        system: format_mac(&data[2..8]),
        key: u16::from_be_bytes([data[8], data[9]]),
        port_priority: u16::from_be_bytes([data[10], data[11]]),
        port: u16::from_be_bytes([data[12], data[13]]),
        state: data[14],
        state_flags: state_flags(data[14]),
    })
}

impl LacpDissector {
    pub fn parse_fields(&self, data: &[u8]) -> Option<LacpFields> {
        // Minimum: subtype(1) + version(1) + actor_tlv(2+18) + partner_tlv(2+18) = 42.
        if data.len() < 42 {
            return None;
        }

        let subtype = data[0];
        if subtype != 0x01 {
            return None;
        }
        let version = data[1];

        // Actor TLV: type(1)=0x01, length(1)=0x14 (20), value(18), reserved area.
        let actor_type = data[2];
        let actor_len = data[3] as usize;
        if actor_type != 0x01 || actor_len < 20 {
            return None;
        }
        let actor = parse_partner_tlv(&data[4..])?;

        // Partner TLV: starts after actor (2 + actor_len).
        let partner_offset = 2 + actor_len;
        if partner_offset + 22 > data.len() {
            return None;
        }
        let partner_type = data[partner_offset];
        let partner_len = data[partner_offset + 1] as usize;
        if partner_type != 0x02 || partner_len < 20 {
            return None;
        }
        let partner = parse_partner_tlv(&data[partner_offset + 2..])?;

        // Collector TLV (optional): starts after partner.
        let mut max_delay = None;
        let collector_offset = partner_offset + 2 + partner_len;
        if collector_offset + 4 <= data.len() && data[collector_offset] == 0x03 {
            let coll_len = data[collector_offset + 1] as usize;
            if coll_len >= 4 && collector_offset + 2 + 2 <= data.len() {
                max_delay = Some(u16::from_be_bytes([
                    data[collector_offset + 2],
                    data[collector_offset + 3],
                ]));
            }
        }

        Some(LacpFields {
            version,
            actor,
            partner,
            max_delay,
        })
    }
}

impl ProtocolDissector for LacpDissector {
    fn name(&self) -> &str {
        "lacp"
    }

    fn can_parse(&self, data: &[u8], src_port: u16, dst_port: u16) -> bool {
        if src_port != 0 || dst_port != 0 {
            return false;
        }
        // Subtype 0x01 = LACP within Slow Protocols.
        data.len() >= 42 && data[0] == 0x01
    }

    fn parse(&self, data: &[u8], _context: &PacketContext) -> Option<ProtocolData> {
        Some(ProtocolData::Lacp(self.parse_fields(data)?))
    }
}

#[derive(Debug, Clone)]
pub struct LacpFields {
    pub version: u8,
    pub actor: LacpPartner,
    pub partner: LacpPartner,
    pub max_delay: Option<u16>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    fn ctx() -> PacketContext {
        PacketContext {
            src_mac: [0; 6],
            dst_mac: [0x01, 0x80, 0xC2, 0x00, 0x00, 0x02],
            src_ip: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            dst_ip: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            src_port: 0,
            dst_port: 0,
            vlan_id: None,
            timestamp: 0,
        }
    }

    fn build_lacp_pdu() -> Vec<u8> {
        let mut pkt = vec![0u8; 110];
        pkt[0] = 0x01; // subtype = LACP
        pkt[1] = 0x01; // version 1

        // Actor TLV: type=0x01, length=0x14
        pkt[2] = 0x01;
        pkt[3] = 0x14;
        // Actor system_priority=0x8000
        pkt[4..6].copy_from_slice(&0x8000u16.to_be_bytes());
        // Actor system MAC
        pkt[6..12].copy_from_slice(&[0x00, 0x1A, 0x2B, 0x3C, 0x4D, 0x5E]);
        // Actor key=100
        pkt[12..14].copy_from_slice(&100u16.to_be_bytes());
        // Actor port_priority=0x00FF
        pkt[14..16].copy_from_slice(&0x00FFu16.to_be_bytes());
        // Actor port=1
        pkt[16..18].copy_from_slice(&1u16.to_be_bytes());
        // Actor state: activity + aggregation + synchronization + collecting + distributing
        pkt[18] = 0x3D;

        // Partner TLV: type=0x02, length=0x14
        let po = 22; // 2 + 20
        pkt[po] = 0x02;
        pkt[po + 1] = 0x14;
        // Partner system_priority
        pkt[po + 2..po + 4].copy_from_slice(&0x8000u16.to_be_bytes());
        // Partner system MAC
        pkt[po + 4..po + 10].copy_from_slice(&[0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]);
        // Partner key=200
        pkt[po + 10..po + 12].copy_from_slice(&200u16.to_be_bytes());
        // Partner port_priority
        pkt[po + 12..po + 14].copy_from_slice(&0x00FFu16.to_be_bytes());
        // Partner port=2
        pkt[po + 14..po + 16].copy_from_slice(&2u16.to_be_bytes());
        // Partner state
        pkt[po + 16] = 0x3D;

        // Collector TLV: type=0x03, length=0x10
        let co = po + 22;
        pkt[co] = 0x03;
        pkt[co + 1] = 0x10;
        // max_delay=50
        pkt[co + 2..co + 4].copy_from_slice(&50u16.to_be_bytes());

        pkt
    }

    #[test]
    fn parses_lacp_pdu() {
        let dissector = LacpDissector;
        let pkt = build_lacp_pdu();
        assert!(dissector.can_parse(&pkt, 0, 0));

        let fields = dissector.parse_fields(&pkt).expect("lacp fields");
        assert_eq!(fields.version, 1);
        assert_eq!(fields.actor.system, "00:1a:2b:3c:4d:5e");
        assert_eq!(fields.actor.key, 100);
        assert_eq!(fields.actor.port, 1);
        assert!(fields.actor.state_flags.contains(&"activity".to_string()));
        assert!(
            fields
                .actor
                .state_flags
                .contains(&"synchronization".to_string())
        );

        assert_eq!(fields.partner.system, "aa:bb:cc:dd:ee:ff");
        assert_eq!(fields.partner.key, 200);
        assert_eq!(fields.partner.port, 2);

        assert_eq!(fields.max_delay, Some(50));
    }

    #[test]
    fn rejects_non_lacp_subtype() {
        let dissector = LacpDissector;
        let mut pkt = build_lacp_pdu();
        pkt[0] = 0x02; // Marker, not LACP
        assert!(!dissector.can_parse(&pkt, 0, 0));
    }

    #[test]
    fn trait_parse_returns_lacp_variant() {
        let dissector = LacpDissector;
        assert!(matches!(
            dissector.parse(&build_lacp_pdu(), &ctx()),
            Some(ProtocolData::Lacp(_))
        ));
    }
}
