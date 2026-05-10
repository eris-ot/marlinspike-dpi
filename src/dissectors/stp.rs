//! STP dissector — enrichment-first parsing for spanning tree BPDUs.

use crate::registry::{PacketContext, ProtocolData, ProtocolDissector};

#[derive(Default)]
pub struct StpDissector;

impl StpDissector {
    pub fn parse_fields(&self, data: &[u8]) -> Option<StpFields> {
        // Configuration / RSTP BPDUs require at least the common 35-byte body.
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
        let _message_age = u16::from_be_bytes([data[27], data[28]]);
        let max_age = u16::from_be_bytes([data[29], data[30]]);
        let hello_time = u16::from_be_bytes([data[31], data[32]]);
        let forward_delay = u16::from_be_bytes([data[33], data[34]]);

        Some(StpFields {
            protocol_version,
            bpdu_type,
            flags,
            root_id,
            root_path_cost,
            bridge_id,
            port_id,
            hello_time,
            max_age,
            forward_delay,
        })
    }
}

impl ProtocolDissector for StpDissector {
    fn name(&self) -> &str {
        "stp"
    }

    fn can_parse(&self, data: &[u8], src_port: u16, dst_port: u16) -> bool {
        if src_port != 0 || dst_port != 0 {
            return false;
        }
        data.len() >= 35 && u16::from_be_bytes([data[0], data[1]]) == 0x0000
    }

    fn parse(&self, data: &[u8], _context: &PacketContext) -> Option<ProtocolData> {
        Some(ProtocolData::Stp(self.parse_fields(data)?))
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

#[derive(Debug, Clone)]
pub struct StpFields {
    pub protocol_version: u8,
    pub bpdu_type: u8,
    pub flags: u8,
    pub root_id: String,
    pub root_path_cost: u32,
    pub bridge_id: String,
    pub port_id: u16,
    pub hello_time: u16,
    pub max_age: u16,
    pub forward_delay: u16,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    fn ctx() -> PacketContext {
        PacketContext {
            src_mac: [0; 6],
            dst_mac: [0x01, 0x80, 0xC2, 0x00, 0x00, 0x00],
            src_ip: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            dst_ip: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            src_port: 0,
            dst_port: 0,
            vlan_id: None,
            timestamp: 0,
        }
    }

    fn build_stp_bpdu() -> Vec<u8> {
        let mut pkt = Vec::new();

        pkt.extend_from_slice(&0x0000u16.to_be_bytes()); // protocol identifier
        pkt.push(0x02); // protocol version
        pkt.push(0x00); // bpdu type: configuration
        pkt.push(0x01); // flags

        // root id: priority 0x8000 + root MAC
        pkt.extend_from_slice(&[0x80, 0x00, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
        pkt.extend_from_slice(&0x0000_0A0Bu32.to_be_bytes()); // root path cost
        // bridge id: priority 0x8000 + bridge MAC
        pkt.extend_from_slice(&[0x80, 0x00, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB]);
        pkt.extend_from_slice(&0x8001u16.to_be_bytes()); // port id

        // message age, max age, hello time, forward delay
        pkt.extend_from_slice(&0x0100u16.to_be_bytes());
        pkt.extend_from_slice(&0x1400u16.to_be_bytes());
        pkt.extend_from_slice(&0x0200u16.to_be_bytes());
        pkt.extend_from_slice(&0x0F00u16.to_be_bytes());

        pkt
    }

    #[test]
    fn parses_stp_enrichment_fields() {
        let dissector = StpDissector;
        let pkt = build_stp_bpdu();
        assert!(dissector.can_parse(&pkt, 0, 0));

        let fields = dissector.parse_fields(&pkt).expect("stp fields");
        assert_eq!(fields.protocol_version, 0x02);
        assert_eq!(fields.bpdu_type, 0x00);
        assert_eq!(fields.flags, 0x01);
        assert_eq!(fields.root_id, "32768/00:11:22:33:44:55");
        assert_eq!(fields.root_path_cost, 0x0000_0A0B);
        assert_eq!(fields.bridge_id, "32768/66:77:88:99:aa:bb");
        assert_eq!(fields.port_id, 0x8001);
        assert_eq!(fields.max_age, 0x1400);
    }

    #[test]
    fn rejects_short_or_port_bound_frames() {
        let dissector = StpDissector;
        assert!(!dissector.can_parse(&[0x00, 0x00, 0x00], 0, 0));
        assert!(!dissector.can_parse(&build_stp_bpdu(), 1, 0));
        assert!(!dissector.can_parse(&build_stp_bpdu(), 0, 1));
    }

    #[test]
    fn trait_parse_returns_stp_variant() {
        let dissector = StpDissector;
        let pkt = build_stp_bpdu();
        assert!(matches!(
            dissector.parse(&pkt, &ctx()),
            Some(ProtocolData::Stp(_))
        ));
    }
}
