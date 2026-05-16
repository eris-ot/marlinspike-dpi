//! VTP dissector — Cisco VLAN Trunking Protocol.
//!
//! SNAP OUI 00:00:0C, PID 0x2003. Extracts domain name, revision, and VLAN list.

use crate::registry::{PacketContext, ProtocolData, ProtocolDissector};

#[derive(Default)]
pub struct VtpDissector;

fn message_type_name(code: u8) -> &'static str {
    match code {
        0x01 => "summary_advertisement",
        0x02 => "subset_advertisement",
        0x03 => "advertisement_request",
        0x04 => "join",
        _ => "unknown",
    }
}

impl VtpDissector {
    pub fn parse_fields(&self, data: &[u8]) -> Option<VtpFields> {
        // Minimum: version(1) + code(1) + followers_or_seq(1) + domain_len(1) + domain(32)
        if data.len() < 36 {
            return None;
        }

        let version = data[0];
        if !matches!(version, 1..=3) {
            return None;
        }
        let code = data[1];
        let domain_name_length = data[3] as usize;
        if domain_name_length > 32 {
            return None;
        }

        let domain_name = String::from_utf8_lossy(&data[4..4 + domain_name_length])
            .trim_end_matches('\0')
            .to_string();

        let mut revision = None;
        let mut vlans = Vec::new();

        match code {
            0x01 => {
                // Summary: after domain(32), revision(4), updater_identity(4), update_timestamp(12), md5(16)
                if data.len() >= 40 {
                    revision = Some(u32::from_be_bytes([data[36], data[37], data[38], data[39]]));
                }
            }
            0x02 => {
                // Subset: after domain(32), revision(4), then VLAN info entries.
                if data.len() >= 40 {
                    revision = Some(u32::from_be_bytes([data[36], data[37], data[38], data[39]]));
                }
                let mut offset = 40;
                while offset + 4 <= data.len() {
                    let entry_len = data[offset] as usize;
                    if entry_len < 4 || offset + entry_len > data.len() {
                        break;
                    }
                    if offset + 6 <= data.len() {
                        let vlan_id = u16::from_be_bytes([data[offset + 2], data[offset + 3]]);
                        vlans.push(vlan_id);
                    }
                    offset += entry_len;
                }
            }
            _ => {}
        }

        Some(VtpFields {
            version,
            message_type: code,
            message_type_name: message_type_name(code).to_string(),
            domain_name,
            revision,
            vlans,
        })
    }
}

impl ProtocolDissector for VtpDissector {
    fn name(&self) -> &str {
        "vtp"
    }

    fn can_parse(&self, data: &[u8], src_port: u16, dst_port: u16) -> bool {
        if src_port != 0 || dst_port != 0 {
            return false;
        }
        data.len() >= 36 && matches!(data[0], 1..=3)
    }

    fn parse(&self, data: &[u8], _context: &PacketContext) -> Option<ProtocolData> {
        Some(ProtocolData::Vtp(self.parse_fields(data)?))
    }
}

#[derive(Debug, Clone)]
pub struct VtpFields {
    pub version: u8,
    pub message_type: u8,
    pub message_type_name: String,
    pub domain_name: String,
    pub revision: Option<u32>,
    pub vlans: Vec<u16>,
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

    fn build_summary() -> Vec<u8> {
        let mut pkt = vec![0u8; 40];
        pkt[0] = 1; // version
        pkt[1] = 0x01; // summary
        pkt[3] = 7; // domain name length
        pkt[4..11].copy_from_slice(b"FACTORY");
        // revision = 42
        pkt[36..40].copy_from_slice(&42u32.to_be_bytes());
        pkt
    }

    #[test]
    fn parses_summary_advertisement() {
        let dissector = VtpDissector;
        let pkt = build_summary();
        let fields = dissector.parse_fields(&pkt).expect("vtp fields");
        assert_eq!(fields.version, 1);
        assert_eq!(fields.message_type_name, "summary_advertisement");
        assert_eq!(fields.domain_name, "FACTORY");
        assert_eq!(fields.revision, Some(42));
    }

    #[test]
    fn rejects_port_bound() {
        let dissector = VtpDissector;
        assert!(!dissector.can_parse(&build_summary(), 80, 0));
    }

    #[test]
    fn trait_parse_returns_vtp_variant() {
        let dissector = VtpDissector;
        assert!(matches!(
            dissector.parse(&build_summary(), &ctx()),
            Some(ProtocolData::Vtp(_))
        ));
    }
}
