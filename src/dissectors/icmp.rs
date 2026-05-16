//! ICMP dissector — parses ICMP messages (IP protocol 1).
//!
//! Extracts type, code, and type-specific fields from ICMP headers.
//! Works alongside the stovetop ICMP anomaly detector: this dissector
//! provides protocol visibility (ProtocolTransaction / AssetObservation),
//! while stovetop flags malicious usage patterns.

use crate::registry::{PacketContext, ProtocolData, ProtocolDissector};

#[derive(Debug, Clone)]
pub struct IcmpFields {
    pub icmp_type: u8,
    pub icmp_code: u8,
    pub checksum: u16,
    pub type_name: String,
    pub code_name: String,
    pub identifier: Option<u16>,
    pub sequence: Option<u16>,
    pub gateway_ip: Option<String>,
    pub payload_len: usize,
}

#[derive(Default)]
pub struct IcmpDissector;

impl ProtocolDissector for IcmpDissector {
    fn name(&self) -> &str {
        "icmp"
    }

    /// ICMP is identified by IP protocol number, not ports. The engine
    /// passes ICMP packets with src_port=0, dst_port=0.
    fn can_parse(&self, data: &[u8], _src_port: u16, _dst_port: u16) -> bool {
        data.len() >= 4
    }

    fn parse(&self, data: &[u8], _context: &PacketContext) -> Option<ProtocolData> {
        if data.len() < 4 {
            return None;
        }

        let icmp_type = data[0];
        let icmp_code = data[1];
        let checksum = u16::from_be_bytes([data[2], data[3]]);

        let type_name = icmp_type_name(icmp_type).to_string();
        let code_name = icmp_code_name(icmp_type, icmp_code).to_string();

        // Type-specific parsing
        let (id, sequence, gateway_ip, payload_len) = match icmp_type {
            // Echo Reply / Echo Request: id(2) + seq(2) + data
            0 | 8 => {
                if data.len() >= 8 {
                    let id = u16::from_be_bytes([data[4], data[5]]);
                    let seq = u16::from_be_bytes([data[6], data[7]]);
                    let payload_len = data.len().saturating_sub(8);
                    (Some(id), Some(seq), None, payload_len)
                } else {
                    (None, None, None, 0)
                }
            }
            // Redirect: gateway IP(4) + original datagram header
            5 => {
                let gw = if data.len() >= 8 {
                    Some(format!("{}.{}.{}.{}", data[4], data[5], data[6], data[7]))
                } else {
                    None
                };
                (None, None, gw, data.len().saturating_sub(8))
            }
            // Destination Unreachable, Time Exceeded, Source Quench:
            // unused(4) + original datagram header
            3 | 4 | 11 => (None, None, None, data.len().saturating_sub(8)),
            // Timestamp Request/Reply: id(2) + seq(2) + timestamps(12)
            13 | 14 => {
                if data.len() >= 8 {
                    let id = u16::from_be_bytes([data[4], data[5]]);
                    let seq = u16::from_be_bytes([data[6], data[7]]);
                    (Some(id), Some(seq), None, data.len().saturating_sub(8))
                } else {
                    (None, None, None, 0)
                }
            }
            // Router Advertisement: num_addrs(1) + addr_entry_size(1) + lifetime(2) + entries
            9 => (None, None, None, data.len().saturating_sub(8)),
            _ => (None, None, None, data.len().saturating_sub(4)),
        };

        Some(ProtocolData::Icmp(IcmpFields {
            icmp_type,
            icmp_code,
            checksum,
            type_name,
            code_name,
            identifier: id,
            sequence,
            gateway_ip,
            payload_len,
        }))
    }
}

fn icmp_type_name(icmp_type: u8) -> &'static str {
    match icmp_type {
        0 => "Echo Reply",
        3 => "Destination Unreachable",
        4 => "Source Quench",
        5 => "Redirect",
        8 => "Echo Request",
        9 => "Router Advertisement",
        10 => "Router Solicitation",
        11 => "Time Exceeded",
        12 => "Parameter Problem",
        13 => "Timestamp Request",
        14 => "Timestamp Reply",
        17 => "Address Mask Request",
        18 => "Address Mask Reply",
        30 => "Traceroute",
        _ => "Unknown",
    }
}

fn icmp_code_name(icmp_type: u8, code: u8) -> &'static str {
    match icmp_type {
        3 => match code {
            0 => "Network Unreachable",
            1 => "Host Unreachable",
            2 => "Protocol Unreachable",
            3 => "Port Unreachable",
            4 => "Fragmentation Needed",
            5 => "Source Route Failed",
            6 => "Destination Network Unknown",
            7 => "Destination Host Unknown",
            9 => "Network Administratively Prohibited",
            10 => "Host Administratively Prohibited",
            13 => "Communication Administratively Prohibited",
            _ => "",
        },
        5 => match code {
            0 => "Redirect for Network",
            1 => "Redirect for Host",
            2 => "Redirect for ToS and Network",
            3 => "Redirect for ToS and Host",
            _ => "",
        },
        11 => match code {
            0 => "TTL Exceeded in Transit",
            1 => "Fragment Reassembly Time Exceeded",
            _ => "",
        },
        _ => "",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    fn ctx() -> PacketContext {
        PacketContext {
            src_mac: [0; 6],
            dst_mac: [0; 6],
            src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            dst_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            src_port: 0,
            dst_port: 0,
            vlan_id: None,
            timestamp: 0,
        }
    }

    #[test]
    fn parse_echo_request() {
        let d = IcmpDissector;
        // Type 8 (echo request), code 0, checksum, id=1, seq=1, 4 bytes payload
        let data = vec![8, 0, 0x12, 0x34, 0, 1, 0, 1, 0xAA, 0xBB, 0xCC, 0xDD];
        assert!(d.can_parse(&data, 0, 0));
        let result = d.parse(&data, &ctx()).unwrap();
        match result {
            ProtocolData::Icmp(fields) => {
                assert_eq!(fields.icmp_type, 8);
                assert_eq!(fields.icmp_code, 0);
                assert_eq!(fields.type_name, "Echo Request");
                assert_eq!(fields.identifier, Some(1));
                assert_eq!(fields.sequence, Some(1));
                assert_eq!(fields.payload_len, 4);
            }
            _ => panic!("expected ICMP"),
        }
    }

    #[test]
    fn parse_echo_reply() {
        let d = IcmpDissector;
        let data = vec![0, 0, 0, 0, 0, 42, 0, 7];
        let result = d.parse(&data, &ctx()).unwrap();
        match result {
            ProtocolData::Icmp(fields) => {
                assert_eq!(fields.icmp_type, 0);
                assert_eq!(fields.type_name, "Echo Reply");
                assert_eq!(fields.identifier, Some(42));
                assert_eq!(fields.sequence, Some(7));
            }
            _ => panic!("expected ICMP"),
        }
    }

    #[test]
    fn parse_redirect() {
        let d = IcmpDissector;
        // Type 5, code 1 (redirect for host), checksum, gateway 192.168.1.1
        let data = vec![5, 1, 0, 0, 192, 168, 1, 1, 0x45, 0x00]; // + original datagram
        let result = d.parse(&data, &ctx()).unwrap();
        match result {
            ProtocolData::Icmp(fields) => {
                assert_eq!(fields.icmp_type, 5);
                assert_eq!(fields.code_name, "Redirect for Host");
                assert_eq!(fields.gateway_ip.as_deref(), Some("192.168.1.1"));
            }
            _ => panic!("expected ICMP"),
        }
    }

    #[test]
    fn parse_dest_unreachable() {
        let d = IcmpDissector;
        let data = vec![3, 3, 0, 0, 0, 0, 0, 0]; // port unreachable
        let result = d.parse(&data, &ctx()).unwrap();
        match result {
            ProtocolData::Icmp(fields) => {
                assert_eq!(fields.icmp_type, 3);
                assert_eq!(fields.code_name, "Port Unreachable");
                assert_eq!(fields.type_name, "Destination Unreachable");
            }
            _ => panic!("expected ICMP"),
        }
    }

    #[test]
    fn parse_timestamp_request() {
        let d = IcmpDissector;
        let data = vec![13, 0, 0, 0, 0, 1, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        let result = d.parse(&data, &ctx()).unwrap();
        match result {
            ProtocolData::Icmp(fields) => {
                assert_eq!(fields.icmp_type, 13);
                assert_eq!(fields.type_name, "Timestamp Request");
                assert_eq!(fields.identifier, Some(1));
                assert_eq!(fields.sequence, Some(1));
            }
            _ => panic!("expected ICMP"),
        }
    }

    #[test]
    fn too_short() {
        let d = IcmpDissector;
        assert!(!d.can_parse(&[8, 0, 0], 0, 0));
        assert!(d.parse(&[8, 0, 0], &ctx()).is_none());
    }
}
