//! RADIUS dissector — extracts authentication/accounting metadata from RADIUS packets.
//!
//! Parses the 20-byte header and key TLV attributes relevant for asset identification:
//! NAS-IP-Address, NAS-Identifier, User-Name, Calling-Station-Id, Called-Station-Id,
//! NAS-Port-Type, Service-Type, Framed-IP-Address.

use crate::registry::{PacketContext, ProtocolData, ProtocolDissector};

#[derive(Default)]
pub struct RadiusDissector;

fn code_name(code: u8) -> &'static str {
    match code {
        1 => "Access-Request",
        2 => "Access-Accept",
        3 => "Access-Reject",
        4 => "Accounting-Request",
        5 => "Accounting-Response",
        11 => "Access-Challenge",
        12 => "Status-Server",
        13 => "Status-Client",
        40 => "Disconnect-Request",
        41 => "Disconnect-ACK",
        42 => "Disconnect-NAK",
        43 => "CoA-Request",
        44 => "CoA-ACK",
        45 => "CoA-NAK",
        _ => "Unknown",
    }
}

fn format_ipv4(bytes: &[u8]) -> String {
    format!("{}.{}.{}.{}", bytes[0], bytes[1], bytes[2], bytes[3])
}

impl RadiusDissector {
    pub fn parse_fields(&self, data: &[u8]) -> Option<RadiusFields> {
        // RADIUS header: code(1) + identifier(1) + length(2) + authenticator(16) = 20 bytes.
        if data.len() < 20 {
            return None;
        }

        let code = data[0];
        let identifier = data[1];
        let length = u16::from_be_bytes([data[2], data[3]]) as usize;

        // Sanity: length must be 20..=4096 and not exceed available data.
        if length < 20 || length > 4096 || length > data.len() {
            return None;
        }

        let mut fields = RadiusFields {
            code,
            code_name: code_name(code).to_string(),
            identifier,
            username: None,
            nas_ip_address: None,
            nas_identifier: None,
            calling_station_id: None,
            called_station_id: None,
            nas_port_type: None,
            framed_ip_address: None,
            service_type: None,
        };

        // Parse attributes (TLV: type(1) + length(1) + value(length-2)).
        let mut offset = 20;
        while offset + 2 <= length {
            let attr_type = data[offset];
            let attr_len = data[offset + 1] as usize;
            if attr_len < 2 || offset + attr_len > length {
                break;
            }
            let value = &data[offset + 2..offset + attr_len];

            match attr_type {
                1 => {
                    // User-Name
                    fields.username = Some(String::from_utf8_lossy(value).to_string());
                }
                4 => {
                    // NAS-IP-Address
                    if value.len() == 4 {
                        fields.nas_ip_address = Some(format_ipv4(value));
                    }
                }
                6 => {
                    // Service-Type
                    if value.len() == 4 {
                        fields.service_type =
                            Some(u32::from_be_bytes([value[0], value[1], value[2], value[3]]));
                    }
                }
                8 => {
                    // Framed-IP-Address
                    if value.len() == 4 {
                        fields.framed_ip_address = Some(format_ipv4(value));
                    }
                }
                30 => {
                    // Called-Station-Id
                    fields.called_station_id =
                        Some(String::from_utf8_lossy(value).to_string());
                }
                31 => {
                    // Calling-Station-Id
                    fields.calling_station_id =
                        Some(String::from_utf8_lossy(value).to_string());
                }
                32 => {
                    // NAS-Identifier
                    fields.nas_identifier =
                        Some(String::from_utf8_lossy(value).to_string());
                }
                61 => {
                    // NAS-Port-Type
                    if value.len() == 4 {
                        fields.nas_port_type =
                            Some(u32::from_be_bytes([value[0], value[1], value[2], value[3]]));
                    }
                }
                _ => {}
            }

            offset += attr_len;
        }

        Some(fields)
    }
}

impl ProtocolDissector for RadiusDissector {
    fn name(&self) -> &str {
        "radius"
    }

    fn can_parse(&self, data: &[u8], src_port: u16, dst_port: u16) -> bool {
        if !matches!(src_port, 1812 | 1813) && !matches!(dst_port, 1812 | 1813) {
            return false;
        }
        if data.len() < 20 {
            return false;
        }
        // Validate code is a known RADIUS type.
        matches!(data[0], 1..=5 | 11..=13 | 40..=45)
    }

    fn parse(&self, data: &[u8], _context: &PacketContext) -> Option<ProtocolData> {
        Some(ProtocolData::Radius(self.parse_fields(data)?))
    }
}

#[derive(Debug, Clone)]
pub struct RadiusFields {
    pub code: u8,
    pub code_name: String,
    pub identifier: u8,
    pub username: Option<String>,
    pub nas_ip_address: Option<String>,
    pub nas_identifier: Option<String>,
    pub calling_station_id: Option<String>,
    pub called_station_id: Option<String>,
    pub nas_port_type: Option<u32>,
    pub framed_ip_address: Option<String>,
    pub service_type: Option<u32>,
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
            src_port: 12345,
            dst_port: 1812,
            vlan_id: None,
            timestamp: 0,
        }
    }

    fn build_access_request() -> Vec<u8> {
        let mut pkt = vec![0u8; 20];
        pkt[0] = 1; // Access-Request
        pkt[1] = 42; // identifier

        // Attributes
        let mut attrs = Vec::new();

        // User-Name = "operator"
        let user = b"operator";
        attrs.push(1u8); // type
        attrs.push((2 + user.len()) as u8); // length
        attrs.extend_from_slice(user);

        // NAS-IP-Address = 10.0.0.1
        attrs.push(4);
        attrs.push(6);
        attrs.extend_from_slice(&[10, 0, 0, 1]);

        // NAS-Identifier = "switch-core-01"
        let nas_id = b"switch-core-01";
        attrs.push(32);
        attrs.push((2 + nas_id.len()) as u8);
        attrs.extend_from_slice(nas_id);

        let total_len = 20 + attrs.len();
        pkt[2] = (total_len >> 8) as u8;
        pkt[3] = total_len as u8;
        pkt.extend_from_slice(&attrs);
        pkt
    }

    #[test]
    fn parses_access_request() {
        let dissector = RadiusDissector;
        let pkt = build_access_request();
        assert!(dissector.can_parse(&pkt, 12345, 1812));

        let fields = dissector.parse_fields(&pkt).expect("radius fields");
        assert_eq!(fields.code, 1);
        assert_eq!(fields.code_name, "Access-Request");
        assert_eq!(fields.identifier, 42);
        assert_eq!(fields.username.as_deref(), Some("operator"));
        assert_eq!(fields.nas_ip_address.as_deref(), Some("10.0.0.1"));
        assert_eq!(fields.nas_identifier.as_deref(), Some("switch-core-01"));
    }

    #[test]
    fn rejects_short_packet() {
        let dissector = RadiusDissector;
        assert!(!dissector.can_parse(&[0u8; 10], 12345, 1812));
    }

    #[test]
    fn rejects_wrong_port() {
        let dissector = RadiusDissector;
        let pkt = build_access_request();
        assert!(!dissector.can_parse(&pkt, 80, 80));
    }

    #[test]
    fn rejects_invalid_code() {
        let dissector = RadiusDissector;
        let mut pkt = build_access_request();
        pkt[0] = 0; // invalid code
        assert!(!dissector.can_parse(&pkt, 12345, 1812));
    }

    #[test]
    fn trait_parse_returns_radius_variant() {
        let dissector = RadiusDissector;
        let pkt = build_access_request();
        assert!(matches!(
            dissector.parse(&pkt, &ctx()),
            Some(ProtocolData::Radius(_))
        ));
    }
}
