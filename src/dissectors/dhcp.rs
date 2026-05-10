//! DHCP dissector focused on enrichment-first BOOTP/DHCP option extraction.

use crate::registry::{PacketContext, ProtocolData, ProtocolDissector};

#[derive(Default)]
pub struct DhcpDissector;

const DHCP_CLIENT_PORT: u16 = 68;
const DHCP_SERVER_PORT: u16 = 67;
const DHCP_MAGIC_COOKIE: [u8; 4] = [0x63, 0x82, 0x53, 0x63];

impl ProtocolDissector for DhcpDissector {
    fn name(&self) -> &str {
        "dhcp"
    }

    fn can_parse(&self, data: &[u8], src_port: u16, dst_port: u16) -> bool {
        if src_port != DHCP_CLIENT_PORT
            && src_port != DHCP_SERVER_PORT
            && dst_port != DHCP_CLIENT_PORT
            && dst_port != DHCP_SERVER_PORT
        {
            return false;
        }
        data.len() >= 240 && data.get(236..240) == Some(&DHCP_MAGIC_COOKIE)
    }

    fn parse(&self, data: &[u8], _context: &PacketContext) -> Option<ProtocolData> {
        Some(ProtocolData::Dhcp(parse_dhcp(data)?))
    }
}

fn parse_dhcp(data: &[u8]) -> Option<DhcpFields> {
    if data.len() < 240 || data.get(236..240) != Some(&DHCP_MAGIC_COOKIE) {
        return None;
    }

    let op = data[0];
    let hlen = data[2].min(16);
    let xid = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);
    let ciaddr = optional_ipv4(&data[12..16])?;
    let yiaddr = optional_ipv4(&data[16..20])?;
    let siaddr = optional_ipv4(&data[20..24])?;
    let giaddr = optional_ipv4(&data[24..28])?;

    let mut client_mac = [0u8; 6];
    let mac_len = usize::min(hlen as usize, client_mac.len());
    client_mac[..mac_len].copy_from_slice(&data[28..28 + mac_len]);

    let mut hostname = None;
    let mut client_id = None;
    let mut vendor_class = None;
    let mut message_type = None;
    let mut server_id = None;
    let mut requested_ip = None;

    let mut offset = 240;
    while offset < data.len() {
        let code = data[offset];
        offset += 1;

        match code {
            0 => continue,
            255 => break,
            _ => {
                if offset >= data.len() {
                    return None;
                }
                let len = data[offset] as usize;
                offset += 1;
                if offset + len > data.len() {
                    return None;
                }
                let value = &data[offset..offset + len];

                match code {
                    12 => hostname = Some(lossy_string(value)),
                    50 => requested_ip = ipv4_from_bytes(value),
                    53 => message_type = value.first().copied(),
                    54 => server_id = ipv4_from_bytes(value),
                    60 => vendor_class = Some(lossy_string(value)),
                    61 => client_id = Some(format_client_id(value)),
                    _ => {}
                }

                offset += len;
            }
        }
    }

    Some(DhcpFields {
        op,
        xid,
        client_mac,
        ciaddr,
        yiaddr,
        siaddr,
        giaddr,
        message_type,
        hostname,
        client_id,
        vendor_class,
        requested_ip,
        server_id,
    })
}

fn format_ipv4(bytes: &[u8; 4]) -> String {
    format!("{}.{}.{}.{}", bytes[0], bytes[1], bytes[2], bytes[3])
}

fn ipv4_from_bytes(bytes: &[u8]) -> Option<String> {
    let arr: [u8; 4] = bytes.try_into().ok()?;
    Some(format_ipv4(&arr))
}

fn optional_ipv4(bytes: &[u8]) -> Option<Option<String>> {
    let value = ipv4_from_bytes(bytes)?;
    if value == "0.0.0.0" {
        Some(None)
    } else {
        Some(Some(value))
    }
}

fn lossy_string(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes)
        .trim_matches(char::from(0))
        .trim()
        .to_string()
}

fn format_client_id(bytes: &[u8]) -> String {
    if bytes.is_empty() {
        return String::new();
    }

    if bytes.iter().all(|b| b.is_ascii_graphic() || *b == b' ') {
        return lossy_string(bytes);
    }

    bytes
        .iter()
        .map(|b| format!("{:02x}", b))
        .collect::<Vec<_>>()
        .join(":")
}

#[derive(Debug, Clone)]
pub struct DhcpFields {
    pub op: u8,
    pub xid: u32,
    pub client_mac: [u8; 6],
    pub ciaddr: Option<String>,
    pub yiaddr: Option<String>,
    pub siaddr: Option<String>,
    pub giaddr: Option<String>,
    pub message_type: Option<u8>,
    pub hostname: Option<String>,
    pub client_id: Option<String>,
    pub vendor_class: Option<String>,
    pub requested_ip: Option<String>,
    pub server_id: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::registry::PacketContext;
    use std::net::{IpAddr, Ipv4Addr};

    fn ctx(src_port: u16, dst_port: u16) -> PacketContext {
        PacketContext {
            src_mac: [0; 6],
            dst_mac: [0; 6],
            src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 10)),
            dst_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            src_port,
            dst_port,
            vlan_id: None,
            timestamp: 0,
        }
    }

    fn build_dhcp_packet() -> Vec<u8> {
        let mut data = vec![0u8; 240];
        data[0] = 1;
        data[1] = 1;
        data[2] = 6;
        data[3] = 2;
        data[4..8].copy_from_slice(&0x3903_f326u32.to_be_bytes());
        data[8..10].copy_from_slice(&300u16.to_be_bytes());
        data[10..12].copy_from_slice(&0x8000u16.to_be_bytes());
        data[12..16].copy_from_slice(&[0, 0, 0, 0]);
        data[16..20].copy_from_slice(&[10, 0, 0, 42]);
        data[20..24].copy_from_slice(&[10, 0, 0, 1]);
        data[24..28].copy_from_slice(&[10, 0, 0, 254]);
        data[28..34].copy_from_slice(&[0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
        data[236..240].copy_from_slice(&DHCP_MAGIC_COOKIE);

        data.extend_from_slice(&[
            53, 1, 1, 12, 8, b'c', b'l', b'i', b'e', b'n', b't', b'-', b'1', 61, 7, 1, 0x00, 0x11,
            0x22, 0x33, 0x44, 0x55, 60, 8, b'v', b'e', b'n', b'd', b'o', b'r', b'-', b'a', 50, 4,
            10, 0, 0, 42, 54, 4, 10, 0, 0, 1, 255,
        ]);

        data
    }

    #[test]
    fn can_parse_dhcp_ports_and_cookie() {
        let d = DhcpDissector;
        let data = build_dhcp_packet();
        assert!(d.can_parse(&data, 68, 67));
        assert!(d.can_parse(&data, 67, 68));
        assert!(!d.can_parse(&data, 1234, 5678));
    }

    #[test]
    fn parse_dhcp_enrichment_fields() {
        let fields = parse_dhcp(&build_dhcp_packet()).expect("dhcp fields");
        assert_eq!(fields.op, 1);
        assert_eq!(fields.xid, 0x3903_f326);
        assert_eq!(fields.ciaddr, None);
        assert_eq!(fields.yiaddr.as_deref(), Some("10.0.0.42"));
        assert_eq!(fields.siaddr.as_deref(), Some("10.0.0.1"));
        assert_eq!(fields.giaddr.as_deref(), Some("10.0.0.254"));
        assert_eq!(fields.client_mac, [0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
        assert_eq!(fields.hostname.as_deref(), Some("client-1"));
        assert_eq!(fields.client_id.as_deref(), Some("01:00:11:22:33:44:55"));
        assert_eq!(fields.vendor_class.as_deref(), Some("vendor-a"));
        assert_eq!(fields.message_type, Some(1));
        assert_eq!(fields.server_id.as_deref(), Some("10.0.0.1"));
        assert_eq!(fields.requested_ip.as_deref(), Some("10.0.0.42"));
    }

    #[test]
    fn parse_rejects_missing_cookie() {
        let mut data = build_dhcp_packet();
        data[236..240].copy_from_slice(&[0, 0, 0, 0]);
        assert!(parse_dhcp(&data).is_none());
    }

    #[test]
    fn trait_parse_returns_dhcp_variant() {
        let d = DhcpDissector;
        assert!(matches!(
            d.parse(&build_dhcp_packet(), &ctx(68, 67)),
            Some(ProtocolData::Dhcp(_))
        ));
    }
}
