//! HTTP dissector — parses HTTP/1.x request and response first lines.

use crate::registry::{PacketContext, ProtocolData, ProtocolDissector};

#[derive(Default)]
pub struct HttpDissector;

const HTTP_PORT: u16 = 80;
const HTTP_ALT_PORT: u16 = 8080;

impl ProtocolDissector for HttpDissector {
    fn name(&self) -> &str {
        "http"
    }

    fn can_parse(&self, data: &[u8], src_port: u16, dst_port: u16) -> bool {
        if src_port != HTTP_PORT
            && dst_port != HTTP_PORT
            && src_port != HTTP_ALT_PORT
            && dst_port != HTTP_ALT_PORT
        {
            return false;
        }
        // Quick heuristic: check for known HTTP methods or "HTTP/" response prefix.
        if data.len() < 4 {
            return false;
        }
        let prefix = &data[..4];
        matches!(
            prefix,
            b"GET " | b"POST" | b"PUT " | b"DELE" | b"HEAD" | b"OPTI" | b"PATC" | b"HTTP"
        )
    }

    fn parse(&self, data: &[u8], _context: &PacketContext) -> Option<ProtocolData> {
        let text = std::str::from_utf8(data).ok()?;
        let first_line = text.lines().next()?;

        if first_line.starts_with("HTTP/") {
            // Response: "HTTP/1.1 200 OK"
            let mut parts = first_line.splitn(3, ' ');
            let _version = parts.next()?;
            let status_str = parts.next()?;
            let status_code = status_str.parse::<u16>().ok()?;

            // Try to find Content-Type and Content-Length headers.
            let content_type = find_header(text, "Content-Type").unwrap_or_default();
            let content_length = find_header(text, "Content-Length")
                .and_then(|v| v.parse::<u64>().ok())
                .unwrap_or(0);

            Some(ProtocolData::Http(HttpFields {
                method: String::new(),
                host: String::new(),
                uri: String::new(),
                status_code,
                content_type,
                content_length,
            }))
        } else {
            // Request: "GET /path HTTP/1.1"
            let mut parts = first_line.splitn(3, ' ');
            let method = parts.next()?.to_string();
            let uri = parts.next()?.to_string();
            let host = find_header(text, "Host").unwrap_or_default();

            let content_type = find_header(text, "Content-Type").unwrap_or_default();
            let content_length = find_header(text, "Content-Length")
                .and_then(|v| v.parse::<u64>().ok())
                .unwrap_or(0);

            Some(ProtocolData::Http(HttpFields {
                method,
                host,
                uri,
                status_code: 0,
                content_type,
                content_length,
            }))
        }
    }
}

fn find_header(text: &str, name: &str) -> Option<String> {
    for line in text.lines() {
        if let Some(value) = line.strip_prefix(name)
            && let Some(value) = value.strip_prefix(':')
        {
            return Some(value.trim().to_string());
        }
    }
    None
}

#[derive(Debug, Clone)]
pub struct HttpFields {
    pub method: String,
    pub host: String,
    pub uri: String,
    pub status_code: u16,
    pub content_type: String,
    pub content_length: u64,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    fn ctx(src_port: u16, dst_port: u16) -> PacketContext {
        PacketContext {
            src_mac: [0; 6],
            dst_mac: [0; 6],
            src_ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
            dst_ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
            src_port,
            dst_port,
            vlan_id: None,
            timestamp: 0,
        }
    }

    #[test]
    fn test_parse_http_request() {
        let data = b"GET /api/v1/status HTTP/1.1\r\nHost: example.com\r\n\r\n";
        let d = HttpDissector;
        assert!(d.can_parse(data, 49152, 80));

        let result = d.parse(data, &ctx(49152, 80)).unwrap();
        match result {
            ProtocolData::Http(h) => {
                assert_eq!(h.method, "GET");
                assert_eq!(h.host, "example.com");
                assert_eq!(h.uri, "/api/v1/status");
                assert_eq!(h.status_code, 0);
            }
            _ => panic!("expected HTTP"),
        }
    }

    #[test]
    fn test_parse_http_response() {
        let data =
            b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 42\r\n\r\n";
        let d = HttpDissector;
        assert!(d.can_parse(data, 80, 49152));

        let result = d.parse(data, &ctx(80, 49152)).unwrap();
        match result {
            ProtocolData::Http(h) => {
                assert_eq!(h.status_code, 200);
                assert!(h.host.is_empty());
                assert_eq!(h.content_type, "application/json");
                assert_eq!(h.content_length, 42);
            }
            _ => panic!("expected HTTP"),
        }
    }
}
