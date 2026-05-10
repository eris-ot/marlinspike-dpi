//! SSH dissector — extracts version banner from SSH protocol identification string.
//!
//! SSH banners follow RFC 4253 §4.2: `SSH-protoversion-softwareversion SP comments`
//! This dissector only parses the initial banner exchange; encrypted traffic is opaque.

use crate::registry::{PacketContext, ProtocolData, ProtocolDissector};

#[derive(Default)]
pub struct SshDissector;

impl SshDissector {
    pub fn parse_fields(&self, data: &[u8]) -> Option<SshFields> {
        let text = std::str::from_utf8(data).ok()?;

        // Find the SSH banner line (may be preceded by pre-banner lines per RFC 4253).
        let line = text.lines().find(|l| l.starts_with("SSH-"))?;
        let banner = line.trim_end().to_string();

        // Parse: SSH-protoversion-softwareversion[ SP comments]
        let after_ssh = &banner[4..]; // skip "SSH-"
        let (proto_version, rest) = after_ssh.split_once('-')?;
        let (software_version, comments) = if let Some(space) = rest.find(' ') {
            (
                rest[..space].to_string(),
                Some(rest[space + 1..].to_string()),
            )
        } else {
            (rest.to_string(), None)
        };

        Some(SshFields {
            protocol_version: proto_version.to_string(),
            software_version,
            comments,
            banner,
        })
    }
}

impl ProtocolDissector for SshDissector {
    fn name(&self) -> &str {
        "ssh"
    }

    fn can_parse(&self, data: &[u8], src_port: u16, dst_port: u16) -> bool {
        if src_port != 22 && dst_port != 22 {
            return false;
        }
        // Look for "SSH-" prefix in the data.
        data.windows(4).any(|w| w == b"SSH-")
    }

    fn parse(&self, data: &[u8], _context: &PacketContext) -> Option<ProtocolData> {
        Some(ProtocolData::Ssh(self.parse_fields(data)?))
    }
}

#[derive(Debug, Clone)]
pub struct SshFields {
    pub protocol_version: String,
    pub software_version: String,
    pub comments: Option<String>,
    pub banner: String,
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
            src_port: 22,
            dst_port: 54321,
            vlan_id: None,
            timestamp: 0,
        }
    }

    #[test]
    fn parses_openssh_banner() {
        let dissector = SshDissector;
        let data = b"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6\r\n";
        let fields = dissector.parse_fields(data).expect("ssh fields");
        assert_eq!(fields.protocol_version, "2.0");
        assert_eq!(fields.software_version, "OpenSSH_8.9p1");
        assert_eq!(fields.comments.as_deref(), Some("Ubuntu-3ubuntu0.6"));
        assert_eq!(fields.banner, "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6");
    }

    #[test]
    fn parses_dropbear_banner() {
        let dissector = SshDissector;
        let data = b"SSH-2.0-dropbear_2022.83\r\n";
        let fields = dissector.parse_fields(data).expect("ssh fields");
        assert_eq!(fields.protocol_version, "2.0");
        assert_eq!(fields.software_version, "dropbear_2022.83");
        assert!(fields.comments.is_none());
    }

    #[test]
    fn handles_pre_banner_lines() {
        let dissector = SshDissector;
        let data = b"Welcome to device\r\nSSH-2.0-Cisco-1.25\r\n";
        let fields = dissector.parse_fields(data).expect("ssh fields");
        assert_eq!(fields.software_version, "Cisco-1.25");
    }

    #[test]
    fn rejects_wrong_port() {
        let dissector = SshDissector;
        assert!(!dissector.can_parse(b"SSH-2.0-test\r\n", 80, 80));
    }

    #[test]
    fn rejects_no_ssh_prefix() {
        let dissector = SshDissector;
        assert!(!dissector.can_parse(b"HTTP/1.1 200 OK\r\n", 22, 54321));
    }

    #[test]
    fn trait_parse_returns_ssh_variant() {
        let dissector = SshDissector;
        let data = b"SSH-2.0-OpenSSH_8.9p1\r\n";
        assert!(matches!(
            dissector.parse(data, &ctx()),
            Some(ProtocolData::Ssh(_))
        ));
    }
}
