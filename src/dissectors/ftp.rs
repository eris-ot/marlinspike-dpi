//! FTP dissector — extracts commands, reply codes, and server banners.

use crate::registry::{PacketContext, ProtocolData, ProtocolDissector};

#[derive(Default)]
pub struct FtpDissector;

impl FtpDissector {
    pub fn parse_fields(&self, data: &[u8]) -> Option<FtpFields> {
        let raw_line = data
            .split(|byte| matches!(byte, b'\r' | b'\n'))
            .find(|line| !line.is_empty())?;
        let line = String::from_utf8_lossy(raw_line);
        let line = line.trim();
        if line.is_empty() {
            return None;
        }

        let line_bytes = line.as_bytes();

        // FTP reply: 3-digit code followed by space or dash.
        if line_bytes.len() >= 4
            && line_bytes[0..3].iter().all(|byte| byte.is_ascii_digit())
            && matches!(line_bytes[3], b' ' | b'-')
        {
            let code: u16 = std::str::from_utf8(&line_bytes[0..3]).ok()?.parse().ok()?;
            let reply_text = String::from_utf8_lossy(&line_bytes[4..]).trim().to_string();
            let banner = if code == 220 {
                Some(reply_text.clone())
            } else {
                None
            };
            return Some(FtpFields {
                is_response: true,
                command: None,
                argument: None,
                reply_code: Some(code),
                reply_text: Some(reply_text),
                banner,
            });
        }

        // FTP command: VERB [argument]\r\n
        let (command, argument) = if let Some(space) = line.find(' ') {
            let cmd = line[..space].to_ascii_uppercase();
            let arg = line[space + 1..].trim().to_string();
            (cmd, if arg.is_empty() { None } else { Some(arg) })
        } else {
            (line.to_ascii_uppercase(), None)
        };

        // Validate: known FTP commands are 3-4 uppercase letters.
        if command.len() < 3 || command.len() > 4 || !command.chars().all(|c| c.is_ascii_uppercase())
        {
            return None;
        }

        Some(FtpFields {
            is_response: false,
            command: Some(command),
            argument,
            reply_code: None,
            reply_text: None,
            banner: None,
        })
    }
}

impl ProtocolDissector for FtpDissector {
    fn name(&self) -> &str {
        "ftp"
    }

    fn can_parse(&self, data: &[u8], src_port: u16, dst_port: u16) -> bool {
        (src_port == 21 || dst_port == 21) && !data.is_empty()
    }

    fn parse(&self, data: &[u8], _context: &PacketContext) -> Option<ProtocolData> {
        Some(ProtocolData::Ftp(self.parse_fields(data)?))
    }
}

#[derive(Debug, Clone)]
pub struct FtpFields {
    pub is_response: bool,
    pub command: Option<String>,
    pub argument: Option<String>,
    pub reply_code: Option<u16>,
    pub reply_text: Option<String>,
    pub banner: Option<String>,
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
            src_port: 21,
            dst_port: 12345,
            vlan_id: None,
            timestamp: 0,
        }
    }

    #[test]
    fn parses_banner() {
        let dissector = FtpDissector;
        let data = b"220 ProFTPD 1.3.6 Server (Siemens S7-1500 FTP)\r\n";
        let fields = dissector.parse_fields(data).expect("ftp fields");
        assert!(fields.is_response);
        assert_eq!(fields.reply_code, Some(220));
        assert_eq!(
            fields.banner.as_deref(),
            Some("ProFTPD 1.3.6 Server (Siemens S7-1500 FTP)")
        );
    }

    #[test]
    fn parses_reply() {
        let dissector = FtpDissector;
        let data = b"230 Login successful.\r\n";
        let fields = dissector.parse_fields(data).expect("ftp fields");
        assert!(fields.is_response);
        assert_eq!(fields.reply_code, Some(230));
        assert!(fields.banner.is_none());
    }

    #[test]
    fn parses_command() {
        let dissector = FtpDissector;
        let data = b"STOR firmware-v2.3.bin\r\n";
        let fields = dissector.parse_fields(data).expect("ftp fields");
        assert!(!fields.is_response);
        assert_eq!(fields.command.as_deref(), Some("STOR"));
        assert_eq!(fields.argument.as_deref(), Some("firmware-v2.3.bin"));
    }

    #[test]
    fn parses_command_no_argument() {
        let dissector = FtpDissector;
        let data = b"QUIT\r\n";
        let fields = dissector.parse_fields(data).expect("ftp fields");
        assert_eq!(fields.command.as_deref(), Some("QUIT"));
        assert!(fields.argument.is_none());
    }

    #[test]
    fn rejects_wrong_port() {
        let dissector = FtpDissector;
        assert!(!dissector.can_parse(b"USER admin\r\n", 80, 80));
    }

    #[test]
    fn trait_parse_returns_ftp_variant() {
        let dissector = FtpDissector;
        let data = b"220 Welcome\r\n";
        assert!(matches!(
            dissector.parse(data, &ctx()),
            Some(ProtocolData::Ftp(_))
        ));
    }

    #[test]
    fn does_not_panic_on_multibyte_prefix() {
        let dissector = FtpDissector;
        let data = b"\0\0\xcf\x96R\0";
        assert!(dissector.parse_fields(data).is_none());
    }
}
