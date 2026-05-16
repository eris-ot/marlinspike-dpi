//! Syslog dissector — extracts facility, severity, hostname, and app name from
//! BSD-style (RFC 3164) and structured (RFC 5424) syslog messages.

use crate::registry::{PacketContext, ProtocolData, ProtocolDissector};

#[derive(Default)]
pub struct SyslogDissector;

fn facility_name(facility: u8) -> &'static str {
    match facility {
        0 => "kern",
        1 => "user",
        2 => "mail",
        3 => "daemon",
        4 => "auth",
        5 => "syslog",
        6 => "lpr",
        7 => "news",
        8 => "uucp",
        9 => "cron",
        10 => "authpriv",
        11 => "ftp",
        12 => "ntp",
        13 => "security",
        14 => "console",
        15 => "solaris-cron",
        16 => "local0",
        17 => "local1",
        18 => "local2",
        19 => "local3",
        20 => "local4",
        21 => "local5",
        22 => "local6",
        23 => "local7",
        _ => "unknown",
    }
}

fn severity_name(severity: u8) -> &'static str {
    match severity {
        0 => "emerg",
        1 => "alert",
        2 => "crit",
        3 => "err",
        4 => "warning",
        5 => "notice",
        6 => "info",
        7 => "debug",
        _ => "unknown",
    }
}

impl SyslogDissector {
    pub fn parse_fields(&self, data: &[u8]) -> Option<SyslogFields> {
        let text = std::str::from_utf8(data).ok()?;
        let text = text.trim();

        // Must start with '<' PRI '>'
        if !text.starts_with('<') {
            return None;
        }
        let close = text.find('>')?;
        if !(2..=4).contains(&close) {
            return None;
        }
        let pri: u16 = text[1..close].parse().ok()?;
        if pri > 191 {
            return None;
        }

        let facility = (pri / 8) as u8;
        let severity = (pri % 8) as u8;
        let after_pri = &text[close + 1..];

        // RFC 5424: starts with version digit then space.
        let (hostname, app_name, message) = if after_pri
            .as_bytes()
            .first()
            .is_some_and(|b| b.is_ascii_digit())
            && after_pri.as_bytes().get(1) == Some(&b' ')
        {
            parse_rfc5424(after_pri)
        } else {
            parse_rfc3164(after_pri)
        };

        Some(SyslogFields {
            facility,
            facility_name: facility_name(facility).to_string(),
            severity,
            severity_name: severity_name(severity).to_string(),
            hostname,
            app_name,
            message,
        })
    }
}

/// Parse RFC 3164 (BSD syslog): `<PRI>TIMESTAMP HOSTNAME APP[PID]: MSG`
fn parse_rfc3164(text: &str) -> (Option<String>, Option<String>, Option<String>) {
    // Skip the timestamp field (e.g. "Mar 26 14:30:01 ").
    // Heuristic: timestamps start with a month abbreviation or digit.
    let rest = skip_bsd_timestamp(text);

    let mut parts = rest.splitn(2, ' ');
    let hostname = parts.next().map(|s| s.to_string());
    let remainder = parts.next().unwrap_or("");

    let (app_name, message) = if let Some(colon_pos) = remainder.find(':') {
        let app_raw = &remainder[..colon_pos];
        // Strip PID: "sshd[1234]" → "sshd"
        let app = app_raw
            .find('[')
            .map_or(app_raw, |i| &app_raw[..i])
            .to_string();
        let msg = remainder[colon_pos + 1..].trim().to_string();
        (Some(app), if msg.is_empty() { None } else { Some(msg) })
    } else {
        (None, Some(remainder.to_string()))
    };

    (hostname, app_name, message)
}

/// Parse RFC 5424: `<PRI>VERSION SP TIMESTAMP SP HOSTNAME SP APP-NAME SP PROCID SP MSGID ...`
fn parse_rfc5424(text: &str) -> (Option<String>, Option<String>, Option<String>) {
    let fields: Vec<&str> = text.splitn(7, ' ').collect();
    // fields: [version, timestamp, hostname, app_name, procid, msgid, msg...]

    let hostname = fields.get(2).and_then(|s| nilvalue(s));
    let app_name = fields.get(3).and_then(|s| nilvalue(s));
    let message = fields.get(6).map(|s| s.to_string());

    (hostname, app_name, message)
}

fn nilvalue(s: &str) -> Option<String> {
    if s == "-" { None } else { Some(s.to_string()) }
}

fn skip_bsd_timestamp(text: &str) -> &str {
    // BSD timestamp is "Mmm dd HH:MM:SS " — 16 chars.
    let months = [
        "Jan ", "Feb ", "Mar ", "Apr ", "May ", "Jun ", "Jul ", "Aug ", "Sep ", "Oct ", "Nov ",
        "Dec ",
    ];
    if text.len() >= 16 && months.iter().any(|m| text.starts_with(m)) {
        &text[16..]
    } else {
        text
    }
}

impl ProtocolDissector for SyslogDissector {
    fn name(&self) -> &str {
        "syslog"
    }

    fn can_parse(&self, data: &[u8], src_port: u16, dst_port: u16) -> bool {
        (src_port == 514 || dst_port == 514) && data.first() == Some(&b'<')
    }

    fn parse(&self, data: &[u8], _context: &PacketContext) -> Option<ProtocolData> {
        Some(ProtocolData::Syslog(self.parse_fields(data)?))
    }
}

#[derive(Debug, Clone)]
pub struct SyslogFields {
    pub facility: u8,
    pub facility_name: String,
    pub severity: u8,
    pub severity_name: String,
    pub hostname: Option<String>,
    pub app_name: Option<String>,
    pub message: Option<String>,
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
            src_port: 514,
            dst_port: 514,
            vlan_id: None,
            timestamp: 0,
        }
    }

    #[test]
    fn parses_rfc3164_message() {
        let dissector = SyslogDissector;
        let msg = b"<134>Mar 26 14:30:01 plc-gw01 sshd[5432]: Accepted key for operator";
        let fields = dissector.parse_fields(msg).expect("syslog fields");
        assert_eq!(fields.facility, 16); // local0
        assert_eq!(fields.severity, 6); // info
        assert_eq!(fields.facility_name, "local0");
        assert_eq!(fields.severity_name, "info");
        assert_eq!(fields.hostname.as_deref(), Some("plc-gw01"));
        assert_eq!(fields.app_name.as_deref(), Some("sshd"));
        assert_eq!(fields.message.as_deref(), Some("Accepted key for operator"));
    }

    #[test]
    fn parses_rfc5424_message() {
        let dissector = SyslogDissector;
        let msg =
            b"<165>1 2026-03-26T14:30:01Z plc-gw01 modbusd 1234 - - Read holding registers 40001";
        let fields = dissector.parse_fields(msg).expect("syslog fields");
        assert_eq!(fields.facility, 20); // local4
        assert_eq!(fields.severity, 5); // notice
        assert_eq!(fields.hostname.as_deref(), Some("plc-gw01"));
        assert_eq!(fields.app_name.as_deref(), Some("modbusd"));
    }

    #[test]
    fn rejects_wrong_port() {
        let dissector = SyslogDissector;
        assert!(!dissector.can_parse(b"<134>test", 80, 80));
    }

    #[test]
    fn rejects_invalid_pri() {
        let dissector = SyslogDissector;
        assert!(dissector.parse_fields(b"<999>test").is_none());
    }

    #[test]
    fn trait_parse_returns_syslog_variant() {
        let dissector = SyslogDissector;
        let msg = b"<134>Mar 26 14:30:01 host app: msg";
        assert!(matches!(
            dissector.parse(msg, &ctx()),
            Some(ProtocolData::Syslog(_))
        ));
    }
}
