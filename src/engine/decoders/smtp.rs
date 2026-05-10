//! SMTP / SMTPS session decoder (RFC 5321).
//!
//! - Port 25 / 587: plaintext ESMTP. Parses server banners and client commands.
//! - Port 465: SMTPS — TLS from byte 1. Emits `smtp_tls_session` once per
//!   session and an `AssetObservation` for the server; no command parsing.
//!
//! After a STARTTLS command is acknowledged by the server with a 220 reply the
//! session flips opaque and further bytes are silently dropped. QUIT similarly
//! halts further emission.

use std::collections::BTreeMap;

use crate::bronze::{
    AssetObservation, BronzeEvent, BronzeEventFamily, ProtocolTransaction, TransportProtocol,
};
use crate::engine::{
    build_envelope, new_event, parse_anomaly_event, DecoderInterest, SessionDecoder, StreamChunk,
};

// ── Session state ─────────────────────────────────────────────────────────────

#[derive(Default)]
struct SmtpSession {
    tls_active: bool,
    done: bool,
    awaiting_starttls_220: bool,
    smtps_emitted: bool,
}

// ── Decoder ───────────────────────────────────────────────────────────────────

#[derive(Default)]
pub(crate) struct SmtpDecoder {
    sessions: std::collections::HashMap<String, SmtpSession>,
}

impl SessionDecoder for SmtpDecoder {
    fn name(&self) -> &'static str { "smtp" }

    fn interest(&self) -> &'static [DecoderInterest] {
        &[
            DecoderInterest::TcpPort(25),
            DecoderInterest::TcpPort(465),
            DecoderInterest::TcpPort(587),
        ]
    }

    fn on_stream_chunk(&mut self, chunk: &StreamChunk<'_>, out: &mut Vec<BronzeEvent>) {
        if chunk.payload.is_empty() { return; }

        let is_smtps = chunk.context.src_port == 465 || chunk.context.dst_port == 465;
        let session = self.sessions.entry(chunk.session_key.clone()).or_default();

        // ── Port 465: TLS from byte 1 ─────────────────────────────────────────
        if is_smtps {
            if session.smtps_emitted { return; }
            session.smtps_emitted = true;
            let env = smtp_env(chunk);
            let dst = chunk.context.dst_ip.to_string();
            out.push(new_event(
                chunk.capture_id.to_string(),
                env.clone(),
                BronzeEventFamily::ProtocolTransaction(ProtocolTransaction {
                    operation: "smtp_tls_session".to_string(),
                    status: "observed".to_string(),
                    request_summary: None,
                    response_summary: None,
                    object_refs: Vec::new(),
                    values: Vec::new(),
                    attributes: BTreeMap::from([(
                        "note".to_string(),
                        "TLS-encrypted from first byte, payload opaque".to_string(),
                    )]),
                    modbus: None,
                    protocol_fields: None,
                }),
            ));
            out.push(new_event(
                chunk.capture_id.to_string(),
                env,
                BronzeEventFamily::AssetObservation(AssetObservation {
                    asset_key: dst,
                    role: Some("smtp_server".to_string()),
                    vendor: None, model: None, firmware: None,
                    hostnames: Vec::new(),
                    protocols: vec!["smtp".to_string()],
                    identifiers: BTreeMap::from([("port".to_string(), "465".to_string())]),
                }),
            ));
            return;
        }

        // ── Plaintext (port 25 / 587) ─────────────────────────────────────────
        if session.tls_active || session.done { return; }

        let text = match std::str::from_utf8(chunk.payload) {
            Ok(s) => s,
            Err(_) => {
                out.push(parse_anomaly_event(
                    chunk.capture_id.to_string(), smtp_env(chunk),
                    "smtp", "low", "non-utf8 bytes on smtp session", chunk.payload,
                ));
                return;
            }
        };

        // True when this chunk flows server → client (src = SMTP port).
        let smtp_port = if chunk.context.dst_port == 25 || chunk.context.dst_port == 587 {
            chunk.context.dst_port
        } else {
            chunk.context.src_port
        };
        let from_server = chunk.context.src_port == smtp_port;

        for raw in text.split('\n') {
            if session.tls_active || session.done { break; }
            let line = raw.trim_end_matches('\r');
            if line.is_empty() { continue; }
            if from_server {
                on_server_line(chunk, session, line, out);
            } else {
                on_client_line(chunk, session, line, out);
            }
        }
    }
}

// ── Server line handler ───────────────────────────────────────────────────────

fn on_server_line(chunk: &StreamChunk<'_>, session: &mut SmtpSession, line: &str, out: &mut Vec<BronzeEvent>) {
    if line.len() < 3 { emit_anomaly(chunk, line, out); return; }
    let Ok(code) = line[..3].parse::<u16>() else { emit_anomaly(chunk, line, out); return; };

    // Multi-line continuation (dash after code): no event, keep going.
    if line.len() > 3 && line.as_bytes()[3] == b'-' { return; }

    // STARTTLS acknowledgement → flip opaque.
    if session.awaiting_starttls_220 {
        session.awaiting_starttls_220 = false;
        if code == 220 { session.tls_active = true; return; }
    }

    // Server banner.
    if code == 220 {
        let rest = if line.len() > 4 { &line[4..] } else { "" };
        let vendor = detect_vendor(rest);
        let dst = chunk.context.dst_ip.to_string();
        let env = smtp_env(chunk);
        let mut attrs = BTreeMap::from([("banner_text".to_string(), rest.to_string())]);
        if let Some(ref v) = vendor { attrs.insert("server_software".to_string(), v.clone()); }

        out.push(new_event(chunk.capture_id.to_string(), env.clone(),
            BronzeEventFamily::ProtocolTransaction(ProtocolTransaction {
                operation: "smtp_banner".to_string(),
                status: "observed".to_string(),
                request_summary: None,
                response_summary: Some(rest.to_string()),
                object_refs: Vec::new(), values: Vec::new(),
                attributes: attrs, modbus: None, protocol_fields: None,
            }),
        ));
        out.push(new_event(chunk.capture_id.to_string(), env,
            BronzeEventFamily::AssetObservation(AssetObservation {
                asset_key: dst.clone(),
                role: Some("smtp_server".to_string()),
                vendor, model: None, firmware: None,
                hostnames: Vec::new(),
                protocols: vec!["smtp".to_string()],
                identifiers: BTreeMap::from([
                    ("ip".to_string(), dst),
                    ("banner".to_string(), rest.to_string()),
                ]),
            }),
        ));
    }
    // All other server response codes: replies to commands, no separate event.
}

// ── Client line handler ───────────────────────────────────────────────────────

fn on_client_line(chunk: &StreamChunk<'_>, session: &mut SmtpSession, line: &str, out: &mut Vec<BronzeEvent>) {
    let (verb_raw, rest) = match line.find(|c: char| c.is_ascii_whitespace()) {
        Some(i) => (&line[..i], line[i + 1..].trim()),
        None => (line, ""),
    };
    let verb = verb_raw.to_ascii_uppercase();

    let mut attrs: BTreeMap<String, String> = BTreeMap::from([("argument".to_string(), rest.to_string())]);

    let operation: &str = match verb.as_str() {
        "HELO" => { attrs.insert("domain".to_string(), rest.to_string()); "smtp_helo" }
        "EHLO" => { attrs.insert("domain".to_string(), rest.to_string()); "smtp_ehlo" }
        "MAIL" => {
            if let Some(addr) = extract_angle_addr(rest) { attrs.insert("address".to_string(), addr); }
            "smtp_mail_from"
        }
        "RCPT" => {
            if let Some(addr) = extract_angle_addr(rest) { attrs.insert("address".to_string(), addr); }
            "smtp_rcpt_to"
        }
        "DATA"     => "smtp_data",
        "RSET"     => "smtp_rset",
        "NOOP"     => "smtp_noop",
        "QUIT"     => { session.done = true; "smtp_quit" }
        "STARTTLS" => { session.awaiting_starttls_220 = true; "smtp_starttls" }
        "AUTH"     => {
            let mech = rest.split_ascii_whitespace().next().unwrap_or("").to_string();
            if !mech.is_empty() { attrs.insert("auth_mechanism".to_string(), mech); }
            "smtp_auth"
        }
        _ => {
            // 3-digit code appearing on client side → anomaly.
            if verb.len() == 3 && verb.bytes().all(|b| b.is_ascii_digit()) {
                emit_anomaly(chunk, line, out);
                return;
            }
            // Unrecognised verb: anomaly if line is long enough to be intentional,
            // otherwise emit as smtp_unknown_command (rare short oddities).
            if line.len() > 16 {
                emit_anomaly(chunk, line, out);
            } else {
                out.push(tx_event(chunk, "smtp_unknown_command", Some(line), attrs));
            }
            return;
        }
    };

    out.push(tx_event(chunk, operation, Some(line), attrs));
}

// ── Emit helpers ──────────────────────────────────────────────────────────────

fn tx_event(
    chunk: &StreamChunk<'_>,
    operation: &str,
    summary: Option<&str>,
    attributes: BTreeMap<String, String>,
) -> BronzeEvent {
    new_event(
        chunk.capture_id.to_string(),
        smtp_env(chunk),
        BronzeEventFamily::ProtocolTransaction(ProtocolTransaction {
            operation: operation.to_string(),
            status: "observed".to_string(),
            request_summary: summary.map(str::to_string),
            response_summary: None,
            object_refs: Vec::new(),
            values: Vec::new(),
            attributes,
            modbus: None,
            protocol_fields: None,
        }),
    )
}

fn smtp_env(chunk: &StreamChunk<'_>) -> crate::bronze::EventEnvelope {
    build_envelope(
        &chunk.context, chunk.interface_id, chunk.frame_index,
        chunk.timestamp, chunk.segment_hash,
        TransportProtocol::Tcp, Some("smtp"),
        chunk.captured_len, chunk.session_key.clone(),
    )
}

fn emit_anomaly(chunk: &StreamChunk<'_>, line: &str, out: &mut Vec<BronzeEvent>) {
    out.push(parse_anomaly_event(
        chunk.capture_id.to_string(), smtp_env(chunk),
        "smtp", "low", "unrecognised smtp line", line.as_bytes(),
    ));
}

/// Extract address from inside `< >` angle brackets, best-effort.
/// Quoted local-parts (e.g. `<"foo bar"@example.com>`) and source-routed
/// addresses are out of scope; we return whatever is between `<` and `>`.
fn extract_angle_addr(s: &str) -> Option<String> {
    let start = s.find('<')? + 1;
    let end = s[start..].find('>')? + start;
    Some(s[start..end].trim().to_string())
}

/// Heuristic MTA software detection from the banner string.
fn detect_vendor(banner: &str) -> Option<String> {
    let lower = banner.to_ascii_lowercase();
    if lower.contains("postfix")                             { return Some("Postfix".to_string()); }
    if lower.contains("exim")                                { return Some("Exim".to_string()); }
    if lower.contains("sendmail")                            { return Some("Sendmail".to_string()); }
    if lower.contains("microsoft") || lower.contains("exchange") || lower.contains("iis") {
        return Some("Microsoft Exchange".to_string());
    }
    None
}

// ── Inventory registration ────────────────────────────────────────────────────

inventory::submit!(crate::engine::decoders::DecoderRegistration {
    name: "smtp",
    factory: || Box::new(SmtpDecoder::default()),
});

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};
    use chrono::{TimeZone, Utc};
    use crate::bronze::BronzeEventFamily;
    use crate::engine::StreamChunk;
    use crate::registry::PacketContext;

    fn ctx(src_port: u16, dst_port: u16) -> PacketContext {
        PacketContext {
            src_mac: [0u8; 6], dst_mac: [0u8; 6],
            src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            dst_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            src_port, dst_port, vlan_id: None,
            timestamp: 1_700_000_000_000_000,
        }
    }

    fn chunk<'a>(payload: &'a [u8], context: PacketContext) -> StreamChunk<'a> {
        StreamChunk {
            capture_id: "test", segment_hash: "seg",
            interface_id: 0, frame_index: 0,
            timestamp: Utc.timestamp_opt(1_700_000_000, 0).unwrap(),
            context, ethertype: 0x0800, ip_proto: Some(6), llc: None,
            transport: TransportProtocol::Tcp, payload,
            session_key: "sk".to_string(), captured_len: payload.len() as u64,
        }
    }

    fn txs(events: &[BronzeEvent]) -> Vec<&ProtocolTransaction> {
        events.iter().filter_map(|e| match &e.family {
            BronzeEventFamily::ProtocolTransaction(tx) => Some(tx),
            _ => None,
        }).collect()
    }

    fn obs(events: &[BronzeEvent]) -> Vec<&AssetObservation> {
        events.iter().filter_map(|e| match &e.family {
            BronzeEventFamily::AssetObservation(o) => Some(o),
            _ => None,
        }).collect()
    }

    // 1. Server banner → smtp_banner, Postfix detected ─────────────────────────

    #[test]
    fn test_banner_postfix() {
        let mut dec = SmtpDecoder::default();
        // src=25 → server→client direction
        let mut out = Vec::new();
        dec.on_stream_chunk(&chunk(b"220 mail.example.com ESMTP Postfix\r\n", ctx(25, 60000)), &mut out);

        let t = txs(&out);
        let banner = t.iter().find(|t| t.operation == "smtp_banner").expect("smtp_banner");
        assert_eq!(banner.status, "observed");
        assert!(banner.attributes.get("server_software").map(|s| s.contains("Postfix")).unwrap_or(false));
        assert!(banner.attributes.get("banner_text").map(|s| s.contains("mail.example.com")).unwrap_or(false));
    }

    // 2. Client EHLO → smtp_ehlo, domain extracted ─────────────────────────────

    #[test]
    fn test_ehlo_domain() {
        let mut dec = SmtpDecoder::default();
        // Seed a banner so the session key "sk" exists.
        dec.on_stream_chunk(&chunk(b"220 smtp.example.com ESMTP\r\n", ctx(25, 60000)), &mut Vec::new());

        let mut out = Vec::new();
        dec.on_stream_chunk(&chunk(b"EHLO client.example.com\r\n", ctx(60000, 25)), &mut out);

        let t = txs(&out);
        let ehlo = t.iter().find(|t| t.operation == "smtp_ehlo").expect("smtp_ehlo");
        assert_eq!(ehlo.attributes.get("domain").map(String::as_str), Some("client.example.com"));
    }

    // 3. MAIL FROM → address extracted from angle brackets ────────────────────

    #[test]
    fn test_mail_from_address() {
        let mut dec = SmtpDecoder::default();
        let mut out = Vec::new();
        dec.on_stream_chunk(&chunk(b"MAIL FROM:<alice@example.com>\r\n", ctx(60000, 25)), &mut out);

        let t = txs(&out);
        let tx = t.iter().find(|t| t.operation == "smtp_mail_from").expect("smtp_mail_from");
        assert_eq!(tx.attributes.get("address").map(String::as_str), Some("alice@example.com"));
    }

    // 4. RCPT TO → address extracted from angle brackets ──────────────────────

    #[test]
    fn test_rcpt_to_address() {
        let mut dec = SmtpDecoder::default();
        let mut out = Vec::new();
        dec.on_stream_chunk(&chunk(b"RCPT TO:<bob@example.com>\r\n", ctx(60000, 25)), &mut out);

        let t = txs(&out);
        let tx = t.iter().find(|t| t.operation == "smtp_rcpt_to").expect("smtp_rcpt_to");
        assert_eq!(tx.attributes.get("address").map(String::as_str), Some("bob@example.com"));
    }

    // 5. STARTTLS → opaque after server 220 ───────────────────────────────────

    #[test]
    fn test_starttls_then_opaque() {
        let mut dec = SmtpDecoder::default();

        // Client sends STARTTLS (client→server: src=60000, dst=25).
        let mut out1 = Vec::new();
        dec.on_stream_chunk(&chunk(b"STARTTLS\r\n", ctx(60000, 25)), &mut out1);
        assert!(txs(&out1).iter().any(|t| t.operation == "smtp_starttls"), "smtp_starttls expected");

        // Server responds 220 (server→client: src=25, dst=60000).
        let mut out2 = Vec::new();
        dec.on_stream_chunk(&chunk(b"220 Go ahead\r\n", ctx(25, 60000)), &mut out2);
        assert!(txs(&out2).is_empty(), "no transaction events after STARTTLS 220");

        // Further client data must be silently dropped.
        let mut out3 = Vec::new();
        dec.on_stream_chunk(&chunk(b"TLS HANDSHAKE BYTES\r\n", ctx(60000, 25)), &mut out3);
        assert!(txs(&out3).is_empty(), "no events after TLS switch");
    }

    // 6. Port 465 SMTPS → smtp_tls_session, no command parsing ───────────────

    #[test]
    fn test_smtps_port_465() {
        let mut dec = SmtpDecoder::default();
        let mut out = Vec::new();
        dec.on_stream_chunk(&chunk(b"\x16\x03\x03\x00\x01\xff", ctx(60000, 465)), &mut out);

        let t = txs(&out);
        assert_eq!(t.len(), 1);
        assert_eq!(t[0].operation, "smtp_tls_session");
        assert_eq!(t[0].status, "observed");
        assert_eq!(t[0].attributes.get("note").map(String::as_str),
            Some("TLS-encrypted from first byte, payload opaque"));

        let o = obs(&out);
        assert!(o.iter().any(|o| o.role.as_deref() == Some("smtp_server")));
        assert!(o.iter().any(|o| o.identifiers.get("port").map(String::as_str) == Some("465")));

        // Second chunk must produce nothing.
        let mut out2 = Vec::new();
        dec.on_stream_chunk(&chunk(b"\x16\x03\x03\x00\x01\xff", ctx(60000, 465)), &mut out2);
        assert!(out2.is_empty(), "SMTPS emits only once per session");
    }

    // 7. Garbage line > 16 bytes → ParseAnomaly severity=low ─────────────────

    #[test]
    fn test_garbage_line_anomaly() {
        let mut dec = SmtpDecoder::default();
        let mut out = Vec::new();
        dec.on_stream_chunk(&chunk(b"hello world this is garbage data longer\r\n", ctx(60000, 25)), &mut out);

        let anomalies: Vec<_> = out.iter().filter_map(|e| match &e.family {
            BronzeEventFamily::ParseAnomaly(a) => Some(a),
            _ => None,
        }).collect();
        assert!(!anomalies.is_empty(), "expected ParseAnomaly");
        assert!(anomalies.iter().any(|a| a.severity == "low"), "severity=low expected");
    }

    // 8. Interest slice contains exactly TcpPort 25, 465, 587 ─────────────────

    #[test]
    fn test_interest_ports() {
        let dec = SmtpDecoder::default();
        let i = dec.interest();
        assert!(i.contains(&DecoderInterest::TcpPort(25)));
        assert!(i.contains(&DecoderInterest::TcpPort(465)));
        assert!(i.contains(&DecoderInterest::TcpPort(587)));
        assert_eq!(i.len(), 3);
    }
}
