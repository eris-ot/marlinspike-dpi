//! WinRM / WS-Management session decoder.
//!
//! WinRM rides plain HTTP on TCP/5985 and TLS-wrapped HTTP on TCP/5986.
//! This decoder byte-pattern scans TCP stream chunks — it does NOT duplicate
//! the HTTP dissector and does NOT attempt real XML parsing. All SOAP element
//! extraction is byte-pattern search only; comments call this out explicitly.

use std::collections::BTreeMap;

use chrono::DateTime;
use chrono::Utc;

use crate::bronze::{
    AssetObservation, BronzeEvent, BronzeEventFamily, ProtocolTransaction, TransportProtocol,
};
use crate::engine::{
    DecoderInterest, SessionDecoder, StreamChunk, build_envelope, new_event, parse_anomaly_event,
};

// ── WS-Management action URI → canonical operation name ──────────────────────

/// Map a WS-Management action URI to a stable operation slug.
/// Returns `None` when the URI is non-empty but not in this table (caller
/// emits `"winrm_unknown_action"`).
fn wsm_action_name(uri: &str) -> Option<&'static str> {
    match uri {
        "http://schemas.xmlsoap.org/ws/2004/09/transfer/Get" => Some("winrm_get"),
        "http://schemas.xmlsoap.org/ws/2004/09/transfer/Put" => Some("winrm_put"),
        "http://schemas.xmlsoap.org/ws/2004/09/transfer/Create" => Some("winrm_create"),
        "http://schemas.xmlsoap.org/ws/2004/09/transfer/Delete" => Some("winrm_delete"),
        "http://schemas.xmlsoap.org/ws/2004/09/enumeration/Enumerate" => Some("winrm_enumerate"),
        "http://schemas.xmlsoap.org/ws/2004/09/enumeration/Pull" => Some("winrm_pull"),
        "http://schemas.xmlsoap.org/ws/2004/09/transfer/CommandLine" => Some("winrm_command"),
        "http://schemas.microsoft.com/wbem/wsman/1/windows/shell/Command" => {
            Some("winrm_shell_command")
        }
        "http://schemas.microsoft.com/wbem/wsman/1/windows/shell/Receive" => {
            Some("winrm_shell_receive")
        }
        "http://schemas.microsoft.com/wbem/wsman/1/windows/shell/Send" => Some("winrm_shell_send"),
        "http://schemas.microsoft.com/wbem/wsman/1/windows/shell/Signal" => {
            Some("winrm_shell_signal")
        }
        _ => None,
    }
}

// ── Byte-pattern helpers ──────────────────────────────────────────────────────

/// Locate `needle` in `haystack`, case-insensitively on ASCII bytes only.
/// WinRM headers are always ASCII so this is safe for header names.
fn find_bytes_ci(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || haystack.len() < needle.len() {
        return None;
    }
    'outer: for i in 0..=(haystack.len() - needle.len()) {
        for (j, &nb) in needle.iter().enumerate() {
            if !haystack[i + j].eq_ignore_ascii_case(&nb) {
                continue 'outer;
            }
        }
        return Some(i);
    }
    None
}

/// Locate `needle` in `haystack` as a raw byte substring (case-sensitive).
fn find_bytes(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || haystack.len() < needle.len() {
        return None;
    }
    haystack.windows(needle.len()).position(|w| w == needle)
}

/// Extract the value of an HTTP header from the raw payload.
/// Looks for `<header-name>:` (case-insensitive), then captures bytes up to
/// the next `\r\n`. Returns `None` if the header is absent.
///
/// NOTE: byte-pattern extraction only — not a real HTTP parser.
fn extract_header_value<'a>(payload: &'a [u8], header: &[u8]) -> Option<&'a str> {
    // Build search needle: "<header>:"
    let mut needle = header.to_ascii_lowercase();
    needle.push(b':');
    let pos = find_bytes_ci(payload, &needle)?;
    let after_colon = pos + needle.len();
    // Skip leading whitespace
    let start = after_colon
        + payload[after_colon..]
            .iter()
            .take_while(|&&b| b == b' ' || b == b'\t')
            .count();
    // Find end of line
    let end = find_bytes(&payload[start..], b"\r\n")
        .map(|e| start + e)
        .unwrap_or_else(|| payload.len());
    std::str::from_utf8(&payload[start..end]).ok()
}

/// Extract the SOAP `<*:Action>` element value from the payload.
///
/// WS-Management SOAP envelopes use a namespace-prefixed element:
/// `<a:Action>`, `<wsa:Action>`, `<s:Action>`, or plain `<Action>`.
/// Rather than parsing XML, we search by the constant suffix `Action>` for
/// the open tag and `Action>` for the close tag (`</…Action>`).
///
/// NOTE: This is byte-pattern matching, not XML parsing. It will mis-fire on
/// pathological SOAP with `Action>` in CDATA sections, but that does not
/// occur in production WinRM traffic.
fn extract_soap_action(payload: &[u8]) -> Option<&str> {
    // Find an opening tag ending in "Action>" — search for b"Action>"
    let open_needle = b"Action>";
    let pos = find_bytes(payload, open_needle)?;

    // Walk backwards from `pos` to find the `<` that opens this tag.
    // The prefix before "Action>" may be a namespace ("a:", "wsa:", etc.)
    // or empty. We allow up to 10 bytes of prefix to cover known prefixes.
    let search_start = pos.saturating_sub(10);
    let lt_pos = payload[search_start..pos]
        .iter()
        .rposition(|&b| b == b'<')?
        + search_start;

    // Verify no '/' immediately after '<' (that would be a closing tag).
    if payload.get(lt_pos + 1).copied() == Some(b'/') {
        // The first hit was a close tag; try to find the open tag another way.
        // Search from the beginning for "<" followed by optional prefix + "Action>".
        // We scan for all occurrences of "Action>" and take the first non-closing one.
        let mut search_from = 0usize;
        loop {
            let rel = find_bytes(&payload[search_from..], open_needle)?;
            let abs = search_from + rel;
            let sb = abs.saturating_sub(10);
            if let Some(ltp) = payload[sb..abs]
                .iter()
                .rposition(|&b| b == b'<')
                .map(|p| p + sb)
                && payload.get(ltp + 1).copied() != Some(b'/')
            {
                // Found a genuine open tag; reposition `pos` logic below
                let value_start = abs + open_needle.len();
                let close_needle = b"</";
                let close_pos = find_bytes(&payload[value_start..], close_needle)?;
                let raw = &payload[value_start..value_start + close_pos];
                return std::str::from_utf8(raw).ok().map(str::trim);
            }
            search_from = abs + 1;
            if search_from >= payload.len() {
                return None;
            }
        }
    }

    // Normal path: `lt_pos` is the `<` of the open tag.
    let value_start = pos + open_needle.len();
    // Find the closing tag `</…Action>` — search for `</` after value_start.
    let close_pos = find_bytes(&payload[value_start..], b"</")?;
    let raw = &payload[value_start..value_start + close_pos];
    std::str::from_utf8(raw).ok().map(str::trim)
}

/// Returns true when the payload begins with `POST /wsman` (with or without
/// trailing slash or query string). Comparison is ASCII case-sensitive per RFC.
fn is_wsman_post(payload: &[u8]) -> bool {
    payload.starts_with(b"POST /wsman/")
        || payload.starts_with(b"POST /wsman\r\n")
        || payload.starts_with(b"POST /wsman ")
}

/// Heuristic: does the first 16 bytes look like any HTTP method start?
/// Used to gate the ParseAnomaly on port 5985 for clearly non-HTTP traffic.
fn looks_like_http(payload: &[u8]) -> bool {
    let prefix = &payload[..payload.len().min(16)];
    // Common HTTP methods
    for method in &[
        b"GET " as &[u8],
        b"POST ",
        b"PUT ",
        b"DELETE ",
        b"HEAD ",
        b"OPTIONS ",
        b"PATCH ",
        b"HTTP/",
    ] {
        if prefix.starts_with(method) {
            return true;
        }
    }
    false
}

// ── Per-session state ─────────────────────────────────────────────────────────

/// Per-session decoder state. For 5986 we track whether we've already emitted
/// the one-shot `winrm_https_session` transaction (to avoid flooding on
/// every reassembled segment).
#[derive(Default)]
struct WinRmSession {
    https_emitted: bool,
}

// ── Decoder ──────────────────────────────────────────────────────────────────

#[derive(Default)]
pub(crate) struct WinRmDecoder {
    sessions: std::collections::HashMap<String, WinRmSession>,
}

impl SessionDecoder for WinRmDecoder {
    fn name(&self) -> &'static str {
        "winrm"
    }

    fn interest(&self) -> &'static [DecoderInterest] {
        &[
            DecoderInterest::TcpPort(5985),
            DecoderInterest::TcpPort(5986),
        ]
    }

    fn on_stream_chunk(&mut self, chunk: &StreamChunk<'_>, out: &mut Vec<BronzeEvent>) {
        let dst_port = chunk.context.dst_port;
        let src_port = chunk.context.src_port;

        // Determine which port defines protocol role. WinRM traffic flows
        // client→server on 5985/5986; responses come from those ports.
        let winrm_port = if dst_port == 5985 || dst_port == 5986 {
            dst_port
        } else if src_port == 5985 || src_port == 5986 {
            src_port
        } else {
            // Should not reach here given interest() filter, but be defensive.
            return;
        };

        let server_ip = if dst_port == winrm_port {
            chunk.context.dst_ip.to_string()
        } else {
            chunk.context.src_ip.to_string()
        };

        let envelope = build_envelope(
            &chunk.context,
            chunk.interface_id,
            chunk.frame_index,
            chunk.timestamp,
            chunk.segment_hash,
            TransportProtocol::Tcp,
            Some("winrm"),
            chunk.captured_len,
            chunk.session_key.clone(),
        );

        // ── Port 5986: TLS-encrypted, payload is opaque ───────────────────
        if winrm_port == 5986 {
            // Emit AssetObservation for the WinRM server on every chunk.
            out.push(new_event(
                chunk.capture_id.to_string(),
                envelope.clone(),
                BronzeEventFamily::AssetObservation(AssetObservation {
                    asset_key: server_ip.clone(),
                    role: Some("winrm_server".to_string()),
                    vendor: None,
                    model: None,
                    firmware: None,
                    hostnames: Vec::new(),
                    protocols: vec!["winrm".to_string()],
                    identifiers: BTreeMap::from([("ip".to_string(), server_ip)]),
                }),
            ));

            // Emit one ProtocolTransaction per session for 5986.
            let session = self.sessions.entry(chunk.session_key.clone()).or_default();
            if !session.https_emitted {
                session.https_emitted = true;
                let mut attributes = BTreeMap::new();
                attributes.insert(
                    "note".to_string(),
                    "TLS-encrypted, payload opaque".to_string(),
                );
                out.push(new_event(
                    chunk.capture_id.to_string(),
                    envelope,
                    BronzeEventFamily::ProtocolTransaction(ProtocolTransaction {
                        operation: "winrm_https_session".to_string(),
                        status: "observed".to_string(),
                        request_summary: Some(
                            "WinRM/HTTPS session (5986, payload opaque)".to_string(),
                        ),
                        response_summary: None,
                        object_refs: Vec::new(),
                        values: Vec::new(),
                        attributes,
                        modbus: None,
                        protocol_fields: None,
                    }),
                ));
            }
            return;
        }

        // ── Port 5985: plaintext HTTP carrying SOAP/WS-Management ─────────

        // Always emit AssetObservation for the server side.
        out.push(new_event(
            chunk.capture_id.to_string(),
            envelope.clone(),
            BronzeEventFamily::AssetObservation(AssetObservation {
                asset_key: server_ip.clone(),
                role: Some("winrm_server".to_string()),
                vendor: None,
                model: None,
                firmware: None,
                hostnames: Vec::new(),
                protocols: vec!["winrm".to_string()],
                identifiers: BTreeMap::from([("ip".to_string(), server_ip)]),
            }),
        ));

        if chunk.payload.is_empty() {
            return;
        }

        // Only decode client→server POST /wsman requests.
        // Server responses on 5985 are HTTP; we skip them (no Action in response).
        if !is_wsman_post(chunk.payload) {
            // If it does not look like any HTTP at all, emit a ParseAnomaly.
            if !looks_like_http(chunk.payload) {
                out.push(parse_anomaly_event(
                    chunk.capture_id.to_string(),
                    envelope,
                    self.name(),
                    "low",
                    "5985 traffic does not match expected HTTP/WS-Management pattern",
                    chunk.payload,
                ));
            }
            // HTTP responses and non-wsman endpoints are silently ignored.
            return;
        }

        // ── Extract optional HTTP header fields ───────────────────────────
        // NOTE: All of the following extractions are byte-pattern searches,
        // not real HTTP header parsing. They are best-effort for DPI purposes.

        // `SOAPAction:` header value (may be quoted; strip quotes if present).
        let soap_action_header = extract_header_value(chunk.payload, b"SOAPAction")
            .map(|v| v.trim_matches('"').to_string());

        // `Host:` header
        let host_header = extract_header_value(chunk.payload, b"Host").map(str::to_string);

        // `User-Agent:` header
        let user_agent = extract_header_value(chunk.payload, b"User-Agent").map(str::to_string);

        // ── Extract SOAP Action URI from the body ─────────────────────────
        // NOTE: byte-pattern extraction of <*:Action>…</…Action>, not XML parsing.
        let soap_body_action = extract_soap_action(chunk.payload);

        // Prefer the in-body Action element; fall back to the SOAPAction header.
        let action_uri: Option<String> = soap_body_action
            .map(str::to_string)
            .or_else(|| soap_action_header.clone());

        // Derive operation name from the resolved action URI.
        let operation = match &action_uri {
            Some(uri) if !uri.is_empty() => wsm_action_name(uri)
                .unwrap_or("winrm_unknown_action")
                .to_string(),
            _ => "winrm_request_no_action".to_string(),
        };

        // Build attributes map.
        let mut attributes = BTreeMap::new();
        if let Some(ref uri) = action_uri {
            attributes.insert("soap_action_uri".to_string(), uri.clone());
        }
        if let Some(ref hdr) = host_header {
            attributes.insert("host_header".to_string(), hdr.clone());
        }
        if let Some(ref ua) = user_agent {
            attributes.insert("user_agent".to_string(), ua.clone());
        }

        let request_summary = Some(format!("POST /wsman Action={operation}"));

        out.push(new_event(
            chunk.capture_id.to_string(),
            envelope,
            BronzeEventFamily::ProtocolTransaction(ProtocolTransaction {
                operation,
                status: "observed".to_string(),
                request_summary,
                response_summary: None,
                object_refs: Vec::new(),
                values: Vec::new(),
                attributes,
                modbus: None,
                protocol_fields: None,
            }),
        ));
    }

    fn on_idle_flush(&mut self, _timestamp: DateTime<Utc>, _out: &mut Vec<BronzeEvent>) {
        // No pending state to flush; session map is purely for once-per-session
        // emission guards and can be left to grow until eviction.
    }

    fn evict_idle(&mut self, _timestamp: DateTime<Utc>, _out: &mut Vec<BronzeEvent>) {
        // Clear session state for idle sessions. In practice WinRM sessions are
        // short-lived, so this is a safety valve rather than a hot path.
        self.sessions.clear();
    }
}

inventory::submit!(crate::engine::decoders::DecoderRegistration {
    name: "winrm",
    factory: || Box::new(WinRmDecoder::default()),
});

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use std::net::{IpAddr, Ipv4Addr};

    use crate::bronze::BronzeEventFamily;
    use crate::engine::{SessionDecoder, StreamChunk};
    use crate::registry::PacketContext;

    // ── Fixture helpers ───────────────────────────────────────────────────────

    fn ctx_5985() -> PacketContext {
        PacketContext {
            src_mac: [0x00, 0x11, 0x22, 0x33, 0x44, 0x55],
            dst_mac: [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF],
            src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 10)),
            dst_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 20)),
            src_port: 52000,
            dst_port: 5985,
            vlan_id: None,
            timestamp: 1_700_000_000_000_000,
        }
    }

    fn ctx_5986() -> PacketContext {
        PacketContext {
            src_port: 52001,
            dst_port: 5986,
            ..ctx_5985()
        }
    }

    fn chunk_with_ctx<'a>(payload: &'a [u8], ctx: PacketContext) -> StreamChunk<'a> {
        let session_key = format!(
            "{}:{}-{}:{}",
            ctx.src_ip, ctx.src_port, ctx.dst_ip, ctx.dst_port
        );
        StreamChunk {
            capture_id: "test-cap",
            segment_hash: "seg-hash",
            interface_id: 0,
            frame_index: 1,
            timestamp: Utc::now(),
            context: ctx,
            ethertype: 0x0800,
            ip_proto: Some(6),
            llc: None,
            transport: TransportProtocol::Tcp,
            payload,
            session_key,
            captured_len: payload.len() as u64,
        }
    }

    /// Minimal WinRM POST /wsman payload with a SOAP envelope containing a
    /// single Action element using the `a:` namespace prefix.
    fn wsman_post(action_uri: &str) -> Vec<u8> {
        let body = format!(
            concat!(
                "<s:Envelope xmlns:s=\"http://www.w3.org/2003/05/soap-envelope\" ",
                "xmlns:a=\"http://schemas.xmlsoap.org/ws/2004/08/addressing\">",
                "<s:Header>",
                "<a:Action mustMustUnderstand=\"true\">{}</a:Action>",
                "</s:Header>",
                "<s:Body/>",
                "</s:Envelope>"
            ),
            action_uri
        );
        let http = format!(
            "POST /wsman HTTP/1.1\r\n\
             Host: 10.0.0.20:5985\r\n\
             User-Agent: Python/3.11 pypsrp/0.8.0\r\n\
             Content-Type: application/soap+xml;charset=UTF-8\r\n\
             SOAPAction: \"{}\"\r\n\
             Content-Length: {}\r\n\
             \r\n\
             {}",
            action_uri,
            body.len(),
            body
        );
        http.into_bytes()
    }

    // ── Test 1: GET action ────────────────────────────────────────────────────

    #[test]
    fn test_winrm_get_action() {
        let mut decoder = WinRmDecoder::default();
        let payload = wsman_post("http://schemas.xmlsoap.org/ws/2004/09/transfer/Get");
        let chunk = chunk_with_ctx(&payload, ctx_5985());
        let mut out = Vec::new();
        decoder.on_stream_chunk(&chunk, &mut out);

        // Expect AssetObservation + ProtocolTransaction
        let tx = out.iter().find_map(|e| {
            if let BronzeEventFamily::ProtocolTransaction(tx) = &e.family {
                Some(tx)
            } else {
                None
            }
        });
        let tx = tx.expect("expected ProtocolTransaction");
        assert_eq!(tx.operation, "winrm_get");
        assert_eq!(tx.status, "observed");
        assert!(tx.request_summary.as_deref().unwrap().contains("winrm_get"));
        assert_eq!(
            tx.attributes.get("soap_action_uri").map(String::as_str),
            Some("http://schemas.xmlsoap.org/ws/2004/09/transfer/Get")
        );
        assert_eq!(
            tx.attributes.get("host_header").map(String::as_str),
            Some("10.0.0.20:5985")
        );
        assert!(tx.attributes.contains_key("user_agent"));
    }

    // ── Test 2: Enumerate action ──────────────────────────────────────────────

    #[test]
    fn test_winrm_enumerate_action() {
        let mut decoder = WinRmDecoder::default();
        let payload = wsman_post("http://schemas.xmlsoap.org/ws/2004/09/enumeration/Enumerate");
        let chunk = chunk_with_ctx(&payload, ctx_5985());
        let mut out = Vec::new();
        decoder.on_stream_chunk(&chunk, &mut out);

        let tx = out.iter().find_map(|e| {
            if let BronzeEventFamily::ProtocolTransaction(tx) = &e.family {
                Some(tx)
            } else {
                None
            }
        });
        assert_eq!(
            tx.expect("ProtocolTransaction").operation,
            "winrm_enumerate"
        );
    }

    // ── Test 3: Shell Command action ──────────────────────────────────────────

    #[test]
    fn test_winrm_shell_command_action() {
        let mut decoder = WinRmDecoder::default();
        let payload = wsman_post("http://schemas.microsoft.com/wbem/wsman/1/windows/shell/Command");
        let chunk = chunk_with_ctx(&payload, ctx_5985());
        let mut out = Vec::new();
        decoder.on_stream_chunk(&chunk, &mut out);

        let tx = out.iter().find_map(|e| {
            if let BronzeEventFamily::ProtocolTransaction(tx) = &e.family {
                Some(tx)
            } else {
                None
            }
        });
        assert_eq!(
            tx.expect("ProtocolTransaction").operation,
            "winrm_shell_command"
        );
    }

    // ── Test 4: No Action element → winrm_request_no_action ──────────────────

    #[test]
    fn test_winrm_no_action() {
        let mut decoder = WinRmDecoder::default();
        // POST /wsman but no Action element in the body.
        let body = "<s:Envelope><s:Header/><s:Body/></s:Envelope>";
        let http = format!(
            "POST /wsman HTTP/1.1\r\nHost: 10.0.0.20:5985\r\nContent-Length: {}\r\n\r\n{}",
            body.len(),
            body
        );
        let payload = http.into_bytes();
        let chunk = chunk_with_ctx(&payload, ctx_5985());
        let mut out = Vec::new();
        decoder.on_stream_chunk(&chunk, &mut out);

        let tx = out.iter().find_map(|e| {
            if let BronzeEventFamily::ProtocolTransaction(tx) = &e.family {
                Some(tx)
            } else {
                None
            }
        });
        assert_eq!(
            tx.expect("ProtocolTransaction").operation,
            "winrm_request_no_action"
        );
    }

    // ── Test 5: Port 5986 → winrm_https_session + AssetObservation ───────────

    #[test]
    fn test_winrm_https_session() {
        let mut decoder = WinRmDecoder::default();
        // Fake TLS-looking bytes — content is opaque to this decoder.
        let payload: Vec<u8> = vec![0x16, 0x03, 0x03, 0x00, 0x28, 0x01, 0x00, 0x00];
        let chunk = chunk_with_ctx(&payload, ctx_5986());
        let mut out = Vec::new();
        decoder.on_stream_chunk(&chunk, &mut out);

        // Must have an AssetObservation
        let obs = out.iter().find_map(|e| {
            if let BronzeEventFamily::AssetObservation(obs) = &e.family {
                Some(obs)
            } else {
                None
            }
        });
        let obs = obs.expect("expected AssetObservation");
        assert_eq!(obs.role.as_deref(), Some("winrm_server"));
        assert!(obs.protocols.contains(&"winrm".to_string()));

        // Must have a ProtocolTransaction with operation winrm_https_session
        let tx = out.iter().find_map(|e| {
            if let BronzeEventFamily::ProtocolTransaction(tx) = &e.family {
                Some(tx)
            } else {
                None
            }
        });
        let tx = tx.expect("expected ProtocolTransaction");
        assert_eq!(tx.operation, "winrm_https_session");
        assert_eq!(tx.status, "observed");
        assert_eq!(
            tx.attributes.get("note").map(String::as_str),
            Some("TLS-encrypted, payload opaque")
        );

        // Second chunk on same session must NOT emit another ProtocolTransaction.
        let mut out2 = Vec::new();
        decoder.on_stream_chunk(&chunk, &mut out2);
        let tx_count = out2
            .iter()
            .filter(|e| matches!(e.family, BronzeEventFamily::ProtocolTransaction(_)))
            .count();
        assert_eq!(
            tx_count, 0,
            "second 5986 chunk should not re-emit ProtocolTransaction"
        );
    }

    // ── Test 6: Non-HTTP traffic on 5985 → ParseAnomaly severity="low" ────────

    #[test]
    fn test_winrm_5985_non_http_anomaly() {
        let mut decoder = WinRmDecoder::default();
        // Binary garbage — clearly not HTTP.
        let payload: Vec<u8> = vec![
            0xFF, 0xFE, 0x00, 0x01, 0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00,
        ];
        let chunk = chunk_with_ctx(&payload, ctx_5985());
        let mut out = Vec::new();
        decoder.on_stream_chunk(&chunk, &mut out);

        let anomaly = out.iter().find_map(|e| {
            if let BronzeEventFamily::ParseAnomaly(a) = &e.family {
                Some(a)
            } else {
                None
            }
        });
        let anomaly = anomaly.expect("expected ParseAnomaly");
        assert_eq!(anomaly.severity, "low");
        assert_eq!(anomaly.decoder, "winrm");
    }

    // ── Test 7: Unknown action URI → winrm_unknown_action ────────────────────

    #[test]
    fn test_winrm_unknown_action_uri() {
        let mut decoder = WinRmDecoder::default();
        let payload = wsman_post("http://example.com/some/proprietary/Action");
        let chunk = chunk_with_ctx(&payload, ctx_5985());
        let mut out = Vec::new();
        decoder.on_stream_chunk(&chunk, &mut out);

        let tx = out.iter().find_map(|e| {
            if let BronzeEventFamily::ProtocolTransaction(tx) = &e.family {
                Some(tx)
            } else {
                None
            }
        });
        assert_eq!(
            tx.expect("ProtocolTransaction").operation,
            "winrm_unknown_action"
        );
    }

    // ── Test 8: AssetObservation role on 5985 traffic ─────────────────────────

    #[test]
    fn test_winrm_5985_asset_observation_emitted() {
        let mut decoder = WinRmDecoder::default();
        let payload = wsman_post("http://schemas.xmlsoap.org/ws/2004/09/transfer/Get");
        let chunk = chunk_with_ctx(&payload, ctx_5985());
        let mut out = Vec::new();
        decoder.on_stream_chunk(&chunk, &mut out);

        let obs = out.iter().find_map(|e| {
            if let BronzeEventFamily::AssetObservation(obs) = &e.family {
                Some(obs)
            } else {
                None
            }
        });
        let obs = obs.expect("expected AssetObservation on port 5985");
        assert_eq!(obs.role.as_deref(), Some("winrm_server"));
        assert_eq!(obs.asset_key, "10.0.0.20");
    }
}
