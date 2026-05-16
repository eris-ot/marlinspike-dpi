//! SIP (RFC 3261) + RTP/RTCP (RFC 3550) combined session decoder.
//!
//! # Dispatch rationale
//!
//! SIP and RTP share UDP carriage but are byte-incompatible at byte 0:
//!   - SIP is ASCII text; every valid SIP message begins with a letter
//!     (request method: I, R, A, C, B, O, S, N, M, U, P) or 'S' from "SIP/2.0"
//!     responses. High bit is always 0 — ASCII range.
//!   - RTP/RTCP version-2 packets have bits 7-6 of byte 0 = `10` (binary), i.e.
//!     byte & 0xC0 == 0x80. That bit pattern is never valid ASCII.
//!
//! We therefore dispatch purely on the first byte rather than port — this lets
//! the decoder handle SIP over ephemeral ports and RTP sessions that the SDP
//! negotiated to ports other than 5004/5005, as long as they land in our
//! interest window. Port 5060 is registered for SIP; 5004/5005 for canonical
//! RTP/RTCP defaults. Real RTP media lands on negotiated ephemeral ports that
//! the engine may route here via wildcard matching in future.

use std::collections::BTreeMap;
use std::collections::HashMap;

use crate::bronze::{AssetObservation, BronzeEvent, BronzeEventFamily, ProtocolTransaction};
use crate::engine::{
    DecoderInterest, SessionDecoder, StreamChunk, build_envelope, new_event, parse_anomaly_event,
};

// ── SIP method set (RFC 3261 core + extensions) ─────────────────────────────

const SIP_METHODS: &[&str] = &[
    "REGISTER",
    "INVITE",
    "ACK",
    "CANCEL",
    "BYE",
    "OPTIONS",
    "SUBSCRIBE",
    "NOTIFY",
    "REFER",
    "MESSAGE",
    "INFO",
    "UPDATE",
    "PRACK",
    "PUBLISH",
];

// ── RTP payload type names (RFC 3551 static map) ─────────────────────────────

fn pt_name(pt: u8) -> &'static str {
    match pt {
        0 => "PCMU",
        8 => "PCMA",
        9 => "G722",
        18 => "G729",
        96..=127 => "dynamic",
        _ => "unknown",
    }
}

// ── RTCP packet-type → operation name ────────────────────────────────────────

fn rtcp_op(pt: u8) -> &'static str {
    match pt {
        200 => "rtcp_sr",
        201 => "rtcp_rr",
        202 => "rtcp_sdes",
        203 => "rtcp_bye",
        204 => "rtcp_app",
        _ => "rtcp_unknown",
    }
}

// ── Per-SSRC RTP stream state (flood suppression) ────────────────────────────

struct RtpStreamState {
    /// Count of datagrams seen for this SSRC.
    count: u64,
    /// Sequence number of the first packet.
    seq_initial: u16,
    /// Whether we have ever seen the marker bit set.
    marker_seen: bool,
}

// ── Decoder ──────────────────────────────────────────────────────────────────

#[derive(Default)]
pub(crate) struct SipRtpDecoder {
    /// Per-SSRC RTP stream tracking. Key = SSRC as u32.
    rtp_streams: HashMap<u32, RtpStreamState>,
}

impl SessionDecoder for SipRtpDecoder {
    fn name(&self) -> &'static str {
        "sip_rtp"
    }

    fn interest(&self) -> &'static [DecoderInterest] {
        &[
            // SIP signalling (plaintext, RFC 3261 §18.1)
            DecoderInterest::UdpPort(5060),
            DecoderInterest::TcpPort(5060),
            // Canonical RTP (RFC 3550) and RTCP (RTP_port+1) defaults
            DecoderInterest::UdpPort(5004),
            DecoderInterest::UdpPort(5005),
        ]
    }

    fn on_datagram(&mut self, chunk: &StreamChunk<'_>, out: &mut Vec<BronzeEvent>) {
        dispatch(self, chunk, out);
    }

    fn on_stream_chunk(&mut self, chunk: &StreamChunk<'_>, out: &mut Vec<BronzeEvent>) {
        // SIP over TCP uses the same ASCII wire format.
        dispatch(self, chunk, out);
    }
}

// ── Dispatch (byte-pattern) ───────────────────────────────────────────────────

/// Central dispatch: choose SIP vs RTP/RTCP by inspecting byte 0.
///
/// SIP bytes start in printable ASCII (0x20–0x7E). RTP version-2 sets
/// bits 7-6 = `10`, giving byte & 0xC0 == 0x80 — a value impossible for
/// valid ASCII, so the two ranges are disjoint and order-independent.
fn dispatch(dec: &mut SipRtpDecoder, chunk: &StreamChunk<'_>, out: &mut Vec<BronzeEvent>) {
    let p = chunk.payload;
    if p.is_empty() {
        return;
    }
    let b0 = p[0];
    // RTP/RTCP: version field occupies bits 7-6 of byte 0; version 2 == 0b10.
    if b0 & 0xC0 == 0x80 && p.len() >= 12 {
        handle_rtp_rtcp(dec, chunk, out);
    } else if b0.is_ascii_alphabetic() {
        // ASCII letter → SIP request or "SIP/2.0" response line.
        handle_sip(dec, chunk, out);
    } else {
        // Unrecognisable — emit a low-severity anomaly so it is surfaced
        // without flooding ops with medium-severity noise.
        out.push(parse_anomaly_event(
            chunk.capture_id.to_string(),
            build_envelope(
                &chunk.context,
                chunk.interface_id,
                chunk.frame_index,
                chunk.timestamp,
                chunk.segment_hash,
                chunk.transport,
                Some("sip_rtp"),
                chunk.captured_len,
                chunk.session_key.clone(),
            ),
            "sip_rtp",
            "low",
            "unrecognised sip_rtp payload (not SIP ASCII, not RTP version-2)",
            p,
        ));
    }
}

// ── SIP parser ───────────────────────────────────────────────────────────────

fn handle_sip(_dec: &mut SipRtpDecoder, chunk: &StreamChunk<'_>, out: &mut Vec<BronzeEvent>) {
    let text = match std::str::from_utf8(chunk.payload) {
        Ok(s) => s,
        Err(_) => {
            out.push(parse_anomaly_event(
                chunk.capture_id.to_string(),
                sip_envelope(chunk),
                "sip_rtp",
                "low",
                "SIP payload is not valid UTF-8",
                chunk.payload,
            ));
            return;
        }
    };

    // Split off the first line (start-line). RFC 3261 mandates CRLF but we
    // accept bare LF for resilience.
    let (start_line, rest) = match text.split_once('\n') {
        Some((l, r)) => (l.trim_end_matches('\r'), r),
        None => {
            // No line terminator at all — malformed per RFC 3261 §7.1.
            out.push(parse_anomaly_event(
                chunk.capture_id.to_string(),
                sip_envelope(chunk),
                "sip_rtp",
                "low",
                "malformed SIP start-line: no CRLF terminator found",
                chunk.payload,
            ));
            return;
        }
    };

    // Parse headers from `rest`; stop at blank line (header/body separator).
    let headers = parse_sip_headers(rest);

    let from = headers
        .get("from")
        .or_else(|| headers.get("f"))
        .cloned()
        .unwrap_or_default();
    let to = headers
        .get("to")
        .or_else(|| headers.get("t"))
        .cloned()
        .unwrap_or_default();
    let call_id = headers
        .get("call-id")
        .or_else(|| headers.get("i"))
        .cloned()
        .unwrap_or_default();
    let cseq = headers.get("cseq").cloned().unwrap_or_default();
    let contact = headers
        .get("contact")
        .or_else(|| headers.get("m"))
        .cloned()
        .unwrap_or_default();
    let user_agent = headers.get("user-agent").cloned();
    let server = headers.get("server").cloned();

    // Determine message type from start-line.
    let tokens: Vec<&str> = start_line.splitn(3, ' ').collect();

    if tokens.len() == 3 && tokens[0] == "SIP/2.0" {
        // Response line: SIP/2.0 <code> <reason>
        let code_str = tokens[1];
        let reason = tokens[2];
        let code: u16 = code_str.parse().unwrap_or(0);

        let mut attributes = BTreeMap::new();
        attributes.insert("response_code".to_string(), code.to_string());
        attributes.insert("response_reason".to_string(), reason.to_string());
        insert_common_attrs(
            &mut attributes,
            &from,
            &to,
            &call_id,
            &cseq,
            &contact,
            user_agent.as_deref(),
            server.as_deref(),
        );

        out.push(new_event(
            chunk.capture_id.to_string(),
            sip_envelope(chunk),
            BronzeEventFamily::ProtocolTransaction(ProtocolTransaction {
                operation: "sip_response".to_string(),
                status: format!("sip_response_{code}"),
                request_summary: Some(format!("{code} {reason}")),
                response_summary: None,
                object_refs: Vec::new(),
                values: Vec::new(),
                attributes,
                modbus: None,
                protocol_fields: None,
            }),
        ));
    } else if tokens.len() == 3 {
        // Request line: METHOD request-uri SIP/2.0
        let method = tokens[0].to_uppercase();
        let request_uri = tokens[1];

        if !SIP_METHODS.contains(&method.as_str()) {
            out.push(parse_anomaly_event(
                chunk.capture_id.to_string(),
                sip_envelope(chunk),
                "sip_rtp",
                "low",
                "unrecognised SIP method in start-line",
                chunk.payload,
            ));
            return;
        }

        let mut attributes = BTreeMap::new();
        attributes.insert("method".to_string(), method.clone());
        attributes.insert("request_uri".to_string(), request_uri.to_string());
        insert_common_attrs(
            &mut attributes,
            &from,
            &to,
            &call_id,
            &cseq,
            &contact,
            user_agent.as_deref(),
            server.as_deref(),
        );

        let operation = format!("sip_{}", method.to_lowercase());
        let summary = format!("{method} {request_uri}");

        out.push(new_event(
            chunk.capture_id.to_string(),
            sip_envelope(chunk),
            BronzeEventFamily::ProtocolTransaction(ProtocolTransaction {
                operation: operation.clone(),
                status: "observed".to_string(),
                request_summary: Some(summary),
                response_summary: None,
                object_refs: vec![request_uri.to_string()],
                values: Vec::new(),
                attributes,
                modbus: None,
                protocol_fields: None,
            }),
        ));

        // REGISTER → emit AssetObservation for the originating endpoint.
        if method == "REGISTER" {
            let src_ip = chunk.context.src_ip.to_string();
            let mut identifiers = BTreeMap::new();
            if !from.is_empty() {
                identifiers.insert("sip_address".to_string(), from.clone());
            }
            identifiers.insert("ip".to_string(), src_ip.clone());
            out.push(new_event(
                chunk.capture_id.to_string(),
                sip_envelope(chunk),
                BronzeEventFamily::AssetObservation(AssetObservation {
                    asset_key: src_ip,
                    role: Some("sip_endpoint".to_string()),
                    vendor: None,
                    model: None,
                    firmware: None,
                    hostnames: Vec::new(),
                    protocols: vec!["sip".to_string()],
                    identifiers,
                }),
            ));
        }
    } else {
        out.push(parse_anomaly_event(
            chunk.capture_id.to_string(),
            sip_envelope(chunk),
            "sip_rtp",
            "low",
            "malformed SIP start-line: unexpected token count",
            chunk.payload,
        ));
    }
}

/// Parse SIP headers from the lines after the start-line into a lowercase
/// key → trimmed value map. Stops at the blank line separating headers from
/// the body. Multi-line (folded) headers are not reassembled; this is
/// sufficient for the fields we extract.
fn parse_sip_headers(text: &str) -> HashMap<String, String> {
    let mut map = HashMap::new();
    for line in text.lines() {
        let line = line.trim_end_matches('\r');
        if line.is_empty() {
            break; // header/body separator
        }
        if let Some((name, value)) = line.split_once(':') {
            map.insert(name.trim().to_lowercase(), value.trim().to_string());
        }
    }
    map
}

#[allow(clippy::too_many_arguments)]
fn insert_common_attrs(
    attrs: &mut BTreeMap<String, String>,
    from: &str,
    to: &str,
    call_id: &str,
    cseq: &str,
    contact: &str,
    user_agent: Option<&str>,
    server: Option<&str>,
) {
    if !from.is_empty() {
        attrs.insert("from".to_string(), from.to_string());
    }
    if !to.is_empty() {
        attrs.insert("to".to_string(), to.to_string());
    }
    if !call_id.is_empty() {
        attrs.insert("call_id".to_string(), call_id.to_string());
    }
    if !cseq.is_empty() {
        attrs.insert("cseq".to_string(), cseq.to_string());
    }
    if !contact.is_empty() {
        attrs.insert("contact".to_string(), contact.to_string());
    }
    if let Some(ua) = user_agent {
        attrs.insert("user_agent".to_string(), ua.to_string());
    }
    if let Some(srv) = server {
        attrs.insert("server".to_string(), srv.to_string());
    }
}

#[inline]
fn sip_envelope(chunk: &StreamChunk<'_>) -> crate::bronze::EventEnvelope {
    build_envelope(
        &chunk.context,
        chunk.interface_id,
        chunk.frame_index,
        chunk.timestamp,
        chunk.segment_hash,
        chunk.transport,
        Some("sip"),
        chunk.captured_len,
        chunk.session_key.clone(),
    )
}

// ── RTP / RTCP parser ────────────────────────────────────────────────────────

fn handle_rtp_rtcp(dec: &mut SipRtpDecoder, chunk: &StreamChunk<'_>, out: &mut Vec<BronzeEvent>) {
    let p = chunk.payload;
    // Minimum RTP/RTCP header is 12 bytes; checked by caller.
    let b0 = p[0];
    let b1 = p[1];

    let version = (b0 >> 6) & 0x03; // always 2 here (checked by caller)

    // RTCP packet types occupy the range 192–223 — full 8-bit byte (no marker
    // bit in RTCP). RTP byte 1 is M(1)|PT(7) where PT is 0–127. The two ranges
    // are disjoint, so dispatch on the raw byte before masking.
    if (192..=223).contains(&b1) {
        let pt_rtcp = b1;
        let mut attributes = BTreeMap::new();
        attributes.insert("packet_type".to_string(), pt_rtcp.to_string());

        out.push(new_event(
            chunk.capture_id.to_string(),
            rtp_envelope(chunk),
            BronzeEventFamily::ProtocolTransaction(ProtocolTransaction {
                operation: rtcp_op(pt_rtcp).to_string(),
                status: "observed".to_string(),
                request_summary: None,
                response_summary: None,
                object_refs: Vec::new(),
                values: Vec::new(),
                attributes,
                modbus: None,
                protocol_fields: None,
            }),
        ));
        return;
    }

    // RTP
    let pt = b1 & 0x7F;
    let seq = u16::from_be_bytes([p[2], p[3]]);
    let _ts_rtp = u32::from_be_bytes([p[4], p[5], p[6], p[7]]);
    let ssrc = u32::from_be_bytes([p[8], p[9], p[10], p[11]]);
    let marker = (b1 & 0x80) != 0;

    let state = dec
        .rtp_streams
        .entry(ssrc)
        .or_insert_with(|| RtpStreamState {
            count: 0,
            seq_initial: seq,
            marker_seen: false,
        });
    state.count += 1;
    if marker {
        state.marker_seen = true;
    }

    // Emit on first packet of a new SSRC, then every 1000th — throttles noise
    // without losing visibility into long-lived media streams.
    let should_emit = state.count == 1 || state.count.is_multiple_of(1000);
    if !should_emit {
        return;
    }

    let mut attributes = BTreeMap::new();
    attributes.insert("version".to_string(), version.to_string());
    attributes.insert("payload_type".to_string(), pt.to_string());
    attributes.insert("payload_type_name".to_string(), pt_name(pt).to_string());
    attributes.insert("ssrc_hex".to_string(), format!("{ssrc:#010x}"));
    attributes.insert(
        "sequence_number_initial".to_string(),
        state.seq_initial.to_string(),
    );
    attributes.insert("marker_seen".to_string(), state.marker_seen.to_string());

    out.push(new_event(
        chunk.capture_id.to_string(),
        rtp_envelope(chunk),
        BronzeEventFamily::ProtocolTransaction(ProtocolTransaction {
            operation: "rtp_stream".to_string(),
            status: "observed".to_string(),
            request_summary: None,
            response_summary: None,
            object_refs: Vec::new(),
            values: Vec::new(),
            attributes,
            modbus: None,
            protocol_fields: None,
        }),
    ));
}

#[inline]
fn rtp_envelope(chunk: &StreamChunk<'_>) -> crate::bronze::EventEnvelope {
    build_envelope(
        &chunk.context,
        chunk.interface_id,
        chunk.frame_index,
        chunk.timestamp,
        chunk.segment_hash,
        chunk.transport,
        Some("rtp"),
        chunk.captured_len,
        chunk.session_key.clone(),
    )
}

// ── Inventory self-registration ───────────────────────────────────────────────

inventory::submit!(crate::engine::decoders::DecoderRegistration {
    name: "sip_rtp",
    factory: || Box::new(SipRtpDecoder::default()),
});

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bronze::TransportProtocol;
    use crate::registry::PacketContext;
    use chrono::{TimeZone, Utc};
    use std::net::{IpAddr, Ipv4Addr};

    // ── helpers ──────────────────────────────────────────────────────────────

    fn ctx(src_port: u16, dst_port: u16) -> PacketContext {
        PacketContext {
            src_mac: [0x00, 0x11, 0x22, 0x33, 0x44, 0x55],
            dst_mac: [0x00, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE],
            src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            dst_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            src_port,
            dst_port,
            vlan_id: None,
            timestamp: 0,
        }
    }

    fn udp_chunk<'a>(payload: &'a [u8], src_port: u16, dst_port: u16) -> StreamChunk<'a> {
        StreamChunk {
            capture_id: "test-cap",
            segment_hash: "seg-hash",
            interface_id: 0,
            frame_index: 1,
            timestamp: Utc.timestamp_opt(1_700_000_000, 0).unwrap(),
            context: ctx(src_port, dst_port),
            ethertype: 0x0800,
            ip_proto: Some(17),
            llc: None,
            transport: TransportProtocol::Udp,
            payload,
            session_key: "sk".to_string(),
            captured_len: payload.len() as u64,
        }
    }

    #[expect(dead_code, reason = "left available for future TCP reassembly tests")]
    fn tcp_chunk<'a>(payload: &'a [u8]) -> StreamChunk<'a> {
        StreamChunk {
            capture_id: "test-cap",
            segment_hash: "seg-hash",
            interface_id: 0,
            frame_index: 1,
            timestamp: Utc.timestamp_opt(1_700_000_000, 0).unwrap(),
            context: ctx(5060, 5060),
            ethertype: 0x0800,
            ip_proto: Some(6),
            llc: None,
            transport: TransportProtocol::Tcp,
            payload,
            session_key: "sk-tcp".to_string(),
            captured_len: payload.len() as u64,
        }
    }

    // ── Test 1: SIP INVITE request ────────────────────────────────────────────

    #[test]
    fn test_sip_invite_request() {
        let payload = b"INVITE sip:bob@biloxi.com SIP/2.0\r\n\
            Via: SIP/2.0/UDP pc33.atlanta.com;branch=z9hG4bK776asdhds\r\n\
            Max-Forwards: 70\r\n\
            To: Bob <sip:bob@biloxi.com>\r\n\
            From: Alice <sip:alice@atlanta.com>;tag=1928301774\r\n\
            Call-ID: a84b4c76e66710@pc33.atlanta.com\r\n\
            CSeq: 314159 INVITE\r\n\
            Contact: <sip:alice@pc33.atlanta.com>\r\n\
            Content-Type: application/sdp\r\n\
            Content-Length: 0\r\n\
            \r\n";

        let chunk = udp_chunk(payload, 5060, 5060);
        let mut dec = SipRtpDecoder::default();
        let mut out = Vec::new();
        dec.on_datagram(&chunk, &mut out);

        assert_eq!(out.len(), 1, "expected exactly one event for INVITE");
        let ev = &out[0];
        if let BronzeEventFamily::ProtocolTransaction(ref tx) = ev.family {
            assert_eq!(tx.operation, "sip_invite");
            assert_eq!(tx.status, "observed");
            assert_eq!(
                tx.attributes.get("method").map(String::as_str),
                Some("INVITE")
            );
            assert_eq!(
                tx.attributes.get("request_uri").map(String::as_str),
                Some("sip:bob@biloxi.com")
            );
            assert!(tx.attributes.contains_key("from"), "from header missing");
            assert!(tx.attributes.contains_key("to"), "to header missing");
            assert!(tx.attributes.contains_key("call_id"), "call_id missing");
            assert!(tx.attributes.contains_key("cseq"), "cseq missing");
            assert_eq!(
                tx.request_summary.as_deref(),
                Some("INVITE sip:bob@biloxi.com")
            );
        } else {
            panic!("expected ProtocolTransaction, got {:?}", ev.family);
        }
    }

    // ── Test 2: SIP 200 OK response ───────────────────────────────────────────

    #[test]
    fn test_sip_200_ok_response() {
        let payload = b"SIP/2.0 200 OK\r\n\
            Via: SIP/2.0/UDP server10.biloxi.com;branch=z9hG4bKnashds8\r\n\
            To: Bob <sip:bob@biloxi.com>;tag=a6c85cf\r\n\
            From: Alice <sip:alice@atlanta.com>;tag=1928301774\r\n\
            Call-ID: a84b4c76e66710@pc33.atlanta.com\r\n\
            CSeq: 314159 INVITE\r\n\
            Contact: <sip:bob@192.0.2.4>\r\n\
            Server: Cisco-SIPGateway/IOS-15.6\r\n\
            Content-Length: 0\r\n\
            \r\n";

        let chunk = udp_chunk(payload, 5060, 5060);
        let mut dec = SipRtpDecoder::default();
        let mut out = Vec::new();
        dec.on_datagram(&chunk, &mut out);

        assert_eq!(out.len(), 1);
        if let BronzeEventFamily::ProtocolTransaction(ref tx) = out[0].family {
            assert_eq!(tx.operation, "sip_response");
            assert_eq!(tx.status, "sip_response_200");
            assert_eq!(
                tx.attributes.get("response_code").map(String::as_str),
                Some("200")
            );
            assert_eq!(
                tx.attributes.get("response_reason").map(String::as_str),
                Some("OK")
            );
            assert_eq!(tx.request_summary.as_deref(), Some("200 OK"));
            assert!(
                tx.attributes.contains_key("server"),
                "server header missing"
            );
        } else {
            panic!("expected ProtocolTransaction");
        }
    }

    // ── Test 3: SIP REGISTER → AssetObservation ───────────────────────────────

    #[test]
    fn test_sip_register_asset_observation() {
        let payload = b"REGISTER sip:registrar.biloxi.com SIP/2.0\r\n\
            Via: SIP/2.0/UDP bobspc.biloxi.com:5060;branch=z9hG4bKnashds7\r\n\
            Max-Forwards: 70\r\n\
            To: Bob <sip:bob@biloxi.com>\r\n\
            From: Bob <sip:bob@biloxi.com>;tag=456248\r\n\
            Call-ID: 843817637684230@998sdasdh09\r\n\
            CSeq: 1826 REGISTER\r\n\
            Contact: <sip:bob@192.0.2.4>\r\n\
            Expires: 7200\r\n\
            Content-Length: 0\r\n\
            \r\n";

        let chunk = udp_chunk(payload, 5060, 5060);
        let mut dec = SipRtpDecoder::default();
        let mut out = Vec::new();
        dec.on_datagram(&chunk, &mut out);

        // Expect: one ProtocolTransaction + one AssetObservation
        assert_eq!(out.len(), 2, "REGISTER should emit tx + asset obs");

        let asset_ev = out
            .iter()
            .find(|e| matches!(e.family, BronzeEventFamily::AssetObservation(_)));
        assert!(
            asset_ev.is_some(),
            "no AssetObservation emitted for REGISTER"
        );

        if let BronzeEventFamily::AssetObservation(ref obs) = asset_ev.unwrap().family {
            assert_eq!(obs.role.as_deref(), Some("sip_endpoint"));
            assert!(
                obs.identifiers.contains_key("sip_address"),
                "sip_address identifier missing"
            );
        } else {
            panic!("wrong family");
        }
    }

    // ── Test 4: RTP PCMU (PT=0, version=2) ───────────────────────────────────

    #[test]
    fn test_rtp_pcmu_packet() {
        // Build a minimal 12-byte RTP header:
        //   byte 0: V=2 P=0 X=0 CC=0 → 0b10000000 = 0x80
        //   byte 1: M=0 PT=0 (PCMU) → 0x00
        //   bytes 2-3: seq = 0x0001
        //   bytes 4-7: timestamp = 0x00000000
        //   bytes 8-11: SSRC = 0xDEADBEEF
        let mut pkt = vec![
            0x80u8, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0xDE, 0xAD, 0xBE, 0xEF,
        ];
        // Append some fake audio payload bytes
        pkt.extend_from_slice(&[0xAA; 20]);

        let chunk = udp_chunk(&pkt, 5004, 5004);
        let mut dec = SipRtpDecoder::default();
        let mut out = Vec::new();
        dec.on_datagram(&chunk, &mut out);

        assert_eq!(out.len(), 1, "first RTP packet must emit one event");
        if let BronzeEventFamily::ProtocolTransaction(ref tx) = out[0].family {
            assert_eq!(tx.operation, "rtp_stream");
            assert_eq!(tx.status, "observed");
            assert_eq!(
                tx.attributes.get("payload_type_name").map(String::as_str),
                Some("PCMU")
            );
            assert_eq!(
                tx.attributes.get("payload_type").map(String::as_str),
                Some("0")
            );
            assert_eq!(tx.attributes.get("version").map(String::as_str), Some("2"));
            assert!(tx.attributes.contains_key("ssrc_hex"), "ssrc_hex missing");
        } else {
            panic!("expected ProtocolTransaction");
        }
    }

    // ── Test 5: RTCP SR (PT=200) ──────────────────────────────────────────────

    #[test]
    fn test_rtcp_sr_packet() {
        // Minimal RTCP SR:
        //   byte 0: V=2 P=0 RC=0 → 0x80
        //   byte 1: PT=200 (SR) → 0xC8
        //   bytes 2-3: length (in 32-bit words minus 1) = 6 → 0x0006
        //   bytes 4-7: SSRC of sender
        //   bytes 8-11: NTP timestamp seconds (padding to 12 bytes minimum)
        let pkt: Vec<u8> = vec![
            0x80, 0xC8, 0x00, 0x06, // header
            0x00, 0x11, 0x22, 0x33, // SSRC
            0x00, 0x00, 0x00, 0x00, // NTP hi (padding)
        ];

        let chunk = udp_chunk(&pkt, 5005, 5005);
        let mut dec = SipRtpDecoder::default();
        let mut out = Vec::new();
        dec.on_datagram(&chunk, &mut out);

        assert_eq!(out.len(), 1);
        if let BronzeEventFamily::ProtocolTransaction(ref tx) = out[0].family {
            assert_eq!(tx.operation, "rtcp_sr");
            assert_eq!(tx.status, "observed");
            assert_eq!(
                tx.attributes.get("packet_type").map(String::as_str),
                Some("200")
            );
        } else {
            panic!("expected ProtocolTransaction");
        }
    }

    // ── Test 6: Malformed SIP (no CRLF / newline in start line) ──────────────

    #[test]
    fn test_malformed_sip_no_crlf() {
        // Single line with no newline at all — RFC 3261 §7.1 requires CRLF.
        let payload = b"INVITE sip:bob@biloxi.com SIP/2.0";

        let chunk = udp_chunk(payload, 5060, 5060);
        let mut dec = SipRtpDecoder::default();
        let mut out = Vec::new();
        dec.on_datagram(&chunk, &mut out);

        assert_eq!(out.len(), 1, "malformed SIP must emit exactly one event");
        if let BronzeEventFamily::ParseAnomaly(ref a) = out[0].family {
            assert_eq!(a.severity, "low");
            assert!(
                a.decoder.contains("sip_rtp"),
                "decoder field wrong: {}",
                a.decoder
            );
        } else {
            panic!("expected ParseAnomaly, got {:?}", out[0].family);
        }
    }

    // ── Test 7: RTP flood suppression — second packet must NOT emit ───────────

    #[test]
    fn test_rtp_flood_suppression_second_packet() {
        let make_pkt = |seq: u16| -> Vec<u8> {
            let mut p = vec![0x80u8, 0x08]; // V=2, PT=8 (PCMA)
            p.extend_from_slice(&seq.to_be_bytes());
            p.extend_from_slice(&0u32.to_be_bytes()); // timestamp
            p.extend_from_slice(&0xCAFE_BABEu32.to_be_bytes()); // SSRC
            p.extend_from_slice(&[0u8; 20]);
            p
        };

        let pkt1 = make_pkt(1);
        let pkt2 = make_pkt(2);

        let mut dec = SipRtpDecoder::default();
        let mut out = Vec::new();

        dec.on_datagram(&udp_chunk(&pkt1, 5004, 5004), &mut out);
        assert_eq!(out.len(), 1, "first packet must emit");
        out.clear();

        dec.on_datagram(&udp_chunk(&pkt2, 5004, 5004), &mut out);
        assert_eq!(
            out.len(),
            0,
            "second packet of same SSRC must NOT emit (flood guard)"
        );
    }
}
