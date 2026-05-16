//! CoAP (RFC 7252) session decoder — UDP port 5683 (plaintext) and 5684 (DTLS).
//!
//! Port 5683: parse the 4-byte fixed header, walk delta-encoded options, and
//! emit a ProtocolTransaction per message.
//!
//! Port 5684 (CoAPS / DTLS): inspect the record-type byte but do not decrypt;
//! emit one ProtocolTransaction per session noting the payload is opaque.

use std::collections::BTreeMap;

use crate::bronze::{BronzeEvent, BronzeEventFamily, ProtocolTransaction, TransportProtocol};
use crate::engine::{
    DecoderInterest, SessionDecoder, StreamChunk, build_envelope, new_event, parse_anomaly_event,
};

// ── CoAP option numbers (RFC 7252 §12.2) ─────────────────────────────────

const OPT_URI_HOST: u16 = 3;
const OPT_URI_PORT: u16 = 7;
const OPT_URI_PATH: u16 = 11;
const OPT_CONTENT_FORMAT: u16 = 12;
const OPT_URI_QUERY: u16 = 15;
const OPT_ACCEPT: u16 = 17;
const OPT_PROXY_URI: u16 = 35;

// ── Option delta/length extended-value decoding ───────────────────────────
//
// Each CoAP option begins with a single "nibble byte" whose upper 4 bits are
// the delta nibble and lower 4 bits are the length nibble:
//
//   nibble  meaning
//   ──────  ────────────────────────────────────────────────────────────────
//   0..=12  value is the nibble itself
//   13      one more byte follows; actual = byte + 13
//   14      two more bytes follow (big-endian u16); actual = u16 + 269
//   15      reserved — if seen in delta position signals 0xFF payload marker;
//           anything else is a protocol error
//
// The same rule applies independently to the delta nibble and length nibble.

fn decode_extended(nibble: u8, buf: &[u8], pos: &mut usize) -> Option<u16> {
    match nibble {
        0..=12 => Some(nibble as u16),
        13 => {
            let b = *buf.get(*pos)?;
            *pos += 1;
            Some(b as u16 + 13)
        }
        14 => {
            let hi = *buf.get(*pos)? as u16;
            let lo = *buf.get(*pos + 1)? as u16;
            *pos += 2;
            Some((hi << 8 | lo) + 269)
        }
        // 15: payload marker or protocol error — caller handles via None path.
        _ => None,
    }
}

/// Walk the CoAP option list starting at `buf[pos]`.
/// Stops at the 0xFF payload marker or end of buffer.
/// Returns `(options, payload_start_pos)` or `None` on a parse error.
fn parse_options(buf: &[u8], mut pos: usize) -> Option<(ParsedOptions, usize)> {
    let mut opts = ParsedOptions::default();
    let mut current: u16 = 0;

    while pos < buf.len() {
        let nb = buf[pos];
        if nb == 0xFF {
            // Payload marker: skip it and stop option parsing.
            pos += 1;
            break;
        }
        pos += 1;

        let d_nibble = (nb >> 4) & 0x0F;
        let l_nibble = nb & 0x0F;

        // delta nibble == 15 without 0xFF byte is a protocol error.
        if d_nibble == 15 {
            return None;
        }

        let delta = decode_extended(d_nibble, buf, &mut pos)?;
        let length = decode_extended(l_nibble, buf, &mut pos)? as usize;

        if pos + length > buf.len() {
            return None; // truncated option value
        }

        current = current.checked_add(delta)?;
        let value = &buf[pos..pos + length];
        pos += length;

        match current {
            OPT_URI_HOST => {
                opts.uri_host = Some(String::from_utf8_lossy(value).into_owned());
            }
            OPT_URI_PATH => {
                opts.uri_path
                    .push(String::from_utf8_lossy(value).into_owned());
            }
            OPT_URI_QUERY => {
                opts.uri_query
                    .push(String::from_utf8_lossy(value).into_owned());
            }
            OPT_CONTENT_FORMAT => {
                let cf = value.iter().fold(0u32, |a, &b| (a << 8) | b as u32);
                opts.content_format = Some(cf);
            }
            // Recognised but not extracted at this time.
            OPT_URI_PORT | OPT_ACCEPT | OPT_PROXY_URI => {}
            _ => {}
        }
    }

    Some((opts, pos))
}

#[derive(Default)]
struct ParsedOptions {
    uri_host: Option<String>,
    uri_path: Vec<String>,
    uri_query: Vec<String>,
    content_format: Option<u32>,
}

// ── Code → operation / status ─────────────────────────────────────────────

fn coap_operation(code: u8, tkl: u8) -> &'static str {
    match code {
        0x00 if tkl == 0 => "coap_empty",
        0x01 => "coap_get",
        0x02 => "coap_post",
        0x03 => "coap_put",
        0x04 => "coap_delete",
        0x05 => "coap_fetch",
        0x06 => "coap_patch",
        0x07 => "coap_ipatch",
        _ => match code >> 5 {
            2 | 4 | 5 => "coap_response",
            _ => "coap_unknown",
        },
    }
}

fn coap_status(code: u8) -> String {
    let class = code >> 5;
    match class {
        2 | 4 | 5 => format!("coap_{}.{:02}", class, code & 0x1F),
        _ => "observed".to_string(),
    }
}

fn type_name(t: u8) -> &'static str {
    match t {
        0 => "CON",
        1 => "NON",
        2 => "ACK",
        3 => "RST",
        _ => "UNKNOWN",
    }
}

// ── Decoder ───────────────────────────────────────────────────────────────

#[derive(Default)]
pub(crate) struct CoapDecoder {
    /// Track whether the DTLS session event has been emitted (once per session).
    dtls_emitted: bool,
}

impl SessionDecoder for CoapDecoder {
    fn name(&self) -> &'static str {
        "coap"
    }

    fn interest(&self) -> &'static [DecoderInterest] {
        &[
            DecoderInterest::UdpPort(5683),
            DecoderInterest::UdpPort(5684),
        ]
    }

    fn on_datagram(&mut self, chunk: &StreamChunk<'_>, out: &mut Vec<BronzeEvent>) {
        let dtls = chunk.context.dst_port == 5684 || chunk.context.src_port == 5684;
        if dtls {
            self.handle_dtls(chunk, out);
        } else {
            self.handle_coap(chunk, out);
        }
    }
}

impl CoapDecoder {
    fn anomaly<'a>(&self, chunk: &StreamChunk<'a>, reason: &str, out: &mut Vec<BronzeEvent>) {
        out.push(parse_anomaly_event(
            chunk.capture_id.to_string(),
            build_envelope(
                &chunk.context,
                chunk.interface_id,
                chunk.frame_index,
                chunk.timestamp,
                chunk.segment_hash,
                TransportProtocol::Udp,
                Some("coap"),
                chunk.captured_len,
                chunk.session_key.clone(),
            ),
            self.name(),
            "low",
            reason,
            chunk.payload,
        ));
    }

    fn envelope(&self, chunk: &StreamChunk<'_>) -> crate::bronze::EventEnvelope {
        build_envelope(
            &chunk.context,
            chunk.interface_id,
            chunk.frame_index,
            chunk.timestamp,
            chunk.segment_hash,
            TransportProtocol::Udp,
            Some("coap"),
            chunk.captured_len,
            chunk.session_key.clone(),
        )
    }

    // ── DTLS / port 5684 ──────────────────────────────────────────────────

    fn handle_dtls(&mut self, chunk: &StreamChunk<'_>, out: &mut Vec<BronzeEvent>) {
        if self.dtls_emitted {
            return;
        }
        self.dtls_emitted = true;

        let mut attributes = BTreeMap::new();
        attributes.insert(
            "note".to_string(),
            "DTLS-encrypted, payload opaque".to_string(),
        );

        out.push(new_event(
            chunk.capture_id.to_string(),
            self.envelope(chunk),
            BronzeEventFamily::ProtocolTransaction(ProtocolTransaction {
                operation: "coap_dtls_session".to_string(),
                status: "observed".to_string(),
                request_summary: None,
                response_summary: None,
                object_refs: vec![],
                values: vec![],
                attributes,
                modbus: None,
                protocol_fields: None,
            }),
        ));
    }

    // ── Plaintext CoAP / port 5683 ────────────────────────────────────────

    fn handle_coap(&self, chunk: &StreamChunk<'_>, out: &mut Vec<BronzeEvent>) {
        let buf = chunk.payload;

        if buf.len() < 4 {
            self.anomaly(chunk, "coap datagram too short (< 4 bytes)", out);
            return;
        }

        // ── Fixed 4-byte header ───────────────────────────────────────────
        //   byte 0: Ver(2) | T(2) | TKL(4)
        //   byte 1: Code  (class:3 | detail:5)
        //   bytes 2-3: Message ID (u16 big-endian)

        let ver = (buf[0] >> 6) & 0x03;
        let msg_type = (buf[0] >> 4) & 0x03;
        let tkl = buf[0] & 0x0F;
        let code = buf[1];
        let message_id = u16::from_be_bytes([buf[2], buf[3]]);

        if ver != 1 {
            self.anomaly(chunk, &format!("coap version {ver} != 1"), out);
            return;
        }
        if tkl > 8 {
            self.anomaly(chunk, &format!("coap TKL {tkl} > 8 (invalid)"), out);
            return;
        }

        let token_end = 4 + tkl as usize;
        if buf.len() < token_end {
            self.anomaly(chunk, "coap datagram truncated before token end", out);
            return;
        }

        let token_hex = hex::encode(&buf[4..token_end]);

        let (opts, _payload_start) = match parse_options(buf, token_end) {
            Some(r) => r,
            None => {
                self.anomaly(
                    chunk,
                    "coap option parse error (truncated or invalid delta)",
                    out,
                );
                return;
            }
        };

        // ── Attributes ────────────────────────────────────────────────────

        let mut attributes: BTreeMap<String, String> = BTreeMap::new();
        attributes.insert("version".to_string(), ver.to_string());
        attributes.insert("type_name".to_string(), type_name(msg_type).to_string());
        attributes.insert("code_hex".to_string(), format!("0x{code:02x}"));
        attributes.insert("message_id".to_string(), message_id.to_string());
        attributes.insert("token_hex".to_string(), token_hex);

        if let Some(h) = opts.uri_host {
            attributes.insert("uri_host".to_string(), h);
        }
        if !opts.uri_path.is_empty() {
            attributes.insert("uri_path".to_string(), opts.uri_path.join("/"));
        }
        if !opts.uri_query.is_empty() {
            attributes.insert("uri_query".to_string(), opts.uri_query.join("&"));
        }
        if let Some(cf) = opts.content_format {
            attributes.insert("content_format".to_string(), cf.to_string());
        }

        let class = code >> 5;
        let detail = code & 0x1F;
        let tn = type_name(msg_type);

        out.push(new_event(
            chunk.capture_id.to_string(),
            self.envelope(chunk),
            BronzeEventFamily::ProtocolTransaction(ProtocolTransaction {
                operation: coap_operation(code, tkl).to_string(),
                status: coap_status(code),
                request_summary: Some(format!("CoAP {tn} {class}.{detail:02} id={message_id}")),
                response_summary: None,
                object_refs: vec![],
                values: vec![],
                attributes,
                modbus: None,
                protocol_fields: None,
            }),
        ));
    }
}

// ── Self-registration ─────────────────────────────────────────────────────

inventory::submit!(crate::engine::decoders::DecoderRegistration {
    name: "coap",
    factory: || Box::new(CoapDecoder::default()),
});

// ── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};

    use chrono::{TimeZone, Utc};

    use super::*;
    use crate::bronze::BronzeEventFamily;
    use crate::engine::{DecoderInterest, StreamChunk};
    use crate::registry::PacketContext;

    fn ctx(src_port: u16, dst_port: u16) -> PacketContext {
        PacketContext {
            src_mac: [0u8; 6],
            dst_mac: [0u8; 6],
            src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            dst_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            src_port,
            dst_port,
            vlan_id: None,
            timestamp: 1_700_000_000_000_000,
        }
    }

    fn chunk<'a>(payload: &'a [u8], src_port: u16, dst_port: u16) -> StreamChunk<'a> {
        StreamChunk {
            capture_id: "cap",
            segment_hash: "seg",
            interface_id: 0,
            frame_index: 0,
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

    /// Build a minimal CoAP datagram. Options must already be serialised by
    /// the caller. A non-empty payload is preceded by the 0xFF marker.
    fn coap_pkt(
        ver: u8,
        msg_type: u8,
        code: u8,
        mid: u16,
        token: &[u8],
        options: &[u8],
        payload: &[u8],
    ) -> Vec<u8> {
        let tkl = token.len() as u8;
        let mut buf = vec![(ver << 6) | (msg_type << 4) | tkl, code];
        buf.extend_from_slice(&mid.to_be_bytes());
        buf.extend_from_slice(token);
        buf.extend_from_slice(options);
        if !payload.is_empty() {
            buf.push(0xFF);
            buf.extend_from_slice(payload);
        }
        buf
    }

    /// Encode one option with delta ≤ 12 and value length ≤ 12 (simple case).
    fn opt(delta: u8, value: &[u8]) -> Vec<u8> {
        let mut v = vec![(delta << 4) | value.len() as u8];
        v.extend_from_slice(value);
        v
    }

    fn tx(evs: &[BronzeEvent]) -> Option<&ProtocolTransaction> {
        evs.iter().find_map(|e| match &e.family {
            BronzeEventFamily::ProtocolTransaction(t) => Some(t),
            _ => None,
        })
    }

    fn anomaly(evs: &[BronzeEvent]) -> Option<&crate::bronze::ParseAnomaly> {
        evs.iter().find_map(|e| match &e.family {
            BronzeEventFamily::ParseAnomaly(a) => Some(a),
            _ => None,
        })
    }

    // 1. GET /sensor/temperature — two Uri-Path (opt 11) options.
    //    delta from 0 = 11, then delta from 11 = 0 (same option number).
    #[test]
    fn test_get_uri_path() {
        let mut opts = opt(11, b"sensor"); // delta=11 → opt 11
        opts.extend(opt(0, b"temperature")); // delta=0  → opt 11 again
        let pkt = coap_pkt(1, 0, 0x01, 1, b"\xAB", &opts, &[]);
        let mut dec = CoapDecoder::default();
        let mut out = vec![];
        dec.on_datagram(&chunk(&pkt, 12345, 5683), &mut out);
        let t = tx(&out).expect("ProtocolTransaction");
        assert_eq!(t.operation, "coap_get");
        assert_eq!(t.status, "observed");
        assert_eq!(t.attributes["uri_path"], "sensor/temperature");
        assert_eq!(t.attributes["type_name"], "CON");
        assert_eq!(t.attributes["message_id"], "1");
    }

    // 2. POST with Uri-Host (opt 3).
    #[test]
    fn test_post_uri_host() {
        let opts = opt(3, b"device.local"); // delta=3 → opt 3 = Uri-Host
        let pkt = coap_pkt(1, 1, 0x02, 2, b"\xCD", &opts, b"{}");
        let mut dec = CoapDecoder::default();
        let mut out = vec![];
        dec.on_datagram(&chunk(&pkt, 54321, 5683), &mut out);
        let t = tx(&out).expect("ProtocolTransaction");
        assert_eq!(t.operation, "coap_post");
        assert_eq!(t.attributes["uri_host"], "device.local");
        assert_eq!(t.attributes["type_name"], "NON");
    }

    // 3. 2.05 Content response — wire code 0x45 = (2<<5)|5.
    #[test]
    fn test_response_2_05() {
        let pkt = coap_pkt(1, 2, 0x45, 1, b"\xAB", &[], b"25.3");
        let mut dec = CoapDecoder::default();
        let mut out = vec![];
        dec.on_datagram(&chunk(&pkt, 5683, 54321), &mut out);
        let t = tx(&out).expect("ProtocolTransaction");
        assert_eq!(t.operation, "coap_response");
        assert_eq!(t.status, "coap_2.05");
        assert_eq!(t.attributes["type_name"], "ACK");
    }

    // 4. 4.04 Not Found — wire code 0x84 = (4<<5)|4.
    #[test]
    fn test_response_4_04() {
        let pkt = coap_pkt(1, 2, 0x84, 3, b"\xDE", &[], &[]);
        let mut dec = CoapDecoder::default();
        let mut out = vec![];
        dec.on_datagram(&chunk(&pkt, 5683, 54321), &mut out);
        let t = tx(&out).expect("ProtocolTransaction");
        assert_eq!(t.operation, "coap_response");
        assert_eq!(t.status, "coap_4.04");
    }

    // 5. DTLS handshake (first byte 0x16) on port 5684.
    #[test]
    fn test_dtls_port_5684() {
        // Minimal DTLS record: content-type=22 (Handshake) + dummy bytes.
        let pkt = vec![
            0x16u8, 0xFE, 0xFF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00,
        ];
        let mut dec = CoapDecoder::default();
        let mut out = vec![];
        dec.on_datagram(&chunk(&pkt, 12345, 5684), &mut out);
        let t = tx(&out).expect("ProtocolTransaction");
        assert_eq!(t.operation, "coap_dtls_session");
        assert_eq!(t.status, "observed");
        assert_eq!(t.attributes["note"], "DTLS-encrypted, payload opaque");
    }

    // 6. Bad version (3) → ParseAnomaly severity=low.
    #[test]
    fn test_bad_version() {
        // byte0 = (3<<6)|(0<<4)|0 = 0xC0
        let pkt = vec![0xC0u8, 0x01, 0x00, 0x01];
        let mut dec = CoapDecoder::default();
        let mut out = vec![];
        dec.on_datagram(&chunk(&pkt, 12345, 5683), &mut out);
        let a = anomaly(&out).expect("ParseAnomaly");
        assert_eq!(a.severity, "low");
        assert!(a.reason.contains("version"));
    }

    // 7. TKL > 8 → ParseAnomaly.
    #[test]
    fn test_invalid_tkl() {
        // byte0 = (1<<6)|(0<<4)|9 = 0x49
        let pkt = vec![
            0x49u8, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];
        let mut dec = CoapDecoder::default();
        let mut out = vec![];
        dec.on_datagram(&chunk(&pkt, 12345, 5683), &mut out);
        let a = anomaly(&out).expect("ParseAnomaly");
        assert_eq!(a.severity, "low");
        assert!(a.reason.contains("TKL"));
    }

    // 8. Decoder interest covers both CoAP ports.
    #[test]
    fn test_interest_ports() {
        let dec = CoapDecoder::default();
        assert!(dec.interest().contains(&DecoderInterest::UdpPort(5683)));
        assert!(dec.interest().contains(&DecoderInterest::UdpPort(5684)));
    }

    // 9. Content-Format option extracted correctly.
    //    Uri-Host (opt 3) delta=3, then Content-Format (opt 12) delta=9.
    //    Content-Format value 50 = application/json.
    #[test]
    fn test_content_format() {
        let mut opts = opt(3, b"sensor.local"); // opt 3 Uri-Host
        opts.push((9 << 4) | 1u8); // delta=9 → opt 12 Content-Format, len=1
        opts.push(50u8); // value = 50 (application/json)
        let pkt = coap_pkt(1, 1, 0x02, 16, b"\x11", &opts, b"data");
        let mut dec = CoapDecoder::default();
        let mut out = vec![];
        dec.on_datagram(&chunk(&pkt, 54321, 5683), &mut out);
        let t = tx(&out).expect("ProtocolTransaction");
        assert_eq!(t.attributes["content_format"], "50");
        assert_eq!(t.attributes["uri_host"], "sensor.local");
    }
}
