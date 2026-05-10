//! Discovery-protocol decoder: mDNS (RFC 6762) and WS-Discovery (OASIS 1.1).
//!
//! Both protocols are high-yield for passive OT asset identification:
//! HMIs, cameras, printers, and embedded controllers announce themselves via
//! mDNS and WS-Discovery on every OT subnet that hasn't explicitly blocked
//! multicast.
//!
//! Routing: destination port 5353 → mDNS, 3702 → WS-Discovery.
//!
//! WS-Discovery parsing is intentionally byte-pattern based — NOT a real XML
//! parser. We search for fixed byte sequences (tag boundaries) to extract
//! message type, Types, and XAddrs. This is sufficient for passive asset
//! identification and avoids any XML dependency.

use std::collections::BTreeMap;
use std::net::{IpAddr, Ipv4Addr};

use crate::bronze::{
    AssetObservation, BronzeEvent, BronzeEventFamily, ProtocolTransaction, TransportProtocol,
};
use crate::engine::{build_envelope, new_event, DecoderInterest, SessionDecoder, StreamChunk};

const PORT_MDNS: u16 = 5353;
const PORT_WSD: u16 = 3702;

// ── Top-level decoder ─────────────────────────────────────────────

#[derive(Default)]
pub(crate) struct DiscoveryDecoder;

impl SessionDecoder for DiscoveryDecoder {
    fn name(&self) -> &'static str {
        "discovery"
    }

    fn interest(&self) -> &'static [DecoderInterest] {
        &[
            DecoderInterest::UdpPort(PORT_MDNS),
            DecoderInterest::UdpPort(PORT_WSD),
        ]
    }

    fn on_datagram(&mut self, chunk: &StreamChunk<'_>, out: &mut Vec<BronzeEvent>) {
        let dst = chunk.context.dst_port;
        let src = chunk.context.src_port;
        if dst == PORT_MDNS || src == PORT_MDNS {
            decode_mdns(chunk, out);
        } else if dst == PORT_WSD || src == PORT_WSD {
            decode_wsd(chunk, out);
        }
    }
}

// ── mDNS decoder ──────────────────────────────────────────────────

/// Parse an mDNS datagram (RFC 1035 / RFC 6762 DNS wire format).
fn decode_mdns(chunk: &StreamChunk<'_>, out: &mut Vec<BronzeEvent>) {
    let data = chunk.payload;
    if data.len() < 12 {
        return;
    }

    let qdcount = u16::from_be_bytes([data[4], data[5]]);
    let ancount = u16::from_be_bytes([data[6], data[7]]);
    let nscount = u16::from_be_bytes([data[8], data[9]]);
    let arcount = u16::from_be_bytes([data[10], data[11]]);

    let operation = match (qdcount > 0, ancount > 0) {
        (true, false) => "mdns_query",
        (true, true) => "mdns_update",
        _ => "mdns_response",
    };

    let mut offset = 12usize;
    let mut question_names: Vec<String> = Vec::new();
    let mut answer_names: Vec<String> = Vec::new();

    // Parse questions — collect names, skip qtype+qclass.
    for _ in 0..qdcount {
        let (name, new_off) = match parse_dns_name(data, offset) {
            Some(v) => v,
            None => break,
        };
        question_names.push(name);
        offset = new_off + 4; // skip qtype(2) + qclass(2)
        if offset > data.len() {
            break;
        }
    }

    // Parse answer + authority + additional sections.
    let total_rr = (ancount as usize)
        .saturating_add(nscount as usize)
        .saturating_add(arcount as usize);

    for rr_idx in 0..total_rr {
        let (name, new_off) = match parse_dns_name(data, offset) {
            Some(v) => v,
            None => break,
        };
        offset = new_off;
        if offset + 10 > data.len() {
            break;
        }

        let rtype = u16::from_be_bytes([data[offset], data[offset + 1]]);
        let rdlength = u16::from_be_bytes([data[offset + 8], data[offset + 9]]) as usize;
        offset += 10;

        if offset + rdlength > data.len() {
            break;
        }
        let rdata = &data[offset..offset + rdlength];

        if rr_idx < ancount as usize {
            answer_names.push(name.clone());
        }

        // Emit AssetObservations for semantically rich record types.
        match rtype {
            // PTR: service type → service instance name + instance as hostname
            12 => {
                let target = parse_name_from_rdata(data, rdata).unwrap_or_default();
                if !name.is_empty() && !target.is_empty() {
                    let mut ids = BTreeMap::new();
                    ids.insert("service_name".to_string(), name.clone());
                    emit_mdns_asset(chunk, out, name, Some("mdns_service"), vec![target], ids);
                }
            }
            // SRV: service instance → service_name, SRV target as hostname
            33 if rdlength >= 6 => {
                if !name.is_empty() {
                    let target = parse_name_from_rdata(data, &rdata[6..]).unwrap_or_default();
                    let mut ids = BTreeMap::new();
                    ids.insert("service_name".to_string(), name.clone());
                    let hostnames = if target.is_empty() { vec![] } else { vec![target] };
                    emit_mdns_asset(chunk, out, name, Some("mdns_service"), hostnames, ids);
                }
            }
            // A: hostname → IPv4 address binding
            1 if rdlength == 4 => {
                if !name.is_empty() {
                    let addr = format!("{}.{}.{}.{}", rdata[0], rdata[1], rdata[2], rdata[3]);
                    let mut ids = BTreeMap::new();
                    ids.insert("resolved_address".to_string(), addr);
                    emit_mdns_asset(chunk, out, name.clone(), None, vec![name], ids);
                }
            }
            // AAAA: hostname → IPv6 address binding
            28 if rdlength == 16 => {
                if !name.is_empty() {
                    let addr = (0..8)
                        .map(|i| format!("{:x}", u16::from_be_bytes([rdata[i * 2], rdata[i * 2 + 1]])))
                        .collect::<Vec<_>>()
                        .join(":");
                    let mut ids = BTreeMap::new();
                    ids.insert("resolved_address".to_string(), addr);
                    emit_mdns_asset(chunk, out, name.clone(), None, vec![name], ids);
                }
            }
            _ => {}
        }

        offset += rdlength;
    }

    // One ProtocolTransaction per packet.
    let object_refs = if ancount > 0 { answer_names } else { question_names };
    let envelope = mdns_envelope(chunk);
    let mut attributes = BTreeMap::new();
    attributes.insert("qdcount".to_string(), qdcount.to_string());
    attributes.insert("ancount".to_string(), ancount.to_string());
    attributes.insert("nscount".to_string(), nscount.to_string());
    attributes.insert("arcount".to_string(), arcount.to_string());

    out.push(new_event(
        chunk.capture_id.to_string(),
        envelope,
        BronzeEventFamily::ProtocolTransaction(ProtocolTransaction {
            operation: operation.to_string(),
            status: "observed".to_string(),
            request_summary: None,
            response_summary: None,
            object_refs,
            values: vec![],
            attributes,
            modbus: None,
            protocol_fields: None,
        }),
    ));
}

/// Build an mDNS EventEnvelope from a StreamChunk.
#[inline]
fn mdns_envelope(chunk: &StreamChunk<'_>) -> crate::bronze::EventEnvelope {
    build_envelope(
        &chunk.context,
        chunk.interface_id,
        chunk.frame_index,
        chunk.timestamp,
        chunk.segment_hash,
        TransportProtocol::Udp,
        Some("mdns"),
        chunk.captured_len,
        chunk.session_key.clone(),
    )
}

/// Emit a single mDNS AssetObservation event.
fn emit_mdns_asset(
    chunk: &StreamChunk<'_>,
    out: &mut Vec<BronzeEvent>,
    asset_key: String,
    role: Option<&str>,
    hostnames: Vec<String>,
    identifiers: BTreeMap<String, String>,
) {
    out.push(new_event(
        chunk.capture_id.to_string(),
        mdns_envelope(chunk),
        BronzeEventFamily::AssetObservation(AssetObservation {
            asset_key,
            role: role.map(str::to_string),
            vendor: None,
            model: None,
            firmware: None,
            hostnames,
            protocols: vec!["mdns".to_string()],
            identifiers,
        }),
    ));
}

// ── WS-Discovery decoder ──────────────────────────────────────────

/// Parse a WS-Discovery SOAP/XML datagram using byte-pattern matching.
///
/// WS-Discovery parsing is intentionally NOT a real XML parser. We perform
/// simple byte-level substring searches for known tag patterns. This is
/// deliberately minimal: namespace prefixes are accepted in either `wsd:`
/// or no-prefix form, and no XML spec compliance is claimed or required for
/// passive asset identification purposes.
fn decode_wsd(chunk: &StreamChunk<'_>, out: &mut Vec<BronzeEvent>) {
    let data = chunk.payload;

    let message_type = wsd_classify(data);
    // Extract Types and XAddrs via byte-pattern search — not XML parsing.
    let types_val = extract_xml_text(data, b"Types>", b"</").unwrap_or_default();
    let xaddrs_val = extract_xml_text(data, b"XAddrs>", b"</").unwrap_or_default();

    let envelope = build_envelope(
        &chunk.context,
        chunk.interface_id,
        chunk.frame_index,
        chunk.timestamp,
        chunk.segment_hash,
        TransportProtocol::Udp,
        Some("wsd"),
        chunk.captured_len,
        chunk.session_key.clone(),
    );

    let mut attributes = BTreeMap::new();
    if !xaddrs_val.is_empty() {
        attributes.insert("xaddrs".to_string(), xaddrs_val.clone());
    }
    if !types_val.is_empty() {
        attributes.insert("types".to_string(), types_val.clone());
    }

    out.push(new_event(
        chunk.capture_id.to_string(),
        envelope.clone(),
        BronzeEventFamily::ProtocolTransaction(ProtocolTransaction {
            operation: message_type.to_string(),
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

    // ProbeMatch and Hello with XAddrs → endpoint AssetObservation.
    if matches!(message_type, "wsd_probe_match" | "wsd_hello") && !xaddrs_val.is_empty() {
        let mut identifiers = BTreeMap::new();
        identifiers.insert("xaddrs".to_string(), xaddrs_val);
        if !types_val.is_empty() {
            identifiers.insert("types".to_string(), types_val);
        }
        out.push(new_event(
            chunk.capture_id.to_string(),
            envelope,
            BronzeEventFamily::AssetObservation(AssetObservation {
                asset_key: chunk.context.src_ip.to_string(),
                role: Some("wsd_endpoint".to_string()),
                vendor: None,
                model: None,
                firmware: None,
                hostnames: vec![],
                protocols: vec!["wsd".to_string()],
                identifiers,
            }),
        ));
    }
}

/// Classify a WS-Discovery message from its SOAP body using byte-pattern matching.
///
/// WS-Discovery parsing is intentionally NOT a real XML parser. We search for
/// fixed tag-name byte sequences. More-specific patterns are checked first to
/// avoid ResolveMatches matching the shorter "Resolve" pattern, and ProbeMatches
/// before "Probe".
fn wsd_classify(data: &[u8]) -> &'static str {
    // Check more-specific patterns before their prefixes.
    if contains(data, b"ResolveMatches") {
        "wsd_resolve_match"
    } else if contains(data, b"ProbeMatches") {
        "wsd_probe_match"
    } else if contains(data, b"Hello") {
        "wsd_hello"
    } else if contains(data, b"Bye") {
        "wsd_bye"
    } else if contains(data, b"Resolve") {
        "wsd_resolve"
    } else if contains(data, b"Probe") {
        "wsd_probe"
    } else {
        "wsd_unknown"
    }
}

/// Return true if `needle` appears anywhere in `haystack`.
#[inline]
fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack.windows(needle.len()).any(|w| w == needle)
}

/// Extract inner text between an opening tag suffix and the next closing tag
/// prefix. For example, `open_suffix = b"XAddrs>"` and `close_prefix = b"</"`
/// extracts the URL(s) from `<wsd:XAddrs>http://…</wsd:XAddrs>`.
///
/// This is byte-pattern extraction, not XML parsing. No escaping, CDATA, or
/// nested element handling — sufficient for WS-Discovery asset identification.
fn extract_xml_text(data: &[u8], open_suffix: &[u8], close_prefix: &[u8]) -> Option<String> {
    let pos = data.windows(open_suffix.len()).position(|w| w == open_suffix)?;
    let content_start = pos + open_suffix.len();
    let rest = &data[content_start..];
    let end = rest.windows(close_prefix.len()).position(|w| w == close_prefix)?;
    let text = std::str::from_utf8(&rest[..end]).ok()?.trim();
    if text.is_empty() { None } else { Some(text.to_string()) }
}

// ── DNS label parser ───────────────────────────────────────────────
//
// dns.rs has equivalent logic but its helpers are private (module-level fn,
// not pub). We implement a minimal copy rather than coupling to dns.rs
// internals. Compression pointers (top two bits = 0b11) are fully supported.

/// Parse a DNS domain name from `data` at `offset`.
/// Returns `(name, next_offset)`. After a compression pointer the stream
/// position advances 2 bytes (not to the pointed-at location).
fn parse_dns_name(data: &[u8], mut offset: usize) -> Option<(String, usize)> {
    let mut labels: Vec<String> = Vec::new();
    let mut jumped = false;
    let mut final_offset = offset;
    let mut hops = 0usize;

    loop {
        if offset >= data.len() || hops > 128 {
            return None;
        }
        let b = data[offset];
        if b == 0 {
            if !jumped {
                final_offset = offset + 1;
            }
            break;
        }
        // Compression pointer: top two bits set.
        if b & 0xC0 == 0xC0 {
            if offset + 1 >= data.len() {
                return None;
            }
            if !jumped {
                final_offset = offset + 2;
            }
            let ptr = ((b as usize & 0x3F) << 8) | data[offset + 1] as usize;
            if ptr >= data.len() {
                return None;
            }
            offset = ptr;
            jumped = true;
            hops += 1;
            continue;
        }
        let label_len = b as usize;
        offset += 1;
        if offset + label_len > data.len() {
            return None;
        }
        let label = std::str::from_utf8(&data[offset..offset + label_len]).ok()?;
        labels.push(label.to_string());
        offset += label_len;
        hops += 1;
    }

    let name = if labels.is_empty() { ".".to_string() } else { labels.join(".") };
    Some((name, final_offset))
}

/// Resolve a domain name from rdata using the full message for compression.
/// `rdata` must be a sub-slice of `full_msg`; pointer arithmetic locates it.
fn parse_name_from_rdata(full_msg: &[u8], rdata: &[u8]) -> Option<String> {
    let full_start = full_msg.as_ptr() as usize;
    let rdata_start = rdata.as_ptr() as usize;
    if rdata_start >= full_start && rdata_start < full_start + full_msg.len() {
        parse_dns_name(full_msg, rdata_start - full_start).map(|(n, _)| n)
    } else {
        // Fallback: no compression support.
        parse_dns_name_no_compression(rdata)
    }
}

/// Parse a DNS domain name without compression pointer support.
fn parse_dns_name_no_compression(data: &[u8]) -> Option<String> {
    let mut labels: Vec<String> = Vec::new();
    let mut offset = 0usize;
    loop {
        if offset >= data.len() { return None; }
        let len = data[offset] as usize;
        if len == 0 { break; }
        if len & 0xC0 == 0xC0 { return None; } // needs full msg
        offset += 1;
        if offset + len > data.len() { return None; }
        labels.push(std::str::from_utf8(&data[offset..offset + len]).ok()?.to_string());
        offset += len;
    }
    if labels.is_empty() { None } else { Some(labels.join(".")) }
}

// ── Inventory registration ────────────────────────────────────────

inventory::submit!(crate::engine::decoders::DecoderRegistration {
    name: "discovery",
    factory: || Box::new(DiscoveryDecoder::default()),
});

// ── Tests ─────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::registry::PacketContext;
    use chrono::Utc;

    // ── Test infrastructure ──────────────────────────────────────

    fn make_chunk<'a>(payload: &'a [u8], src_port: u16, dst_port: u16) -> StreamChunk<'a> {
        StreamChunk {
            capture_id: "test",
            segment_hash: "seg",
            interface_id: 0,
            frame_index: 0,
            timestamp: Utc::now(),
            context: PacketContext {
                src_mac: [0u8; 6],
                dst_mac: [0u8; 6],
                src_ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10)),
                dst_ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 255)),
                src_port,
                dst_port,
                vlan_id: None,
                timestamp: 0,
            },
            ethertype: 0x0800,
            ip_proto: Some(17),
            llc: None,
            transport: TransportProtocol::Udp,
            payload,
            session_key: "sess".to_string(),
            captured_len: payload.len() as u64,
        }
    }

    fn mdns_chunk(payload: &[u8]) -> StreamChunk<'_> {
        make_chunk(payload, PORT_MDNS, PORT_MDNS)
    }

    fn wsd_chunk(payload: &[u8]) -> StreamChunk<'_> {
        make_chunk(payload, PORT_WSD, PORT_WSD)
    }

    /// Encode DNS name as length-prefixed labels + root terminator.
    fn dns_name(name: &str) -> Vec<u8> {
        let mut buf = Vec::new();
        for label in name.split('.') {
            buf.push(label.len() as u8);
            buf.extend_from_slice(label.as_bytes());
        }
        buf.push(0);
        buf
    }

    fn mdns_query(qname: &str) -> Vec<u8> {
        let mut p = vec![
            0x00, 0x00, // id
            0x00, 0x00, // flags: query
            0x00, 0x01, // qdcount=1
            0x00, 0x00, // ancount=0
            0x00, 0x00, // nscount=0
            0x00, 0x00, // arcount=0
        ];
        p.extend_from_slice(&dns_name(qname));
        p.extend_from_slice(&[0x00, 0x0C, 0x00, 0x01]); // type PTR, class IN
        p
    }

    fn mdns_ptr_response(ptr_name: &str, ptr_target: &str) -> Vec<u8> {
        let mut p = vec![
            0x00, 0x00, // id
            0x84, 0x00, // flags: response, authoritative
            0x00, 0x00, // qdcount=0
            0x00, 0x01, // ancount=1
            0x00, 0x00, // nscount=0
            0x00, 0x00, // arcount=0
        ];
        p.extend_from_slice(&dns_name(ptr_name));
        p.extend_from_slice(&[0x00, 0x0C, 0x00, 0x01]); // PTR IN
        p.extend_from_slice(&[0x00, 0x00, 0x11, 0x94]); // TTL=4500
        let rdata = dns_name(ptr_target);
        p.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
        p.extend_from_slice(&rdata);
        p
    }

    fn mdns_a_response(host: &str, ip: [u8; 4]) -> Vec<u8> {
        let mut p = vec![
            0x00, 0x00, 0x84, 0x00, // id + flags: response/authoritative
            0x00, 0x00, 0x00, 0x01, // qdcount=0, ancount=1
            0x00, 0x00, 0x00, 0x00, // nscount=0, arcount=0
        ];
        p.extend_from_slice(&dns_name(host));
        p.extend_from_slice(&[0x00, 0x01, 0x00, 0x01]); // A IN
        p.extend_from_slice(&[0x00, 0x00, 0x00, 0x78]); // TTL=120
        p.extend_from_slice(&[0x00, 0x04]); // rdlength=4
        p.extend_from_slice(&ip);
        p
    }

    fn soap(body: &str) -> Vec<u8> {
        let mut s = String::from(
            r#"<?xml version="1.0"?><s:Envelope "#,
        );
        s.push_str(r#"xmlns:s="http://www.w3.org/2003/05/soap-envelope" "#);
        s.push_str(r#"xmlns:wsd="http://schemas.xmlsoap.org/ws/2005/04/discovery">"#);
        s.push_str("<s:Body>");
        s.push_str(body);
        s.push_str("</s:Body></s:Envelope>");
        s.into_bytes()
    }

    fn find_tx(out: &[BronzeEvent]) -> Option<&ProtocolTransaction> {
        out.iter().find_map(|e| {
            if let BronzeEventFamily::ProtocolTransaction(ref tx) = e.family {
                Some(tx)
            } else {
                None
            }
        })
    }

    fn find_obs(out: &[BronzeEvent]) -> Option<&AssetObservation> {
        out.iter().find_map(|e| {
            if let BronzeEventFamily::AssetObservation(ref obs) = e.family {
                Some(obs)
            } else {
                None
            }
        })
    }

    // ── Test 1: mDNS query → operation = "mdns_query" ────────────

    #[test]
    fn test_mdns_query_operation() {
        let pkt = mdns_query("_services._dns-sd._udp.local");
        let mut out = Vec::new();
        decode_mdns(&mdns_chunk(&pkt), &mut out);

        let tx = find_tx(&out).expect("ProtocolTransaction");
        assert_eq!(tx.operation, "mdns_query");
        assert_eq!(tx.status, "observed");
        assert!(tx.object_refs.iter().any(|r| r.contains("_services._dns-sd._udp.local")));
        assert_eq!(tx.attributes["qdcount"], "1");
        assert_eq!(tx.attributes["ancount"], "0");
    }

    // ── Test 2: mDNS PTR response → "mdns_response" + AssetObservation ──

    #[test]
    fn test_mdns_ptr_response() {
        let pkt = mdns_ptr_response("_http._tcp.local", "My Camera._http._tcp.local");
        let mut out = Vec::new();
        decode_mdns(&mdns_chunk(&pkt), &mut out);

        assert_eq!(find_tx(&out).expect("tx").operation, "mdns_response");

        let obs = find_obs(&out).expect("AssetObservation for PTR");
        assert_eq!(obs.role.as_deref(), Some("mdns_service"));
        assert!(obs.identifiers["service_name"].contains("_http._tcp.local"));
        assert!(obs.hostnames.iter().any(|h| h.contains("My Camera")));
    }

    // ── Test 3: mDNS A response → AssetObservation with resolved_address ──

    #[test]
    fn test_mdns_a_response() {
        let pkt = mdns_a_response("hmi-panel.local", [10, 0, 1, 42]);
        let mut out = Vec::new();
        decode_mdns(&mdns_chunk(&pkt), &mut out);

        let obs = find_obs(&out).expect("AssetObservation for A");
        assert!(obs.hostnames.iter().any(|h| h == "hmi-panel.local"));
        assert_eq!(obs.identifiers["resolved_address"], "10.0.1.42");
    }

    // ── Test 4: WSD Probe → "wsd_probe" ─────────────────────────

    #[test]
    fn test_wsd_probe() {
        let pkt = soap(r#"<wsd:Probe><wsd:Types>wsdp:Device</wsd:Types></wsd:Probe>"#);
        let mut out = Vec::new();
        decode_wsd(&wsd_chunk(&pkt), &mut out);

        let tx = find_tx(&out).expect("tx");
        assert_eq!(tx.operation, "wsd_probe");
        assert_eq!(tx.status, "observed");
    }

    // ── Test 5: WSD ProbeMatch with XAddrs → AssetObservation ───

    #[test]
    fn test_wsd_probe_match_with_xaddrs() {
        let pkt = soap(concat!(
            "<wsd:ProbeMatches><wsd:ProbeMatch>",
            "<wsd:Types>dn:NetworkVideoTransmitter</wsd:Types>",
            "<wsd:XAddrs>http://1.2.3.4/onvif/device_service</wsd:XAddrs>",
            "</wsd:ProbeMatch></wsd:ProbeMatches>"
        ));
        let mut out = Vec::new();
        decode_wsd(&wsd_chunk(&pkt), &mut out);

        assert_eq!(find_tx(&out).expect("tx").operation, "wsd_probe_match");

        let obs = find_obs(&out).expect("AssetObservation for ProbeMatch");
        assert_eq!(obs.role.as_deref(), Some("wsd_endpoint"));
        let xaddrs = &obs.identifiers["xaddrs"];
        assert!(xaddrs.contains("http://1.2.3.4/"), "got: {xaddrs}");
    }

    // ── Test 6: WSD Hello → "wsd_hello" + AssetObservation ──────

    #[test]
    fn test_wsd_hello() {
        let pkt = soap(concat!(
            "<wsd:Hello>",
            "<wsd:Types>wsdp:Device</wsd:Types>",
            "<wsd:XAddrs>http://192.168.0.5/wsd</wsd:XAddrs>",
            "</wsd:Hello>"
        ));
        let mut out = Vec::new();
        decode_wsd(&wsd_chunk(&pkt), &mut out);

        assert_eq!(find_tx(&out).expect("tx").operation, "wsd_hello");
        assert!(find_obs(&out).is_some(), "Hello with XAddrs should produce AssetObservation");
    }

    // ── Test 7: Unknown WSD action → "wsd_unknown" ───────────────

    #[test]
    fn test_wsd_unknown() {
        let pkt =
            b"<?xml version=\"1.0\"?><s:Envelope><s:Body><custom:Action/></s:Body></s:Envelope>";
        let mut out = Vec::new();
        decode_wsd(&wsd_chunk(pkt), &mut out);

        assert_eq!(find_tx(&out).expect("tx").operation, "wsd_unknown");
    }
}
