//! Foundation Fieldbus HSE (High Speed Ethernet) recognition decoder.
//!
//! IMPORTANT — SPEC STATUS: Foundation Fieldbus HSE wire spec (FF-588/FF-589)
//! is member-restricted. This decoder is honest port-based recognition +
//! magic-byte fingerprinting + AssetObservation. Deep FDA / FMS parsing is
//! not feasible without spec access.
//!
//! Ports: 1089 (Annunciation), 1090 (FMS), 1091 (System Management).
//! Magic strings searched in first 16 bytes: "FOUNDATION", "FF-HSE".
//! Header layout (Wireshark packet-fcp.c reference): byte 0 = version,
//! byte 1 = message_type, bytes 2..4 = declared_length BE, bytes 4+ = opaque FDA payload.

use std::collections::{BTreeMap, HashSet};
use std::net::IpAddr;

use crate::bronze::{
    AssetObservation, BronzeEvent, BronzeEventFamily, ProtocolTransaction, TransportProtocol,
};
use crate::engine::{build_envelope, new_event, DecoderInterest, SessionDecoder, StreamChunk};

const HSE_HEADER_MIN: usize = 4;
const MAGIC_SEARCH_LIMIT: usize = 16;
const MAGIC_PATTERNS: &[&[u8]] = &[b"FOUNDATION", b"FF-HSE"];

const PORT_ANNUNCIATION: u16 = 1089;
const PORT_FMS: u16 = 1090;
const PORT_SYSTEM_MGMT: u16 = 1091;

fn ff_function(port: u16) -> &'static str {
    match port {
        PORT_ANNUNCIATION => "annunciation",
        PORT_FMS => "fms",
        PORT_SYSTEM_MGMT => "system_management",
        _ => "unknown",
    }
}

fn operation_for_port(port: u16) -> &'static str {
    match port {
        PORT_ANNUNCIATION => "ff_hse_annunciation",
        PORT_FMS => "ff_hse_fms",
        PORT_SYSTEM_MGMT => "ff_hse_system_management",
        _ => "ff_hse_session",
    }
}

fn find_magic(haystack: &[u8]) -> Option<&'static str> {
    let window = &haystack[..haystack.len().min(MAGIC_SEARCH_LIMIT)];
    for &pattern in MAGIC_PATTERNS {
        if window.windows(pattern.len()).any(|w| w == pattern) {
            return Some(std::str::from_utf8(pattern).unwrap());
        }
    }
    None
}

fn hse_server(chunk: &StreamChunk<'_>) -> (u16, IpAddr) {
    const HSE_PORTS: &[u16] = &[PORT_ANNUNCIATION, PORT_FMS, PORT_SYSTEM_MGMT];
    if HSE_PORTS.contains(&chunk.context.dst_port) {
        (chunk.context.dst_port, chunk.context.dst_ip)
    } else {
        (chunk.context.src_port, chunk.context.src_ip)
    }
}

/// Recognition-only decoder for Foundation Fieldbus HSE traffic.
/// Emits one ProtocolTransaction per session and one AssetObservation per
/// unique (server_ip, port). No ParseAnomaly: the spec is undocumented.
#[derive(Default)]
pub(crate) struct FfHseDecoder {
    seen_sessions: HashSet<String>,
    seen_assets: HashSet<(String, u16)>,
}

impl SessionDecoder for FfHseDecoder {
    fn name(&self) -> &'static str {
        "ff_hse"
    }

    fn interest(&self) -> &'static [DecoderInterest] {
        &[
            DecoderInterest::TcpPort(PORT_ANNUNCIATION),
            DecoderInterest::TcpPort(PORT_FMS),
            DecoderInterest::TcpPort(PORT_SYSTEM_MGMT),
            DecoderInterest::UdpPort(PORT_ANNUNCIATION),
            DecoderInterest::UdpPort(PORT_FMS),
            DecoderInterest::UdpPort(PORT_SYSTEM_MGMT),
        ]
    }

    fn on_stream_chunk(&mut self, chunk: &StreamChunk<'_>, out: &mut Vec<BronzeEvent>) {
        self.handle(chunk, TransportProtocol::Tcp, out);
    }

    fn on_datagram(&mut self, chunk: &StreamChunk<'_>, out: &mut Vec<BronzeEvent>) {
        self.handle(chunk, TransportProtocol::Udp, out);
    }
}

impl FfHseDecoder {
    fn handle(
        &mut self,
        chunk: &StreamChunk<'_>,
        transport: TransportProtocol,
        out: &mut Vec<BronzeEvent>,
    ) {
        let (port, server_ip) = hse_server(chunk);
        let server_ip_str = server_ip.to_string();

        let asset_key = (server_ip_str.clone(), port);
        if !self.seen_assets.contains(&asset_key) {
            self.seen_assets.insert(asset_key);
            out.push(hse_asset_observation(chunk, transport, &server_ip_str, port));
        }

        if self.seen_sessions.contains(&chunk.session_key) {
            return;
        }
        self.seen_sessions.insert(chunk.session_key.clone());

        let p = chunk.payload;
        let mut attributes = BTreeMap::new();
        attributes.insert("port".to_string(), port.to_string());
        attributes.insert("transport".to_string(), transport.as_str().to_string());
        if let Some(v) = p.first().copied() {
            attributes.insert("version_byte".to_string(), v.to_string());
        }
        if let Some(mt) = p.get(1).copied() {
            attributes.insert("message_type_byte".to_string(), mt.to_string());
        }
        if p.len() >= HSE_HEADER_MIN {
            let dl = u16::from_be_bytes([p[2], p[3]]);
            attributes.insert("declared_length".to_string(), dl.to_string());
        }
        if let Some(magic) = find_magic(p) {
            attributes.insert("magic_seen".to_string(), magic.to_string());
        }

        let env = build_envelope(
            &chunk.context, chunk.interface_id, chunk.frame_index,
            chunk.timestamp, chunk.segment_hash, transport, Some("ff_hse"),
            chunk.captured_len, chunk.session_key.clone(),
        );
        out.push(new_event(
            chunk.capture_id.to_string(), env,
            BronzeEventFamily::ProtocolTransaction(ProtocolTransaction {
                operation: operation_for_port(port).to_string(),
                status: "observed".to_string(),
                request_summary: Some(format!("FF HSE {} on port {}", ff_function(port), port)),
                response_summary: None, object_refs: Vec::new(), values: Vec::new(),
                attributes, modbus: None, protocol_fields: None,
            }),
        ));
    }
}

fn hse_asset_observation(chunk: &StreamChunk<'_>, transport: TransportProtocol, server_ip: &str, port: u16) -> BronzeEvent {
    let env = build_envelope(
        &chunk.context, chunk.interface_id, chunk.frame_index,
        chunk.timestamp, chunk.segment_hash, transport, Some("ff_hse"),
        chunk.captured_len, chunk.session_key.clone(),
    );
    new_event(chunk.capture_id.to_string(), env, BronzeEventFamily::AssetObservation(AssetObservation {
        asset_key: server_ip.to_string(),
        role: Some("foundation_fieldbus_hse_node".to_string()),
        vendor: None, model: None, firmware: None, hostnames: Vec::new(),
        protocols: vec!["ff_hse".to_string()],
        identifiers: BTreeMap::from([
            ("port".to_string(), port.to_string()),
            ("ff_function".to_string(), ff_function(port).to_string()),
        ]),
    }))
}

inventory::submit!(crate::engine::decoders::DecoderRegistration {
    name: "ff_hse",
    factory: || Box::new(FfHseDecoder::default()),
});

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    use chrono::DateTime;

    use crate::engine::StreamChunk;
    use crate::registry::PacketContext;

    fn ctx(src_ip: [u8; 4], src_port: u16, dst_ip: [u8; 4], dst_port: u16) -> PacketContext {
        PacketContext {
            src_mac: [0; 6], dst_mac: [0; 6],
            src_ip: IpAddr::V4(Ipv4Addr::from(src_ip)),
            dst_ip: IpAddr::V4(Ipv4Addr::from(dst_ip)),
            src_port, dst_port, vlan_id: None, timestamp: 0,
        }
    }

    fn make_chunk<'a>(
        payload: &'a [u8],
        context: PacketContext,
        session: &str,
        transport: TransportProtocol,
    ) -> StreamChunk<'a> {
        let ip_proto = if transport == TransportProtocol::Tcp { Some(6u8) } else { Some(17u8) };
        StreamChunk {
            capture_id: "test-cap", segment_hash: "deadbeef",
            interface_id: 0, frame_index: 0,
            timestamp: DateTime::from_timestamp(1_700_000_000, 0).unwrap(),
            context, ethertype: 0x0800, ip_proto, llc: None,
            transport, payload,
            session_key: session.to_string(),
            captured_len: payload.len() as u64,
        }
    }
    fn tcp<'a>(p: &'a [u8], c: PacketContext, s: &str) -> StreamChunk<'a> {
        make_chunk(p, c, s, TransportProtocol::Tcp)
    }
    fn udp<'a>(p: &'a [u8], c: PacketContext, s: &str) -> StreamChunk<'a> {
        make_chunk(p, c, s, TransportProtocol::Udp)
    }

    fn transactions(events: &[BronzeEvent]) -> Vec<&ProtocolTransaction> {
        events.iter().filter_map(|e| match &e.family {
            BronzeEventFamily::ProtocolTransaction(t) => Some(t), _ => None,
        }).collect()
    }

    fn asset_observations(events: &[BronzeEvent]) -> Vec<&AssetObservation> {
        events.iter().filter_map(|e| match &e.family {
            BronzeEventFamily::AssetObservation(a) => Some(a), _ => None,
        }).collect()
    }

    fn hse_payload(version: u8, msg_type: u8, declared_len: u16, suffix: &[u8]) -> Vec<u8> {
        let mut b = vec![version, msg_type, (declared_len >> 8) as u8, declared_len as u8];
        b.extend_from_slice(suffix);
        b
    }

    #[test]
    fn tcp_1089_annunciation_and_asset_observation() {
        let mut dec = FfHseDecoder::default();
        let mut out = Vec::new();

        let payload = hse_payload(1, 2, 16, b"\x00\x01binary alarm data");
        let c = ctx([10, 0, 0, 5], 54321, [192, 168, 1, 10], PORT_ANNUNCIATION);
        dec.on_stream_chunk(&tcp(&payload, c, "sess-1"), &mut out);

        let txns = transactions(&out);
        assert_eq!(txns.len(), 1);
        assert_eq!(txns[0].operation, "ff_hse_annunciation");
        assert_eq!(txns[0].status, "observed");
        assert_eq!(txns[0].attributes.get("port").map(String::as_str), Some("1089"));
        assert_eq!(txns[0].attributes.get("transport").map(String::as_str), Some("tcp"));
        assert_eq!(txns[0].attributes.get("version_byte").map(String::as_str), Some("1"));
        assert_eq!(txns[0].attributes.get("message_type_byte").map(String::as_str), Some("2"));
        assert_eq!(txns[0].attributes.get("declared_length").map(String::as_str), Some("16"));

        let assets = asset_observations(&out);
        assert_eq!(assets.len(), 1);
        assert_eq!(assets[0].role.as_deref(), Some("foundation_fieldbus_hse_node"));
        assert_eq!(assets[0].vendor, None);
        assert_eq!(assets[0].identifiers.get("ff_function").map(String::as_str), Some("annunciation"));
        assert_eq!(assets[0].identifiers.get("port").map(String::as_str), Some("1089"));
    }

    #[test]
    fn udp_1090_fms_transport_udp() {
        let mut dec = FfHseDecoder::default();
        let mut out = Vec::new();

        let payload = hse_payload(1, 5, 32, b"\xff\xfe device data");
        let c = ctx([10, 0, 0, 20], 60001, [10, 0, 0, 50], PORT_FMS);
        dec.on_datagram(&udp(&payload, c, "sess-2"), &mut out);

        let txns = transactions(&out);
        assert_eq!(txns.len(), 1);
        assert_eq!(txns[0].operation, "ff_hse_fms");
        assert_eq!(txns[0].attributes.get("transport").map(String::as_str), Some("udp"));
        assert_eq!(txns[0].attributes.get("port").map(String::as_str), Some("1090"));

        let assets = asset_observations(&out);
        assert_eq!(assets.len(), 1);
        assert_eq!(assets[0].identifiers.get("ff_function").map(String::as_str), Some("fms"));
    }

    #[test]
    fn port_1091_foundation_magic_captured() {
        let mut dec = FfHseDecoder::default();
        let mut out = Vec::new();

        let mut payload = hse_payload(1, 1, 20, b"FOUNDATION\x00\x01\x02");
        payload.truncate(16);

        let c = ctx([172, 16, 0, 1], 52000, [172, 16, 0, 200], PORT_SYSTEM_MGMT);
        dec.on_stream_chunk(&tcp(&payload, c, "sess-3"), &mut out);

        let txns = transactions(&out);
        assert_eq!(txns.len(), 1);
        assert_eq!(txns[0].operation, "ff_hse_system_management");
        assert_eq!(
            txns[0].attributes.get("magic_seen").map(String::as_str),
            Some("FOUNDATION")
        );
    }

    #[test]
    fn second_chunk_same_session_no_duplicate_transaction() {
        let mut dec = FfHseDecoder::default();
        let mut out = Vec::new();

        let payload1 = hse_payload(1, 3, 8, b"\x00binary");
        let c1 = ctx([10, 1, 0, 5], 55000, [10, 1, 0, 100], PORT_ANNUNCIATION);
        dec.on_stream_chunk(&tcp(&payload1, c1, "sess-4"), &mut out);

        let payload2 = hse_payload(1, 3, 8, b"FF-HSE\x00more data");
        let c2 = ctx([10, 1, 0, 5], 55000, [10, 1, 0, 100], PORT_ANNUNCIATION);
        dec.on_stream_chunk(&tcp(&payload2, c2, "sess-4"), &mut out);

        let txns = transactions(&out);
        assert_eq!(txns.len(), 1, "ProtocolTransaction emitted exactly once per session");
        assert!(txns[0].attributes.get("magic_seen").is_none());
    }

    #[test]
    fn two_server_ips_two_asset_observations() {
        let mut dec = FfHseDecoder::default();
        let mut out = Vec::new();

        let payload = hse_payload(1, 2, 12, b"\x00\x01\x02\x03");
        let c_a = ctx([10, 0, 0, 1], 50000, [192, 168, 10, 1], PORT_ANNUNCIATION);
        dec.on_stream_chunk(&tcp(&payload, c_a, "sess-5a"), &mut out);
        let c_b = ctx([10, 0, 0, 2], 50001, [192, 168, 10, 2], PORT_ANNUNCIATION);
        dec.on_stream_chunk(&tcp(&payload, c_b, "sess-5b"), &mut out);

        let assets = asset_observations(&out);
        assert_eq!(assets.len(), 2, "one AssetObservation per distinct server IP");

        let ips: Vec<&str> = assets.iter().map(|a| a.asset_key.as_str()).collect();
        assert!(ips.contains(&"192.168.10.1"));
        assert!(ips.contains(&"192.168.10.2"));

        for a in &assets {
            assert_eq!(a.role.as_deref(), Some("foundation_fieldbus_hse_node"));
            assert_eq!(a.vendor, None);
            assert_eq!(
                a.identifiers.get("ff_function").map(String::as_str),
                Some("annunciation")
            );
        }
    }

    #[test]
    fn ff_hse_magic_string_captured() {
        let mut dec = FfHseDecoder::default();
        let mut out = Vec::new();

        let payload = hse_payload(1, 0, 18, b"FF-HSE\x00announce");
        let c = ctx([10, 2, 0, 1], 51000, [10, 2, 0, 50], PORT_ANNUNCIATION);
        dec.on_stream_chunk(&tcp(&payload, c, "sess-6"), &mut out);

        let txns = transactions(&out);
        assert_eq!(txns.len(), 1);
        assert_eq!(
            txns[0].attributes.get("magic_seen").map(String::as_str),
            Some("FF-HSE")
        );
    }
}
