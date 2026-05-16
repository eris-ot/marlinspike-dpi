//! OSIsoft PI Server / PI Web API recognition decoder.
//!
//! OSIsoft PI Server protocol is proprietary and undocumented. This decoder
//! does port-based recognition plus byte-pattern fingerprinting of known magic
//! strings. Deep PDU parsing is not feasible without vendor documentation.
//!
//! Ports: 5450 (PI Net Manager), 5460–5462 (PI Connector / AF variants).
//! Magic strings searched in first 256 bytes: "PINETMGR", "PISystem", "PI-API", "AFServer".
//! Version pattern in first 512 bytes: "3.4.<digits>.<digits>".
//!
//! Emits one ProtocolTransaction + one AssetObservation per session/server on
//! first matching chunk. Subsequent chunks are silently skipped.

use std::collections::{BTreeMap, HashSet};
use std::net::IpAddr;

use crate::bronze::{
    AssetObservation, BronzeEvent, BronzeEventFamily, ProtocolTransaction, TransportProtocol,
};
use crate::engine::{DecoderInterest, SessionDecoder, StreamChunk, build_envelope, new_event};

const MAGIC_PATTERNS: &[&[u8]] = &[b"PINETMGR", b"PISystem", b"PI-API", b"AFServer"];
const MAGIC_SEARCH_LIMIT: usize = 256;
const VERSION_SEARCH_LIMIT: usize = 512;

/// Returns the first magic pattern found in `haystack[..limit]`, or `None`.
fn find_magic(haystack: &[u8], limit: usize) -> Option<&'static str> {
    let window = &haystack[..haystack.len().min(limit)];
    for &pattern in MAGIC_PATTERNS {
        if window.windows(pattern.len()).any(|w| w == pattern) {
            return Some(std::str::from_utf8(pattern).unwrap()); // all are valid UTF-8
        }
    }
    None
}

/// Scans `haystack[..limit]` for a PI Server version string of the form
/// `3.4.<digits>.<digits>` (Major=3, Minor=4 across the PI Server 3.x line).
fn find_version(haystack: &[u8], limit: usize) -> Option<String> {
    let window = &haystack[..haystack.len().min(limit)];
    let prefix = b"3.4.";
    for start in 0..window.len().saturating_sub(prefix.len()) {
        if &window[start..start + prefix.len()] != prefix {
            continue;
        }
        // Consume digits after "3.4."
        let mut pos = start + prefix.len();
        let build_start = pos;
        while pos < window.len() && window[pos].is_ascii_digit() {
            pos += 1;
        }
        if pos == build_start || pos >= window.len() || window[pos] != b'.' {
            continue;
        }
        pos += 1; // skip the separating dot
        let patch_start = pos;
        while pos < window.len() && window[pos].is_ascii_digit() {
            pos += 1;
        }
        if pos == patch_start {
            continue;
        }
        return std::str::from_utf8(&window[start..pos])
            .ok()
            .map(str::to_string);
    }
    None
}

fn connector_kind(port: u16) -> &'static str {
    if port == 5450 {
        "pi_net_manager"
    } else {
        "pi_connector"
    }
}

/// Returns `(server_port, server_ip)` — the well-known PI port side of the flow.
fn pi_server(chunk: &StreamChunk<'_>) -> (u16, IpAddr) {
    const PI_PORTS: &[u16] = &[5450, 5460, 5461, 5462];
    if PI_PORTS.contains(&chunk.context.dst_port) {
        (chunk.context.dst_port, chunk.context.dst_ip)
    } else {
        (chunk.context.src_port, chunk.context.src_ip)
    }
}

// ── Decoder ──────────────────────────────────────────────────────────────────

/// Recognition-only decoder for OSIsoft PI Server / PI Web API binary traffic.
/// State tracks emitted sessions (one-shot ProtocolTransaction) and emitted
/// server endpoints (one-shot AssetObservation per unique server IP+port).
#[derive(Default)]
pub(crate) struct OsiPiDecoder {
    /// Sessions that have already had a ProtocolTransaction emitted.
    seen_sessions: HashSet<String>,
    /// (server_ip_string, port) pairs that have had an AssetObservation emitted.
    seen_assets: HashSet<(String, u16)>,
}

impl SessionDecoder for OsiPiDecoder {
    fn name(&self) -> &'static str {
        "osi_pi"
    }

    fn interest(&self) -> &'static [DecoderInterest] {
        &[
            DecoderInterest::TcpPort(5450),
            DecoderInterest::TcpPort(5460),
            DecoderInterest::TcpPort(5461),
            DecoderInterest::TcpPort(5462),
        ]
    }

    fn on_stream_chunk(&mut self, chunk: &StreamChunk<'_>, out: &mut Vec<BronzeEvent>) {
        let (port, server_ip) = pi_server(chunk);
        let server_ip_str = server_ip.to_string();

        // AssetObservation: once per unique (server_ip, port); port alone is authoritative.
        let asset_key = (server_ip_str.clone(), port);
        if !self.seen_assets.contains(&asset_key) {
            self.seen_assets.insert(asset_key);
            out.push(pi_asset_observation(chunk, &server_ip_str, port));
        }

        // ProtocolTransaction: one per session, only when a magic string is present.
        // Undocumented protocol — do not manufacture signals from port alone.
        if self.seen_sessions.contains(&chunk.session_key) {
            return;
        }
        let Some(magic) = find_magic(chunk.payload, MAGIC_SEARCH_LIMIT) else {
            return;
        };
        self.seen_sessions.insert(chunk.session_key.clone());

        let mut attributes = BTreeMap::from([
            ("port".to_string(), port.to_string()),
            ("magic_seen".to_string(), magic.to_string()),
            (
                "connector_kind".to_string(),
                connector_kind(port).to_string(),
            ),
        ]);
        if let Some(v) = find_version(chunk.payload, VERSION_SEARCH_LIMIT) {
            attributes.insert("version_string".to_string(), v);
        }

        let envelope = build_envelope(
            &chunk.context,
            chunk.interface_id,
            chunk.frame_index,
            chunk.timestamp,
            chunk.segment_hash,
            TransportProtocol::Tcp,
            Some("osi_pi"),
            chunk.captured_len,
            chunk.session_key.clone(),
        );
        out.push(new_event(
            chunk.capture_id.to_string(),
            envelope,
            BronzeEventFamily::ProtocolTransaction(ProtocolTransaction {
                operation: "pi_session_observed".to_string(),
                status: "observed".to_string(),
                request_summary: Some(format!("OSIsoft PI session on port {port}")),
                response_summary: None,
                object_refs: Vec::new(),
                values: Vec::new(),
                attributes,
                modbus: None,
                protocol_fields: None,
            }),
        ));
    }
}

fn pi_asset_observation(chunk: &StreamChunk<'_>, server_ip: &str, port: u16) -> BronzeEvent {
    let envelope = build_envelope(
        &chunk.context,
        chunk.interface_id,
        chunk.frame_index,
        chunk.timestamp,
        chunk.segment_hash,
        TransportProtocol::Tcp,
        Some("osi_pi"),
        chunk.captured_len,
        chunk.session_key.clone(),
    );
    new_event(
        chunk.capture_id.to_string(),
        envelope,
        BronzeEventFamily::AssetObservation(AssetObservation {
            asset_key: server_ip.to_string(),
            role: Some("osisoft_pi_server".to_string()),
            vendor: Some("OSIsoft".to_string()),
            model: None,
            firmware: None,
            hostnames: Vec::new(),
            protocols: vec!["osi_pi".to_string()],
            identifiers: BTreeMap::from([("port".to_string(), port.to_string())]),
        }),
    )
}

// ── Self-registration ─────────────────────────────────────────────────────────

inventory::submit!(crate::engine::decoders::DecoderRegistration {
    name: "osi_pi",
    factory: || Box::new(OsiPiDecoder::default()),
});

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    use chrono::Utc;

    use crate::engine::StreamChunk;
    use crate::registry::PacketContext;

    fn ctx(src_ip: [u8; 4], src_port: u16, dst_ip: [u8; 4], dst_port: u16) -> PacketContext {
        PacketContext {
            src_mac: [0; 6],
            dst_mac: [0; 6],
            src_ip: IpAddr::V4(Ipv4Addr::from(src_ip)),
            dst_ip: IpAddr::V4(Ipv4Addr::from(dst_ip)),
            src_port,
            dst_port,
            vlan_id: None,
            timestamp: 0,
        }
    }

    fn chunk<'a>(payload: &'a [u8], context: PacketContext, session: &str) -> StreamChunk<'a> {
        StreamChunk {
            capture_id: "test-cap",
            segment_hash: "deadbeef",
            interface_id: 0,
            frame_index: 0,
            timestamp: Utc::now(),
            context,
            ethertype: 0x0800,
            ip_proto: Some(6),
            llc: None,
            transport: TransportProtocol::Tcp,
            payload,
            session_key: session.to_string(),
            captured_len: payload.len() as u64,
        }
    }

    fn transactions(events: &[BronzeEvent]) -> Vec<&ProtocolTransaction> {
        events
            .iter()
            .filter_map(|e| match &e.family {
                BronzeEventFamily::ProtocolTransaction(t) => Some(t),
                _ => None,
            })
            .collect()
    }

    fn asset_observations(events: &[BronzeEvent]) -> Vec<&AssetObservation> {
        events
            .iter()
            .filter_map(|e| match &e.family {
                BronzeEventFamily::AssetObservation(a) => Some(a),
                _ => None,
            })
            .collect()
    }

    // 1. port 5450 + "PINETMGR" → ProtocolTransaction
    #[test]
    fn port_5450_pinetmgr_emits_transaction() {
        let mut dec = OsiPiDecoder::default();
        let mut out = Vec::new();

        // Client (ephemeral) → PI Net Manager (5450).
        let payload = b"PINETMGR\x00\x01\x02\x03some binary data follows";
        let c = ctx([10, 0, 0, 10], 52000, [192, 168, 1, 100], 5450);
        dec.on_stream_chunk(&chunk(payload, c, "sess-a"), &mut out);

        let txns = transactions(&out);
        assert_eq!(txns.len(), 1);
        assert_eq!(txns[0].operation, "pi_session_observed");
        assert_eq!(txns[0].status, "observed");
        assert_eq!(
            txns[0].attributes.get("magic_seen").map(String::as_str),
            Some("PINETMGR")
        );
        assert_eq!(
            txns[0].attributes.get("connector_kind").map(String::as_str),
            Some("pi_net_manager")
        );
        assert_eq!(
            txns[0].attributes.get("port").map(String::as_str),
            Some("5450")
        );
    }

    // 2. port 5460 + "PISystem 3.4.430.460" → version captured
    #[test]
    fn port_5460_pisystem_version_captured() {
        let mut dec = OsiPiDecoder::default();
        let mut out = Vec::new();

        let payload = b"\x00\x00PISystem 3.4.430.460\x00trailing bytes";
        let c = ctx([10, 0, 0, 20], 61000, [192, 168, 1, 101], 5460);
        dec.on_stream_chunk(&chunk(payload, c, "sess-b"), &mut out);

        let txns = transactions(&out);
        assert_eq!(txns.len(), 1);
        assert_eq!(txns[0].operation, "pi_session_observed");
        assert_eq!(
            txns[0].attributes.get("magic_seen").map(String::as_str),
            Some("PISystem")
        );
        assert_eq!(
            txns[0].attributes.get("version_string").map(String::as_str),
            Some("3.4.430.460")
        );
        assert_eq!(
            txns[0].attributes.get("connector_kind").map(String::as_str),
            Some("pi_connector")
        );
    }

    // 3. port 5450, no magic → no ProtocolTransaction; AssetObservation still emitted.
    // Port alone is authoritative for the asset; magic is required for the transaction.
    #[test]
    fn port_5450_no_magic_no_transaction() {
        let mut dec = OsiPiDecoder::default();
        let mut out = Vec::new();

        let payload = b"\x00\x00\x00\x00generic binary garbage with no pi magic";
        let c = ctx([10, 0, 0, 30], 53000, [192, 168, 1, 102], 5450);
        dec.on_stream_chunk(&chunk(payload, c, "sess-c"), &mut out);

        assert!(
            transactions(&out).is_empty(),
            "no ProtocolTransaction without magic bytes"
        );
        let assets = asset_observations(&out);
        assert_eq!(assets.len(), 1, "AssetObservation emitted on port match");
        assert_eq!(assets[0].vendor.as_deref(), Some("OSIsoft"));
    }

    // 4. Two distinct PI server destinations → two AssetObservations
    #[test]
    fn two_pi_servers_two_asset_observations() {
        let mut dec = OsiPiDecoder::default();
        let mut out = Vec::new();

        let payload_a = b"PINETMGR\x00\x01";
        let c_a = ctx([10, 0, 0, 1], 50000, [192, 168, 1, 10], 5450);
        dec.on_stream_chunk(&chunk(payload_a, c_a, "sess-d1"), &mut out);

        let payload_b = b"PISystem\x00\x01";
        let c_b = ctx([10, 0, 0, 2], 50001, [192, 168, 1, 20], 5450);
        dec.on_stream_chunk(&chunk(payload_b, c_b, "sess-d2"), &mut out);

        let assets = asset_observations(&out);
        assert_eq!(
            assets.len(),
            2,
            "each distinct PI server emits an AssetObservation"
        );
        let ips: Vec<&str> = assets.iter().map(|a| a.asset_key.as_str()).collect();
        assert!(ips.contains(&"192.168.1.10") && ips.contains(&"192.168.1.20"));
        for a in &assets {
            assert_eq!(a.role.as_deref(), Some("osisoft_pi_server"));
            assert_eq!(a.vendor.as_deref(), Some("OSIsoft"));
        }
    }

    // 5. Second chunk on same session → no duplicate ProtocolTransaction
    #[test]
    fn second_chunk_same_session_no_duplicate_transaction() {
        let mut dec = OsiPiDecoder::default();
        let mut out = Vec::new();

        let payload = b"PINETMGR\x00continuation";
        let c1 = ctx([10, 0, 0, 5], 54321, [10, 0, 0, 99], 5450);
        dec.on_stream_chunk(&chunk(payload, c1, "sess-e"), &mut out);

        // Different magic on chunk 2 — confirms it's the session gate, not the magic gate.
        let payload2 = b"PI-API\x00\x01\x02 second frame same session";
        let c2 = ctx([10, 0, 0, 5], 54321, [10, 0, 0, 99], 5450);
        dec.on_stream_chunk(&chunk(payload2, c2, "sess-e"), &mut out);

        let txns = transactions(&out);
        assert_eq!(
            txns.len(),
            1,
            "ProtocolTransaction emitted exactly once per session"
        );
        assert_eq!(
            txns[0].attributes.get("magic_seen").map(String::as_str),
            Some("PINETMGR")
        );
    }

    // 6. "AFServer" magic on port 5461
    #[test]
    fn afserver_magic_port_5461() {
        let mut dec = OsiPiDecoder::default();
        let mut out = Vec::new();

        let payload = b"\x00\xFFAFServer\x01connected";
        let c = ctx([10, 1, 0, 1], 60000, [10, 1, 0, 200], 5461);
        dec.on_stream_chunk(&chunk(payload, c, "sess-f"), &mut out);

        let txns = transactions(&out);
        assert_eq!(txns.len(), 1);
        assert_eq!(
            txns[0].attributes.get("magic_seen").map(String::as_str),
            Some("AFServer")
        );
        assert_eq!(
            txns[0].attributes.get("connector_kind").map(String::as_str),
            Some("pi_connector")
        );
        assert_eq!(
            txns[0].attributes.get("port").map(String::as_str),
            Some("5461")
        );
    }
}
