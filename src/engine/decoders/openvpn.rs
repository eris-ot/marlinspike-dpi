//! OpenVPN session decoder — control-channel handshake visibility for OT/ICS
//! remote-access tunnels.
//!
//! Every OpenVPN packet begins with a 1-byte opcode/key_id field packed as:
//!   bits 7..3 (high 5 bits) = opcode (>> 3)
//!   bits 2..0 (low  3 bits) = key_id (& 0x07)
//!
//! Bytes 1..=8 carry the 8-byte sender Session ID. TCP transport prefixes each
//! packet with a 2-byte big-endian length header; this decoder buffers per-session
//! bytes and extracts complete packets before parsing.

use std::collections::{BTreeMap, HashMap, HashSet};

use crate::bronze::{
    AssetObservation, BronzeEvent, BronzeEventFamily, ProtocolTransaction, TransportProtocol,
};
use crate::engine::{
    build_envelope, new_event, parse_anomaly_event, DecoderInterest, SessionDecoder, StreamChunk,
};

// ── Opcode constants ─────────────────────────────────────────────────────────

const P_CONTROL_HARD_RESET_CLIENT_V1: u8 = 1;
const P_CONTROL_HARD_RESET_SERVER_V1: u8 = 2;
const P_CONTROL_SOFT_RESET_V1:        u8 = 3;
const P_CONTROL_V1:                   u8 = 4;
const P_ACK_V1:                       u8 = 5;
const P_DATA_V1:                      u8 = 6;
const P_CONTROL_HARD_RESET_CLIENT_V2: u8 = 7;
const P_CONTROL_HARD_RESET_SERVER_V2: u8 = 8;
const P_DATA_V2:                      u8 = 9;
const P_CONTROL_HARD_RESET_CLIENT_V3: u8 = 10;
const P_CONTROL_WKC_V1:               u8 = 11;

const OPCODE_MAX_KNOWN: u8 = 11;

/// Minimum packet size: 1 byte opcode + 8 bytes session_id = 9 bytes.
const MIN_PACKET_LEN: usize = 9;

// ── Operation string lookup ──────────────────────────────────────────────────

fn opcode_to_operation(opcode: u8) -> String {
    match opcode {
        P_CONTROL_HARD_RESET_CLIENT_V1 => "openvpn_hard_reset_client_v1".to_string(),
        P_CONTROL_HARD_RESET_SERVER_V1 => "openvpn_hard_reset_server_v1".to_string(),
        P_CONTROL_SOFT_RESET_V1        => "openvpn_soft_reset".to_string(),
        P_CONTROL_V1                   => "openvpn_control".to_string(),
        P_ACK_V1                       => "openvpn_ack".to_string(),
        P_DATA_V1                      => "openvpn_data".to_string(),
        P_CONTROL_HARD_RESET_CLIENT_V2 => "openvpn_hard_reset_client_v2".to_string(),
        P_CONTROL_HARD_RESET_SERVER_V2 => "openvpn_hard_reset_server_v2".to_string(),
        P_DATA_V2                      => "openvpn_data_v2".to_string(),
        P_CONTROL_HARD_RESET_CLIENT_V3 => "openvpn_hard_reset_client_v3".to_string(),
        P_CONTROL_WKC_V1               => "openvpn_wkc".to_string(),
        n                              => format!("openvpn_unknown_opcode_{n}"),
    }
}

/// Returns true for opcodes that initiate a new session (hard resets, either side).
#[inline]
fn is_hard_reset(opcode: u8) -> bool {
    matches!(
        opcode,
        P_CONTROL_HARD_RESET_CLIENT_V1
            | P_CONTROL_HARD_RESET_SERVER_V1
            | P_CONTROL_HARD_RESET_CLIENT_V2
            | P_CONTROL_HARD_RESET_SERVER_V2
            | P_CONTROL_HARD_RESET_CLIENT_V3
    )
}

// ── Core packet parser ───────────────────────────────────────────────────────

/// Parse a single OpenVPN packet (without any TCP length prefix) and push
/// events to `out`. `transport` is passed through to attributes and envelope.
fn parse_openvpn_packet(
    pkt: &[u8],
    transport: TransportProtocol,
    transport_str: &'static str,
    chunk: &StreamChunk<'_>,
    seen_sessions: &mut HashSet<[u8; 8]>,
    out: &mut Vec<BronzeEvent>,
) {
    let build_env = |tp: TransportProtocol| {
        build_envelope(
            &chunk.context,
            chunk.interface_id,
            chunk.frame_index,
            chunk.timestamp,
            chunk.segment_hash,
            tp,
            Some("openvpn"),
            chunk.captured_len,
            chunk.session_key.clone(),
        )
    };

    // Minimum length gate: opcode byte + 8-byte session_id.
    if pkt.len() <= MIN_PACKET_LEN - 1 {
        out.push(parse_anomaly_event(
            chunk.capture_id.to_string(),
            build_env(transport),
            "openvpn",
            "low",
            "packet too short for opcode + session_id",
            pkt,
        ));
        return;
    }

    // Unpack the opcode/key_id byte.
    // High 5 bits = opcode; low 3 bits = key_id.
    let first    = pkt[0];
    let opcode   = first >> 3;
    let key_id   = first & 0x07;

    // Unknown opcode guard (> 11 is outside the defined table).
    if opcode > OPCODE_MAX_KNOWN {
        out.push(parse_anomaly_event(
            chunk.capture_id.to_string(),
            build_env(transport),
            "openvpn",
            "low",
            &format!("unrecognized openvpn opcode {opcode}"),
            pkt,
        ));
        return;
    }

    // Extract the 8-byte session ID (bytes 1..=8).
    let session_id_bytes: [u8; 8] = pkt[1..9].try_into().expect("length already checked");
    let session_id_hex = hex::encode(session_id_bytes);

    let operation      = opcode_to_operation(opcode);
    let payload_length = pkt.len();

    let mut attributes = BTreeMap::new();
    attributes.insert("opcode".to_string(),          opcode.to_string());
    attributes.insert("key_id".to_string(),          key_id.to_string());
    attributes.insert("session_id_hex".to_string(),  session_id_hex.clone());
    attributes.insert("transport".to_string(),       transport_str.to_string());
    attributes.insert("payload_length".to_string(),  payload_length.to_string());

    let envelope = build_env(transport);

    out.push(new_event(
        chunk.capture_id.to_string(),
        envelope.clone(),
        BronzeEventFamily::ProtocolTransaction(ProtocolTransaction {
            operation: operation.clone(),
            status: "observed".to_string(),
            request_summary: Some(format!(
                "OpenVPN opcode={opcode} key_id={key_id} session={session_id_hex}"
            )),
            response_summary: None,
            object_refs: vec![],
            values: vec![],
            attributes,
            modbus: None,
            protocol_fields: None,
        }),
    ));

    // Emit AssetObservation once per unique session_id on any hard-reset packet.
    if is_hard_reset(opcode) && seen_sessions.insert(session_id_bytes) {
        let mut identifiers = BTreeMap::new();
        identifiers.insert(
            "openvpn_session_id".to_string(),
            session_id_hex.clone(),
        );
        identifiers.insert("ip".to_string(), chunk.context.src_ip.to_string());

        out.push(new_event(
            chunk.capture_id.to_string(),
            envelope,
            BronzeEventFamily::AssetObservation(AssetObservation {
                asset_key:   chunk.context.src_ip.to_string(),
                role:        Some("openvpn_endpoint".to_string()),
                vendor:      None,
                model:       None,
                firmware:    None,
                hostnames:   vec![],
                protocols:   vec!["openvpn".to_string()],
                identifiers,
            }),
        ));
    }
}

// ── Decoder ──────────────────────────────────────────────────────────────────

#[derive(Default)]
pub(crate) struct OpenVpnDecoder {
    /// Tracks session IDs for which we have already emitted an AssetObservation,
    /// deduplicated per decoder lifetime (one per DpiEngine session).
    seen_sessions: HashSet<[u8; 8]>,
    /// Per-session TCP byte buffers, keyed by session_key.
    tcp_buffers: HashMap<String, Vec<u8>>,
}

impl SessionDecoder for OpenVpnDecoder {
    fn name(&self) -> &'static str {
        "openvpn"
    }

    fn interest(&self) -> &'static [DecoderInterest] {
        // UDP/1194 is the canonical OpenVPN port; TCP/1194 for TCP mode.
        // Deployments on 443 or custom ports can be addressed via port-agnostic
        // shape recognition in a future pass.
        &[
            DecoderInterest::UdpPort(1194),
            DecoderInterest::TcpPort(1194),
        ]
    }

    /// UDP datagrams: each is a standalone OpenVPN packet (no length prefix).
    fn on_datagram(&mut self, chunk: &StreamChunk<'_>, out: &mut Vec<BronzeEvent>) {
        parse_openvpn_packet(
            chunk.payload,
            TransportProtocol::Udp,
            "udp",
            chunk,
            &mut self.seen_sessions,
            out,
        );
    }

    /// TCP stream chunks: buffer bytes per session, then extract complete
    /// OpenVPN packets using the 2-byte BE length prefix.
    fn on_stream_chunk(&mut self, chunk: &StreamChunk<'_>, out: &mut Vec<BronzeEvent>) {
        let buf = self
            .tcp_buffers
            .entry(chunk.session_key.clone())
            .or_default();
        buf.extend_from_slice(chunk.payload);

        // Extract and process as many complete packets as the buffer allows.
        loop {
            // Need at least 2 bytes for the length header.
            if buf.len() < 2 {
                break;
            }
            let pkt_len = u16::from_be_bytes([buf[0], buf[1]]) as usize;
            // Need 2-byte header + pkt_len bytes.
            if buf.len() < 2 + pkt_len {
                break;
            }
            // Extract the packet bytes (without the length header).
            let pkt: Vec<u8> = buf[2..2 + pkt_len].to_vec();
            // Drain consumed bytes from the front.
            buf.drain(..2 + pkt_len);

            parse_openvpn_packet(
                &pkt,
                TransportProtocol::Tcp,
                "tcp",
                chunk,
                &mut self.seen_sessions,
                out,
            );
        }
    }
}

// ── Inventory registration ────────────────────────────────────────────────────

inventory::submit!(crate::engine::decoders::DecoderRegistration {
    name: "openvpn",
    factory: || Box::new(OpenVpnDecoder::default()),
});

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};

    use chrono::{TimeZone, Utc};

    use super::*;
    use crate::bronze::BronzeEventFamily;
    use crate::engine::{DecoderInterest, StreamChunk};
    use crate::registry::PacketContext;

    fn ctx() -> PacketContext {
        PacketContext {
            src_mac: [0u8; 6],
            dst_mac: [0u8; 6],
            src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            dst_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            src_port: 12345,
            dst_port: 1194,
            vlan_id: None,
            timestamp: 1_700_000_000_000_000,
        }
    }

    fn udp_chunk<'a>(payload: &'a [u8]) -> StreamChunk<'a> {
        StreamChunk {
            capture_id: "test",
            segment_hash: "seg",
            interface_id: 0,
            frame_index: 0,
            timestamp: Utc.timestamp_opt(1_700_000_000, 0).unwrap(),
            context: ctx(),
            ethertype: 0x0800,
            ip_proto: Some(17),
            llc: None,
            transport: TransportProtocol::Udp,
            payload,
            session_key: "sk-udp".to_string(),
            captured_len: payload.len() as u64,
        }
    }

    fn tcp_chunk<'a>(payload: &'a [u8]) -> StreamChunk<'a> {
        StreamChunk {
            capture_id: "test",
            segment_hash: "seg",
            interface_id: 0,
            frame_index: 0,
            timestamp: Utc.timestamp_opt(1_700_000_000, 0).unwrap(),
            context: ctx(),
            ethertype: 0x0800,
            ip_proto: Some(6),
            llc: None,
            transport: TransportProtocol::Tcp,
            payload,
            session_key: "sk-tcp".to_string(),
            captured_len: payload.len() as u64,
        }
    }

    /// Build a minimal OpenVPN packet: opcode/key_id byte + 8-byte session_id
    /// + optional padding bytes to reach `total_len`.
    fn build_pkt(opcode: u8, key_id: u8, session_id: [u8; 8], total_len: usize) -> Vec<u8> {
        let mut pkt = Vec::with_capacity(total_len.max(9));
        pkt.push((opcode << 3) | (key_id & 0x07));
        pkt.extend_from_slice(&session_id);
        // Pad with zeroes to reach requested total_len.
        while pkt.len() < total_len {
            pkt.push(0x00);
        }
        pkt
    }

    fn get_tx(events: &[BronzeEvent]) -> Option<&ProtocolTransaction> {
        events.iter().find_map(|e| {
            if let BronzeEventFamily::ProtocolTransaction(ref tx) = e.family {
                Some(tx)
            } else {
                None
            }
        })
    }

    fn get_asset(events: &[BronzeEvent]) -> Option<&AssetObservation> {
        events.iter().find_map(|e| {
            if let BronzeEventFamily::AssetObservation(ref a) = e.family {
                Some(a)
            } else {
                None
            }
        })
    }

    fn get_anomaly(events: &[BronzeEvent]) -> Option<&crate::bronze::ParseAnomaly> {
        events.iter().find_map(|e| {
            if let BronzeEventFamily::ParseAnomaly(ref a) = e.family {
                Some(a)
            } else {
                None
            }
        })
    }

    // ── Test 1: UDP hard-reset client v2 (opcode=7, key_id=0) ───────────────

    #[test]
    fn test_udp_hard_reset_client_v2() {
        let session_id = [0xde, 0xad, 0xbe, 0xef, 0x01, 0x02, 0x03, 0x04];
        let pkt = build_pkt(7, 0, session_id, 14);

        let mut dec = OpenVpnDecoder::default();
        let mut evs = Vec::new();
        dec.on_datagram(&udp_chunk(&pkt), &mut evs);

        // Expect: ProtocolTransaction + AssetObservation.
        assert_eq!(evs.len(), 2, "expected tx + asset, got {}", evs.len());

        let tx = get_tx(&evs).unwrap();
        assert_eq!(tx.operation, "openvpn_hard_reset_client_v2");
        assert_eq!(tx.status, "observed");
        assert_eq!(tx.attributes["session_id_hex"], hex::encode(session_id));
        assert_eq!(tx.attributes["transport"], "udp");
        assert_eq!(tx.attributes["opcode"], "7");
        assert_eq!(tx.attributes["key_id"], "0");

        let asset = get_asset(&evs).unwrap();
        assert_eq!(asset.role.as_deref(), Some("openvpn_endpoint"));
        assert_eq!(
            asset.identifiers["openvpn_session_id"],
            hex::encode(session_id)
        );
    }

    // ── Test 2: UDP hard-reset server v2 (opcode=8) ──────────────────────────

    #[test]
    fn test_udp_hard_reset_server_v2() {
        let session_id = [0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88];
        let pkt = build_pkt(8, 0, session_id, 14);

        let mut dec = OpenVpnDecoder::default();
        let mut evs = Vec::new();
        dec.on_datagram(&udp_chunk(&pkt), &mut evs);

        let tx = get_tx(&evs).unwrap();
        assert_eq!(tx.operation, "openvpn_hard_reset_server_v2");
        assert_eq!(tx.status, "observed");
        assert_eq!(tx.attributes["transport"], "udp");

        // Server hard-reset also triggers an AssetObservation.
        assert!(get_asset(&evs).is_some(), "AssetObservation missing");
    }

    // ── Test 3: UDP data packet (opcode=6) ───────────────────────────────────

    #[test]
    fn test_udp_data_packet() {
        let session_id = [0xaa; 8];
        // Data packets can be arbitrary length — use 64 bytes.
        let pkt = build_pkt(6, 0, session_id, 64);

        let mut dec = OpenVpnDecoder::default();
        let mut evs = Vec::new();
        dec.on_datagram(&udp_chunk(&pkt), &mut evs);

        // Data packets: ProtocolTransaction only (no AssetObservation).
        assert_eq!(evs.len(), 1, "data packet should emit tx only, got {}", evs.len());

        let tx = get_tx(&evs).unwrap();
        assert_eq!(tx.operation, "openvpn_data");
        assert_eq!(tx.attributes["transport"], "udp");
        assert_eq!(tx.attributes["payload_length"], "64");
    }

    // ── Test 4: TCP with 2-byte length prefix wrapping a hard-reset client v2 ─

    #[test]
    fn test_tcp_hard_reset_client_v2_with_length_prefix() {
        let session_id = [0xca, 0xfe, 0xba, 0xbe, 0x00, 0x01, 0x02, 0x03];
        let inner = build_pkt(7, 0, session_id, 14); // 14-byte OpenVPN packet
        let inner_len = inner.len() as u16;

        // TCP framing: 2-byte BE length + packet bytes.
        let mut tcp_payload = Vec::new();
        tcp_payload.extend_from_slice(&inner_len.to_be_bytes());
        tcp_payload.extend_from_slice(&inner);

        let mut dec = OpenVpnDecoder::default();
        let mut evs = Vec::new();
        dec.on_stream_chunk(&tcp_chunk(&tcp_payload), &mut evs);

        assert_eq!(evs.len(), 2, "expected tx + asset, got {}", evs.len());

        let tx = get_tx(&evs).unwrap();
        assert_eq!(tx.operation, "openvpn_hard_reset_client_v2");
        assert_eq!(tx.attributes["transport"], "tcp");
        assert_eq!(tx.attributes["session_id_hex"], hex::encode(session_id));
    }

    // ── Test 5: Unknown opcode 25 → ParseAnomaly severity=low ───────────────

    #[test]
    fn test_unknown_opcode_parse_anomaly() {
        // opcode=25 is well beyond the max known value of 11.
        // Encode: (25 << 3) | 0 = 200 = 0xC8.
        let mut pkt = vec![0xC8u8]; // opcode=25, key_id=0
        pkt.extend_from_slice(&[0xAAu8; 8]); // session_id
        pkt.extend_from_slice(&[0x00u8; 5]); // padding

        let mut dec = OpenVpnDecoder::default();
        let mut evs = Vec::new();
        dec.on_datagram(&udp_chunk(&pkt), &mut evs);

        assert_eq!(evs.len(), 1, "expected exactly one anomaly event");
        let anomaly = get_anomaly(&evs).expect("ParseAnomaly missing");
        assert_eq!(anomaly.severity, "low");
        assert!(
            anomaly.reason.contains("25"),
            "reason should mention opcode 25, got: {}",
            anomaly.reason
        );
    }

    // ── Test 6: Packet too short (5 bytes) → ParseAnomaly severity=low ──────

    #[test]
    fn test_packet_too_short_parse_anomaly() {
        // 5 bytes is less than the required 9 (1 opcode + 8 session_id).
        let pkt = vec![0x38u8, 0x01, 0x02, 0x03, 0x04]; // opcode=7 byte + 4 junk bytes

        let mut dec = OpenVpnDecoder::default();
        let mut evs = Vec::new();
        dec.on_datagram(&udp_chunk(&pkt), &mut evs);

        assert_eq!(evs.len(), 1, "expected exactly one anomaly event");
        let anomaly = get_anomaly(&evs).expect("ParseAnomaly missing");
        assert_eq!(anomaly.severity, "low");
    }

    // ── Test 7: interest() returns both canonical ports ──────────────────────

    #[test]
    fn test_interest_ports() {
        let dec = OpenVpnDecoder::default();
        assert!(dec.interest().contains(&DecoderInterest::UdpPort(1194)));
        assert!(dec.interest().contains(&DecoderInterest::TcpPort(1194)));
    }

    // ── Test 8: AssetObservation deduplicated per session_id ─────────────────

    #[test]
    fn test_asset_observation_deduplicated() {
        let session_id = [0xFF; 8];
        let pkt = build_pkt(7, 0, session_id, 14);

        let mut dec = OpenVpnDecoder::default();
        let mut evs = Vec::new();

        // Feed the same hard-reset three times.
        dec.on_datagram(&udp_chunk(&pkt), &mut evs);
        dec.on_datagram(&udp_chunk(&pkt), &mut evs);
        dec.on_datagram(&udp_chunk(&pkt), &mut evs);

        let asset_count = evs
            .iter()
            .filter(|e| matches!(e.family, BronzeEventFamily::AssetObservation(_)))
            .count();
        assert_eq!(asset_count, 1, "AssetObservation must be emitted exactly once per session_id");
    }
}
