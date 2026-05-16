//! WireGuard session decoder — wire format per Donenfeld (2017).
//!
//! Recognition fingerprint: bytes 0..4 = type (1–4) + three mandatory zeros.
//! Non-zero reserved bytes → low-severity ParseAnomaly, not parsed as WireGuard.
//!
//! | type | name                  | total bytes |
//! |------|-----------------------|-------------|
//! | 0x01 | Handshake Initiation  | 148         |
//! | 0x02 | Handshake Response    | 92          |
//! | 0x03 | Cookie Reply          | 64          |
//! | 0x04 | Transport Data        | ≥ 32        |

use std::collections::{BTreeMap, HashSet};

use crate::bronze::{
    AssetObservation, BronzeEvent, BronzeEventFamily, ProtocolTransaction, TransportProtocol,
};
use crate::engine::{
    DecoderInterest, SessionDecoder, StreamChunk, build_envelope, new_event, parse_anomaly_event,
};

// ── Wire-format constants ─────────────────────────────────────────────────────

const LEN_INITIATION: usize = 148;
const LEN_RESPONSE: usize = 92;
const LEN_COOKIE: usize = 64;
const LEN_TRANSPORT_MIN: usize = 32;

// ── Decoder ───────────────────────────────────────────────────────────────────

/// Passive decoder for the WireGuard VPN protocol (UDP/51820 by default).
/// Tracks unique sender indices from Handshake Initiations for asset correlation.
/// Transport data is opaque — the AEAD payload cannot be decrypted passively.
#[derive(Default)]
pub(crate) struct WireGuardDecoder {
    seen_initiators: HashSet<u32>,
}

impl SessionDecoder for WireGuardDecoder {
    fn name(&self) -> &'static str {
        "wireguard"
    }

    /// UDP/51820 is the common default. WireGuard has no IANA-assigned port;
    /// deployments on other ports can be covered by future heuristic matching.
    fn interest(&self) -> &'static [DecoderInterest] {
        &[DecoderInterest::UdpPort(51820)]
    }

    fn on_datagram(&mut self, chunk: &StreamChunk<'_>, out: &mut Vec<BronzeEvent>) {
        let p = chunk.payload;

        let make_env = || {
            build_envelope(
                &chunk.context,
                chunk.interface_id,
                chunk.frame_index,
                chunk.timestamp,
                chunk.segment_hash,
                TransportProtocol::Udp,
                Some("wireguard"),
                chunk.captured_len,
                chunk.session_key.clone(),
            )
        };
        let anomaly = |reason: &str| {
            parse_anomaly_event(
                chunk.capture_id.to_string(),
                make_env(),
                self.name(),
                "low",
                reason,
                p,
            )
        };

        if p.len() < 4 {
            out.push(anomaly("wireguard packet too short (< 4 bytes)"));
            return;
        }

        // The three reserved bytes immediately after the type byte MUST be zero.
        // Non-zero reserved bytes → not WireGuard.
        if p[1] != 0 || p[2] != 0 || p[3] != 0 {
            out.push(anomaly("wireguard reserved bytes (1..4) are non-zero"));
            return;
        }

        let msg_type = p[0];

        match msg_type {
            0x01 => {
                if p.len() != LEN_INITIATION {
                    out.push(anomaly(&format!(
                        "wireguard initiation expected {LEN_INITIATION} bytes, got {}",
                        p.len()
                    )));
                    return;
                }
                let sender_index = u32::from_le_bytes(p[4..8].try_into().unwrap());
                let mut attrs = BTreeMap::new();
                attrs.insert("message_type".into(), "1".into());
                attrs.insert("sender_index".into(), fmt_idx(sender_index));
                attrs.insert("ephemeral_pubkey_hex".into(), hex::encode(&p[8..24]));
                attrs.insert("payload_length".into(), p.len().to_string());

                let env = make_env();
                out.push(new_event(
                    chunk.capture_id.to_string(),
                    env.clone(),
                    BronzeEventFamily::ProtocolTransaction(ProtocolTransaction {
                        operation: "wireguard_handshake_initiation".into(),
                        status: "observed".into(),
                        request_summary: Some(format!(
                            "WireGuard Handshake Initiation sender={}",
                            fmt_idx(sender_index)
                        )),
                        response_summary: None,
                        object_refs: vec![],
                        values: vec![],
                        attributes: attrs,
                        modbus: None,
                        protocol_fields: None,
                    }),
                ));

                if self.seen_initiators.insert(sender_index) {
                    out.push(new_event(
                        chunk.capture_id.to_string(),
                        env,
                        BronzeEventFamily::AssetObservation(AssetObservation {
                            asset_key: chunk.context.src_ip.to_string(),
                            role: Some("wireguard_initiator".into()),
                            vendor: None,
                            model: None,
                            firmware: None,
                            hostnames: vec![],
                            protocols: vec!["wireguard".into()],
                            identifiers: BTreeMap::from([
                                ("ip".into(), chunk.context.src_ip.to_string()),
                                ("wireguard_sender_index".into(), fmt_idx(sender_index)),
                            ]),
                        }),
                    ));
                }
            }

            0x02 => {
                if p.len() != LEN_RESPONSE {
                    out.push(anomaly(&format!(
                        "wireguard response expected {LEN_RESPONSE} bytes, got {}",
                        p.len()
                    )));
                    return;
                }
                let sender_index = u32::from_le_bytes(p[4..8].try_into().unwrap());
                let receiver_index = u32::from_le_bytes(p[8..12].try_into().unwrap());
                let mut attrs = BTreeMap::new();
                attrs.insert("message_type".into(), "2".into());
                attrs.insert("sender_index".into(), fmt_idx(sender_index));
                attrs.insert("receiver_index".into(), fmt_idx(receiver_index));
                attrs.insert("ephemeral_pubkey_hex".into(), hex::encode(&p[12..28]));
                attrs.insert("payload_length".into(), p.len().to_string());

                out.push(new_event(
                    chunk.capture_id.to_string(),
                    make_env(),
                    BronzeEventFamily::ProtocolTransaction(ProtocolTransaction {
                        operation: "wireguard_handshake_response".into(),
                        status: "observed".into(),
                        request_summary: Some(format!(
                            "WireGuard Handshake Response sender={} receiver={}",
                            fmt_idx(sender_index),
                            fmt_idx(receiver_index)
                        )),
                        response_summary: None,
                        object_refs: vec![],
                        values: vec![],
                        attributes: attrs,
                        modbus: None,
                        protocol_fields: None,
                    }),
                ));
            }

            0x03 => {
                if p.len() != LEN_COOKIE {
                    out.push(anomaly(&format!(
                        "wireguard cookie reply expected {LEN_COOKIE} bytes, got {}",
                        p.len()
                    )));
                    return;
                }
                let receiver_index = u32::from_le_bytes(p[4..8].try_into().unwrap());
                let mut attrs = BTreeMap::new();
                attrs.insert("message_type".into(), "3".into());
                attrs.insert("receiver_index".into(), fmt_idx(receiver_index));
                attrs.insert("payload_length".into(), p.len().to_string());

                out.push(new_event(
                    chunk.capture_id.to_string(),
                    make_env(),
                    BronzeEventFamily::ProtocolTransaction(ProtocolTransaction {
                        operation: "wireguard_cookie_reply".into(),
                        status: "observed".into(),
                        request_summary: Some(format!(
                            "WireGuard Cookie Reply receiver={}",
                            fmt_idx(receiver_index)
                        )),
                        response_summary: None,
                        object_refs: vec![],
                        values: vec![],
                        attributes: attrs,
                        modbus: None,
                        protocol_fields: None,
                    }),
                ));
            }

            0x04 => {
                if p.len() < LEN_TRANSPORT_MIN {
                    out.push(anomaly(&format!(
                        "wireguard transport expected ≥{LEN_TRANSPORT_MIN} bytes, got {}",
                        p.len()
                    )));
                    return;
                }
                let receiver_index = u32::from_le_bytes(p[4..8].try_into().unwrap());
                let counter = u64::from_le_bytes(p[8..16].try_into().unwrap());
                let mut attrs = BTreeMap::new();
                attrs.insert("message_type".into(), "4".into());
                attrs.insert("receiver_index".into(), fmt_idx(receiver_index));
                attrs.insert("counter".into(), counter.to_string());
                attrs.insert("payload_length".into(), p.len().to_string());

                out.push(new_event(
                    chunk.capture_id.to_string(),
                    make_env(),
                    BronzeEventFamily::ProtocolTransaction(ProtocolTransaction {
                        operation: "wireguard_transport".into(),
                        status: "observed".into(),
                        request_summary: Some(format!(
                            "WireGuard Transport receiver={} counter={counter}",
                            fmt_idx(receiver_index)
                        )),
                        response_summary: None,
                        object_refs: vec![],
                        values: vec![],
                        attributes: attrs,
                        modbus: None,
                        protocol_fields: None,
                    }),
                ));
            }

            n => {
                // Unknown type byte, but reserved bytes were zero.  Emit a
                // transaction so operators can triage; don't emit a ParseAnomaly
                // because the four-byte fingerprint was valid.
                let mut attrs = BTreeMap::new();
                attrs.insert("message_type".into(), n.to_string());
                attrs.insert("payload_length".into(), p.len().to_string());
                out.push(new_event(
                    chunk.capture_id.to_string(),
                    make_env(),
                    BronzeEventFamily::ProtocolTransaction(ProtocolTransaction {
                        operation: format!("wireguard_unknown_type_{n}"),
                        status: "observed".into(),
                        request_summary: Some(format!("WireGuard unknown type {n:#04x}")),
                        response_summary: None,
                        object_refs: vec![],
                        values: vec![],
                        attributes: attrs,
                        modbus: None,
                        protocol_fields: None,
                    }),
                ));
            }
        }
    }
}

/// Format a WireGuard session index as `0x........` (8 hex digits, lowercase).
#[inline]
fn fmt_idx(idx: u32) -> String {
    format!("{idx:#010x}")
}

// ── Inventory registration ────────────────────────────────────────────────────

inventory::submit!(crate::engine::decoders::DecoderRegistration {
    name: "wireguard",
    factory: || Box::new(WireGuardDecoder::default()),
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
            src_port: 51820,
            dst_port: 51820,
            vlan_id: None,
            timestamp: 1_700_000_000_000_000,
        }
    }
    fn chunk<'a>(payload: &'a [u8]) -> StreamChunk<'a> {
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
            session_key: "sk".to_string(),
            captured_len: payload.len() as u64,
        }
    }
    fn tx(evs: &[BronzeEvent]) -> Option<&ProtocolTransaction> {
        evs.iter().find_map(|e| {
            if let BronzeEventFamily::ProtocolTransaction(ref t) = e.family {
                Some(t)
            } else {
                None
            }
        })
    }
    fn anomaly(evs: &[BronzeEvent]) -> Option<&crate::bronze::ParseAnomaly> {
        evs.iter().find_map(|e| {
            if let BronzeEventFamily::ParseAnomaly(ref a) = e.family {
                Some(a)
            } else {
                None
            }
        })
    }
    fn initiation(sender_index: u32, ephemeral: [u8; 32]) -> Vec<u8> {
        let mut b = vec![0u8; 148];
        b[0] = 0x01;
        b[4..8].copy_from_slice(&sender_index.to_le_bytes());
        b[8..40].copy_from_slice(&ephemeral);
        b
    }
    fn response(sender: u32, receiver: u32, ephemeral: [u8; 32]) -> Vec<u8> {
        let mut b = vec![0u8; 92];
        b[0] = 0x02;
        b[4..8].copy_from_slice(&sender.to_le_bytes());
        b[8..12].copy_from_slice(&receiver.to_le_bytes());
        b[12..44].copy_from_slice(&ephemeral);
        b
    }
    fn cookie(receiver_index: u32) -> Vec<u8> {
        let mut b = vec![0u8; 64];
        b[0] = 0x03;
        b[4..8].copy_from_slice(&receiver_index.to_le_bytes());
        b
    }
    fn transport(receiver: u32, counter: u64, total_len: usize) -> Vec<u8> {
        let mut b = vec![0u8; total_len];
        b[0] = 0x04;
        b[4..8].copy_from_slice(&receiver.to_le_bytes());
        b[8..16].copy_from_slice(&counter.to_le_bytes());
        b
    }

    // ── 1. Handshake Initiation ───────────────────────────────────────────────

    #[test]
    fn test_handshake_initiation() {
        let sender: u32 = 0xDEAD_BEEF;
        let pkt = initiation(sender, [0xABu8; 32]);
        let mut dec = WireGuardDecoder::default();
        let mut evs = Vec::new();
        dec.on_datagram(&chunk(&pkt), &mut evs);

        assert_eq!(evs.len(), 2, "expected tx + asset");
        let t = tx(&evs).unwrap();
        assert_eq!(t.operation, "wireguard_handshake_initiation");
        assert_eq!(t.status, "observed");
        assert_eq!(t.attributes["sender_index"], fmt_idx(sender));
        assert_eq!(t.attributes["message_type"], "1");

        // Duplicate initiation must not emit a second AssetObservation.
        let mut evs2 = Vec::new();
        dec.on_datagram(&chunk(&pkt), &mut evs2);
        assert_eq!(
            evs2.len(),
            1,
            "duplicate sender_index must skip AssetObservation"
        );
    }

    // ── 2. Handshake Response ─────────────────────────────────────────────────

    #[test]
    fn test_handshake_response() {
        let sender: u32 = 0x0A0B_0C0D;
        let receiver: u32 = 0xDEAD_BEEF;
        let pkt = response(sender, receiver, [0xAAu8; 32]);
        let mut evs = Vec::new();
        WireGuardDecoder::default().on_datagram(&chunk(&pkt), &mut evs);

        assert_eq!(evs.len(), 1);
        let t = tx(&evs).unwrap();
        assert_eq!(t.operation, "wireguard_handshake_response");
        assert_eq!(t.attributes["receiver_index"], fmt_idx(receiver));
        assert_eq!(t.attributes["message_type"], "2");
    }

    // ── 3. Cookie Reply ───────────────────────────────────────────────────────

    #[test]
    fn test_cookie_reply() {
        let receiver: u32 = 0x1234_5678;
        let pkt = cookie(receiver);
        let mut evs = Vec::new();
        WireGuardDecoder::default().on_datagram(&chunk(&pkt), &mut evs);

        assert_eq!(evs.len(), 1);
        let t = tx(&evs).unwrap();
        assert_eq!(t.operation, "wireguard_cookie_reply");
        assert_eq!(t.attributes["receiver_index"], fmt_idx(receiver));
        assert_eq!(t.attributes["message_type"], "3");
    }

    // ── 4. Transport Data ─────────────────────────────────────────────────────

    #[test]
    fn test_transport_data() {
        let receiver: u32 = 0xCAFE_BABE;
        let counter: u64 = 0x42;
        let pkt = transport(receiver, counter, 96);
        let mut evs = Vec::new();
        WireGuardDecoder::default().on_datagram(&chunk(&pkt), &mut evs);

        assert_eq!(evs.len(), 1);
        let t = tx(&evs).unwrap();
        assert_eq!(t.operation, "wireguard_transport");
        assert_eq!(t.attributes["receiver_index"], fmt_idx(receiver));
        assert_eq!(t.attributes["counter"], counter.to_string());
        assert_eq!(t.attributes["message_type"], "4");
    }

    // ── 5. Non-zero reserved bytes → ParseAnomaly severity=low ───────────────

    #[test]
    fn test_nonzero_reserved_bytes() {
        let mut pkt = initiation(0x1234, [0u8; 32]);
        pkt[2] = 0xFF; // corrupt reserved byte

        let mut evs = Vec::new();
        WireGuardDecoder::default().on_datagram(&chunk(&pkt), &mut evs);

        assert_eq!(evs.len(), 1);
        let a = anomaly(&evs).expect("expected ParseAnomaly");
        assert_eq!(a.severity, "low");
        assert!(a.reason.contains("reserved bytes"), "reason: {}", a.reason);
    }

    // ── 6. Initiation with wrong length → ParseAnomaly severity=low ──────────

    #[test]
    fn test_initiation_wrong_length() {
        // 100 bytes with type=1 and valid reserved bytes
        let mut pkt = vec![0u8; 100];
        pkt[0] = 0x01;

        let mut evs = Vec::new();
        WireGuardDecoder::default().on_datagram(&chunk(&pkt), &mut evs);

        assert_eq!(evs.len(), 1);
        let a = anomaly(&evs).expect("expected ParseAnomaly");
        assert_eq!(a.severity, "low");
        assert!(a.reason.contains("148"), "reason: {}", a.reason);
    }

    // ── 7. interest() exposes UDP/51820 ──────────────────────────────────────

    #[test]
    fn test_interest_port() {
        assert!(
            WireGuardDecoder::default()
                .interest()
                .contains(&DecoderInterest::UdpPort(51820))
        );
    }

    // ── 8. AssetObservation has wireguard_sender_index identifier ─────────────

    #[test]
    fn test_asset_observation_identifiers() {
        let sender: u32 = 0xABCD_1234;
        let pkt = initiation(sender, [0x55u8; 32]);
        let mut evs = Vec::new();
        WireGuardDecoder::default().on_datagram(&chunk(&pkt), &mut evs);
        let asset = evs
            .iter()
            .find_map(|e| {
                if let BronzeEventFamily::AssetObservation(ref a) = e.family {
                    Some(a)
                } else {
                    None
                }
            })
            .expect("AssetObservation missing");
        assert_eq!(asset.role.as_deref(), Some("wireguard_initiator"));
        assert_eq!(asset.identifiers["wireguard_sender_index"], fmt_idx(sender));
        assert!(asset.protocols.contains(&"wireguard".to_string()));
    }
}
