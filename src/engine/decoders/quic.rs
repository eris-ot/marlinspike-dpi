//! QUIC session decoder — RFC 9000 (QUIC v1) long-header recognition.
//!
//! QUIC INITIAL payload is AEAD-encrypted with keys derived from DCID.
//! We do NOT decrypt. SNI/ClientHello extraction is intentionally out of scope.
//!
//! Parsed in the clear: version, DCID, SCID, packet type, supported versions
//! (Version Negotiation), and token length estimate (Retry). Short-header
//! packets are recognized but not parsed — DCID length is connection-context-
//! dependent without state tracking.

use std::collections::BTreeMap;

use crate::bronze::{
    AssetObservation, BronzeEvent, BronzeEventFamily, ProtocolTransaction, TransportProtocol,
};
use crate::engine::{
    DecoderInterest, SessionDecoder, StreamChunk, build_envelope, new_event, parse_anomaly_event,
};

// ── QUIC version constants ───────────────────────────────────────────────────

const VERSION_NEGOTIATION: u32 = 0x0000_0000;
const QUIC_V1: u32 = 0x0000_0001;
const QUIC_V2: u32 = 0x6b33_43cf;
const DRAFT_MIN: u32 = 0xff00_0020; // draft-32
const DRAFT_MAX: u32 = 0xff00_0022; // draft-34

fn version_label(v: u32) -> &'static str {
    match v {
        VERSION_NEGOTIATION => "version_negotiation",
        QUIC_V1 => "quic_v1",
        QUIC_V2 => "quic_v2",
        d if (DRAFT_MIN..=DRAFT_MAX).contains(&d) => "quic_draft",
        _ => "quic_unknown_version",
    }
}

// ── Long-header parse result ─────────────────────────────────────────────────

struct LongHeader {
    first_byte: u8,
    version: u32,
    dcid: Vec<u8>,
    scid: Vec<u8>,
    /// Bytes consumed through end of SCID.
    consumed: usize,
}

/// Parse a QUIC long header from `buf[0..]`. Returns `None` on truncation.
/// Callers must validate `dcid_len <= 20` before calling; this function does
/// not enforce that constraint so the caller can emit the anomaly itself.
fn parse_long_header(buf: &[u8]) -> Option<LongHeader> {
    if buf.len() < 7 {
        return None;
    }
    let first_byte = buf[0];
    let version = u32::from_be_bytes([buf[1], buf[2], buf[3], buf[4]]);
    let dcid_len = buf[5] as usize;

    // If dcid_len is out-of-spec the caller already emitted the anomaly;
    // return a stub so we can still attribute the short parse.
    if dcid_len > 20 || 6 + dcid_len >= buf.len() {
        return None;
    }
    let dcid = buf[6..6 + dcid_len].to_vec();
    let si = 6 + dcid_len; // index of scid_len byte
    let scid_len = buf[si] as usize;
    if scid_len > 20 || si + 1 + scid_len > buf.len() {
        return None;
    }
    let scid = buf[si + 1..si + 1 + scid_len].to_vec();
    Some(LongHeader {
        first_byte,
        version,
        dcid,
        scid,
        consumed: si + 1 + scid_len,
    })
}

// ── QUIC varint decoder ──────────────────────────────────────────────────────
//
// RFC 9000 §16: top 2 bits of first byte encode width:
//   0b00 → 1 byte  (mask 0x3f)
//   0b01 → 2 bytes (mask 0x3fff)
//   0b10 → 4 bytes (mask 0x3fffffff)
//   0b11 → 8 bytes (mask 0x3fffffffffffffff)

#[allow(dead_code)]
fn read_varint(buf: &[u8], off: usize) -> Option<(u64, usize)> {
    let first = *buf.get(off)?;
    match first >> 6 {
        0 => Some(((first & 0x3f) as u64, 1)),
        1 => {
            if off + 2 > buf.len() {
                return None;
            }
            Some((u16::from_be_bytes([first & 0x3f, buf[off + 1]]) as u64, 2))
        }
        2 => {
            if off + 4 > buf.len() {
                return None;
            }
            Some((
                u32::from_be_bytes([first & 0x3f, buf[off + 1], buf[off + 2], buf[off + 3]]) as u64,
                4,
            ))
        }
        _ => {
            if off + 8 > buf.len() {
                return None;
            }
            Some((
                u64::from_be_bytes([
                    first & 0x3f,
                    buf[off + 1],
                    buf[off + 2],
                    buf[off + 3],
                    buf[off + 4],
                    buf[off + 5],
                    buf[off + 6],
                    buf[off + 7],
                ]),
                8,
            ))
        }
    }
}

// ── Decoder ──────────────────────────────────────────────────────────────────

#[derive(Default)]
pub(crate) struct QuicDecoder {
    /// Deduplicates AssetObservation per dst IP — one per session.
    seen_initial_dsts: std::collections::HashSet<String>,
}

impl SessionDecoder for QuicDecoder {
    fn name(&self) -> &'static str {
        "quic"
    }

    fn interest(&self) -> &'static [DecoderInterest] {
        &[DecoderInterest::UdpPort(443), DecoderInterest::UdpPort(80)]
    }

    fn on_datagram(&mut self, chunk: &StreamChunk<'_>, out: &mut Vec<BronzeEvent>) {
        let buf = chunk.payload;
        if buf.is_empty() {
            return;
        }

        let mk_env = || {
            build_envelope(
                &chunk.context,
                chunk.interface_id,
                chunk.frame_index,
                chunk.timestamp,
                chunk.segment_hash,
                TransportProtocol::Udp,
                Some("quic"),
                chunk.captured_len,
                chunk.session_key.clone(),
            )
        };

        let first_byte = buf[0];
        let header_form = (first_byte >> 7) & 1; // 1 = long header
        let fixed_bit = (first_byte >> 6) & 1; // must be 1 except Version Negotiation

        // ── Short header (bit 7 == 0) ────────────────────────────────────────
        // DCID length is connection-context-dependent; cannot parse without state.
        if header_form == 0 {
            let mut attrs = BTreeMap::new();
            attrs.insert(
                "note".to_string(),
                "dcid_length_unknown_without_connection_context".to_string(),
            );
            out.push(new_event(
                chunk.capture_id.to_string(),
                mk_env(),
                BronzeEventFamily::ProtocolTransaction(ProtocolTransaction {
                    operation: "quic_short_header".to_string(),
                    status: "observed".to_string(),
                    request_summary: None,
                    response_summary: None,
                    object_refs: vec![],
                    values: vec![],
                    attributes: attrs,
                    modbus: None,
                    protocol_fields: None,
                }),
            ));
            if fixed_bit == 0 {
                out.push(parse_anomaly_event(
                    chunk.capture_id.to_string(),
                    mk_env(),
                    self.name(),
                    "low",
                    "quic fixed bit is 0 in short-header packet",
                    &buf[..1],
                ));
            }
            return;
        }

        // ── Long header (bit 7 == 1) ─────────────────────────────────────────
        if buf.len() < 6 {
            out.push(parse_anomaly_event(
                chunk.capture_id.to_string(),
                mk_env(),
                self.name(),
                "low",
                "quic long header truncated",
                buf,
            ));
            return;
        }

        let version = u32::from_be_bytes([buf[1], buf[2], buf[3], buf[4]]);
        let dcid_len_raw = buf[5] as usize;

        // Fixed bit must be 1 except for Version Negotiation packets.
        if fixed_bit == 0 && version != VERSION_NEGOTIATION {
            out.push(parse_anomaly_event(
                chunk.capture_id.to_string(),
                mk_env(),
                self.name(),
                "low",
                "quic fixed bit is 0 in non-version-negotiation long-header packet",
                &buf[..1],
            ));
        }

        // DCID length > 20 violates RFC 9000 §17.2.
        if dcid_len_raw > 20 {
            out.push(parse_anomaly_event(
                chunk.capture_id.to_string(),
                mk_env(),
                self.name(),
                "low",
                &format!(
                    "quic dcid length {} exceeds rfc 9000 maximum of 20",
                    dcid_len_raw
                ),
                buf,
            ));
            return;
        }

        let Some(lh) = parse_long_header(buf) else {
            out.push(parse_anomaly_event(
                chunk.capture_id.to_string(),
                mk_env(),
                self.name(),
                "low",
                "quic long header parse failed (truncated)",
                buf,
            ));
            return;
        };

        let version_hex = format!("{:08x}", lh.version);
        let dcid_hex = hex::encode(&lh.dcid);
        let scid_hex = hex::encode(&lh.scid);

        // Packet type from bits 4-5 of first byte (long header only).
        // Version Negotiation is identified by version == 0; type bits ignored.
        let type_bits = (lh.first_byte >> 4) & 0b11;
        let operation = if lh.version == VERSION_NEGOTIATION {
            "quic_version_negotiation"
        } else {
            match type_bits {
                0b00 => "quic_initial",
                0b01 => "quic_0rtt",
                0b10 => "quic_handshake",
                0b11 => "quic_retry",
                _ => "quic_unknown",
            }
        };

        let mut attrs = BTreeMap::new();
        attrs.insert("version_hex".to_string(), version_hex.clone());
        attrs.insert("dcid_hex".to_string(), dcid_hex.clone());
        attrs.insert("scid_hex".to_string(), scid_hex.clone());
        attrs.insert("dcid_length".to_string(), lh.dcid.len().to_string());
        attrs.insert("scid_length".to_string(), lh.scid.len().to_string());
        attrs.insert(
            "quic_version".to_string(),
            version_label(lh.version).to_string(),
        );

        // Version Negotiation: remaining bytes after SCID are supported versions (u32 BE list).
        if lh.version == VERSION_NEGOTIATION {
            let mut pos = lh.consumed;
            let mut svs = Vec::new();
            while pos + 4 <= buf.len() {
                svs.push(format!(
                    "{:08x}",
                    u32::from_be_bytes([buf[pos], buf[pos + 1], buf[pos + 2], buf[pos + 3]])
                ));
                pos += 4;
            }
            if !svs.is_empty() {
                attrs.insert("supported_versions_hex".to_string(), svs.join(","));
            }
        }

        // Retry: RFC 9000 §17.2.5 — token occupies all bytes after SCID except
        // the final 16-byte Retry Integrity Tag.
        if lh.version != VERSION_NEGOTIATION && type_bits == 0b11 {
            let token_len = buf.len().saturating_sub(lh.consumed).saturating_sub(16);
            attrs.insert("token_length".to_string(), token_len.to_string());
        }

        out.push(new_event(
            chunk.capture_id.to_string(),
            mk_env(),
            BronzeEventFamily::ProtocolTransaction(ProtocolTransaction {
                operation: operation.to_string(),
                status: "observed".to_string(),
                request_summary: Some(format!(
                    "QUIC {} version={} dcid={}",
                    operation, version_hex, dcid_hex
                )),
                response_summary: None,
                object_refs: vec![],
                values: vec![],
                attributes: attrs,
                modbus: None,
                protocol_fields: None,
            }),
        ));

        // AssetObservation for the QUIC server on first INITIAL per destination.
        if operation == "quic_initial" {
            let dst = chunk.context.dst_ip.to_string();
            if self.seen_initial_dsts.insert(dst.clone()) {
                let mut ids = BTreeMap::new();
                ids.insert("ip".to_string(), dst.clone());
                ids.insert("quic_version".to_string(), version_hex);
                out.push(new_event(
                    chunk.capture_id.to_string(),
                    mk_env(),
                    BronzeEventFamily::AssetObservation(AssetObservation {
                        asset_key: dst,
                        role: Some("quic_server".to_string()),
                        vendor: None,
                        model: None,
                        firmware: None,
                        hostnames: vec![],
                        protocols: vec!["quic".to_string()],
                        identifiers: ids,
                    }),
                ));
            }
        }
    }
}

// ── Inventory registration ───────────────────────────────────────────────────

inventory::submit!(crate::engine::decoders::DecoderRegistration {
    name: "quic",
    factory: || Box::new(QuicDecoder::default()),
});

// ── Tests ────────────────────────────────────────────────────────────────────

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
            dst_port: 443,
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

    /// Build a QUIC long-header datagram.
    /// first_byte = 0b1_1_TT_0000  (header_form=1, fixed=1, type=TT, pn_len=00)
    fn long_pkt(type_bits: u8, version: u32, dcid: &[u8], scid: &[u8], extra: &[u8]) -> Vec<u8> {
        let first = 0b1100_0000u8 | ((type_bits & 0b11) << 4);
        let mut b = vec![first];
        b.extend_from_slice(&version.to_be_bytes());
        b.push(dcid.len() as u8);
        b.extend_from_slice(dcid);
        b.push(scid.len() as u8);
        b.extend_from_slice(scid);
        b.extend_from_slice(extra);
        b
    }

    fn get_tx(evs: &[BronzeEvent]) -> Option<&ProtocolTransaction> {
        evs.iter().find_map(|e| {
            if let BronzeEventFamily::ProtocolTransaction(ref t) = e.family {
                Some(t)
            } else {
                None
            }
        })
    }

    fn get_anomaly(evs: &[BronzeEvent]) -> Option<&crate::bronze::ParseAnomaly> {
        evs.iter().find_map(|e| {
            if let BronzeEventFamily::ParseAnomaly(ref a) = e.family {
                Some(a)
            } else {
                None
            }
        })
    }

    // 1. INITIAL v1, DCID=8, SCID=8
    #[test]
    fn test_initial_v1_dcid8_scid8() {
        let dcid = [0xd0u8, 0xd1, 0xd2, 0xd3, 0xd4, 0xd5, 0xd6, 0xd7];
        let scid = [0xc0u8, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7];
        let pkt = long_pkt(0b00, QUIC_V1, &dcid, &scid, &[]);
        let mut dec = QuicDecoder::default();
        let mut evs = Vec::new();
        dec.on_datagram(&chunk(&pkt), &mut evs);

        assert!(evs.len() >= 2, "expected ≥2 events, got {}", evs.len());
        let tx = get_tx(&evs).unwrap();
        assert_eq!(tx.operation, "quic_initial");
        assert_eq!(tx.status, "observed");
        assert_eq!(tx.attributes["version_hex"], "00000001");
        assert_eq!(tx.attributes["dcid_hex"], hex::encode(dcid));
        assert_eq!(tx.attributes["scid_hex"], hex::encode(scid));
        assert_eq!(tx.attributes["dcid_length"], "8");
        assert_eq!(tx.attributes["scid_length"], "8");

        let asset = evs
            .iter()
            .find_map(|e| {
                if let BronzeEventFamily::AssetObservation(ref a) = e.family {
                    Some(a)
                } else {
                    None
                }
            })
            .unwrap();
        assert_eq!(asset.role.as_deref(), Some("quic_server"));
        assert_eq!(asset.identifiers["quic_version"], "00000001");
    }

    // 2. HANDSHAKE — long type=10, version=1
    #[test]
    fn test_handshake_v1() {
        let pkt = long_pkt(0b10, QUIC_V1, &[0xaau8; 8], &[0xbb; 4], &[]);
        let mut dec = QuicDecoder::default();
        let mut evs = Vec::new();
        dec.on_datagram(&chunk(&pkt), &mut evs);
        let tx = get_tx(&evs).unwrap();
        assert_eq!(tx.operation, "quic_handshake");
        assert!(
            !evs.iter()
                .any(|e| matches!(e.family, BronzeEventFamily::AssetObservation(_))),
            "HANDSHAKE must not emit AssetObservation"
        );
    }

    // 3. Version Negotiation — version=0, two supported versions
    #[test]
    fn test_version_negotiation_supported_versions() {
        // Fixed bit may be 0 in VN (RFC 9000 §17.2.1).
        let mut pkt = vec![0x80u8]; // long, fixed=0
        pkt.extend_from_slice(&VERSION_NEGOTIATION.to_be_bytes());
        pkt.push(4u8);
        pkt.extend_from_slice(&[0x01u8; 4]); // dcid
        pkt.push(1u8);
        pkt.push(0xffu8); // scid
        pkt.extend_from_slice(&QUIC_V1.to_be_bytes());
        pkt.extend_from_slice(&QUIC_V2.to_be_bytes());

        let mut dec = QuicDecoder::default();
        let mut evs = Vec::new();
        dec.on_datagram(&chunk(&pkt), &mut evs);
        let tx = get_tx(&evs).unwrap();
        assert_eq!(tx.operation, "quic_version_negotiation");
        let sv = tx.attributes.get("supported_versions_hex").unwrap();
        assert!(sv.contains("00000001"), "missing v1 in: {sv}");
        assert!(sv.contains("6b3343cf"), "missing v2 in: {sv}");
    }

    // 4. Short header (bit 7=0) → quic_short_header
    #[test]
    fn test_short_header_recognition() {
        let pkt = [0b0100_0000u8, 0xde, 0xad, 0xbe, 0xef];
        let mut dec = QuicDecoder::default();
        let mut evs = Vec::new();
        dec.on_datagram(&chunk(&pkt), &mut evs);
        let tx = get_tx(&evs).unwrap();
        assert_eq!(tx.operation, "quic_short_header");
        assert_eq!(tx.status, "observed");
    }

    // 5. Draft-32 (0xff000020), type=INITIAL → version_hex correct
    #[test]
    fn test_draft32_initial() {
        let pkt = long_pkt(0b00, 0xff00_0020, &[0x10u8; 4], &[0x20u8; 4], &[]);
        let mut dec = QuicDecoder::default();
        let mut evs = Vec::new();
        dec.on_datagram(&chunk(&pkt), &mut evs);
        let tx = get_tx(&evs).unwrap();
        assert_eq!(tx.operation, "quic_initial");
        assert_eq!(tx.attributes["version_hex"], "ff000020");
        assert_eq!(tx.attributes["quic_version"], "quic_draft");
    }

    // 6. DCID length 25 (> 20) → ParseAnomaly severity=low
    #[test]
    fn test_dcid_length_too_large_anomaly() {
        let mut pkt = vec![0b1100_0000u8];
        pkt.extend_from_slice(&QUIC_V1.to_be_bytes());
        pkt.push(25u8); // invalid dcid_len
        pkt.extend_from_slice(&[0xadu8; 25]);
        pkt.push(4u8);
        pkt.extend_from_slice(&[0xbcu8; 4]);

        let mut dec = QuicDecoder::default();
        let mut evs = Vec::new();
        dec.on_datagram(&chunk(&pkt), &mut evs);
        let anomaly = get_anomaly(&evs).expect("ParseAnomaly expected");
        assert_eq!(anomaly.severity, "low");
        assert!(
            anomaly.reason.contains("dcid") || anomaly.reason.contains("20"),
            "reason: {}",
            anomaly.reason
        );
    }

    // 7. Fixed-bit clear in non-VN long header → ParseAnomaly severity=low
    #[test]
    fn test_fixed_bit_clear_long_header_anomaly() {
        let mut pkt = vec![0b1000_0000u8]; // header_form=1, fixed=0
        pkt.extend_from_slice(&QUIC_V1.to_be_bytes());
        pkt.push(4u8);
        pkt.extend_from_slice(&[0x01u8; 4]);
        pkt.push(4u8);
        pkt.extend_from_slice(&[0x02u8; 4]);

        let mut dec = QuicDecoder::default();
        let mut evs = Vec::new();
        dec.on_datagram(&chunk(&pkt), &mut evs);
        let anomaly = get_anomaly(&evs).expect("ParseAnomaly expected for fixed-bit-clear");
        assert_eq!(anomaly.severity, "low");
        assert!(
            anomaly.reason.contains("fixed bit"),
            "reason: {}",
            anomaly.reason
        );
    }

    // 8. 0-RTT packet type (0b01)
    #[test]
    fn test_0rtt_packet_type() {
        let pkt = long_pkt(0b01, QUIC_V1, &[0x01u8; 8], &[0x02u8; 4], &[]);
        let mut dec = QuicDecoder::default();
        let mut evs = Vec::new();
        dec.on_datagram(&chunk(&pkt), &mut evs);
        assert_eq!(get_tx(&evs).unwrap().operation, "quic_0rtt");
    }

    // 9. interest() exposes UdpPort(443) and UdpPort(80)
    #[test]
    fn test_interest_ports() {
        let dec = QuicDecoder::default();
        assert!(dec.interest().contains(&DecoderInterest::UdpPort(443)));
        assert!(dec.interest().contains(&DecoderInterest::UdpPort(80)));
    }
}
