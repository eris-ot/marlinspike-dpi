//! IKE (Internet Key Exchange) session decoder — IKEv1 (RFC 2409) and
//! IKEv2 (RFC 7296). UDP 500 (plain IKE) and 4500 (NAT-T).
//!
//! The SA negotiation is in the clear; only AUTH onward and ESP are encrypted.
//! Port 4500 NAT-T: four zero-bytes prefix an IKE message; a non-zero first
//! byte means ESP — skip those silently.

use std::collections::BTreeMap;

use crate::bronze::{
    AssetObservation, BronzeEvent, BronzeEventFamily, ProtocolTransaction, TransportProtocol,
};
use crate::engine::{
    DecoderInterest, SessionDecoder, StreamChunk, build_envelope, new_event, parse_anomaly_event,
};

// ── Known Vendor ID prefix table ─────────────────────────────────────────────

const VENDOR_IDS: &[(&[u8], &str)] = &[
    // Microsoft Vid-Initial-Contact (8 bytes)
    (
        &[0x1e, 0x2b, 0x51, 0x69, 0x9d, 0x3c, 0xe8, 0x2d],
        "MS-Vid-Initial-Contact",
    ),
    // "MS NT5 ISAKMPOAKLEY" — Windows IKE stack
    (
        &[
            0x40, 0x48, 0xb7, 0xd5, 0x6e, 0xbc, 0xe8, 0x85, 0x25, 0xe7, 0xde, 0x7f, 0x00, 0xd6,
            0xc2, 0xd3,
        ],
        "MS-NT5-ISAKMPOAKLEY",
    ),
    // Cisco Unity
    (
        &[
            0x12, 0xf5, 0xf2, 0x8c, 0x45, 0x71, 0x68, 0xa9, 0x70, 0x2d, 0x9f, 0xe2, 0x74, 0xcc,
            0x02, 0xd4,
        ],
        "Cisco-Unity",
    ),
    // DPD — Dead Peer Detection (RFC 3706)
    (
        &[
            0xaf, 0xca, 0xd7, 0x13, 0x68, 0xa1, 0xf1, 0xc9, 0x6b, 0x86, 0x96, 0xfc, 0x77, 0x57,
            0x01, 0x00,
        ],
        "DPD-RFC3706",
    ),
    // NAT-T RFC 3947 / draft-ietf-ipsec-nat-t-ike-02
    (
        &[
            0x4a, 0x13, 0x1c, 0x81, 0x07, 0x03, 0x58, 0x45, 0x5c, 0x57, 0x28, 0xf2, 0x0e, 0x95,
            0x45, 0x2f,
        ],
        "NAT-T-RFC3947",
    ),
    // NAT-T draft-03
    (
        &[
            0x90, 0xcb, 0x80, 0x91, 0x3e, 0xbb, 0x69, 0x6e, 0x08, 0x63, 0x81, 0xb5, 0xec, 0x42,
            0x7b, 0x1f,
        ],
        "NAT-T-draft-03",
    ),
];

fn match_vendor_id(data: &[u8]) -> String {
    for (prefix, name) in VENDOR_IDS {
        if data.len() >= prefix.len() && &data[..prefix.len()] == *prefix {
            return name.to_string();
        }
    }
    // Unknown: emit first 16 bytes as hex.
    format!("unknown:{}", hex::encode(&data[..data.len().min(16)]))
}

// ── IKE fixed header (28 bytes, all big-endian) ───────────────────────────────

struct IkeHeader {
    initiator_spi: [u8; 8],
    responder_spi: [u8; 8],
    next_payload: u8,
    /// Raw version byte.
    ///
    /// IMPORTANT — version is a packed nibble pair, NOT a decimal:
    ///   high nibble (`>> 4`) = major version
    ///   low  nibble (`& 0x0f`) = minor version
    /// So IKEv1 = 0x10, IKEv2 = 0x20.  Treating this as a plain integer is
    /// a common parsing mistake (0x20 != 20, 0x10 != 10).
    version_byte: u8,
    exchange_type: u8,
    flags: u8,
    message_id: u32,
}

impl IkeHeader {
    fn major(&self) -> u8 {
        self.version_byte >> 4
    }

    fn parse(buf: &[u8]) -> Option<Self> {
        if buf.len() < 28 {
            return None;
        }
        Some(IkeHeader {
            initiator_spi: buf[0..8].try_into().ok()?,
            responder_spi: buf[8..16].try_into().ok()?,
            next_payload: buf[16],
            version_byte: buf[17],
            exchange_type: buf[18],
            flags: buf[19],
            message_id: u32::from_be_bytes(buf[20..24].try_into().ok()?),
        })
    }
}

// ── Payload chain walker ──────────────────────────────────────────────────────

/// Walk the generic payload chain starting at `offset` with `next_payload` as
/// the first payload type. Returns (vendor_id_names, chain_was_malformed).
fn walk_payloads(buf: &[u8], mut next_payload: u8, mut offset: usize) -> (Vec<String>, bool) {
    let mut vendor_ids = Vec::new();
    let mut malformed = false;

    while next_payload != 0 {
        if offset + 4 > buf.len() {
            malformed = true;
            break;
        }
        let this_next = buf[offset];
        let payload_len = u16::from_be_bytes([buf[offset + 2], buf[offset + 3]]) as usize;
        if payload_len < 4 || offset + payload_len > buf.len() {
            malformed = true;
            break;
        }

        // Payload type 13 = Vendor ID (used in both IKEv1 and IKEv2).
        if next_payload == 13 && payload_len > 4 {
            vendor_ids.push(match_vendor_id(&buf[offset + 4..offset + payload_len]));
        }

        next_payload = this_next;
        offset += payload_len;
    }

    (vendor_ids, malformed)
}

// ── Decoder ───────────────────────────────────────────────────────────────────

#[derive(Default)]
pub(crate) struct IkeDecoder {
    /// Deduplicates AssetObservation per unique initiator SPI.
    seen_spis: std::collections::HashSet<[u8; 8]>,
}

impl SessionDecoder for IkeDecoder {
    fn name(&self) -> &'static str {
        "ike"
    }

    fn interest(&self) -> &'static [DecoderInterest] {
        &[
            DecoderInterest::UdpPort(500),
            DecoderInterest::UdpPort(4500),
        ]
    }

    fn on_datagram(&mut self, chunk: &StreamChunk<'_>, out: &mut Vec<BronzeEvent>) {
        let payload = chunk.payload;
        let src_port = chunk.context.src_port;
        let dst_port = chunk.context.dst_port;
        let is_natt = src_port == 4500 || dst_port == 4500;

        // NAT-T disambiguation: four zero bytes → IKE; non-zero first byte → ESP (skip).
        let ike_buf = if is_natt {
            if payload.len() < 4 {
                return;
            }
            if payload[0] != 0x00 {
                return;
            } // ESP — encrypted, skip silently
            if payload[..4] != [0x00, 0x00, 0x00, 0x00] {
                return;
            }
            &payload[4..]
        } else {
            payload
        };

        let anomaly_envelope = || {
            build_envelope(
                &chunk.context,
                chunk.interface_id,
                chunk.frame_index,
                chunk.timestamp,
                chunk.segment_hash,
                TransportProtocol::Udp,
                Some("ike"),
                chunk.captured_len,
                chunk.session_key.clone(),
            )
        };

        let Some(hdr) = IkeHeader::parse(ike_buf) else {
            out.push(parse_anomaly_event(
                chunk.capture_id.to_string(),
                anomaly_envelope(),
                self.name(),
                "low",
                "ike header too short",
                ike_buf,
            ));
            return;
        };

        // Reject unknown version bytes. Only 0x10 (IKEv1) and 0x20 (IKEv2) are valid.
        if hdr.version_byte != 0x10 && hdr.version_byte != 0x20 {
            out.push(parse_anomaly_event(
                chunk.capture_id.to_string(),
                anomaly_envelope(),
                self.name(),
                "medium",
                &format!("unknown ike version byte 0x{:02x}", hdr.version_byte),
                ike_buf,
            ));
            return;
        }

        let major = hdr.major();

        let operation = match (major, hdr.exchange_type) {
            (1, 2) => "ike_v1_main_mode".to_string(),
            (1, 4) => "ike_v1_aggressive".to_string(),
            (1, 5) => "ike_v1_informational".to_string(),
            (1, 32) => "ike_v1_quick_mode".to_string(),
            (1, 33) => "ike_v1_new_group_mode".to_string(),
            (2, 34) => "ike_v2_sa_init".to_string(),
            (2, 35) => "ike_v2_auth".to_string(),
            (2, 36) => "ike_v2_create_child_sa".to_string(),
            (2, 37) => "ike_v2_informational".to_string(),
            _ => format!("ike_unknown_v{}_xt_{:02x}", major, hdr.exchange_type),
        };

        // IKEv2 RFC 7296 §3.1: flags bit 5 (0x20) is the Response flag.
        // IKEv1 heuristic: responder SPI all-zeros on first exchange = initiator request.
        let status = if major == 2 {
            if hdr.flags & 0x20 != 0 {
                "response"
            } else {
                "request"
            }
        } else {
            let resp_zero = hdr.responder_spi == [0u8; 8];
            let init_valid = hdr.initiator_spi != [0u8; 8];
            if init_valid && resp_zero {
                "request"
            } else if !resp_zero {
                "response"
            } else {
                "observed"
            }
        };

        let (vendor_ids, malformed) = walk_payloads(ike_buf, hdr.next_payload, 28);

        let envelope = build_envelope(
            &chunk.context,
            chunk.interface_id,
            chunk.frame_index,
            chunk.timestamp,
            chunk.segment_hash,
            TransportProtocol::Udp,
            Some("ike"),
            chunk.captured_len,
            chunk.session_key.clone(),
        );

        if malformed {
            out.push(parse_anomaly_event(
                chunk.capture_id.to_string(),
                envelope.clone(),
                self.name(),
                "low",
                "malformed ike payload chain",
                ike_buf,
            ));
        }

        let init_spi_hex = hex::encode(hdr.initiator_spi);
        let resp_spi_hex = hex::encode(hdr.responder_spi);

        let mut attributes = BTreeMap::new();
        attributes.insert("version".to_string(), format!("v{major}"));
        attributes.insert("exchange_type".to_string(), hdr.exchange_type.to_string());
        attributes.insert("initiator_spi".to_string(), init_spi_hex.clone());
        attributes.insert("responder_spi".to_string(), resp_spi_hex);
        attributes.insert("message_id".to_string(), hdr.message_id.to_string());
        if !vendor_ids.is_empty() {
            attributes.insert("vendor_ids".to_string(), vendor_ids.join(","));
        }

        out.push(new_event(
            chunk.capture_id.to_string(),
            envelope.clone(),
            BronzeEventFamily::ProtocolTransaction(ProtocolTransaction {
                operation: operation.clone(),
                status: status.to_string(),
                request_summary: Some(format!("IKEv{major} {operation} spi={init_spi_hex}")),
                response_summary: None,
                object_refs: vec![],
                values: vec![],
                attributes,
                modbus: None,
                protocol_fields: None,
            }),
        ));

        // One AssetObservation per unique initiator SPI.
        if self.seen_spis.insert(hdr.initiator_spi) {
            let mut identifiers = BTreeMap::new();
            identifiers.insert("ip".to_string(), chunk.context.src_ip.to_string());
            identifiers.insert("ike_spi".to_string(), init_spi_hex.clone());
            out.push(new_event(
                chunk.capture_id.to_string(),
                envelope,
                BronzeEventFamily::AssetObservation(AssetObservation {
                    asset_key: chunk.context.src_ip.to_string(),
                    role: Some("ipsec_initiator".to_string()),
                    vendor: None,
                    model: None,
                    firmware: None,
                    hostnames: vec![],
                    protocols: vec!["ike".to_string()],
                    identifiers,
                }),
            ));
        }
    }
}

// ── Inventory registration ────────────────────────────────────────────────────

inventory::submit!(crate::engine::decoders::DecoderRegistration {
    name: "ike",
    factory: || Box::new(IkeDecoder::default()),
});

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bronze::BronzeEventFamily;
    use crate::engine::{DecoderInterest, StreamChunk};
    use crate::registry::PacketContext;
    use chrono::{TimeZone, Utc};
    use std::net::{IpAddr, Ipv4Addr};

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

    fn chunk<'a>(payload: &'a [u8], context: PacketContext) -> StreamChunk<'a> {
        StreamChunk {
            capture_id: "test",
            segment_hash: "seg",
            interface_id: 0,
            frame_index: 0,
            timestamp: Utc.timestamp_opt(1_700_000_000, 0).unwrap(),
            context,
            ethertype: 0x0800,
            ip_proto: Some(17),
            llc: None,
            transport: TransportProtocol::Udp,
            payload,
            session_key: "sk".to_string(),
            captured_len: payload.len() as u64,
        }
    }

    /// Build a minimal 28-byte IKE fixed header.
    fn hdr(
        init_spi: [u8; 8],
        resp_spi: [u8; 8],
        next_payload: u8,
        version_byte: u8,
        exchange_type: u8,
        flags: u8,
        message_id: u32,
    ) -> Vec<u8> {
        let mut b = Vec::with_capacity(28);
        b.extend_from_slice(&init_spi);
        b.extend_from_slice(&resp_spi);
        b.push(next_payload);
        b.push(version_byte);
        b.push(exchange_type);
        b.push(flags);
        b.extend_from_slice(&message_id.to_be_bytes());
        b.extend_from_slice(&28u32.to_be_bytes()); // total length
        b
    }

    /// Build a Vendor ID payload (type 13).
    fn vid_payload(next: u8, data: &[u8]) -> Vec<u8> {
        let len = (4 + data.len()) as u16;
        let mut b = vec![next, 0x00];
        b.extend_from_slice(&len.to_be_bytes());
        b.extend_from_slice(data);
        b
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

    // ── 1. IKEv2 IKE_SA_INIT request ─────────────────────────────────────────

    #[test]
    fn test_ikev2_sa_init_request() {
        let init_spi = [0xde, 0xad, 0xbe, 0xef, 0x01, 0x02, 0x03, 0x04];
        let payload = hdr(init_spi, [0u8; 8], 0, 0x20, 34, 0x08, 0);
        let mut dec = IkeDecoder::default();
        let mut evs = Vec::new();
        dec.on_datagram(&chunk(&payload, ctx(12345, 500)), &mut evs);

        assert_eq!(evs.len(), 2); // tx + asset
        let tx = get_tx(&evs).unwrap();
        assert_eq!(tx.operation, "ike_v2_sa_init");
        assert_eq!(tx.status, "request");
        assert_eq!(tx.attributes["initiator_spi"], hex::encode(init_spi));
        assert_eq!(tx.attributes["version"], "v2");
    }

    // ── 2. IKEv1 Main Mode ────────────────────────────────────────────────────

    #[test]
    fn test_ikev1_main_mode() {
        let init_spi = [0xaa, 0xbb, 0xcc, 0xdd, 0x11, 0x22, 0x33, 0x44];
        let payload = hdr(init_spi, [0u8; 8], 0, 0x10, 2, 0x00, 0);
        let mut dec = IkeDecoder::default();
        let mut evs = Vec::new();
        dec.on_datagram(&chunk(&payload, ctx(500, 500)), &mut evs);

        let tx = get_tx(&evs).unwrap();
        assert_eq!(tx.operation, "ike_v1_main_mode");
        assert_eq!(tx.attributes["version"], "v1");
    }

    // ── 3. NAT-T port 4500 with 4-byte zero prefix ───────────────────────────

    #[test]
    fn test_natt_ike_zero_prefix() {
        let init_spi = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];
        let mut payload = vec![0x00u8; 4]; // non-ESP marker
        payload.extend_from_slice(&hdr(init_spi, [0u8; 8], 0, 0x20, 34, 0x08, 0));

        let mut dec = IkeDecoder::default();
        let mut evs = Vec::new();
        dec.on_datagram(&chunk(&payload, ctx(12345, 4500)), &mut evs);

        let tx = get_tx(&evs).unwrap();
        assert_eq!(tx.operation, "ike_v2_sa_init");
        assert_eq!(tx.status, "request");
    }

    // ── 4. ESP on port 4500 → zero events ────────────────────────────────────

    #[test]
    fn test_natt_esp_silently_skipped() {
        // Non-zero first byte → ESP, must be silently ignored.
        let payload = vec![0xc0u8, 0x00, 0x00, 0x01, 0xde, 0xad, 0xbe, 0xef];
        let mut dec = IkeDecoder::default();
        let mut evs = Vec::new();
        dec.on_datagram(&chunk(&payload, ctx(12345, 4500)), &mut evs);
        assert!(
            evs.is_empty(),
            "ESP on 4500 must emit nothing, got {}",
            evs.len()
        );
    }

    // ── 5. Vendor ID payload — NAT-T RFC 3947 ────────────────────────────────

    #[test]
    fn test_vendor_id_natt_rfc3947() {
        let natt_vid: &[u8] = &[
            0x4a, 0x13, 0x1c, 0x81, 0x07, 0x03, 0x58, 0x45, 0x5c, 0x57, 0x28, 0xf2, 0x0e, 0x95,
            0x45, 0x2f,
        ];
        let mut payload = hdr([0x10; 8], [0u8; 8], 13, 0x20, 34, 0x08, 0);
        payload.extend_from_slice(&vid_payload(0, natt_vid));

        let mut dec = IkeDecoder::default();
        let mut evs = Vec::new();
        dec.on_datagram(&chunk(&payload, ctx(500, 500)), &mut evs);

        let tx = get_tx(&evs).unwrap();
        let vids = tx.attributes.get("vendor_ids").expect("vendor_ids missing");
        assert!(vids.contains("NAT-T-RFC3947"), "got: {vids}");
    }

    // ── 6. Bad version byte → ParseAnomaly severity=medium ───────────────────

    #[test]
    fn test_bad_version_byte_anomaly() {
        let payload = hdr([0xca; 8], [0u8; 8], 0, 0x30, 34, 0x08, 0);
        let mut dec = IkeDecoder::default();
        let mut evs = Vec::new();
        dec.on_datagram(&chunk(&payload, ctx(500, 500)), &mut evs);

        let anomaly = evs
            .iter()
            .find_map(|e| {
                if let BronzeEventFamily::ParseAnomaly(ref a) = e.family {
                    Some(a)
                } else {
                    None
                }
            })
            .expect("ParseAnomaly missing");
        assert_eq!(anomaly.severity, "medium");
        assert!(
            anomaly.reason.contains("0x30"),
            "reason: {}",
            anomaly.reason
        );
    }

    // ── 7. IKEv2 response flag → status=response ─────────────────────────────

    #[test]
    fn test_ikev2_response_flag() {
        // flags bit 5 (0x20) = response
        let payload = hdr([0x11; 8], [0x22; 8], 0, 0x20, 34, 0x28, 1);
        let mut dec = IkeDecoder::default();
        let mut evs = Vec::new();
        dec.on_datagram(&chunk(&payload, ctx(500, 500)), &mut evs);

        let tx = get_tx(&evs).unwrap();
        assert_eq!(tx.status, "response");
    }

    // ── 8. interest() exposes both expected UDP ports ─────────────────────────

    #[test]
    fn test_interest_ports() {
        let dec = IkeDecoder::default();
        assert!(dec.interest().contains(&DecoderInterest::UdpPort(500)));
        assert!(dec.interest().contains(&DecoderInterest::UdpPort(4500)));
    }
}
