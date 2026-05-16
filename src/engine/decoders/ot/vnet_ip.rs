//! Yokogawa Vnet/IP decoder (UDP port 32768, "Vnet" control plane).
//!
//! IMPORTANT — SPEC STATUS: The Vnet/IP wire format is **not publicly
//! documented** by Yokogawa. This decoder is **best-effort recognition** based
//! on the Wireshark open-source dissector
//! (`epan/dissectors/packet-vnetip.c`), a small number of CVE write-ups, and
//! passive traffic analysis. The function-code subset named here (0x0001–
//! 0x0004, 0x0010, 0x0020) is the only publicly referenced subset; all other
//! codes are emitted as `vnet_unknown_0x<hex>` so embedders can assign names
//! as field knowledge improves. **Do not treat any field offset or byte-order
//! assumption below as authoritative.** Deploy only for passive observation;
//! never use for control decisions.
//!
//! ## Header layout assumed (24-byte minimum)
//!
//! | Offset | Len | Field              | Byte order |
//! |--------|-----|--------------------|------------|
//! |  0..2  |  2  | type/subtype bytes |  —         |
//! |  2..4  |  2  | total length       |  BE        |
//! |  4..6  |  2  | sequence number    |  BE        |
//! |  6..8  |  2  | function code      |  BE        |
//! |  8..10 |  2  | source vnet addr   |  BE        |
//! | 10..12 |  2  | dst vnet addr      |  BE        |
//! | 12..24 | 12  | (reserved/padding) |  —         |
//! | 24..   |  *  | payload            |  —         |
//!
//! Byte order is assumed big-endian throughout, consistent with the Wireshark
//! dissector. The `total_length` field is not validated beyond a minimum-size
//! check because discrepancies between declared and captured length are common
//! in vendor-segmented payloads.

use std::collections::{BTreeMap, HashSet};

use crate::bronze::{
    AssetObservation, BronzeEvent, BronzeEventFamily, ProtocolTransaction, TransportProtocol,
};
use crate::engine::{
    DecoderInterest, SessionDecoder, StreamChunk, build_envelope, new_event, parse_anomaly_event,
};

/// Minimum number of bytes required to extract all header fields.
const VNET_HEADER_MIN: usize = 24;

/// UDP port on which Yokogawa Vnet/IP control-plane traffic is observed.
const VNET_UDP_PORT: u16 = 32768;

/// Map a function code to a human-readable operation string.
/// Only codes documented in public sources are named; everything else is
/// returned as `None` and emitted by the caller as `vnet_unknown_0x<hex>`.
fn vnet_operation(function_code: u16) -> Option<&'static str> {
    match function_code {
        0x0001 => Some("vnet_read"),
        0x0002 => Some("vnet_write"),
        0x0003 => Some("vnet_read_response"),
        0x0004 => Some("vnet_write_response"),
        0x0010 => Some("vnet_time_sync"),
        0x0020 => Some("vnet_status_notification"),
        _ => None,
    }
}

#[derive(Default)]
pub(crate) struct VnetIpDecoder {
    /// IPs from which we have already emitted an AssetObservation, keyed by
    /// (src_ip_string, src_vnet_addr_hex) to avoid spamming repeated
    /// observations for the same node within a capture segment.
    observed_assets: HashSet<(String, String)>,
}

impl SessionDecoder for VnetIpDecoder {
    fn name(&self) -> &'static str {
        "vnet_ip"
    }

    fn interest(&self) -> &'static [DecoderInterest] {
        &[DecoderInterest::UdpPort(VNET_UDP_PORT)]
    }

    fn on_datagram(&mut self, chunk: &StreamChunk<'_>, out: &mut Vec<BronzeEvent>) {
        let payload = chunk.payload;

        // ── Truncation guard ────────────────────────────────────────────────
        if payload.len() < VNET_HEADER_MIN {
            out.push(parse_anomaly_event(
                chunk.capture_id.to_string(),
                build_envelope(
                    &chunk.context,
                    chunk.interface_id,
                    chunk.frame_index,
                    chunk.timestamp,
                    chunk.segment_hash,
                    TransportProtocol::Udp,
                    Some("vnet_ip"),
                    chunk.captured_len,
                    chunk.session_key.clone(),
                ),
                self.name(),
                "medium",
                "vnet_ip datagram shorter than 24-byte minimum header",
                payload,
            ));
            return;
        }

        // ── Header extraction (big-endian) ──────────────────────────────────
        // Bytes 0..2: type / subtype — consumed but not interpreted further
        let sequence_number = u16::from_be_bytes([payload[4], payload[5]]);
        let function_code = u16::from_be_bytes([payload[6], payload[7]]);
        let src_vnet_addr = u16::from_be_bytes([payload[8], payload[9]]);
        let dst_vnet_addr = u16::from_be_bytes([payload[10], payload[11]]);
        let payload_length = payload.len().saturating_sub(VNET_HEADER_MIN);

        let envelope = build_envelope(
            &chunk.context,
            chunk.interface_id,
            chunk.frame_index,
            chunk.timestamp,
            chunk.segment_hash,
            TransportProtocol::Udp,
            Some("vnet_ip"),
            chunk.captured_len,
            chunk.session_key.clone(),
        );

        // ── Operation mapping ───────────────────────────────────────────────
        let operation = vnet_operation(function_code)
            .map(str::to_string)
            .unwrap_or_else(|| format!("vnet_unknown_0x{function_code:04x}"));

        let is_unknown = vnet_operation(function_code).is_none();

        // ── Attributes ─────────────────────────────────────────────────────
        let mut attributes = BTreeMap::new();
        attributes.insert(
            "function_code".to_string(),
            format!("0x{function_code:04x}"),
        );
        attributes.insert("sequence_number".to_string(), sequence_number.to_string());
        attributes.insert(
            "src_vnet_addr".to_string(),
            format!("0x{src_vnet_addr:04x}"),
        );
        attributes.insert(
            "dst_vnet_addr".to_string(),
            format!("0x{dst_vnet_addr:04x}"),
        );
        attributes.insert("payload_length".to_string(), payload_length.to_string());

        // ── ParseAnomaly for unknown function codes (low severity) ──────────
        if is_unknown {
            out.push(parse_anomaly_event(
                chunk.capture_id.to_string(),
                envelope.clone(),
                self.name(),
                "low",
                &format!("vnet_ip unknown function code 0x{function_code:04x}; emitting by hex"),
                &payload[6..8],
            ));
        }

        // ── ProtocolTransaction ─────────────────────────────────────────────
        out.push(new_event(
            chunk.capture_id.to_string(),
            envelope.clone(),
            BronzeEventFamily::ProtocolTransaction(ProtocolTransaction {
                operation,
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

        // ── AssetObservation (deduplicated per segment) ─────────────────────
        let src_ip = chunk.context.src_ip.to_string();
        let vnet_addr_hex = format!("0x{src_vnet_addr:04x}");
        let asset_key = (src_ip.clone(), vnet_addr_hex.clone());

        if !self.observed_assets.contains(&asset_key) {
            self.observed_assets.insert(asset_key);

            let mut identifiers = BTreeMap::new();
            identifiers.insert("vnet_address".to_string(), vnet_addr_hex);
            identifiers.insert("ip".to_string(), src_ip.clone());

            out.push(new_event(
                chunk.capture_id.to_string(),
                envelope,
                BronzeEventFamily::AssetObservation(AssetObservation {
                    asset_key: src_ip,
                    role: Some("yokogawa_vnet_node".to_string()),
                    vendor: Some("Yokogawa".to_string()),
                    model: None,
                    firmware: None,
                    hostnames: Vec::new(),
                    protocols: vec!["vnet_ip".to_string()],
                    identifiers,
                }),
            ));
        }
    }
}

inventory::submit!(crate::engine::decoders::DecoderRegistration {
    name: "vnet_ip",
    factory: || Box::new(VnetIpDecoder::default()),
});

// ════════════════════════════════════════════════════════════════════════════
// Tests
// ════════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};

    use chrono::DateTime;

    use super::*;
    use crate::engine::StreamChunk;
    use crate::registry::PacketContext;

    /// Build a minimal 24-byte Vnet/IP header with the given function code.
    fn make_payload(fc: u16, src_vnet: u16, dst_vnet: u16) -> Vec<u8> {
        let mut b = vec![0u8; 24];
        b[3] = 0x18; // total_length = 24 BE
        b[5] = 0x01; // sequence = 1
        b[6] = (fc >> 8) as u8;
        b[7] = fc as u8;
        b[8] = (src_vnet >> 8) as u8;
        b[9] = src_vnet as u8;
        b[10] = (dst_vnet >> 8) as u8;
        b[11] = dst_vnet as u8;
        b
    }

    fn run(decoder: &mut VnetIpDecoder, payload: &[u8], src_ip: Ipv4Addr) -> Vec<BronzeEvent> {
        let ctx = PacketContext {
            src_mac: [0u8; 6],
            dst_mac: [0u8; 6],
            src_ip: IpAddr::V4(src_ip),
            dst_ip: IpAddr::V4(Ipv4Addr::new(224, 0, 0, 1)),
            src_port: 32768,
            dst_port: 32768,
            vlan_id: None,
            timestamp: 1_700_000_000_000_000_000u64,
        };
        let chunk = StreamChunk {
            capture_id: "cap",
            segment_hash: "seg",
            interface_id: 0,
            frame_index: 1,
            timestamp: DateTime::from_timestamp(1_700_000_000, 0).unwrap(),
            context: ctx,
            ethertype: 0x0800,
            ip_proto: Some(17),
            llc: None,
            transport: TransportProtocol::Udp,
            payload,
            session_key: "sk".to_string(),
            captured_len: payload.len() as u64,
        };
        let mut out = Vec::new();
        decoder.on_datagram(&chunk, &mut out);
        out
    }

    fn find_tx(out: &[BronzeEvent]) -> Option<&ProtocolTransaction> {
        out.iter().find_map(|ev| {
            if let BronzeEventFamily::ProtocolTransaction(tx) = &ev.family {
                Some(tx)
            } else {
                None
            }
        })
    }
    fn find_anomaly(out: &[BronzeEvent]) -> Option<&crate::bronze::ParseAnomaly> {
        out.iter().find_map(|ev| {
            if let BronzeEventFamily::ParseAnomaly(a) = &ev.family {
                Some(a)
            } else {
                None
            }
        })
    }
    fn find_obs(out: &[BronzeEvent]) -> Option<&AssetObservation> {
        out.iter().find_map(|ev| {
            if let BronzeEventFamily::AssetObservation(o) = &ev.family {
                Some(o)
            } else {
                None
            }
        })
    }

    #[test]
    fn test_read_function_code() {
        let mut dec = VnetIpDecoder::default();
        let out = run(
            &mut dec,
            &make_payload(0x0001, 0x0010, 0x0020),
            Ipv4Addr::new(10, 0, 0, 1),
        );
        let tx = find_tx(&out).expect("transaction");
        assert_eq!(tx.operation, "vnet_read");
        assert_eq!(tx.status, "observed");
        assert_eq!(
            tx.attributes.get("function_code").map(String::as_str),
            Some("0x0001")
        );
    }

    #[test]
    fn test_write_function_code() {
        let mut dec = VnetIpDecoder::default();
        let out = run(
            &mut dec,
            &make_payload(0x0002, 0x0011, 0x0022),
            Ipv4Addr::new(10, 0, 0, 2),
        );
        assert_eq!(find_tx(&out).expect("transaction").operation, "vnet_write");
    }

    #[test]
    fn test_unknown_function_code() {
        let mut dec = VnetIpDecoder::default();
        let out = run(
            &mut dec,
            &make_payload(0x9999, 0x0030, 0x0040),
            Ipv4Addr::new(10, 0, 0, 3),
        );
        let a = find_anomaly(&out).expect("anomaly");
        assert_eq!(a.severity, "low");
        assert_eq!(find_tx(&out).expect("tx").operation, "vnet_unknown_0x9999");
    }

    #[test]
    fn test_truncated_datagram() {
        let mut dec = VnetIpDecoder::default();
        let out = run(&mut dec, &vec![0u8; 10], Ipv4Addr::new(10, 0, 0, 4));
        assert_eq!(out.len(), 1);
        let a = find_anomaly(&out).expect("anomaly");
        assert_eq!(a.severity, "medium");
    }

    #[test]
    fn test_asset_observation_vnet_address() {
        let mut dec = VnetIpDecoder::default();
        let out = run(
            &mut dec,
            &make_payload(0x0001, 0x00AB, 0x00CD),
            Ipv4Addr::new(192, 168, 1, 10),
        );
        let obs = find_obs(&out).expect("asset observation");
        assert_eq!(obs.vendor.as_deref(), Some("Yokogawa"));
        assert_eq!(obs.role.as_deref(), Some("yokogawa_vnet_node"));
        assert_eq!(
            obs.identifiers.get("vnet_address").map(String::as_str),
            Some("0x00ab")
        );
    }

    #[test]
    fn test_asset_observation_deduplicated() {
        let mut dec = VnetIpDecoder::default();
        let payload = make_payload(0x0001, 0x0010, 0x0020);
        let ip = Ipv4Addr::new(10, 1, 1, 1);
        let mut all_out = Vec::new();
        for _ in 0..3 {
            all_out.extend(run(&mut dec, &payload, ip));
        }
        let obs_count = all_out
            .iter()
            .filter(|ev| matches!(ev.family, BronzeEventFamily::AssetObservation(_)))
            .count();
        assert_eq!(obs_count, 1);
    }
}
