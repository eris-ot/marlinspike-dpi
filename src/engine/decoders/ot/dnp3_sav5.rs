//! DNP3 Secure Authentication v5 (SAv5) recognition decoder.
//!
//! # Purpose
//! Recognition-only layer, co-registered on TCP/20000 alongside the main DNP3
//! decoder (`ot/dnp3.rs`). Each decoder receives its own copy of the stream;
//! this one specifically looks for Object Group 120 (g120) SAv5 authentication
//! messages defined in IEEE 1815-2012.
//!
//! # What it emits
//! - `ProtocolTransaction` per SAv5 frame (only when g120 is detected).
//! - `AssetObservation` for the source address, role `"dnp3_sav5_capable"`.
//! - `ParseAnomaly` severity `"high"` on g120v7 (Authentication Error).
//! - `ParseAnomaly` severity `"low"` on corrupt link-layer start sequence.
//!
//! # Wire format summary
//! DNP3 link header is 10 bytes: 0x05 0x64, length, control, dest_addr(LE u16),
//! src_addr(LE u16), crc(u16). Following user data is in 16-data-byte blocks
//! each followed by a 2-byte CRC. For recognition purposes we linearly scan the
//! buffer after the link header for the g120 byte pair `0x78 0xVV` (VV 0x01–0x0F).

use std::collections::BTreeMap;

use crate::bronze::{
    AssetObservation, BronzeEvent, BronzeEventFamily, ProtocolTransaction, TransportProtocol,
};
use crate::engine::{
    DecoderInterest, SessionDecoder, StreamChunk, build_envelope, new_event, parse_anomaly_event,
};

// ---------------------------------------------------------------------------
// Link-header constants
// ---------------------------------------------------------------------------

const DNP3_START_BYTE_0: u8 = 0x05;
const DNP3_START_BYTE_1: u8 = 0x64;
const DNP3_LINK_HEADER_LEN: usize = 10;
const G120_GROUP: u8 = 0x78; // Group 120

// ---------------------------------------------------------------------------
// Decoder
// ---------------------------------------------------------------------------

#[derive(Default)]
pub(crate) struct Dnp3Sav5Decoder;

impl SessionDecoder for Dnp3Sav5Decoder {
    fn name(&self) -> &'static str {
        "dnp3_sav5"
    }

    fn interest(&self) -> &'static [DecoderInterest] {
        &[DecoderInterest::TcpPort(20000)]
    }

    fn on_stream_chunk(&mut self, chunk: &StreamChunk<'_>, out: &mut Vec<BronzeEvent>) {
        let buf = chunk.payload;

        // Minimum viable frame: link header (10 bytes) + transport (1) + app (2)
        if buf.len() < DNP3_LINK_HEADER_LEN {
            return;
        }

        // Verify link-layer start bytes.
        if buf[0] != DNP3_START_BYTE_0 || buf[1] != DNP3_START_BYTE_1 {
            return;
        }

        // Validate link-layer length field (byte 2). Per spec, length covers
        // control through end of user data (excluding CRCs), minimum 5.
        let link_len = buf[2] as usize;
        if link_len < 5 {
            // Corrupted link header — length below protocol minimum.
            let envelope = build_envelope(
                &chunk.context,
                chunk.interface_id,
                chunk.frame_index,
                chunk.timestamp,
                chunk.segment_hash,
                TransportProtocol::Tcp,
                Some("dnp3_sav5"),
                chunk.captured_len,
                chunk.session_key.clone(),
            );
            out.push(parse_anomaly_event(
                chunk.capture_id.to_string(),
                envelope,
                self.name(),
                "low",
                "DNP3-SAv5: corrupted DNP3 link header (length field below minimum)",
                buf,
            ));
            return;
        }

        // Extract link-layer addresses (bytes 4-5 = dest LE, bytes 6-7 = src LE).
        let dest_addr = u16::from_le_bytes([buf[4], buf[5]]);
        let src_addr = u16::from_le_bytes([buf[6], buf[7]]);

        // Scan for g120 object headers in user data (after the 10-byte link header).
        // We do a linear scan ignoring CRC block boundaries — false positive rate
        // for the 0x78 0x01..0x0F pattern is negligible in OT traffic.
        let user_data = &buf[DNP3_LINK_HEADER_LEN..];
        let variations = find_g120_variations(user_data);

        if variations.is_empty() {
            // No SAv5 objects; let the main DNP3 decoder handle this frame.
            return;
        }

        // Deduplicate and name the variations found.
        let mut seen: Vec<u8> = variations.clone();
        seen.dedup();
        let names: Vec<&'static str> = seen.iter().copied().map(g120_variation_name).collect();
        let variations_seen_str = names.join(",");

        // Use the first (dominant) variation for the operation name.
        let primary_var = seen[0];
        let operation = g120_variation_name(primary_var);

        let envelope = build_envelope(
            &chunk.context,
            chunk.interface_id,
            chunk.frame_index,
            chunk.timestamp,
            chunk.segment_hash,
            TransportProtocol::Tcp,
            Some("dnp3_sav5"),
            chunk.captured_len,
            chunk.session_key.clone(),
        );

        // --- ProtocolTransaction ---
        let mut attributes = BTreeMap::new();
        attributes.insert("dnp3_source_addr".to_string(), src_addr.to_string());
        attributes.insert("dnp3_dest_addr".to_string(), dest_addr.to_string());
        attributes.insert("g120_variation".to_string(), primary_var.to_string());
        attributes.insert("variations_seen".to_string(), variations_seen_str);

        out.push(new_event(
            chunk.capture_id.to_string(),
            envelope.clone(),
            BronzeEventFamily::ProtocolTransaction(ProtocolTransaction {
                operation: operation.to_string(),
                status: "observed".to_string(),
                request_summary: Some(format!("{operation} src={src_addr} dst={dest_addr}")),
                response_summary: None,
                object_refs: vec![format!("dnp3:g120v{primary_var}")],
                values: Vec::new(),
                attributes,
                modbus: None,
                protocol_fields: None,
            }),
        ));

        // --- AssetObservation for source address ---
        out.push(new_event(
            chunk.capture_id.to_string(),
            envelope.clone(),
            BronzeEventFamily::AssetObservation(AssetObservation {
                asset_key: chunk.context.src_ip.to_string(),
                role: Some("dnp3_sav5_capable".to_string()),
                vendor: None,
                model: None,
                firmware: None,
                hostnames: Vec::new(),
                protocols: vec!["dnp3_sav5".to_string()],
                identifiers: BTreeMap::from([("dnp3_addr".to_string(), src_addr.to_string())]),
            }),
        ));

        // --- ParseAnomaly on g120v7 (Authentication Error) ---
        if seen.contains(&7) {
            out.push(parse_anomaly_event(
                chunk.capture_id.to_string(),
                envelope,
                self.name(),
                "high",
                "DNP3-SAv5 Authentication Error — auth failure on the wire",
                buf,
            ));
        }
    }
}

// ---------------------------------------------------------------------------
// g120 scan helpers
// ---------------------------------------------------------------------------

/// Scan `data` for bytes matching `0x78 0xVV` where VV is a valid g120
/// variation (0x01..=0x0F). Returns variations in order of appearance
/// (may contain duplicates if multiple headers appear in one frame).
fn find_g120_variations(data: &[u8]) -> Vec<u8> {
    let mut result = Vec::new();
    if data.len() < 2 {
        return result;
    }
    for i in 0..data.len() - 1 {
        if data[i] == G120_GROUP {
            let var = data[i + 1];
            if (0x01..=0x0F).contains(&var) {
                result.push(var);
            }
        }
    }
    result
}

/// Map a g120 variation number to its canonical operation name.
fn g120_variation_name(var: u8) -> &'static str {
    match var {
        1 => "dnp3_sav5_challenge",
        2 => "dnp3_sav5_reply",
        3 => "dnp3_sav5_aggressive_request",
        4 => "dnp3_sav5_session_key_status_request",
        5 => "dnp3_sav5_session_key_status",
        6 => "dnp3_sav5_session_key_change",
        7 => "dnp3_sav5_error",
        8 => "dnp3_sav5_user_cert",
        9 => "dnp3_sav5_mac",
        10 => "dnp3_sav5_user_status_change",
        11 => "dnp3_sav5_update_key_change_req",
        12 => "dnp3_sav5_update_key_change_reply",
        13 => "dnp3_sav5_update_key_change",
        14 => "dnp3_sav5_update_key_signature",
        15 => "dnp3_sav5_update_key_confirmation",
        _ => "dnp3_sav5_unknown_var",
    }
}

// ---------------------------------------------------------------------------
// Self-registration
// ---------------------------------------------------------------------------

inventory::submit!(crate::engine::decoders::DecoderRegistration {
    name: "dnp3_sav5",
    factory: || Box::new(Dnp3Sav5Decoder),
});

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    use chrono::Utc;

    use crate::engine::StreamChunk;
    use crate::registry::PacketContext;

    // -----------------------------------------------------------------------
    // Test helpers
    // -----------------------------------------------------------------------

    fn ctx() -> PacketContext {
        PacketContext {
            src_mac: [0u8; 6],
            dst_mac: [0u8; 6],
            src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            dst_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            src_port: 12345,
            dst_port: 20000,
            vlan_id: None,
            timestamp: 0,
        }
    }

    fn chunk<'a>(payload: &'a [u8]) -> StreamChunk<'a> {
        StreamChunk {
            capture_id: "test-cap",
            segment_hash: "deadbeef",
            interface_id: 0,
            frame_index: 1,
            timestamp: Utc::now(),
            context: ctx(),
            ethertype: 0x0800,
            ip_proto: Some(6),
            llc: None,
            transport: TransportProtocol::Tcp,
            payload,
            session_key: "10.0.0.1:12345-10.0.0.2:20000".to_string(),
            captured_len: payload.len() as u64,
        }
    }

    /// Build a minimal DNP3 frame with:
    ///   - 10-byte link header (start bytes, length=0x05, control, dest LE, src LE, dummy CRC)
    ///   - transport byte
    ///   - 2-byte app header
    ///   - `user_bytes` appended directly (for g120 object headers etc.)
    fn dnp3_frame(dest: u16, src: u16, user_bytes: &[u8]) -> Vec<u8> {
        let mut frame = Vec::new();
        // Start bytes
        frame.push(0x05);
        frame.push(0x64);
        // Length (minimum valid = 5; we use a larger value to pass validation)
        frame.push(0x10);
        // Control byte (DIR=1, PRM=1, FCB=0, FCV=0, FC=0x04 = user data)
        frame.push(0xC4);
        // Destination address (LE)
        frame.extend_from_slice(&dest.to_le_bytes());
        // Source address (LE)
        frame.extend_from_slice(&src.to_le_bytes());
        // Link CRC (dummy, recognition does not validate)
        frame.extend_from_slice(&[0x00, 0x00]);
        // Transport byte (FIN|FIR = 0xC0, SEQ=0)
        frame.push(0xC0);
        // Application header: AC (FIR|FIN = 0xC0), FC (read = 0x01)
        frame.push(0xC0);
        frame.push(0x01);
        // User/object data
        frame.extend_from_slice(user_bytes);
        frame
    }

    // -----------------------------------------------------------------------
    // Test 1: g120v1 Challenge — emits ProtocolTransaction + AssetObservation
    // -----------------------------------------------------------------------
    #[test]
    fn test_g120v1_challenge_emits_transaction_and_asset() {
        let mut decoder = Dnp3Sav5Decoder;
        // dest=1, src=2; g120v1 object header followed by qualifier 0x50
        let frame = dnp3_frame(1, 2, &[0x78, 0x01, 0x50]);
        let mut out = Vec::new();
        decoder.on_stream_chunk(&chunk(&frame), &mut out);

        // Must emit at least ProtocolTransaction + AssetObservation
        assert!(
            out.len() >= 2,
            "expected at least 2 events, got {}",
            out.len()
        );

        let tx = out.iter().find_map(|e| {
            if let BronzeEventFamily::ProtocolTransaction(ref tx) = e.family {
                Some(tx.clone())
            } else {
                None
            }
        });
        let tx = tx.expect("ProtocolTransaction not found");
        assert_eq!(tx.operation, "dnp3_sav5_challenge");
        assert_eq!(tx.status, "observed");
        assert_eq!(
            tx.attributes.get("dnp3_source_addr").map(String::as_str),
            Some("2")
        );
        assert_eq!(
            tx.attributes.get("dnp3_dest_addr").map(String::as_str),
            Some("1")
        );
        assert_eq!(
            tx.attributes.get("g120_variation").map(String::as_str),
            Some("1")
        );

        let asset = out.iter().find_map(|e| {
            if let BronzeEventFamily::AssetObservation(ref a) = e.family {
                Some(a.clone())
            } else {
                None
            }
        });
        let asset = asset.expect("AssetObservation not found");
        assert_eq!(asset.role.as_deref(), Some("dnp3_sav5_capable"));
        assert_eq!(
            asset.identifiers.get("dnp3_addr").map(String::as_str),
            Some("2")
        );

        // No ParseAnomaly on a clean challenge
        let anomaly_count = out
            .iter()
            .filter(|e| matches!(e.family, BronzeEventFamily::ParseAnomaly(_)))
            .count();
        assert_eq!(anomaly_count, 0);
    }

    // -----------------------------------------------------------------------
    // Test 2: g120v2 Reply
    // -----------------------------------------------------------------------
    #[test]
    fn test_g120v2_reply() {
        let mut decoder = Dnp3Sav5Decoder;
        let frame = dnp3_frame(3, 4, &[0x78, 0x02, 0x50]);
        let mut out = Vec::new();
        decoder.on_stream_chunk(&chunk(&frame), &mut out);

        let tx = out.iter().find_map(|e| {
            if let BronzeEventFamily::ProtocolTransaction(ref tx) = e.family {
                Some(tx.clone())
            } else {
                None
            }
        });
        let tx = tx.expect("ProtocolTransaction not found");
        assert_eq!(tx.operation, "dnp3_sav5_reply");
        assert_eq!(
            tx.attributes.get("dnp3_source_addr").map(String::as_str),
            Some("4")
        );
        assert_eq!(
            tx.attributes.get("dnp3_dest_addr").map(String::as_str),
            Some("3")
        );
    }

    // -----------------------------------------------------------------------
    // Test 3: g120v7 Auth Error — emits transaction + high-severity ParseAnomaly
    // -----------------------------------------------------------------------
    #[test]
    fn test_g120v7_auth_error_emits_high_anomaly() {
        let mut decoder = Dnp3Sav5Decoder;
        let frame = dnp3_frame(10, 20, &[0x78, 0x07, 0x50]);
        let mut out = Vec::new();
        decoder.on_stream_chunk(&chunk(&frame), &mut out);

        let tx = out.iter().find_map(|e| {
            if let BronzeEventFamily::ProtocolTransaction(ref tx) = e.family {
                Some(tx.clone())
            } else {
                None
            }
        });
        let tx = tx.expect("ProtocolTransaction not found");
        assert_eq!(tx.operation, "dnp3_sav5_error");

        let anomaly = out.iter().find_map(|e| {
            if let BronzeEventFamily::ParseAnomaly(ref a) = e.family {
                Some(a.clone())
            } else {
                None
            }
        });
        let anomaly = anomaly.expect("ParseAnomaly not found for g120v7");
        assert_eq!(anomaly.severity, "high");
        assert!(
            anomaly.reason.contains("Authentication Error"),
            "unexpected reason: {}",
            anomaly.reason
        );
    }

    // -----------------------------------------------------------------------
    // Test 4: Non-SAv5 DNP3 frame (g30v1 analog input) — no events
    // -----------------------------------------------------------------------
    #[test]
    fn test_non_sav5_frame_emits_no_events() {
        let mut decoder = Dnp3Sav5Decoder;
        // g30v1 = group 30, variation 1 (Analog Input); object header 0x1E 0x01
        let frame = dnp3_frame(5, 6, &[0x1E, 0x01, 0x00, 0x00, 0x01, 0x00]);
        let mut out = Vec::new();
        decoder.on_stream_chunk(&chunk(&frame), &mut out);
        assert!(
            out.is_empty(),
            "expected no events for non-SAv5 frame, got {}",
            out.len()
        );
    }

    // -----------------------------------------------------------------------
    // Test 5: Corrupted link header (length < 5) → low-severity ParseAnomaly
    // -----------------------------------------------------------------------
    #[test]
    fn test_corrupted_link_header_emits_low_anomaly() {
        let mut decoder = Dnp3Sav5Decoder;
        // Valid start bytes but length=0x02 (below minimum of 5)
        let frame = vec![
            0x05, 0x64, 0x02, 0xC4, // start, start, bad_length, control
            0x01, 0x00, // dest addr LE
            0x02, 0x00, // src addr LE
            0x00, 0x00, // link CRC
            0x78, 0x01, // g120v1 (should not be reached)
        ];
        let mut out = Vec::new();
        decoder.on_stream_chunk(&chunk(&frame), &mut out);

        assert_eq!(out.len(), 1, "expected exactly 1 event (ParseAnomaly)");
        let anomaly = match &out[0].family {
            BronzeEventFamily::ParseAnomaly(a) => a.clone(),
            other => panic!("expected ParseAnomaly, got {:?}", other),
        };
        assert_eq!(anomaly.severity, "low");
        assert!(
            anomaly.reason.contains("corrupted"),
            "unexpected reason: {}",
            anomaly.reason
        );
    }

    // -----------------------------------------------------------------------
    // Test 6: Multiple g120 variations in one frame — variations_seen populated
    // -----------------------------------------------------------------------
    #[test]
    fn test_multiple_variations_in_one_frame() {
        let mut decoder = Dnp3Sav5Decoder;
        // Frame containing g120v1 then g120v9 (MAC)
        let frame = dnp3_frame(7, 8, &[0x78, 0x01, 0x50, 0x78, 0x09, 0x50]);
        let mut out = Vec::new();
        decoder.on_stream_chunk(&chunk(&frame), &mut out);

        let tx = out.iter().find_map(|e| {
            if let BronzeEventFamily::ProtocolTransaction(ref tx) = e.family {
                Some(tx.clone())
            } else {
                None
            }
        });
        let tx = tx.expect("ProtocolTransaction not found");
        // Primary operation is the first variation
        assert_eq!(tx.operation, "dnp3_sav5_challenge");
        let variations_seen = tx
            .attributes
            .get("variations_seen")
            .expect("variations_seen missing");
        assert!(
            variations_seen.contains("dnp3_sav5_challenge"),
            "variations_seen missing challenge: {variations_seen}"
        );
        assert!(
            variations_seen.contains("dnp3_sav5_mac"),
            "variations_seen missing mac: {variations_seen}"
        );
    }

    // -----------------------------------------------------------------------
    // Test 7: Frame too short (< 10 bytes) — silently ignored, no events
    // -----------------------------------------------------------------------
    #[test]
    fn test_short_frame_ignored() {
        let mut decoder = Dnp3Sav5Decoder;
        let frame = vec![0x05, 0x64, 0x10, 0xC4]; // only 4 bytes
        let mut out = Vec::new();
        decoder.on_stream_chunk(&chunk(&frame), &mut out);
        assert!(out.is_empty(), "short frame should produce no events");
    }
}
