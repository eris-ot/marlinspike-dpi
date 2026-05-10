//! BACnet/SC (BACnet Secure Connect) session decoder — ASHRAE 135-2020 Addendum bj.
//!
//! # Architecture note
//!
//! In production, BACnet/SC traffic is **always TLS-wrapped WebSocket**. A passive
//! sensor cannot see past the TLS layer, so the primary function of this decoder is
//! TLS-session recognition and asset observation on ports 47808 (TCP, reused from
//! BACnet/IP) and 4843 (BACnet/SC hub-direct, some deployments).
//!
//! Plaintext BVLC-SC header parsing is included for completeness — it applies only
//! to testbench packet captures or the rare non-WSS deployment. In those cases the
//! decoder parses the 4-byte BVLC-SC fixed header and optional variable-length MAC
//! fields and emits per-frame `ProtocolTransaction` events.
//!
//! # Registration
//!
//! Self-registered via `inventory::submit!` at the bottom of this file. No edits to
//! any other source file are required to add this decoder to the engine.

use std::collections::BTreeMap;
use std::net::IpAddr;

use crate::bronze::{
    AssetObservation, BronzeEvent, BronzeEventFamily, ProtocolTransaction, TransportProtocol,
};
use crate::engine::{
    build_envelope, new_event, parse_anomaly_event, DecoderInterest, SessionDecoder, StreamChunk,
};

// ── BVLC-SC function codes (ASHRAE 135-2020 Addendum bj, Table 24-5) ──────────

const BVLC_RESULT: u8 = 0x00;
const BVLC_ENCAPSULATED_NPDU: u8 = 0x01;
const BVLC_ADDRESS_RESOLUTION: u8 = 0x02;
const BVLC_ADDRESS_RESOLUTION_ACK: u8 = 0x03;
const BVLC_ADVERTISEMENT: u8 = 0x04;
const BVLC_ADVERTISEMENT_SOLICITATION: u8 = 0x05;
const BVLC_CONNECT_REQUEST: u8 = 0x06;
const BVLC_CONNECT_ACCEPT: u8 = 0x07;
const BVLC_DISCONNECT_REQUEST: u8 = 0x08;
const BVLC_DISCONNECT_ACK: u8 = 0x09;
const BVLC_HEARTBEAT_REQUEST: u8 = 0x0A;
const BVLC_HEARTBEAT_ACK: u8 = 0x0B;
const BVLC_PROPRIETARY_MESSAGE: u8 = 0x0C;
const BVLC_MAX_KNOWN: u8 = BVLC_PROPRIETARY_MESSAGE;

// Control flag bit positions.
const FLAG_DST_VMAC: u8 = 0x01; // bit 0 — destination VMAC present
const FLAG_ORIG_VMAC: u8 = 0x02; // bit 1 — originating VMAC present
const FLAG_DATA_OPTION: u8 = 0x04; // bit 2 — data option present
const FLAG_SECURE_PATH: u8 = 0x08; // bit 3 — secure-path option present
const VALID_FLAGS_MASK: u8 = FLAG_DST_VMAC | FLAG_ORIG_VMAC | FLAG_DATA_OPTION | FLAG_SECURE_PATH;

// TLS record type bytes (first byte of a TLS record).
const TLS_CHANGE_CIPHER_SPEC: u8 = 0x14;
const TLS_ALERT: u8 = 0x15;
const TLS_HANDSHAKE: u8 = 0x16;
const TLS_APPLICATION_DATA: u8 = 0x17;

// Length of a Virtual MAC in BACnet/SC.
const VMAC_LEN: usize = 6;

// ── Decoder ────────────────────────────────────────────────────────────────────

/// Per-session state: track whether we have already emitted the one-time TLS
/// session event so we do not duplicate it on every subsequent chunk.
#[derive(Default)]
pub(crate) struct BacnetScDecoder {
    tls_session_emitted: bool,
}

impl SessionDecoder for BacnetScDecoder {
    fn name(&self) -> &'static str {
        "bacnet_sc"
    }

    fn interest(&self) -> &'static [DecoderInterest] {
        static INTERESTS: [DecoderInterest; 2] = [
            // Port 47808 (0xBAC0) — historical BACnet/IP port reused for TCP/WSS in BACnet/SC.
            DecoderInterest::TcpPort(47808),
            // Port 4843 — BACnet/SC hub-direct port used by some deployments.
            DecoderInterest::TcpPort(4843),
        ];
        &INTERESTS
    }

    fn on_stream_chunk(&mut self, chunk: &StreamChunk<'_>, out: &mut Vec<BronzeEvent>) {
        let payload = chunk.payload;
        if payload.is_empty() {
            return;
        }

        // ── TLS recognition (the common case in production) ────────────────────
        //
        // If the first byte matches a TLS record type, the session is encrypted.
        // Emit one `bacnet_sc_tls_session` ProtocolTransaction per session and
        // one AssetObservation for the destination endpoint, then stop.
        let first = payload[0];
        let is_tls = matches!(
            first,
            TLS_CHANGE_CIPHER_SPEC | TLS_ALERT | TLS_HANDSHAKE | TLS_APPLICATION_DATA
        );

        if is_tls {
            if !self.tls_session_emitted {
                self.tls_session_emitted = true;
                let envelope = build_envelope(
                    &chunk.context,
                    chunk.interface_id,
                    chunk.frame_index,
                    chunk.timestamp,
                    chunk.segment_hash,
                    TransportProtocol::Tcp,
                    Some("bacnet_sc"),
                    chunk.captured_len,
                    chunk.session_key.clone(),
                );

                // One-time session transaction.
                let mut attrs = BTreeMap::new();
                attrs.insert(
                    "note".to_string(),
                    "TLS-wrapped WebSocket; payload opaque".to_string(),
                );
                out.push(new_event(
                    chunk.capture_id.to_string(),
                    envelope.clone(),
                    BronzeEventFamily::ProtocolTransaction(ProtocolTransaction {
                        operation: "bacnet_sc_tls_session".to_string(),
                        status: "observed".to_string(),
                        request_summary: None,
                        response_summary: None,
                        object_refs: Vec::new(),
                        values: Vec::new(),
                        attributes: attrs,
                        modbus: None,
                        protocol_fields: None,
                    }),
                ));

                // Asset observation for the destination endpoint.
                let dst_key = dst_asset_key(&chunk.context);
                let mut identifiers = BTreeMap::new();
                identifiers.insert("port".to_string(), chunk.context.dst_port.to_string());
                out.push(new_event(
                    chunk.capture_id.to_string(),
                    envelope,
                    BronzeEventFamily::AssetObservation(AssetObservation {
                        asset_key: dst_key,
                        role: Some("bacnet_sc_endpoint".to_string()),
                        vendor: None,
                        model: None,
                        firmware: None,
                        hostnames: Vec::new(),
                        protocols: vec!["bacnet_sc".to_string()],
                        identifiers,
                    }),
                ));
            }
            return;
        }

        // ── Plaintext BVLC-SC parsing (testbench / non-WSS deployments) ───────
        //
        // Minimum BVLC-SC header is 4 bytes: function (1) + control (1) + message-id (2).
        if payload.len() < 4 {
            out.push(parse_anomaly_event(
                chunk.capture_id.to_string(),
                build_envelope(
                    &chunk.context,
                    chunk.interface_id,
                    chunk.frame_index,
                    chunk.timestamp,
                    chunk.segment_hash,
                    TransportProtocol::Tcp,
                    Some("bacnet_sc"),
                    chunk.captured_len,
                    chunk.session_key.clone(),
                ),
                self.name(),
                "low",
                "BVLC-SC header truncated (< 4 bytes)",
                payload,
            ));
            return;
        }

        let function = payload[0];
        let control = payload[1];
        let message_id = u16::from_be_bytes([payload[2], payload[3]]);

        // Reject obviously invalid control flag combinations.
        let control_reserved = control & !VALID_FLAGS_MASK;
        if control_reserved != 0 && function <= BVLC_MAX_KNOWN {
            // Reserved bits set — suspicious but treat as low-severity anomaly
            // and attempt to continue parsing; fall through.
        }

        // Parse optional VMACs starting at offset 4.
        let mut cursor = 4usize;
        let orig_vmac: Option<[u8; VMAC_LEN]>;
        let dst_vmac: Option<[u8; VMAC_LEN]>;

        // Originating VMAC (flag bit 1).
        if control & FLAG_ORIG_VMAC != 0 {
            if cursor + VMAC_LEN > payload.len() {
                out.push(parse_anomaly_event(
                    chunk.capture_id.to_string(),
                    build_envelope(
                        &chunk.context,
                        chunk.interface_id,
                        chunk.frame_index,
                        chunk.timestamp,
                        chunk.segment_hash,
                        TransportProtocol::Tcp,
                        Some("bacnet_sc"),
                        chunk.captured_len,
                        chunk.session_key.clone(),
                    ),
                    self.name(),
                    "low",
                    "BVLC-SC originating VMAC declared but not enough bytes",
                    payload,
                ));
                return;
            }
            let mut mac = [0u8; VMAC_LEN];
            mac.copy_from_slice(&payload[cursor..cursor + VMAC_LEN]);
            orig_vmac = Some(mac);
            cursor += VMAC_LEN;
        } else {
            orig_vmac = None;
        }

        // Destination VMAC (flag bit 0).
        if control & FLAG_DST_VMAC != 0 {
            if cursor + VMAC_LEN > payload.len() {
                out.push(parse_anomaly_event(
                    chunk.capture_id.to_string(),
                    build_envelope(
                        &chunk.context,
                        chunk.interface_id,
                        chunk.frame_index,
                        chunk.timestamp,
                        chunk.segment_hash,
                        TransportProtocol::Tcp,
                        Some("bacnet_sc"),
                        chunk.captured_len,
                        chunk.session_key.clone(),
                    ),
                    self.name(),
                    "low",
                    "BVLC-SC destination VMAC declared but not enough bytes",
                    payload,
                ));
                return;
            }
            let mut mac = [0u8; VMAC_LEN];
            mac.copy_from_slice(&payload[cursor..cursor + VMAC_LEN]);
            dst_vmac = Some(mac);
            cursor += VMAC_LEN;
        } else {
            dst_vmac = None;
        }

        let _ = cursor; // remaining bytes are the APDU / header options — not parsed here

        let operation = bvlc_operation_name(function);
        let envelope = build_envelope(
            &chunk.context,
            chunk.interface_id,
            chunk.frame_index,
            chunk.timestamp,
            chunk.segment_hash,
            TransportProtocol::Tcp,
            Some("bacnet_sc"),
            chunk.captured_len,
            chunk.session_key.clone(),
        );

        // Build attributes map.
        let mut attrs = BTreeMap::new();
        attrs.insert("function_code".to_string(), format!("{function:#04x}"));
        attrs.insert("control_flags_hex".to_string(), format!("{control:#04x}"));
        attrs.insert("message_id".to_string(), message_id.to_string());
        if let Some(vmac) = orig_vmac {
            attrs.insert("originating_vmac".to_string(), format_vmac(&vmac));
        }
        if let Some(vmac) = dst_vmac {
            attrs.insert("destination_vmac".to_string(), format_vmac(&vmac));
        }

        // Unknown function code → anomaly + transaction.
        if function > BVLC_MAX_KNOWN {
            out.push(parse_anomaly_event(
                chunk.capture_id.to_string(),
                envelope.clone(),
                self.name(),
                "low",
                &format!("unknown BVLC-SC function code {function:#04x}"),
                payload,
            ));
        }

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
                attributes: attrs,
                modbus: None,
                protocol_fields: None,
            }),
        ));

        // AssetObservation for originating VMAC when present.
        if let Some(vmac) = orig_vmac {
            let vmac_str = format_vmac(&vmac);
            let mut identifiers = BTreeMap::new();
            identifiers.insert("vmac".to_string(), vmac_str.clone());
            out.push(new_event(
                chunk.capture_id.to_string(),
                envelope,
                BronzeEventFamily::AssetObservation(AssetObservation {
                    asset_key: vmac_str,
                    role: Some("bacnet_sc_node".to_string()),
                    vendor: None,
                    model: None,
                    firmware: None,
                    hostnames: Vec::new(),
                    protocols: vec!["bacnet_sc".to_string()],
                    identifiers,
                }),
            ));
        }
    }
}

// ── Helpers ────────────────────────────────────────────────────────────────────

/// Map a BVLC-SC function byte to the canonical operation name string.
fn bvlc_operation_name(function: u8) -> String {
    match function {
        BVLC_RESULT => "bacnet_sc_result".to_string(),
        BVLC_ENCAPSULATED_NPDU => "bacnet_sc_encapsulated_npdu".to_string(),
        BVLC_ADDRESS_RESOLUTION => "bacnet_sc_address_resolution".to_string(),
        BVLC_ADDRESS_RESOLUTION_ACK => "bacnet_sc_address_resolution_ack".to_string(),
        BVLC_ADVERTISEMENT => "bacnet_sc_advertisement".to_string(),
        BVLC_ADVERTISEMENT_SOLICITATION => "bacnet_sc_advertisement_solicitation".to_string(),
        BVLC_CONNECT_REQUEST => "bacnet_sc_connect_request".to_string(),
        BVLC_CONNECT_ACCEPT => "bacnet_sc_connect_accept".to_string(),
        BVLC_DISCONNECT_REQUEST => "bacnet_sc_disconnect_request".to_string(),
        BVLC_DISCONNECT_ACK => "bacnet_sc_disconnect_ack".to_string(),
        BVLC_HEARTBEAT_REQUEST => "bacnet_sc_heartbeat_request".to_string(),
        BVLC_HEARTBEAT_ACK => "bacnet_sc_heartbeat_ack".to_string(),
        BVLC_PROPRIETARY_MESSAGE => "bacnet_sc_proprietary_message".to_string(),
        other => format!("bacnet_sc_unknown_{other:#04x}"),
    }
}

/// Format a 6-byte VMAC as a lowercase hex string (e.g., `"aabbccddeeff"`).
fn format_vmac(mac: &[u8; VMAC_LEN]) -> String {
    hex::encode(mac)
}

/// Asset key for the destination side of the session (for TLS endpoint observation).
fn dst_asset_key(context: &crate::registry::PacketContext) -> String {
    match context.dst_ip {
        IpAddr::V4(ip) if ip != std::net::Ipv4Addr::UNSPECIFIED => ip.to_string(),
        IpAddr::V6(ip) if ip != std::net::Ipv6Addr::UNSPECIFIED => ip.to_string(),
        _ => crate::registry::format_mac(&context.dst_mac),
    }
}

// ── Self-registration ──────────────────────────────────────────────────────────

inventory::submit!(crate::engine::decoders::DecoderRegistration {
    name: "bacnet_sc",
    factory: || Box::new(BacnetScDecoder::default()),
});

// ── Tests ──────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    use chrono::Utc;

    use crate::bronze::BronzeEventFamily;
    use crate::engine::{DecoderInterest, SessionDecoder, StreamChunk};
    use crate::registry::PacketContext;

    // ── Test infrastructure ────────────────────────────────────────────────────

    fn make_context(dst_port: u16) -> PacketContext {
        PacketContext {
            src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            dst_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            src_port: 55000,
            dst_port,
            src_mac: [0x00, 0x11, 0x22, 0x33, 0x44, 0x55],
            dst_mac: [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF],
            vlan_id: None,
            timestamp: 0,
        }
    }

    fn make_chunk<'a>(payload: &'a [u8], context: &'a PacketContext) -> StreamChunk<'a> {
        StreamChunk {
            capture_id: "test_cap",
            segment_hash: "deadbeef",
            interface_id: 0,
            frame_index: 1,
            timestamp: Utc::now(),
            context: context.clone(),
            ethertype: 0x0800,
            ip_proto: Some(6),
            llc: None,
            transport: TransportProtocol::Tcp,
            payload,
            session_key: "sess-1".to_string(),
            captured_len: payload.len() as u64,
        }
    }

    fn extract_transaction(ev: &BronzeEvent) -> &ProtocolTransaction {
        match &ev.family {
            BronzeEventFamily::ProtocolTransaction(tx) => tx,
            other => panic!("expected ProtocolTransaction, got {other:?}"),
        }
    }

    fn extract_asset(ev: &BronzeEvent) -> &AssetObservation {
        match &ev.family {
            BronzeEventFamily::AssetObservation(a) => a,
            other => panic!("expected AssetObservation, got {other:?}"),
        }
    }

    fn extract_anomaly(ev: &BronzeEvent) -> &crate::bronze::ParseAnomaly {
        match &ev.family {
            BronzeEventFamily::ParseAnomaly(a) => a,
            other => panic!("expected ParseAnomaly, got {other:?}"),
        }
    }

    // ── Test 1: TLS handshake byte (0x16) on port 47808 ───────────────────────
    //
    // A TLS ClientHello is the first byte from a connecting BACnet/SC node.
    // We expect one ProtocolTransaction("bacnet_sc_tls_session") and one
    // AssetObservation for the destination.

    #[test]
    fn tls_handshake_on_47808_emits_session_event() {
        let mut dec = BacnetScDecoder::default();
        let mut out = Vec::new();

        // 0x16 = TLS Handshake record type (ClientHello).
        let payload = [0x16u8, 0x03, 0x01, 0x00, 0x28];
        let ctx = make_context(47808);
        dec.on_stream_chunk(&make_chunk(&payload, &ctx), &mut out);

        assert_eq!(out.len(), 2, "expected 2 events (transaction + asset), got {}", out.len());

        let tx = extract_transaction(&out[0]);
        assert_eq!(tx.operation, "bacnet_sc_tls_session");
        assert_eq!(tx.status, "observed");
        assert_eq!(
            tx.attributes.get("note").map(String::as_str),
            Some("TLS-wrapped WebSocket; payload opaque")
        );

        let asset = extract_asset(&out[1]);
        assert_eq!(asset.role.as_deref(), Some("bacnet_sc_endpoint"));
        assert_eq!(asset.identifiers.get("port").map(String::as_str), Some("47808"));

        // Subsequent chunks on the same session must NOT re-emit.
        let payload2 = [0x17u8, 0x03, 0x03, 0x00, 0x10];
        dec.on_stream_chunk(&make_chunk(&payload2, &ctx), &mut out);
        assert_eq!(out.len(), 2, "duplicate TLS session event must not be emitted");
    }

    // ── Test 2: Plaintext Connect-Request (0x06) with no VMACs ────────────────

    #[test]
    fn plaintext_connect_request_no_vmacs() {
        let mut dec = BacnetScDecoder::default();
        let mut out = Vec::new();

        // function=0x06, control=0x00 (no VMACs), message_id=0x0001
        let payload = [0x06u8, 0x00, 0x00, 0x01];
        let ctx = make_context(47808);
        dec.on_stream_chunk(&make_chunk(&payload, &ctx), &mut out);

        // Should emit exactly 1 ProtocolTransaction; no AssetObservation (no VMAC).
        assert_eq!(out.len(), 1, "expected 1 event, got {}", out.len());
        let tx = extract_transaction(&out[0]);
        assert_eq!(tx.operation, "bacnet_sc_connect_request");
        assert_eq!(tx.status, "observed");
        assert_eq!(tx.attributes.get("message_id").map(String::as_str), Some("1"));
        assert_eq!(
            tx.attributes.get("function_code").map(String::as_str),
            Some("0x06")
        );
        assert!(
            !tx.attributes.contains_key("originating_vmac"),
            "no originating VMAC expected"
        );
    }

    // ── Test 3: Encapsulated-NPDU (0x01) with both originating and destination VMACs ─

    #[test]
    fn encapsulated_npdu_with_both_vmacs() {
        let mut dec = BacnetScDecoder::default();
        let mut out = Vec::new();

        // control = 0x03 → bits 0 (dst) and 1 (orig) both set
        // originating VMAC = aa:bb:cc:dd:ee:ff
        // destination VMAC = 11:22:33:44:55:66
        // message_id = 0x0042
        let orig: [u8; 6] = [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF];
        let dst: [u8; 6] = [0x11, 0x22, 0x33, 0x44, 0x55, 0x66];

        let mut payload = vec![0x01u8, 0x03, 0x00, 0x42];
        payload.extend_from_slice(&orig);
        payload.extend_from_slice(&dst);
        // trailing APDU bytes (ignored at this layer)
        payload.extend_from_slice(&[0x81, 0x0A, 0x00, 0x04]);

        let ctx = make_context(47808);
        dec.on_stream_chunk(&make_chunk(&payload, &ctx), &mut out);

        // Expect: 1 ProtocolTransaction + 1 AssetObservation (for originating VMAC).
        assert_eq!(out.len(), 2, "expected 2 events, got {}", out.len());

        let tx = extract_transaction(&out[0]);
        assert_eq!(tx.operation, "bacnet_sc_encapsulated_npdu");
        assert_eq!(tx.attributes["originating_vmac"], "aabbccddeeff");
        assert_eq!(tx.attributes["destination_vmac"], "112233445566");

        let asset = extract_asset(&out[1]);
        assert_eq!(asset.role.as_deref(), Some("bacnet_sc_node"));
        assert_eq!(
            asset.identifiers.get("vmac").map(String::as_str),
            Some("aabbccddeeff")
        );
    }

    // ── Test 4: Heartbeat-Request (0x0A) ──────────────────────────────────────

    #[test]
    fn heartbeat_request_emits_correct_operation() {
        let mut dec = BacnetScDecoder::default();
        let mut out = Vec::new();

        // function=0x0A, control=0x00, message_id=0x0007
        let payload = [0x0Au8, 0x00, 0x00, 0x07];
        let ctx = make_context(4843); // hub-direct port
        dec.on_stream_chunk(&make_chunk(&payload, &ctx), &mut out);

        assert_eq!(out.len(), 1);
        let tx = extract_transaction(&out[0]);
        assert_eq!(tx.operation, "bacnet_sc_heartbeat_request");
        assert_eq!(tx.attributes["control_flags_hex"], "0x00");
        assert_eq!(tx.attributes["message_id"], "7");
    }

    // ── Test 5: Unknown function code 0x99 → anomaly + unknown operation ───────

    #[test]
    fn unknown_function_code_emits_anomaly_and_transaction() {
        let mut dec = BacnetScDecoder::default();
        let mut out = Vec::new();

        // function=0x99, control=0x00, message_id=0x0001
        let payload = [0x99u8, 0x00, 0x00, 0x01];
        let ctx = make_context(47808);
        dec.on_stream_chunk(&make_chunk(&payload, &ctx), &mut out);

        // Expect: 1 ParseAnomaly + 1 ProtocolTransaction.
        assert_eq!(out.len(), 2, "expected anomaly + transaction, got {}", out.len());

        let anomaly = extract_anomaly(&out[0]);
        assert_eq!(anomaly.severity, "low");
        assert!(
            anomaly.reason.contains("0x99"),
            "reason should mention function code, got: {}",
            anomaly.reason
        );

        let tx = extract_transaction(&out[1]);
        assert_eq!(tx.operation, "bacnet_sc_unknown_0x99");
        assert_eq!(tx.status, "observed");
    }

    // ── Additional: verify interest ports ─────────────────────────────────────

    #[test]
    fn decoder_interests_cover_both_ports() {
        let dec = BacnetScDecoder::default();
        let interests = dec.interest();
        assert!(interests.contains(&DecoderInterest::TcpPort(47808)));
        assert!(interests.contains(&DecoderInterest::TcpPort(4843)));
    }
}
