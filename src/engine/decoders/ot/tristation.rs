//! TriStation protocol decoder — Schneider Electric / Triconex Safety
//! Instrumented System (SIS). Covers Tricon, Trident, and Tri-GP controllers.
//!
//! # Protocol background
//!
//! TriStation is a proprietary, undocumented protocol. This parser is built
//! from publicly available reverse-engineering research:
//!
//! - FireEye/Mandiant: "TRITON: The First ICS Malware Designed to Attack Safety
//!   Instrumented Systems" (2017) — function code names and 0x70 significance.
//! - Nozomi Networks: "Triton/Trisis ICS Malware Analysis" (2017/2018) —
//!   header layout (command_type byte 0, subtype byte 1, length bytes 2-3 LE).
//! - Dragos: "TRISIS Malware Analysis of Safety Instrumented System Targeting"
//!   (2017) — supplementary function code identification.
//!
//! **No official Schneider/Triconex vendor specification is publicly available.**
//! All field names and semantics are best-effort from the sources above.
//! This parser is intentionally conservative: it only decodes the header
//! (4 bytes) and records observed function codes — payload bytes are not
//! further interpreted to avoid false positives from protocol ambiguity.
//!
//! # Wire format (per Nozomi Networks analysis)
//!
//! ```text
//! Byte 0:   command_type  (function code, u8)
//! Byte 1:   command_subtype or reserved (u8, varies by command_type)
//! Bytes 2-3: payload_length (u16, little-endian)
//! Bytes 4+: payload (not further parsed here)
//! ```
//!
//! Transport: UDP/1502 (standard). TCP/1502 also observed in some deployments
//! but the primary attack surface (TRITON/TRISIS) used UDP.

use std::collections::BTreeMap;

use crate::bronze::{
    AssetObservation, BronzeEvent, BronzeEventFamily, ProtocolTransaction, TransportProtocol,
};
use crate::engine::{
    DecoderInterest, SessionDecoder, StreamChunk, build_envelope, new_event, parse_anomaly_event,
};

// Minimum header size: command_type(1) + command_subtype(1) + payload_length(2)
const HEADER_LEN: usize = 4;

/// TriStation function codes — source: FireEye/Mandiant, Nozomi Networks, Dragos
/// public write-ups (2017-2018). Names are best-effort; unknown codes are
/// labelled `tristation_unknown_0x<hh>`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TsFunctionCode {
    /// 0x01 — Connection Request; initiating host is an engineering workstation.
    ConnectionRequest,
    /// 0x02 — Connection Response; responding host is a Triconex controller.
    ConnectionResponse,
    /// 0x05 — Get CP (Control Processor) Status. Used by TRITON for
    /// reconnaissance and to confirm the controller is in the expected state
    /// before payload delivery (FireEye/Mandiant, 2017).
    GetCpStatus,
    /// 0x14 — Upload All; bulk program/config upload from controller.
    UploadAll,
    /// 0x1D — Connect (session-level connect distinct from 0x01).
    Connect,
    /// 0x6D — Get CPU Status.
    GetCpuStatus,
    /// 0x70 — Set Control Program. **Critical**: this is the command used by
    /// TRITON/TRISIS to deliver its malicious safety logic to Triconex
    /// controllers (FireEye/Mandiant, 2017). Any observation of this code
    /// warrants a high-severity alert.
    SetControlProgram,
    /// 0x86 — Allocate Memory.
    AllocateMemory,
    /// 0x96 — Sequence of Operation Events.
    SequenceOfOperationEvents,
    /// Unrecognised code — preserved verbatim for alerting.
    Unknown(u8),
}

impl TsFunctionCode {
    fn from_byte(b: u8) -> Self {
        match b {
            0x01 => Self::ConnectionRequest,
            0x02 => Self::ConnectionResponse,
            0x05 => Self::GetCpStatus,
            0x14 => Self::UploadAll,
            0x1D => Self::Connect,
            0x6D => Self::GetCpuStatus,
            0x70 => Self::SetControlProgram,
            0x86 => Self::AllocateMemory,
            0x96 => Self::SequenceOfOperationEvents,
            other => Self::Unknown(other),
        }
    }

    /// Bronze operation string for `ProtocolTransaction.operation`.
    fn operation_name(self) -> String {
        match self {
            Self::ConnectionRequest => "tristation_connection_request".to_string(),
            Self::ConnectionResponse => "tristation_connection_response".to_string(),
            Self::GetCpStatus => "tristation_get_cp_status".to_string(),
            Self::UploadAll => "tristation_upload_all".to_string(),
            Self::Connect => "tristation_connect".to_string(),
            Self::GetCpuStatus => "tristation_get_cpu_status".to_string(),
            Self::SetControlProgram => "tristation_set_control_program".to_string(),
            Self::AllocateMemory => "tristation_allocate_memory".to_string(),
            Self::SequenceOfOperationEvents => {
                "tristation_sequence_of_operation_events".to_string()
            }
            Self::Unknown(code) => format!("tristation_unknown_0x{code:02x}"),
        }
    }
}

/// Passive TriStation/Triconex decoder. Stateless — one event per UDP datagram.
/// No request/response pairing is attempted; UDP provides no reliable correlator
/// and the protocol's transaction IDs are not publicly documented.
#[derive(Default)]
pub(crate) struct TriStationDecoder;

impl SessionDecoder for TriStationDecoder {
    fn name(&self) -> &'static str {
        "tristation"
    }

    fn interest(&self) -> &'static [DecoderInterest] {
        &[DecoderInterest::UdpPort(1502)]
    }

    fn on_datagram(&mut self, chunk: &StreamChunk<'_>, out: &mut Vec<BronzeEvent>) {
        let payload = chunk.payload;

        if payload.len() < HEADER_LEN {
            // Too short to be a valid TriStation header; emit a low anomaly
            // rather than silently dropping — short datagrams on 1502 warrant
            // attention even if they are not parseable.
            out.push(parse_anomaly_event(
                chunk.capture_id.to_string(),
                build_envelope(
                    &chunk.context,
                    chunk.interface_id,
                    chunk.frame_index,
                    chunk.timestamp,
                    chunk.segment_hash,
                    TransportProtocol::Udp,
                    Some("tristation"),
                    chunk.captured_len,
                    chunk.session_key.clone(),
                ),
                self.name(),
                "low",
                "TriStation datagram too short to contain valid header (< 4 bytes)",
                payload,
            ));
            return;
        }

        let command_type_raw = payload[0];
        let command_subtype = payload[1];
        let payload_length = u16::from_le_bytes([payload[2], payload[3]]);
        let fc = TsFunctionCode::from_byte(command_type_raw);

        let envelope = build_envelope(
            &chunk.context,
            chunk.interface_id,
            chunk.frame_index,
            chunk.timestamp,
            chunk.segment_hash,
            TransportProtocol::Udp,
            Some("tristation"),
            chunk.captured_len,
            chunk.session_key.clone(),
        );

        // ── ProtocolTransaction ──────────────────────────────────────────────
        let mut attributes = BTreeMap::new();
        attributes.insert(
            "command_type".to_string(),
            format!("0x{command_type_raw:02x}"),
        );
        attributes.insert(
            "command_subtype".to_string(),
            format!("0x{command_subtype:02x}"),
        );
        attributes.insert("payload_length".to_string(), payload_length.to_string());

        out.push(new_event(
            chunk.capture_id.to_string(),
            envelope.clone(),
            BronzeEventFamily::ProtocolTransaction(ProtocolTransaction {
                operation: fc.operation_name(),
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

        // ── High-severity alert: Set Control Program (0x70) ─────────────────
        // TRITON/TRISIS (2017 Saudi Aramco / SABIC petrochemical attack) used
        // this function code to deliver malicious safety logic to Triconex
        // controllers. Any observation in passive capture is high-fidelity
        // evidence of either a legitimate rare engineering action or an attack
        // in progress. Source: FireEye/Mandiant TRITON report (2017).
        if fc == TsFunctionCode::SetControlProgram {
            out.push(parse_anomaly_event(
                chunk.capture_id.to_string(),
                envelope.clone(),
                self.name(),
                "high",
                "TriStation Set Control Program — TRITON/TRISIS payload-delivery command observed",
                payload,
            ));
        }

        // ── Low-severity alert: unknown function code ────────────────────────
        if let TsFunctionCode::Unknown(_) = fc {
            out.push(parse_anomaly_event(
                chunk.capture_id.to_string(),
                envelope.clone(),
                self.name(),
                "low",
                &format!(
                    "TriStation unknown function code 0x{command_type_raw:02x} — \
                     not in the publicly documented set; parser is intentionally conservative"
                ),
                payload,
            ));
        }

        // ── AssetObservation: connection handshake role attribution ──────────
        // Source: Nozomi Networks analysis — 0x01 is sent by the engineering
        // workstation, 0x02 is the controller's acknowledgment.
        match fc {
            TsFunctionCode::ConnectionRequest => {
                // The source of a connection request is an engineering workstation.
                let src_ip = chunk.context.src_ip.to_string();

                let mut identifiers = BTreeMap::new();
                identifiers.insert("endpoint".to_string(), src_ip.clone());

                out.push(new_event(
                    chunk.capture_id.to_string(),
                    envelope,
                    BronzeEventFamily::AssetObservation(AssetObservation {
                        asset_key: src_ip,
                        role: Some("tristation_engineering_workstation".to_string()),
                        vendor: None,
                        model: None,
                        firmware: None,
                        hostnames: vec![],
                        protocols: vec!["tristation".to_string()],
                        identifiers,
                    }),
                ));
            }
            TsFunctionCode::ConnectionResponse => {
                // The source of a connection response is a Triconex controller.
                let src_ip = chunk.context.src_ip.to_string();

                let mut identifiers = BTreeMap::new();
                identifiers.insert("endpoint".to_string(), src_ip.clone());

                out.push(new_event(
                    chunk.capture_id.to_string(),
                    envelope,
                    BronzeEventFamily::AssetObservation(AssetObservation {
                        asset_key: src_ip,
                        role: Some("triconex_controller".to_string()),
                        vendor: Some("Schneider Electric".to_string()),
                        model: None,
                        firmware: None,
                        hostnames: vec![],
                        protocols: vec!["tristation".to_string()],
                        identifiers,
                    }),
                ));
            }
            _ => {}
        }
    }
}

inventory::submit!(crate::engine::decoders::DecoderRegistration {
    name: "tristation",
    factory: || Box::new(TriStationDecoder),
});

#[cfg(test)]
mod tests {
    use std::net::IpAddr;

    use chrono::Utc;

    use crate::bronze::{BronzeEventFamily, TransportProtocol};
    use crate::engine::{DecoderInterest, SessionDecoder, StreamChunk};
    use crate::registry::PacketContext;

    use super::TriStationDecoder;

    /// Build a minimal `PacketContext` for test datagrams.
    fn test_context(src: &str, dst: &str) -> PacketContext {
        PacketContext {
            src_mac: [0x00, 0x11, 0x22, 0x33, 0x44, 0x55],
            dst_mac: [0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb],
            src_ip: src.parse::<IpAddr>().unwrap(),
            dst_ip: dst.parse::<IpAddr>().unwrap(),
            src_port: 45678,
            dst_port: 1502,
            vlan_id: None,
            timestamp: 0,
        }
    }

    /// Build a 4-byte TriStation header datagram: [cmd_type, cmd_subtype, len_lo, len_hi].
    fn ts_datagram(cmd_type: u8, cmd_subtype: u8, payload_len: u16) -> Vec<u8> {
        let [lo, hi] = payload_len.to_le_bytes();
        vec![cmd_type, cmd_subtype, lo, hi]
    }

    fn make_chunk<'a>(payload: &'a [u8], context: &'a PacketContext) -> StreamChunk<'a> {
        StreamChunk {
            capture_id: "test-cap",
            segment_hash: "seg-hash",
            interface_id: 0,
            frame_index: 1,
            timestamp: Utc::now(),
            context: context.clone(),
            ethertype: 0x0800,
            ip_proto: Some(17),
            llc: None,
            transport: TransportProtocol::Udp,
            payload,
            session_key: "udp:10.0.0.1:45678:10.0.0.2:1502".to_string(),
            captured_len: payload.len() as u64,
        }
    }

    // ── Test 1: Get CP Status (0x05) ──────────────────────────────────────────
    // Verifies basic ProtocolTransaction emission with operation name.
    #[test]
    fn get_cp_status_emits_protocol_transaction() {
        let mut decoder = TriStationDecoder;
        let payload = ts_datagram(0x05, 0x00, 0);
        let ctx = test_context("10.0.0.10", "10.0.0.20");
        let chunk = make_chunk(&payload, &ctx);
        let mut out = vec![];

        decoder.on_datagram(&chunk, &mut out);

        assert_eq!(out.len(), 1, "expected exactly one event for Get CP Status");
        match &out[0].family {
            BronzeEventFamily::ProtocolTransaction(tx) => {
                assert_eq!(tx.operation, "tristation_get_cp_status");
                assert_eq!(tx.status, "observed");
                assert_eq!(tx.attributes.get("command_type").unwrap(), "0x05");
            }
            other => panic!("expected ProtocolTransaction, got {:?}", other),
        }
    }

    // ── Test 2: Set Control Program (0x70) ────────────────────────────────────
    // TRITON/TRISIS payload-delivery command. Must emit ProtocolTransaction AND
    // a high-severity ParseAnomaly.
    #[test]
    fn set_control_program_emits_transaction_and_high_anomaly() {
        let mut decoder = TriStationDecoder;
        let payload = ts_datagram(0x70, 0x00, 128);
        let ctx = test_context("192.168.1.50", "192.168.1.100");
        let chunk = make_chunk(&payload, &ctx);
        let mut out = vec![];

        decoder.on_datagram(&chunk, &mut out);

        assert_eq!(out.len(), 2, "expected ProtocolTransaction + ParseAnomaly");

        let tx = out.iter().find_map(|e| {
            if let BronzeEventFamily::ProtocolTransaction(tx) = &e.family {
                Some(tx)
            } else {
                None
            }
        });
        assert!(tx.is_some(), "missing ProtocolTransaction");
        assert_eq!(tx.unwrap().operation, "tristation_set_control_program");

        let anomaly = out.iter().find_map(|e| {
            if let BronzeEventFamily::ParseAnomaly(a) = &e.family {
                Some(a)
            } else {
                None
            }
        });
        assert!(anomaly.is_some(), "missing ParseAnomaly");
        let a = anomaly.unwrap();
        assert_eq!(a.severity, "high");
        assert!(
            a.reason.contains("TRITON"),
            "reason should mention TRITON, got: {}",
            a.reason
        );
    }

    // ── Test 3: Connection Request (0x01) → AssetObservation EWS ─────────────
    #[test]
    fn connection_request_emits_ews_asset_observation() {
        let mut decoder = TriStationDecoder;
        let payload = ts_datagram(0x01, 0x00, 0);
        let ctx = test_context("10.1.2.3", "10.1.2.200");
        let chunk = make_chunk(&payload, &ctx);
        let mut out = vec![];

        decoder.on_datagram(&chunk, &mut out);

        // Expect: ProtocolTransaction + AssetObservation
        assert_eq!(out.len(), 2);

        let obs = out.iter().find_map(|e| {
            if let BronzeEventFamily::AssetObservation(o) = &e.family {
                Some(o)
            } else {
                None
            }
        });
        assert!(obs.is_some(), "missing AssetObservation");
        let o = obs.unwrap();
        assert_eq!(
            o.role.as_deref(),
            Some("tristation_engineering_workstation")
        );
        assert_eq!(
            o.identifiers.get("endpoint").map(String::as_str),
            Some("10.1.2.3")
        );
    }

    // ── Test 4: Connection Response (0x02) → AssetObservation controller ─────
    #[test]
    fn connection_response_emits_controller_asset_observation() {
        let mut decoder = TriStationDecoder;
        let payload = ts_datagram(0x02, 0x00, 0);
        let ctx = test_context("10.1.2.200", "10.1.2.3");
        let chunk = make_chunk(&payload, &ctx);
        let mut out = vec![];

        decoder.on_datagram(&chunk, &mut out);

        assert_eq!(out.len(), 2);

        let obs = out.iter().find_map(|e| {
            if let BronzeEventFamily::AssetObservation(o) = &e.family {
                Some(o)
            } else {
                None
            }
        });
        assert!(obs.is_some(), "missing AssetObservation");
        let o = obs.unwrap();
        assert_eq!(o.role.as_deref(), Some("triconex_controller"));
        assert_eq!(
            o.identifiers.get("endpoint").map(String::as_str),
            Some("10.1.2.200")
        );
        assert_eq!(o.vendor.as_deref(), Some("Schneider Electric"));
    }

    // ── Test 5: Unknown function code → low ParseAnomaly + "unknown" operation ─
    #[test]
    fn unknown_function_code_emits_low_anomaly_and_unknown_operation() {
        let mut decoder = TriStationDecoder;
        // 0xAB is not in the documented set
        let payload = ts_datagram(0xAB, 0x00, 0);
        let ctx = test_context("10.0.0.1", "10.0.0.2");
        let chunk = make_chunk(&payload, &ctx);
        let mut out = vec![];

        decoder.on_datagram(&chunk, &mut out);

        // Expect: ProtocolTransaction + low ParseAnomaly
        assert_eq!(out.len(), 2);

        let tx = out.iter().find_map(|e| {
            if let BronzeEventFamily::ProtocolTransaction(tx) = &e.family {
                Some(tx)
            } else {
                None
            }
        });
        assert!(tx.is_some());
        let op = &tx.unwrap().operation;
        assert!(
            op.contains("unknown"),
            "operation should contain 'unknown', got: {op}"
        );
        assert!(
            op.contains("0xab"),
            "operation should contain hex code, got: {op}"
        );

        let anomaly = out.iter().find_map(|e| {
            if let BronzeEventFamily::ParseAnomaly(a) = &e.family {
                Some(a)
            } else {
                None
            }
        });
        assert!(anomaly.is_some(), "missing ParseAnomaly");
        assert_eq!(anomaly.unwrap().severity, "low");
    }

    // ── Test 6: decoder interest is UDP/1502 ──────────────────────────────────
    #[test]
    fn decoder_interest_is_udp_1502() {
        let decoder = TriStationDecoder;
        assert_eq!(decoder.name(), "tristation");
        let interest = decoder.interest();
        assert_eq!(interest.len(), 1);
        assert_eq!(interest[0], DecoderInterest::UdpPort(1502));
    }
}
