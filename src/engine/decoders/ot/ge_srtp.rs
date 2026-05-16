//! GE SRTP (Service Request Transport Protocol) session decoder.
//!
//! Port 18245/TCP. GE PACSystems and Series 90 (90-30, 90-70) PLCs.
//! Wire format: 56-byte fixed header + optional variable payload.
//! References: Wireshark epan/dissectors/packet-gesrtp.c, Talos 2018 SRTP
//! research, GE GFK-2224 (partial public release).

use std::collections::{BTreeMap, HashMap};

use chrono::{DateTime, Utc};

use crate::bronze::{
    BronzeEvent, BronzeEventFamily, EventEnvelope, GeSrtpBronzeFields, ProtocolFields,
    ProtocolTransaction, TransportProtocol,
};
use crate::engine::{
    DecoderInterest, SessionDecoder, StreamChunk, build_envelope, new_event, parse_anomaly_event,
};

// ---------------------------------------------------------------------------
// Wire-format offsets
// ---------------------------------------------------------------------------

const SRTP_HEADER_LEN: usize = 56;

// Offset 2: message type. Source: Wireshark `srtp.type`.
const OFFSET_MSG_TYPE: usize = 2;

// Offsets 9..11: sequence number (LE u16). Source: Wireshark `srtp.seq`.
// Used to pair request and response within a TCP session.
const OFFSET_SEQ_NUM: usize = 9;

// Offset 31: service request code. Source: Wireshark `srtp.cmd`.
// Cross-checked with Talos annotated hex dumps; confidence: high.
const OFFSET_SERVICE_CODE: usize = 31;

// Offset 42: major status (Wireshark `srtp.stat`). Confidence: medium —
// confirmed in the Wireshark dissector source but not in the GE public manual.
const OFFSET_STATUS_CODE: usize = 42;

// Offset 43: minor status (Wireshark `srtp.minor_stat`).
const OFFSET_MINOR_STATUS: usize = 43;

const MSG_TYPE_REQUEST: u8 = 0x02;
const MSG_TYPE_RESPONSE: u8 = 0x03;

// ---------------------------------------------------------------------------
// Frame parsing
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
struct SrtpFrame {
    msg_type: u8,
    seq_num: u16,
    service_code: u8,
    status_code: u8,
    minor_status: u8,
}

fn parse_srtp_header(buf: &[u8]) -> Option<SrtpFrame> {
    if buf.len() < SRTP_HEADER_LEN {
        return None;
    }
    Some(SrtpFrame {
        msg_type: buf[OFFSET_MSG_TYPE],
        seq_num: u16::from_le_bytes([buf[OFFSET_SEQ_NUM], buf[OFFSET_SEQ_NUM + 1]]),
        service_code: buf[OFFSET_SERVICE_CODE],
        status_code: buf[OFFSET_STATUS_CODE],
        minor_status: buf[OFFSET_MINOR_STATUS],
    })
}

fn service_code_name(code: u8) -> String {
    match code {
        0x03 => "srtp_read_system_memory".to_string(),
        0x04 => "srtp_write_system_memory".to_string(),
        0x06 => "srtp_read_task_memory".to_string(),
        0x07 => "srtp_write_task_memory".to_string(),
        0x18 => "srtp_read_plc_status".to_string(),
        0x1B => "srtp_read_plc_time".to_string(),
        0x21 => "srtp_set_plc_time".to_string(),
        0x4E => "srtp_programmer_login".to_string(),
        0xC0 => "srtp_establish_session".to_string(),
        other => format!("srtp_unknown_0x{other:02x}"),
    }
}

fn is_known_service_code(code: u8) -> bool {
    matches!(
        code,
        0x03 | 0x04 | 0x06 | 0x07 | 0x18 | 0x1B | 0x21 | 0x4E | 0xC0
    )
}

fn srtp_attributes(frame: &SrtpFrame) -> BTreeMap<String, String> {
    let mut m = BTreeMap::new();
    m.insert(
        "service_code".to_string(),
        format!("0x{:02x}", frame.service_code),
    );
    m.insert("sequence_number".to_string(), frame.seq_num.to_string());
    m.insert(
        "status_code".to_string(),
        format!("0x{:02x}", frame.status_code),
    );
    m.insert(
        "minor_status".to_string(),
        format!("0x{:02x}", frame.minor_status),
    );
    m
}

fn srtp_bronze_fields(req: &SrtpFrame, resp: &SrtpFrame, direction: &str) -> GeSrtpBronzeFields {
    GeSrtpBronzeFields {
        msg_type: req.msg_type,
        sequence_number: req.seq_num,
        service_code: req.service_code,
        service_code_name: service_code_name(req.service_code),
        status_code: resp.status_code,
        minor_status: resp.minor_status,
        direction: direction.to_string(),
    }
}

// ---------------------------------------------------------------------------
// Pending request state (request half awaiting its response)
// ---------------------------------------------------------------------------

#[derive(Clone)]
struct PendingRequest {
    capture_id: String,
    envelope: EventEnvelope,
    frame: SrtpFrame,
    #[expect(dead_code, reason = "reserved for future stale-request handling")]
    last_seen: DateTime<Utc>,
}

// ---------------------------------------------------------------------------
// Decoder
// ---------------------------------------------------------------------------

#[derive(Default)]
pub(crate) struct GeSrtpDecoder {
    pending: HashMap<String, PendingRequest>,
}

impl GeSrtpDecoder {
    #[allow(clippy::too_many_arguments)]
    fn emit_transaction(
        capture_id: String,
        envelope: EventEnvelope,
        operation: String,
        status: String,
        request_summary: Option<String>,
        response_summary: Option<String>,
        service_code: u8,
        attributes: BTreeMap<String, String>,
        pf: GeSrtpBronzeFields,
        out: &mut Vec<BronzeEvent>,
    ) {
        out.push(new_event(
            capture_id,
            envelope,
            BronzeEventFamily::ProtocolTransaction(ProtocolTransaction {
                operation,
                status,
                request_summary,
                response_summary,
                object_refs: vec![format!("srtp_service:0x{service_code:02x}")],
                values: Vec::new(),
                attributes,
                modbus: None,
                protocol_fields: Some(ProtocolFields::GeSrtp(pf)),
            }),
        ));
    }
}

impl SessionDecoder for GeSrtpDecoder {
    fn name(&self) -> &'static str {
        "ge_srtp"
    }

    fn interest(&self) -> &'static [DecoderInterest] {
        &[DecoderInterest::TcpPort(18245)]
    }

    fn on_stream_chunk(&mut self, chunk: &StreamChunk<'_>, out: &mut Vec<BronzeEvent>) {
        let payload = chunk.payload;

        // Truncated frame: port-matched but too short for a full header.
        // Severity "medium" — likely a capture/reassembly gap, not random noise.
        if payload.len() < SRTP_HEADER_LEN {
            if !payload.is_empty() {
                out.push(parse_anomaly_event(
                    chunk.capture_id.to_string(),
                    build_envelope(
                        &chunk.context,
                        chunk.interface_id,
                        chunk.frame_index,
                        chunk.timestamp,
                        chunk.segment_hash,
                        TransportProtocol::Tcp,
                        Some("ge_srtp"),
                        chunk.captured_len,
                        chunk.session_key.clone(),
                    ),
                    self.name(),
                    "medium",
                    &format!(
                        "frame shorter than SRTP header ({} < {SRTP_HEADER_LEN})",
                        payload.len()
                    ),
                    payload,
                ));
            }
            return;
        }

        let frame = match parse_srtp_header(payload) {
            Some(f) => f,
            None => return,
        };

        let envelope = build_envelope(
            &chunk.context,
            chunk.interface_id,
            chunk.frame_index,
            chunk.timestamp,
            chunk.segment_hash,
            TransportProtocol::Tcp,
            Some("ge_srtp"),
            chunk.captured_len,
            chunk.session_key.clone(),
        );

        // Unknown service code: low severity. May be a vendor extension or newer
        // firmware revision. Still participate in pairing so the transaction is
        // visible in the forensic event log.
        if !is_known_service_code(frame.service_code) {
            out.push(parse_anomaly_event(
                chunk.capture_id.to_string(),
                envelope.clone(),
                self.name(),
                "low",
                &format!("unknown SRTP service code 0x{:02x}", frame.service_code),
                &payload[..SRTP_HEADER_LEN],
            ));
        }

        let pending_key = format!("{}:{}", chunk.session_key, frame.seq_num);

        match frame.msg_type {
            MSG_TYPE_REQUEST => {
                self.pending.insert(
                    pending_key,
                    PendingRequest {
                        capture_id: chunk.capture_id.to_string(),
                        envelope,
                        frame,
                        last_seen: chunk.timestamp,
                    },
                );
            }

            MSG_TYPE_RESPONSE => {
                if let Some(req) = self.pending.remove(&pending_key) {
                    let operation = service_code_name(req.frame.service_code);
                    let status = if frame.status_code == 0 {
                        "ok".to_string()
                    } else {
                        format!(
                            "srtp_status_0x{:02x}_minor_0x{:02x}",
                            frame.status_code, frame.minor_status
                        )
                    };
                    let mut attrs = srtp_attributes(&req.frame);
                    attrs.insert(
                        "status_code".to_string(),
                        format!("0x{:02x}", frame.status_code),
                    );
                    attrs.insert(
                        "minor_status".to_string(),
                        format!("0x{:02x}", frame.minor_status),
                    );
                    let mut merged = req.envelope.clone();
                    merged.bytes_count += envelope.bytes_count;
                    merged.packet_count += 1;
                    let pf = srtp_bronze_fields(&req.frame, &frame, &status);
                    Self::emit_transaction(
                        req.capture_id,
                        merged,
                        operation,
                        status,
                        Some(format!(
                            "seq={} svc=0x{:02x}",
                            req.frame.seq_num, req.frame.service_code
                        )),
                        Some(format!(
                            "status=0x{:02x} minor=0x{:02x}",
                            frame.status_code, frame.minor_status
                        )),
                        req.frame.service_code,
                        attrs,
                        pf,
                        out,
                    );
                } else {
                    let status = "response_only".to_string();
                    let pf = srtp_bronze_fields(&frame, &frame, &status);
                    Self::emit_transaction(
                        chunk.capture_id.to_string(),
                        envelope,
                        service_code_name(frame.service_code),
                        status,
                        None,
                        Some(format!(
                            "status=0x{:02x} minor=0x{:02x}",
                            frame.status_code, frame.minor_status
                        )),
                        frame.service_code,
                        srtp_attributes(&frame),
                        pf,
                        out,
                    );
                }
            }

            _ => {
                let status = "request_only".to_string();
                let pf = srtp_bronze_fields(&frame, &frame, &status);
                Self::emit_transaction(
                    chunk.capture_id.to_string(),
                    envelope,
                    service_code_name(frame.service_code),
                    status,
                    Some(format!(
                        "seq={} svc=0x{:02x} type=0x{:02x}",
                        frame.seq_num, frame.service_code, frame.msg_type
                    )),
                    None,
                    frame.service_code,
                    srtp_attributes(&frame),
                    pf,
                    out,
                );
            }
        }
    }

    fn on_idle_flush(&mut self, _timestamp: DateTime<Utc>, out: &mut Vec<BronzeEvent>) {
        for (_key, req) in self.pending.drain() {
            let svc = req.frame.service_code;
            let status = "request_only".to_string();
            let pf = srtp_bronze_fields(&req.frame, &req.frame, &status);
            Self::emit_transaction(
                req.capture_id,
                req.envelope,
                service_code_name(svc),
                status,
                Some(format!("seq={} svc=0x{svc:02x}", req.frame.seq_num)),
                None,
                svc,
                srtp_attributes(&req.frame),
                pf,
                out,
            );
        }
    }
}

// ---------------------------------------------------------------------------
// Self-registration
// ---------------------------------------------------------------------------

inventory::submit!(crate::engine::decoders::DecoderRegistration {
    name: "ge_srtp",
    factory: || Box::new(GeSrtpDecoder::default()),
});

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use std::net::{IpAddr, Ipv4Addr};

    use crate::registry::PacketContext;

    /// Build a 56-byte SRTP test frame. Offsets: [2]=msg_type, [9..11]=seq LE,
    /// [31]=svc, [42]=status, [43]=minor; all others 0x00.
    fn srtp_frame(msg_type: u8, seq: u16, svc: u8, status: u8, minor: u8) -> Vec<u8> {
        let mut buf = vec![0u8; SRTP_HEADER_LEN];
        buf[0] = 0x02;
        buf[OFFSET_MSG_TYPE] = msg_type;
        let s = seq.to_le_bytes();
        buf[OFFSET_SEQ_NUM] = s[0];
        buf[OFFSET_SEQ_NUM + 1] = s[1];
        buf[OFFSET_SERVICE_CODE] = svc;
        buf[OFFSET_STATUS_CODE] = status;
        buf[OFFSET_MINOR_STATUS] = minor;
        buf
    }

    fn feed(
        dec: &mut GeSrtpDecoder,
        payload: &[u8],
        src_port: u16,
        dst_port: u16,
        out: &mut Vec<BronzeEvent>,
    ) {
        let context = PacketContext {
            src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            dst_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            src_port,
            dst_port,
            src_mac: [0u8; 6],
            dst_mac: [0u8; 6],
            vlan_id: None,
            timestamp: 0,
        };
        let chunk = StreamChunk {
            capture_id: "cap",
            segment_hash: "aa",
            interface_id: 0,
            frame_index: 1,
            timestamp: Utc::now(),
            context,
            ethertype: 0x0800,
            ip_proto: Some(6),
            llc: None,
            transport: TransportProtocol::Tcp,
            payload,
            session_key: "10.0.0.1-10.0.0.2-50000-18245".to_string(),
            captured_len: payload.len() as u64,
        };
        dec.on_stream_chunk(&chunk, out);
    }

    /// 1. Programmer Login request alone → no events, one pending entry.
    #[test]
    fn test_programmer_login_request_no_emit() {
        let mut dec = GeSrtpDecoder::default();
        let mut out = Vec::new();
        let f = srtp_frame(MSG_TYPE_REQUEST, 1, 0x4E, 0, 0);
        feed(&mut dec, &f, 50000, 18245, &mut out);
        assert!(out.is_empty(), "request alone must not emit");
        assert_eq!(dec.pending.len(), 1);
    }

    /// 2. Login request + response status=0 → ProtocolTransaction ok, srtp_programmer_login.
    #[test]
    fn test_programmer_login_paired_ok() {
        let mut dec = GeSrtpDecoder::default();
        let mut out = Vec::new();
        feed(
            &mut dec,
            &srtp_frame(MSG_TYPE_REQUEST, 7, 0x4E, 0, 0),
            50000,
            18245,
            &mut out,
        );
        assert!(out.is_empty());
        feed(
            &mut dec,
            &srtp_frame(MSG_TYPE_RESPONSE, 7, 0x4E, 0, 0),
            18245,
            50000,
            &mut out,
        );
        assert_eq!(out.len(), 1);
        let BronzeEventFamily::ProtocolTransaction(ref txn) = out[0].family else {
            panic!("expected ProtocolTransaction");
        };
        assert_eq!(txn.operation, "srtp_programmer_login");
        assert_eq!(txn.status, "ok");
        assert!(dec.pending.is_empty());
    }

    /// 3. Read System Memory + response status=0x05 → status starts with "srtp_status_0x05".
    #[test]
    fn test_read_system_memory_error_status() {
        let mut dec = GeSrtpDecoder::default();
        let mut out = Vec::new();
        feed(
            &mut dec,
            &srtp_frame(MSG_TYPE_REQUEST, 42, 0x03, 0, 0),
            50000,
            18245,
            &mut out,
        );
        feed(
            &mut dec,
            &srtp_frame(MSG_TYPE_RESPONSE, 42, 0x03, 0x05, 0x01),
            18245,
            50000,
            &mut out,
        );
        assert_eq!(out.len(), 1);
        let BronzeEventFamily::ProtocolTransaction(ref txn) = out[0].family else {
            panic!("expected ProtocolTransaction");
        };
        assert_eq!(txn.operation, "srtp_read_system_memory");
        assert!(
            txn.status.starts_with("srtp_status_0x05"),
            "got: {}",
            txn.status
        );
    }

    /// 4. Unknown service code → ParseAnomaly emitted; flushed transaction operation contains "unknown".
    #[test]
    fn test_unknown_service_code_anomaly_and_operation() {
        let mut dec = GeSrtpDecoder::default();
        let mut out = Vec::new();
        feed(
            &mut dec,
            &srtp_frame(MSG_TYPE_REQUEST, 99, 0xAB, 0, 0),
            50000,
            18245,
            &mut out,
        );
        let anomalies: Vec<_> = out
            .iter()
            .filter(|e| matches!(e.family, BronzeEventFamily::ParseAnomaly(_)))
            .collect();
        assert_eq!(anomalies.len(), 1, "one low-severity ParseAnomaly expected");
        dec.on_idle_flush(Utc::now(), &mut out);
        let txns: Vec<_> = out
            .iter()
            .filter(|e| matches!(e.family, BronzeEventFamily::ProtocolTransaction(_)))
            .collect();
        assert_eq!(txns.len(), 1);
        let BronzeEventFamily::ProtocolTransaction(ref txn) = txns[0].family else {
            panic!()
        };
        assert!(txn.operation.contains("unknown"), "got: {}", txn.operation);
    }

    /// 5. Truncated frame (< 56 bytes) on port 18245 → ParseAnomaly severity="medium".
    #[test]
    fn test_truncated_frame_medium_anomaly() {
        let mut dec = GeSrtpDecoder::default();
        let mut out = Vec::new();
        // 20-byte stub — port context marks it as SRTP but header is incomplete.
        // Bytes [0..20] = 0x02, 0x00, 0x02, ... (opaque framing; only length matters here).
        let truncated = vec![
            0x02u8, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];
        assert!(truncated.len() < SRTP_HEADER_LEN);
        feed(&mut dec, &truncated, 50000, 18245, &mut out);
        assert_eq!(out.len(), 1);
        let BronzeEventFamily::ParseAnomaly(ref a) = out[0].family else {
            panic!("expected ParseAnomaly, got {:?}", out[0].family);
        };
        assert_eq!(a.severity, "medium");
        assert_eq!(a.decoder, "ge_srtp");
    }
}
