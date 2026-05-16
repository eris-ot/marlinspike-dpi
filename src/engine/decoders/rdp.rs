//! RDP (Microsoft Remote Desktop Protocol) session decoder — MS-RDPBCGR §5.
//!
//! Passive DPI for OT/ICS pivot detection. RDP is the dominant lateral-movement
//! vector on plant networks: jump hosts and HMI workstations almost universally
//! expose port 3389. The negotiation handshake (CR + CC) is cleartext; once the
//! Connection Confirm arrives, traffic becomes opaque TLS/CredSSP.
//!
//! This decoder targets only those first two TPKT/X.224 PDUs. After the first
//! CR/CC pair is resolved it stops emitting on the session.
//!
//! Wire layers (outermost → innermost):
//!   TPKT (RFC 1006, 4 B) → X.224 Class 0 TPDU → optional RDP Negotiation IE

use std::collections::BTreeMap;

use crate::bronze::{
    AssetObservation, BronzeEvent, BronzeEventFamily, ProtocolTransaction, TransportProtocol,
};
use crate::engine::{
    DecoderInterest, SessionDecoder, StreamChunk, build_envelope, new_event, parse_anomaly_event,
};

// ── TPKT / X.224 constants ──────────────────────────────────────────────────

const TPKT_VERSION: u8 = 3;
const TPKT_HEADER_LEN: usize = 4;

const X224_CR: u8 = 0xE0; // Connection Request
const X224_CC: u8 = 0xD0; // Connection Confirm

const RDP_NEG_REQ: u8 = 1;
const RDP_NEG_RSP: u8 = 2;
const RDP_NEG_FAIL: u8 = 3;

// requestedProtocols / selectedProtocol bitmask values (u32 LE):
//   0x00000000 = Standard RDP Security (legacy)
//   0x00000001 = TLS
//   0x00000002 = CredSSP
//   0x00000004 = RDSTLS
//   0x00000008 = CredSSP Early User Authentication

// ── Per-session state ────────────────────────────────────────────────────────

/// Half-parsed Connection Request data retained until we see the CC.
#[derive(Debug)]
struct PendingCr {
    /// mstshash cookie value from `Cookie: mstshash=<value>\r\n`.
    ///
    /// NOTE: mstshash is unauthenticated and trivially spoofable — any client
    /// can set an arbitrary value. Treat as an observation hint only.
    mstshash: Option<String>,
    /// requestedProtocols bitmask from the RDP Negotiation Request IE.
    requested_protocols: Option<u32>,
    /// TPDU class nibble from the CR header byte at offset 6.
    tpdu_class: u8,
}

#[derive(Debug, Default)]
enum State {
    #[default]
    AwaitingCr,
    AwaitingCc(PendingCr),
    Done,
}

#[derive(Default)]
pub(crate) struct RdpDecoder {
    buf: Vec<u8>,
    state: State,
}

// ── Wire parsing ─────────────────────────────────────────────────────────────

/// Returns `Some(total_len)` when a complete TPKT is buffered, `None`
/// if more bytes are needed or if a `ParseAnomaly` was emitted for a bad
/// version byte.
fn check_tpkt(
    data: &[u8],
    capture_id: &str,
    chunk: &StreamChunk<'_>,
    out: &mut Vec<BronzeEvent>,
) -> Option<usize> {
    if data.len() < TPKT_HEADER_LEN {
        return None;
    }
    if data[0] != TPKT_VERSION {
        out.push(parse_anomaly_event(
            capture_id.to_string(),
            build_envelope(
                &chunk.context,
                chunk.interface_id,
                chunk.frame_index,
                chunk.timestamp,
                chunk.segment_hash,
                TransportProtocol::Tcp,
                Some("rdp"),
                chunk.captured_len,
                chunk.session_key.clone(),
            ),
            "rdp",
            "low",
            "unexpected TPKT version byte — not RDP or mid-stream capture",
            data,
        ));
        return None;
    }
    let total = u16::from_be_bytes([data[2], data[3]]) as usize;
    if total < TPKT_HEADER_LEN || data.len() < total {
        return None; // incomplete — keep buffering
    }
    Some(total)
}

/// Parses a Connection Request TPDU (X.224 §13.3) starting right after the
/// 4-byte TPKT header.
///
/// Layout from tpdu[0]:
///   [0]    LI (header length, excludes the LI byte)
///   [1]    0xE0 (CR code)
///   [2..4] dst-ref  [4..6] src-ref  [6] class/options
///   [7..]  variable user-data (cookie + optional Neg Request IE)
fn parse_cr(tpdu: &[u8]) -> Option<PendingCr> {
    if tpdu.len() < 7 {
        return None;
    }
    let li = tpdu[0] as usize;
    if li < 6 || tpdu.len() < li + 1 {
        return None;
    }
    let tpdu_class = tpdu[6] >> 4;
    let user_data = &tpdu[li + 1..];

    let cookie_prefix = b"Cookie: mstshash=";
    let (mstshash, neg_data) = if user_data.starts_with(cookie_prefix) {
        let rest = &user_data[cookie_prefix.len()..];
        if let Some(crlf) = rest.windows(2).position(|w| w == b"\r\n") {
            let value = std::str::from_utf8(&rest[..crlf]).ok().map(str::to_string);
            (value, &rest[crlf + 2..])
        } else {
            (None, user_data)
        }
    } else {
        (None, user_data)
    };

    Some(PendingCr {
        mstshash,
        requested_protocols: parse_neg_request(neg_data),
        tpdu_class,
    })
}

/// Parses an 8-byte RDP Negotiation Request IE and returns `requestedProtocols`.
fn parse_neg_request(data: &[u8]) -> Option<u32> {
    if data.len() < 8 || data[0] != RDP_NEG_REQ {
        return None;
    }
    if u16::from_le_bytes([data[2], data[3]]) != 8 {
        return None;
    }
    Some(u32::from_le_bytes([data[4], data[5], data[6], data[7]]))
}

enum CcPayload {
    NegResponse { selected_protocol: u32 },
    NegFailure { failure_code: u32 },
    Bare,
}

/// Parses a Connection Confirm TPDU. Same fixed header layout as CR.
fn parse_cc(tpdu: &[u8]) -> Option<CcPayload> {
    if tpdu.len() < 7 {
        return None;
    }
    let li = tpdu[0] as usize;
    if li < 6 || tpdu.len() < li + 1 {
        return None;
    }
    let user_data = &tpdu[li + 1..];
    if user_data.len() < 8 {
        return Some(CcPayload::Bare);
    }
    let ie_type = user_data[0];
    if u16::from_le_bytes([user_data[2], user_data[3]]) != 8 {
        return Some(CcPayload::Bare);
    }
    let value = u32::from_le_bytes([user_data[4], user_data[5], user_data[6], user_data[7]]);
    Some(match ie_type {
        RDP_NEG_RSP => CcPayload::NegResponse {
            selected_protocol: value,
        },
        RDP_NEG_FAIL => CcPayload::NegFailure {
            failure_code: value,
        },
        _ => CcPayload::Bare,
    })
}

// ── Event builders ───────────────────────────────────────────────────────────

fn emit_asset_observation(mstshash: &str, chunk: &StreamChunk<'_>, out: &mut Vec<BronzeEvent>) {
    let src_ip = chunk.context.src_ip.to_string();
    out.push(new_event(
        chunk.capture_id.to_string(),
        build_envelope(
            &chunk.context,
            chunk.interface_id,
            chunk.frame_index,
            chunk.timestamp,
            chunk.segment_hash,
            TransportProtocol::Tcp,
            Some("rdp"),
            chunk.captured_len,
            chunk.session_key.clone(),
        ),
        BronzeEventFamily::AssetObservation(AssetObservation {
            asset_key: src_ip.clone(),
            // Role is rdp_client; mstshash_username is unauthenticated — spoofable.
            role: Some("rdp_client".to_string()),
            vendor: None,
            model: None,
            firmware: None,
            hostnames: Vec::new(),
            protocols: vec!["rdp".to_string()],
            identifiers: BTreeMap::from([
                ("ip".to_string(), src_ip),
                ("mstshash_username".to_string(), mstshash.to_string()),
            ]),
        }),
    ));
}

fn emit_transaction(
    cr: PendingCr,
    cc: CcPayload,
    chunk: &StreamChunk<'_>,
    out: &mut Vec<BronzeEvent>,
) {
    let mut attributes = BTreeMap::new();
    attributes.insert("tpdu_class".to_string(), cr.tpdu_class.to_string());
    if let Some(rp) = cr.requested_protocols {
        attributes.insert(
            "requested_protocols_hex".to_string(),
            format!("{:#010x}", rp),
        );
    }
    if let Some(ref u) = cr.mstshash {
        attributes.insert("mstshash".to_string(), u.clone());
    }

    let request_summary = cr
        .mstshash
        .as_deref()
        .map(|u| format!("CR with cookie {u}"))
        .unwrap_or_else(|| "CR without cookie".to_string());

    let (status, response_summary) = match &cc {
        CcPayload::NegResponse { selected_protocol } => {
            attributes.insert(
                "selected_protocol_hex".to_string(),
                format!("{:#010x}", selected_protocol),
            );
            (
                "ok".to_string(),
                format!(
                    "CC negotiation_response selected={:#010x}",
                    selected_protocol
                ),
            )
        }
        CcPayload::NegFailure { failure_code } => {
            attributes.insert(
                "negotiation_failure_code".to_string(),
                format!("{:#010x}", failure_code),
            );
            (
                "failed".to_string(),
                format!("CC negotiation_failure code={:#010x}", failure_code),
            )
        }
        CcPayload::Bare => ("observed".to_string(), "CC (no negotiation IE)".to_string()),
    };

    out.push(new_event(
        chunk.capture_id.to_string(),
        build_envelope(
            &chunk.context,
            chunk.interface_id,
            chunk.frame_index,
            chunk.timestamp,
            chunk.segment_hash,
            TransportProtocol::Tcp,
            Some("rdp"),
            chunk.captured_len,
            chunk.session_key.clone(),
        ),
        BronzeEventFamily::ProtocolTransaction(ProtocolTransaction {
            operation: "rdp_connect".to_string(),
            status,
            request_summary: Some(request_summary),
            response_summary: Some(response_summary),
            object_refs: Vec::new(),
            values: Vec::new(),
            attributes,
            modbus: None,
            protocol_fields: None,
        }),
    ));
}

// ── SessionDecoder impl ──────────────────────────────────────────────────────

impl SessionDecoder for RdpDecoder {
    fn name(&self) -> &'static str {
        "rdp"
    }

    fn interest(&self) -> &'static [DecoderInterest] {
        &[DecoderInterest::TcpPort(3389)]
    }

    fn on_stream_chunk(&mut self, chunk: &StreamChunk<'_>, out: &mut Vec<BronzeEvent>) {
        if matches!(self.state, State::Done) || chunk.payload.is_empty() {
            return;
        }
        self.buf.extend_from_slice(chunk.payload);

        while let Some(total) = check_tpkt(&self.buf, chunk.capture_id, chunk, out) {
            let pdu = self.buf[..total].to_vec();
            let tpdu = &pdu[TPKT_HEADER_LEN..];
            if tpdu.len() < 2 {
                self.buf.drain(..total);
                break;
            }
            let tpdu_code = tpdu[1];

            match &self.state {
                State::AwaitingCr => {
                    if tpdu_code == X224_CR
                        && let Some(cr) = parse_cr(tpdu)
                    {
                        if let Some(ref u) = cr.mstshash.clone() {
                            emit_asset_observation(u, chunk, out);
                        }
                        self.state = State::AwaitingCc(cr);
                    }
                    self.buf.drain(..total);
                }
                State::AwaitingCc(_) => {
                    if tpdu_code == X224_CC {
                        let cr = match std::mem::replace(&mut self.state, State::Done) {
                            State::AwaitingCc(cr) => cr,
                            _ => unreachable!(),
                        };
                        if let Some(cc) = parse_cc(tpdu) {
                            emit_transaction(cr, cc, chunk, out);
                        }
                        self.buf.drain(..total);
                        break; // traffic goes encrypted — stop
                    }
                    self.buf.drain(..total);
                }
                State::Done => break,
            }
        }
    }
}

// ── Inventory registration ───────────────────────────────────────────────────

inventory::submit!(crate::engine::decoders::DecoderRegistration {
    name: "rdp",
    factory: || Box::new(RdpDecoder::default()),
});

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use std::net::{IpAddr, Ipv4Addr};

    use crate::bronze::BronzeEventFamily;
    use crate::engine::{SessionDecoder, StreamChunk};
    use crate::registry::PacketContext;

    fn ctx() -> PacketContext {
        PacketContext {
            src_mac: [0x00, 0x11, 0x22, 0x33, 0x44, 0x55],
            dst_mac: [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF],
            src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            dst_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            src_port: 54321,
            dst_port: 3389,
            vlan_id: None,
            timestamp: 1_700_000_000_000_000,
        }
    }

    fn chunk_from(payload: &[u8]) -> StreamChunk<'_> {
        StreamChunk {
            capture_id: "test-cap",
            segment_hash: "seg",
            interface_id: 0,
            frame_index: 1,
            timestamp: Utc::now(),
            context: ctx(),
            ethertype: 0x0800,
            ip_proto: Some(6),
            llc: None,
            transport: TransportProtocol::Tcp,
            payload,
            session_key: "10.0.0.1:54321-10.0.0.2:3389".to_string(),
            captured_len: payload.len() as u64,
        }
    }

    /// Minimal CR: TPKT(11B) + X.224 CR header only, no user data.
    fn minimal_cr() -> Vec<u8> {
        vec![
            0x03, 0x00, 0x00, 0x0B, // TPKT: version=3, rsvd=0, total=11
            0x06, // LI=6 (covers code+refs+class)
            0xE0, // CR
            0x00, 0x00, // dst-ref
            0x00, 0x00, // src-ref
            0x00, // class 0
        ]
    }

    /// CC with an RDP Negotiation Response IE; total=19.
    fn cc_neg_response(selected: u32) -> Vec<u8> {
        let mut v = vec![
            0x03, 0x00, 0x00, 0x13, // TPKT total=19
            0x06, 0xD0, // LI=6, CC
            0x00, 0x00, 0x00, 0x00, // dst-ref, src-ref
            0x00, // class
        ];
        v.push(RDP_NEG_RSP);
        v.push(0x00);
        v.extend_from_slice(&8u16.to_le_bytes());
        v.extend_from_slice(&selected.to_le_bytes());
        v
    }

    /// CC with an RDP Negotiation Failure IE.
    fn cc_neg_failure(code: u32) -> Vec<u8> {
        let mut v = vec![
            0x03, 0x00, 0x00, 0x13, 0x06, 0xD0, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];
        v.push(RDP_NEG_FAIL);
        v.push(0x00);
        v.extend_from_slice(&8u16.to_le_bytes());
        v.extend_from_slice(&code.to_le_bytes());
        v
    }

    /// CR carrying a mstshash cookie and a Neg Request IE.
    fn cr_with_cookie(username: &str, requested: u32) -> Vec<u8> {
        let cookie = format!("Cookie: mstshash={}\r\n", username);
        let mut neg_req = vec![RDP_NEG_REQ, 0x00];
        neg_req.extend_from_slice(&8u16.to_le_bytes());
        neg_req.extend_from_slice(&requested.to_le_bytes());
        let user_data_len = cookie.len() + neg_req.len();
        let total = TPKT_HEADER_LEN + 7 + user_data_len; // 4 + (LI+1+code+refs+class) + user
        let mut v = Vec::with_capacity(total);
        v.push(0x03);
        v.push(0x00);
        v.extend_from_slice(&(total as u16).to_be_bytes());
        v.push(0x06); // LI=6
        v.push(X224_CR);
        v.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // dst-ref + src-ref
        v.push(0x00); // class
        v.extend_from_slice(cookie.as_bytes());
        v.extend_from_slice(&neg_req);
        v
    }

    // ── Test 1: minimal CR alone → no ProtocolTransaction ───────────────────

    #[test]
    fn t1_minimal_cr_no_transaction() {
        let mut dec = RdpDecoder::default();
        let mut out = Vec::new();
        dec.on_stream_chunk(&chunk_from(&minimal_cr()), &mut out);
        assert!(
            !out.iter()
                .any(|e| matches!(e.family, BronzeEventFamily::ProtocolTransaction(_))),
            "CR alone must not emit a ProtocolTransaction"
        );
    }

    // ── Test 2: CR + CC (TLS) → status=ok, selected_protocol_hex=0x00000001 ─

    #[test]
    fn t2_cr_cc_tls_ok() {
        let mut dec = RdpDecoder::default();
        let mut out = Vec::new();
        let mut payload = minimal_cr();
        payload.extend(cc_neg_response(1));
        dec.on_stream_chunk(&chunk_from(&payload), &mut out);
        let tx = out
            .iter()
            .find_map(|e| {
                if let BronzeEventFamily::ProtocolTransaction(ref t) = e.family {
                    Some(t.clone())
                } else {
                    None
                }
            })
            .expect("ProtocolTransaction must be emitted");
        assert_eq!(tx.operation, "rdp_connect");
        assert_eq!(tx.status, "ok");
        assert_eq!(
            tx.attributes
                .get("selected_protocol_hex")
                .map(String::as_str),
            Some("0x00000001")
        );
    }

    // ── Test 3: CR with cookie → AssetObservation mstshash_username=alice ───

    #[test]
    fn t3_cookie_asset_observation() {
        let mut dec = RdpDecoder::default();
        let mut out = Vec::new();
        dec.on_stream_chunk(&chunk_from(&cr_with_cookie("alice", 1)), &mut out);
        let obs = out
            .iter()
            .find_map(|e| {
                if let BronzeEventFamily::AssetObservation(ref o) = e.family {
                    Some(o.clone())
                } else {
                    None
                }
            })
            .expect("AssetObservation must be emitted");
        assert_eq!(obs.role.as_deref(), Some("rdp_client"));
        assert_eq!(
            obs.identifiers.get("mstshash_username").map(String::as_str),
            Some("alice")
        );
    }

    // ── Test 4: CR + CC negotiation_failure → status=failed, code present ───

    #[test]
    fn t4_negotiation_failure() {
        let mut dec = RdpDecoder::default();
        let mut out = Vec::new();
        let mut payload = minimal_cr();
        payload.extend(cc_neg_failure(2)); // SSL_NOT_ALLOWED_BY_SERVER = 2
        dec.on_stream_chunk(&chunk_from(&payload), &mut out);
        let tx = out
            .iter()
            .find_map(|e| {
                if let BronzeEventFamily::ProtocolTransaction(ref t) = e.family {
                    Some(t.clone())
                } else {
                    None
                }
            })
            .expect("ProtocolTransaction must be emitted");
        assert_eq!(tx.status, "failed");
        assert_eq!(
            tx.attributes
                .get("negotiation_failure_code")
                .map(String::as_str),
            Some("0x00000002")
        );
    }

    // ── Test 5: fragmented delivery → buffer until complete, then emit ───────

    #[test]
    fn t5_fragmented_buffering() {
        let mut dec = RdpDecoder::default();
        let mut out = Vec::new();
        let mut full = cr_with_cookie("bob", 3);
        full.extend(cc_neg_response(1));
        // Deliver the first half — may not contain complete CC yet.
        let split = full.len() / 2;
        dec.on_stream_chunk(&chunk_from(&full[..split]), &mut out);
        // Deliver the rest.
        dec.on_stream_chunk(&chunk_from(&full[split..]), &mut out);
        // After both fragments we must have both an AssetObservation and a transaction.
        assert!(
            out.iter()
                .any(|e| matches!(e.family, BronzeEventFamily::AssetObservation(_))),
            "AssetObservation must appear across fragments"
        );
        assert!(
            out.iter()
                .any(|e| matches!(e.family, BronzeEventFamily::ProtocolTransaction(_))),
            "ProtocolTransaction must appear after reassembly"
        );
    }

    // ── Test 6: bad TPKT version → ParseAnomaly severity=low ────────────────

    #[test]
    fn t6_bad_tpkt_version_anomaly() {
        let mut dec = RdpDecoder::default();
        let mut out = Vec::new();
        let mut bad = minimal_cr();
        bad[0] = 0x04; // wrong version
        dec.on_stream_chunk(&chunk_from(&bad), &mut out);
        let anomaly = out
            .iter()
            .find_map(|e| {
                if let BronzeEventFamily::ParseAnomaly(ref a) = e.family {
                    Some(a.clone())
                } else {
                    None
                }
            })
            .expect("ParseAnomaly must be emitted for bad TPKT version");
        assert_eq!(anomaly.severity, "low");
        assert_eq!(anomaly.decoder, "rdp");
    }
}
