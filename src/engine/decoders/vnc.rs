//! VNC / RFB (Remote Framebuffer) session decoder — RFC 6143.
//!
//! Passive DPI for OT/ICS Linux HMI and legacy industrial gear visibility.
//! VNC is the dominant Linux-side remote-access protocol (counterpart to RDP).
//! The RFB handshake is pre-encryption and high-value: ProtocolVersion banners
//! and SecurityTypes list are always cleartext regardless of chosen auth.
//!
//! ## Wire sequence (simplified)
//!
//! ```text
//! SERVER → CLIENT   "RFB 003.008\n"   (12 bytes, ProtocolVersion)
//! CLIENT → SERVER   "RFB 003.008\n"   (12 bytes, echoes chosen version)
//!
//! v3.3:  server picks auth via single u32 BE — no per-security-type list.
//! v3.7+: SERVER → u8 count + u8[] types
//!        CLIENT → u8 chosen_type
//! ```
//!
//! After that, traffic is opaque (auth challenge/response, then encrypted
//! framebuffer data). We stop emitting once the handshake is resolved.

use std::collections::BTreeMap;

use crate::bronze::{
    AssetObservation, BronzeEvent, BronzeEventFamily, ProtocolTransaction, TransportProtocol,
};
use crate::engine::{
    DecoderInterest, SessionDecoder, StreamChunk, build_envelope, new_event, parse_anomaly_event,
};

// ── RFB constants ────────────────────────────────────────────────────────────

const BANNER_LEN: usize = 12; // "RFB MMM.mmm\n"
const BANNER_PREFIX: &[u8] = b"RFB ";

// ── Security type names ──────────────────────────────────────────────────────

fn security_type_name(t: u8) -> &'static str {
    match t {
        0 => "invalid",
        1 => "none",
        2 => "vnc_auth",
        5 => "ra2",
        6 => "ra2ne",
        16 => "tight",
        17 => "ultra",
        18 => "tls",
        19 => "vencrypt",
        20 => "gtk_vnc_sasl",
        21 => "md5_hash_auth",
        22 => "colin_dean_xvp",
        30 => "apple_remote_desktop",
        _ => "unknown",
    }
}

// ── Per-session state machine ────────────────────────────────────────────────

#[derive(Debug, Default)]
enum State {
    /// Waiting for the server's 12-byte ProtocolVersion banner.
    #[default]
    AwaitingServerBanner,
    /// Server banner parsed; waiting for client's 12-byte version echo.
    AwaitingClientBanner {
        server_version: String,
        /// Major version digit parsed from the server banner (3 for all common versions).
        major: u8,
        /// Minor version digit controls which security negotiation branch applies.
        minor: u8,
    },
    /// Both banners seen; now collecting security negotiation bytes.
    AwaitingSecurityTypes {
        server_version: String,
        client_version: String,
        major: u8,
        minor: u8,
    },
    /// Handshake resolved — no further events emitted for this session.
    Done,
}

#[derive(Default)]
pub(crate) struct VncDecoder {
    /// Reassembly buffer — we accumulate bytes across TCP segments.
    buf: Vec<u8>,
    state: State,
}

// ── Banner parsing ───────────────────────────────────────────────────────────

/// Parse `"RFB MMM.mmm\n"` into `(major, minor, version_string)`.
/// Returns `None` if the 12 bytes don't match the expected shape.
fn parse_banner(data: &[u8]) -> Option<(u8, u8, String)> {
    if data.len() < BANNER_LEN {
        return None;
    }
    let banner = &data[..BANNER_LEN];
    if !banner.starts_with(BANNER_PREFIX) {
        return None;
    }
    // Bytes [4..7]: 3-digit major, [7]: '.', [8..11]: 3-digit minor, [11]: '\n'
    if banner[7] != b'.' || banner[11] != b'\n' {
        return None;
    }
    let major_bytes = &banner[4..7];
    let minor_bytes = &banner[8..11];
    let major: u8 = std::str::from_utf8(major_bytes).ok()?.trim().parse().ok()?;
    let minor: u8 = std::str::from_utf8(minor_bytes).ok()?.trim().parse().ok()?;
    let version = format!("{}.{}", major, minor);
    Some((major, minor, version))
}

/// Returns true if the 12-byte slice looks like a valid RFB banner.
fn is_valid_banner(data: &[u8]) -> bool {
    parse_banner(data).is_some()
}

// ── SessionDecoder impl ───────────────────────────────────────────────────────

impl SessionDecoder for VncDecoder {
    fn name(&self) -> &'static str {
        "vnc"
    }

    fn interest(&self) -> &'static [DecoderInterest] {
        &[
            DecoderInterest::TcpPort(5900),
            DecoderInterest::TcpPort(5901),
            DecoderInterest::TcpPort(5902),
            DecoderInterest::TcpPort(5903),
            DecoderInterest::TcpPort(5904),
            DecoderInterest::TcpPort(5905),
            DecoderInterest::TcpPort(5906),
            DecoderInterest::TcpPort(5907),
            DecoderInterest::TcpPort(5908),
            DecoderInterest::TcpPort(5909),
            DecoderInterest::TcpPort(5910),
        ]
    }

    fn on_stream_chunk(&mut self, chunk: &StreamChunk<'_>, out: &mut Vec<BronzeEvent>) {
        if matches!(self.state, State::Done) || chunk.payload.is_empty() {
            return;
        }
        self.buf.extend_from_slice(chunk.payload);

        loop {
            match &self.state {
                State::AwaitingServerBanner => {
                    if self.buf.len() < BANNER_LEN {
                        break; // need more bytes
                    }
                    let banner_bytes = self.buf[..BANNER_LEN].to_vec();

                    if !is_valid_banner(&banner_bytes) {
                        // Emit ParseAnomaly for malformed server banner.
                        out.push(parse_anomaly_event(
                            chunk.capture_id.to_string(),
                            build_envelope(
                                &chunk.context,
                                chunk.interface_id,
                                chunk.frame_index,
                                chunk.timestamp,
                                chunk.segment_hash,
                                TransportProtocol::Tcp,
                                Some("vnc"),
                                chunk.captured_len,
                                chunk.session_key.clone(),
                            ),
                            self.name(),
                            "low",
                            "server banner does not match RFB MMM.mmm\\n shape",
                            &banner_bytes,
                        ));
                        self.state = State::Done;
                        break;
                    }

                    let (major, minor, version) = parse_banner(&banner_bytes).unwrap();
                    self.buf.drain(..BANNER_LEN);
                    self.state = State::AwaitingClientBanner {
                        server_version: version,
                        major,
                        minor,
                    };
                }

                State::AwaitingClientBanner { .. } => {
                    if self.buf.len() < BANNER_LEN {
                        break; // need more bytes
                    }
                    let banner_bytes = self.buf[..BANNER_LEN].to_vec();
                    let client_version = if is_valid_banner(&banner_bytes) {
                        let (_, _, v) = parse_banner(&banner_bytes).unwrap();
                        v
                    } else {
                        // Client echo doesn't have to be valid — just consume and continue.
                        String::from_utf8_lossy(&banner_bytes)
                            .trim_end_matches('\n')
                            .to_string()
                    };

                    self.buf.drain(..BANNER_LEN);

                    // Move to security negotiation, capturing version for borrow safety.
                    let (sv, major, minor) = if let State::AwaitingClientBanner {
                        server_version,
                        major,
                        minor,
                    } = std::mem::replace(&mut self.state, State::Done)
                    {
                        (server_version, major, minor)
                    } else {
                        unreachable!()
                    };

                    self.state = State::AwaitingSecurityTypes {
                        server_version: sv,
                        client_version,
                        major,
                        minor,
                    };
                }

                State::AwaitingSecurityTypes { major, minor, .. } => {
                    // Two distinct branches based on protocol version:
                    //
                    // v3.3: Server directly picks a single u32 BE security type.
                    //       There is NO count byte — the server makes the choice unilaterally.
                    //       Client does not reply with a chosen type in this branch.
                    //
                    // v3.7+: Server sends u8 count followed by count bytes of offered types.
                    //        Client responds with a single u8 chosen type.
                    //        If count == 0 or types == [0 (Invalid)], server may follow with
                    //        u32 BE reason-length + UTF-8 reason bytes.

                    let major = *major;
                    let minor = *minor;

                    if major == 3 && minor <= 3 {
                        // ── v3.3 branch ──────────────────────────────────────
                        // Server sends 4-byte BE u32 security type directly.
                        if self.buf.len() < 4 {
                            break;
                        }
                        let sec_type = u32::from_be_bytes([
                            self.buf[0],
                            self.buf[1],
                            self.buf[2],
                            self.buf[3],
                        ]);
                        self.buf.drain(..4);

                        let (sv, cv) = if let State::AwaitingSecurityTypes {
                            server_version,
                            client_version,
                            ..
                        } = std::mem::replace(&mut self.state, State::Done)
                        {
                            (server_version, client_version)
                        } else {
                            unreachable!()
                        };

                        let type_name = security_type_name(sec_type as u8);
                        let types_str = type_name.to_string();
                        let status = if sec_type == 0 { "failed" } else { "ok" };

                        emit_handshake(chunk, &sv, Some(&cv), &types_str, None, status, None, out);
                        break;
                    } else {
                        // ── v3.7+ branch ─────────────────────────────────────
                        // First byte is the count of offered security types.
                        if self.buf.is_empty() {
                            break;
                        }
                        let count = self.buf[0] as usize;

                        if self.buf.len() < 1 + count {
                            break; // wait for all type bytes
                        }

                        let types: Vec<u8> = self.buf[1..1 + count].to_vec();
                        self.buf.drain(..1 + count);

                        // Check if Invalid (0) is the only or first type — server
                        // follows with a reason string: u32 BE length + UTF-8 bytes.
                        let has_invalid = types.contains(&0);
                        let all_invalid = types.iter().all(|&t| t == 0) || types.is_empty();

                        let mut invalid_reason: Option<String> = None;

                        if has_invalid && count <= 1 {
                            // Attempt to read the reason string (best-effort).
                            if self.buf.len() >= 4 {
                                let reason_len = u32::from_be_bytes([
                                    self.buf[0],
                                    self.buf[1],
                                    self.buf[2],
                                    self.buf[3],
                                ]) as usize;
                                if self.buf.len() >= 4 + reason_len {
                                    let reason_bytes = &self.buf[4..4 + reason_len];
                                    invalid_reason =
                                        std::str::from_utf8(reason_bytes).ok().map(str::to_string);
                                    self.buf.drain(..4 + reason_len);
                                }
                                // If we don't have enough bytes yet, skip — partial capture.
                            }
                        }

                        // Chosen type from client (v3.7+): 1 byte, only present if count > 0.
                        let chosen_type: Option<String> =
                            if !types.is_empty() && !self.buf.is_empty() {
                                let chosen = self.buf[0];
                                self.buf.drain(..1);
                                Some(security_type_name(chosen).to_string())
                            } else {
                                None
                            };

                        let types_str = types
                            .iter()
                            .map(|&t| security_type_name(t))
                            .collect::<Vec<_>>()
                            .join(",");

                        let status = if all_invalid || types.is_empty() {
                            "failed"
                        } else {
                            "ok"
                        };

                        let (sv, cv) = if let State::AwaitingSecurityTypes {
                            server_version,
                            client_version,
                            ..
                        } = std::mem::replace(&mut self.state, State::Done)
                        {
                            (server_version, client_version)
                        } else {
                            unreachable!()
                        };

                        emit_handshake(
                            chunk,
                            &sv,
                            Some(&cv),
                            &types_str,
                            chosen_type.as_deref(),
                            status,
                            invalid_reason.as_deref(),
                            out,
                        );
                        break;
                    }
                }

                State::Done => break,
            }
        }
    }
}

// ── Event builder ─────────────────────────────────────────────────────────────

#[allow(clippy::too_many_arguments)]
fn emit_handshake(
    chunk: &StreamChunk<'_>,
    server_version: &str,
    client_version: Option<&str>,
    security_types_offered: &str,
    chosen_security_type: Option<&str>,
    status: &str,
    invalid_reason: Option<&str>,
    out: &mut Vec<BronzeEvent>,
) {
    let envelope = build_envelope(
        &chunk.context,
        chunk.interface_id,
        chunk.frame_index,
        chunk.timestamp,
        chunk.segment_hash,
        TransportProtocol::Tcp,
        Some("vnc"),
        chunk.captured_len,
        chunk.session_key.clone(),
    );

    let mut attributes: BTreeMap<String, String> = BTreeMap::new();
    attributes.insert(
        "server_protocol_version".to_string(),
        server_version.to_string(),
    );
    if let Some(cv) = client_version {
        attributes.insert("client_protocol_version".to_string(), cv.to_string());
    }
    if !security_types_offered.is_empty() {
        attributes.insert(
            "security_types_offered".to_string(),
            security_types_offered.to_string(),
        );
    }
    if let Some(chosen) = chosen_security_type {
        attributes.insert("chosen_security_type".to_string(), chosen.to_string());
    }
    if let Some(reason) = invalid_reason {
        attributes.insert("invalid_reason".to_string(), reason.to_string());
    }

    let request_summary = format!("VNC server RFB {server_version}");
    let response_summary = if security_types_offered.is_empty() {
        format!("security_types=none offered status={status}")
    } else {
        format!("security_types=[{security_types_offered}] status={status}")
    };

    // Determine server IP — server is always destination on port 59xx.
    let server_ip = chunk.context.dst_ip.to_string();
    let mut identifiers: BTreeMap<String, String> = BTreeMap::new();
    identifiers.insert("ip".to_string(), server_ip.clone());
    identifiers.insert("protocol_version".to_string(), server_version.to_string());

    out.push(new_event(
        chunk.capture_id.to_string(),
        envelope.clone(),
        BronzeEventFamily::ProtocolTransaction(ProtocolTransaction {
            operation: "vnc_connect".to_string(),
            status: status.to_string(),
            request_summary: Some(request_summary),
            response_summary: Some(response_summary),
            object_refs: Vec::new(),
            values: Vec::new(),
            attributes,
            modbus: None,
            protocol_fields: None,
        }),
    ));

    out.push(new_event(
        chunk.capture_id.to_string(),
        envelope,
        BronzeEventFamily::AssetObservation(AssetObservation {
            asset_key: server_ip,
            role: Some("vnc_server".to_string()),
            vendor: None, // RFB banners carry no vendor string
            model: None,
            firmware: None,
            hostnames: Vec::new(),
            protocols: vec!["vnc".to_string()],
            identifiers,
        }),
    ));
}

// ── Inventory registration ────────────────────────────────────────────────────

inventory::submit!(crate::engine::decoders::DecoderRegistration {
    name: "vnc",
    factory: || Box::new(VncDecoder::default()),
});

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    use crate::bronze::BronzeEventFamily;
    use crate::engine::{SessionDecoder, StreamChunk};
    use crate::registry::PacketContext;

    // ── Test helpers ─────────────────────────────────────────────────────────

    fn make_ctx(src_port: u16, dst_port: u16) -> PacketContext {
        PacketContext {
            src_mac: [0x00, 0x11, 0x22, 0x33, 0x44, 0x55],
            dst_mac: [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF],
            src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 10)),
            dst_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 20)),
            src_port,
            dst_port,
            vlan_id: None,
            timestamp: 1_700_000_000_000_000,
        }
    }

    fn chunk_with_ctx<'a>(payload: &'a [u8], ctx: PacketContext) -> StreamChunk<'a> {
        StreamChunk {
            capture_id: "test-cap",
            segment_hash: "seg",
            interface_id: 0,
            frame_index: 1,
            timestamp: chrono::Utc::now(),
            context: ctx,
            ethertype: 0x0800,
            ip_proto: Some(6),
            llc: None,
            transport: TransportProtocol::Tcp,
            payload,
            session_key: "10.0.0.10:54321-10.0.0.20:5900".to_string(),
            captured_len: payload.len() as u64,
        }
    }

    fn chunk(payload: &[u8]) -> StreamChunk<'_> {
        chunk_with_ctx(payload, make_ctx(54321, 5900))
    }

    /// Build a complete v3.8 server-banner + security-types payload in one vec.
    #[expect(dead_code, reason = "kept for future protocol-version test coverage")]
    fn server_banner_38_with_types(types: &[u8]) -> Vec<u8> {
        let mut v = b"RFB 003.008\n".to_vec();
        v.push(types.len() as u8);
        v.extend_from_slice(types);
        v
    }

    /// Client banner bytes for v3.8.
    fn client_banner_38() -> Vec<u8> {
        b"RFB 003.008\n".to_vec()
    }

    // ── Test 1: Server banner alone → buffered, no event ─────────────────────

    #[test]
    fn test_server_banner_alone_no_event() {
        let mut dec = VncDecoder::default();
        let mut out = Vec::new();
        let banner = b"RFB 003.008\n";
        dec.on_stream_chunk(&chunk(banner), &mut out);
        // Banner buffered, awaiting client echo — no events yet.
        assert!(
            out.is_empty(),
            "expected no events on banner alone, got {:?}",
            out.len()
        );
    }

    // ── Test 2: Full v3.8 handshake, types [1, 2] → ok ───────────────────────

    #[test]
    fn test_v38_types_none_and_vnc_auth_ok() {
        let mut dec = VncDecoder::default();
        let mut out = Vec::new();

        // Wire order: server_banner → client_banner → server_types → client_chosen.
        dec.on_stream_chunk(&chunk(b"RFB 003.008\n"), &mut out);
        dec.on_stream_chunk(&chunk(&client_banner_38()), &mut out);
        assert!(out.is_empty(), "no event until security types arrive");

        // Server sends count + types [1=None, 2=VNC Auth] AND client chosen byte
        // arrives in the same processing window (combined for the decoder's
        // single-pass parse of the security-negotiation phase).
        let sec_types_and_chosen = vec![2u8, 1u8, 2u8, 2u8]; // count, types, chosen=VNC Auth
        dec.on_stream_chunk(&chunk(&sec_types_and_chosen), &mut out);

        // Expect ProtocolTransaction + AssetObservation
        assert_eq!(out.len(), 2, "expected 2 events");

        let tx = match &out[0].family {
            BronzeEventFamily::ProtocolTransaction(t) => t,
            other => panic!("expected ProtocolTransaction, got {:?}", other),
        };
        assert_eq!(tx.operation, "vnc_connect");
        assert_eq!(tx.status, "ok");
        let offered = tx.attributes.get("security_types_offered").unwrap();
        assert!(offered.contains("none"), "should contain 'none': {offered}");
        assert!(
            offered.contains("vnc_auth"),
            "should contain 'vnc_auth': {offered}"
        );
        assert_eq!(tx.attributes.get("server_protocol_version").unwrap(), "3.8");
        assert_eq!(
            tx.attributes.get("chosen_security_type").unwrap(),
            "vnc_auth"
        );

        let obs = match &out[1].family {
            BronzeEventFamily::AssetObservation(a) => a,
            other => panic!("expected AssetObservation, got {:?}", other),
        };
        assert_eq!(obs.role.as_deref(), Some("vnc_server"));
        assert_eq!(obs.identifiers.get("protocol_version").unwrap(), "3.8");
    }

    // ── Test 3: Invalid security type (0) with reason → status=failed ─────────

    #[test]
    fn test_invalid_security_type_with_reason() {
        let mut dec = VncDecoder::default();
        let mut out = Vec::new();

        // Wire order: server_banner → client_banner → server_security_types(+reason).
        dec.on_stream_chunk(&chunk(b"RFB 003.008\n"), &mut out);
        dec.on_stream_chunk(&chunk(&client_banner_38()), &mut out);
        assert!(out.is_empty(), "no event until security types arrive");

        // Server sends count=1, Invalid(0), then reason: "Too many failures".
        let reason = b"Too many failures";
        let reason_len = reason.len() as u32;
        let mut sec_payload = vec![1u8, 0u8];
        sec_payload.extend_from_slice(&reason_len.to_be_bytes());
        sec_payload.extend_from_slice(reason);
        dec.on_stream_chunk(&chunk(&sec_payload), &mut out);

        assert_eq!(out.len(), 2);
        let tx = match &out[0].family {
            BronzeEventFamily::ProtocolTransaction(t) => t,
            other => panic!("expected ProtocolTransaction, got {:?}", other),
        };
        assert_eq!(tx.status, "failed");
        assert_eq!(
            tx.attributes.get("invalid_reason").unwrap(),
            "Too many failures"
        );
        assert_eq!(
            tx.attributes.get("security_types_offered").unwrap(),
            "invalid"
        );
    }

    // ── Test 4: v3.3 — server picks single u32 BE security type ──────────────
    //
    // In v3.3 the server unilaterally selects authentication: no count byte,
    // no client reply — just a 4-byte u32 BE type directly after the banners.

    #[test]
    fn test_v33_single_u32_security_type() {
        let mut dec = VncDecoder::default();
        let mut out = Vec::new();

        // Server banner is v3.3
        dec.on_stream_chunk(&chunk(b"RFB 003.003\n"), &mut out);
        assert!(out.is_empty());

        // Client echoes v3.3
        dec.on_stream_chunk(&chunk(b"RFB 003.003\n"), &mut out);
        assert!(out.is_empty());

        // Server sends 4-byte u32 BE security type = 2 (VNC Auth)
        let sec_type: u32 = 2;
        dec.on_stream_chunk(&chunk(&sec_type.to_be_bytes()), &mut out);

        assert_eq!(out.len(), 2);
        let tx = match &out[0].family {
            BronzeEventFamily::ProtocolTransaction(t) => t,
            other => panic!("expected ProtocolTransaction, got {:?}", other),
        };
        assert_eq!(tx.operation, "vnc_connect");
        assert_eq!(tx.status, "ok");
        assert_eq!(
            tx.attributes.get("security_types_offered").unwrap(),
            "vnc_auth"
        );
        assert_eq!(tx.attributes.get("server_protocol_version").unwrap(), "3.3");
        // v3.3: no chosen_security_type attribute (server chooses, client doesn't reply)
        assert!(tx.attributes.get("chosen_security_type").is_none());
    }

    // ── Test 5: Two sessions on different ports → two separate events ──────────

    #[test]
    fn test_two_sessions_different_ports() {
        let mut dec_5900 = VncDecoder::default();
        let mut dec_5902 = VncDecoder::default();
        let mut out_5900 = Vec::new();
        let mut out_5902 = Vec::new();

        let ctx_5900 = make_ctx(11111, 5900);
        let ctx_5902 = make_ctx(22222, 5902);

        // Wire order on each session: server_banner → client_banner → server_types → client_chosen.

        // 5900: server banner
        dec_5900.on_stream_chunk(
            &chunk_with_ctx(b"RFB 003.008\n", ctx_5900.clone()),
            &mut out_5900,
        );
        // 5902: server banner
        dec_5902.on_stream_chunk(
            &chunk_with_ctx(b"RFB 003.008\n", ctx_5902.clone()),
            &mut out_5902,
        );

        // Client banners
        dec_5900.on_stream_chunk(
            &chunk_with_ctx(&client_banner_38(), ctx_5900.clone()),
            &mut out_5900,
        );
        dec_5902.on_stream_chunk(
            &chunk_with_ctx(&client_banner_38(), ctx_5902.clone()),
            &mut out_5902,
        );

        assert!(out_5900.is_empty());
        assert!(out_5902.is_empty());

        // Server security types + client chosen in one window.
        dec_5900.on_stream_chunk(&chunk_with_ctx(&[1u8, 1u8, 1u8], ctx_5900), &mut out_5900); // count=1,[None],chosen=None
        dec_5902.on_stream_chunk(&chunk_with_ctx(&[1u8, 2u8, 2u8], ctx_5902), &mut out_5902); // count=1,[VNC Auth],chosen=VNC Auth

        assert_eq!(out_5900.len(), 2);
        assert_eq!(out_5902.len(), 2);

        let tx_5900 = match &out_5900[0].family {
            BronzeEventFamily::ProtocolTransaction(t) => t,
            _ => panic!("expected ProtocolTransaction"),
        };
        let tx_5902 = match &out_5902[0].family {
            BronzeEventFamily::ProtocolTransaction(t) => t,
            _ => panic!("expected ProtocolTransaction"),
        };

        assert_eq!(
            tx_5900.attributes.get("security_types_offered").unwrap(),
            "none"
        );
        assert_eq!(
            tx_5902.attributes.get("security_types_offered").unwrap(),
            "vnc_auth"
        );
        assert_eq!(tx_5900.status, "ok");
        assert_eq!(tx_5902.status, "ok");
    }

    // ── Test 6: Bad banner → ParseAnomaly severity=low ────────────────────────

    #[test]
    fn test_bad_banner_emits_parse_anomaly() {
        let mut dec = VncDecoder::default();
        let mut out = Vec::new();

        // First 12 bytes from server don't start with "RFB "
        dec.on_stream_chunk(&chunk(b"FOO 003.008\n"), &mut out);

        assert_eq!(out.len(), 1, "expected 1 ParseAnomaly event");
        let anomaly = match &out[0].family {
            BronzeEventFamily::ParseAnomaly(a) => a,
            other => panic!("expected ParseAnomaly, got {:?}", other),
        };
        assert_eq!(anomaly.severity, "low");
        assert_eq!(anomaly.decoder, "vnc");
    }

    // ── Bonus test 7: Partial banner — no event, stays buffered ──────────────

    #[test]
    fn test_partial_server_banner_no_event() {
        let mut dec = VncDecoder::default();
        let mut out = Vec::new();
        // Send only 6 bytes of the 12-byte banner
        dec.on_stream_chunk(&chunk(b"RFB 00"), &mut out);
        assert!(out.is_empty(), "partial banner must not emit");
    }
}
