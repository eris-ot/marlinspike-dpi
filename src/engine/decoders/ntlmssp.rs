//! NTLMSSP recognition decoder — embedded-protocol scanner.
//!
//! NTLMSSP is not a standalone wire protocol. It is an authentication blob
//! embedded inside higher-layer protocols:
//!   - SMB Session Setup (ports 139, 445)
//!   - HTTP `WWW-Authenticate: Negotiate` / `Authorization: Negotiate` (80, 8080)
//!   - DCE/RPC AUTH3 (port 135)
//!   - WinRM over HTTP (port 5985)
//!
//! This decoder scans stream chunks for the `NTLMSSP\0` magic and parses
//! Type1/Type2/Type3 messages in-place without speaking the outer framing
//! protocol. NTLM-relay is the dominant AD attack on OT/IT-bridge networks;
//! recognising these flows surfaces relay targets and credential exposure.
//!
//! MS-NLMP: <https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp>

use std::collections::BTreeMap;

use crate::bronze::{AssetObservation, BronzeEvent, BronzeEventFamily, ProtocolTransaction};
use crate::engine::{
    build_envelope, new_event, parse_anomaly_event, DecoderInterest, SessionDecoder, StreamChunk,
};

// ── Constants ─────────────────────────────────────────────────────────────────

const NTLMSSP_MAGIC: &[u8] = b"NTLMSSP\x00";
const MSG_NEGOTIATE: u32 = 1;
const MSG_CHALLENGE: u32 = 2;
const MSG_AUTHENTICATE: u32 = 3;
/// Bit 0 of NegotiateFlags: NTLMSSP_NEGOTIATE_UNICODE.
const FLAG_UNICODE: u32 = 0x0000_0001;
// AV_PAIR AvIds (MS-NLMP §2.2.2.1)
const AV_EOL: u16 = 0;
const AV_NB_COMPUTER_NAME: u16 = 1;
const AV_NB_DOMAIN_NAME: u16 = 2;
const AV_DNS_COMPUTER_NAME: u16 = 3;
const AV_DNS_DOMAIN_NAME: u16 = 4;

// ── Decoder registration ──────────────────────────────────────────────────────

#[derive(Default)]
pub(crate) struct NtlmsspDecoder;

impl SessionDecoder for NtlmsspDecoder {
    fn name(&self) -> &'static str { "ntlmssp" }

    fn interest(&self) -> &'static [DecoderInterest] {
        &[
            DecoderInterest::TcpPort(80),
            DecoderInterest::TcpPort(135),
            DecoderInterest::TcpPort(139),
            DecoderInterest::TcpPort(445),
            DecoderInterest::TcpPort(8080),
            DecoderInterest::TcpPort(5985),
        ]
    }

    fn on_stream_chunk(&mut self, chunk: &StreamChunk<'_>, out: &mut Vec<BronzeEvent>) {
        process_chunk(chunk, out);
    }
}

inventory::submit!(crate::engine::decoders::DecoderRegistration {
    name: "ntlmssp",
    factory: || Box::new(NtlmsspDecoder::default()),
});

// ── Wire helpers ──────────────────────────────────────────────────────────────

fn u16le(buf: &[u8], off: usize) -> Option<u16> {
    buf.get(off..off + 2).map(|s| u16::from_le_bytes([s[0], s[1]]))
}

fn u32le(buf: &[u8], off: usize) -> Option<u32> {
    buf.get(off..off + 4).map(|s| u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
}

/// Security buffer: `len u16 | maxlen u16 | offset u32`. Returns (len, offset).
fn sec_buf_field(buf: &[u8], off: usize) -> Option<(usize, usize)> {
    Some((u16le(buf, off)? as usize, u32le(buf, off + 4)? as usize))
}

fn sec_buf_slice<'a>(buf: &'a [u8], off: usize) -> Option<&'a [u8]> {
    let (len, start) = sec_buf_field(buf, off)?;
    if len == 0 { return Some(&[]); }
    buf.get(start..start + len)
}

/// Decode a string obeying the UNICODE flag. Falls back to hex on failure.
fn decode(bytes: &[u8], flags: u32) -> String {
    if bytes.is_empty() { return String::new(); }
    if flags & FLAG_UNICODE != 0 {
        if bytes.len() % 2 != 0 { return hex::encode(bytes); }
        let units: Vec<u16> = bytes.chunks_exact(2)
            .map(|c| u16::from_le_bytes([c[0], c[1]])).collect();
        String::from_utf16(&units).unwrap_or_else(|_| hex::encode(bytes))
    } else {
        bytes.iter().map(|&b| b as char).collect()
    }
}

// ── AV_PAIR (TargetInfo, always UTF-16LE per spec) ───────────────────────────

struct AvPairs {
    nb_computer: String,
    nb_domain: String,
    dns_computer: String,
    dns_domain: String,
}

fn parse_av_pairs(blob: &[u8]) -> AvPairs {
    let mut r = AvPairs {
        nb_computer: String::new(),
        nb_domain: String::new(),
        dns_computer: String::new(),
        dns_domain: String::new(),
    };
    let mut pos = 0;
    loop {
        let av_id = match u16le(blob, pos) { Some(v) => v, None => break };
        let av_len = match u16le(blob, pos + 2) { Some(v) => v as usize, None => break };
        pos += 4;
        if av_id == AV_EOL { break; }
        let val = match blob.get(pos..pos + av_len) { Some(b) => b, None => break };
        // TargetInfo strings are always UTF-16LE (MS-NLMP §2.2.2.1)
        let s = decode(val, FLAG_UNICODE);
        match av_id {
            AV_NB_COMPUTER_NAME  => r.nb_computer  = s,
            AV_NB_DOMAIN_NAME    => r.nb_domain     = s,
            AV_DNS_COMPUTER_NAME => r.dns_computer  = s,
            AV_DNS_DOMAIN_NAME   => r.dns_domain    = s,
            _ => {}
        }
        pos += av_len;
    }
    r
}

// ── Event helpers ─────────────────────────────────────────────────────────────

fn envelope(chunk: &StreamChunk<'_>) -> crate::bronze::EventEnvelope {
    build_envelope(
        &chunk.context, chunk.interface_id, chunk.frame_index, chunk.timestamp,
        chunk.segment_hash, chunk.transport, Some("ntlmssp"),
        chunk.captured_len, chunk.session_key.clone(),
    )
}

fn emit_tx(op: &str, attrs: BTreeMap<String, String>, chunk: &StreamChunk<'_>, out: &mut Vec<BronzeEvent>) {
    out.push(new_event(
        chunk.capture_id.to_string(),
        envelope(chunk),
        BronzeEventFamily::ProtocolTransaction(ProtocolTransaction {
            operation: op.to_string(),
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
}

fn emit_anomaly(severity: &str, reason: &str, raw: &[u8], chunk: &StreamChunk<'_>, out: &mut Vec<BronzeEvent>) {
    out.push(parse_anomaly_event(
        chunk.capture_id.to_string(),
        envelope(chunk),
        "ntlmssp",
        severity,
        reason,
        &raw[..raw.len().min(32)],
    ));
}

fn attrs(pairs: &[(&str, String)]) -> BTreeMap<String, String> {
    pairs.iter().map(|(k, v)| (k.to_string(), v.clone())).collect()
}

// ── Per-message parsers ───────────────────────────────────────────────────────

fn parse_type1(blob: &[u8], flags: u32, chunk: &StreamChunk<'_>, out: &mut Vec<BronzeEvent>) {
    let domain    = sec_buf_slice(blob, 16).map(|b| decode(b, flags)).unwrap_or_default();
    let workstation = sec_buf_slice(blob, 24).map(|b| decode(b, flags)).unwrap_or_default();
    emit_tx("ntlmssp_negotiate", attrs(&[
        ("message_type",      "1".to_string()),
        ("negotiate_flags_hex", format!("{flags:#010x}")),
        ("domain_name",       domain),
        ("workstation",       workstation),
    ]), chunk, out);
}

fn parse_type2(blob: &[u8], flags: u32, chunk: &StreamChunk<'_>, out: &mut Vec<BronzeEvent>) {
    let target_name = sec_buf_slice(blob, 12).map(|b| decode(b, flags)).unwrap_or_default();
    let challenge_hex = blob.get(24..32).map(hex::encode).unwrap_or_default();
    let av = sec_buf_slice(blob, 40).map(parse_av_pairs);
    let nb_computer  = av.as_ref().map(|a| a.nb_computer.clone()).unwrap_or_default();
    let nb_domain    = av.as_ref().map(|a| a.nb_domain.clone()).unwrap_or_default();
    let dns_computer = av.as_ref().map(|a| a.dns_computer.clone()).unwrap_or_default();
    let dns_domain   = av.as_ref().map(|a| a.dns_domain.clone()).unwrap_or_default();

    emit_tx("ntlmssp_challenge", attrs(&[
        ("message_type",       "2".to_string()),
        ("negotiate_flags_hex", format!("{flags:#010x}")),
        ("target_name",        target_name),
        ("server_challenge_hex", challenge_hex),
        ("nb_computer_name",   nb_computer.clone()),
        ("nb_domain_name",     nb_domain.clone()),
        ("dns_computer_name",  dns_computer.clone()),
        ("dns_domain_name",    dns_domain.clone()),
    ]), chunk, out);

    // Asset: AD authentication target (server side of the handshake)
    let hostname = if !nb_computer.is_empty()  { nb_computer.clone() }
                   else if !dns_computer.is_empty() { dns_computer }
                   else { chunk.context.src_ip.to_string() };
    let ad_domain = if !nb_domain.is_empty() { nb_domain } else { dns_domain };
    let mut ids = BTreeMap::new();
    ids.insert("ad_domain".to_string(), ad_domain);
    out.push(new_event(
        chunk.capture_id.to_string(),
        envelope(chunk),
        BronzeEventFamily::AssetObservation(AssetObservation {
            asset_key: chunk.context.src_ip.to_string(),
            role: Some("ad_authentication_target".to_string()),
            vendor: None, model: None, firmware: None,
            hostnames: if hostname.is_empty() { vec![] } else { vec![hostname] },
            protocols: vec!["ntlmssp".to_string()],
            identifiers: ids,
        }),
    ));
}

fn parse_type3(blob: &[u8], flags: u32, chunk: &StreamChunk<'_>, out: &mut Vec<BronzeEvent>) {
    let lm_len  = sec_buf_field(blob, 12).map(|(l, _)| l).unwrap_or(0);
    let nt_len  = sec_buf_field(blob, 20).map(|(l, _)| l).unwrap_or(0);
    let domain  = sec_buf_slice(blob, 28).map(|b| decode(b, flags)).unwrap_or_default();
    let username = sec_buf_slice(blob, 36).map(|b| decode(b, flags)).unwrap_or_default();
    let workstation = sec_buf_slice(blob, 44).map(|b| decode(b, flags)).unwrap_or_default();

    emit_tx("ntlmssp_authenticate", attrs(&[
        ("message_type",       "3".to_string()),
        ("negotiate_flags_hex", format!("{flags:#010x}")),
        ("domain_name",        domain.clone()),
        ("username",           username.clone()),
        ("workstation",        workstation.clone()),
        ("nt_response_len",    nt_len.to_string()),
        ("lm_response_len",    lm_len.to_string()),
    ]), chunk, out);

    // Asset: AD authentication client (identity carrier)
    if !username.is_empty() {
        let mut ids = BTreeMap::new();
        ids.insert("ad_username".to_string(), username);
        ids.insert("ad_domain".to_string(), domain);
        out.push(new_event(
            chunk.capture_id.to_string(),
            envelope(chunk),
            BronzeEventFamily::AssetObservation(AssetObservation {
                asset_key: chunk.context.src_ip.to_string(),
                role: Some("ad_authentication_client".to_string()),
                vendor: None, model: None, firmware: None,
                hostnames: if workstation.is_empty() { vec![] } else { vec![workstation] },
                protocols: vec!["ntlmssp".to_string()],
                identifiers: ids,
            }),
        ));
    }
}

// ── Core scanner ──────────────────────────────────────────────────────────────

fn process_chunk(chunk: &StreamChunk<'_>, out: &mut Vec<BronzeEvent>) {
    let payload = chunk.payload;
    let (sp, dp) = (chunk.context.src_port, chunk.context.dst_port);
    let on_http  = sp == 80 || dp == 80 || sp == 8080 || dp == 8080;

    // HTTP Negotiate header shortcut — do not base64-decode the blob (out of scope).
    // A text heuristic (first byte ASCII) prevents false-positives on binary data.
    if on_http
        && payload.first().map_or(false, |b| b.is_ascii())
        && payload.windows(10).any(|w| w == b"Negotiate ")
    {
        emit_tx("ntlmssp_in_http_negotiate", attrs(&[
            ("message_type",       "0".to_string()),
            ("negotiate_flags_hex", "0x00000000".to_string()),
        ]), chunk, out);
        return;
    }

    // Scan for every NTLMSSP\0 magic in the payload. Multiple blobs can appear
    // in a single TCP segment (e.g. SMB compound requests).
    let mut from = 0usize;
    while from + NTLMSSP_MAGIC.len() <= payload.len() {
        let pos = match payload[from..].windows(NTLMSSP_MAGIC.len()).position(|w| w == NTLMSSP_MAGIC) {
            Some(p) => from + p,
            None    => break,
        };
        let blob = &payload[pos..];
        if blob.len() < 12 { break; }

        let msg_type = match u32le(blob, 8) { Some(t) => t, None => break };

        // Credential exposure: binary NTLMSSP blob over unencrypted HTTP port 80.
        if sp == 80 || dp == 80 {
            emit_anomaly("medium", "NTLMSSP over plaintext HTTP — credential exposure risk",
                         blob, chunk, out);
        }

        match msg_type {
            MSG_NEGOTIATE => {
                if blob.len() < 32 { emit_anomaly("low",
                    "Truncated NTLMSSP message — security buffer offsets out of range",
                    blob, chunk, out);
                } else {
                    parse_type1(blob, u32le(blob, 12).unwrap_or(0), chunk, out);
                }
            }
            MSG_CHALLENGE => {
                if blob.len() < 48 { emit_anomaly("low",
                    "Truncated NTLMSSP message — security buffer offsets out of range",
                    blob, chunk, out);
                } else {
                    parse_type2(blob, u32le(blob, 20).unwrap_or(0), chunk, out);
                }
            }
            MSG_AUTHENTICATE => {
                if blob.len() < 64 { emit_anomaly("low",
                    "Truncated NTLMSSP message — security buffer offsets out of range",
                    blob, chunk, out);
                } else {
                    parse_type3(blob, u32le(blob, 60).unwrap_or(0), chunk, out);
                }
            }
            other => {
                emit_tx(&format!("ntlmssp_unknown_type_{other}"), attrs(&[
                    ("message_type",       other.to_string()),
                    ("negotiate_flags_hex", "0x00000000".to_string()),
                ]), chunk, out);
                emit_anomaly("low", &format!("Unknown NTLMSSP message type: {other}"),
                             blob, chunk, out);
            }
        }

        from = pos + NTLMSSP_MAGIC.len();
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};
    use chrono::{TimeZone, Utc};
    use super::*;
    use crate::bronze::BronzeEventFamily;
    use crate::engine::{DecoderInterest, StreamChunk};
    use crate::registry::PacketContext;

    fn ctx(sp: u16, dp: u16) -> PacketContext {
        PacketContext {
            src_mac: [0u8; 6], dst_mac: [0u8; 6],
            src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            dst_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            src_port: sp, dst_port: dp, vlan_id: None,
            timestamp: 1_700_000_000_000_000,
        }
    }

    fn chunk<'a>(payload: &'a [u8], context: PacketContext) -> StreamChunk<'a> {
        StreamChunk {
            capture_id: "test", segment_hash: "seg",
            interface_id: 0, frame_index: 0,
            timestamp: Utc.timestamp_opt(1_700_000_000, 0).unwrap(),
            context, ethertype: 0x0800, ip_proto: Some(6), llc: None,
            transport: crate::bronze::TransportProtocol::Tcp,
            payload, session_key: "sk".to_string(),
            captured_len: payload.len() as u64,
        }
    }

    fn get_tx(evs: &[BronzeEvent]) -> Option<&ProtocolTransaction> {
        evs.iter().find_map(|e| if let BronzeEventFamily::ProtocolTransaction(ref t) = e.family { Some(t) } else { None })
    }
    fn get_asset(evs: &[BronzeEvent]) -> Option<&AssetObservation> {
        evs.iter().find_map(|e| if let BronzeEventFamily::AssetObservation(ref a) = e.family { Some(a) } else { None })
    }
    fn get_anomaly(evs: &[BronzeEvent]) -> Option<&crate::bronze::ParseAnomaly> {
        evs.iter().find_map(|e| if let BronzeEventFamily::ParseAnomaly(ref a) = e.family { Some(a) } else { None })
    }

    fn utf16le(s: &str) -> Vec<u8> {
        s.encode_utf16().flat_map(|c| c.to_le_bytes()).collect()
    }

    /// Security buffer: len u16 LE | maxlen u16 LE | offset u32 LE.
    fn sbuf(len: u16, offset: u32) -> Vec<u8> {
        let mut v = len.to_le_bytes().to_vec();
        v.extend_from_slice(&len.to_le_bytes());
        v.extend_from_slice(&offset.to_le_bytes());
        v
    }

    // ── 1. Type1 NEGOTIATE — Unicode domain + workstation ────────────────────

    #[test]
    fn test_type1_negotiate_unicode() {
        let dom = utf16le("EXAMPLE");
        let ws  = utf16le("CLIENT01");
        let dom_off: u32 = 32;
        let ws_off: u32  = dom_off + dom.len() as u32;

        let mut pkt = Vec::new();
        pkt.extend_from_slice(NTLMSSP_MAGIC);
        pkt.extend_from_slice(&1u32.to_le_bytes());              // type
        pkt.extend_from_slice(&1u32.to_le_bytes());              // flags UNICODE
        pkt.extend_from_slice(&sbuf(dom.len() as u16, dom_off));
        pkt.extend_from_slice(&sbuf(ws.len() as u16, ws_off));
        pkt.extend_from_slice(&dom);
        pkt.extend_from_slice(&ws);

        let mut dec = NtlmsspDecoder::default();
        let mut evs = Vec::new();
        dec.on_stream_chunk(&chunk(&pkt, ctx(12345, 445)), &mut evs);

        let tx = get_tx(&evs).unwrap();
        assert_eq!(tx.operation, "ntlmssp_negotiate");
        assert_eq!(tx.status, "observed");
        assert_eq!(tx.attributes["message_type"], "1");
        assert_eq!(tx.attributes["domain_name"], "EXAMPLE");
        assert_eq!(tx.attributes["workstation"], "CLIENT01");
        assert_eq!(tx.attributes["negotiate_flags_hex"], "0x00000001");
    }

    // ── 2. Type2 CHALLENGE — basic + AssetObservation ────────────────────────

    #[test]
    fn test_type2_challenge_basic() {
        let tn  = utf16le("EXAMPLE");
        let ti  = vec![0x00u8, 0x00, 0x00, 0x00]; // AV_EOL
        let tn_off: u32  = 48;
        let ti_off: u32  = tn_off + tn.len() as u32;
        let sc: [u8; 8]  = [0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0xba, 0xbe];

        let mut pkt = Vec::new();
        pkt.extend_from_slice(NTLMSSP_MAGIC);
        pkt.extend_from_slice(&2u32.to_le_bytes());
        pkt.extend_from_slice(&sbuf(tn.len() as u16, tn_off));
        pkt.extend_from_slice(&1u32.to_le_bytes());    // flags UNICODE
        pkt.extend_from_slice(&sc);
        pkt.extend_from_slice(&[0u8; 8]);              // reserved
        pkt.extend_from_slice(&sbuf(ti.len() as u16, ti_off));
        pkt.extend_from_slice(&tn);
        pkt.extend_from_slice(&ti);

        let mut evs = Vec::new();
        NtlmsspDecoder::default().on_stream_chunk(&chunk(&pkt, ctx(445, 12345)), &mut evs);

        let tx = get_tx(&evs).unwrap();
        assert_eq!(tx.operation, "ntlmssp_challenge");
        assert_eq!(tx.attributes["target_name"], "EXAMPLE");
        assert_eq!(tx.attributes["server_challenge_hex"], hex::encode(sc));
        assert_eq!(get_asset(&evs).unwrap().role.as_deref(), Some("ad_authentication_target"));
    }

    // ── 3. Type2 CHALLENGE — full AV_PAIRs ───────────────────────────────────

    #[test]
    fn test_type2_challenge_avpairs() {
        fn av(id: u16, val: &[u8]) -> Vec<u8> {
            let mut v = id.to_le_bytes().to_vec();
            v.extend_from_slice(&(val.len() as u16).to_le_bytes());
            v.extend_from_slice(val);
            v
        }
        let tn = utf16le("EXAMPLE");
        let mut ti = Vec::new();
        ti.extend(av(AV_NB_COMPUTER_NAME,  &utf16le("DC01")));
        ti.extend(av(AV_NB_DOMAIN_NAME,    &utf16le("EXAMPLE")));
        ti.extend(av(AV_DNS_COMPUTER_NAME, &utf16le("dc01.example.local")));
        ti.extend(av(AV_DNS_DOMAIN_NAME,   &utf16le("example.local")));
        ti.extend(av(AV_EOL, &[]));

        let tn_off: u32 = 48;
        let ti_off: u32 = tn_off + tn.len() as u32;

        let mut pkt = Vec::new();
        pkt.extend_from_slice(NTLMSSP_MAGIC);
        pkt.extend_from_slice(&2u32.to_le_bytes());
        pkt.extend_from_slice(&sbuf(tn.len() as u16, tn_off));
        pkt.extend_from_slice(&1u32.to_le_bytes());
        pkt.extend_from_slice(&[0x11u8; 8]);
        pkt.extend_from_slice(&[0u8; 8]);
        pkt.extend_from_slice(&sbuf(ti.len() as u16, ti_off));
        pkt.extend_from_slice(&tn);
        pkt.extend_from_slice(&ti);

        let mut evs = Vec::new();
        NtlmsspDecoder::default().on_stream_chunk(&chunk(&pkt, ctx(445, 12345)), &mut evs);

        let tx = get_tx(&evs).unwrap();
        assert_eq!(tx.attributes["nb_computer_name"], "DC01");
        assert_eq!(tx.attributes["nb_domain_name"], "EXAMPLE");
        assert_eq!(tx.attributes["dns_computer_name"], "dc01.example.local");
        assert_eq!(tx.attributes["dns_domain_name"], "example.local");

        let asset = get_asset(&evs).unwrap();
        assert_eq!(asset.role.as_deref(), Some("ad_authentication_target"));
        assert!(asset.hostnames.contains(&"DC01".to_string()));
        assert_eq!(asset.identifiers.get("ad_domain").map(String::as_str), Some("EXAMPLE"));
    }

    // ── 4. Type3 AUTHENTICATE — client AssetObservation ─────────────────────

    #[test]
    fn test_type3_authenticate_asset() {
        let lm  = vec![0xAAu8; 24];
        let nt  = vec![0xBBu8; 24];
        let dom = utf16le("EXAMPLE");
        let usr = utf16le("alice");
        let ws  = utf16le("CLIENT01");
        let base: u32 = 64;
        let lm_off  = base;
        let nt_off  = lm_off  + lm.len() as u32;
        let dom_off = nt_off  + nt.len() as u32;
        let usr_off = dom_off + dom.len() as u32;
        let ws_off  = usr_off + usr.len() as u32;
        let enc_off = ws_off  + ws.len() as u32;

        let mut pkt = Vec::new();
        pkt.extend_from_slice(NTLMSSP_MAGIC);
        pkt.extend_from_slice(&3u32.to_le_bytes());
        pkt.extend_from_slice(&sbuf(lm.len() as u16,  lm_off));
        pkt.extend_from_slice(&sbuf(nt.len() as u16,  nt_off));
        pkt.extend_from_slice(&sbuf(dom.len() as u16, dom_off));
        pkt.extend_from_slice(&sbuf(usr.len() as u16, usr_off));
        pkt.extend_from_slice(&sbuf(ws.len() as u16,  ws_off));
        pkt.extend_from_slice(&sbuf(0u16, enc_off));
        pkt.extend_from_slice(&1u32.to_le_bytes()); // flags UNICODE
        pkt.extend_from_slice(&lm); pkt.extend_from_slice(&nt);
        pkt.extend_from_slice(&dom); pkt.extend_from_slice(&usr);
        pkt.extend_from_slice(&ws);

        let mut evs = Vec::new();
        NtlmsspDecoder::default().on_stream_chunk(&chunk(&pkt, ctx(12345, 445)), &mut evs);

        let tx = get_tx(&evs).unwrap();
        assert_eq!(tx.operation, "ntlmssp_authenticate");
        assert_eq!(tx.attributes["username"], "alice");
        assert_eq!(tx.attributes["domain_name"], "EXAMPLE");
        assert_eq!(tx.attributes["workstation"], "CLIENT01");
        assert_eq!(tx.attributes["nt_response_len"], "24");
        assert_eq!(tx.attributes["lm_response_len"], "24");

        let asset = get_asset(&evs).unwrap();
        assert_eq!(asset.role.as_deref(), Some("ad_authentication_client"));
        assert_eq!(asset.identifiers.get("ad_username").map(String::as_str), Some("alice"));
        assert_eq!(asset.identifiers.get("ad_domain").map(String::as_str),   Some("EXAMPLE"));
    }

    // ── 5. Plaintext HTTP (port 80) → ParseAnomaly medium ───────────────────

    #[test]
    fn test_plaintext_http_anomaly() {
        let mut pkt = Vec::new();
        pkt.extend_from_slice(NTLMSSP_MAGIC);
        pkt.extend_from_slice(&1u32.to_le_bytes());
        pkt.extend_from_slice(&1u32.to_le_bytes());
        pkt.extend_from_slice(&sbuf(0, 32));
        pkt.extend_from_slice(&sbuf(0, 32));

        let mut evs = Vec::new();
        NtlmsspDecoder::default().on_stream_chunk(&chunk(&pkt, ctx(12345, 80)), &mut evs);

        let a = get_anomaly(&evs).unwrap();
        assert_eq!(a.severity, "medium");
        assert!(a.reason.contains("plaintext HTTP"), "reason: {}", a.reason);
    }

    // ── 6. Unknown message type → ntlmssp_unknown_type_4 + anomaly low ──────

    #[test]
    fn test_unknown_message_type() {
        let mut pkt = Vec::new();
        pkt.extend_from_slice(NTLMSSP_MAGIC);
        pkt.extend_from_slice(&4u32.to_le_bytes());
        pkt.extend_from_slice(&[0u8; 8]);

        let mut evs = Vec::new();
        NtlmsspDecoder::default().on_stream_chunk(&chunk(&pkt, ctx(12345, 445)), &mut evs);

        assert_eq!(get_tx(&evs).unwrap().operation, "ntlmssp_unknown_type_4");
        assert_eq!(get_anomaly(&evs).unwrap().severity, "low");
    }

    // ── 7. interest() exposes correct ports ──────────────────────────────────

    #[test]
    fn test_interest_ports() {
        let i = NtlmsspDecoder::default().interest();
        assert!(i.contains(&DecoderInterest::TcpPort(445)));
        assert!(i.contains(&DecoderInterest::TcpPort(80)));
        assert!(i.contains(&DecoderInterest::TcpPort(135)));
        assert!(i.contains(&DecoderInterest::TcpPort(5985)));
    }

    // ── 8. HTTP Negotiate header → ntlmssp_in_http_negotiate ─────────────────

    #[test]
    fn test_http_negotiate_header() {
        let pkt = b"HTTP/1.1 401 Unauthorized\r\nWWW-Authenticate: Negotiate YIIFwAYGKwY...\r\n\r\n";
        let mut evs = Vec::new();
        NtlmsspDecoder::default().on_stream_chunk(&chunk(pkt, ctx(80, 12345)), &mut evs);

        let tx = get_tx(&evs).unwrap();
        assert_eq!(tx.operation, "ntlmssp_in_http_negotiate");
        assert_eq!(tx.status, "observed");
    }
}
