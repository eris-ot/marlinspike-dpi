//! TACACS+ (RFC 8907) session decoder — port 49/TCP.
//!
//! Body obfuscation is XOR-based, not encryption: the body is XORed with a
//! pad derived from MD5(session_id || secret || version || seq_no || ...).
//! Without the shared secret the pad is unrecoverable; obfuscated bodies are
//! treated as opaque. The 12-byte header is always plaintext and yields:
//! session_id, packet type, sequence number, and the unencrypted-flag bit.
//! When TAC_PLUS_UNENCRYPTED_FLAG (bit 0 of flags) is set the body is
//! cleartext; for AUTHEN START packets we extract user, port, rem_addr, etc.

use std::collections::BTreeMap;

use chrono::{DateTime, Utc};

use crate::bronze::{
    AssetObservation, BronzeEvent, BronzeEventFamily, ProtocolTransaction, TransportProtocol,
};
use crate::engine::{
    build_envelope, new_event, parse_anomaly_event, DecoderInterest, SessionDecoder, StreamChunk,
};

// ── Wire constants ────────────────────────────────────────────────────────────

const HEADER_LEN: usize = 12;
const MAJOR_VER_EXPECTED: u8 = 0xC;
const TYPE_AUTHEN: u8 = 0x01;
const TYPE_AUTHOR: u8 = 0x02;
const TYPE_ACCT: u8 = 0x03;
const ACTION_LOGIN: u8 = 0x01;
const ACTION_CHPASS: u8 = 0x02;
const ACTION_SENDPASS: u8 = 0x03;
const AUTHEN_TYPE_ASCII: u8 = 0x01;
const AUTHEN_TYPE_PAP: u8 = 0x02;
const AUTHEN_TYPE_CHAP: u8 = 0x03;
const AUTHEN_TYPE_MSCHAP: u8 = 0x04;
const AUTHEN_TYPE_MSCHAPV2: u8 = 0x05;
const SERVICE_NONE: u8 = 0x00;
const SERVICE_LOGIN: u8 = 0x01;
const SERVICE_ENABLE: u8 = 0x02;
const SERVICE_PPP: u8 = 0x03;
const SERVICE_ARAP: u8 = 0x04;
const SERVICE_PT: u8 = 0x05;
const SERVICE_RCMD: u8 = 0x06;
const SERVICE_X25: u8 = 0x07;
const SERVICE_NASI: u8 = 0x08;
const SERVICE_FWPROXY: u8 = 0x09;

// ── Header parser ─────────────────────────────────────────────────────────────

struct TacacsHeader {
    major_ver: u8,
    minor_ver: u8,
    pkt_type: u8,
    seq_no: u8,
    flags: u8,
    session_id: u32,
    body_length: u32,
}

impl TacacsHeader {
    fn parse(buf: &[u8]) -> Option<Self> {
        if buf.len() < HEADER_LEN { return None; }
        let ver = buf[0];
        Some(Self {
            major_ver: ver >> 4,
            minor_ver: ver & 0x0F,
            pkt_type: buf[1],
            seq_no: buf[2],
            flags: buf[3],
            session_id: u32::from_be_bytes([buf[4], buf[5], buf[6], buf[7]]),
            body_length: u32::from_be_bytes([buf[8], buf[9], buf[10], buf[11]]),
        })
    }

    /// Bit 0 of flags: body is NOT obfuscated when set (RFC 8907 §4.1).
    fn body_unencrypted(&self) -> bool { self.flags & 0x01 != 0 }
    fn version_byte(&self) -> u8 { (self.major_ver << 4) | self.minor_ver }
}

// ── AUTHEN START body (plaintext path only) ───────────────────────────────────

struct AuthenStartBody {
    action: u8,
    priv_lvl: u8,
    authen_type: u8,
    service: u8,
    username: String,
    port: String,
    rem_addr: String,
}

impl AuthenStartBody {
    fn parse(body: &[u8]) -> Option<Self> {
        if body.len() < 8 { return None; }
        let user_len = body[4] as usize;
        let port_len = body[5] as usize;
        let rem_len  = body[6] as usize;
        if body.len() < 8 + user_len + port_len + rem_len { return None; }
        let mut off = 8;
        let username = String::from_utf8_lossy(&body[off..off + user_len]).into_owned(); off += user_len;
        let port     = String::from_utf8_lossy(&body[off..off + port_len]).into_owned(); off += port_len;
        let rem_addr = String::from_utf8_lossy(&body[off..off + rem_len]).into_owned();
        Some(Self { action: body[0], priv_lvl: body[1], authen_type: body[2], service: body[3],
                    username, port, rem_addr })
    }
}

// ── Name helpers ──────────────────────────────────────────────────────────────

fn tacacs_operation(pkt_type: u8, seq_no: u8) -> String {
    match pkt_type {
        TYPE_AUTHEN => match seq_no {
            1 => "tacacs_authen_start".to_string(),
            n if n % 2 == 0 => "tacacs_authen_reply".to_string(),
            _ => "tacacs_authen_continue".to_string(),
        },
        TYPE_AUTHOR => if seq_no == 1 { "tacacs_author_request".to_string() }
                       else           { "tacacs_author_reply".to_string() },
        TYPE_ACCT   => if seq_no == 1 { "tacacs_acct_request".to_string() }
                       else           { "tacacs_acct_reply".to_string() },
        other => format!("tacacs_unknown_type_0x{other:02x}"),
    }
}

fn action_name(v: u8) -> &'static str {
    match v { ACTION_LOGIN => "LOGIN", ACTION_CHPASS => "CHPASS",
              ACTION_SENDPASS => "SENDPASS", _ => "UNKNOWN" }
}

fn authen_type_name(v: u8) -> &'static str {
    match v { AUTHEN_TYPE_ASCII => "ASCII", AUTHEN_TYPE_PAP => "PAP",
              AUTHEN_TYPE_CHAP => "CHAP", AUTHEN_TYPE_MSCHAP => "MS-CHAP",
              AUTHEN_TYPE_MSCHAPV2 => "MS-CHAPv2", _ => "UNKNOWN" }
}

fn service_name(v: u8) -> &'static str {
    match v { SERVICE_NONE => "NONE", SERVICE_LOGIN => "LOGIN",
              SERVICE_ENABLE => "ENABLE", SERVICE_PPP => "PPP",
              SERVICE_ARAP => "ARAP", SERVICE_PT => "PT", SERVICE_RCMD => "RCMD",
              SERVICE_X25 => "X25", SERVICE_NASI => "NASI",
              SERVICE_FWPROXY => "FWPROXY", _ => "UNKNOWN" }
}

// ── Decoder ───────────────────────────────────────────────────────────────────

#[derive(Default)]
pub(crate) struct TacacsDecoder;

impl SessionDecoder for TacacsDecoder {
    fn name(&self) -> &'static str { "tacacs" }

    fn interest(&self) -> &'static [DecoderInterest] {
        &[DecoderInterest::TcpPort(49)]
    }

    fn on_stream_chunk(&mut self, chunk: &StreamChunk<'_>, out: &mut Vec<BronzeEvent>) {
        let payload = chunk.payload;

        macro_rules! envelope {
            () => {
                build_envelope(
                    &chunk.context, chunk.interface_id, chunk.frame_index,
                    chunk.timestamp, chunk.segment_hash, TransportProtocol::Tcp,
                    Some("tacacs"), chunk.captured_len, chunk.session_key.clone(),
                )
            };
        }

        let Some(hdr) = TacacsHeader::parse(payload) else {
            out.push(parse_anomaly_event(
                chunk.capture_id.to_string(), envelope!(), self.name(),
                "low", "tacacs+ header too short", payload,
            ));
            return;
        };

        // Anomaly: unexpected major version
        if hdr.major_ver != MAJOR_VER_EXPECTED {
            out.push(parse_anomaly_event(
                chunk.capture_id.to_string(), envelope!(), self.name(), "medium",
                &format!("unexpected tacacs+ major version 0x{:x}, expected 0xc", hdr.major_ver),
                payload,
            ));
        }

        let body_slice = &payload[HEADER_LEN..];
        let observed_len = body_slice.len();
        let claimed_len  = hdr.body_length as usize;

        // Anomaly: body length mismatch
        if observed_len != claimed_len {
            out.push(parse_anomaly_event(
                chunk.capture_id.to_string(), envelope!(), self.name(), "low",
                &format!("tacacs+ body length mismatch: header claims {claimed_len}, observed {observed_len}"),
                payload,
            ));
        }

        let body_unencrypted = hdr.body_unencrypted();
        let operation = tacacs_operation(hdr.pkt_type, hdr.seq_no);

        let mut attrs: BTreeMap<String, String> = BTreeMap::new();
        attrs.insert("version".to_string(),          format!("{:02x}", hdr.version_byte()));
        attrs.insert("tacacs_type".to_string(),      hdr.pkt_type.to_string());
        attrs.insert("seq_no".to_string(),           hdr.seq_no.to_string());
        attrs.insert("session_id".to_string(),       format!("{:08x}", hdr.session_id));
        attrs.insert("flags_hex".to_string(),        format!("{:02x}", hdr.flags));
        attrs.insert("body_length".to_string(),      hdr.body_length.to_string());
        attrs.insert("body_unencrypted".to_string(), if body_unencrypted { "true" } else { "false" }.to_string());

        // AUTHEN START + plaintext body → extract user fields
        if hdr.pkt_type == TYPE_AUTHEN && hdr.seq_no == 1 && body_unencrypted {
            let body = &body_slice[..observed_len.min(claimed_len)];
            if let Some(s) = AuthenStartBody::parse(body) {
                attrs.insert("action_name".to_string(),      action_name(s.action).to_string());
                attrs.insert("authen_type_name".to_string(), authen_type_name(s.authen_type).to_string());
                attrs.insert("service_name".to_string(),     service_name(s.service).to_string());
                attrs.insert("priv_lvl".to_string(),         s.priv_lvl.to_string());
                attrs.insert("username".to_string(),         s.username);
                attrs.insert("port".to_string(),             s.port);
                attrs.insert("rem_addr".to_string(),         s.rem_addr);
            }
        }

        out.push(new_event(
            chunk.capture_id.to_string(),
            envelope!(),
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

        // Asset observations: only on AUTHEN requests (seq_no == 1, type == AUTHEN)
        // dst = TACACS+ server, src = network device (client)
        if hdr.pkt_type == TYPE_AUTHEN && hdr.seq_no == 1 {
            let server_ip = chunk.context.dst_ip.to_string();
            let client_ip = chunk.context.src_ip.to_string();

            out.push(new_event(
                chunk.capture_id.to_string(), envelope!(),
                BronzeEventFamily::AssetObservation(AssetObservation {
                    asset_key: server_ip.clone(),
                    role: Some("tacacs_server".to_string()),
                    vendor: None, model: None, firmware: None,
                    hostnames: Vec::new(),
                    protocols: vec!["tacacs".to_string()],
                    identifiers: BTreeMap::from([("ip".to_string(), server_ip)]),
                }),
            ));

            out.push(new_event(
                chunk.capture_id.to_string(), envelope!(),
                BronzeEventFamily::AssetObservation(AssetObservation {
                    asset_key: client_ip.clone(),
                    role: Some("tacacs_client".to_string()),
                    vendor: None, model: None, firmware: None,
                    hostnames: Vec::new(),
                    protocols: vec!["tacacs".to_string()],
                    identifiers: BTreeMap::from([("ip".to_string(), client_ip)]),
                }),
            ));
        }
    }
}

inventory::submit!(crate::engine::decoders::DecoderRegistration {
    name: "tacacs",
    factory: || Box::new(TacacsDecoder::default()),
});

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};
    use chrono::{TimeZone, Utc};
    use super::*;
    use crate::bronze::BronzeEventFamily;
    use crate::engine::{DecoderInterest, StreamChunk};
    use crate::registry::PacketContext;

    fn ctx(src_port: u16, dst_port: u16) -> PacketContext {
        PacketContext {
            src_mac: [0u8; 6], dst_mac: [0u8; 6],
            src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            dst_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            src_port, dst_port, vlan_id: None,
            timestamp: 1_700_000_000_000_000,
        }
    }

    fn chunk<'a>(payload: &'a [u8], context: PacketContext) -> StreamChunk<'a> {
        StreamChunk {
            capture_id: "test", segment_hash: "seg",
            interface_id: 0, frame_index: 0,
            timestamp: Utc.timestamp_opt(1_700_000_000, 0).unwrap(),
            context, ethertype: 0x0800, ip_proto: Some(6), llc: None,
            transport: TransportProtocol::Tcp, payload,
            session_key: "sk".to_string(), captured_len: payload.len() as u64,
        }
    }

    /// Build a complete TACACS+ packet: 12-byte header + body.
    fn pkt(ver: u8, pkt_type: u8, seq_no: u8, flags: u8, session_id: u32, body: &[u8]) -> Vec<u8> {
        let mut buf = vec![ver, pkt_type, seq_no, flags];
        buf.extend_from_slice(&session_id.to_be_bytes());
        buf.extend_from_slice(&(body.len() as u32).to_be_bytes());
        buf.extend_from_slice(body);
        buf
    }

    fn get_tx(evs: &[BronzeEvent]) -> Option<&ProtocolTransaction> {
        evs.iter().find_map(|e| {
            if let BronzeEventFamily::ProtocolTransaction(ref tx) = e.family { Some(tx) } else { None }
        })
    }

    fn get_anomalies(evs: &[BronzeEvent]) -> Vec<&crate::bronze::ParseAnomaly> {
        evs.iter().filter_map(|e| {
            if let BronzeEventFamily::ParseAnomaly(ref a) = e.family { Some(a) } else { None }
        }).collect()
    }

    fn get_assets(evs: &[BronzeEvent]) -> Vec<&AssetObservation> {
        evs.iter().filter_map(|e| {
            if let BronzeEventFamily::AssetObservation(ref a) = e.family { Some(a) } else { None }
        }).collect()
    }

    // 1. AUTHEN START obfuscated (type=1, seq=1, flags=0) ─────────────────────
    #[test]
    fn test_authen_start_obfuscated() {
        let p = pkt(0xC1, TYPE_AUTHEN, 1, 0x00, 0xDEADBEEF, &[0xABu8; 16]);
        let mut dec = TacacsDecoder::default();
        let mut evs = Vec::new();
        dec.on_stream_chunk(&chunk(&p, ctx(12345, 49)), &mut evs);

        let tx = get_tx(&evs).unwrap();
        assert_eq!(tx.operation, "tacacs_authen_start");
        assert_eq!(tx.status, "observed");
        assert_eq!(tx.attributes["version"], "c1");
        assert_eq!(tx.attributes["tacacs_type"], "1");
        assert_eq!(tx.attributes["seq_no"], "1");
        assert_eq!(tx.attributes["session_id"], "deadbeef");
        assert_eq!(tx.attributes["body_unencrypted"], "false");
        assert!(!tx.attributes.contains_key("username"));
        assert!(!tx.attributes.contains_key("action_name"));

        let assets = get_assets(&evs);
        assert_eq!(assets.len(), 2);
        assert!(assets.iter().any(|a| a.role.as_deref() == Some("tacacs_server") && a.asset_key == "10.0.0.2"));
        assert!(assets.iter().any(|a| a.role.as_deref() == Some("tacacs_client") && a.asset_key == "10.0.0.1"));
    }

    // 2. AUTHEN START unencrypted — LOGIN/ASCII/LOGIN, extract user fields ─────
    #[test]
    fn test_authen_start_unencrypted_login() {
        let username = b"admin";
        let port_b   = b"tty0";
        let rem_b    = b"10.0.0.5";
        let mut body = vec![
            ACTION_LOGIN, 0x01, AUTHEN_TYPE_ASCII, SERVICE_LOGIN,
            username.len() as u8, port_b.len() as u8, rem_b.len() as u8, 0u8,
        ];
        body.extend_from_slice(username);
        body.extend_from_slice(port_b);
        body.extend_from_slice(rem_b);

        let p = pkt(0xC1, TYPE_AUTHEN, 1, 0x01, 0x11223344, &body);
        let mut dec = TacacsDecoder::default();
        let mut evs = Vec::new();
        dec.on_stream_chunk(&chunk(&p, ctx(54321, 49)), &mut evs);

        let tx = get_tx(&evs).unwrap();
        assert_eq!(tx.operation, "tacacs_authen_start");
        assert_eq!(tx.attributes["body_unencrypted"], "true");
        assert_eq!(tx.attributes["action_name"],      "LOGIN");
        assert_eq!(tx.attributes["authen_type_name"], "ASCII");
        assert_eq!(tx.attributes["service_name"],     "LOGIN");
        assert_eq!(tx.attributes["priv_lvl"],         "1");
        assert_eq!(tx.attributes["username"],         "admin");
        assert_eq!(tx.attributes["port"],             "tty0");
        assert_eq!(tx.attributes["rem_addr"],         "10.0.0.5");
    }

    // 3. AUTHEN REPLY (type=1, seq=2, even) ───────────────────────────────────
    #[test]
    fn test_authen_reply() {
        let p = pkt(0xC1, TYPE_AUTHEN, 2, 0x00, 0xAABBCCDD, &[0x01, 0x00, 0x00, 0x00, 0x00, 0x00]);
        let mut dec = TacacsDecoder::default();
        let mut evs = Vec::new();
        dec.on_stream_chunk(&chunk(&p, ctx(49, 12345)), &mut evs);

        let tx = get_tx(&evs).unwrap();
        assert_eq!(tx.operation, "tacacs_authen_reply");
        assert_eq!(tx.attributes["seq_no"], "2");
        assert!(get_assets(&evs).is_empty(), "no asset obs for replies");
    }

    // 4. ACCT REQUEST (type=3, seq=1) ─────────────────────────────────────────
    #[test]
    fn test_acct_request() {
        let p = pkt(0xC1, TYPE_ACCT, 1, 0x00, 0x55667788, &[0u8; 10]);
        let mut dec = TacacsDecoder::default();
        let mut evs = Vec::new();
        dec.on_stream_chunk(&chunk(&p, ctx(22222, 49)), &mut evs);

        let tx = get_tx(&evs).unwrap();
        assert_eq!(tx.operation, "tacacs_acct_request");
        assert_eq!(tx.attributes["tacacs_type"], "3");
        assert_eq!(tx.attributes["session_id"],  "55667788");
    }

    // 5. Bad version byte → ParseAnomaly severity=medium ─────────────────────
    #[test]
    fn test_bad_version_anomaly() {
        let p = pkt(0xE0, TYPE_AUTHEN, 1, 0x00, 0x12345678, &[0xFFu8; 8]);
        let mut dec = TacacsDecoder::default();
        let mut evs = Vec::new();
        dec.on_stream_chunk(&chunk(&p, ctx(9999, 49)), &mut evs);

        assert!(
            get_anomalies(&evs).iter().any(|a| a.severity == "medium"),
            "expected medium anomaly for bad major version"
        );
    }

    // 6. Length mismatch (header claims 100, only 30 bytes follow) → low ──────
    #[test]
    fn test_body_length_mismatch() {
        // Manually construct: header body_length=100 but only 30 body bytes.
        let mut p = vec![0xC1u8, TYPE_AUTHEN, 0x01, 0x00,
                         0x00, 0x00, 0x00, 0x01,   // session_id=1
                         0x00, 0x00, 0x00, 100];    // body_length=100
        p.extend_from_slice(&[0xABu8; 30]);

        let mut dec = TacacsDecoder::default();
        let mut evs = Vec::new();
        dec.on_stream_chunk(&chunk(&p, ctx(11111, 49)), &mut evs);

        assert!(
            get_anomalies(&evs).iter().any(|a| a.severity == "low"),
            "expected low anomaly for body length mismatch"
        );
    }

    // 7. Interest declares port 49/TCP ────────────────────────────────────────
    #[test]
    fn test_interest() {
        let dec = TacacsDecoder::default();
        assert!(dec.interest().contains(&DecoderInterest::TcpPort(49)));
    }

    // 8. AUTHOR REQUEST (type=2, seq=1) ───────────────────────────────────────
    #[test]
    fn test_author_request() {
        let p = pkt(0xC1, TYPE_AUTHOR, 1, 0x00, 0xCAFEBABE, &[0u8; 12]);
        let mut dec = TacacsDecoder::default();
        let mut evs = Vec::new();
        dec.on_stream_chunk(&chunk(&p, ctx(33333, 49)), &mut evs);

        let tx = get_tx(&evs).unwrap();
        assert_eq!(tx.operation, "tacacs_author_request");
        assert_eq!(tx.attributes["tacacs_type"], "2");
    }
}
