//! Recognition-only `SessionDecoder` impls — port + light signature check,
//! emit a `ProtocolTransaction` for traffic classification. No deep PDU
//! parsing.
//!
//! Members: SMB, Kerberos, LDAP/LDAPS, CC-Link IE, CODESYS, IO-Link Wireless,
//! IGMP. Each is registered in `DpiEngine::new()`.

use std::collections::BTreeMap;

use crate::bronze::{BronzeEvent, BronzeEventFamily, ProtocolTransaction};
use crate::engine::{
    build_envelope, new_event, DecoderInterest, SessionDecoder, StreamChunk,
};

/// Helper to emit a single ProtocolTransaction recognition event.
fn emit_recognition(
    chunk: &StreamChunk<'_>,
    out: &mut Vec<BronzeEvent>,
    protocol: &'static str,
    operation: &'static str,
    summary: &str,
) {
    let envelope = build_envelope(
        &chunk.context,
        chunk.interface_id,
        chunk.frame_index,
        chunk.timestamp,
        chunk.segment_hash,
        chunk.transport,
        Some(protocol),
        chunk.captured_len,
        chunk.session_key.clone(),
    );
    let mut attributes = BTreeMap::new();
    attributes.insert("protocol".to_string(), protocol.to_string());
    out.push(new_event(
        chunk.capture_id.to_string(),
        envelope,
        BronzeEventFamily::ProtocolTransaction(ProtocolTransaction {
            operation: operation.to_string(),
            status: "ok".to_string(),
            request_summary: Some(summary.to_string()),
            response_summary: None,
            object_refs: Vec::new(),
            values: Vec::new(),
            attributes,
            modbus: None,
                                        protocol_fields: None,
        }),
    ));
}

pub(crate) struct SmbRecognizer;

impl SessionDecoder for SmbRecognizer {
    fn name(&self) -> &'static str {
        "smb"
    }

    fn interest(&self) -> &'static [DecoderInterest] {
        &[DecoderInterest::TcpPort(445), DecoderInterest::TcpPort(139)]
    }

    fn on_stream_chunk(&mut self, chunk: &StreamChunk<'_>, out: &mut Vec<BronzeEvent>) {
        let p = chunk.payload;
        // SMB direct (port 445): the SMB header may start at offset 4 if a
        // 4-byte NetBIOS-style length prefix is present (always for 139,
        // sometimes for 445), or at offset 0.
        let candidates: [usize; 2] = [4, 0];
        for &off in &candidates {
            if off + 4 > p.len() {
                continue;
            }
            let sig = &p[off..off + 4];
            if sig == [0xFF, b'S', b'M', b'B'] {
                emit_recognition(chunk, out, "smb", "smb1_message", "SMB1 traffic");
                return;
            }
            if sig == [0xFE, b'S', b'M', b'B'] {
                emit_recognition(chunk, out, "smb", "smb2_message", "SMB2 traffic");
                return;
            }
        }
    }
}

pub(crate) struct KerberosRecognizer;

impl SessionDecoder for KerberosRecognizer {
    fn name(&self) -> &'static str {
        "kerberos"
    }

    fn interest(&self) -> &'static [DecoderInterest] {
        &[
            DecoderInterest::TcpPort(88),
            DecoderInterest::UdpPort(88),
            DecoderInterest::TcpPort(464),
            DecoderInterest::UdpPort(464),
        ]
    }

    fn on_stream_chunk(&mut self, chunk: &StreamChunk<'_>, out: &mut Vec<BronzeEvent>) {
        if looks_like_kerberos(chunk.payload) {
            emit_recognition(chunk, out, "kerberos", "kerberos_message", "Kerberos traffic");
        }
    }

    fn on_datagram(&mut self, chunk: &StreamChunk<'_>, out: &mut Vec<BronzeEvent>) {
        if looks_like_kerberos(chunk.payload) {
            emit_recognition(chunk, out, "kerberos", "kerberos_message", "Kerberos traffic");
        }
    }
}

/// Light Kerberos signature: ASN.1 BER application-tagged messages. KRB
/// messages start with application-tag bytes 0x6A (AS-REQ), 0x6B (AS-REP),
/// 0x6C (TGS-REQ), 0x6D (TGS-REP), 0x6E (AP-REQ), 0x6F (AP-REP), 0x7E
/// (KRB-ERROR). For TCP, a 4-byte length precedes the ASN.1.
fn looks_like_kerberos(p: &[u8]) -> bool {
    if p.is_empty() {
        return false;
    }
    let candidates = [0usize, 4];
    for &off in &candidates {
        if let Some(b) = p.get(off) {
            if matches!(*b, 0x6A..=0x6F | 0x7E) {
                return true;
            }
        }
    }
    false
}

pub(crate) struct LdapRecognizer;

impl SessionDecoder for LdapRecognizer {
    fn name(&self) -> &'static str {
        "ldap"
    }

    fn interest(&self) -> &'static [DecoderInterest] {
        &[DecoderInterest::TcpPort(389), DecoderInterest::TcpPort(636)]
    }

    fn on_stream_chunk(&mut self, chunk: &StreamChunk<'_>, out: &mut Vec<BronzeEvent>) {
        if chunk.context.dst_port == 636 || chunk.context.src_port == 636 {
            // LDAPS is TLS-encrypted; recognition only by port.
            emit_recognition(chunk, out, "ldap", "ldaps_traffic", "LDAPS traffic");
            return;
        }
        if looks_like_ldap(chunk.payload) {
            emit_recognition(chunk, out, "ldap", "ldap_message", "LDAP traffic");
        }
    }
}

/// LDAP messages are ASN.1 BER SEQUENCEs starting with 0x30, followed by
/// a length encoding. Reject obviously-too-short payloads.
fn looks_like_ldap(p: &[u8]) -> bool {
    if p.len() < 2 {
        return false;
    }
    if p[0] != 0x30 {
        return false;
    }
    matches!(p[1], 0x00..=0x7F | 0x81..=0x84)
}

// CC-Link IE Field — UDP 61450, often multicast (239.192.0.0/16).
pub(crate) struct CcLinkRecognizer;

impl SessionDecoder for CcLinkRecognizer {
    fn name(&self) -> &'static str {
        "cclink"
    }

    fn interest(&self) -> &'static [DecoderInterest] {
        &[DecoderInterest::UdpPort(61450)]
    }

    fn on_datagram(&mut self, chunk: &StreamChunk<'_>, out: &mut Vec<BronzeEvent>) {
        emit_recognition(chunk, out, "cclink", "cclink_ie_traffic", "CC-Link IE Field traffic");
    }
}

// CODESYS — TCP 1217 (V3 Gateway), 1740 (V2), 2455 (V3 alt), 11740 (V3 Runtime).
pub(crate) struct CodesysRecognizer;

impl SessionDecoder for CodesysRecognizer {
    fn name(&self) -> &'static str {
        "codesys"
    }

    fn interest(&self) -> &'static [DecoderInterest] {
        &[
            DecoderInterest::TcpPort(1217),
            DecoderInterest::TcpPort(1740),
            DecoderInterest::TcpPort(2455),
            DecoderInterest::TcpPort(11740),
        ]
    }

    fn on_stream_chunk(&mut self, chunk: &StreamChunk<'_>, out: &mut Vec<BronzeEvent>) {
        let summary = match chunk.context.dst_port.max(chunk.context.src_port) {
            1217 => "CODESYS V3 Gateway traffic",
            1740 => "CODESYS V2 traffic",
            2455 => "CODESYS V3 (alternate) traffic",
            11740 => "CODESYS V3 Runtime traffic",
            _ => "CODESYS traffic",
        };
        emit_recognition(chunk, out, "codesys", "codesys_traffic", summary);
    }
}

// IO-Link Wireless — UDP 59152.
pub(crate) struct IoLinkRecognizer;

impl SessionDecoder for IoLinkRecognizer {
    fn name(&self) -> &'static str {
        "iolink"
    }

    fn interest(&self) -> &'static [DecoderInterest] {
        &[DecoderInterest::UdpPort(59152)]
    }

    fn on_datagram(&mut self, chunk: &StreamChunk<'_>, out: &mut Vec<BronzeEvent>) {
        emit_recognition(chunk, out, "iolink", "iolink_traffic", "IO-Link Wireless traffic");
    }
}

// IGMP — IP protocol 2. Light parse to extract type byte for Membership Query
// vs Report distinction; full v3 group records left for future work.
pub(crate) struct IgmpRecognizer;

impl SessionDecoder for IgmpRecognizer {
    fn name(&self) -> &'static str {
        "igmp"
    }

    fn interest(&self) -> &'static [DecoderInterest] {
        &[DecoderInterest::IpProto(2)]
    }

    fn on_datagram(&mut self, chunk: &StreamChunk<'_>, out: &mut Vec<BronzeEvent>) {
        if chunk.payload.is_empty() {
            return;
        }
        let igmp_type = chunk.payload[0];
        let (operation, summary) = match igmp_type {
            0x11 => ("igmp_membership_query", "IGMP Membership Query"),
            0x12 => ("igmp_v1_membership_report", "IGMPv1 Membership Report"),
            0x16 => ("igmp_v2_membership_report", "IGMPv2 Membership Report"),
            0x17 => ("igmp_leave_group", "IGMPv2 Leave Group"),
            0x22 => ("igmp_v3_membership_report", "IGMPv3 Membership Report"),
            _ => ("igmp_message", "IGMP traffic"),
        };
        emit_recognition(chunk, out, "igmp", operation, summary);
    }
}

// ── Inventory registration ──────────────────────────────────────
inventory::submit!(crate::engine::decoders::DecoderRegistration {
    name: "smb",
    factory: || Box::new(SmbRecognizer),
});
inventory::submit!(crate::engine::decoders::DecoderRegistration {
    name: "kerberos",
    factory: || Box::new(KerberosRecognizer),
});
inventory::submit!(crate::engine::decoders::DecoderRegistration {
    name: "ldap",
    factory: || Box::new(LdapRecognizer),
});
inventory::submit!(crate::engine::decoders::DecoderRegistration {
    name: "cclink",
    factory: || Box::new(CcLinkRecognizer),
});
inventory::submit!(crate::engine::decoders::DecoderRegistration {
    name: "codesys",
    factory: || Box::new(CodesysRecognizer),
});
inventory::submit!(crate::engine::decoders::DecoderRegistration {
    name: "iolink",
    factory: || Box::new(IoLinkRecognizer),
});
inventory::submit!(crate::engine::decoders::DecoderRegistration {
    name: "igmp",
    factory: || Box::new(IgmpRecognizer),
});
