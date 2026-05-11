//! Kerberos (RFC 4120) full ASN.1 parser — AS/TGS/AP request-response cycles
//! and KRB-ERROR.
//!
//! Wire framing:
//!   TCP (ports 88, 464): 4-byte big-endian length prefix, then ASN.1 DER.
//!   UDP (ports 88, 464): ASN.1 DER starts at byte 0.
//!
//! BER tag map used here (application-class, primitive=0):
//!   0x6A  AS-REQ      [APPLICATION 10]
//!   0x6B  AS-REP      [APPLICATION 11]
//!   0x6C  TGS-REQ     [APPLICATION 12]
//!   0x6D  TGS-REP     [APPLICATION 13]
//!   0x6E  AP-REQ      [APPLICATION 14]
//!   0x6F  AP-REP      [APPLICATION 15]
//!   0x7E  KRB-ERROR   [APPLICATION 30]
//!
//! Context-specific (constructed) tags inside KDC-REQ-BODY and friends use the
//! encoding [0] .. [N] which maps to 0xA0 .. 0xAn on the wire.
//!
//! Only cleartext fields are extracted. Encrypted payloads (EncTicketPart,
//! EncKDCRepPart, EncAPRepPart, EncAuthenticator) are noted by etype but not
//! decrypted.

use std::collections::BTreeMap;

use crate::bronze::{
    AssetObservation, BronzeEvent, BronzeEventFamily, ProtocolTransaction, TransportProtocol,
};
use crate::engine::{
    build_envelope, new_event, parse_anomaly_event, DecoderInterest, SessionDecoder, StreamChunk,
};

// ── Constants ─────────────────────────────────────────────────────────────────

// Application-class BER tags (constructed bit set → 0x60 | tag).
const TAG_AS_REQ: u8 = 0x6A;
const TAG_AS_REP: u8 = 0x6B;
const TAG_TGS_REQ: u8 = 0x6C;
const TAG_TGS_REP: u8 = 0x6D;
const TAG_AP_REQ: u8 = 0x6E;
const TAG_AP_REP: u8 = 0x6F;
const TAG_KRB_ERROR: u8 = 0x7E;

// Universal BER tags.
const TAG_SEQUENCE: u8 = 0x30;
const TAG_INTEGER: u8 = 0x02;
const TAG_OCTET_STRING: u8 = 0x04;
const TAG_GENERAL_STRING: u8 = 0x1B;
const TAG_GENERALIZED_TIME: u8 = 0x18;
const TAG_BIT_STRING: u8 = 0x03;

// Context-specific constructed tags [0]..[30] → 0xA0..0xBE.
const CTX: u8 = 0xA0;

// ── BER / DER primitives ───────────────────────────────────────────────────────

/// Read a BER/DER length value starting at `buf[0]`.
/// Returns `(length, bytes_consumed)` or `None` on truncation.
fn ber_length(buf: &[u8]) -> Option<(usize, usize)> {
    if buf.is_empty() {
        return None;
    }
    let first = buf[0];
    if first & 0x80 == 0 {
        // Short form.
        return Some((first as usize, 1));
    }
    let n_bytes = (first & 0x7F) as usize;
    if n_bytes == 0 || n_bytes > 4 || buf.len() < 1 + n_bytes {
        return None;
    }
    let mut len: usize = 0;
    for &b in &buf[1..=n_bytes] {
        len = len.checked_shl(8)?.checked_add(b as usize)?;
    }
    Some((len, 1 + n_bytes))
}

/// Read a TLV header: `(tag, content_slice, bytes_consumed_total)`.
/// Returns `None` if truncated.
fn ber_tlv<'a>(buf: &'a [u8]) -> Option<(u8, &'a [u8], usize)> {
    if buf.is_empty() {
        return None;
    }
    let tag = buf[0];
    let (len, llen) = ber_length(&buf[1..])?;
    let hdr = 1 + llen;
    if buf.len() < hdr + len {
        return None;
    }
    Some((tag, &buf[hdr..hdr + len], hdr + len))
}

/// Decode a BER INTEGER (up to 8 bytes) to i64.
fn ber_integer(content: &[u8]) -> Option<i64> {
    if content.is_empty() || content.len() > 8 {
        return None;
    }
    let sign_extend: i64 = if content[0] & 0x80 != 0 { -1i64 } else { 0i64 };
    let mut v: i64 = sign_extend;
    for &b in content {
        v = (v << 8) | (b as i64);
    }
    Some(v)
}

/// Decode a GeneralString / GeneralizedTime / UTF8String / IA5String as lossy UTF-8.
fn ber_string(content: &[u8]) -> String {
    String::from_utf8_lossy(content).into_owned()
}

/// Iterate over the immediate children of a SEQUENCE (or any constructed TLV
/// whose content slice is passed directly).
struct TlvIter<'a> {
    buf: &'a [u8],
}

impl<'a> TlvIter<'a> {
    fn new(buf: &'a [u8]) -> Self {
        TlvIter { buf }
    }
}

impl<'a> Iterator for TlvIter<'a> {
    type Item = (u8, &'a [u8]);
    fn next(&mut self) -> Option<Self::Item> {
        loop {
            if self.buf.is_empty() {
                return None;
            }
            let (tag, content, total) = ber_tlv(self.buf)?;
            self.buf = &self.buf[total..];
            return Some((tag, content));
        }
    }
}

/// Find the first child element with the given tag.
fn find_child(buf: &[u8], tag: u8) -> Option<&[u8]> {
    TlvIter::new(buf).find_map(|(t, c)| if t == tag { Some(c) } else { None })
}

/// Read a context-specific wrapper [n] (tag = CTX | n) and return its inner
/// content.
fn ctx_inner(buf: &[u8], n: u8) -> Option<&[u8]> {
    find_child(buf, CTX | n)
}

// ── Kerberos-specific helpers ──────────────────────────────────────────────────

/// Parse a PrincipalName ASN.1 structure:
///   PrincipalName ::= SEQUENCE {
///     name-type  [0] Int32,
///     name-string[1] SEQUENCE OF KerberosString
///   }
/// Returns a slash-joined string of the name components, e.g. "host/server.ad.corp".
fn parse_principal_name(content: &[u8]) -> Option<String> {
    let seq = find_child(content, TAG_SEQUENCE)?;
    let name_string_ctx = ctx_inner(seq, 1)?;
    let name_seq = find_child(name_string_ctx, TAG_SEQUENCE)?;
    let parts: Vec<String> = TlvIter::new(name_seq)
        .filter_map(|(t, c)| {
            if t == TAG_GENERAL_STRING {
                Some(ber_string(c))
            } else {
                None
            }
        })
        .collect();
    if parts.is_empty() {
        None
    } else {
        Some(parts.join("/"))
    }
}

/// Parse a Realm (KerberosString = GeneralString).
fn parse_realm(content: &[u8]) -> Option<String> {
    let s = find_child(content, TAG_GENERAL_STRING)?;
    Some(ber_string(s))
}

/// Parse an ETYPE-INFO2 or etype SEQUENCE OF Int32 into a comma-separated list.
fn parse_etype_list(content: &[u8]) -> Option<String> {
    let seq = find_child(content, TAG_SEQUENCE)?;
    let etypes: Vec<String> = TlvIter::new(seq)
        .filter_map(|(t, c)| {
            if t == TAG_INTEGER {
                ber_integer(c).map(|v| v.to_string())
            } else {
                None
            }
        })
        .collect();
    if etypes.is_empty() {
        None
    } else {
        Some(etypes.join(","))
    }
}

/// Parse a KerberosTime (GeneralizedTime) from a context wrapper.
fn parse_kerberos_time(content: &[u8]) -> Option<String> {
    let s = find_child(content, TAG_GENERALIZED_TIME)?;
    Some(ber_string(s))
}

/// Parse a 32-bit KDC-options BitString (first byte is unused-bits count).
fn parse_options(content: &[u8]) -> Option<u32> {
    let bs = find_child(content, TAG_BIT_STRING)?;
    if bs.len() < 2 {
        return None;
    }
    // Byte 0 = unused bits count; bytes 1..5 are the flag bytes (BE).
    let flag_bytes = &bs[1..];
    let mut val: u32 = 0;
    for (i, &b) in flag_bytes.iter().enumerate().take(4) {
        val |= (b as u32) << (24 - i * 8);
    }
    Some(val)
}

// ── Per-message parsed view ────────────────────────────────────────────────────

#[derive(Debug, Default)]
struct KrbMsg {
    /// pvno (should be 5).
    pvno: Option<i64>,
    /// msg-type integer.
    msg_type: Option<i64>,
    /// Client principal name (cname), if present.
    cname: Option<String>,
    /// Client or ticket realm.
    realm: Option<String>,
    /// Server principal name (sname).
    sname: Option<String>,
    /// Ticket realm (from inner ticket, AS-REP / TGS-REP / AP-REQ).
    ticket_realm: Option<String>,
    /// Ticket sname (from inner ticket).
    ticket_sname: Option<String>,
    /// KDC-options or AP-options bitmask.
    options: Option<u32>,
    /// Requested etypes list (KDC-REQ).
    etypes: Option<String>,
    /// Nonce.
    nonce: Option<i64>,
    /// from timestamp.
    from: Option<String>,
    /// till timestamp.
    till: Option<String>,
    /// rtime timestamp.
    rtime: Option<String>,
    /// Encrypted-part etype (REP messages only — etype is in clear header).
    enc_etype: Option<i64>,
    /// KRB-ERROR error-code.
    error_code: Option<i64>,
    /// KRB-ERROR e-text.
    e_text: Option<String>,
    /// Server realm (KRB-ERROR).
    svc_realm: Option<String>,
}

// ── Message-specific parsers ───────────────────────────────────────────────────

/// Parse a KDC-REQ (AS-REQ or TGS-REQ) body.
///
/// KDC-REQ ::= SEQUENCE {
///   pvno      [1] INTEGER (5),
///   msg-type  [2] INTEGER (AS-REQ=10 | TGS-REQ=12),
///   padata    [3] SEQUENCE OF PA-DATA OPTIONAL,
///   req-body  [4] KDC-REQ-BODY
/// }
fn parse_kdc_req(content: &[u8]) -> KrbMsg {
    let mut m = KrbMsg::default();
    let seq = match find_child(content, TAG_SEQUENCE) {
        Some(s) => s,
        None => return m,
    };

    if let Some(c) = ctx_inner(seq, 1) {
        m.pvno = find_child(c, TAG_INTEGER).and_then(ber_integer);
    }
    if let Some(c) = ctx_inner(seq, 2) {
        m.msg_type = find_child(c, TAG_INTEGER).and_then(ber_integer);
    }

    // req-body is [4].
    if let Some(body_ctx) = ctx_inner(seq, 4) {
        let body = match find_child(body_ctx, TAG_SEQUENCE) {
            Some(s) => s,
            None => return m,
        };
        // [0] kdc-options BitString
        if let Some(c) = ctx_inner(body, 0) {
            m.options = parse_options(c);
        }
        // [1] cname PrincipalName
        if let Some(c) = ctx_inner(body, 1) {
            m.cname = parse_principal_name(c);
        }
        // [2] realm KerberosString
        if let Some(c) = ctx_inner(body, 2) {
            m.realm = parse_realm(c);
        }
        // [3] sname PrincipalName
        if let Some(c) = ctx_inner(body, 3) {
            m.sname = parse_principal_name(c);
        }
        // [4] from KerberosTime OPTIONAL
        if let Some(c) = ctx_inner(body, 4) {
            m.from = parse_kerberos_time(c);
        }
        // [5] till KerberosTime
        if let Some(c) = ctx_inner(body, 5) {
            m.till = parse_kerberos_time(c);
        }
        // [6] rtime KerberosTime OPTIONAL
        if let Some(c) = ctx_inner(body, 6) {
            m.rtime = parse_kerberos_time(c);
        }
        // [7] nonce UInt32
        if let Some(c) = ctx_inner(body, 7) {
            m.nonce = find_child(c, TAG_INTEGER).and_then(ber_integer);
        }
        // [8] etype SEQUENCE OF Int32
        if let Some(c) = ctx_inner(body, 8) {
            m.etypes = parse_etype_list(c);
        }
    }
    m
}

/// Parse a KDC-REP (AS-REP or TGS-REP) body.
///
/// KDC-REP ::= SEQUENCE {
///   pvno    [0] INTEGER (5),
///   msg-type[1] INTEGER,
///   padata  [2] SEQUENCE OF PA-DATA OPTIONAL,
///   crealm  [3] Realm,
///   cname   [4] PrincipalName,
///   ticket  [5] Ticket,
///   enc-part[6] EncryptedData
/// }
fn parse_kdc_rep(content: &[u8]) -> KrbMsg {
    let mut m = KrbMsg::default();
    let seq = match find_child(content, TAG_SEQUENCE) {
        Some(s) => s,
        None => return m,
    };

    if let Some(c) = ctx_inner(seq, 0) {
        m.pvno = find_child(c, TAG_INTEGER).and_then(ber_integer);
    }
    if let Some(c) = ctx_inner(seq, 1) {
        m.msg_type = find_child(c, TAG_INTEGER).and_then(ber_integer);
    }
    // [3] crealm
    if let Some(c) = ctx_inner(seq, 3) {
        m.realm = parse_realm(c);
    }
    // [4] cname
    if let Some(c) = ctx_inner(seq, 4) {
        m.cname = parse_principal_name(c);
    }
    // [5] ticket → inner Ticket SEQUENCE
    if let Some(ticket_ctx) = ctx_inner(seq, 5) {
        parse_ticket_fields(ticket_ctx, &mut m);
    }
    // [6] enc-part EncryptedData — only grab etype (etype [0] INTEGER).
    if let Some(enc_ctx) = ctx_inner(seq, 6) {
        if let Some(enc_seq) = find_child(enc_ctx, TAG_SEQUENCE) {
            if let Some(et_ctx) = ctx_inner(enc_seq, 0) {
                m.enc_etype = find_child(et_ctx, TAG_INTEGER).and_then(ber_integer);
            }
        }
    }
    m
}

/// Parse AP-REQ.
///
/// AP-REQ ::= [APPLICATION 14] SEQUENCE {
///   pvno     [0] INTEGER (5),
///   msg-type [1] INTEGER (14),
///   ap-options[2] APOptions (BitString),
///   ticket   [3] Ticket,
///   authenticator[4] EncryptedData
/// }
fn parse_ap_req(content: &[u8]) -> KrbMsg {
    let mut m = KrbMsg::default();
    let seq = match find_child(content, TAG_SEQUENCE) {
        Some(s) => s,
        None => return m,
    };

    if let Some(c) = ctx_inner(seq, 0) {
        m.pvno = find_child(c, TAG_INTEGER).and_then(ber_integer);
    }
    if let Some(c) = ctx_inner(seq, 1) {
        m.msg_type = find_child(c, TAG_INTEGER).and_then(ber_integer);
    }
    // [2] ap-options
    if let Some(c) = ctx_inner(seq, 2) {
        m.options = parse_options(c);
    }
    // [3] ticket
    if let Some(ticket_ctx) = ctx_inner(seq, 3) {
        parse_ticket_fields(ticket_ctx, &mut m);
    }
    m
}

/// Parse AP-REP (minimal — only pvno/msg-type; enc-part is opaque).
fn parse_ap_rep(content: &[u8]) -> KrbMsg {
    let mut m = KrbMsg::default();
    let seq = match find_child(content, TAG_SEQUENCE) {
        Some(s) => s,
        None => return m,
    };
    if let Some(c) = ctx_inner(seq, 0) {
        m.pvno = find_child(c, TAG_INTEGER).and_then(ber_integer);
    }
    if let Some(c) = ctx_inner(seq, 1) {
        m.msg_type = find_child(c, TAG_INTEGER).and_then(ber_integer);
    }
    m
}

/// Parse KRB-ERROR.
///
/// KRB-ERROR ::= [APPLICATION 30] SEQUENCE {
///   pvno         [0] INTEGER (5),
///   msg-type     [1] INTEGER (30),
///   ctime        [2] KerberosTime OPTIONAL,
///   cusec        [3] Microseconds OPTIONAL,
///   stime        [4] KerberosTime,
///   susec        [5] Microseconds,
///   error-code   [6] Int32,
///   crealm       [7] Realm OPTIONAL,
///   cname        [8] PrincipalName OPTIONAL,
///   realm        [9] Realm,
///   sname        [10] PrincipalName,
///   e-text       [11] KerberosString OPTIONAL,
///   e-data       [12] OCTET STRING OPTIONAL
/// }
fn parse_krb_error(content: &[u8]) -> KrbMsg {
    let mut m = KrbMsg::default();
    let seq = match find_child(content, TAG_SEQUENCE) {
        Some(s) => s,
        None => return m,
    };

    if let Some(c) = ctx_inner(seq, 0) {
        m.pvno = find_child(c, TAG_INTEGER).and_then(ber_integer);
    }
    if let Some(c) = ctx_inner(seq, 1) {
        m.msg_type = find_child(c, TAG_INTEGER).and_then(ber_integer);
    }
    // [6] error-code
    if let Some(c) = ctx_inner(seq, 6) {
        m.error_code = find_child(c, TAG_INTEGER).and_then(ber_integer);
    }
    // [7] crealm
    if let Some(c) = ctx_inner(seq, 7) {
        m.realm = parse_realm(c);
    }
    // [8] cname
    if let Some(c) = ctx_inner(seq, 8) {
        m.cname = parse_principal_name(c);
    }
    // [9] realm (server realm)
    if let Some(c) = ctx_inner(seq, 9) {
        m.svc_realm = parse_realm(c);
    }
    // [10] sname
    if let Some(c) = ctx_inner(seq, 10) {
        m.sname = parse_principal_name(c);
    }
    // [11] e-text
    if let Some(c) = ctx_inner(seq, 11) {
        m.e_text = find_child(c, TAG_GENERAL_STRING).map(ber_string);
    }
    m
}

/// Extract realm and sname from a Ticket embedded in a KDC-REP or AP-REQ.
///
/// Ticket ::= [APPLICATION 1] SEQUENCE {
///   tkt-vno [0] INTEGER (5),
///   realm   [1] Realm,
///   sname   [2] PrincipalName,
///   enc-part[3] EncryptedData
/// }
fn parse_ticket_fields(ticket_ctx: &[u8], m: &mut KrbMsg) {
    // The Ticket is wrapped in APPLICATION 1 (0x61) inside the context tag.
    let ticket_app = match find_child(ticket_ctx, 0x61) {
        Some(t) => t,
        None => return,
    };
    let ticket_seq = match find_child(ticket_app, TAG_SEQUENCE) {
        Some(s) => s,
        None => return,
    };
    if let Some(c) = ctx_inner(ticket_seq, 1) {
        m.ticket_realm = parse_realm(c);
    }
    if let Some(c) = ctx_inner(ticket_seq, 2) {
        m.ticket_sname = parse_principal_name(c);
    }
}

// ── Framing helpers ────────────────────────────────────────────────────────────

/// Strip the 4-byte TCP length prefix and return the ASN.1 payload, or the
/// buffer unchanged if already starts with a Kerberos application tag.
fn tcp_payload(buf: &[u8]) -> Option<&[u8]> {
    if buf.len() < 4 {
        return None;
    }
    if is_krb_tag(buf[0]) {
        return Some(buf);
    }
    let msg_len = u32::from_be_bytes(buf[0..4].try_into().ok()?) as usize;
    if buf.len() < 4 + msg_len {
        return None;
    }
    Some(&buf[4..4 + msg_len])
}

#[inline]
fn is_krb_tag(b: u8) -> bool {
    matches!(b, TAG_AS_REQ | TAG_AS_REP | TAG_TGS_REQ | TAG_TGS_REP | TAG_AP_REQ | TAG_AP_REP | TAG_KRB_ERROR)
}

// ── Decoder ───────────────────────────────────────────────────────────────────

#[derive(Default)]
pub(crate) struct KerberosDecoder {
    asset_emitted: bool,
}

inventory::submit!(crate::engine::decoders::DecoderRegistration {
    name: "kerberos",
    factory: || Box::new(KerberosDecoder::default()),
});

impl SessionDecoder for KerberosDecoder {
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
        let asn1 = match tcp_payload(chunk.payload) {
            Some(p) => p,
            None => {
                if !chunk.payload.is_empty() {
                    out.push(parse_anomaly_event(
                        chunk.capture_id.to_string(),
                        build_envelope(
                            &chunk.context,
                            chunk.interface_id,
                            chunk.frame_index,
                            chunk.timestamp,
                            chunk.segment_hash,
                            TransportProtocol::Tcp,
                            Some("kerberos"),
                            chunk.captured_len,
                            chunk.session_key.clone(),
                        ),
                        self.name(),
                        "low",
                        "truncated kerberos tcp framing (4-byte length prefix)",
                        chunk.payload,
                    ));
                }
                return;
            }
        };
        self.decode_asn1(chunk, asn1, TransportProtocol::Tcp, out);
    }

    fn on_datagram(&mut self, chunk: &StreamChunk<'_>, out: &mut Vec<BronzeEvent>) {
        self.decode_asn1(chunk, chunk.payload, TransportProtocol::Udp, out);
    }
}

impl KerberosDecoder {
    fn decode_asn1(
        &mut self,
        chunk: &StreamChunk<'_>,
        asn1: &[u8],
        transport: TransportProtocol,
        out: &mut Vec<BronzeEvent>,
    ) {
        if asn1.len() < 2 {
            out.push(parse_anomaly_event(
                chunk.capture_id.to_string(),
                build_envelope(
                    &chunk.context,
                    chunk.interface_id,
                    chunk.frame_index,
                    chunk.timestamp,
                    chunk.segment_hash,
                    transport,
                    Some("kerberos"),
                    chunk.captured_len,
                    chunk.session_key.clone(),
                ),
                self.name(),
                "low",
                "kerberos payload too short",
                asn1,
            ));
            return;
        }

        let app_tag = asn1[0];
        if !is_krb_tag(app_tag) {
            out.push(parse_anomaly_event(
                chunk.capture_id.to_string(),
                build_envelope(
                    &chunk.context,
                    chunk.interface_id,
                    chunk.frame_index,
                    chunk.timestamp,
                    chunk.segment_hash,
                    transport,
                    Some("kerberos"),
                    chunk.captured_len,
                    chunk.session_key.clone(),
                ),
                self.name(),
                "low",
                &format!("unknown kerberos application tag 0x{app_tag:02x}"),
                asn1,
            ));
            return;
        }

        // Unwrap the outer APPLICATION tag to get the SEQUENCE content.
        let (_, content, _) = match ber_tlv(asn1) {
            Some(v) => v,
            None => {
                out.push(parse_anomaly_event(
                    chunk.capture_id.to_string(),
                    build_envelope(
                        &chunk.context,
                        chunk.interface_id,
                        chunk.frame_index,
                        chunk.timestamp,
                        chunk.segment_hash,
                        transport,
                        Some("kerberos"),
                        chunk.captured_len,
                        chunk.session_key.clone(),
                    ),
                    self.name(),
                    "low",
                    "truncated kerberos asn.1 application tag",
                    asn1,
                ));
                return;
            }
        };

        let msg = match app_tag {
            TAG_AS_REQ | TAG_TGS_REQ => parse_kdc_req(content),
            TAG_AS_REP | TAG_TGS_REP => parse_kdc_rep(content),
            TAG_AP_REQ => parse_ap_req(content),
            TAG_AP_REP => parse_ap_rep(content),
            TAG_KRB_ERROR => parse_krb_error(content),
            _ => unreachable!(),
        };

        let operation = msg_operation(app_tag);
        let is_error = app_tag == TAG_KRB_ERROR;

        let status = if is_error {
            "error".to_string()
        } else {
            match app_tag {
                TAG_AS_REQ | TAG_TGS_REQ | TAG_AP_REQ => "request_only".to_string(),
                TAG_AS_REP | TAG_TGS_REP | TAG_AP_REP => "response_only".to_string(),
                _ => "ok".to_string(),
            }
        };

        let envelope = build_envelope(
            &chunk.context,
            chunk.interface_id,
            chunk.frame_index,
            chunk.timestamp,
            chunk.segment_hash,
            transport,
            Some("kerberos"),
            chunk.captured_len,
            chunk.session_key.clone(),
        );

        // Build attributes.
        let mut attributes: BTreeMap<String, String> = BTreeMap::new();
        attributes.insert("msg_tag".to_string(), format!("0x{app_tag:02x}"));
        if let Some(v) = msg.pvno {
            attributes.insert("pvno".to_string(), v.to_string());
        }
        if let Some(v) = msg.msg_type {
            attributes.insert("msg_type".to_string(), v.to_string());
        }
        if let Some(ref v) = msg.cname {
            attributes.insert("cname".to_string(), v.clone());
        }
        if let Some(ref v) = msg.realm {
            attributes.insert("realm".to_string(), v.clone());
        }
        if let Some(ref v) = msg.sname {
            attributes.insert("sname".to_string(), v.clone());
        }
        if let Some(ref v) = msg.ticket_realm {
            attributes.insert("ticket_realm".to_string(), v.clone());
        }
        if let Some(ref v) = msg.ticket_sname {
            attributes.insert("ticket_sname".to_string(), v.clone());
        }
        if let Some(v) = msg.options {
            attributes.insert("options".to_string(), format!("0x{v:08x}"));
        }
        if let Some(ref v) = msg.etypes {
            attributes.insert("etypes".to_string(), v.clone());
        }
        if let Some(v) = msg.nonce {
            attributes.insert("nonce".to_string(), format!("0x{v:08x}"));
        }
        if let Some(ref v) = msg.from {
            attributes.insert("from".to_string(), v.clone());
        }
        if let Some(ref v) = msg.till {
            attributes.insert("till".to_string(), v.clone());
        }
        if let Some(ref v) = msg.rtime {
            attributes.insert("rtime".to_string(), v.clone());
        }
        if let Some(v) = msg.enc_etype {
            attributes.insert("enc_etype".to_string(), v.to_string());
        }
        if let Some(v) = msg.error_code {
            attributes.insert("error_code".to_string(), v.to_string());
        }
        if let Some(ref v) = msg.e_text {
            attributes.insert("e_text".to_string(), v.clone());
        }
        if let Some(ref v) = msg.svc_realm {
            attributes.insert("svc_realm".to_string(), v.clone());
        }

        // Build summary strings.
        let request_summary = build_summary(&msg, app_tag);

        out.push(new_event(
            chunk.capture_id.to_string(),
            envelope.clone(),
            BronzeEventFamily::ProtocolTransaction(ProtocolTransaction {
                operation: operation.to_string(),
                status,
                request_summary,
                response_summary: None,
                object_refs: [msg.cname.as_deref(), msg.realm.as_deref()]
                    .iter()
                    .flatten()
                    .map(|s| s.to_string())
                    .collect(),
                values: vec![],
                attributes,
                modbus: None,
                protocol_fields: None,
            }),
        ));

        // KRB-ERROR → additional ParseAnomaly at medium severity.
        if is_error {
            let reason = format!(
                "kerberos error: code={} realm={} sname={}",
                msg.error_code
                    .map_or_else(|| "?".to_string(), |c| c.to_string()),
                msg.svc_realm.as_deref().unwrap_or("?"),
                msg.sname.as_deref().unwrap_or("?"),
            );
            out.push(parse_anomaly_event(
                chunk.capture_id.to_string(),
                envelope.clone(),
                self.name(),
                "medium",
                &reason,
                asn1,
            ));
        }

        // AssetObservation: KDC server from AS-REQ (first time).
        if matches!(app_tag, TAG_AS_REQ | TAG_TGS_REQ) && !self.asset_emitted {
            self.asset_emitted = true;
            let kdc_ip = chunk.context.dst_ip.to_string();
            let mut identifiers: BTreeMap<String, String> = BTreeMap::new();
            if let Some(ref r) = msg.realm {
                identifiers.insert("realm".to_string(), r.clone());
            }
            out.push(new_event(
                chunk.capture_id.to_string(),
                envelope.clone(),
                BronzeEventFamily::AssetObservation(AssetObservation {
                    asset_key: kdc_ip,
                    role: Some("kdc_server".to_string()),
                    vendor: None,
                    model: None,
                    firmware: None,
                    hostnames: vec![],
                    protocols: vec!["kerberos".to_string()],
                    identifiers,
                }),
            ));

            // Authenticating client asset.
            let client_ip = chunk.context.src_ip.to_string();
            let mut client_ids: BTreeMap<String, String> = BTreeMap::new();
            if let Some(ref c) = msg.cname {
                client_ids.insert("cname".to_string(), c.clone());
            }
            if let Some(ref r) = msg.realm {
                client_ids.insert("realm".to_string(), r.clone());
            }
            out.push(new_event(
                chunk.capture_id.to_string(),
                envelope,
                BronzeEventFamily::AssetObservation(AssetObservation {
                    asset_key: client_ip,
                    role: Some("kerberos_client".to_string()),
                    vendor: None,
                    model: None,
                    firmware: None,
                    hostnames: vec![],
                    protocols: vec!["kerberos".to_string()],
                    identifiers: client_ids,
                }),
            ));
        }
    }
}

fn msg_operation(tag: u8) -> &'static str {
    match tag {
        TAG_AS_REQ => "kerberos_as_req",
        TAG_AS_REP => "kerberos_as_rep",
        TAG_TGS_REQ => "kerberos_tgs_req",
        TAG_TGS_REP => "kerberos_tgs_rep",
        TAG_AP_REQ => "kerberos_ap_req",
        TAG_AP_REP => "kerberos_ap_rep",
        TAG_KRB_ERROR => "kerberos_error",
        _ => "kerberos_unknown",
    }
}

fn build_summary(m: &KrbMsg, tag: u8) -> Option<String> {
    match tag {
        TAG_AS_REQ | TAG_TGS_REQ => {
            let client = m.cname.as_deref().unwrap_or("?");
            let realm = m.realm.as_deref().unwrap_or("?");
            let server = m.sname.as_deref().unwrap_or("?");
            Some(format!("{client}@{realm} → {server}"))
        }
        TAG_AS_REP | TAG_TGS_REP => {
            let client = m.cname.as_deref().unwrap_or("?");
            let realm = m.realm.as_deref().unwrap_or("?");
            let ts = m.ticket_sname.as_deref().unwrap_or("?");
            let enc = m
                .enc_etype
                .map_or_else(|| "?".to_string(), |e| e.to_string());
            Some(format!("{client}@{realm} ticket={ts} enc={enc}"))
        }
        TAG_AP_REQ => {
            let ts = m.ticket_sname.as_deref().unwrap_or("?");
            let tr = m.ticket_realm.as_deref().unwrap_or("?");
            Some(format!("ticket={ts}@{tr}"))
        }
        TAG_KRB_ERROR => {
            let code = m
                .error_code
                .map_or_else(|| "?".to_string(), |c| c.to_string());
            let realm = m.svc_realm.as_deref().unwrap_or("?");
            let sname = m.sname.as_deref().unwrap_or("?");
            Some(format!("error={code} {sname}@{realm}"))
        }
        _ => None,
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};

    use chrono::{TimeZone, Utc};

    use super::*;
    use crate::bronze::BronzeEventFamily;
    use crate::engine::StreamChunk;
    use crate::registry::PacketContext;

    fn ctx(sp: u16, dp: u16) -> PacketContext {
        PacketContext {
            src_mac: [0u8; 6],
            dst_mac: [0u8; 6],
            src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            dst_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            src_port: sp,
            dst_port: dp,
            vlan_id: None,
            timestamp: 1_700_000_000_000_000,
        }
    }

    fn chunk_tcp<'a>(payload: &'a [u8], sp: u16, dp: u16) -> StreamChunk<'a> {
        StreamChunk {
            capture_id: "test",
            segment_hash: "seg",
            interface_id: 0,
            frame_index: 0,
            timestamp: Utc.timestamp_opt(1_700_000_000, 0).unwrap(),
            context: ctx(sp, dp),
            ethertype: 0x0800,
            ip_proto: Some(6),
            llc: None,
            transport: TransportProtocol::Tcp,
            payload,
            session_key: "sk".to_string(),
            captured_len: payload.len() as u64,
        }
    }

    fn chunk_udp<'a>(payload: &'a [u8], sp: u16, dp: u16) -> StreamChunk<'a> {
        StreamChunk {
            capture_id: "test",
            segment_hash: "seg",
            interface_id: 0,
            frame_index: 0,
            timestamp: Utc.timestamp_opt(1_700_000_000, 0).unwrap(),
            context: ctx(sp, dp),
            ethertype: 0x0800,
            ip_proto: Some(17),
            llc: None,
            transport: TransportProtocol::Udp,
            payload,
            session_key: "sk".to_string(),
            captured_len: payload.len() as u64,
        }
    }

    fn get_tx(evs: &[BronzeEvent]) -> Option<&ProtocolTransaction> {
        evs.iter().find_map(|e| {
            if let BronzeEventFamily::ProtocolTransaction(ref t) = e.family {
                Some(t)
            } else {
                None
            }
        })
    }

    fn get_anomaly(evs: &[BronzeEvent]) -> Option<&crate::bronze::ParseAnomaly> {
        evs.iter().find_map(|e| {
            if let BronzeEventFamily::ParseAnomaly(ref a) = e.family {
                Some(a)
            } else {
                None
            }
        })
    }

    fn get_assets(evs: &[BronzeEvent]) -> Vec<&AssetObservation> {
        evs.iter()
            .filter_map(|e| {
                if let BronzeEventFamily::AssetObservation(ref a) = e.family {
                    Some(a)
                } else {
                    None
                }
            })
            .collect()
    }

    // ── BER helpers ──────────────────────────────────────────────────────────

    /// Encode a BER/DER TLV.
    fn tlv(tag: u8, content: &[u8]) -> Vec<u8> {
        let mut out = vec![tag];
        let len = content.len();
        if len < 0x80 {
            out.push(len as u8);
        } else if len < 0x100 {
            out.push(0x81);
            out.push(len as u8);
        } else {
            out.push(0x82);
            out.push((len >> 8) as u8);
            out.push(len as u8);
        }
        out.extend_from_slice(content);
        out
    }

    fn seq(content: &[u8]) -> Vec<u8> {
        tlv(TAG_SEQUENCE, content)
    }

    fn integer(v: i64) -> Vec<u8> {
        // Minimal encoding for small non-negative values.
        if v >= 0 && v < 0x80 {
            tlv(TAG_INTEGER, &[v as u8])
        } else if v >= 0 && v < 0x8000 {
            tlv(TAG_INTEGER, &[(v >> 8) as u8, v as u8])
        } else {
            tlv(TAG_INTEGER, &v.to_be_bytes())
        }
    }

    fn ctx_wrap(n: u8, content: &[u8]) -> Vec<u8> {
        tlv(CTX | n, content)
    }

    fn general_string(s: &str) -> Vec<u8> {
        tlv(TAG_GENERAL_STRING, s.as_bytes())
    }

    fn generalized_time(s: &str) -> Vec<u8> {
        tlv(TAG_GENERALIZED_TIME, s.as_bytes())
    }

    fn bit_string(flags: u32) -> Vec<u8> {
        // 4 flag bytes + 1 unused-bits byte (=0).
        let bytes = flags.to_be_bytes();
        tlv(TAG_BIT_STRING, &[0x00, bytes[0], bytes[1], bytes[2], bytes[3]])
    }

    fn principal_name(name_type: i64, parts: &[&str]) -> Vec<u8> {
        let mut name_string_seq_content = Vec::new();
        for p in parts {
            name_string_seq_content.extend_from_slice(&general_string(p));
        }
        let inner = seq(&{
            let mut v = ctx_wrap(0, &integer(name_type));
            v.extend_from_slice(&ctx_wrap(1, &seq(&name_string_seq_content)));
            v
        });
        inner
    }

    // ── AS-REQ builder ───────────────────────────────────────────────────────

    /// Build a minimal but complete AS-REQ ASN.1 payload.
    fn as_req_payload(
        cname_parts: &[&str],
        realm: &str,
        sname_parts: &[&str],
        etypes: &[i64],
    ) -> Vec<u8> {
        let mut etype_content = Vec::new();
        for e in etypes {
            etype_content.extend_from_slice(&integer(*e));
        }

        let mut body_content = Vec::new();
        // [0] kdc-options
        body_content.extend_from_slice(&ctx_wrap(0, &bit_string(0x40810010)));
        // [1] cname
        body_content.extend_from_slice(&ctx_wrap(1, &principal_name(1, cname_parts)));
        // [2] realm
        body_content.extend_from_slice(&ctx_wrap(2, &general_string(realm)));
        // [3] sname
        body_content.extend_from_slice(&ctx_wrap(3, &principal_name(2, sname_parts)));
        // [5] till
        body_content.extend_from_slice(&ctx_wrap(5, &generalized_time("20370913024805Z")));
        // [7] nonce
        body_content.extend_from_slice(&ctx_wrap(7, &integer(0x12345678)));
        // [8] etype
        body_content.extend_from_slice(&ctx_wrap(8, &seq(&etype_content)));

        let body = seq(&body_content);

        let mut req_seq_content = Vec::new();
        req_seq_content.extend_from_slice(&ctx_wrap(1, &integer(5)));
        req_seq_content.extend_from_slice(&ctx_wrap(2, &integer(10)));
        req_seq_content.extend_from_slice(&ctx_wrap(4, &body));

        tlv(TAG_AS_REQ, &seq(&req_seq_content))
    }

    /// Build a minimal AS-REP payload.
    fn as_rep_payload(cname_parts: &[&str], realm: &str, enc_etype: i64) -> Vec<u8> {
        // Ticket APPLICATION 1.
        let ticket_sname = principal_name(2, &["krbtgt", realm]);
        let mut ticket_seq_content = Vec::new();
        ticket_seq_content.extend_from_slice(&ctx_wrap(0, &integer(5)));
        ticket_seq_content.extend_from_slice(&ctx_wrap(1, &general_string(realm)));
        ticket_seq_content.extend_from_slice(&ctx_wrap(2, &ticket_sname));
        // enc-part placeholder
        let fake_enc_part = seq(&{
            let mut v = ctx_wrap(0, &integer(enc_etype));
            v.extend_from_slice(&ctx_wrap(2, &tlv(TAG_OCTET_STRING, b"encryptedblob")));
            v
        });
        ticket_seq_content.extend_from_slice(&ctx_wrap(3, &fake_enc_part));
        let ticket = tlv(0x61, &seq(&ticket_seq_content));

        // EncryptedData for enc-part of the REP.
        let enc_part_seq = seq(&{
            let mut v = ctx_wrap(0, &integer(enc_etype));
            v.extend_from_slice(&ctx_wrap(2, &tlv(TAG_OCTET_STRING, b"repblob")));
            v
        });

        let mut rep_seq = Vec::new();
        rep_seq.extend_from_slice(&ctx_wrap(0, &integer(5)));
        rep_seq.extend_from_slice(&ctx_wrap(1, &integer(11)));
        rep_seq.extend_from_slice(&ctx_wrap(3, &general_string(realm)));
        rep_seq.extend_from_slice(&ctx_wrap(4, &principal_name(1, cname_parts)));
        rep_seq.extend_from_slice(&ctx_wrap(5, &ticket));
        rep_seq.extend_from_slice(&ctx_wrap(6, &enc_part_seq));

        tlv(TAG_AS_REP, &seq(&rep_seq))
    }

    /// Build a minimal KRB-ERROR payload.
    fn krb_error_payload(error_code: i64, realm: &str, sname_parts: &[&str]) -> Vec<u8> {
        let mut seq_content = Vec::new();
        seq_content.extend_from_slice(&ctx_wrap(0, &integer(5)));
        seq_content.extend_from_slice(&ctx_wrap(1, &integer(30)));
        // stime [4] and susec [5] are required.
        seq_content.extend_from_slice(&ctx_wrap(4, &generalized_time("20240101120000Z")));
        seq_content.extend_from_slice(&ctx_wrap(5, &integer(0)));
        seq_content.extend_from_slice(&ctx_wrap(6, &integer(error_code)));
        seq_content.extend_from_slice(&ctx_wrap(9, &general_string(realm)));
        seq_content.extend_from_slice(&ctx_wrap(10, &principal_name(2, sname_parts)));
        seq_content.extend_from_slice(&ctx_wrap(11, &general_string("Client not found in Kerberos database")));
        tlv(TAG_KRB_ERROR, &seq(&seq_content))
    }

    // ── Test: AS-REQ parse ────────────────────────────────────────────────────

    #[test]
    fn test_as_req_parse() {
        let payload = as_req_payload(&["alice"], "CORP.LOCAL", &["krbtgt", "CORP.LOCAL"], &[18, 17, 23]);
        let mut dec = KerberosDecoder::default();
        let mut evs = Vec::new();
        dec.on_datagram(&chunk_udp(&payload, 54321, 88), &mut evs);
        let tx = get_tx(&evs).unwrap();
        assert_eq!(tx.operation, "kerberos_as_req");
        assert_eq!(tx.status, "request_only");
        assert_eq!(tx.attributes.get("cname").map(String::as_str), Some("alice"));
        assert_eq!(tx.attributes.get("realm").map(String::as_str), Some("CORP.LOCAL"));
        assert_eq!(tx.attributes.get("etypes").map(String::as_str), Some("18,17,23"));
        assert_eq!(tx.attributes.get("nonce").map(String::as_str), Some("0x12345678"));
    }

    // ── Test: AS-REP parse ────────────────────────────────────────────────────

    #[test]
    fn test_as_rep_parse() {
        let payload = as_rep_payload(&["alice"], "CORP.LOCAL", 18);
        let mut dec = KerberosDecoder::default();
        let mut evs = Vec::new();
        dec.on_datagram(&chunk_udp(&payload, 88, 54321), &mut evs);
        let tx = get_tx(&evs).unwrap();
        assert_eq!(tx.operation, "kerberos_as_rep");
        assert_eq!(tx.status, "response_only");
        assert_eq!(tx.attributes.get("cname").map(String::as_str), Some("alice"));
        assert_eq!(tx.attributes.get("realm").map(String::as_str), Some("CORP.LOCAL"));
        assert_eq!(tx.attributes.get("enc_etype").map(String::as_str), Some("18"));
        // Ticket sname should be extracted.
        assert_eq!(
            tx.attributes.get("ticket_sname").map(String::as_str),
            Some("krbtgt/CORP.LOCAL")
        );
    }

    // ── Test: TGS-REQ parse ───────────────────────────────────────────────────

    #[test]
    fn test_tgs_req_parse() {
        // TGS-REQ shares the KDC-REQ structure; only tag changes.
        let inner = as_req_payload(&["alice"], "CORP.LOCAL", &["cifs", "fileserver.corp.local"], &[18]);
        // Patch the outer tag from AS-REQ (0x6A) to TGS-REQ (0x6C).
        let mut pkt = inner.clone();
        pkt[0] = TAG_TGS_REQ;
        let mut dec = KerberosDecoder::default();
        let mut evs = Vec::new();
        dec.on_datagram(&chunk_udp(&pkt, 54321, 88), &mut evs);
        let tx = get_tx(&evs).unwrap();
        assert_eq!(tx.operation, "kerberos_tgs_req");
        assert_eq!(tx.attributes.get("sname").map(String::as_str), Some("cifs/fileserver.corp.local"));
    }

    // ── Test: AP-REQ parse ────────────────────────────────────────────────────

    #[test]
    fn test_ap_req_parse() {
        // Build AP-REQ.
        let ticket_sname = principal_name(2, &["cifs", "fileserver.corp.local"]);
        let mut ticket_seq_c = Vec::new();
        ticket_seq_c.extend_from_slice(&ctx_wrap(0, &integer(5)));
        ticket_seq_c.extend_from_slice(&ctx_wrap(1, &general_string("CORP.LOCAL")));
        ticket_seq_c.extend_from_slice(&ctx_wrap(2, &ticket_sname));
        ticket_seq_c.extend_from_slice(&ctx_wrap(3, &seq(&{
            let mut v = ctx_wrap(0, &integer(18));
            v.extend_from_slice(&ctx_wrap(2, &tlv(TAG_OCTET_STRING, b"ticketblob")));
            v
        })));
        let ticket = tlv(0x61, &seq(&ticket_seq_c));

        let mut seq_c = Vec::new();
        seq_c.extend_from_slice(&ctx_wrap(0, &integer(5)));
        seq_c.extend_from_slice(&ctx_wrap(1, &integer(14)));
        seq_c.extend_from_slice(&ctx_wrap(2, &bit_string(0x20000000)));
        seq_c.extend_from_slice(&ctx_wrap(3, &ticket));
        seq_c.extend_from_slice(&ctx_wrap(4, &seq(&{
            let mut v = ctx_wrap(0, &integer(18));
            v.extend_from_slice(&ctx_wrap(2, &tlv(TAG_OCTET_STRING, b"authblob")));
            v
        })));

        let pkt = tlv(TAG_AP_REQ, &seq(&seq_c));
        let mut dec = KerberosDecoder::default();
        let mut evs = Vec::new();
        dec.on_datagram(&chunk_udp(&pkt, 54321, 88), &mut evs);
        let tx = get_tx(&evs).unwrap();
        assert_eq!(tx.operation, "kerberos_ap_req");
        assert_eq!(tx.status, "request_only");
        assert_eq!(
            tx.attributes.get("ticket_sname").map(String::as_str),
            Some("cifs/fileserver.corp.local")
        );
        assert_eq!(
            tx.attributes.get("ticket_realm").map(String::as_str),
            Some("CORP.LOCAL")
        );
        assert_eq!(
            tx.attributes.get("options").map(String::as_str),
            Some("0x20000000")
        );
    }

    // ── Test: KRB-ERROR parse ─────────────────────────────────────────────────

    #[test]
    fn test_krb_error_parse() {
        let payload = krb_error_payload(25, "CORP.LOCAL", &["krbtgt", "CORP.LOCAL"]);
        let mut dec = KerberosDecoder::default();
        let mut evs = Vec::new();
        dec.on_datagram(&chunk_udp(&payload, 88, 54321), &mut evs);
        let tx = get_tx(&evs).unwrap();
        assert_eq!(tx.operation, "kerberos_error");
        assert_eq!(tx.status, "error");
        assert_eq!(tx.attributes.get("error_code").map(String::as_str), Some("25"));
        assert_eq!(tx.attributes.get("svc_realm").map(String::as_str), Some("CORP.LOCAL"));
        // Also emits a ParseAnomaly at medium severity.
        let anomaly = get_anomaly(&evs).unwrap();
        assert_eq!(anomaly.severity, "medium");
        assert!(anomaly.reason.contains("code=25"));
    }

    // ── Test: TCP framing (4-byte length prefix) ──────────────────────────────

    #[test]
    fn test_tcp_framing() {
        let asn1 = as_req_payload(&["bob"], "AD.EXAMPLE.COM", &["krbtgt", "AD.EXAMPLE.COM"], &[18]);
        let mut pkt = (asn1.len() as u32).to_be_bytes().to_vec();
        pkt.extend_from_slice(&asn1);

        let mut dec = KerberosDecoder::default();
        let mut evs = Vec::new();
        dec.on_stream_chunk(&chunk_tcp(&pkt, 54321, 88), &mut evs);
        let tx = get_tx(&evs).unwrap();
        assert_eq!(tx.operation, "kerberos_as_req");
        assert_eq!(tx.attributes.get("cname").map(String::as_str), Some("bob"));
        assert_eq!(tx.attributes.get("realm").map(String::as_str), Some("AD.EXAMPLE.COM"));
    }

    // ── Test: UDP datagram (no length prefix) ─────────────────────────────────

    #[test]
    fn test_udp_datagram() {
        let payload = as_req_payload(&["carol"], "NET.TEST", &["krbtgt", "NET.TEST"], &[17, 18]);
        let mut dec = KerberosDecoder::default();
        let mut evs = Vec::new();
        dec.on_datagram(&chunk_udp(&payload, 12345, 88), &mut evs);
        assert_eq!(get_tx(&evs).unwrap().operation, "kerberos_as_req");
    }

    // ── Test: truncated TCP message → anomaly ────────────────────────────────

    #[test]
    fn test_truncated_tcp_anomaly() {
        // 4-byte length prefix claiming 200 bytes but only 10 bytes follow.
        let pkt = [0x00u8, 0x00, 0x00, 200, 0x6A, 0x82, 0x00, 0x01, 0x01, 0x01];
        let mut dec = KerberosDecoder::default();
        let mut evs = Vec::new();
        dec.on_stream_chunk(&chunk_tcp(&pkt, 54321, 88), &mut evs);
        let anomaly = get_anomaly(&evs).unwrap();
        assert_eq!(anomaly.severity, "low");
        assert!(anomaly.reason.contains("truncated"));
    }

    // ── Test: unknown application tag → anomaly ───────────────────────────────

    #[test]
    fn test_unknown_tag_anomaly() {
        // Tag 0x7F is not a valid Kerberos application tag.
        let pkt = [0x7Fu8, 0x03, 0x01, 0x02, 0x03];
        let mut dec = KerberosDecoder::default();
        let mut evs = Vec::new();
        dec.on_datagram(&chunk_udp(&pkt, 54321, 88), &mut evs);
        let anomaly = get_anomaly(&evs).unwrap();
        assert_eq!(anomaly.severity, "low");
        assert!(anomaly.reason.contains("unknown kerberos application tag"));
    }

    // ── Test: principal-name extraction (multi-component) ────────────────────

    #[test]
    fn test_principal_name_multi_component() {
        let payload = as_req_payload(
            &["alice"],
            "CORP.LOCAL",
            &["host", "dc01.corp.local"],
            &[18],
        );
        let mut dec = KerberosDecoder::default();
        let mut evs = Vec::new();
        dec.on_datagram(&chunk_udp(&payload, 54321, 88), &mut evs);
        let tx = get_tx(&evs).unwrap();
        assert_eq!(
            tx.attributes.get("sname").map(String::as_str),
            Some("host/dc01.corp.local")
        );
    }

    // ── Test: realm extraction ────────────────────────────────────────────────

    #[test]
    fn test_realm_extraction() {
        let payload = as_req_payload(&["svc_sql"], "FOREST.EXAMPLE.ORG", &["krbtgt", "FOREST.EXAMPLE.ORG"], &[18]);
        let mut dec = KerberosDecoder::default();
        let mut evs = Vec::new();
        dec.on_datagram(&chunk_udp(&payload, 54321, 88), &mut evs);
        let tx = get_tx(&evs).unwrap();
        assert_eq!(
            tx.attributes.get("realm").map(String::as_str),
            Some("FOREST.EXAMPLE.ORG")
        );
    }

    // ── Test: KDC and client AssetObservation on first AS-REQ ────────────────

    #[test]
    fn test_asset_observations_on_as_req() {
        let payload = as_req_payload(&["dave"], "CORP.LOCAL", &["krbtgt", "CORP.LOCAL"], &[18]);
        let mut dec = KerberosDecoder::default();
        let mut evs = Vec::new();
        dec.on_datagram(&chunk_udp(&payload, 54321, 88), &mut evs);
        let assets = get_assets(&evs);
        // Expect two AssetObservations: kdc_server and kerberos_client.
        assert_eq!(assets.len(), 2);
        let kdc = assets.iter().find(|a| a.role.as_deref() == Some("kdc_server")).unwrap();
        let client = assets.iter().find(|a| a.role.as_deref() == Some("kerberos_client")).unwrap();
        assert_eq!(kdc.identifiers.get("realm").map(String::as_str), Some("CORP.LOCAL"));
        assert_eq!(client.identifiers.get("cname").map(String::as_str), Some("dave"));
    }

    // ── Test: AS-REP + TGS-REP: enc_etype in attributes ─────────────────────

    #[test]
    fn test_tgs_rep_enc_etype() {
        let asn1 = as_rep_payload(&["alice"], "CORP.LOCAL", 17);
        let mut pkt = asn1.clone();
        pkt[0] = TAG_TGS_REP;
        let mut dec = KerberosDecoder::default();
        let mut evs = Vec::new();
        dec.on_datagram(&chunk_udp(&pkt, 88, 54321), &mut evs);
        let tx = get_tx(&evs).unwrap();
        assert_eq!(tx.operation, "kerberos_tgs_rep");
        assert_eq!(tx.attributes.get("enc_etype").map(String::as_str), Some("17"));
    }
}
