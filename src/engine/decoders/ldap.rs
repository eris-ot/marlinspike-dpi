//! LDAP (RFC 4511) BER operation parser — LDAPv3 over TCP 389.
//!
//! # Wire format
//! Each LDAPMessage is a BER SEQUENCE:
//!   0x30 <length> <messageID:INTEGER> <protocolOp:APPLICATION-TAGGED-CHOICE> [<controls:0xA0>]
//!
//! Application tag values (lower 5 bits of 0x6X / 0x4X):
//!   [0]  BindRequest      [1]  BindResponse
//!   [2]  UnbindRequest    [3]  SearchRequest
//!   [4]  SearchResultEntry[5]  SearchResultDone
//!   [6]  ModifyRequest    [7]  ModifyResponse
//!   [8]  AddRequest       [9]  AddResponse
//!   [10] DelRequest       [11] DelResponse
//!   [12] ModifyDNRequest  [13] ModifyDNResponse
//!   [14] CompareRequest   [15] CompareResponse
//!   [16] AbandonRequest
//!   [23] ExtendedRequest  [24] ExtendedResponse
//!
//! TCP stream chunking: LDAP messages can straddle TCP segments. A per-session
//! reassembly buffer accumulates bytes until a complete BER SEQUENCE is present.
//!
//! LDAPS (port 636): TLS-encrypted — recognition-only, emits one
//! `ldap_tls_session` ProtocolTransaction per session.

use std::collections::{BTreeMap, HashMap};

use crate::bronze::{
    AssetObservation, BronzeEvent, BronzeEventFamily, ProtocolTransaction, TransportProtocol,
};
use crate::engine::{
    DecoderInterest, SessionDecoder, StreamChunk, build_envelope, new_event, parse_anomaly_event,
};

// ── BER tag constants ─────────────────────────────────────────────────────────

const TAG_SEQUENCE: u8 = 0x30; // UNIVERSAL 16 constructed
const TAG_INTEGER: u8 = 0x02;
const TAG_OCTET_STRING: u8 = 0x04;
#[cfg(test)]
const TAG_BOOLEAN: u8 = 0x01;
const TAG_ENUMERATED: u8 = 0x0A;
#[cfg(test)]
const TAG_NULL: u8 = 0x05;

// Application-class constructed (0x60 | n) and primitive (0x40 | n)
// RFC 4511 §4: most protocolOp choices are constructed application tags.
const APP_BIND_REQUEST: u8 = 0x60; // [APPLICATION 0] CONSTRUCTED
const APP_BIND_RESPONSE: u8 = 0x61; // [APPLICATION 1] CONSTRUCTED
const APP_UNBIND_REQUEST: u8 = 0x42; // [APPLICATION 2] PRIMITIVE
const APP_SEARCH_REQUEST: u8 = 0x63; // [APPLICATION 3] CONSTRUCTED
const APP_SEARCH_RESULT_ENTRY: u8 = 0x64; // [APPLICATION 4] CONSTRUCTED
const APP_SEARCH_RESULT_DONE: u8 = 0x65; // [APPLICATION 5] CONSTRUCTED
const APP_MODIFY_REQUEST: u8 = 0x66; // [APPLICATION 6] CONSTRUCTED
const APP_MODIFY_RESPONSE: u8 = 0x67; // [APPLICATION 7] CONSTRUCTED
const APP_ADD_REQUEST: u8 = 0x68; // [APPLICATION 8] CONSTRUCTED
const APP_ADD_RESPONSE: u8 = 0x69; // [APPLICATION 9] CONSTRUCTED
const APP_DEL_REQUEST: u8 = 0x4A; // [APPLICATION 10] PRIMITIVE (DN as octet string body)
const APP_DEL_RESPONSE: u8 = 0x6B; // [APPLICATION 11] CONSTRUCTED
const APP_MODIFY_DN_REQUEST: u8 = 0x6C; // [APPLICATION 12] CONSTRUCTED
const APP_MODIFY_DN_RESPONSE: u8 = 0x6D; // [APPLICATION 13] CONSTRUCTED
const APP_COMPARE_REQUEST: u8 = 0x6E; // [APPLICATION 14] CONSTRUCTED
const APP_COMPARE_RESPONSE: u8 = 0x6F; // [APPLICATION 15] CONSTRUCTED
const APP_ABANDON_REQUEST: u8 = 0x50; // [APPLICATION 16] PRIMITIVE
const APP_EXTENDED_REQUEST: u8 = 0x77; // [APPLICATION 23] CONSTRUCTED
const APP_EXTENDED_RESPONSE: u8 = 0x78; // [APPLICATION 24] CONSTRUCTED

// Context-specific tags inside BindRequest authentication CHOICE
const CTX_PRIM_0: u8 = 0x80; // [0] simple OCTET STRING
const CTX_CONS_3: u8 = 0xA3; // [3] saslCredentials CONSTRUCTED

// Context-specific tags inside ExtendedRequest
const CTX_PRIM_80: u8 = 0x80; // [0] IMPLICIT OID (requestName)

// StartTLS OID
const STARTTLS_OID: &str = "1.3.6.1.4.1.1466.20037";

// Scope values for SearchRequest
const SCOPE_BASE: u8 = 0;
const SCOPE_ONE: u8 = 1;
const SCOPE_SUB: u8 = 2;

// LDAP result codes of interest
const RC_SUCCESS: u32 = 0;
const RC_INVALID_CREDENTIALS: u32 = 49;

// ── BER parsing primitives ────────────────────────────────────────────────────

/// Decode a BER length field starting at `buf[0]`. Returns `(length, bytes_consumed)`.
/// Returns `None` on truncation or unsupported long-form (> 4 bytes).
fn decode_ber_length(buf: &[u8]) -> Option<(usize, usize)> {
    if buf.is_empty() {
        return None;
    }
    let first = buf[0];
    if first & 0x80 == 0 {
        // Short form
        return Some((first as usize, 1));
    }
    let num_bytes = (first & 0x7F) as usize;
    if num_bytes == 0 || num_bytes > 4 || buf.len() < 1 + num_bytes {
        return None;
    }
    let mut len: usize = 0;
    for i in 0..num_bytes {
        len = (len << 8) | (buf[1 + i] as usize);
    }
    Some((len, 1 + num_bytes))
}

/// Decode a BER TLV. Returns `(tag, value_slice, total_bytes_consumed)`.
fn decode_tlv(buf: &[u8]) -> Option<(u8, &[u8], usize)> {
    if buf.len() < 2 {
        return None;
    }
    let tag = buf[0];
    let (vlen, llen) = decode_ber_length(&buf[1..])?;
    let hdr = 1 + llen;
    if hdr + vlen > buf.len() {
        return None;
    }
    Some((tag, &buf[hdr..hdr + vlen], hdr + vlen))
}

/// Peek at the total encoded length of the outer BER SEQUENCE starting at
/// `buf[0]`. Returns the full byte count (tag + length_bytes + value_bytes)
/// if determinable from `buf`, or `None` if truncated.
fn outer_sequence_total_len(buf: &[u8]) -> Option<usize> {
    if buf.is_empty() || buf[0] != TAG_SEQUENCE {
        return None;
    }
    let (vlen, llen) = decode_ber_length(&buf[1..])?;
    Some(1 + llen + vlen)
}

/// Decode a BER INTEGER (up to 4 bytes value) to i64.
fn decode_integer(val: &[u8]) -> Option<i64> {
    if val.is_empty() || val.len() > 8 {
        return None;
    }
    let sign_extend = if val[0] & 0x80 != 0 { !0i64 } else { 0i64 };
    let mut n = sign_extend;
    for &b in val {
        n = (n << 8) | (b as i64);
    }
    Some(n)
}

/// Decode a BER ENUMERATED (same encoding as INTEGER) to u32.
fn decode_enumerated(val: &[u8]) -> Option<u32> {
    decode_integer(val).map(|v| v as u32)
}

/// Attempt to decode bytes as UTF-8; fall back to lossy conversion.
fn ber_string(val: &[u8]) -> String {
    String::from_utf8_lossy(val).into_owned()
}

/// Decode a BER OID value bytes into dotted notation string.
#[expect(dead_code, reason = "kept for future LDAP schema/OID enrichment work")]
fn decode_oid(val: &[u8]) -> Option<String> {
    if val.is_empty() {
        return None;
    }
    let first = val[0];
    let mut components = vec![(first / 40).to_string(), (first % 40).to_string()];
    let mut acc: u64 = 0;
    for &b in &val[1..] {
        acc = (acc << 7) | ((b & 0x7F) as u64);
        if b & 0x80 == 0 {
            components.push(acc.to_string());
            acc = 0;
        }
    }
    Some(components.join("."))
}

/// Walk the children of a SEQUENCE/SET/constructed value, calling `f` for each TLV.
fn walk_sequence<F: FnMut(u8, &[u8])>(seq_val: &[u8], mut f: F) {
    let mut pos = 0;
    while pos < seq_val.len() {
        if let Some((tag, val, consumed)) = decode_tlv(&seq_val[pos..]) {
            f(tag, val);
            pos += consumed;
        } else {
            break;
        }
    }
}

// ── LDAP result code name ─────────────────────────────────────────────────────

fn result_code_name(code: u32) -> &'static str {
    match code {
        0 => "success",
        1 => "operationsError",
        2 => "protocolError",
        3 => "timeLimitExceeded",
        4 => "sizeLimitExceeded",
        7 => "authMethodNotSupported",
        8 => "strongerAuthRequired",
        10 => "referral",
        11 => "adminLimitExceeded",
        16 => "noSuchAttribute",
        17 => "undefinedAttributeType",
        20 => "attributeOrValueExists",
        21 => "invalidAttributeSyntax",
        32 => "noSuchObject",
        33 => "aliasProblem",
        34 => "invalidDNSyntax",
        48 => "inappropriateAuthentication",
        49 => "invalidCredentials",
        50 => "insufficientAccessRights",
        51 => "busy",
        52 => "unavailable",
        53 => "unwillingToPerform",
        64 => "namingViolation",
        65 => "objectClassViolation",
        66 => "notAllowedOnNonLeaf",
        67 => "notAllowedOnRDN",
        68 => "entryAlreadyExists",
        69 => "objectClassModsProhibited",
        80 => "other",
        _ => "unknownResultCode",
    }
}

// ── Filter type discriminator ─────────────────────────────────────────────────

/// Return a short human-readable name for the top-level LDAP filter choice.
/// RFC 4511 §4.5.1: filter choices are context-specific constructed/primitive tags.
fn filter_type_name(filter_tag: u8) -> &'static str {
    match filter_tag {
        0xA0 => "and",
        0xA1 => "or",
        0xA2 => "not",
        0xA3 => "equalityMatch",
        0xA4 => "substrings",
        0xA5 => "greaterOrEqual",
        0xA6 => "lessOrEqual",
        0x87 => "present",
        0xA8 => "approxMatch",
        0xA9 => "extensibleMatch",
        _ => "unknown",
    }
}

// ── Scope name ────────────────────────────────────────────────────────────────

fn scope_name(scope: u8) -> &'static str {
    match scope {
        SCOPE_BASE => "baseObject",
        SCOPE_ONE => "singleLevel",
        SCOPE_SUB => "wholeSubtree",
        _ => "unknown",
    }
}

// ── Per-message extraction structures ────────────────────────────────────────

#[derive(Debug)]
struct LdapMessage {
    message_id: i64,
    op_tag: u8,
    details: LdapOpDetails,
}

#[derive(Debug, Default)]
struct LdapOpDetails {
    /// Distinguished name (BindRequest name, SearchRequest base, target DN)
    dn: Option<String>,
    /// Bind auth type: "simple" or "sasl"
    auth_type: Option<String>,
    /// SASL mechanism
    sasl_mechanism: Option<String>,
    /// Result code (responses)
    result_code: Option<u32>,
    /// matchedDN from response
    matched_dn: Option<String>,
    /// SearchRequest scope
    scope: Option<u8>,
    /// Top-level filter tag name
    filter_type: Option<String>,
    /// Attribute selectors from SearchRequest
    attributes: Vec<String>,
    /// ExtendedRequest OID
    extended_oid: Option<String>,
    /// objectName from SearchResultEntry
    object_name: Option<String>,
}

// ── Parse a complete LDAPMessage SEQUENCE ────────────────────────────────────

/// Parse a complete LDAPMessage (outer SEQUENCE already known to be present).
/// Returns `None` on structural BER error.
fn parse_ldap_message(seq_val: &[u8]) -> Option<LdapMessage> {
    let mut pos = 0;

    // messageID INTEGER
    let (id_tag, id_val, consumed) = decode_tlv(&seq_val[pos..])?;
    if id_tag != TAG_INTEGER {
        return None;
    }
    let message_id = decode_integer(id_val)?;
    pos += consumed;

    // protocolOp APPLICATION-TAGGED CHOICE
    if pos >= seq_val.len() {
        return None;
    }
    let (op_tag, op_val, consumed) = decode_tlv(&seq_val[pos..])?;
    pos += consumed;
    let _ = pos; // controls parsing deferred — not needed for extraction

    let details = extract_op_details(op_tag, op_val);

    Some(LdapMessage {
        message_id,
        op_tag,
        details,
    })
}

fn extract_op_details(op_tag: u8, op_val: &[u8]) -> LdapOpDetails {
    let mut d = LdapOpDetails::default();
    match op_tag {
        APP_BIND_REQUEST => parse_bind_request(op_val, &mut d),
        APP_BIND_RESPONSE => parse_ldap_result(op_val, &mut d),
        APP_UNBIND_REQUEST => {} // empty
        APP_SEARCH_REQUEST => parse_search_request(op_val, &mut d),
        APP_SEARCH_RESULT_ENTRY => parse_search_result_entry(op_val, &mut d),
        APP_SEARCH_RESULT_DONE => parse_ldap_result(op_val, &mut d),
        APP_MODIFY_REQUEST => parse_dn_first(op_val, &mut d),
        APP_MODIFY_RESPONSE => parse_ldap_result(op_val, &mut d),
        APP_ADD_REQUEST => parse_dn_first(op_val, &mut d),
        APP_ADD_RESPONSE => parse_ldap_result(op_val, &mut d),
        APP_DEL_REQUEST => {
            // DelRequest is [APPLICATION 10] IMPLICIT LDAPString — the val IS the DN bytes
            d.dn = Some(ber_string(op_val));
        }
        APP_DEL_RESPONSE => parse_ldap_result(op_val, &mut d),
        APP_MODIFY_DN_REQUEST => parse_dn_first(op_val, &mut d),
        APP_MODIFY_DN_RESPONSE => parse_ldap_result(op_val, &mut d),
        APP_COMPARE_REQUEST => parse_dn_first(op_val, &mut d),
        APP_COMPARE_RESPONSE => parse_ldap_result(op_val, &mut d),
        APP_ABANDON_REQUEST => {} // INTEGER, skip
        APP_EXTENDED_REQUEST => parse_extended_request(op_val, &mut d),
        APP_EXTENDED_RESPONSE => parse_ldap_result(op_val, &mut d),
        _ => {}
    }
    d
}

/// Parse BindRequest: version INTEGER, name LDAPDN, authentication CHOICE
fn parse_bind_request(val: &[u8], d: &mut LdapOpDetails) {
    let mut children = Vec::new();
    walk_sequence(val, |tag, v| children.push((tag, v.to_vec())));

    // version, name, authentication
    if children.len() < 3 {
        return;
    }
    // name is child[1], OCTET STRING (LDAPString)
    if children[1].0 == TAG_OCTET_STRING {
        d.dn = Some(ber_string(&children[1].1));
    }
    let auth_tag = children[2].0;
    let auth_val = &children[2].1;
    match auth_tag {
        CTX_PRIM_0 => {
            d.auth_type = Some("simple".to_string());
        }
        CTX_CONS_3 => {
            d.auth_type = Some("sasl".to_string());
            // SaslCredentials: mechanism LDAPSTRING, credentials OCTET STRING opt
            let mut sasl_children = Vec::new();
            walk_sequence(auth_val, |t, v| sasl_children.push((t, v.to_vec())));
            if let Some((t, v)) = sasl_children.first()
                && *t == TAG_OCTET_STRING
            {
                d.sasl_mechanism = Some(ber_string(v));
            }
        }
        _ => {
            d.auth_type = Some(format!("unknown_auth_{:#04x}", auth_tag));
        }
    }
}

/// Parse LDAPResult: resultCode ENUMERATED, matchedDN, diagnosticMessage
fn parse_ldap_result(val: &[u8], d: &mut LdapOpDetails) {
    let mut pos = 0;
    // resultCode ENUMERATED
    if let Some((tag, v, consumed)) = decode_tlv(&val[pos..]) {
        if tag == TAG_ENUMERATED {
            d.result_code = decode_enumerated(v);
        }
        pos += consumed;
    }
    // matchedDN OCTET STRING
    if let Some((tag, v, _consumed)) = decode_tlv(&val[pos..])
        && tag == TAG_OCTET_STRING
        && !v.is_empty()
    {
        d.matched_dn = Some(ber_string(v));
    }
}

/// Parse SearchRequest
fn parse_search_request(val: &[u8], d: &mut LdapOpDetails) {
    let mut pos = 0;
    // baseObject LDAPDN (OCTET STRING)
    if let Some((tag, v, consumed)) = decode_tlv(&val[pos..]) {
        if tag == TAG_OCTET_STRING {
            d.dn = Some(ber_string(v));
        }
        pos += consumed;
    }
    // scope ENUMERATED
    if let Some((tag, v, consumed)) = decode_tlv(&val[pos..]) {
        if tag == TAG_ENUMERATED {
            d.scope = decode_enumerated(v).map(|s| s as u8);
        }
        pos += consumed;
    }
    // derefAliases ENUMERATED — skip
    if let Some((_, _, consumed)) = decode_tlv(&val[pos..]) {
        pos += consumed;
    }
    // sizeLimit INTEGER — skip
    if let Some((_, _, consumed)) = decode_tlv(&val[pos..]) {
        pos += consumed;
    }
    // timeLimit INTEGER — skip
    if let Some((_, _, consumed)) = decode_tlv(&val[pos..]) {
        pos += consumed;
    }
    // typesOnly BOOLEAN — skip
    if let Some((_, _, consumed)) = decode_tlv(&val[pos..]) {
        pos += consumed;
    }
    // filter CHOICE — decode top-level tag for discriminator
    if let Some((tag, _v, consumed)) = decode_tlv(&val[pos..]) {
        d.filter_type = Some(filter_type_name(tag).to_string());
        pos += consumed;
    }
    // attributes AttributeDescriptionList (SEQUENCE OF LDAPSTRING)
    if let Some((tag, v, _)) = decode_tlv(&val[pos..])
        && tag == TAG_SEQUENCE
    {
        walk_sequence(v, |t, attr_v| {
            if t == TAG_OCTET_STRING {
                d.attributes.push(ber_string(attr_v));
            }
        });
    }
}

/// Parse SearchResultEntry: objectName LDAPDN, attributes PartialAttributeList
fn parse_search_result_entry(val: &[u8], d: &mut LdapOpDetails) {
    if let Some((tag, v, _)) = decode_tlv(val)
        && tag == TAG_OCTET_STRING
    {
        d.object_name = Some(ber_string(v));
    }
}

/// Parse structures that begin with the target DN (ModifyRequest, AddRequest,
/// ModifyDNRequest, CompareRequest).
fn parse_dn_first(val: &[u8], d: &mut LdapOpDetails) {
    if let Some((tag, v, _)) = decode_tlv(val)
        && tag == TAG_OCTET_STRING
    {
        d.dn = Some(ber_string(v));
    }
}

/// Parse ExtendedRequest: requestName [0] IMPLICIT LDAPOID
fn parse_extended_request(val: &[u8], d: &mut LdapOpDetails) {
    if let Some((tag, v, _)) = decode_tlv(val)
        && tag == CTX_PRIM_80
    {
        // requestName is stored as an OID in OCTET STRING encoding,
        // but RFC 4511 says it's an LDAPOID (really just an OctetString
        // containing the dotted OID as ASCII text).
        d.extended_oid = Some(ber_string(v));
    }
}

// ── Operation name → string ───────────────────────────────────────────────────

fn op_name(tag: u8) -> &'static str {
    match tag {
        APP_BIND_REQUEST => "ldap_bind_request",
        APP_BIND_RESPONSE => "ldap_bind_response",
        APP_UNBIND_REQUEST => "ldap_unbind_request",
        APP_SEARCH_REQUEST => "ldap_search_request",
        APP_SEARCH_RESULT_ENTRY => "ldap_search_result_entry",
        APP_SEARCH_RESULT_DONE => "ldap_search_result_done",
        APP_MODIFY_REQUEST => "ldap_modify_request",
        APP_MODIFY_RESPONSE => "ldap_modify_response",
        APP_ADD_REQUEST => "ldap_add_request",
        APP_ADD_RESPONSE => "ldap_add_response",
        APP_DEL_REQUEST => "ldap_del_request",
        APP_DEL_RESPONSE => "ldap_del_response",
        APP_MODIFY_DN_REQUEST => "ldap_modifydn_request",
        APP_MODIFY_DN_RESPONSE => "ldap_modifydn_response",
        APP_COMPARE_REQUEST => "ldap_compare_request",
        APP_COMPARE_RESPONSE => "ldap_compare_response",
        APP_ABANDON_REQUEST => "ldap_abandon_request",
        APP_EXTENDED_REQUEST => "ldap_extended_request",
        APP_EXTENDED_RESPONSE => "ldap_extended_response",
        _ => "ldap_unknown_op",
    }
}

/// Whether this op tag represents a request (client→server) direction.
#[expect(dead_code, reason = "kept for future directional heuristics")]
fn is_request_op(tag: u8) -> bool {
    matches!(
        tag,
        APP_BIND_REQUEST
            | APP_UNBIND_REQUEST
            | APP_SEARCH_REQUEST
            | APP_MODIFY_REQUEST
            | APP_ADD_REQUEST
            | APP_DEL_REQUEST
            | APP_MODIFY_DN_REQUEST
            | APP_COMPARE_REQUEST
            | APP_ABANDON_REQUEST
            | APP_EXTENDED_REQUEST
    )
}

/// Whether this op tag is paired (has a matching response).
fn is_paired_request(tag: u8) -> bool {
    matches!(
        tag,
        APP_BIND_REQUEST
            | APP_SEARCH_REQUEST
            | APP_MODIFY_REQUEST
            | APP_ADD_REQUEST
            | APP_DEL_REQUEST
            | APP_MODIFY_DN_REQUEST
            | APP_COMPARE_REQUEST
            | APP_EXTENDED_REQUEST
    )
}

fn is_response_op(tag: u8) -> bool {
    matches!(
        tag,
        APP_BIND_RESPONSE
            | APP_SEARCH_RESULT_DONE
            | APP_MODIFY_RESPONSE
            | APP_ADD_RESPONSE
            | APP_DEL_RESPONSE
            | APP_MODIFY_DN_RESPONSE
            | APP_COMPARE_RESPONSE
            | APP_EXTENDED_RESPONSE
    )
}

// ── Pending request tracker ───────────────────────────────────────────────────

#[derive(Debug)]
struct PendingReq {
    #[expect(dead_code, reason = "reserved for richer request/response correlation")]
    op_tag: u8,
}

// ── Session state ─────────────────────────────────────────────────────────────

#[derive(Debug, Default)]
struct LdapSession {
    /// Per-session reassembly buffer for TCP segmentation.
    buf: Vec<u8>,
    /// Pending requests keyed by messageID.
    pending: HashMap<i64, PendingReq>,
    /// Server asset already emitted for this session.
    server_asset_emitted: bool,
}

// ── Decoder ───────────────────────────────────────────────────────────────────

/// LDAP (RFC 4511) BER operation decoder.
/// Port 389: plaintext — full BER parse.
/// Port 636: LDAPS (TLS) — recognition-only, one session marker per session.
#[derive(Default)]
pub(crate) struct LdapDecoder {
    sessions: HashMap<String, LdapSession>,
    /// LDAPS sessions that have already emitted their marker.
    ldaps_emitted: HashMap<String, bool>,
}

inventory::submit!(crate::engine::decoders::DecoderRegistration {
    name: "ldap",
    factory: || Box::new(LdapDecoder::default()),
});

impl SessionDecoder for LdapDecoder {
    fn name(&self) -> &'static str {
        "ldap"
    }

    fn interest(&self) -> &'static [DecoderInterest] {
        &[DecoderInterest::TcpPort(389), DecoderInterest::TcpPort(636)]
    }

    fn on_stream_chunk(&mut self, chunk: &StreamChunk<'_>, out: &mut Vec<BronzeEvent>) {
        let dst_port = chunk.context.dst_port;
        let src_port = chunk.context.src_port;

        if dst_port == 636 || src_port == 636 {
            self.handle_ldaps(chunk, out);
            return;
        }

        self.handle_ldap_plaintext(chunk, out);
    }
}

impl LdapDecoder {
    // ── LDAPS session marker ──────────────────────────────────────────────────

    fn handle_ldaps(&mut self, chunk: &StreamChunk<'_>, out: &mut Vec<BronzeEvent>) {
        if self.ldaps_emitted.contains_key(&chunk.session_key) {
            return;
        }
        self.ldaps_emitted.insert(chunk.session_key.clone(), true);

        let envelope = build_envelope(
            &chunk.context,
            chunk.interface_id,
            chunk.frame_index,
            chunk.timestamp,
            chunk.segment_hash,
            TransportProtocol::Tcp,
            Some("ldap"),
            chunk.captured_len,
            chunk.session_key.clone(),
        );

        let server_ip = chunk.context.dst_ip.to_string();
        out.push(new_event(
            chunk.capture_id.to_string(),
            envelope.clone(),
            BronzeEventFamily::AssetObservation(AssetObservation {
                asset_key: server_ip,
                role: Some("ldap_server".to_string()),
                vendor: None,
                model: None,
                firmware: None,
                hostnames: vec![],
                protocols: vec!["ldaps".to_string()],
                identifiers: BTreeMap::new(),
            }),
        ));
        out.push(new_event(
            chunk.capture_id.to_string(),
            envelope,
            BronzeEventFamily::ProtocolTransaction(ProtocolTransaction {
                operation: "ldap_tls_session".to_string(),
                status: "observed".to_string(),
                request_summary: None,
                response_summary: None,
                object_refs: vec![],
                values: vec![],
                attributes: BTreeMap::new(),
                modbus: None,
                protocol_fields: None,
            }),
        ));
    }

    // ── Plaintext LDAP (port 389) ─────────────────────────────────────────────

    fn handle_ldap_plaintext(&mut self, chunk: &StreamChunk<'_>, out: &mut Vec<BronzeEvent>) {
        // Accumulate into buffer first, then release the borrow before calling emit_message.
        {
            let session = self.sessions.entry(chunk.session_key.clone()).or_default();
            session.buf.extend_from_slice(chunk.payload);
        }

        // Drain complete messages into a local Vec to avoid holding &mut self.sessions
        // while calling emit_message (which also borrows self.sessions).
        enum DrainResult {
            Message(LdapMessage),
            MalformedBer(Vec<u8>),
            InvalidTag(Vec<u8>),
        }
        let mut drained: Vec<DrainResult> = Vec::new();

        {
            let session = self.sessions.get_mut(&chunk.session_key).unwrap();
            loop {
                if session.buf.len() < 2 {
                    break;
                }
                if session.buf[0] != TAG_SEQUENCE {
                    let excerpt: Vec<u8> = session.buf.clone();
                    session.buf.clear();
                    drained.push(DrainResult::InvalidTag(excerpt));
                    break;
                }
                let total = match outer_sequence_total_len(&session.buf) {
                    Some(n) => n,
                    None => break, // incomplete — wait for more data
                };
                if session.buf.len() < total {
                    break; // not yet complete
                }
                let msg_bytes: Vec<u8> = session.buf[..total].to_vec();
                session.buf.drain(..total);

                let llen = {
                    let lb = msg_bytes[1];
                    if lb & 0x80 == 0 {
                        1usize
                    } else {
                        1 + (lb & 0x7F) as usize
                    }
                };
                let seq_val_start = 1 + llen;
                match parse_ldap_message(&msg_bytes[seq_val_start..]) {
                    Some(m) => drained.push(DrainResult::Message(m)),
                    None => drained.push(DrainResult::MalformedBer(msg_bytes)),
                }
            }
        }

        for result in drained {
            match result {
                DrainResult::Message(msg) => {
                    self.emit_message(chunk, msg, out);
                }
                DrainResult::MalformedBer(msg_bytes) => {
                    let envelope = build_envelope(
                        &chunk.context,
                        chunk.interface_id,
                        chunk.frame_index,
                        chunk.timestamp,
                        chunk.segment_hash,
                        TransportProtocol::Tcp,
                        Some("ldap"),
                        chunk.captured_len,
                        chunk.session_key.clone(),
                    );
                    out.push(parse_anomaly_event(
                        chunk.capture_id.to_string(),
                        envelope,
                        "ldap",
                        "low",
                        "malformed BER in LDAPMessage content",
                        &msg_bytes,
                    ));
                }
                DrainResult::InvalidTag(excerpt) => {
                    let envelope = build_envelope(
                        &chunk.context,
                        chunk.interface_id,
                        chunk.frame_index,
                        chunk.timestamp,
                        chunk.segment_hash,
                        TransportProtocol::Tcp,
                        Some("ldap"),
                        chunk.captured_len,
                        chunk.session_key.clone(),
                    );
                    out.push(parse_anomaly_event(
                        chunk.capture_id.to_string(),
                        envelope,
                        "ldap",
                        "low",
                        "expected BER SEQUENCE (0x30) at start of LDAP message",
                        &excerpt,
                    ));
                }
            }
        }
    }

    fn emit_message(
        &mut self,
        chunk: &StreamChunk<'_>,
        msg: LdapMessage,
        out: &mut Vec<BronzeEvent>,
    ) {
        let session = self.sessions.get_mut(&chunk.session_key).unwrap();

        // ── Server asset (once per session, on first message) ─────────────────
        if !session.server_asset_emitted {
            session.server_asset_emitted = true;
            let server_ip = chunk.context.dst_ip.to_string();
            let env = build_envelope(
                &chunk.context,
                chunk.interface_id,
                chunk.frame_index,
                chunk.timestamp,
                chunk.segment_hash,
                TransportProtocol::Tcp,
                Some("ldap"),
                chunk.captured_len,
                chunk.session_key.clone(),
            );
            out.push(new_event(
                chunk.capture_id.to_string(),
                env,
                BronzeEventFamily::AssetObservation(AssetObservation {
                    asset_key: server_ip,
                    role: Some("ldap_server".to_string()),
                    vendor: None,
                    model: None,
                    firmware: None,
                    hostnames: vec![],
                    protocols: vec!["ldap".to_string()],
                    identifiers: BTreeMap::new(),
                }),
            ));
        }

        let op_tag = msg.op_tag;
        let details = msg.details;

        // ── Request/response pairing ──────────────────────────────────────────
        let status = if is_paired_request(op_tag) {
            session
                .pending
                .insert(msg.message_id, PendingReq { op_tag });
            "request_only".to_string()
        } else if is_response_op(op_tag) {
            let rc = details.result_code.unwrap_or(0);
            if session.pending.remove(&msg.message_id).is_some() {
                if rc == RC_SUCCESS {
                    "ok".to_string()
                } else {
                    "error".to_string()
                }
            } else {
                // Unsolicited response
                if rc == RC_SUCCESS {
                    "response_only".to_string()
                } else {
                    "error".to_string()
                }
            }
        } else {
            // Unpaired ops: UnbindRequest, SearchResultEntry, AbandonRequest
            "ok".to_string()
        };

        // ── Build attributes ──────────────────────────────────────────────────
        let mut attributes: BTreeMap<String, String> = BTreeMap::new();
        attributes.insert("message_id".to_string(), msg.message_id.to_string());
        attributes.insert("op_tag_hex".to_string(), format!("{:#04x}", op_tag));

        if let Some(ref dn) = details.dn {
            attributes.insert("dn".to_string(), dn.clone());
        }
        if let Some(ref auth) = details.auth_type {
            attributes.insert("auth_type".to_string(), auth.clone());
        }
        if let Some(ref mech) = details.sasl_mechanism {
            attributes.insert("sasl_mechanism".to_string(), mech.clone());
        }
        if let Some(rc) = details.result_code {
            attributes.insert("result_code".to_string(), rc.to_string());
            attributes.insert(
                "result_code_name".to_string(),
                result_code_name(rc).to_string(),
            );
        }
        if let Some(ref mdn) = details.matched_dn {
            attributes.insert("matched_dn".to_string(), mdn.clone());
        }
        if let Some(scope) = details.scope {
            attributes.insert("scope".to_string(), scope_name(scope).to_string());
        }
        if let Some(ref ft) = details.filter_type {
            attributes.insert("filter_type".to_string(), ft.clone());
        }
        if !details.attributes.is_empty() {
            attributes.insert("attributes".to_string(), details.attributes.join(","));
        }
        if let Some(ref oid) = details.extended_oid {
            attributes.insert("extended_oid".to_string(), oid.clone());
            if oid == STARTTLS_OID {
                attributes.insert("starttls".to_string(), "true".to_string());
            }
        }
        if let Some(ref obj) = details.object_name {
            attributes.insert("object_name".to_string(), obj.clone());
        }

        // ── Request/response summaries ────────────────────────────────────────
        let request_summary = match op_tag {
            APP_BIND_REQUEST => {
                let auth = details.auth_type.as_deref().unwrap_or("?");
                let dn = details.dn.as_deref().unwrap_or("");
                Some(format!("bind dn=\"{dn}\" auth={auth}"))
            }
            APP_SEARCH_REQUEST => {
                let base = details.dn.as_deref().unwrap_or("");
                let scope = details.scope.map(scope_name).unwrap_or("?");
                let ftype = details.filter_type.as_deref().unwrap_or("?");
                Some(format!(
                    "search base=\"{base}\" scope={scope} filter={ftype}"
                ))
            }
            APP_DEL_REQUEST
            | APP_MODIFY_REQUEST
            | APP_ADD_REQUEST
            | APP_MODIFY_DN_REQUEST
            | APP_COMPARE_REQUEST => {
                let dn = details.dn.as_deref().unwrap_or("");
                Some(format!("dn=\"{dn}\""))
            }
            APP_EXTENDED_REQUEST => {
                let oid = details.extended_oid.as_deref().unwrap_or("?");
                Some(format!("oid={oid}"))
            }
            APP_SEARCH_RESULT_ENTRY => {
                let obj = details.object_name.as_deref().unwrap_or("");
                Some(format!("entry=\"{obj}\""))
            }
            _ => None,
        };

        let response_summary = if is_response_op(op_tag) {
            let rc = details.result_code.unwrap_or(0);
            Some(format!("result={} ({})", rc, result_code_name(rc)))
        } else {
            None
        };

        // ── Anomaly events ────────────────────────────────────────────────────
        let envelope = build_envelope(
            &chunk.context,
            chunk.interface_id,
            chunk.frame_index,
            chunk.timestamp,
            chunk.segment_hash,
            TransportProtocol::Tcp,
            Some("ldap"),
            chunk.captured_len,
            chunk.session_key.clone(),
        );

        // Failed bind: emit medium-severity ParseAnomaly
        if op_tag == APP_BIND_RESPONSE {
            let rc = details.result_code.unwrap_or(0);
            if rc == RC_INVALID_CREDENTIALS {
                out.push(parse_anomaly_event(
                    chunk.capture_id.to_string(),
                    envelope.clone(),
                    "ldap",
                    "medium",
                    "LDAP bind failed: invalidCredentials (49)",
                    &[],
                ));
            }
        }

        // StartTLS detected: informational low-severity
        if op_tag == APP_EXTENDED_REQUEST && details.extended_oid.as_deref() == Some(STARTTLS_OID) {
            out.push(parse_anomaly_event(
                chunk.capture_id.to_string(),
                envelope.clone(),
                "ldap",
                "low",
                "StartTLS negotiation detected — session may go opaque after this message",
                &[],
            ));
        }

        // ── Client AssetObservation on successful bind ─────────────────────────
        // Emit for BindRequest so we capture the attempted DN even before response.
        if op_tag == APP_BIND_REQUEST
            && let Some(ref dn) = details.dn
            && !dn.is_empty()
        {
            let mut identifiers: BTreeMap<String, String> = BTreeMap::new();
            identifiers.insert("bind_dn".to_string(), dn.clone());
            if let Some(ref mech) = details.sasl_mechanism {
                identifiers.insert("sasl_mechanism".to_string(), mech.clone());
            }
            out.push(new_event(
                chunk.capture_id.to_string(),
                envelope.clone(),
                BronzeEventFamily::AssetObservation(AssetObservation {
                    asset_key: chunk.context.src_ip.to_string(),
                    role: Some("ldap_client".to_string()),
                    vendor: None,
                    model: None,
                    firmware: None,
                    hostnames: vec![],
                    protocols: vec!["ldap".to_string()],
                    identifiers,
                }),
            ));
        }

        // ── ProtocolTransaction event ─────────────────────────────────────────
        out.push(new_event(
            chunk.capture_id.to_string(),
            envelope,
            BronzeEventFamily::ProtocolTransaction(ProtocolTransaction {
                operation: op_name(op_tag).to_string(),
                status,
                request_summary,
                response_summary,
                object_refs: vec![],
                values: vec![],
                attributes,
                modbus: None,
                protocol_fields: None,
            }),
        ));
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bronze::BronzeEventFamily;
    use crate::engine::{DecoderInterest, SessionDecoder, StreamChunk};
    use crate::registry::PacketContext;
    use chrono::Utc;
    use std::net::{IpAddr, Ipv4Addr};

    // ── Test helpers ─────────────────────────────────────────────────────────

    fn ctx(sp: u16, dp: u16) -> PacketContext {
        PacketContext {
            src_mac: [0u8; 6],
            dst_mac: [0u8; 6],
            src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            dst_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            src_port: sp,
            dst_port: dp,
            vlan_id: None,
            timestamp: 0,
        }
    }

    fn chunk_with_key<'a>(
        payload: &'a [u8],
        context: PacketContext,
        session_key: &'a str,
    ) -> StreamChunk<'a> {
        StreamChunk {
            capture_id: "test",
            segment_hash: "seg",
            interface_id: 0,
            frame_index: 0,
            timestamp: Utc::now(),
            context,
            ethertype: 0x0800,
            ip_proto: Some(6),
            llc: None,
            transport: TransportProtocol::Tcp,
            payload,
            session_key: session_key.to_string(),
            captured_len: payload.len() as u64,
        }
    }

    fn chunk<'a>(payload: &'a [u8], context: PacketContext) -> StreamChunk<'a> {
        chunk_with_key(payload, context, "sk")
    }

    fn get_txns(evs: &[BronzeEvent]) -> Vec<&ProtocolTransaction> {
        evs.iter()
            .filter_map(|e| {
                if let BronzeEventFamily::ProtocolTransaction(ref t) = e.family {
                    Some(t)
                } else {
                    None
                }
            })
            .collect()
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

    fn get_anomalies(evs: &[BronzeEvent]) -> Vec<&crate::bronze::ParseAnomaly> {
        evs.iter()
            .filter_map(|e| {
                if let BronzeEventFamily::ParseAnomaly(ref a) = e.family {
                    Some(a)
                } else {
                    None
                }
            })
            .collect()
    }

    // ── BER encoding helpers ──────────────────────────────────────────────────

    /// Encode a BER TLV. Handles short (<128) and long-form lengths.
    fn tlv(tag: u8, value: &[u8]) -> Vec<u8> {
        let mut out = vec![tag];
        let len = value.len();
        if len < 128 {
            out.push(len as u8);
        } else if len <= 0xFF {
            out.extend_from_slice(&[0x81, len as u8]);
        } else {
            out.extend_from_slice(&[0x82, (len >> 8) as u8, (len & 0xFF) as u8]);
        }
        out.extend_from_slice(value);
        out
    }

    fn integer(v: i64) -> Vec<u8> {
        // Minimal DER integer encoding
        if v == 0 {
            return tlv(TAG_INTEGER, &[0]);
        }
        let mut bytes = [0u8; 8];
        let be = v.to_be_bytes();
        bytes.copy_from_slice(&be);
        // find first non-redundant byte
        let mut start = 0usize;
        while start < 7 {
            let b0 = bytes[start];
            let b1 = bytes[start + 1];
            // redundant if sign-extension
            if (b0 == 0x00 && b1 & 0x80 == 0) || (b0 == 0xFF && b1 & 0x80 != 0) {
                start += 1;
            } else {
                break;
            }
        }
        tlv(TAG_INTEGER, &bytes[start..])
    }

    fn octet_string(s: &[u8]) -> Vec<u8> {
        tlv(TAG_OCTET_STRING, s)
    }

    fn enumerated(v: u32) -> Vec<u8> {
        tlv(TAG_ENUMERATED, &[v as u8])
    }

    fn boolean_val(v: bool) -> Vec<u8> {
        tlv(TAG_BOOLEAN, &[if v { 0xFF } else { 0x00 }])
    }

    fn sequence(inner: &[u8]) -> Vec<u8> {
        tlv(TAG_SEQUENCE, inner)
    }

    #[expect(dead_code, reason = "kept for future BER test fixtures")]
    fn null() -> Vec<u8> {
        vec![TAG_NULL, 0x00]
    }

    /// Wrap inner bytes as an LDAPMessage SEQUENCE: msgID + protocolOp.
    fn ldap_message(msg_id: i64, proto_op: &[u8]) -> Vec<u8> {
        let mut inner = integer(msg_id);
        inner.extend_from_slice(proto_op);
        sequence(&inner)
    }

    // ── Test 1: BindRequest simple auth ──────────────────────────────────────

    #[test]
    fn test_bind_request_simple_auth() {
        // BindRequest [APPLICATION 0] CONSTRUCTED: version, name, [0] password
        let mut bind_inner = integer(3); // version = 3
        bind_inner.extend_from_slice(&octet_string(b"cn=admin,dc=example,dc=com"));
        bind_inner.extend_from_slice(&tlv(CTX_PRIM_0, b"secret")); // simple auth
        let bind_req = tlv(APP_BIND_REQUEST, &bind_inner);
        let pkt = ldap_message(1, &bind_req);

        let mut dec = LdapDecoder::default();
        let mut evs = Vec::new();
        dec.on_stream_chunk(&chunk(&pkt, ctx(50000, 389)), &mut evs);

        let txns = get_txns(&evs);
        assert!(!txns.is_empty(), "expected ProtocolTransaction");
        let tx = txns
            .iter()
            .find(|t| t.operation == "ldap_bind_request")
            .expect("bind_request tx");
        assert_eq!(
            tx.attributes.get("dn").map(String::as_str),
            Some("cn=admin,dc=example,dc=com")
        );
        assert_eq!(
            tx.attributes.get("auth_type").map(String::as_str),
            Some("simple")
        );
        assert_eq!(tx.status, "request_only");
    }

    // ── Test 2: BindRequest SASL auth ─────────────────────────────────────────

    #[test]
    fn test_bind_request_sasl_auth() {
        let sasl_cred = {
            let mut inner = octet_string(b"GSSAPI");
            inner.extend_from_slice(&octet_string(b"\x00\x01\x02token")); // credentials
            tlv(CTX_CONS_3, &inner)
        };
        let mut bind_inner = integer(3);
        bind_inner.extend_from_slice(&octet_string(b""));
        bind_inner.extend_from_slice(&sasl_cred);
        let bind_req = tlv(APP_BIND_REQUEST, &bind_inner);
        let pkt = ldap_message(2, &bind_req);

        let mut dec = LdapDecoder::default();
        let mut evs = Vec::new();
        dec.on_stream_chunk(&chunk(&pkt, ctx(50001, 389)), &mut evs);

        let txns = get_txns(&evs);
        let tx = txns
            .iter()
            .find(|t| t.operation == "ldap_bind_request")
            .expect("bind_request tx");
        assert_eq!(
            tx.attributes.get("auth_type").map(String::as_str),
            Some("sasl")
        );
        assert_eq!(
            tx.attributes.get("sasl_mechanism").map(String::as_str),
            Some("GSSAPI")
        );
    }

    // ── Test 3: BindResponse success ─────────────────────────────────────────

    #[test]
    fn test_bind_response_success() {
        // First a request so we can pair it
        let mut bind_inner = integer(3);
        bind_inner.extend_from_slice(&octet_string(b"cn=admin,dc=test"));
        bind_inner.extend_from_slice(&tlv(CTX_PRIM_0, b"pass"));
        let req_pkt = ldap_message(1, &tlv(APP_BIND_REQUEST, &bind_inner));

        // BindResponse success: resultCode=0, matchedDN="", message=""
        let mut resp_inner = enumerated(0);
        resp_inner.extend_from_slice(&octet_string(b""));
        resp_inner.extend_from_slice(&octet_string(b""));
        let resp_pkt = ldap_message(1, &tlv(APP_BIND_RESPONSE, &resp_inner));

        let mut dec = LdapDecoder::default();
        let mut evs = Vec::new();
        dec.on_stream_chunk(
            &chunk_with_key(&req_pkt, ctx(50002, 389), "sess-bind"),
            &mut evs,
        );
        dec.on_stream_chunk(
            &chunk_with_key(&resp_pkt, ctx(50002, 389), "sess-bind"),
            &mut evs,
        );

        let txns = get_txns(&evs);
        let resp_tx = txns
            .iter()
            .find(|t| t.operation == "ldap_bind_response")
            .expect("bind_response tx");
        assert_eq!(resp_tx.status, "ok");
        assert_eq!(
            resp_tx.attributes.get("result_code").map(String::as_str),
            Some("0")
        );
        assert_eq!(
            resp_tx
                .attributes
                .get("result_code_name")
                .map(String::as_str),
            Some("success")
        );
    }

    // ── Test 4: BindResponse invalidCredentials (49) ─────────────────────────

    #[test]
    fn test_bind_response_invalid_credentials() {
        let mut resp_inner = enumerated(RC_INVALID_CREDENTIALS as u32);
        resp_inner.extend_from_slice(&octet_string(b""));
        resp_inner.extend_from_slice(&octet_string(b"Invalid credentials"));
        let resp_pkt = ldap_message(5, &tlv(APP_BIND_RESPONSE, &resp_inner));

        let mut dec = LdapDecoder::default();
        let mut evs = Vec::new();
        dec.on_stream_chunk(&chunk(&resp_pkt, ctx(50003, 389)), &mut evs);

        let txns = get_txns(&evs);
        let resp_tx = txns
            .iter()
            .find(|t| t.operation == "ldap_bind_response")
            .expect("bind_response");
        assert_eq!(resp_tx.status, "error");
        assert_eq!(
            resp_tx.attributes.get("result_code").map(String::as_str),
            Some("49")
        );
        assert_eq!(
            resp_tx
                .attributes
                .get("result_code_name")
                .map(String::as_str),
            Some("invalidCredentials")
        );

        let anomalies = get_anomalies(&evs);
        assert!(!anomalies.is_empty(), "expected anomaly for failed bind");
        assert_eq!(anomalies[0].severity, "medium");
        assert!(anomalies[0].reason.contains("invalidCredentials"));
    }

    // ── Test 5: SearchRequest wholeSubtree + present filter + attributes ──────

    #[test]
    fn test_search_request_wholetree_filter_attributes() {
        let mut search_inner = octet_string(b"dc=example,dc=com"); // baseObject
        search_inner.extend_from_slice(&enumerated(SCOPE_SUB as u32)); // scope=wholeSubtree
        search_inner.extend_from_slice(&enumerated(0)); // derefAliases
        search_inner.extend_from_slice(&integer(0)); // sizeLimit
        search_inner.extend_from_slice(&integer(0)); // timeLimit
        search_inner.extend_from_slice(&boolean_val(false)); // typesOnly
        // filter: present (0x87) for "objectClass"
        search_inner.extend_from_slice(&tlv(0x87, b"objectClass"));
        // attributes: ["cn", "mail"]
        let mut attr_seq_inner = octet_string(b"cn");
        attr_seq_inner.extend_from_slice(&octet_string(b"mail"));
        search_inner.extend_from_slice(&sequence(&attr_seq_inner));
        let search_req = tlv(APP_SEARCH_REQUEST, &search_inner);
        let pkt = ldap_message(3, &search_req);

        let mut dec = LdapDecoder::default();
        let mut evs = Vec::new();
        dec.on_stream_chunk(&chunk(&pkt, ctx(50004, 389)), &mut evs);

        let txns = get_txns(&evs);
        let tx = txns
            .iter()
            .find(|t| t.operation == "ldap_search_request")
            .expect("search_request");
        assert_eq!(
            tx.attributes.get("dn").map(String::as_str),
            Some("dc=example,dc=com")
        );
        assert_eq!(
            tx.attributes.get("scope").map(String::as_str),
            Some("wholeSubtree")
        );
        assert_eq!(
            tx.attributes.get("filter_type").map(String::as_str),
            Some("present")
        );
        let attrs_str = tx
            .attributes
            .get("attributes")
            .map(String::as_str)
            .unwrap_or("");
        assert!(attrs_str.contains("cn"));
        assert!(attrs_str.contains("mail"));
    }

    // ── Test 6: SearchResultEntry ─────────────────────────────────────────────

    #[test]
    fn test_search_result_entry() {
        let mut entry_inner = octet_string(b"cn=john,dc=example,dc=com"); // objectName
        entry_inner.extend_from_slice(&sequence(&[])); // attributes (empty)
        let entry = tlv(APP_SEARCH_RESULT_ENTRY, &entry_inner);
        let pkt = ldap_message(3, &entry);

        let mut dec = LdapDecoder::default();
        let mut evs = Vec::new();
        dec.on_stream_chunk(&chunk(&pkt, ctx(389, 50004)), &mut evs);

        let txns = get_txns(&evs);
        let tx = txns
            .iter()
            .find(|t| t.operation == "ldap_search_result_entry")
            .expect("result_entry");
        assert_eq!(
            tx.attributes.get("object_name").map(String::as_str),
            Some("cn=john,dc=example,dc=com")
        );
        assert_eq!(tx.status, "ok");
    }

    // ── Test 7: SearchResultDone with result code ─────────────────────────────

    #[test]
    fn test_search_result_done_success() {
        // First emit a request to pair with
        let mut search_inner = octet_string(b"dc=test");
        search_inner.extend_from_slice(&enumerated(2)); // scope=sub
        search_inner.extend_from_slice(&enumerated(0));
        search_inner.extend_from_slice(&integer(0));
        search_inner.extend_from_slice(&integer(0));
        search_inner.extend_from_slice(&boolean_val(false));
        search_inner.extend_from_slice(&tlv(0x87, b"objectClass")); // filter
        search_inner.extend_from_slice(&sequence(&[]));
        let req_pkt = ldap_message(10, &tlv(APP_SEARCH_REQUEST, &search_inner));

        let mut done_inner = enumerated(0);
        done_inner.extend_from_slice(&octet_string(b""));
        done_inner.extend_from_slice(&octet_string(b""));
        let done_pkt = ldap_message(10, &tlv(APP_SEARCH_RESULT_DONE, &done_inner));

        let mut dec = LdapDecoder::default();
        let mut evs = Vec::new();
        dec.on_stream_chunk(
            &chunk_with_key(&req_pkt, ctx(50005, 389), "sess-search"),
            &mut evs,
        );
        dec.on_stream_chunk(
            &chunk_with_key(&done_pkt, ctx(50005, 389), "sess-search"),
            &mut evs,
        );

        let txns = get_txns(&evs);
        let done_tx = txns
            .iter()
            .find(|t| t.operation == "ldap_search_result_done")
            .expect("done");
        assert_eq!(done_tx.status, "ok");
        assert_eq!(
            done_tx.attributes.get("result_code").map(String::as_str),
            Some("0")
        );
    }

    // ── Test 8: ModifyRequest ─────────────────────────────────────────────────

    #[test]
    fn test_modify_request() {
        let mut mod_inner = octet_string(b"cn=bob,dc=corp,dc=com");
        mod_inner.extend_from_slice(&sequence(&[])); // modification list (empty)
        let modify_req = tlv(APP_MODIFY_REQUEST, &mod_inner);
        let pkt = ldap_message(7, &modify_req);

        let mut dec = LdapDecoder::default();
        let mut evs = Vec::new();
        dec.on_stream_chunk(&chunk(&pkt, ctx(50006, 389)), &mut evs);

        let txns = get_txns(&evs);
        let tx = txns
            .iter()
            .find(|t| t.operation == "ldap_modify_request")
            .expect("modify_request");
        assert_eq!(
            tx.attributes.get("dn").map(String::as_str),
            Some("cn=bob,dc=corp,dc=com")
        );
        assert_eq!(tx.status, "request_only");
    }

    // ── Test 9: AddRequest ────────────────────────────────────────────────────

    #[test]
    fn test_add_request() {
        let mut add_inner = octet_string(b"cn=newuser,ou=users,dc=corp");
        add_inner.extend_from_slice(&sequence(&[])); // attributes (empty)
        let add_req = tlv(APP_ADD_REQUEST, &add_inner);
        let pkt = ldap_message(8, &add_req);

        let mut dec = LdapDecoder::default();
        let mut evs = Vec::new();
        dec.on_stream_chunk(&chunk(&pkt, ctx(50007, 389)), &mut evs);

        let txns = get_txns(&evs);
        let tx = txns
            .iter()
            .find(|t| t.operation == "ldap_add_request")
            .expect("add_request");
        assert_eq!(
            tx.attributes.get("dn").map(String::as_str),
            Some("cn=newuser,ou=users,dc=corp")
        );
    }

    // ── Test 10: DelRequest ───────────────────────────────────────────────────

    #[test]
    fn test_del_request() {
        // DelRequest [APPLICATION 10] PRIMITIVE — value IS the DN
        let del_req = tlv(APP_DEL_REQUEST, b"cn=old,dc=corp");
        let pkt = ldap_message(9, &del_req);

        let mut dec = LdapDecoder::default();
        let mut evs = Vec::new();
        dec.on_stream_chunk(&chunk(&pkt, ctx(50008, 389)), &mut evs);

        let txns = get_txns(&evs);
        let tx = txns
            .iter()
            .find(|t| t.operation == "ldap_del_request")
            .expect("del_request");
        assert_eq!(
            tx.attributes.get("dn").map(String::as_str),
            Some("cn=old,dc=corp")
        );
    }

    // ── Test 11: ExtendedRequest StartTLS ────────────────────────────────────

    #[test]
    fn test_extended_request_starttls() {
        // ExtendedRequest [APPLICATION 23] CONSTRUCTED
        // requestName [0] IMPLICIT LDAPString (OID as ASCII)
        let ext_inner = tlv(CTX_PRIM_80, STARTTLS_OID.as_bytes());
        let ext_req = tlv(APP_EXTENDED_REQUEST, &ext_inner);
        let pkt = ldap_message(20, &ext_req);

        let mut dec = LdapDecoder::default();
        let mut evs = Vec::new();
        dec.on_stream_chunk(&chunk(&pkt, ctx(50009, 389)), &mut evs);

        let txns = get_txns(&evs);
        let tx = txns
            .iter()
            .find(|t| t.operation == "ldap_extended_request")
            .expect("extended_request");
        assert_eq!(
            tx.attributes.get("extended_oid").map(String::as_str),
            Some(STARTTLS_OID)
        );
        assert_eq!(
            tx.attributes.get("starttls").map(String::as_str),
            Some("true")
        );

        let anomalies = get_anomalies(&evs);
        assert!(!anomalies.is_empty(), "expected StartTLS anomaly");
        assert_eq!(anomalies[0].severity, "low");
        assert!(anomalies[0].reason.contains("StartTLS"));
    }

    // ── Test 12: LDAPS port 636 session marker ────────────────────────────────

    #[test]
    fn test_ldaps_port_636_session_marker() {
        let tls_hello = [0x16u8, 0x03, 0x03, 0x00, 0x01];
        let mut dec = LdapDecoder::default();
        let mut evs = Vec::new();
        dec.on_stream_chunk(&chunk(&tls_hello, ctx(50010, 636)), &mut evs);

        let txns = get_txns(&evs);
        assert!(!txns.is_empty(), "expected ldap_tls_session tx");
        let tx = txns
            .iter()
            .find(|t| t.operation == "ldap_tls_session")
            .expect("tls_session");
        assert_eq!(tx.status, "observed");

        let assets = get_assets(&evs);
        assert!(!assets.is_empty(), "expected server asset");
        assert_eq!(assets[0].role.as_deref(), Some("ldap_server"));
        assert!(assets[0].protocols.contains(&"ldaps".to_string()));

        // Second chunk on same session should produce no new events
        let n = evs.len();
        dec.on_stream_chunk(&chunk(&tls_hello, ctx(50010, 636)), &mut evs);
        assert_eq!(evs.len(), n, "second chunk on same session must not emit");
    }

    // ── Test 13: Truncated BER → anomaly ─────────────────────────────────────

    #[test]
    fn test_truncated_ber_produces_anomaly() {
        // SEQUENCE tag + length=100 but only 5 bytes of payload
        let truncated = [0x30u8, 0x64, 0x02, 0x01, 0x01];

        let mut dec = LdapDecoder::default();
        let mut evs = Vec::new();
        dec.on_stream_chunk(&chunk(&truncated, ctx(50011, 389)), &mut evs);

        // Buffer should hold the bytes and not emit a ProtocolTransaction yet.
        // No events should appear — message is incomplete, waiting for more data.
        let txns = get_txns(&evs);
        assert!(
            txns.is_empty(),
            "incomplete message must not emit ProtocolTransaction"
        );
        let anomalies = get_anomalies(&evs);
        assert!(
            anomalies.is_empty(),
            "incomplete message must not emit anomaly — just buffer"
        );
    }

    // ── Test 14: Message straddling two chunks (buffering) ────────────────────

    #[test]
    fn test_message_straddling_chunks() {
        // Build a complete BindRequest message
        let mut bind_inner = integer(3);
        bind_inner.extend_from_slice(&octet_string(b"cn=test,dc=local"));
        bind_inner.extend_from_slice(&tlv(CTX_PRIM_0, b"pw"));
        let bind_req = tlv(APP_BIND_REQUEST, &bind_inner);
        let full_pkt = ldap_message(1, &bind_req);

        // Split into two chunks at midpoint
        let mid = full_pkt.len() / 2;
        let part1 = &full_pkt[..mid];
        let part2 = &full_pkt[mid..];

        let mut dec = LdapDecoder::default();
        let mut evs = Vec::new();

        // First half: should buffer, no tx emitted yet
        dec.on_stream_chunk(
            &chunk_with_key(part1, ctx(50012, 389), "sess-straddle"),
            &mut evs,
        );
        let txns_after_first = get_txns(&evs);
        assert!(
            txns_after_first.is_empty(),
            "first chunk should not produce tx"
        );

        // Second half: now complete, should emit
        dec.on_stream_chunk(
            &chunk_with_key(part2, ctx(50012, 389), "sess-straddle"),
            &mut evs,
        );
        let txns = get_txns(&evs);
        let bind_tx = txns.iter().find(|t| t.operation == "ldap_bind_request");
        assert!(
            bind_tx.is_some(),
            "assembled message should produce bind_request tx"
        );
        assert_eq!(
            bind_tx.unwrap().attributes.get("dn").map(String::as_str),
            Some("cn=test,dc=local")
        );
    }
}
