//! IEC 61850-family dissector prototype.
//!
//! Scope for this first pass:
//! - MMS over ISO-on-TCP on port 102, because that is the tractable slice in the local corpus
//!   and it carries the highest immediate identity value.
//! - GOOSE and Sampled Values Ethernet frames, using the fixed IEC 61850 EtherTypes.
//!
//! This file is intentionally self-contained so it can be developed in isolation before the
//! shared `registry.rs` and `engine.rs` wiring lands.

use crate::registry::{PacketContext, ProtocolData, ProtocolDissector};

pub const IEC61850_MMS_PORT: u16 = 102;
pub const IEC61850_GOOSE_ETHERTYPE: u16 = 0x88B8;
pub const IEC61850_SV_ETHERTYPE: u16 = 0x88BA;
const TPKT_HEADER_SIZE: usize = 4;
const MMS_VISIBLE_STRING_MIN: usize = 3;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Iec61850Profile {
    MmsIsoOnTcp,
    Goose,
    SampledValues,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Iec61850Fields {
    pub profile: Iec61850Profile,
    pub transport: String,
    pub message_type: String,
    pub tpkt_length: Option<usize>,
    pub cotp_pdu_type: Option<String>,
    pub app_id: Option<u16>,
    pub called_tsap: Option<String>,
    pub calling_tsap: Option<String>,
    pub service: Option<String>,
    pub ied_name: Option<String>,
    pub logical_device: Option<String>,
    pub logical_node: Option<String>,
    pub dataset: Option<String>,
    pub object_references: Vec<String>,
    pub visible_strings: Vec<String>,
    pub payload: Vec<u8>,
    /// GOOSE stNum — state number, incremented on each state change event.
    pub goose_st_num: Option<u32>,
    /// GOOSE sqNum — sequence number, incremented for each retransmission.
    pub goose_sq_num: Option<u32>,
    /// GOOSE test bit — true when the PDU is a test/simulation message.
    pub goose_test: bool,
    /// MMS invoke-ID extracted from confirmed-request/response PDU header.
    pub mms_invoke_id: Option<u32>,
    /// SV smpCnt — sample count from the first ASDU.
    pub sv_smp_cnt: Option<u16>,
    /// SV smpSynch — sample synchronisation flag.
    pub sv_smp_synch: Option<u8>,
}

#[derive(Debug, Default)]
pub struct Iec61850Dissector;

impl ProtocolDissector for Iec61850Dissector {
    fn name(&self) -> &str {
        "iec61850"
    }

    fn can_parse(&self, data: &[u8], src_port: u16, dst_port: u16) -> bool {
        Iec61850Dissector::can_parse(self, data, src_port, dst_port, None)
    }

    fn parse(&self, data: &[u8], context: &PacketContext) -> Option<ProtocolData> {
        Iec61850Dissector::parse(self, data, context.src_port, context.dst_port, None)
            .map(ProtocolData::Iec61850)
    }
}

impl Iec61850Dissector {
    pub fn name(&self) -> &str {
        "iec61850"
    }

    pub fn can_parse(
        &self,
        data: &[u8],
        src_port: u16,
        dst_port: u16,
        ethertype: Option<u16>,
    ) -> bool {
        match ethertype {
            Some(IEC61850_GOOSE_ETHERTYPE) | Some(IEC61850_SV_ETHERTYPE) => data.len() >= 8,
            _ => {
                (src_port == IEC61850_MMS_PORT || dst_port == IEC61850_MMS_PORT)
                    && looks_like_mms_iso_on_tcp(data)
            }
        }
    }

    pub fn parse(
        &self,
        data: &[u8],
        src_port: u16,
        dst_port: u16,
        ethertype: Option<u16>,
    ) -> Option<Iec61850Fields> {
        match ethertype {
            Some(IEC61850_GOOSE_ETHERTYPE) => parse_goose_or_sv(data, Iec61850Profile::Goose),
            Some(IEC61850_SV_ETHERTYPE) => parse_goose_or_sv(data, Iec61850Profile::SampledValues),
            _ if src_port == IEC61850_MMS_PORT || dst_port == IEC61850_MMS_PORT => {
                parse_mms_iso_on_tcp(data)
            }
            _ => None,
        }
    }
}

fn parse_mms_iso_on_tcp(data: &[u8]) -> Option<Iec61850Fields> {
    let layout = parse_cotp_layout(data)?;
    let cotp_pdu_name = cotp_pdu_name(layout.cotp_pdu_type).to_string();

    if matches!(layout.cotp_pdu_type, 0xE0 | 0xD0) || layout.payload.is_empty() {
        return Some(Iec61850Fields {
            profile: Iec61850Profile::MmsIsoOnTcp,
            transport: "tpkt_cotp".to_string(),
            message_type: "cotp_control".to_string(),
            tpkt_length: Some(layout.tpkt_length),
            cotp_pdu_type: Some(cotp_pdu_name),
            app_id: None,
            called_tsap: layout.called_tsap,
            calling_tsap: layout.calling_tsap,
            service: Some(mms_service_name(&[]).to_string()),
            ied_name: None,
            logical_device: None,
            logical_node: None,
            dataset: None,
            object_references: Vec::new(),
            visible_strings: Vec::new(),
            payload: Vec::new(),
            goose_st_num: None,
            goose_sq_num: None,
            goose_test: false,
            mms_invoke_id: None,
            sv_smp_cnt: None,
            sv_smp_synch: None,
        });
    }

    if !looks_like_mms_tag(layout.payload[0]) {
        return None;
    }

    let payload = layout.payload.to_vec();
    let visible_strings = extract_visible_strings(&payload);
    let references = extract_object_references(&visible_strings);
    let identity = derive_identity(&visible_strings, &references);
    let mms_invoke_id = extract_mms_invoke_id(&payload);

    Some(Iec61850Fields {
        profile: Iec61850Profile::MmsIsoOnTcp,
        transport: "tpkt_cotp".to_string(),
        message_type: "mms".to_string(),
        tpkt_length: Some(layout.tpkt_length),
        cotp_pdu_type: Some(cotp_pdu_name),
        app_id: None,
        called_tsap: layout.called_tsap,
        calling_tsap: layout.calling_tsap,
        service: Some(mms_service_name(&payload).to_string()),
        ied_name: identity.ied_name,
        logical_device: identity.logical_device,
        logical_node: identity.logical_node,
        dataset: identity.dataset,
        object_references: references,
        visible_strings,
        payload,
        goose_st_num: None,
        goose_sq_num: None,
        goose_test: false,
        mms_invoke_id,
        sv_smp_cnt: None,
        sv_smp_synch: None,
    })
}

struct CotpLayout<'a> {
    tpkt_length: usize,
    cotp_pdu_type: u8,
    called_tsap: Option<String>,
    calling_tsap: Option<String>,
    payload: &'a [u8],
}

fn looks_like_mms_iso_on_tcp(data: &[u8]) -> bool {
    let Some(layout) = parse_cotp_layout(data) else {
        return false;
    };

    if matches!(layout.cotp_pdu_type, 0xE0 | 0xD0) {
        return true;
    }

    layout
        .payload
        .first()
        .copied()
        .map(looks_like_mms_tag)
        .unwrap_or(false)
}

fn parse_cotp_layout(data: &[u8]) -> Option<CotpLayout<'_>> {
    if data.len() < TPKT_HEADER_SIZE || data[0] != 0x03 {
        return None;
    }

    let tpkt_length = u16::from_be_bytes([data[2], data[3]]) as usize;
    if tpkt_length < TPKT_HEADER_SIZE || tpkt_length > data.len() {
        return None;
    }

    let cotp_length = *data.get(TPKT_HEADER_SIZE)? as usize;
    let cotp_total = 1 + cotp_length;
    let cotp_end = TPKT_HEADER_SIZE + cotp_total;
    if cotp_length == 0 || cotp_end > tpkt_length || cotp_end > data.len() {
        return None;
    }

    let cotp_pdu_type = *data.get(TPKT_HEADER_SIZE + 1)?;
    let mut called_tsap = None;
    let mut calling_tsap = None;

    if cotp_pdu_type == 0xE0 || cotp_pdu_type == 0xD0 {
        let mut cursor = TPKT_HEADER_SIZE + 7;
        while cursor + 1 < cotp_end {
            let code = data[cursor];
            let len = data[cursor + 1] as usize;
            cursor += 2;
            if cursor + len > cotp_end {
                break;
            }
            let value = &data[cursor..cursor + len];
            match code {
                0xC1 => called_tsap = Some(format_tsap(value)),
                0xC2 => calling_tsap = Some(format_tsap(value)),
                0xC0 if len == 1 => {}
                _ => {}
            }
            cursor += len;
        }
    }

    Some(CotpLayout {
        tpkt_length,
        cotp_pdu_type,
        called_tsap,
        calling_tsap,
        payload: &data[cotp_end..tpkt_length],
    })
}

fn looks_like_mms_tag(tag: u8) -> bool {
    matches!(tag, 0x60 | 0x61 | 0xA0..=0xA8)
}

fn parse_goose_or_sv(data: &[u8], profile: Iec61850Profile) -> Option<Iec61850Fields> {
    if data.len() < 8 {
        return None;
    }

    let app_id = u16::from_be_bytes([data[0], data[1]]);
    let length = u16::from_be_bytes([data[2], data[3]]) as usize;
    let payload_end = length.min(data.len());
    if payload_end < 8 {
        return None;
    }

    let payload = data[8..payload_end].to_vec();
    let visible_strings = extract_visible_strings(&payload);
    let references = extract_object_references(&visible_strings);
    let identity = derive_identity(&visible_strings, &references);

    let transport = match profile {
        Iec61850Profile::Goose => "ethernet_goose",
        Iec61850Profile::SampledValues => "ethernet_sampled_values",
        Iec61850Profile::MmsIsoOnTcp => "tpkt_cotp",
    }
    .to_string();

    let message_type = match profile {
        Iec61850Profile::Goose => "goose",
        Iec61850Profile::SampledValues => "sampled_values",
        Iec61850Profile::MmsIsoOnTcp => "mms",
    }
    .to_string();

    let service = if profile == Iec61850Profile::Goose {
        Some("goose_pdu".to_string())
    } else {
        Some("sampled_values_pdu".to_string())
    };

    let (goose_st_num, goose_sq_num, goose_test) = if profile == Iec61850Profile::Goose {
        let nums = extract_goose_sequence_numbers(&payload);
        (nums.0, nums.1, nums.2)
    } else {
        (None, None, false)
    };

    let (sv_smp_cnt, sv_smp_synch) = if profile == Iec61850Profile::SampledValues {
        extract_sv_sample_fields(&payload)
    } else {
        (None, None)
    };

    Some(Iec61850Fields {
        profile,
        transport,
        message_type,
        tpkt_length: None,
        cotp_pdu_type: None,
        app_id: Some(app_id),
        called_tsap: None,
        calling_tsap: None,
        service,
        ied_name: identity.ied_name,
        logical_device: identity.logical_device,
        logical_node: identity.logical_node,
        dataset: identity.dataset,
        object_references: references,
        visible_strings,
        payload,
        goose_st_num,
        goose_sq_num,
        goose_test,
        mms_invoke_id: None,
        sv_smp_cnt,
        sv_smp_synch,
    })
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
struct IdentityHints {
    ied_name: Option<String>,
    logical_device: Option<String>,
    logical_node: Option<String>,
    dataset: Option<String>,
}

fn derive_identity(strings: &[String], references: &[String]) -> IdentityHints {
    let mut hints = IdentityHints::default();

    for reference in references {
        let (prefix, suffix) = reference.split_once('/').unwrap_or((reference, ""));
        if hints.logical_device.is_none() && !prefix.is_empty() {
            hints.logical_device = Some(prefix.to_string());
        }
        if hints.ied_name.is_none() {
            hints.ied_name = strip_logical_device_suffix(prefix).map(str::to_string);
        }
        if hints.logical_node.is_none() && !suffix.is_empty() {
            let logical_node = suffix
                .split(['.', '$', '/'])
                .next()
                .unwrap_or(suffix)
                .trim();
            if !logical_node.is_empty() {
                hints.logical_node = Some(logical_node.to_string());
            }
        }
        if hints.dataset.is_none() {
            if let Some(dataset) = extract_dataset_hint(reference) {
                hints.dataset = Some(dataset.to_string());
            }
        }
    }

    for value in strings {
        if hints.dataset.is_none() && looks_like_dataset_name(value) {
            hints.dataset = Some(value.to_string());
        }
        if hints.ied_name.is_none() && looks_like_ied_name(value) {
            hints.ied_name = Some(value.to_string());
        }
    }

    hints
}

fn strip_logical_device_suffix(value: &str) -> Option<&str> {
    let bytes = value.as_bytes();
    let mut idx = bytes.len();
    while idx > 0 && bytes[idx - 1].is_ascii_digit() {
        idx -= 1;
    }
    if idx >= 2 && &value[idx - 2..idx] == "LD" {
        let prefix = &value[..idx - 2];
        if prefix.is_empty() {
            None
        } else {
            Some(prefix)
        }
    } else {
        None
    }
}

fn extract_dataset_hint(reference: &str) -> Option<&str> {
    reference
        .split_once('$')
        .map(|(_, tail)| tail.split(['$', '.', '/']).next().unwrap_or(tail).trim())
        .filter(|value| {
            !value.is_empty()
                && (value.len() > 2
                    || value
                        .chars()
                        .any(|c| c.is_ascii_lowercase() || c.is_ascii_digit()))
        })
}

fn looks_like_dataset_name(value: &str) -> bool {
    let lower = value.to_ascii_lowercase();
    (lower.contains("dataset") || lower.contains("datset") || lower.contains("goose"))
        && !value.contains(' ')
        && value.len() >= MMS_VISIBLE_STRING_MIN
}

fn looks_like_ied_name(value: &str) -> bool {
    let trimmed = value.trim();
    !trimmed.is_empty()
        && trimmed.len() >= 2
        && trimmed.len() <= 32
        && trimmed
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
}

fn format_tsap(bytes: &[u8]) -> String {
    match bytes {
        [single] => format!("0x{single:02X}"),
        [hi, lo] => format!("0x{hi:02X}{lo:02X}"),
        _ => bytes
            .iter()
            .map(|byte| format!("{byte:02X}"))
            .collect::<Vec<_>>()
            .join(":"),
    }
}

fn mms_service_name(payload: &[u8]) -> &'static str {
    match payload.first().copied() {
        Some(0x60) => "initiate_request",
        Some(0x61) => "initiate_response",
        Some(0xA0) => "confirmed_request_pdu",
        Some(0xA1) => "confirmed_response_pdu",
        Some(0xA2) => "cancel_request_pdu",
        Some(0xA3) => "cancel_response_pdu",
        Some(0xA4) => "unconfirmed_pdu",
        Some(0xA5) => "reject_pdu",
        Some(0xA6) => "cancel_error_pdu",
        Some(0xA7) => "confirmed_error_pdu",
        Some(0xA8) => "information_report_pdu",
        Some(_) => "mms_apdu",
        None => "cotp_control",
    }
}

fn cotp_pdu_name(code: u8) -> &'static str {
    match code {
        0xE0 => "connection_request",
        0xD0 => "connection_confirm",
        0xF0 => "data_transfer",
        0x80 => "disconnect_request",
        _ => "cotp_pdu",
    }
}

fn extract_visible_strings(data: &[u8]) -> Vec<String> {
    let mut strings = Vec::new();
    let mut run = Vec::new();

    for &byte in data {
        if is_visible_ascii(byte) {
            run.push(byte);
        } else {
            push_visible_run(&mut strings, &mut run);
        }
    }
    push_visible_run(&mut strings, &mut run);

    strings
}

fn push_visible_run(strings: &mut Vec<String>, run: &mut Vec<u8>) {
    if run.len() >= MMS_VISIBLE_STRING_MIN {
        if let Ok(value) = String::from_utf8(run.clone()) {
            strings.push(value);
        }
    }
    run.clear();
}

fn is_visible_ascii(byte: u8) -> bool {
    matches!(byte, 0x20..=0x7E)
}

/// Extract the MMS invoke-ID from a confirmed-request or confirmed-response PDU.
///
/// Confirmed-request PDU (tag 0xA0) layout after the outer TLV:
///   [invokeID tag=0x02] [len] [invoke-id bytes up to 4]
/// We scan for the first INTEGER (0x02) after the outer tag/length to tolerate
/// variable-length BER encoding of the outer sequence length.
fn extract_mms_invoke_id(payload: &[u8]) -> Option<u32> {
    // Only apply to confirmed-request (0xA0) and confirmed-response (0xA1).
    let outer_tag = *payload.first()?;
    if !matches!(outer_tag, 0xA0 | 0xA1) {
        return None;
    }
    // Skip outer tag + BER length (1 or 3 bytes for short/long form).
    let skip = if payload.len() > 2 && payload[1] == 0x82 {
        4 // 0x82 means 2 length bytes follow
    } else {
        2
    };
    let inner = payload.get(skip..)?;
    // Scan for first INTEGER (0x02) within the first 16 bytes.
    for i in 0..inner.len().min(16) {
        if inner[i] == 0x02 {
            let len = *inner.get(i + 1)? as usize;
            if len == 0 || len > 4 {
                continue;
            }
            let value_bytes = inner.get(i + 2..i + 2 + len)?;
            let mut val: u32 = 0;
            for &b in value_bytes {
                val = val << 8 | b as u32;
            }
            return Some(val);
        }
    }
    None
}

/// Scan the GOOSE payload for stNum, sqNum, and the test bit using a sliding
/// byte scanner. This tolerates payloads that mix visible-ASCII strings (for
/// dataset refs) with the BER-encoded GOOSE PDU body, as commonly seen in the
/// IEC 61850-8-1 wire format.
///
/// GOOSE PDU context-primitive tags (IEC 61850-8-1 clause 8.6.3):
///   0x86  [6] IMPLICIT BOOLEAN  — test flag
///   0x89  [9] IMPLICIT INTEGER  — stNum (state number, u32)
///   0x8A  [10] IMPLICIT INTEGER — sqNum (sequence number, u32)
fn extract_goose_sequence_numbers(payload: &[u8]) -> (Option<u32>, Option<u32>, bool) {
    let mut st_num = None;
    let mut sq_num = None;
    let mut test = false;

    // Sliding scan: look for known context-primitive tags anywhere in the payload.
    // For each candidate tag we validate that length + value fit within remaining bytes.
    let mut i = 0;
    while i + 1 < payload.len() {
        let tag = payload[i];
        let len = payload[i + 1] as usize;
        // Sanity: value must fit, and length must be plausible for these fields.
        if len == 0 || i + 2 + len > payload.len() {
            i += 1;
            continue;
        }
        let value = &payload[i + 2..i + 2 + len];
        match tag {
            0x86 if len == 1 => {
                test = value[0] != 0x00;
                i += 2 + len;
            }
            0x89 if len >= 1 && len <= 4 => {
                let mut v: u32 = 0;
                for &b in value {
                    v = v << 8 | b as u32;
                }
                st_num = Some(v);
                i += 2 + len;
            }
            0x8A if len >= 1 && len <= 4 => {
                let mut v: u32 = 0;
                for &b in value {
                    v = v << 8 | b as u32;
                }
                sq_num = Some(v);
                i += 2 + len;
            }
            _ => {
                i += 1;
            }
        }
        // Stop once we have all three fields.
        if st_num.is_some() && sq_num.is_some() {
            break;
        }
    }

    (st_num, sq_num, test)
}

/// Extract smpCnt and smpSynch from an SV PDU using a sliding scanner.
///
/// Scans the payload for the well-known context-primitive SV ASDU tags:
///   0x82  [2] IMPLICIT INTEGER — smpCnt (2 bytes, unsigned)
///   0x85  [5] IMPLICIT INTEGER — smpSynch (1 byte, 0=none/1=local/2=global)
///
/// A sliding scan is used so the function tolerates mixed payloads where
/// visible-ASCII dataset references precede the BER-encoded SV PDU body.
fn extract_sv_sample_fields(payload: &[u8]) -> (Option<u16>, Option<u8>) {
    let mut smp_cnt = None;
    let mut smp_synch = None;

    let mut i = 0;
    while i + 1 < payload.len() {
        let tag = payload[i];
        let len = payload[i + 1] as usize;
        if len == 0 || i + 2 + len > payload.len() {
            i += 1;
            continue;
        }
        let value = &payload[i + 2..i + 2 + len];
        match tag {
            0x82 if len == 2 => {
                smp_cnt = Some(u16::from_be_bytes([value[0], value[1]]));
                i += 2 + len;
            }
            0x85 if len == 1 => {
                smp_synch = Some(value[0]);
                i += 2 + len;
            }
            _ => {
                i += 1;
            }
        }
        if smp_cnt.is_some() && smp_synch.is_some() {
            break;
        }
    }

    (smp_cnt, smp_synch)
}

fn extract_object_references(strings: &[String]) -> Vec<String> {
    let mut references = Vec::new();
    for value in strings {
        if looks_like_object_reference(value) && !references.contains(value) {
            references.push(value.clone());
        }
    }
    references
}

fn looks_like_object_reference(value: &str) -> bool {
    let has_separator = value.contains('/') || value.contains('.') || value.contains('$');
    has_separator
        && value.chars().any(|c| c.is_ascii_alphabetic())
        && value
            .chars()
            .any(|c| c.is_ascii_digit() || c.is_ascii_uppercase())
        && value.len() >= 4
}

#[cfg(test)]
mod tests {
    use super::*;

    fn build_tpkt_cotp_mms(payload: &[u8]) -> Vec<u8> {
        let cotp_len = 2u8;
        let tpkt_len = (TPKT_HEADER_SIZE + 1 + cotp_len as usize + payload.len()) as u16;

        let mut pkt = Vec::new();
        pkt.push(0x03);
        pkt.push(0x00);
        pkt.extend_from_slice(&tpkt_len.to_be_bytes());
        pkt.push(cotp_len);
        pkt.push(0xF0);
        pkt.push(0x80);
        pkt.extend_from_slice(payload);
        pkt
    }

    fn build_cotp_connect_packet(called_tsap: [u8; 2], calling_tsap: [u8; 2]) -> Vec<u8> {
        let mut cotp = vec![
            0x0E, // length indicator
            0xE0, // connection request
            0x00,
            0x00, // dst ref
            0x00,
            0x01, // src ref
            0x00, // class/options
            0xC1,
            0x02,
            called_tsap[0],
            called_tsap[1],
            0xC2,
            0x02,
            calling_tsap[0],
            calling_tsap[1],
            0xC0,
            0x01,
            0x0A, // tpdu size
        ];
        let tpkt_len = (TPKT_HEADER_SIZE + cotp.len()) as u16;
        let mut pkt = vec![0x03, 0x00];
        pkt.extend_from_slice(&tpkt_len.to_be_bytes());
        pkt.append(&mut cotp);
        pkt
    }

    fn goose_or_sv_frame(app_id: u16, payload: &[u8]) -> Vec<u8> {
        let len = (8 + payload.len()) as u16;
        let mut pkt = Vec::new();
        pkt.extend_from_slice(&app_id.to_be_bytes());
        pkt.extend_from_slice(&len.to_be_bytes());
        pkt.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);
        pkt.extend_from_slice(payload);
        pkt
    }

    #[test]
    fn can_parse_mms_on_port_102() {
        let dissector = Iec61850Dissector;
        let pkt = build_tpkt_cotp_mms(&[0x60, 0x01, 0x02, 0x03, 0x04]);
        assert!(dissector.can_parse(&pkt, 50_000, IEC61850_MMS_PORT, None));
    }

    #[test]
    fn parse_mms_extracts_references_and_strings() {
        let dissector = Iec61850Dissector;
        let payload = b"\x60\x1B\xA1\x19IED1LD0/LLN0$ST$Mod.stVal\x00Dataset01\x00";
        let pkt = build_tpkt_cotp_mms(payload);

        let result = dissector.parse(&pkt, 50_000, IEC61850_MMS_PORT, None);
        if let Some(fields) = result {
            assert_eq!(fields.profile, Iec61850Profile::MmsIsoOnTcp);
            assert_eq!(fields.transport, "tpkt_cotp");
            assert_eq!(fields.message_type, "mms");
            assert_eq!(fields.service.as_deref(), Some("initiate_request"));
            assert_eq!(fields.cotp_pdu_type.as_deref(), Some("data_transfer"));
            assert_eq!(fields.ied_name.as_deref(), Some("IED1"));
            assert_eq!(fields.logical_device.as_deref(), Some("IED1LD0"));
            assert_eq!(fields.logical_node.as_deref(), Some("LLN0"));
            assert_eq!(fields.dataset.as_deref(), Some("Dataset01"));
            assert!(
                fields
                    .object_references
                    .iter()
                    .any(|value| value.contains("IED1LD0/LLN0$ST$Mod.stVal"))
            );
            assert!(
                fields
                    .visible_strings
                    .iter()
                    .any(|value| value.contains("Dataset01"))
            );
        } else {
            panic!("expected iec61850 fields");
        }
    }

    #[test]
    fn parse_cotp_connection_request_extracts_tsaps() {
        let dissector = Iec61850Dissector;
        let pkt = build_cotp_connect_packet([0x01, 0x00], [0x03, 0x00]);

        let result = dissector.parse(&pkt, 50_000, IEC61850_MMS_PORT, None);
        if let Some(fields) = result {
            assert_eq!(fields.cotp_pdu_type.as_deref(), Some("connection_request"));
            assert_eq!(fields.called_tsap.as_deref(), Some("0x0100"));
            assert_eq!(fields.calling_tsap.as_deref(), Some("0x0300"));
            assert_eq!(fields.service.as_deref(), Some("cotp_control"));
        } else {
            panic!("expected iec61850 fields");
        }
    }

    #[test]
    fn can_parse_goose_and_sv_ethertypes() {
        let dissector = Iec61850Dissector;
        let goose = goose_or_sv_frame(0x1001, b"\x61\x11gcb1IED2LD1/LLN0$GO$Trip\x00");
        let sv = goose_or_sv_frame(0x1002, b"\x60\x10IED3LD0/LPHD1$SV$Samples\x00");
        assert!(dissector.can_parse(&goose, 0, 0, Some(IEC61850_GOOSE_ETHERTYPE)));
        assert!(dissector.can_parse(&sv, 0, 0, Some(IEC61850_SV_ETHERTYPE)));
    }

    #[test]
    fn parse_goose_extracts_app_id_and_reference_strings() {
        let dissector = Iec61850Dissector;
        let pkt = goose_or_sv_frame(0x1001, b"\x61\x14IED2LD1/LLN0$GO$Trip\x00GoCB01\x00");

        let result = dissector.parse(&pkt, 0, 0, Some(IEC61850_GOOSE_ETHERTYPE));
        if let Some(fields) = result {
            assert_eq!(fields.profile, Iec61850Profile::Goose);
            assert_eq!(fields.transport, "ethernet_goose");
            assert_eq!(fields.app_id, Some(0x1001));
            assert_eq!(fields.message_type, "goose");
            assert!(
                fields
                    .object_references
                    .iter()
                    .any(|value| value.contains("IED2LD1/LLN0$GO$Trip"))
            );
        } else {
            panic!("expected iec61850 fields");
        }
    }

    #[test]
    fn parse_sampled_values_extracts_app_id() {
        let dissector = Iec61850Dissector;
        let pkt = goose_or_sv_frame(0x1002, b"\x60\x14IED3LD0/LPHD1$SV$Samples\x00DatasetSV\x00");

        let result = dissector.parse(&pkt, 0, 0, Some(IEC61850_SV_ETHERTYPE));
        if let Some(fields) = result {
            assert_eq!(fields.profile, Iec61850Profile::SampledValues);
            assert_eq!(fields.transport, "ethernet_sampled_values");
            assert_eq!(fields.message_type, "sampled_values");
            assert_eq!(fields.app_id, Some(0x1002));
            assert!(
                fields
                    .visible_strings
                    .iter()
                    .any(|value| value.contains("DatasetSV"))
            );
        } else {
            panic!("expected iec61850 fields");
        }
    }
}
