//! PCCC PDU parser + stateful TNS correlation.
//!
//! After CIP service 0x4B (Execute PCCC), the embedded payload is:
//!   requestor_id          (variable; 1-byte length prefix + bytes; on the
//!                          wire ENIP-CIP-PCCC the first byte is the length
//!                          of the requestor_id including itself, typically 7)
//!   cmd                   (1 byte)
//!   sts                   (1 byte; 0 in requests, status in responses)
//!   tns                   (2 bytes little-endian — transaction number)
//!   function              (request only; 1 byte for many functions)
//!   data...               (variable — depends on function)
//!
//! Functions of interest for VQT extraction:
//!   - 0x67  Protected Typed Logical Read with Three Address Fields  (PLC-5/SLC)
//!   - 0x68  Protected Typed Logical Write with Three Address Fields
//!   - 0xA2  Typed Read (newer)
//!   - 0xAB  Typed Write (newer)
//!
//! Address layout for 0x67/0x68:
//!   byte_size (1) + file_number (1) + file_type (1) + element (1)
//!   + sub_element (1)
//!
//! When element/file_number need >1 byte they're prefixed by 0xFF and the
//! actual value follows in 2 bytes — we handle the common 1-byte form here
//! and skip exotic encodings (returning None for unknown patterns).

use std::collections::HashMap;
use std::net::IpAddr;

use crate::bronze::{
    BRONZE_SCHEMA_VERSION, BronzeEvent, BronzeEventFamily, EventEnvelope, PointIdentifier,
    PointValue, ProcessReading, RawQuality,
};

const SOURCE_PROTOCOL: &str = "pccc";

/// PCCC commands relevant to data-table I/O.
const CMD_PROTECTED_TYPED_LOGICAL: u8 = 0x0F;
const FN_PROTECTED_TYPED_READ: u8 = 0x68;
const FN_PROTECTED_TYPED_WRITE: u8 = 0x67;

/// PCCC file type codes (subset). The full table is large — these are the
/// numeric/bool families a historian typically wants.
pub const FT_BIT: u8 = 0x85;
pub const FT_TIMER: u8 = 0x86;
pub const FT_COUNTER: u8 = 0x87;
pub const FT_INTEGER: u8 = 0x89;
pub const FT_FLOAT: u8 = 0x8A;

/// Decoded PCCC PDU header (cmd/sts/tns).
#[derive(Debug, Clone, Copy)]
pub struct PcccHeader {
    pub cmd: u8,
    pub sts: u8,
    pub tns: u16,
}

/// Decoded PCCC address (file_type / file_number / element / sub_element).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PcccAddress {
    pub file_type: u8,
    pub file_number: u8,
    pub element: u16,
    pub sub_element: Option<u8>,
}

/// Cursor helpers for PCCC (little-endian).
fn read_u8(b: &[u8], i: &mut usize) -> Option<u8> {
    let v = *b.get(*i)?;
    *i += 1;
    Some(v)
}
fn read_u16_le(b: &[u8], i: &mut usize) -> Option<u16> {
    if *i + 2 > b.len() {
        return None;
    }
    let v = u16::from_le_bytes([b[*i], b[*i + 1]]);
    *i += 2;
    Some(v)
}
fn read_i16_le(b: &[u8], i: &mut usize) -> Option<i16> {
    Some(read_u16_le(b, i)? as i16)
}
fn read_f32_le(b: &[u8], i: &mut usize) -> Option<f32> {
    if *i + 4 > b.len() {
        return None;
    }
    let v = f32::from_le_bytes([b[*i], b[*i + 1], b[*i + 2], b[*i + 3]]);
    *i += 4;
    Some(v)
}

/// Read the PCCC PDU header. Caller has already advanced past the
/// requestor_id (`Execute PCCC` carries that as a 1-byte-length-prefixed
/// blob immediately before the cmd byte).
pub fn read_header(bytes: &[u8], offset: &mut usize) -> Option<PcccHeader> {
    let cmd = read_u8(bytes, offset)?;
    let sts = read_u8(bytes, offset)?;
    let tns = read_u16_le(bytes, offset)?;
    Some(PcccHeader { cmd, sts, tns })
}

/// Strip the PCCC `requestor_id` prefix (length-prefixed blob). Returns
/// `Some(())` if successful; `None` if the bytes are too short.
pub fn skip_requestor_id(bytes: &[u8], offset: &mut usize) -> Option<()> {
    let len = read_u8(bytes, offset)? as usize;
    if len == 0 {
        return Some(());
    }
    // The length byte counts itself; skip the remaining bytes.
    let to_skip = len.saturating_sub(1);
    if *offset + to_skip > bytes.len() {
        return None;
    }
    *offset += to_skip;
    Some(())
}

/// Read a PCCC three-address-field address: byte_size + file_number +
/// file_type + element + sub_element. Each field uses 1 byte, with the 0xFF
/// escape promoting it to a following 2-byte little-endian value.
pub fn read_three_address(bytes: &[u8], offset: &mut usize) -> Option<PcccAddress> {
    let _byte_size = read_one_or_extended(bytes, offset)?;
    let file_number = read_one_or_extended(bytes, offset)? as u8;
    let file_type = read_u8(bytes, offset)?;
    let element = read_one_or_extended(bytes, offset)?;
    let sub = read_one_or_extended(bytes, offset)?;
    let sub_element = if sub == 0 { None } else { Some(sub as u8) };
    Some(PcccAddress {
        file_type,
        file_number,
        element,
        sub_element,
    })
}

/// Read a PCCC byte that may be 0xFF-extended to a u16. Returns the u16 value.
fn read_one_or_extended(bytes: &[u8], offset: &mut usize) -> Option<u16> {
    let b = read_u8(bytes, offset)?;
    if b == 0xFF {
        read_u16_le(bytes, offset)
    } else {
        Some(b as u16)
    }
}

/// One pending request keyed by `(src_ip, tns)`. We store the address(es)
/// being read so the matching response can be paired into ProcessReadings.
#[derive(Debug, Clone)]
struct Pending {
    /// Number of elements requested.
    quantity: u16,
    /// Starting address.
    start: PcccAddress,
}

#[derive(Default)]
pub struct PcccDecoder {
    pending: HashMap<(IpAddr, u16), Pending>,
    event_id_counter: u64,
}

impl PcccDecoder {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn pending_count(&self) -> usize {
        self.pending.len()
    }

    fn next_event_id(&mut self) -> String {
        self.event_id_counter = self.event_id_counter.wrapping_add(1);
        format!("pccc-{}", self.event_id_counter)
    }

    /// Process one PCCC PDU lifted from CIP service 0x4B.
    /// `is_request` distinguishes request vs response (caller knows from the
    /// CIP service header bit). `client_ip` is the side that sent the request
    /// — used as part of the correlation key so multiple clients don't collide.
    pub fn handle_pdu(
        &mut self,
        bytes: &[u8],
        is_request: bool,
        client_ip: IpAddr,
        envelope: &EventEnvelope,
        capture_id: &str,
    ) -> Vec<BronzeEvent> {
        let mut offset = 0;
        if skip_requestor_id(bytes, &mut offset).is_none() {
            return Vec::new();
        }
        let Some(header) = read_header(bytes, &mut offset) else {
            return Vec::new();
        };
        let body = &bytes[offset..];

        if is_request && header.cmd == CMD_PROTECTED_TYPED_LOGICAL {
            self.handle_request(header, body, client_ip);
            return Vec::new();
        }
        if !is_request {
            return self.handle_response(header, body, client_ip, envelope, capture_id);
        }
        Vec::new()
    }

    fn handle_request(&mut self, header: PcccHeader, body: &[u8], client_ip: IpAddr) {
        let mut i = 0;
        let Some(function) = read_u8(body, &mut i) else {
            return;
        };
        match function {
            FN_PROTECTED_TYPED_READ => {
                // body after function: byte_size (1) + tns echo (2)? actually:
                // function 0x68 layout: byte_size(1) + file_number(1) +
                // file_type(1) + element(1) + sub_element(1)
                // (PLC-5/SLC variant). Some firmwares use 0xFF-extended forms.
                let Some(byte_size) = read_u8(body, &mut i) else {
                    return;
                };
                let address_start = i;
                let Some(addr) = read_three_address_from_function_body(body, &mut i) else {
                    return;
                };
                let _ = address_start;
                // byte_size is total bytes to read including all sub-elements.
                // Element width depends on file_type — INT=2, FLOAT=4, BIT=2.
                let elem_width = element_width(addr.file_type);
                let quantity = if elem_width == 0 {
                    1
                } else {
                    (byte_size as u16 / elem_width as u16).max(1)
                };
                self.pending.insert(
                    (client_ip, header.tns),
                    Pending {
                        quantity,
                        start: addr,
                    },
                );
            }
            FN_PROTECTED_TYPED_WRITE => {
                // We don't currently emit ProcessReading for writes — would
                // need to also track the values. Future work; skip silently.
            }
            _ => {}
        }
    }

    fn handle_response(
        &mut self,
        header: PcccHeader,
        body: &[u8],
        client_ip: IpAddr,
        envelope: &EventEnvelope,
        capture_id: &str,
    ) -> Vec<BronzeEvent> {
        let Some(pending) = self.pending.remove(&(client_ip, header.tns)) else {
            return Vec::new();
        };
        if header.sts != 0 {
            // Error response; emit an empty-value reading per pending element
            // would be misleading. Surface the failure as zero readings —
            // embedder can correlate via the matching ProtocolTransaction.
            return Vec::new();
        }
        let mut readings = Vec::with_capacity(pending.quantity as usize);
        let mut i = 0;
        let observed_ts = envelope_us(envelope);
        for n in 0..pending.quantity {
            let value = match decode_value(body, &mut i, pending.start.file_type) {
                Some(v) => v,
                None => break,
            };
            let address = PcccAddress {
                element: pending.start.element + n,
                ..pending.start
            };
            readings.push(self.make_event(address, value, envelope, capture_id, observed_ts));
        }
        readings
    }

    fn make_event(
        &mut self,
        address: PcccAddress,
        value: PointValue,
        envelope: &EventEnvelope,
        capture_id: &str,
        observed_ts: u64,
    ) -> BronzeEvent {
        BronzeEvent {
            event_id: self.next_event_id(),
            capture_id: capture_id.to_string(),
            schema_version: BRONZE_SCHEMA_VERSION.into(),
            envelope: envelope.clone(),
            family: BronzeEventFamily::ProcessReading(ProcessReading {
                source_protocol: SOURCE_PROTOCOL.into(),
                point_id: PointIdentifier::PcccAddress {
                    file_type: address.file_type,
                    file_number: address.file_number,
                    element: address.element,
                    sub_element: address.sub_element,
                },
                value,
                quality: RawQuality::CipGeneralStatus(0),
                source_ts: None, // PCCC doesn't carry per-value timestamps
                observed_ts,
            }),
        }
    }
}

fn read_three_address_from_function_body(bytes: &[u8], offset: &mut usize) -> Option<PcccAddress> {
    // For function 0x67/0x68 the address fields follow byte_size with
    // file_number, file_type, element, sub_element. byte_size already read
    // by caller.
    let file_number = read_one_or_extended(bytes, offset)? as u8;
    let file_type = read_u8(bytes, offset)?;
    let element = read_one_or_extended(bytes, offset)?;
    let sub = read_one_or_extended(bytes, offset)?;
    let sub_element = if sub == 0 { None } else { Some(sub as u8) };
    Some(PcccAddress {
        file_type,
        file_number,
        element,
        sub_element,
    })
}

fn element_width(file_type: u8) -> u8 {
    match file_type {
        FT_INTEGER | FT_BIT => 2,
        FT_FLOAT => 4,
        FT_TIMER | FT_COUNTER => 6, // 3 words
        _ => 0,
    }
}

fn decode_value(bytes: &[u8], offset: &mut usize, file_type: u8) -> Option<PointValue> {
    match file_type {
        FT_INTEGER => Some(PointValue::Int16(read_i16_le(bytes, offset)?)),
        FT_BIT => Some(PointValue::UInt16(read_u16_le(bytes, offset)?)),
        FT_FLOAT => Some(PointValue::Float(read_f32_le(bytes, offset)?)),
        _ => None,
    }
}

fn envelope_us(env: &EventEnvelope) -> u64 {
    let nanos = env.timestamp.timestamp_nanos_opt().unwrap_or(0);
    if nanos < 0 { 0 } else { (nanos / 1_000) as u64 }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bronze::TransportProtocol;
    use chrono::{DateTime, Utc};
    use std::net::Ipv4Addr;

    fn envelope() -> EventEnvelope {
        EventEnvelope {
            timestamp: DateTime::<Utc>::from_timestamp(1_700_000_000, 1_000).unwrap(),
            interface_id: 0,
            segment_hash: "seg".into(),
            frame_index: 0,
            session_key: "k".into(),
            src_mac: None,
            dst_mac: None,
            src_ip: None,
            dst_ip: None,
            src_port: None,
            dst_port: None,
            vlan_id: None,
            transport: TransportProtocol::Tcp,
            protocol: Some("pccc".into()),
            bytes_count: 0,
            packet_count: 1,
        }
    }

    /// Build a typed-read PCCC request PDU: requestor_id (1 byte len = 7
    /// followed by 6 bytes), then cmd=0x0F sts=0 tns + function=0x68 +
    /// byte_size + file_number + file_type + element + sub_element.
    fn build_read_request(
        tns: u16,
        byte_size: u8,
        file_number: u8,
        file_type: u8,
        element: u8,
    ) -> Vec<u8> {
        let mut b = Vec::new();
        b.push(7); // length of requestor_id including itself
        b.extend_from_slice(&[0x00, 0x00, 0x00, 0x07, 0x05, 0x09]); // 6 bytes
        b.push(0x0F); // cmd
        b.push(0x00); // sts
        b.extend_from_slice(&tns.to_le_bytes());
        b.push(0x68); // function = Protected Typed Logical Read
        b.push(byte_size);
        b.push(file_number);
        b.push(file_type);
        b.push(element);
        b.push(0); // sub-element
        b
    }

    fn build_read_response(tns: u16, body: &[u8]) -> Vec<u8> {
        let mut b = Vec::new();
        b.push(7);
        b.extend_from_slice(&[0x00, 0x00, 0x00, 0x07, 0x05, 0x09]);
        b.push(0x4F); // command + reply bit (0x40 OR'd in)
        b.push(0x00); // sts = success
        b.extend_from_slice(&tns.to_le_bytes());
        b.extend_from_slice(body);
        b
    }

    #[test]
    fn reads_one_int16_value() {
        let mut d = PcccDecoder::new();
        let client: IpAddr = Ipv4Addr::new(10, 0, 0, 5).into();
        let env = envelope();
        let req = build_read_request(0x1234, 2, 7, FT_INTEGER, 5);
        let _ = d.handle_pdu(&req, true, client, &env, "cap");
        assert_eq!(d.pending_count(), 1);
        let resp = build_read_response(0x1234, &(2350i16).to_le_bytes());
        let events = d.handle_pdu(&resp, false, client, &env, "cap");
        assert_eq!(events.len(), 1);
        match &events[0].family {
            BronzeEventFamily::ProcessReading(r) => {
                assert_eq!(r.value, PointValue::Int16(2350));
                assert!(matches!(
                    r.point_id,
                    PointIdentifier::PcccAddress {
                        file_type: FT_INTEGER,
                        file_number: 7,
                        element: 5,
                        sub_element: None
                    }
                ));
            }
            _ => panic!(),
        }
        assert_eq!(d.pending_count(), 0);
    }

    #[test]
    fn reads_three_int16_values_emits_three_readings() {
        let mut d = PcccDecoder::new();
        let client: IpAddr = Ipv4Addr::new(10, 0, 0, 5).into();
        let env = envelope();
        let req = build_read_request(1, 6, 7, FT_INTEGER, 0); // 3 elements × 2 bytes
        let _ = d.handle_pdu(&req, true, client, &env, "cap");
        let mut body = Vec::new();
        body.extend_from_slice(&100i16.to_le_bytes());
        body.extend_from_slice(&200i16.to_le_bytes());
        body.extend_from_slice(&300i16.to_le_bytes());
        let resp = build_read_response(1, &body);
        let events = d.handle_pdu(&resp, false, client, &env, "cap");
        assert_eq!(events.len(), 3);
        for (i, ev) in events.iter().enumerate() {
            match &ev.family {
                BronzeEventFamily::ProcessReading(r) => match &r.point_id {
                    PointIdentifier::PcccAddress { element, .. } => {
                        assert_eq!(*element, i as u16);
                    }
                    _ => panic!(),
                },
                _ => panic!(),
            }
        }
    }

    #[test]
    fn float_file_decodes_as_f32() {
        let mut d = PcccDecoder::new();
        let client: IpAddr = Ipv4Addr::new(10, 0, 0, 5).into();
        let env = envelope();
        let req = build_read_request(7, 4, 8, FT_FLOAT, 0);
        let _ = d.handle_pdu(&req, true, client, &env, "cap");
        let resp = build_read_response(7, &72.5f32.to_le_bytes());
        let events = d.handle_pdu(&resp, false, client, &env, "cap");
        assert_eq!(events.len(), 1);
        if let BronzeEventFamily::ProcessReading(r) = &events[0].family {
            assert_eq!(r.value, PointValue::Float(72.5));
        }
    }

    #[test]
    fn response_without_request_emits_nothing() {
        let mut d = PcccDecoder::new();
        let client: IpAddr = Ipv4Addr::new(10, 0, 0, 5).into();
        let env = envelope();
        let resp = build_read_response(99, &(1i16).to_le_bytes());
        let events = d.handle_pdu(&resp, false, client, &env, "cap");
        assert!(events.is_empty());
    }

    #[test]
    fn different_client_ips_do_not_cross_pollinate() {
        let mut d = PcccDecoder::new();
        let env = envelope();
        let a: IpAddr = Ipv4Addr::new(10, 0, 0, 1).into();
        let b: IpAddr = Ipv4Addr::new(10, 0, 0, 2).into();
        let _ = d.handle_pdu(
            &build_read_request(5, 2, 7, FT_INTEGER, 0),
            true,
            a,
            &env,
            "cap",
        );
        // Response from a different client with the same TNS should not match.
        let events = d.handle_pdu(
            &build_read_response(5, &1i16.to_le_bytes()),
            false,
            b,
            &env,
            "cap",
        );
        assert!(events.is_empty());
        assert_eq!(d.pending_count(), 1);
    }

    #[test]
    fn error_response_emits_no_readings() {
        let mut d = PcccDecoder::new();
        let client: IpAddr = Ipv4Addr::new(10, 0, 0, 5).into();
        let env = envelope();
        let _ = d.handle_pdu(
            &build_read_request(3, 2, 7, FT_INTEGER, 0),
            true,
            client,
            &env,
            "cap",
        );
        // Response with non-zero status.
        let mut bytes = Vec::new();
        bytes.push(7);
        bytes.extend_from_slice(&[0u8; 6]);
        bytes.push(0x4F); // cmd + reply bit
        bytes.push(0x10); // sts = illegal command
        bytes.extend_from_slice(&3u16.to_le_bytes());
        let events = d.handle_pdu(&bytes, false, client, &env, "cap");
        assert!(events.is_empty());
        assert_eq!(d.pending_count(), 0); // request consumed
    }
}
