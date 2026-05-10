//! CIP Safety decoder for marlinspike-dpi.
//!
//! Detects CIP Safety by recognizing Network Safety Segment (0x50) in
//! Forward_Open connection paths. Safety segment internal fields (Type 1/2/Extended,
//! max_consumer, ping interval) are not parsed in this version — detection is the
//! v1 scope.
//!
//! Shares TCP port 44818 with the EtherNet/IP decoder. Each decoder gets its own
//! copy of the stream; this one ignores everything except CIP service 0x54
//! (Forward_Open) and 0x5B (Large_Forward_Open) that carry segment type 0x50 in
//! their connection path.

use std::collections::{BTreeMap, HashSet};
use std::net::IpAddr;

use crate::bronze::{
    AssetObservation, BronzeEvent, BronzeEventFamily, ProtocolTransaction, TransportProtocol,
};
use crate::engine::{
    build_envelope, new_event, parse_anomaly_event, DecoderInterest, SessionDecoder, StreamChunk,
};

// ── CIP service codes of interest ───────────────────────────────────────────

/// CIP Forward_Open (standard, O→T/T→O params are 2 bytes each).
const SERVICE_FORWARD_OPEN: u8 = 0x54;
/// CIP Large_Forward_Open (O→T/T→O params are 4 bytes each).
const SERVICE_LARGE_FORWARD_OPEN: u8 = 0x5B;
/// Network Safety Segment type byte in a CIP connection path.
// Safety Network Segment: high 3 bits = 010 (Network segment class),
// sub-type 0x10 in the low 5 bits → full byte 0x40 | 0x10 = 0x50.
// Per CIP Vol 5 Ch 5 (Safety) and Wireshark packet-cipsafety.c.
const SAFETY_SEGMENT_TYPE: u8 = 0x50;

// ── EtherNet/IP encapsulation commands we care about ────────────────────────
const CMD_SEND_RR_DATA: u16 = 0x006F;
const CMD_SEND_UNIT_DATA: u16 = 0x0070;

// ── CPF item types ───────────────────────────────────────────────────────────
/// Unconnected Message (UCMM) — carries explicit CIP messages.
const ITEM_UCMM: u16 = 0x00B2;
/// Connected Data — also carries CIP in connected sessions.
const ITEM_CONNECTED_DATA: u16 = 0x00B1;

// ─────────────────────────────────────────────────────────────────────────────

/// State retained across chunks: tracks which destination IPs we have already
/// emitted an AssetObservation for, so we only fire once per safety device.
#[derive(Default)]
pub(crate) struct CipSafetyDecoder {
    seen_safety_devices: HashSet<String>,
}

impl SessionDecoder for CipSafetyDecoder {
    fn name(&self) -> &'static str {
        "cip_safety"
    }

    fn interest(&self) -> &'static [DecoderInterest] {
        &[DecoderInterest::TcpPort(44818)]
    }

    fn on_stream_chunk(&mut self, chunk: &StreamChunk<'_>, out: &mut Vec<BronzeEvent>) {
        let payload = chunk.payload;

        // ── 1. Parse EtherNet/IP encapsulation header (24 bytes, LE) ─────────
        if payload.len() < 24 {
            return;
        }
        let command = u16::from_le_bytes([payload[0], payload[1]]);
        let data_len = u16::from_le_bytes([payload[2], payload[3]]) as usize;

        // Only process commands that carry CIP data.
        if !matches!(command, CMD_SEND_RR_DATA | CMD_SEND_UNIT_DATA) {
            return;
        }
        let cip_region = &payload[24..];
        if cip_region.len() < data_len {
            return;
        }
        let cip_data = &cip_region[..data_len];

        // ── 2. Walk CPF items to find the UCMM / Connected Data item ─────────
        // CPF layout: interface_handle (4) + timeout (2) + item_count (2) + items
        if cip_data.len() < 8 {
            return;
        }
        let item_count = u16::from_le_bytes([cip_data[6], cip_data[7]]) as usize;
        let mut offset = 8usize;

        let mut message: Option<&[u8]> = None;
        for _ in 0..item_count {
            if offset + 4 > cip_data.len() {
                break;
            }
            let item_type = u16::from_le_bytes([cip_data[offset], cip_data[offset + 1]]);
            let item_len = u16::from_le_bytes([cip_data[offset + 2], cip_data[offset + 3]]) as usize;
            offset += 4;
            if offset + item_len > cip_data.len() {
                break;
            }
            if matches!(item_type, ITEM_UCMM | ITEM_CONNECTED_DATA) {
                message = Some(&cip_data[offset..offset + item_len]);
                break;
            }
            offset += item_len;
        }

        let msg = match message {
            Some(m) if !m.is_empty() => m,
            _ => return,
        };

        // ── 3. Check CIP service code ─────────────────────────────────────────
        // Byte 0: service code (request has bit 7 clear; response has bit 7 set).
        let service = msg[0];
        // Ignore responses (bit 7 set).
        if service & 0x80 != 0 {
            return;
        }

        let is_large = match service {
            SERVICE_FORWARD_OPEN => false,
            SERVICE_LARGE_FORWARD_OPEN => true,
            _ => return, // Not a Forward_Open — nothing to do.
        };

        // ── 4. Parse Forward_Open header up to connection_path ────────────────
        // Byte 1: request_path_size (in words). Skip the request path.
        if msg.len() < 2 {
            return;
        }
        let req_path_size_words = msg[1] as usize;
        let req_path_bytes = req_path_size_words * 2;
        let fo_start = 2 + req_path_bytes; // first byte of Forward_Open body

        // Forward_Open fixed fields before connection_path_size:
        //   priority_time_tick (1) + timeout_ticks (1)        = 2
        //   O->T conn ID (4) + T->O conn ID (4)               = 8
        //   connection_serial (2) + vendor_id (2)              = 4
        //   originator_serial (4)                              = 4
        //   conn_timeout_multiplier (1) + reserved (3)         = 4
        //   O->T RPI (4) + O->T net params (2 or 4)           = 6 or 8
        //   T->O RPI (4) + T->O net params (2 or 4)           = 6 or 8
        //   transport_type (1) + connection_path_size (1)      = 2
        //
        // Sum of fixed pre-conn_path fields:
        // priority(1) + timeout(1) + ot_id(4) + to_id(4) + serial(2) + vendor(2) +
        // orig_serial(4) + timeout_mult(1) + reserved(3) + ot_rpi(4) + ot_params(2/4) +
        // to_rpi(4) + to_params(2/4) + transport_type(1) + conn_path_size(1)
        // = 36 standard, 40 large.
        let fixed_body_len: usize = if is_large { 40 } else { 36 };
        let min_msg_len = fo_start + fixed_body_len;

        if msg.len() < min_msg_len {
            // Packet is too short to be a valid Forward_Open — emit ParseAnomaly.
            let envelope = build_envelope(
                &chunk.context,
                chunk.interface_id,
                chunk.frame_index,
                chunk.timestamp,
                chunk.segment_hash,
                TransportProtocol::Tcp,
                Some("cip_safety"),
                chunk.captured_len,
                chunk.session_key.clone(),
            );
            out.push(parse_anomaly_event(
                chunk.capture_id.to_string(),
                envelope,
                "cip_safety",
                "low",
                "truncated Forward_Open: buffer too short for fixed fields",
                msg,
            ));
            return;
        }

        // Extract named fields from the Forward_Open body.
        let b = &msg[fo_start..];

        // b[0]: priority_time_tick, b[1]: timeout_ticks
        let ot_conn_id    = u32::from_le_bytes([b[2],  b[3],  b[4],  b[5]]);
        let _to_conn_id   = u32::from_le_bytes([b[6],  b[7],  b[8],  b[9]]);
        let conn_serial   = u16::from_le_bytes([b[10], b[11]]);
        let vendor_id     = u16::from_le_bytes([b[12], b[13]]);
        let orig_serial   = u32::from_le_bytes([b[14], b[15], b[16], b[17]]);
        // b[18]: conn_timeout_multiplier, b[19..21]: reserved

        let (ot_rpi, to_rpi, transport_type, conn_path_size_words) = if is_large {
            // Large Forward_Open: net params are 4 bytes each.
            let ot_rpi = u32::from_le_bytes([b[22], b[23], b[24], b[25]]);
            // b[26..29]: O->T net params (4 bytes)
            let to_rpi = u32::from_le_bytes([b[30], b[31], b[32], b[33]]);
            // b[34..37]: T->O net params (4 bytes)
            let transport_type = b[38];
            let conn_path_size = b[39] as usize;
            (ot_rpi, to_rpi, transport_type, conn_path_size)
        } else {
            // Standard Forward_Open: net params are 2 bytes each.
            let ot_rpi = u32::from_le_bytes([b[22], b[23], b[24], b[25]]);
            // b[26..27]: O->T net params (2 bytes)
            let to_rpi = u32::from_le_bytes([b[28], b[29], b[30], b[31]]);
            // b[32..33]: T->O net params (2 bytes)
            let transport_type = b[34];
            let conn_path_size = b[35] as usize;
            (ot_rpi, to_rpi, transport_type, conn_path_size)
        };

        let conn_path_bytes = conn_path_size_words * 2;
        let conn_path_start = fo_start + fixed_body_len;

        // ── 5. Validate connection_path fits in buffer ────────────────────────
        if msg.len() < conn_path_start + conn_path_bytes {
            let envelope = build_envelope(
                &chunk.context,
                chunk.interface_id,
                chunk.frame_index,
                chunk.timestamp,
                chunk.segment_hash,
                TransportProtocol::Tcp,
                Some("cip_safety"),
                chunk.captured_len,
                chunk.session_key.clone(),
            );
            out.push(parse_anomaly_event(
                chunk.capture_id.to_string(),
                envelope,
                "cip_safety",
                "low",
                "truncated Forward_Open: connection_path_size exceeds buffer",
                msg,
            ));
            return;
        }

        let conn_path = &msg[conn_path_start..conn_path_start + conn_path_bytes];

        // ── 6. Walk connection path for Network Safety Segment (0x50) ─────────
        // EPATH segments: first byte is the segment type. Walk linearly.
        // Port segment:      type & 0xF0 == 0x00, length from low nibble
        // Logical segment:   type & 0xFC == 0x20 (class/instance/attr/etc.)
        // Network segment:   type & 0xE0 == 0x40
        //   Safety segment = 0x50, followed by 1 byte length-in-words (per CIP spec)
        let mut has_safety = false;
        let mut cp_offset = 0usize;
        while cp_offset < conn_path.len() {
            let seg_type = conn_path[cp_offset];

            if seg_type == SAFETY_SEGMENT_TYPE {
                // Network Safety Segment found.
                has_safety = true;
                break;
            }

            // Advance past this segment. We only need to skip, not parse.
            // Segment type high 3 bits encode the segment class:
            //   000 = Port segment        — variable; byte 1 is link addr size
            //   001 = Logical segment     — format in low 2 bits; 1 or 2 or 4 byte data
            //   010 = Network segment     — byte 1 is segment length in words
            //   011 = Symbolic segment    — variable
            //   100 = Data segment        — byte 1 is length in words
            //   101 = Data type           — fixed 2 bytes
            //   110/111 = reserved
            let class = (seg_type >> 5) & 0x07;
            let advance = match class {
                0b000 => {
                    // Port segment: type(1) + link_addr_size(1) + link_addr(n) + pad
                    if cp_offset + 1 >= conn_path.len() {
                        break;
                    }
                    let link_addr_size = conn_path[cp_offset + 1] as usize;
                    let total = 2 + link_addr_size;
                    // Pad to even
                    if total % 2 != 0 { total + 1 } else { total }
                }
                0b001 => {
                    // Logical segment: format = low 2 bits of seg_type
                    let format = seg_type & 0x03;
                    match format {
                        0x00 => 2, // 8-bit logical value
                        0x01 => 3, // 16-bit logical value (type + pad + 2 bytes)
                        0x02 => 5, // 32-bit logical value (type + pad + 4 bytes)
                        _ => break,
                    }
                }
                0b010 => {
                    // Network segment: type(1) + length_in_words(1) + data
                    if cp_offset + 1 >= conn_path.len() {
                        break;
                    }
                    let words = conn_path[cp_offset + 1] as usize;
                    2 + words * 2
                }
                0b011 => {
                    // Symbolic segment: type(1) + symbol_size(1) + symbol + pad
                    if cp_offset + 1 >= conn_path.len() {
                        break;
                    }
                    let sym_size = conn_path[cp_offset + 1] as usize;
                    let total = 2 + sym_size;
                    if total % 2 != 0 { total + 1 } else { total }
                }
                0b100 | 0b101 => {
                    // Data segment or data type: type(1) + length_in_words(1) + data
                    if cp_offset + 1 >= conn_path.len() {
                        break;
                    }
                    let words = conn_path[cp_offset + 1] as usize;
                    2 + words * 2
                }
                _ => break, // Reserved or unknown — stop walking.
            };

            if advance == 0 {
                break; // Safety guard against infinite loop.
            }
            cp_offset += advance;
        }

        // ── 7. Only emit if a Safety segment was detected ─────────────────────
        if !has_safety {
            return;
        }

        let operation = if is_large {
            "cip_safety_forward_open_large"
        } else {
            "cip_safety_forward_open"
        };

        let mut attributes = BTreeMap::new();
        attributes.insert("service_code".to_string(),     format!("{:#04x}", service));
        attributes.insert("connection_serial".to_string(), format!("{:#06x}", conn_serial));
        attributes.insert("vendor_id".to_string(),        format!("{:#06x}", vendor_id));
        attributes.insert("originator_serial".to_string(), format!("{:#010x}", orig_serial));
        attributes.insert("ot_rpi_us".to_string(),        ot_rpi.to_string());
        attributes.insert("to_rpi_us".to_string(),        to_rpi.to_string());
        attributes.insert("transport_type".to_string(),   format!("{:#04x}", transport_type));
        attributes.insert("safety_segment_present".to_string(), "true".to_string());

        // Suppress unused variable warning — ot_conn_id is available for
        // future use (e.g. tracking connection lifecycle).
        let _ = ot_conn_id;

        let envelope = build_envelope(
            &chunk.context,
            chunk.interface_id,
            chunk.frame_index,
            chunk.timestamp,
            chunk.segment_hash,
            TransportProtocol::Tcp,
            Some("cip_safety"),
            chunk.captured_len,
            chunk.session_key.clone(),
        );

        out.push(new_event(
            chunk.capture_id.to_string(),
            envelope.clone(),
            BronzeEventFamily::ProtocolTransaction(ProtocolTransaction {
                operation: operation.to_string(),
                status: "observed".to_string(),
                request_summary: Some(format!(
                    "{operation} serial={conn_serial:#06x} vendor={vendor_id:#06x}"
                )),
                response_summary: None,
                object_refs: vec!["cip_service:forward_open".to_string(), "cip_safety".to_string()],
                values: Vec::new(),
                attributes,
                modbus: None,
                protocol_fields: None,
            }),
        ));

        // ── 8. AssetObservation — once per destination IP ─────────────────────
        let dst_key = match chunk.context.dst_ip {
            IpAddr::V4(v4) => v4.to_string(),
            IpAddr::V6(v6) => v6.to_string(),
        };
        if !self.seen_safety_devices.contains(&dst_key) {
            self.seen_safety_devices.insert(dst_key.clone());
            let mut identifiers = BTreeMap::new();
            identifiers.insert("ip".to_string(),               dst_key.clone());
            identifiers.insert("cip_vendor_id".to_string(),    format!("{:#06x}", vendor_id));
            identifiers.insert("originator_serial".to_string(), format!("{:#010x}", orig_serial));
            out.push(new_event(
                chunk.capture_id.to_string(),
                envelope,
                BronzeEventFamily::AssetObservation(AssetObservation {
                    asset_key: dst_key,
                    role: Some("cip_safety_device".to_string()),
                    vendor: None,
                    model: None,
                    firmware: None,
                    hostnames: Vec::new(),
                    protocols: vec!["ethernet_ip".to_string(), "cip".to_string(), "cip_safety".to_string()],
                    identifiers,
                }),
            ));
        }
    }
}

inventory::submit!(crate::engine::decoders::DecoderRegistration {
    name: "cip_safety",
    factory: || Box::new(CipSafetyDecoder::default()),
});

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};

    use chrono::Utc;

    use super::*;
    use crate::bronze::BronzeEventFamily;
    use crate::engine::{DecoderInterest, SessionDecoder, StreamChunk};
    use crate::registry::PacketContext;

    // ── Packet builder helpers ────────────────────────────────────────────────

    /// Build a minimal EtherNet/IP SendRRData (0x6F) frame wrapping a CIP
    /// UCMM item. `cip_service_and_body` is everything inside the UCMM item
    /// beginning at the service code byte.
    fn build_enip_frame(cip_service_and_body: &[u8]) -> Vec<u8> {
        // CPF structure:
        //   interface_handle (4) + timeout (2) + item_count (2)
        //   item 0: Null Address  — type 0x0000, len 0x0000  (4 bytes)
        //   item 1: UCMM (0x00B2), len = cip_service_and_body.len()  (4 + data)
        let item_count: u16 = 2;
        let ucmm_len = cip_service_and_body.len() as u16;

        // Build CPF payload.
        let mut cpf: Vec<u8> = Vec::new();
        cpf.extend_from_slice(&0u32.to_le_bytes()); // interface_handle
        cpf.extend_from_slice(&0u16.to_le_bytes()); // timeout
        cpf.extend_from_slice(&item_count.to_le_bytes());
        // Null Address item
        cpf.extend_from_slice(&0x0000u16.to_le_bytes()); // type
        cpf.extend_from_slice(&0x0000u16.to_le_bytes()); // length
        // UCMM item
        cpf.extend_from_slice(&0x00B2u16.to_le_bytes()); // type
        cpf.extend_from_slice(&ucmm_len.to_le_bytes());
        cpf.extend_from_slice(cip_service_and_body);

        // Build EIP encapsulation header.
        let mut frame: Vec<u8> = Vec::new();
        frame.extend_from_slice(&CMD_SEND_RR_DATA.to_le_bytes()); // command 0x6F
        frame.extend_from_slice(&(cpf.len() as u16).to_le_bytes()); // data length
        frame.extend_from_slice(&0x0000_0001u32.to_le_bytes()); // session_handle
        frame.extend_from_slice(&0u32.to_le_bytes());            // status (success)
        frame.extend_from_slice(&[0u8; 8]);                      // sender_context
        frame.extend_from_slice(&0u32.to_le_bytes());            // options
        frame.extend_from_slice(&cpf);

        frame
    }

    /// Build the CIP Forward_Open request bytes (service header + body).
    /// `connection_path` is the raw EPATH bytes (must be even length).
    fn build_forward_open(
        service: u8,
        conn_serial: u16,
        vendor_id: u16,
        orig_serial: u32,
        ot_rpi: u32,
        to_rpi: u32,
        transport_type: u8,
        connection_path: &[u8],
    ) -> Vec<u8> {
        assert!(connection_path.len() % 2 == 0, "connection_path must be word-aligned");
        let conn_path_words = (connection_path.len() / 2) as u8;

        // CIP service header:
        //   byte 0: service code
        //   byte 1: request_path_size (words) — we use 2 words: class(2) + instance(2)
        //   bytes 2..5: EPATH for Connection Manager: 0x20 0x06 0x24 0x01
        let req_path: &[u8] = &[0x20, 0x06, 0x24, 0x01]; // class 0x06 instance 1
        let req_path_words = (req_path.len() / 2) as u8;

        let mut msg: Vec<u8> = Vec::new();
        msg.push(service);
        msg.push(req_path_words);
        msg.extend_from_slice(req_path);

        let is_large = service == SERVICE_LARGE_FORWARD_OPEN;

        // Forward_Open body:
        msg.push(0x0A); // priority_time_tick
        msg.push(0x05); // timeout_ticks
        // O->T network connection ID
        msg.extend_from_slice(&0x1234_5678u32.to_le_bytes());
        // T->O network connection ID
        msg.extend_from_slice(&0x8765_4321u32.to_le_bytes());
        // connection_serial
        msg.extend_from_slice(&conn_serial.to_le_bytes());
        // vendor_id
        msg.extend_from_slice(&vendor_id.to_le_bytes());
        // originator_serial
        msg.extend_from_slice(&orig_serial.to_le_bytes());
        // conn_timeout_multiplier + 3 reserved bytes
        msg.push(0x00);
        msg.extend_from_slice(&[0x00, 0x00, 0x00]);
        // O->T RPI (4 bytes)
        msg.extend_from_slice(&ot_rpi.to_le_bytes());
        // O->T network params
        if is_large {
            msg.extend_from_slice(&0x4200_0000u32.to_le_bytes()); // 4-byte (large)
        } else {
            msg.extend_from_slice(&0x4200u16.to_le_bytes()); // 2-byte (standard)
        }
        // T->O RPI (4 bytes)
        msg.extend_from_slice(&to_rpi.to_le_bytes());
        // T->O network params
        if is_large {
            msg.extend_from_slice(&0x4200_0000u32.to_le_bytes()); // 4-byte
        } else {
            msg.extend_from_slice(&0x4200u16.to_le_bytes()); // 2-byte
        }
        // transport_class_trigger
        msg.push(transport_type);
        // connection_path_size (in words)
        msg.push(conn_path_words);
        // connection path
        msg.extend_from_slice(connection_path);

        msg
    }

    /// Minimal connection path: class 0x06 Connection Manager instance 1.
    /// 4 bytes = 2 words — standard CIP, NO safety segment.
    fn path_no_safety() -> Vec<u8> {
        vec![0x20, 0x06, 0x24, 0x01]
    }

    /// Connection path with a Network Safety Segment (0x50) appended.
    /// Path: class 0x06 inst 1 + safety segment (type 0x50, 1 word body = 2 bytes).
    fn path_with_safety() -> Vec<u8> {
        let mut p = path_no_safety(); // 4 bytes
        // Safety segment: type 0x50 + length 0x01 (1 word = 2 bytes data) + 2 dummy bytes
        p.extend_from_slice(&[0x50, 0x01, 0xAA, 0xBB]);
        p
    }

    fn make_chunk<'a>(
        payload: &'a [u8],
        src_port: u16,
        dst_port: u16,
        dst_ip: Ipv4Addr,
    ) -> StreamChunk<'a> {
        StreamChunk {
            capture_id: "test_cap",
            segment_hash: "deadbeef",
            interface_id: 0,
            frame_index: 1,
            timestamp: Utc::now(),
            context: PacketContext {
                src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
                dst_ip: IpAddr::V4(dst_ip),
                src_port,
                dst_port,
                src_mac: [0u8; 6],
                dst_mac: [0u8; 6],
                vlan_id: None,
                timestamp: 0,
            },
            ethertype: 0x0800,
            ip_proto: Some(6),
            llc: None,
            transport: TransportProtocol::Tcp,
            payload,
            session_key: "sess-cip-safety".to_string(),
            captured_len: payload.len() as u64,
        }
    }

    // ── Test 1 ───────────────────────────────────────────────────────────────
    // Standard Forward_Open (0x54) with Safety segment → ProtocolTransaction +
    // AssetObservation emitted.
    #[test]
    fn test_forward_open_with_safety_segment_emits_events() {
        let mut dec = CipSafetyDecoder::default();
        let mut out = Vec::new();

        let fo = build_forward_open(
            SERVICE_FORWARD_OPEN,
            0xABCD,  // conn_serial
            0x0001,  // vendor_id (Rockwell)
            0xDEAD_BEEF, // orig_serial
            125_000, // ot_rpi  (125 ms in µs)
            125_000, // to_rpi
            0xA3,    // transport_type: class 3 server (safety typical)
            &path_with_safety(),
        );
        let frame = build_enip_frame(&fo);
        let chunk = make_chunk(&frame, 49152, 44818, Ipv4Addr::new(192, 168, 1, 10));
        dec.on_stream_chunk(&chunk, &mut out);

        assert_eq!(out.len(), 2, "expected ProtocolTransaction + AssetObservation; got {}", out.len());

        // First event: ProtocolTransaction.
        let BronzeEventFamily::ProtocolTransaction(ref tx) = out[0].family else {
            panic!("expected ProtocolTransaction, got {:?}", out[0].family_name());
        };
        assert_eq!(tx.operation, "cip_safety_forward_open");
        assert_eq!(tx.status, "observed");
        assert_eq!(tx.attributes.get("safety_segment_present").map(String::as_str), Some("true"));
        assert_eq!(tx.attributes.get("vendor_id").map(String::as_str), Some("0x0001"));
        assert_eq!(tx.attributes.get("connection_serial").map(String::as_str), Some("0xabcd"));

        // Second event: AssetObservation.
        let BronzeEventFamily::AssetObservation(ref ao) = out[1].family else {
            panic!("expected AssetObservation, got {:?}", out[1].family_name());
        };
        assert_eq!(ao.role.as_deref(), Some("cip_safety_device"));
        assert_eq!(ao.vendor, None);
        assert_eq!(ao.asset_key, "192.168.1.10");
        assert!(ao.identifiers.contains_key("cip_vendor_id"));
    }

    // ── Test 2 ───────────────────────────────────────────────────────────────
    // Standard Forward_Open with NO Safety segment → no event emitted.
    #[test]
    fn test_forward_open_without_safety_segment_no_event() {
        let mut dec = CipSafetyDecoder::default();
        let mut out = Vec::new();

        let fo = build_forward_open(
            SERVICE_FORWARD_OPEN,
            0x1111,
            0x0001,
            0x1234_5678,
            100_000,
            100_000,
            0x01,
            &path_no_safety(),
        );
        let frame = build_enip_frame(&fo);
        let chunk = make_chunk(&frame, 49153, 44818, Ipv4Addr::new(192, 168, 1, 20));
        dec.on_stream_chunk(&chunk, &mut out);

        assert!(out.is_empty(), "non-safety Forward_Open must not emit events; got {}", out.len());
    }

    // ── Test 3 ───────────────────────────────────────────────────────────────
    // Large Forward_Open (0x5B) with Safety segment → operation is
    // "cip_safety_forward_open_large".
    #[test]
    fn test_large_forward_open_with_safety_segment() {
        let mut dec = CipSafetyDecoder::default();
        let mut out = Vec::new();

        let fo = build_forward_open(
            SERVICE_LARGE_FORWARD_OPEN,
            0xBEEF,
            0x002A, // some vendor
            0xCAFE_BABE,
            500_000, // 500 ms
            500_000,
            0xA3,
            &path_with_safety(),
        );
        let frame = build_enip_frame(&fo);
        let chunk = make_chunk(&frame, 49154, 44818, Ipv4Addr::new(10, 0, 1, 1));
        dec.on_stream_chunk(&chunk, &mut out);

        assert!(out.len() >= 1, "expected at least one event; got {}", out.len());
        let BronzeEventFamily::ProtocolTransaction(ref tx) = out[0].family else {
            panic!("expected ProtocolTransaction");
        };
        assert_eq!(tx.operation, "cip_safety_forward_open_large");
        assert_eq!(tx.attributes.get("service_code").map(String::as_str), Some("0x5b"));
    }

    // ── Test 4 ───────────────────────────────────────────────────────────────
    // CIP service 0x4E (Forward_Close) → no event emitted.
    #[test]
    fn test_forward_close_service_no_event() {
        let mut dec = CipSafetyDecoder::default();
        let mut out = Vec::new();

        // Build a minimal Forward_Close — service 0x4E, same path segment, rest arbitrary.
        let req_path: &[u8] = &[0x20, 0x06, 0x24, 0x01];
        let mut fc: Vec<u8> = Vec::new();
        fc.push(0x4E); // Forward_Close
        fc.push(2u8);  // req_path_size (2 words)
        fc.extend_from_slice(req_path);
        // Forward_Close body (simplified, no safety check attempted):
        fc.push(0x0A); // priority_time_tick
        fc.push(0x05); // timeout_ticks
        fc.extend_from_slice(&0x1111u16.to_le_bytes()); // connection_serial
        fc.extend_from_slice(&0x0001u16.to_le_bytes()); // vendor_id
        fc.extend_from_slice(&0x1111_1111u32.to_le_bytes()); // orig_serial
        fc.push(0x02); // connection_path_size (1 word)
        fc.extend_from_slice(&path_no_safety());

        let frame = build_enip_frame(&fc);
        let chunk = make_chunk(&frame, 49155, 44818, Ipv4Addr::new(10, 0, 1, 2));
        dec.on_stream_chunk(&chunk, &mut out);

        assert!(out.is_empty(), "Forward_Close must not emit events; got {}", out.len());
    }

    // ── Test 5 ───────────────────────────────────────────────────────────────
    // Truncated Forward_Open (connection_path_size exceeds buffer) → ParseAnomaly
    // with severity "low".
    #[test]
    fn test_truncated_forward_open_emits_parse_anomaly() {
        let mut dec = CipSafetyDecoder::default();
        let mut out = Vec::new();

        // Build a valid Forward_Open up to connection_path_size, then claim a
        // huge connection path (255 words = 510 bytes) that doesn't exist.
        let mut fo = build_forward_open(
            SERVICE_FORWARD_OPEN,
            0x9999,
            0x0001,
            0xAAAA_AAAA,
            100_000,
            100_000,
            0x01,
            &path_no_safety(), // Actual path is 4 bytes (2 words).
        );

        // Patch the connection_path_size byte to claim 255 words.
        // service header: 1 + 1 + 4 = 6 bytes; standard fixed body = 36 bytes.
        // conn_path_size byte is at offset 6 + 36 - 1 = 41.
        let conn_path_size_offset = 6 + 36 - 1;
        fo[conn_path_size_offset] = 0xFF; // claim 255 words (510 bytes)

        let frame = build_enip_frame(&fo);
        let chunk = make_chunk(&frame, 49156, 44818, Ipv4Addr::new(10, 0, 1, 3));
        dec.on_stream_chunk(&chunk, &mut out);

        assert_eq!(out.len(), 1, "expected one ParseAnomaly; got {}", out.len());
        let BronzeEventFamily::ParseAnomaly(ref pa) = out[0].family else {
            panic!("expected ParseAnomaly, got {:?}", out[0].family_name());
        };
        assert_eq!(pa.severity, "low");
        assert_eq!(pa.decoder, "cip_safety");
    }

    // ── Test 6 (bonus) ───────────────────────────────────────────────────────
    // AssetObservation is only emitted once per destination IP even across
    // multiple Safety Forward_Open packets.
    #[test]
    fn test_asset_observation_emitted_once_per_dst_ip() {
        let mut dec = CipSafetyDecoder::default();
        let mut out = Vec::new();
        let dst = Ipv4Addr::new(10, 10, 10, 10);

        for _ in 0..3 {
            let fo = build_forward_open(
                SERVICE_FORWARD_OPEN,
                0x0001,
                0x0001,
                0x0000_0001,
                125_000,
                125_000,
                0xA3,
                &path_with_safety(),
            );
            let frame = build_enip_frame(&fo);
            let chunk = make_chunk(&frame, 50000, 44818, dst);
            dec.on_stream_chunk(&chunk, &mut out);
        }

        let asset_obs_count = out
            .iter()
            .filter(|e| matches!(e.family, BronzeEventFamily::AssetObservation(_)))
            .count();
        assert_eq!(asset_obs_count, 1, "AssetObservation should be emitted exactly once per dst IP");

        let tx_count = out
            .iter()
            .filter(|e| matches!(e.family, BronzeEventFamily::ProtocolTransaction(_)))
            .count();
        assert_eq!(tx_count, 3, "ProtocolTransaction should be emitted once per Forward_Open");
    }

    // ── Test 7 (bonus) ───────────────────────────────────────────────────────
    // Verify DecoderInterest reports TcpPort 44818.
    #[test]
    fn test_decoder_interest_is_tcp_44818() {
        let dec = CipSafetyDecoder::default();
        assert!(
            dec.interest().contains(&DecoderInterest::TcpPort(44818)),
            "must declare interest in TCP 44818"
        );
    }
}
