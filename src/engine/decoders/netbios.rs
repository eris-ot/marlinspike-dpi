//! NetBIOS / NBT decoder — NBNS (UDP 137) and NBDS (UDP 138).
//!
//! NetBIOS Name Service leaks hostnames, workgroup names, domain names, and
//! browser-service roles on virtually every OT/legacy Windows VLAN. This
//! decoder surfaces that data as AssetObservation events, making it a reliable
//! passive asset-identification source even without any active scanning.
//!
//! References: RFC 1001 (concepts), RFC 1002 (wire format).

use std::collections::BTreeMap;
use std::net::{IpAddr, Ipv4Addr};

use crate::bronze::{
    AssetObservation, BronzeEvent, BronzeEventFamily, ParseAnomaly, ProtocolTransaction,
    TransportProtocol,
};
use crate::engine::{
    build_envelope, new_event, parse_anomaly_event, DecoderInterest, SessionDecoder, StreamChunk,
};

// ── Port constants ────────────────────────────────────────────────────────────

const PORT_NBNS: u16 = 137;
const PORT_NBDS: u16 = 138;

// ── Name decoding ─────────────────────────────────────────────────────────────

/// Decode one NetBIOS name from a wire buffer starting at `offset`.
///
/// NetBIOS names are 16 bytes. To make them safe for DNS-label contexts, RFC
/// 1002 §4.1 encodes each byte as TWO ASCII letters: split the byte into high
/// nibble and low nibble, then add 0x41 ('A') to each nibble. The resulting
/// value always falls in [0x41, 0x50] ('A'–'P'), which are all valid DNS label
/// characters.  The 32-character result is length-prefixed with 0x20 (32) and
/// null-terminated, making it look like a single DNS label.
///
/// To decode: read length byte (expect 0x20 = 32). For each pair of encoded
/// chars (hi, lo): byte = ((hi - 0x41) << 4) | (lo - 0x41). The decoded 16
/// bytes are space-padded to 15 chars; byte[15] is the suffix type that
/// identifies the NetBIOS service role.
///
/// Returns `(decoded_bytes_16, bytes_consumed)` or an error string for
/// malformed input.
fn decode_netbios_name(buf: &[u8], offset: usize) -> Result<([u8; 16], usize), &'static str> {
    if offset >= buf.len() {
        return Err("name offset out of bounds");
    }

    let len_byte = buf[offset] as usize;
    if len_byte != 32 {
        // Non-32 length is malformed per RFC 1002. Scope labels (len < 32 after
        // the name) are possible but we only handle the name label here.
        return Err("netbios name length not 32");
    }

    let start = offset + 1;
    let end = start + 32;
    if end > buf.len() {
        return Err("buffer too short for encoded netbios name");
    }

    let encoded = &buf[start..end];

    // Validate that every encoded character is in 'A'..='P' (0x41..=0x50).
    for &b in encoded {
        if !(0x41..=0x50).contains(&b) {
            return Err("encoded netbios name contains non-A-P character");
        }
    }

    let mut decoded = [0u8; 16];
    for i in 0..16 {
        let hi = encoded[i * 2] - 0x41;
        let lo = encoded[i * 2 + 1] - 0x41;
        decoded[i] = (hi << 4) | lo;
    }

    // Total consumed: 1 (length byte) + 32 (encoded chars) + 1 (null terminator if present).
    let null_offset = start + 32;
    let consumed = if null_offset < buf.len() && buf[null_offset] == 0x00 {
        34 // 1 + 32 + 1
    } else {
        33 // 1 + 32, no null
    };

    Ok((decoded, consumed))
}

/// Format decoded 16-byte NetBIOS name as `"NAME<hh>"`.
/// The first 15 bytes are the space-padded name; byte 15 is the suffix.
fn format_netbios_name(decoded: &[u8; 16]) -> String {
    // Strip trailing spaces from the 15-char name portion.
    let name_bytes = &decoded[..15];
    let trimmed = name_bytes
        .iter()
        .rposition(|&b| b != b' ')
        .map(|i| &name_bytes[..=i])
        .unwrap_or(&[][..]);
    let name_str = String::from_utf8_lossy(trimmed);
    let suffix = decoded[15];
    format!("{}<{:02X}>", name_str, suffix)
}

/// Derive asset role from the NetBIOS suffix byte.
fn suffix_to_role(suffix: u8) -> &'static str {
    match suffix {
        0x00 => "netbios_workstation",
        0x03 => "netbios_messenger",
        0x1B => "netbios_domain_master_browser",
        0x1C => "netbios_domain_controllers",
        0x1D => "netbios_master_browser",
        0x1E => "netbios_browser_election",
        0x20 => "netbios_file_server",
        _ => "netbios_node",
    }
}

// ── NBNS header ───────────────────────────────────────────────────────────────

struct NbnsHeader {
    transaction_id: u16,
    flags: u16,
    qdcount: u16,
    ancount: u16,
    nscount: u16,
    arcount: u16,
}

impl NbnsHeader {
    fn parse(buf: &[u8]) -> Option<Self> {
        if buf.len() < 12 {
            return None;
        }
        Some(Self {
            transaction_id: u16::from_be_bytes([buf[0], buf[1]]),
            flags: u16::from_be_bytes([buf[2], buf[3]]),
            qdcount: u16::from_be_bytes([buf[4], buf[5]]),
            ancount: u16::from_be_bytes([buf[6], buf[7]]),
            nscount: u16::from_be_bytes([buf[8], buf[9]]),
            arcount: u16::from_be_bytes([buf[10], buf[11]]),
        })
    }

    /// QR bit (bit 15): 0 = query, 1 = response.
    fn is_response(&self) -> bool {
        self.flags & 0x8000 != 0
    }

    /// Opcode (bits 14:11).
    fn opcode(&self) -> u8 {
        ((self.flags >> 11) & 0x0F) as u8
    }

    /// Rcode (bits 3:0).
    fn rcode(&self) -> u8 {
        (self.flags & 0x000F) as u8
    }

    /// Derive operation string from QR + opcode.
    fn operation(&self) -> &'static str {
        if !self.is_response() {
            return "nbns_query";
        }
        match self.opcode() {
            5 => "nbns_registration",
            6 => "nbns_release",
            7 => "nbns_wack",
            8 => "nbns_refresh",
            _ => "nbns_response",
        }
    }
}

// ── Decoder ───────────────────────────────────────────────────────────────────

#[derive(Default)]
pub(crate) struct NetBiosDecoder;

impl SessionDecoder for NetBiosDecoder {
    fn name(&self) -> &'static str {
        "netbios"
    }

    fn interest(&self) -> &'static [DecoderInterest] {
        &[
            DecoderInterest::UdpPort(PORT_NBNS),
            DecoderInterest::UdpPort(PORT_NBDS),
        ]
    }

    fn on_datagram(&mut self, chunk: &StreamChunk<'_>, out: &mut Vec<BronzeEvent>) {
        let dst = chunk.context.dst_port;
        let src = chunk.context.src_port;
        if dst == PORT_NBNS || src == PORT_NBNS {
            decode_nbns(chunk, out);
        } else if dst == PORT_NBDS || src == PORT_NBDS {
            decode_nbds(chunk, out);
        }
    }
}

// ── NBNS decoder (UDP 137) ────────────────────────────────────────────────────

fn decode_nbns(chunk: &StreamChunk<'_>, out: &mut Vec<BronzeEvent>) {
    let data = chunk.payload;

    let hdr = match NbnsHeader::parse(data) {
        Some(h) => h,
        None => {
            out.push(parse_anomaly_event(
                chunk.capture_id.to_string(),
                build_envelope(
                    &chunk.context,
                    chunk.interface_id,
                    chunk.frame_index,
                    chunk.timestamp,
                    chunk.segment_hash,
                    TransportProtocol::Udp,
                    Some("netbios"),
                    chunk.captured_len,
                    chunk.session_key.clone(),
                ),
                "netbios",
                "low",
                "nbns packet shorter than 12-byte header",
                data,
            ));
            return;
        }
    };

    let envelope = build_envelope(
        &chunk.context,
        chunk.interface_id,
        chunk.frame_index,
        chunk.timestamp,
        chunk.segment_hash,
        TransportProtocol::Udp,
        Some("netbios"),
        chunk.captured_len,
        chunk.session_key.clone(),
    );

    // Walk questions and answers to collect NetBIOS names. We don't need to
    // fully parse the RR wire format — just decode names as we encounter the
    // 0x20-length prefix that RFC 1002 mandates.
    let mut offset = 12usize;
    let mut decoded_names: Vec<String> = Vec::new();
    let total_rrs = (hdr.qdcount as usize)
        .saturating_add(hdr.ancount as usize)
        .saturating_add(hdr.nscount as usize)
        .saturating_add(hdr.arcount as usize);

    let mut anomaly: Option<&'static str> = None;

    'rr: for rr_idx in 0..total_rrs {
        if offset >= data.len() {
            break;
        }

        // Decode the NetBIOS name label.
        match decode_netbios_name(data, offset) {
            Ok((name_bytes, consumed)) => {
                decoded_names.push(format_netbios_name(&name_bytes));
                offset += consumed;
            }
            Err(e) => {
                anomaly = Some(e);
                break 'rr;
            }
        }

        // Skip type (u16) + class (u16) = 4 bytes. For answers there are
        // additional fields (TTL u32, rdlength u16, rdata), but since we only
        // need the names and don't interpret rdata, we stop parsing after all
        // names are collected. In questions there is no rdata.
        if rr_idx < hdr.qdcount as usize {
            // Question section: name + type(2) + class(2).
            offset = offset.saturating_add(4);
        } else {
            // Answer/authority/additional: name + type(2) + class(2) + ttl(4) + rdlength(2) + rdata.
            if offset + 8 > data.len() {
                break;
            }
            let rdlength = u16::from_be_bytes([data[offset + 6], data[offset + 7]]) as usize;
            offset = offset.saturating_add(8 + rdlength);
        }
    }

    // If there's an anomalous name encoding, emit a ParseAnomaly before the
    // transaction so the consumer can correlate them by timestamp.
    if let Some(reason) = anomaly {
        out.push(new_event(
            chunk.capture_id.to_string(),
            envelope.clone(),
            BronzeEventFamily::ParseAnomaly(ParseAnomaly {
                decoder: "netbios".to_string(),
                severity: "low".to_string(),
                reason: reason.to_string(),
                raw_excerpt_hex: hex::encode(&data[..data.len().min(32)]),
            }),
        ));
    }

    let operation = hdr.operation().to_string();
    let status = if hdr.is_response() && hdr.rcode() != 0 {
        format!("nbns_rcode_{}", hdr.rcode())
    } else {
        "observed".to_string()
    };

    let decoded_names_str = decoded_names.join(",");
    let mut attributes = BTreeMap::new();
    attributes.insert("transaction_id".to_string(), hdr.transaction_id.to_string());
    attributes.insert("opcode".to_string(), hdr.opcode().to_string());
    attributes.insert("qdcount".to_string(), hdr.qdcount.to_string());
    attributes.insert("ancount".to_string(), hdr.ancount.to_string());
    attributes.insert("nscount".to_string(), hdr.nscount.to_string());
    attributes.insert("arcount".to_string(), hdr.arcount.to_string());
    attributes.insert("decoded_names".to_string(), decoded_names_str);

    out.push(new_event(
        chunk.capture_id.to_string(),
        envelope.clone(),
        BronzeEventFamily::ProtocolTransaction(ProtocolTransaction {
            operation,
            status,
            request_summary: None,
            response_summary: None,
            object_refs: decoded_names.clone(),
            values: vec![],
            attributes,
            modbus: None,
            protocol_fields: None,
        }),
    ));

    // Emit one AssetObservation per unique decoded name.
    for name_str in &decoded_names {
        let suffix_hex = &name_str[name_str.len() - 3..name_str.len() - 1]; // "hh" from "<hh>"
        let suffix_byte = u8::from_str_radix(suffix_hex, 16).unwrap_or(0xFF);
        let role = suffix_to_role(suffix_byte);

        // Trimmed name without the <HH> suffix for the hostname field.
        let trimmed = name_str
            .find('<')
            .map(|i| &name_str[..i])
            .unwrap_or(name_str.as_str())
            .to_string();

        let mut identifiers = BTreeMap::from([(
            "ip".to_string(),
            chunk.context.src_ip.to_string(),
        )]);
        identifiers.insert("netbios_name".to_string(), name_str.clone());
        identifiers.insert("netbios_suffix_hex".to_string(), suffix_hex.to_lowercase());

        out.push(new_event(
            chunk.capture_id.to_string(),
            envelope.clone(),
            BronzeEventFamily::AssetObservation(AssetObservation {
                asset_key: chunk.context.src_ip.to_string(),
                role: Some(role.to_string()),
                vendor: None,
                model: None,
                firmware: None,
                hostnames: vec![trimmed],
                protocols: vec!["netbios".to_string()],
                identifiers,
            }),
        ));
    }
}

// ── NBDS decoder (UDP 138) ────────────────────────────────────────────────────

fn decode_nbds(chunk: &StreamChunk<'_>, out: &mut Vec<BronzeEvent>) {
    let data = chunk.payload;

    // Minimum NBDS header: msg_type(1) + flags(1) + datagram_id(2) +
    // source_ip(4) + source_port(2) = 10 bytes. Direct/broadcast messages add
    // dgm_length(2) + packet_offset(2) = 14 bytes before the names.
    if data.len() < 10 {
        out.push(parse_anomaly_event(
            chunk.capture_id.to_string(),
            build_envelope(
                &chunk.context,
                chunk.interface_id,
                chunk.frame_index,
                chunk.timestamp,
                chunk.segment_hash,
                TransportProtocol::Udp,
                Some("netbios"),
                chunk.captured_len,
                chunk.session_key.clone(),
            ),
            "netbios",
            "low",
            "nbds packet shorter than 10-byte header",
            data,
        ));
        return;
    }

    let msg_type = data[0];
    let datagram_id = u16::from_be_bytes([data[2], data[3]]);
    let source_ip = Ipv4Addr::new(data[4], data[5], data[6], data[7]);
    let source_port = u16::from_be_bytes([data[8], data[9]]);

    let operation = match msg_type {
        0x10 => "nbds_direct_unique",
        0x11 => "nbds_direct_group",
        0x12 => "nbds_broadcast",
        other => return emit_nbds_unknown(chunk, out, other),
    };

    // Direct/broadcast messages: 4 more bytes before names.
    let names_offset = if data.len() >= 14 { 14 } else { 10 };
    let mut offset = names_offset;

    let envelope = build_envelope(
        &chunk.context,
        chunk.interface_id,
        chunk.frame_index,
        chunk.timestamp,
        chunk.segment_hash,
        TransportProtocol::Udp,
        Some("netbios"),
        chunk.captured_len,
        chunk.session_key.clone(),
    );

    // Source name.
    let (src_name_bytes, src_consumed) = match decode_netbios_name(data, offset) {
        Ok(v) => v,
        Err(reason) => {
            out.push(new_event(
                chunk.capture_id.to_string(),
                envelope,
                BronzeEventFamily::ParseAnomaly(ParseAnomaly {
                    decoder: "netbios".to_string(),
                    severity: "low".to_string(),
                    reason: reason.to_string(),
                    raw_excerpt_hex: hex::encode(&data[..data.len().min(32)]),
                }),
            ));
            return;
        }
    };
    let source_name = format_netbios_name(&src_name_bytes);
    offset += src_consumed;

    // Destination name (best-effort; may be absent in truncated datagrams).
    let dest_name = if offset < data.len() {
        match decode_netbios_name(data, offset) {
            Ok((bytes, _)) => format_netbios_name(&bytes),
            Err(_) => String::new(),
        }
    } else {
        String::new()
    };

    let mut attributes = BTreeMap::new();
    attributes.insert("datagram_id".to_string(), datagram_id.to_string());
    attributes.insert("source_ip".to_string(), source_ip.to_string());
    attributes.insert("source_port".to_string(), source_port.to_string());
    attributes.insert("source_name".to_string(), source_name.clone());
    attributes.insert("dest_name".to_string(), dest_name.clone());

    out.push(new_event(
        chunk.capture_id.to_string(),
        envelope.clone(),
        BronzeEventFamily::ProtocolTransaction(ProtocolTransaction {
            operation: operation.to_string(),
            status: "observed".to_string(),
            request_summary: None,
            response_summary: None,
            object_refs: vec![source_name.clone(), dest_name],
            values: vec![],
            attributes,
            modbus: None,
            protocol_fields: None,
        }),
    ));

    // AssetObservation for the source node.
    let suffix_hex = &source_name[source_name.len() - 3..source_name.len() - 1];
    let suffix_byte = u8::from_str_radix(suffix_hex, 16).unwrap_or(0xFF);
    let role = suffix_to_role(suffix_byte);
    let trimmed_src = source_name
        .find('<')
        .map(|i| &source_name[..i])
        .unwrap_or(source_name.as_str())
        .to_string();

    let mut identifiers = BTreeMap::from([(
        "ip".to_string(),
        IpAddr::V4(source_ip).to_string(),
    )]);
    identifiers.insert("netbios_name".to_string(), source_name.clone());
    identifiers.insert("netbios_suffix_hex".to_string(), suffix_hex.to_lowercase());

    out.push(new_event(
        chunk.capture_id.to_string(),
        envelope,
        BronzeEventFamily::AssetObservation(AssetObservation {
            asset_key: IpAddr::V4(source_ip).to_string(),
            role: Some(role.to_string()),
            vendor: None,
            model: None,
            firmware: None,
            hostnames: vec![trimmed_src],
            protocols: vec!["netbios".to_string()],
            identifiers,
        }),
    ));
}

fn emit_nbds_unknown(chunk: &StreamChunk<'_>, out: &mut Vec<BronzeEvent>, msg_type: u8) {
    let envelope = build_envelope(
        &chunk.context,
        chunk.interface_id,
        chunk.frame_index,
        chunk.timestamp,
        chunk.segment_hash,
        TransportProtocol::Udp,
        Some("netbios"),
        chunk.captured_len,
        chunk.session_key.clone(),
    );
    out.push(new_event(
        chunk.capture_id.to_string(),
        envelope,
        BronzeEventFamily::ProtocolTransaction(ProtocolTransaction {
            operation: format!("nbds_unknown_0x{:02x}", msg_type),
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

// ── Inventory registration ────────────────────────────────────────────────────

inventory::submit!(crate::engine::decoders::DecoderRegistration {
    name: "netbios",
    factory: || Box::new(NetBiosDecoder::default()),
});

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::registry::PacketContext;
    use chrono::Utc;

    // ── Test infrastructure ───────────────────────────────────────────────────

    fn make_chunk<'a>(payload: &'a [u8], src_port: u16, dst_port: u16) -> StreamChunk<'a> {
        StreamChunk {
            capture_id: "test",
            segment_hash: "seg",
            interface_id: 0,
            frame_index: 0,
            timestamp: Utc::now(),
            context: PacketContext {
                src_mac: [0u8; 6],
                dst_mac: [0u8; 6],
                src_ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10)),
                dst_ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 255)),
                src_port,
                dst_port,
                vlan_id: None,
                timestamp: 0,
            },
            ethertype: 0x0800,
            ip_proto: Some(17),
            llc: None,
            transport: TransportProtocol::Udp,
            payload,
            session_key: "sess".to_string(),
            captured_len: payload.len() as u64,
        }
    }

    /// Encode a NetBIOS name for the wire. `name` must be ≤ 15 bytes; it is
    /// space-padded; `suffix` becomes byte[15]. Returns the 34-byte label:
    /// 0x20 (length) + 32 encoded chars + 0x00 (null terminator).
    fn encode_netbios_name(name: &str, suffix: u8) -> Vec<u8> {
        let mut raw = [b' '; 16];
        let nb = name.as_bytes();
        let copy_len = nb.len().min(15);
        raw[..copy_len].copy_from_slice(&nb[..copy_len]);
        raw[15] = suffix;

        // Each byte → two chars: high nibble + 0x41, low nibble + 0x41.
        let mut encoded = Vec::with_capacity(34);
        encoded.push(0x20u8); // length = 32
        for &b in &raw {
            encoded.push(0x41 + (b >> 4));
            encoded.push(0x41 + (b & 0x0F));
        }
        encoded.push(0x00); // null terminator
        encoded
    }

    /// Build a minimal NBNS query packet: header + one question with the given
    /// name/suffix, NB type (0x0020), IN class (0x0001).
    fn nbns_query(name: &str, suffix: u8) -> Vec<u8> {
        let mut pkt = vec![
            0x00, 0x01, // transaction_id = 1
            0x01, 0x10, // flags: QR=0 (query), opcode=0, RD=1, B=1
            0x00, 0x01, // qdcount = 1
            0x00, 0x00, // ancount = 0
            0x00, 0x00, // nscount = 0
            0x00, 0x00, // arcount = 0
        ];
        pkt.extend(encode_netbios_name(name, suffix));
        pkt.extend_from_slice(&[0x00, 0x20, 0x00, 0x01]); // type NB, class IN
        pkt
    }

    /// Build a minimal NBNS response with one answer RR. The answer rdata is
    /// 6 bytes (flags u16 + IP u32) per RFC 1002.
    fn nbns_response(name: &str, suffix: u8, rcode: u8) -> Vec<u8> {
        let flags_hi = 0x85u8; // QR=1, AA=1, opcode=0
        let flags_lo = rcode & 0x0F;
        let mut pkt = vec![
            0x00, 0x02,     // transaction_id = 2
            flags_hi, flags_lo,
            0x00, 0x00,     // qdcount = 0
            0x00, 0x01,     // ancount = 1
            0x00, 0x00,     // nscount = 0
            0x00, 0x00,     // arcount = 0
        ];
        pkt.extend(encode_netbios_name(name, suffix));
        // type NB (0x0020), class IN (0x0001), TTL (4 bytes), rdlength = 6.
        pkt.extend_from_slice(&[0x00, 0x20, 0x00, 0x01, 0x00, 0x00, 0x04, 0xB0, 0x00, 0x06]);
        // rdata: NB flags (2) + owner IP (4).
        pkt.extend_from_slice(&[0x00, 0x00, 0xC0, 0xA8, 0x01, 0x0A]);
        pkt
    }

    /// Build a minimal NBNS registration (opcode=5 in response).
    fn nbns_registration(name: &str, suffix: u8) -> Vec<u8> {
        let mut pkt = vec![
            0x00, 0x03,     // transaction_id = 3
            0xAD, 0x00,     // QR=1, opcode=5 (registration), AA=1
            0x00, 0x00,     // qdcount = 0
            0x00, 0x01,     // ancount = 1
            0x00, 0x00,
            0x00, 0x00,
        ];
        pkt.extend(encode_netbios_name(name, suffix));
        pkt.extend_from_slice(&[0x00, 0x20, 0x00, 0x01, 0x00, 0x00, 0x04, 0xB0, 0x00, 0x06]);
        pkt.extend_from_slice(&[0x60, 0x00, 0xC0, 0xA8, 0x01, 0x0A]);
        pkt
    }

    /// Build a minimal NBDS datagram with source + dest names.
    fn nbds_datagram(msg_type: u8, src_name: &str, src_suffix: u8, dst_name: &str, dst_suffix: u8) -> Vec<u8> {
        let mut pkt = vec![
            msg_type,           // msg_type
            0x02,               // flags: first fragment
            0xAB, 0xCD,         // datagram_id
            192, 168, 1, 20,    // source_ip
            0x00, 0x8A,         // source_port = 138
            0x00, 0x50,         // dgm_length = 80
            0x00, 0x00,         // packet_offset = 0
        ];
        pkt.extend(encode_netbios_name(src_name, src_suffix));
        pkt.extend(encode_netbios_name(dst_name, dst_suffix));
        pkt
    }

    // ── Test 1: NBNS query for WORKSTATION<00> ────────────────────────────────

    #[test]
    fn nbns_query_workstation_00() {
        let payload = nbns_query("WORKSTATION", 0x00);
        let chunk = make_chunk(&payload, 1025, PORT_NBNS);
        let mut out = Vec::new();
        let mut dec = NetBiosDecoder::default();
        dec.on_datagram(&chunk, &mut out);

        // Expect ProtocolTransaction + AssetObservation.
        assert!(out.len() >= 2, "expected at least 2 events, got {}", out.len());

        let tx = out.iter().find_map(|e| {
            if let BronzeEventFamily::ProtocolTransaction(tx) = &e.family { Some(tx) } else { None }
        }).expect("no ProtocolTransaction");

        assert_eq!(tx.operation, "nbns_query");
        assert_eq!(tx.status, "observed");
        assert!(
            tx.attributes.get("decoded_names").unwrap().contains("WORKSTATION<00>"),
            "decoded_names={:?}", tx.attributes.get("decoded_names")
        );
        assert!(tx.object_refs.iter().any(|r| r.contains("WORKSTATION<00>")));

        let obs = out.iter().find_map(|e| {
            if let BronzeEventFamily::AssetObservation(o) = &e.family { Some(o) } else { None }
        }).expect("no AssetObservation");

        assert_eq!(obs.role.as_deref(), Some("netbios_workstation"));
        assert!(obs.hostnames.iter().any(|h| h == "WORKSTATION"), "hostnames={:?}", obs.hostnames);
    }

    // ── Test 2: NBNS response for FILESERVER<20> ─────────────────────────────

    #[test]
    fn nbns_response_file_server_20() {
        let payload = nbns_response("FILESERVER", 0x20, 0);
        let chunk = make_chunk(&payload, PORT_NBNS, 1025);
        let mut out = Vec::new();
        let mut dec = NetBiosDecoder::default();
        dec.on_datagram(&chunk, &mut out);

        let tx = out.iter().find_map(|e| {
            if let BronzeEventFamily::ProtocolTransaction(tx) = &e.family { Some(tx) } else { None }
        }).expect("no ProtocolTransaction");

        assert_eq!(tx.operation, "nbns_response");
        assert_eq!(tx.status, "observed");

        let obs = out.iter().find_map(|e| {
            if let BronzeEventFamily::AssetObservation(o) = &e.family { Some(o) } else { None }
        }).expect("no AssetObservation");

        assert_eq!(obs.role.as_deref(), Some("netbios_file_server"));
        assert!(obs.hostnames.iter().any(|h| h == "FILESERVER"));
    }

    // ── Test 3: NBNS query for DOMAIN<1C> (domain controllers) ───────────────

    #[test]
    fn nbns_query_domain_controllers_1c() {
        let payload = nbns_query("DOMAIN", 0x1C);
        let chunk = make_chunk(&payload, 1025, PORT_NBNS);
        let mut out = Vec::new();
        let mut dec = NetBiosDecoder::default();
        dec.on_datagram(&chunk, &mut out);

        let obs = out.iter().find_map(|e| {
            if let BronzeEventFamily::AssetObservation(o) = &e.family { Some(o) } else { None }
        }).expect("no AssetObservation");

        assert_eq!(obs.role.as_deref(), Some("netbios_domain_controllers"));
        let ids = &obs.identifiers;
        assert!(ids.get("netbios_name").map(|n| n.contains("1C")).unwrap_or(false));
        assert_eq!(ids.get("netbios_suffix_hex").map(|s| s.as_str()), Some("1c"));
    }

    // ── Test 4: NBDS direct-group message ────────────────────────────────────

    #[test]
    fn nbds_direct_group_names_captured() {
        let payload = nbds_datagram(0x11, "SRCHOST", 0x00, "WORKGROUP", 0x1E);
        let chunk = make_chunk(&payload, PORT_NBDS, PORT_NBDS);
        let mut out = Vec::new();
        let mut dec = NetBiosDecoder::default();
        dec.on_datagram(&chunk, &mut out);

        let tx = out.iter().find_map(|e| {
            if let BronzeEventFamily::ProtocolTransaction(tx) = &e.family { Some(tx) } else { None }
        }).expect("no ProtocolTransaction");

        assert_eq!(tx.operation, "nbds_direct_group");
        assert_eq!(tx.status, "observed");

        let src = tx.attributes.get("source_name").expect("source_name missing");
        let dst = tx.attributes.get("dest_name").expect("dest_name missing");
        assert!(src.contains("SRCHOST"), "source_name={src}");
        assert!(dst.contains("WORKGROUP"), "dest_name={dst}");

        // Both names appear in object_refs.
        assert!(tx.object_refs.iter().any(|r| r.contains("SRCHOST")));
        assert!(tx.object_refs.iter().any(|r| r.contains("WORKGROUP")));

        // AssetObservation for the source.
        let obs = out.iter().find_map(|e| {
            if let BronzeEventFamily::AssetObservation(o) = &e.family { Some(o) } else { None }
        }).expect("no AssetObservation");
        assert_eq!(obs.role.as_deref(), Some("netbios_workstation")); // suffix 0x00
    }

    // ── Test 5: NBNS registration (opcode=5) ─────────────────────────────────

    #[test]
    fn nbns_registration_opcode5() {
        let payload = nbns_registration("MYSERVER", 0x20);
        let chunk = make_chunk(&payload, PORT_NBNS, PORT_NBNS);
        let mut out = Vec::new();
        let mut dec = NetBiosDecoder::default();
        dec.on_datagram(&chunk, &mut out);

        let tx = out.iter().find_map(|e| {
            if let BronzeEventFamily::ProtocolTransaction(tx) = &e.family { Some(tx) } else { None }
        }).expect("no ProtocolTransaction");

        assert_eq!(tx.operation, "nbns_registration");
    }

    // ── Test 6: Malformed name (encoded length ≠ 32) → ParseAnomaly ──────────

    #[test]
    fn malformed_name_emits_parse_anomaly() {
        // Build an NBNS query where the name label length byte is 0x10 (16),
        // not 0x20 (32), triggering the "netbios name length not 32" branch.
        let mut pkt = vec![
            0x00, 0x04, // transaction_id
            0x01, 0x10, // flags: query
            0x00, 0x01, // qdcount = 1
            0x00, 0x00,
            0x00, 0x00,
            0x00, 0x00,
        ];
        pkt.push(0x10); // wrong length byte (16 instead of 32)
        pkt.extend_from_slice(b"AAAAAAAAAAAAAAAA"); // 16 chars, not 32
        pkt.push(0x00); // null
        pkt.extend_from_slice(&[0x00, 0x20, 0x00, 0x01]);

        let chunk = make_chunk(&pkt, 1025, PORT_NBNS);
        let mut out = Vec::new();
        let mut dec = NetBiosDecoder::default();
        dec.on_datagram(&chunk, &mut out);

        let anomaly = out.iter().find_map(|e| {
            if let BronzeEventFamily::ParseAnomaly(a) = &e.family { Some(a) } else { None }
        }).expect("expected a ParseAnomaly event");

        assert_eq!(anomaly.severity, "low");
        assert_eq!(anomaly.decoder, "netbios");
    }
}
