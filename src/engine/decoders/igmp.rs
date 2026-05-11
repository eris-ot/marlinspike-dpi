//! IGMP (Internet Group Management Protocol) deep decoder.
//!
//! Implements RFC 2236 (IGMPv2) and RFC 3376 (IGMPv3) full parse.
//!
//! # Wire format — IGMPv1/v2 (8 bytes fixed)
//!
//! ```text
//! byte  0     : type
//! byte  1     : max-resp-time (v1/v2) or max-resp-code (v3 Query, float-encoded if MSB set)
//! bytes 2..4  : checksum u16 BE (not validated)
//! bytes 4..8  : group-address u32 BE (0.0.0.0 for general query)
//! ```
//!
//! # IGMPv3 Membership Query (RFC 3376 §4.1) — 12+ bytes
//!
//! Bytes 0–7 as above, then:
//! ```text
//! byte  8     : reserved(4)|S(1)|QRV(3)
//! byte  9     : QQIC (float-encoded if MSB set)
//! bytes 10..12: number-of-sources N u16 BE
//! N × 4 bytes : source addresses
//! ```
//!
//! # IGMPv3 Membership Report — type 0x22 (RFC 3376 §4.2)
//!
//! ```text
//! byte  0     : 0x22
//! byte  1     : reserved
//! bytes 2..4  : checksum
//! bytes 4..6  : reserved
//! bytes 6..8  : number-of-group-records M u16 BE
//! M × Group Records, each:
//!   byte  0   : record-type
//!   byte  1   : aux-data-len (32-bit words)
//!   bytes 2..4: number-of-sources N u16 BE
//!   bytes 4..8: multicast-group address u32 BE
//!   N × 4-byte source addresses
//!   aux-data-len*4 aux bytes
//! ```

use std::collections::BTreeMap;
use std::net::Ipv4Addr;

use crate::bronze::{
    BronzeEvent, BronzeEventFamily, ProtocolTransaction, TopologyObservation, TransportProtocol,
};
use crate::engine::{
    build_envelope, new_event, parse_anomaly_event, DecoderInterest, SessionDecoder, StreamChunk,
};

// ── Type constants ────────────────────────────────────────────────────────────

const TYPE_MEMBERSHIP_QUERY: u8 = 0x11;
const TYPE_V1_MEMBERSHIP_REPORT: u8 = 0x12;
const TYPE_V2_MEMBERSHIP_REPORT: u8 = 0x16;
const TYPE_LEAVE_GROUP: u8 = 0x17;
const TYPE_V3_MEMBERSHIP_REPORT: u8 = 0x22;

// IGMPv3 group-record record-types (RFC 3376 §4.2.12)
const RT_MODE_IS_INCLUDE: u8 = 1;
const RT_MODE_IS_EXCLUDE: u8 = 2;
const RT_CHANGE_TO_INCLUDE: u8 = 3;
const RT_CHANGE_TO_EXCLUDE: u8 = 4;
const RT_ALLOW_NEW_SOURCES: u8 = 5;
const RT_BLOCK_OLD_SOURCES: u8 = 6;

// Minimum lengths
const MIN_V1V2_LEN: usize = 8;
const MIN_V3_QUERY_LEN: usize = 12;
const V3_REPORT_HDR_LEN: usize = 8;
const GROUP_RECORD_HDR_LEN: usize = 8;

// ── Float-encoded time (RFC 3376 §4.1.1) ─────────────────────────────────────

/// Decode a float-encoded byte value (used for max-resp-code and QQIC in v3).
/// If MSB is 0, the value is the byte itself.
/// If MSB is 1: value = (mant | 0x10) << (exp + 3), where exp = (byte >> 4) & 0x7, mant = byte & 0x0F.
#[inline]
fn decode_float_time(byte: u8) -> u32 {
    if byte & 0x80 == 0 {
        u32::from(byte)
    } else {
        let exp = u32::from((byte >> 4) & 0x07);
        let mant = u32::from(byte & 0x0F);
        (mant | 0x10) << (exp + 3)
    }
}

// ── Helpers ───────────────────────────────────────────────────────────────────

fn record_type_name(rt: u8) -> &'static str {
    match rt {
        RT_MODE_IS_INCLUDE => "mode_is_include",
        RT_MODE_IS_EXCLUDE => "mode_is_exclude",
        RT_CHANGE_TO_INCLUDE => "change_to_include",
        RT_CHANGE_TO_EXCLUDE => "change_to_exclude",
        RT_ALLOW_NEW_SOURCES => "allow_new_sources",
        RT_BLOCK_OLD_SOURCES => "block_old_sources",
        _ => "unknown",
    }
}

/// Returns true for record types that represent join/interest (adding membership).
fn is_join_record_type(rt: u8) -> bool {
    matches!(rt, RT_MODE_IS_INCLUDE | RT_CHANGE_TO_INCLUDE | RT_ALLOW_NEW_SOURCES)
}

fn ip_from_u32(addr: u32) -> String {
    Ipv4Addr::from(addr).to_string()
}

fn read_u16_be(buf: &[u8], off: usize) -> Option<u16> {
    buf.get(off..off + 2)
        .map(|b| u16::from_be_bytes([b[0], b[1]]))
}

fn read_u32_be(buf: &[u8], off: usize) -> Option<u32> {
    buf.get(off..off + 4)
        .map(|b| u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
}

// ── Parsed structures ─────────────────────────────────────────────────────────

struct IgmpV3GroupRecord {
    record_type: u8,
    #[allow(dead_code)]
    num_sources: u16,
    group_addr: u32,
    #[allow(dead_code)]
    source_addrs: Vec<u32>,
}

// ── Decoder ───────────────────────────────────────────────────────────────────

/// IGMPv2 (RFC 2236) + IGMPv3 (RFC 3376) deep decoder.
/// Registered on IP protocol 2.
#[derive(Default)]
pub(crate) struct IgmpDecoder;

inventory::submit!(crate::engine::decoders::DecoderRegistration {
    name: "igmp",
    factory: || Box::new(IgmpDecoder),
});

impl SessionDecoder for IgmpDecoder {
    fn name(&self) -> &'static str {
        "igmp"
    }

    fn interest(&self) -> &'static [DecoderInterest] {
        &[DecoderInterest::IpProto(2)]
    }

    fn on_datagram(&mut self, chunk: &StreamChunk<'_>, out: &mut Vec<BronzeEvent>) {
        let data = chunk.payload;

        if data.is_empty() {
            out.push(anomaly(chunk, "low", "empty IGMP datagram", data));
            return;
        }

        if data.len() < MIN_V1V2_LEN {
            out.push(anomaly(chunk, "low", "IGMP datagram shorter than 8-byte minimum", data));
            return;
        }

        let igmp_type = data[0];

        match igmp_type {
            TYPE_MEMBERSHIP_QUERY => self.decode_query(chunk, data, out),
            TYPE_V1_MEMBERSHIP_REPORT => self.decode_v1_report(chunk, data, out),
            TYPE_V2_MEMBERSHIP_REPORT => self.decode_v2_report(chunk, data, out),
            TYPE_LEAVE_GROUP => self.decode_leave(chunk, data, out),
            TYPE_V3_MEMBERSHIP_REPORT => self.decode_v3_report(chunk, data, out),
            other => {
                out.push(anomaly(
                    chunk,
                    "low",
                    &format!("unknown IGMP type {other:#04x}"),
                    data,
                ));
            }
        }
    }
}

impl IgmpDecoder {
    // ── Membership Query (0x11) ───────────────────────────────────────────────

    fn decode_query(&self, chunk: &StreamChunk<'_>, data: &[u8], out: &mut Vec<BronzeEvent>) {
        let max_resp_code_raw = data[1];
        // group address at bytes 4..8
        let group_addr = read_u32_be(data, 4).unwrap_or(0);
        let group_str = ip_from_u32(group_addr);

        // Determine query kind and version
        let (query_kind, version, attrs) = if data.len() >= MIN_V3_QUERY_LEN {
            // IGMPv3 query
            let max_resp_decoded = decode_float_time(max_resp_code_raw);
            let flags_byte = data[8];
            let s_flag = (flags_byte >> 3) & 0x01;
            let qrv = flags_byte & 0x07;
            let qqic_raw = data[9];
            let qqic = decode_float_time(qqic_raw);
            let num_sources = read_u16_be(data, 10).unwrap_or(0);

            // Parse source addresses
            let mut source_addrs: Vec<String> = Vec::with_capacity(num_sources as usize);
            let sources_end = 12 + num_sources as usize * 4;
            if sources_end <= data.len() {
                for i in 0..num_sources as usize {
                    if let Some(addr) = read_u32_be(data, 12 + i * 4) {
                        source_addrs.push(ip_from_u32(addr));
                    }
                }
            } else {
                out.push(anomaly(
                    chunk,
                    "low",
                    "IGMPv3 query: source address list truncated",
                    data,
                ));
            }

            let kind = if group_addr == 0 {
                "general"
            } else if num_sources == 0 {
                "group_specific"
            } else {
                "group_and_source_specific"
            };

            let mut a: BTreeMap<String, String> = BTreeMap::new();
            a.insert("version".to_string(), "3".to_string());
            a.insert("query_kind".to_string(), kind.to_string());
            a.insert("group_address".to_string(), group_str.clone());
            a.insert("max_resp_code_decisec".to_string(), max_resp_decoded.to_string());
            a.insert("s_flag".to_string(), s_flag.to_string());
            a.insert("qrv".to_string(), qrv.to_string());
            a.insert("qqic".to_string(), qqic.to_string());
            a.insert("source_count".to_string(), num_sources.to_string());
            if !source_addrs.is_empty() {
                a.insert("source_addresses".to_string(), source_addrs.join(","));
            }

            (kind, 3u8, a)
        } else {
            // IGMPv1/v2 query
            let max_resp_time = max_resp_code_raw;
            let kind = if group_addr == 0 {
                "general"
            } else {
                "group_specific"
            };
            let ver: u8 = if max_resp_time == 0 { 1 } else { 2 };

            let mut a: BTreeMap<String, String> = BTreeMap::new();
            a.insert("version".to_string(), ver.to_string());
            a.insert("query_kind".to_string(), kind.to_string());
            a.insert("group_address".to_string(), group_str.clone());
            a.insert("max_resp_time_decisec".to_string(), max_resp_time.to_string());

            (kind, ver, a)
        };

        let _ = version; // used in attrs

        let envelope = mk_envelope(chunk);
        let src_str = chunk.context.src_ip.to_string();
        let object_refs = if group_addr != 0 {
            vec![group_str.clone()]
        } else {
            vec![]
        };

        out.push(new_event(
            chunk.capture_id.to_string(),
            envelope,
            BronzeEventFamily::ProtocolTransaction(ProtocolTransaction {
                operation: "igmp_membership_query".to_string(),
                status: "observed".to_string(),
                request_summary: Some(format!(
                    "IGMP Membership Query kind={query_kind} group={group_str}"
                )),
                response_summary: None,
                object_refs,
                values: vec![],
                attributes: attrs,
                modbus: None,
                protocol_fields: None,
            }),
        ));

        let _ = src_str;
    }

    // ── IGMPv1 Membership Report (0x12) ───────────────────────────────────────

    fn decode_v1_report(&self, chunk: &StreamChunk<'_>, data: &[u8], out: &mut Vec<BronzeEvent>) {
        let group_addr = read_u32_be(data, 4).unwrap_or(0);
        let group_str = ip_from_u32(group_addr);
        let src_str = chunk.context.src_ip.to_string();

        let mut attrs: BTreeMap<String, String> = BTreeMap::new();
        attrs.insert("version".to_string(), "1".to_string());
        attrs.insert("group_address".to_string(), group_str.clone());

        let envelope = mk_envelope(chunk);
        out.push(new_event(
            chunk.capture_id.to_string(),
            envelope.clone(),
            BronzeEventFamily::ProtocolTransaction(ProtocolTransaction {
                operation: "igmp_v1_membership_report".to_string(),
                status: "observed".to_string(),
                request_summary: Some(format!("IGMPv1 Report group={group_str}")),
                response_summary: None,
                object_refs: vec![group_str.clone()],
                values: vec![],
                attributes: attrs,
                modbus: None,
                protocol_fields: None,
            }),
        ));

        // TopologyObservation: multicast join
        emit_multicast_join(chunk, envelope, src_str, group_str, out);
    }

    // ── IGMPv2 Membership Report (0x16) ───────────────────────────────────────

    fn decode_v2_report(&self, chunk: &StreamChunk<'_>, data: &[u8], out: &mut Vec<BronzeEvent>) {
        let max_resp_time = data[1];
        let group_addr = read_u32_be(data, 4).unwrap_or(0);
        let group_str = ip_from_u32(group_addr);
        let src_str = chunk.context.src_ip.to_string();

        let mut attrs: BTreeMap<String, String> = BTreeMap::new();
        attrs.insert("version".to_string(), "2".to_string());
        attrs.insert("group_address".to_string(), group_str.clone());
        attrs.insert("max_resp_time_decisec".to_string(), max_resp_time.to_string());

        let envelope = mk_envelope(chunk);
        out.push(new_event(
            chunk.capture_id.to_string(),
            envelope.clone(),
            BronzeEventFamily::ProtocolTransaction(ProtocolTransaction {
                operation: "igmp_v2_membership_report".to_string(),
                status: "observed".to_string(),
                request_summary: Some(format!("IGMPv2 Report group={group_str}")),
                response_summary: None,
                object_refs: vec![group_str.clone()],
                values: vec![],
                attributes: attrs,
                modbus: None,
                protocol_fields: None,
            }),
        ));

        // TopologyObservation: multicast join
        emit_multicast_join(chunk, envelope, src_str, group_str, out);
    }

    // ── IGMPv2 Leave Group (0x17) ─────────────────────────────────────────────

    fn decode_leave(&self, chunk: &StreamChunk<'_>, data: &[u8], out: &mut Vec<BronzeEvent>) {
        let group_addr = read_u32_be(data, 4).unwrap_or(0);
        let group_str = ip_from_u32(group_addr);

        let mut attrs: BTreeMap<String, String> = BTreeMap::new();
        attrs.insert("version".to_string(), "2".to_string());
        attrs.insert("group_address".to_string(), group_str.clone());

        let envelope = mk_envelope(chunk);
        out.push(new_event(
            chunk.capture_id.to_string(),
            envelope,
            BronzeEventFamily::ProtocolTransaction(ProtocolTransaction {
                operation: "igmp_leave_group".to_string(),
                status: "observed".to_string(),
                request_summary: Some(format!("IGMPv2 Leave Group group={group_str}")),
                response_summary: None,
                object_refs: vec![group_str],
                values: vec![],
                attributes: attrs,
                modbus: None,
                protocol_fields: None,
            }),
        ));
    }

    // ── IGMPv3 Membership Report (0x22) ───────────────────────────────────────

    fn decode_v3_report(&self, chunk: &StreamChunk<'_>, data: &[u8], out: &mut Vec<BronzeEvent>) {
        if data.len() < V3_REPORT_HDR_LEN {
            out.push(anomaly(
                chunk,
                "low",
                "IGMPv3 report truncated: shorter than 8-byte header",
                data,
            ));
            return;
        }

        let num_records = read_u16_be(data, 6).unwrap_or(0);
        let mut records: Vec<IgmpV3GroupRecord> = Vec::with_capacity(num_records as usize);
        let mut pos = V3_REPORT_HDR_LEN;
        let mut record_parse_error = false;

        for _ in 0..num_records {
            if pos + GROUP_RECORD_HDR_LEN > data.len() {
                record_parse_error = true;
                break;
            }
            let record_type = data[pos];
            let aux_data_len = data[pos + 1] as usize; // in 32-bit words
            let num_sources = read_u16_be(data, pos + 2).unwrap_or(0);
            let group_addr = read_u32_be(data, pos + 4).unwrap_or(0);

            pos += GROUP_RECORD_HDR_LEN;

            // Parse source addresses
            let sources_end = pos + num_sources as usize * 4;
            if sources_end > data.len() {
                record_parse_error = true;
                break;
            }
            let mut source_addrs: Vec<u32> = Vec::with_capacity(num_sources as usize);
            for i in 0..num_sources as usize {
                if let Some(addr) = read_u32_be(data, pos + i * 4) {
                    source_addrs.push(addr);
                }
            }
            pos = sources_end + aux_data_len * 4;

            records.push(IgmpV3GroupRecord {
                record_type,
                num_sources,
                group_addr,
                source_addrs,
            });
        }

        if record_parse_error {
            out.push(anomaly(
                chunk,
                "low",
                "IGMPv3 report: group record list truncated or malformed",
                data,
            ));
        }

        // Count records by type for attributes
        let mut rt_counts: BTreeMap<String, u32> = BTreeMap::new();
        let mut group_refs: Vec<String> = Vec::new();

        for rec in &records {
            let rt_name = record_type_name(rec.record_type);
            *rt_counts.entry(rt_name.to_string()).or_insert(0) += 1;
            let group_str = ip_from_u32(rec.group_addr);
            if !group_refs.contains(&group_str) {
                group_refs.push(group_str);
            }
        }

        let mut attrs: BTreeMap<String, String> = BTreeMap::new();
        attrs.insert("version".to_string(), "3".to_string());
        attrs.insert("record_count".to_string(), records.len().to_string());
        for (rt_name, count) in &rt_counts {
            attrs.insert(
                format!("record_type_{rt_name}_count"),
                count.to_string(),
            );
        }

        let envelope = mk_envelope(chunk);
        out.push(new_event(
            chunk.capture_id.to_string(),
            envelope.clone(),
            BronzeEventFamily::ProtocolTransaction(ProtocolTransaction {
                operation: "igmp_v3_membership_report".to_string(),
                status: "observed".to_string(),
                request_summary: Some(format!(
                    "IGMPv3 Report records={}",
                    records.len()
                )),
                response_summary: None,
                object_refs: group_refs,
                values: vec![],
                attributes: attrs,
                modbus: None,
                protocol_fields: None,
            }),
        ));

        // TopologyObservation for join-style records
        let src_str = chunk.context.src_ip.to_string();
        for rec in &records {
            if is_join_record_type(rec.record_type) {
                let group_str = ip_from_u32(rec.group_addr);
                emit_multicast_join(chunk, envelope.clone(), src_str.clone(), group_str, out);
            }
        }
    }
}

// ── Module-level helpers ──────────────────────────────────────────────────────

fn mk_envelope(chunk: &StreamChunk<'_>) -> crate::bronze::EventEnvelope {
    build_envelope(
        &chunk.context,
        chunk.interface_id,
        chunk.frame_index,
        chunk.timestamp,
        chunk.segment_hash,
        TransportProtocol::Udp,
        Some("igmp"),
        chunk.captured_len,
        chunk.session_key.clone(),
    )
}

fn anomaly(chunk: &StreamChunk<'_>, severity: &str, reason: &str, data: &[u8]) -> BronzeEvent {
    parse_anomaly_event(
        chunk.capture_id.to_string(),
        mk_envelope(chunk),
        "igmp",
        severity,
        reason,
        data,
    )
}

fn emit_multicast_join(
    chunk: &StreamChunk<'_>,
    envelope: crate::bronze::EventEnvelope,
    src_ip: String,
    group_addr: String,
    out: &mut Vec<BronzeEvent>,
) {
    out.push(new_event(
        chunk.capture_id.to_string(),
        envelope,
        BronzeEventFamily::TopologyObservation(TopologyObservation {
            observation_type: "multicast_join".to_string(),
            local_id: src_ip,
            remote_id: Some(group_addr),
            description: None,
            capabilities: vec![],
            metadata: BTreeMap::new(),
        }),
    ));
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    use chrono::Utc;

    use crate::bronze::{BronzeEventFamily, ParseAnomaly, ProtocolTransaction, TopologyObservation};
    use crate::engine::{DecoderInterest, SessionDecoder, StreamChunk};
    use crate::registry::PacketContext;

    // ── Test helpers ──────────────────────────────────────────────────────────

    fn ctx(src: [u8; 4]) -> PacketContext {
        PacketContext {
            src_mac: [0u8; 6],
            dst_mac: [0u8; 6],
            src_ip: IpAddr::V4(Ipv4Addr::from(src)),
            dst_ip: IpAddr::V4(Ipv4Addr::new(224, 0, 0, 1)),
            src_port: 0,
            dst_port: 0,
            vlan_id: None,
            timestamp: 0,
        }
    }

    fn chunk<'a>(payload: &'a [u8], ctx: PacketContext) -> StreamChunk<'a> {
        StreamChunk {
            capture_id: "test",
            segment_hash: "seg",
            interface_id: 0,
            frame_index: 0,
            timestamp: Utc::now(),
            context: ctx,
            ethertype: 0x0800,
            ip_proto: Some(2),
            llc: None,
            transport: TransportProtocol::Udp,
            payload,
            session_key: "igmp-sk".to_string(),
            captured_len: payload.len() as u64,
        }
    }

    fn get_tx(evs: &[BronzeEvent]) -> Vec<&ProtocolTransaction> {
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

    fn get_topo(evs: &[BronzeEvent]) -> Vec<&TopologyObservation> {
        evs.iter()
            .filter_map(|e| {
                if let BronzeEventFamily::TopologyObservation(ref t) = e.family {
                    Some(t)
                } else {
                    None
                }
            })
            .collect()
    }

    fn get_anomaly(evs: &[BronzeEvent]) -> Vec<&ParseAnomaly> {
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

    // Build a standard IGMPv1/v2 8-byte datagram.
    fn igmp_v2(igmp_type: u8, max_resp: u8, group: [u8; 4]) -> Vec<u8> {
        let mut v = vec![igmp_type, max_resp, 0x00, 0x00];
        v.extend_from_slice(&group);
        v
    }

    // ── Test 1: IGMPv2 General Query ─────────────────────────────────────────

    #[test]
    fn v2_general_query() {
        let pkt = igmp_v2(TYPE_MEMBERSHIP_QUERY, 100, [0, 0, 0, 0]);
        let mut dec = IgmpDecoder;
        let mut out = Vec::new();
        dec.on_datagram(&chunk(&pkt, ctx([10, 0, 0, 1])), &mut out);

        let txs = get_tx(&out);
        assert_eq!(txs.len(), 1);
        let tx = txs[0];
        assert_eq!(tx.operation, "igmp_membership_query");
        assert_eq!(tx.attributes.get("query_kind").map(String::as_str), Some("general"));
        assert_eq!(tx.attributes.get("group_address").map(String::as_str), Some("0.0.0.0"));
        assert_eq!(tx.attributes.get("version").map(String::as_str), Some("2"));
    }

    // ── Test 2: IGMPv2 Group-Specific Query ──────────────────────────────────

    #[test]
    fn v2_group_specific_query() {
        let pkt = igmp_v2(TYPE_MEMBERSHIP_QUERY, 50, [239, 1, 2, 3]);
        let mut dec = IgmpDecoder;
        let mut out = Vec::new();
        dec.on_datagram(&chunk(&pkt, ctx([10, 0, 0, 1])), &mut out);

        let txs = get_tx(&out);
        assert_eq!(txs.len(), 1);
        let tx = txs[0];
        assert_eq!(tx.operation, "igmp_membership_query");
        assert_eq!(tx.attributes.get("query_kind").map(String::as_str), Some("group_specific"));
        assert_eq!(
            tx.attributes.get("group_address").map(String::as_str),
            Some("239.1.2.3")
        );
        // object_refs should contain the group
        assert!(tx.object_refs.contains(&"239.1.2.3".to_string()));
    }

    // ── Test 3: IGMPv2 Membership Report ─────────────────────────────────────

    #[test]
    fn v2_membership_report() {
        let pkt = igmp_v2(TYPE_V2_MEMBERSHIP_REPORT, 0, [239, 255, 0, 1]);
        let mut dec = IgmpDecoder;
        let mut out = Vec::new();
        dec.on_datagram(&chunk(&pkt, ctx([192, 168, 1, 10])), &mut out);

        let txs = get_tx(&out);
        assert_eq!(txs.len(), 1);
        assert_eq!(txs[0].operation, "igmp_v2_membership_report");
        assert_eq!(
            txs[0].attributes.get("group_address").map(String::as_str),
            Some("239.255.0.1")
        );

        // TopologyObservation for multicast_join
        let topos = get_topo(&out);
        assert_eq!(topos.len(), 1);
        assert_eq!(topos[0].observation_type, "multicast_join");
        assert_eq!(topos[0].local_id, "192.168.1.10");
        assert_eq!(topos[0].remote_id.as_deref(), Some("239.255.0.1"));
    }

    // ── Test 4: IGMPv2 Leave Group ────────────────────────────────────────────

    #[test]
    fn v2_leave_group() {
        let pkt = igmp_v2(TYPE_LEAVE_GROUP, 0, [239, 0, 0, 5]);
        let mut dec = IgmpDecoder;
        let mut out = Vec::new();
        dec.on_datagram(&chunk(&pkt, ctx([10, 1, 2, 3])), &mut out);

        let txs = get_tx(&out);
        assert_eq!(txs.len(), 1);
        assert_eq!(txs[0].operation, "igmp_leave_group");
        assert_eq!(
            txs[0].attributes.get("group_address").map(String::as_str),
            Some("239.0.0.5")
        );
        // No topology observation for leave
        assert!(get_topo(&out).is_empty());
    }

    // ── Test 5: IGMPv3 Query with source addresses ────────────────────────────

    #[test]
    fn v3_query_with_sources() {
        // 12-byte base + 2 source addresses = 20 bytes total
        let group: [u8; 4] = [239, 10, 0, 1];
        let src1: [u8; 4] = [10, 0, 0, 1];
        let src2: [u8; 4] = [10, 0, 0, 2];

        let mut pkt = vec![
            TYPE_MEMBERSHIP_QUERY, // type
            0x14,                  // max-resp-code = 20 (MSB clear → value is 20)
            0x00, 0x00,            // checksum
        ];
        pkt.extend_from_slice(&group); // group address
        pkt.push(0x05); // reserved(4)|S=0|QRV=5
        pkt.push(0x0A); // QQIC = 10 (MSB clear)
        pkt.extend_from_slice(&2u16.to_be_bytes()); // num_sources = 2
        pkt.extend_from_slice(&src1);
        pkt.extend_from_slice(&src2);

        let mut dec = IgmpDecoder;
        let mut out = Vec::new();
        dec.on_datagram(&chunk(&pkt, ctx([10, 0, 0, 100])), &mut out);

        let txs = get_tx(&out);
        assert_eq!(txs.len(), 1);
        let tx = txs[0];
        assert_eq!(tx.operation, "igmp_membership_query");
        assert_eq!(tx.attributes.get("version").map(String::as_str), Some("3"));
        assert_eq!(
            tx.attributes.get("query_kind").map(String::as_str),
            Some("group_and_source_specific")
        );
        assert_eq!(tx.attributes.get("source_count").map(String::as_str), Some("2"));
        assert_eq!(tx.attributes.get("qrv").map(String::as_str), Some("5"));
        assert_eq!(tx.attributes.get("qqic").map(String::as_str), Some("10"));
        assert_eq!(
            tx.attributes.get("max_resp_code_decisec").map(String::as_str),
            Some("20")
        );
        let sources = tx.attributes.get("source_addresses").unwrap();
        assert!(sources.contains("10.0.0.1"));
        assert!(sources.contains("10.0.0.2"));
    }

    // ── Test 6: IGMPv3 Membership Report — MODE_IS_INCLUDE ───────────────────

    #[test]
    fn v3_report_mode_is_include() {
        let group: [u8; 4] = [239, 5, 5, 5];
        let src: [u8; 4] = [10, 0, 1, 1];

        // Report header: type(1) + reserved(1) + checksum(2) + reserved(2) + num_records(2)
        let mut pkt: Vec<u8> = vec![
            TYPE_V3_MEMBERSHIP_REPORT,
            0x00,       // reserved
            0x00, 0x00, // checksum
            0x00, 0x00, // reserved
        ];
        pkt.extend_from_slice(&1u16.to_be_bytes()); // num_records = 1
        // Group record
        pkt.push(RT_MODE_IS_INCLUDE); // record type
        pkt.push(0x00);               // aux_data_len = 0
        pkt.extend_from_slice(&1u16.to_be_bytes()); // num_sources = 1
        pkt.extend_from_slice(&group);
        pkt.extend_from_slice(&src);

        let mut dec = IgmpDecoder;
        let mut out = Vec::new();
        dec.on_datagram(&chunk(&pkt, ctx([10, 0, 1, 2])), &mut out);

        let txs = get_tx(&out);
        assert_eq!(txs.len(), 1);
        let tx = txs[0];
        assert_eq!(tx.operation, "igmp_v3_membership_report");
        assert_eq!(tx.attributes.get("record_count").map(String::as_str), Some("1"));
        assert_eq!(
            tx.attributes
                .get("record_type_mode_is_include_count")
                .map(String::as_str),
            Some("1")
        );
        assert!(tx.object_refs.contains(&"239.5.5.5".to_string()));

        // Topology observation for MODE_IS_INCLUDE (join-style)
        let topos = get_topo(&out);
        assert_eq!(topos.len(), 1);
        assert_eq!(topos[0].observation_type, "multicast_join");
        assert_eq!(topos[0].remote_id.as_deref(), Some("239.5.5.5"));
    }

    // ── Test 7: IGMPv3 Membership Report — multiple records ──────────────────

    #[test]
    fn v3_report_multiple_records() {
        let group1: [u8; 4] = [239, 1, 1, 1];
        let group2: [u8; 4] = [239, 2, 2, 2];

        let mut pkt: Vec<u8> = vec![
            TYPE_V3_MEMBERSHIP_REPORT,
            0x00,
            0x00, 0x00,
            0x00, 0x00,
        ];
        pkt.extend_from_slice(&2u16.to_be_bytes()); // 2 records

        // Record 1: CHANGE_TO_INCLUDE, no sources
        pkt.push(RT_CHANGE_TO_INCLUDE);
        pkt.push(0x00); // aux_data_len = 0
        pkt.extend_from_slice(&0u16.to_be_bytes()); // num_sources = 0
        pkt.extend_from_slice(&group1);

        // Record 2: CHANGE_TO_EXCLUDE, no sources
        pkt.push(RT_CHANGE_TO_EXCLUDE);
        pkt.push(0x00);
        pkt.extend_from_slice(&0u16.to_be_bytes());
        pkt.extend_from_slice(&group2);

        let mut dec = IgmpDecoder;
        let mut out = Vec::new();
        dec.on_datagram(&chunk(&pkt, ctx([10, 0, 0, 5])), &mut out);

        let txs = get_tx(&out);
        assert_eq!(txs.len(), 1);
        let tx = txs[0];
        assert_eq!(tx.attributes.get("record_count").map(String::as_str), Some("2"));
        assert_eq!(
            tx.attributes
                .get("record_type_change_to_include_count")
                .map(String::as_str),
            Some("1")
        );
        assert_eq!(
            tx.attributes
                .get("record_type_change_to_exclude_count")
                .map(String::as_str),
            Some("1")
        );
        // object_refs contains both groups
        assert!(tx.object_refs.contains(&"239.1.1.1".to_string()));
        assert!(tx.object_refs.contains(&"239.2.2.2".to_string()));

        // Only CHANGE_TO_INCLUDE is join-style → 1 topology obs
        let topos = get_topo(&out);
        assert_eq!(topos.len(), 1);
        assert_eq!(topos[0].remote_id.as_deref(), Some("239.1.1.1"));
    }

    // ── Test 8: IGMPv3 Membership Report — EXCLUDE record ────────────────────

    #[test]
    fn v3_report_exclude_no_topology_join() {
        let group: [u8; 4] = [239, 7, 7, 7];

        let mut pkt: Vec<u8> = vec![
            TYPE_V3_MEMBERSHIP_REPORT,
            0x00,
            0x00, 0x00,
            0x00, 0x00,
        ];
        pkt.extend_from_slice(&1u16.to_be_bytes()); // 1 record
        pkt.push(RT_MODE_IS_EXCLUDE);
        pkt.push(0x00);
        pkt.extend_from_slice(&0u16.to_be_bytes()); // 0 sources
        pkt.extend_from_slice(&group);

        let mut dec = IgmpDecoder;
        let mut out = Vec::new();
        dec.on_datagram(&chunk(&pkt, ctx([10, 0, 0, 9])), &mut out);

        let txs = get_tx(&out);
        assert_eq!(txs.len(), 1);
        assert_eq!(txs[0].operation, "igmp_v3_membership_report");
        assert_eq!(
            txs[0]
                .attributes
                .get("record_type_mode_is_exclude_count")
                .map(String::as_str),
            Some("1")
        );
        // MODE_IS_EXCLUDE is NOT join-style — no TopologyObservation
        assert!(get_topo(&out).is_empty());
    }

    // ── Test 9: Float-encoded max-resp-code ───────────────────────────────────

    #[test]
    fn float_encoded_max_resp_code() {
        // MSB=1, exp=0b011=3, mant=0b0101=5 → byte = 1_011_0101 = 0xB5
        // value = (5 | 0x10) << (3 + 3) = 21 << 6 = 1344
        let byte = 0xB5u8;
        let decoded = decode_float_time(byte);
        assert_eq!(decoded, 1344);

        // Non-float: MSB=0 → value is the byte itself
        assert_eq!(decode_float_time(0x7F), 127);
        assert_eq!(decode_float_time(0x00), 0);

        // Build a v3 query with float-encoded max-resp-code
        let pkt = vec![
            TYPE_MEMBERSHIP_QUERY,
            byte,
            0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, // group = 0.0.0.0 (general)
            0x00,                   // S=0, QRV=0
            0x00,                   // QQIC=0
            0x00, 0x00,             // num_sources=0
        ];

        let mut dec = IgmpDecoder;
        let mut out = Vec::new();
        dec.on_datagram(&chunk(&pkt, ctx([10, 0, 0, 1])), &mut out);

        let txs = get_tx(&out);
        assert_eq!(txs.len(), 1);
        assert_eq!(
            txs[0]
                .attributes
                .get("max_resp_code_decisec")
                .map(String::as_str),
            Some("1344")
        );
    }

    // ── Test 10: Truncated payload → anomaly ─────────────────────────────────

    #[test]
    fn truncated_payload_emits_anomaly() {
        // Only 5 bytes — less than the 8-byte minimum
        let pkt = vec![TYPE_MEMBERSHIP_QUERY, 0x14, 0x00, 0x00, 0x00];
        let mut dec = IgmpDecoder;
        let mut out = Vec::new();
        dec.on_datagram(&chunk(&pkt, ctx([10, 0, 0, 1])), &mut out);

        let anomalies = get_anomaly(&out);
        assert_eq!(anomalies.len(), 1);
        assert_eq!(anomalies[0].severity, "low");
        assert!(anomalies[0].reason.contains("shorter than 8-byte"));
        assert!(get_tx(&out).is_empty());
    }

    // ── Test 11: Unknown IGMP type → anomaly ─────────────────────────────────

    #[test]
    fn unknown_igmp_type_emits_anomaly() {
        let pkt = igmp_v2(0xAB, 0, [0, 0, 0, 0]);
        let mut dec = IgmpDecoder;
        let mut out = Vec::new();
        dec.on_datagram(&chunk(&pkt, ctx([10, 0, 0, 1])), &mut out);

        let anomalies = get_anomaly(&out);
        assert_eq!(anomalies.len(), 1);
        assert!(anomalies[0].reason.contains("0xab"));
        assert!(get_tx(&out).is_empty());
    }

    // ── Test 12: Decoder interest is IpProto(2) ──────────────────────────────

    #[test]
    fn decoder_interest_is_ip_proto_2() {
        let dec = IgmpDecoder;
        assert!(dec.interest().contains(&DecoderInterest::IpProto(2)));
    }
}
