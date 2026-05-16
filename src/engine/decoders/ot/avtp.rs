//! AVTP / IEEE 1722-2016 decoder — EtherType 0x22F0.
//!
//! Audio Video Transport Protocol is the wire format for TSN audio-video
//! bridging. Originally automotive (in-vehicle infotainment, ADAS); growing
//! into industrial TSN for camera feeds, audio-over-Ethernet, and other
//! latency-bounded media.
//!
//! # Common header (12 bytes, big-endian)
//!
//! ```text
//! byte  0     : subtype
//! byte  1     : sv(7) | version(4..6) | mr(3) | reserved(1..2) | tv(0)
//! byte  2     : sequence_num
//! byte  3     : reserved
//! bytes 4..12 : stream_id (EUI-48 MAC + 16-bit UniqueID)
//! bytes 12..16: avtp_timestamp (gPTP-locked, may be absent on short frames)
//! ```
//!
//! # Sampling rationale
//!
//! AAF audio at 48 kHz / 6 samples-per-frame yields ~8000 AVTP packets/sec per
//! stream; CVF video fragments add further volume. Emitting one Bronze event per
//! packet floods consumers. Strategy: emit on first sight of a (session, stream_id)
//! pair, then every 1000th packet. Control packets (ADP/AECP/ACMP/MAAP/…) are
//! rare enough to emit unconditionally.

use std::collections::{BTreeMap, HashMap};

use crate::bronze::{
    AssetObservation, BronzeEvent, BronzeEventFamily, ProtocolTransaction, TransportProtocol,
};
use crate::engine::{
    DecoderInterest, SessionDecoder, StreamChunk, build_envelope, new_event, parse_anomaly_event,
};

// ── Subtype constants (IEEE 1722-2016 §5.3) ───────────────────────────────────

const SUBTYPE_IEC61883: u8 = 0x00;
const SUBTYPE_MMA: u8 = 0x02;
const SUBTYPE_AAF: u8 = 0x03;
const SUBTYPE_CVF: u8 = 0x04;
const SUBTYPE_CRF: u8 = 0x05;
const SUBTYPE_TSCF: u8 = 0x06;
const SUBTYPE_SVF: u8 = 0x07;
const SUBTYPE_RVF: u8 = 0x08;
const SUBTYPE_NTSCF: u8 = 0x6E;
const SUBTYPE_ESCF: u8 = 0x6F;
const SUBTYPE_EECF: u8 = 0x70;
const SUBTYPE_AEF: u8 = 0x71;
const SUBTYPE_ADP: u8 = 0x7A;
const SUBTYPE_AECP: u8 = 0x7B;
const SUBTYPE_ACMP: u8 = 0x7C;
const SUBTYPE_MAAP: u8 = 0x7E;

const ADP_MSG_ENTITY_AVAILABLE: u8 = 0;
const ADP_MSG_ENTITY_DEPARTING: u8 = 1;
const ADP_MSG_ENTITY_DISCOVER: u8 = 2;

const MEDIA_PERIODIC_INTERVAL: u64 = 1000;

// ── Subtype helpers ───────────────────────────────────────────────────────────

fn subtype_name(s: u8) -> &'static str {
    match s {
        SUBTYPE_IEC61883 => "iec61883",
        SUBTYPE_MMA => "mma",
        SUBTYPE_AAF => "aaf",
        SUBTYPE_CVF => "cvf",
        SUBTYPE_CRF => "crf",
        SUBTYPE_TSCF => "tscf",
        SUBTYPE_SVF => "svf",
        SUBTYPE_RVF => "rvf",
        SUBTYPE_NTSCF => "ntscf",
        SUBTYPE_ESCF => "escf",
        SUBTYPE_EECF => "eecf",
        SUBTYPE_AEF => "aef",
        SUBTYPE_ADP => "adp",
        SUBTYPE_AECP => "aecp",
        SUBTYPE_ACMP => "acmp",
        SUBTYPE_MAAP => "maap",
        _ => "unknown",
    }
}

fn is_media_subtype(s: u8) -> bool {
    matches!(
        s,
        SUBTYPE_IEC61883
            | SUBTYPE_MMA
            | SUBTYPE_AAF
            | SUBTYPE_CVF
            | SUBTYPE_CRF
            | SUBTYPE_TSCF
            | SUBTYPE_SVF
            | SUBTYPE_RVF
    )
}

// ── Common header ─────────────────────────────────────────────────────────────

struct AvtpHdr {
    subtype: u8,
    stream_valid: bool,
    version: u8,
    media_clock_restart: bool,
    timestamp_valid: bool,
    stream_id: u64,
}

fn parse_hdr(p: &[u8]) -> AvtpHdr {
    let flags = p[1];
    let stream_id = if p.len() >= 12 {
        u64::from_be_bytes([p[4], p[5], p[6], p[7], p[8], p[9], p[10], p[11]])
    } else {
        0
    };
    AvtpHdr {
        subtype: p[0],
        stream_valid: (flags >> 7) & 1 == 1,
        version: (flags >> 4) & 0x07,
        media_clock_restart: (flags >> 3) & 1 == 1,
        timestamp_valid: flags & 1 == 1,
        stream_id,
    }
}

// ── Decoder ───────────────────────────────────────────────────────────────────

#[derive(Default)]
pub(crate) struct AvtpDecoder {
    /// Per-stream packet counter; keyed by (session_key, stream_id).
    streams: HashMap<(String, u64), u64>,
}

impl SessionDecoder for AvtpDecoder {
    fn name(&self) -> &'static str {
        "avtp"
    }

    fn interest(&self) -> &'static [DecoderInterest] {
        &[DecoderInterest::EtherType(0x22F0)]
    }

    fn on_datagram(&mut self, chunk: &StreamChunk<'_>, out: &mut Vec<BronzeEvent>) {
        let payload = chunk.payload;

        if payload.len() < 12 {
            out.push(parse_anomaly_event(
                chunk.capture_id.to_string(),
                build_envelope(
                    &chunk.context,
                    chunk.interface_id,
                    chunk.frame_index,
                    chunk.timestamp,
                    chunk.segment_hash,
                    TransportProtocol::Ethernet,
                    Some("avtp"),
                    chunk.captured_len,
                    chunk.session_key.clone(),
                ),
                self.name(),
                "medium",
                "avtp frame shorter than 12-byte common header",
                payload,
            ));
            return;
        }

        let hdr = parse_hdr(payload);
        let envelope = build_envelope(
            &chunk.context,
            chunk.interface_id,
            chunk.frame_index,
            chunk.timestamp,
            chunk.segment_hash,
            TransportProtocol::Ethernet,
            Some("avtp"),
            chunk.captured_len,
            chunk.session_key.clone(),
        );

        if is_media_subtype(hdr.subtype) {
            self.handle_media(chunk, envelope, &hdr, out);
        } else if subtype_name(hdr.subtype) != "unknown" {
            self.handle_control(chunk, envelope, &hdr, payload, out);
        } else {
            self.handle_unknown(chunk, envelope, &hdr, payload, out);
        }
    }
}

impl AvtpDecoder {
    fn handle_media(
        &mut self,
        chunk: &StreamChunk<'_>,
        envelope: crate::bronze::EventEnvelope,
        hdr: &AvtpHdr,
        out: &mut Vec<BronzeEvent>,
    ) {
        let key = (chunk.session_key.clone(), hdr.stream_id);
        let count = {
            let c = self.streams.entry(key).or_insert(0);
            *c += 1;
            *c
        };

        if count != 1 && count % MEDIA_PERIODIC_INTERVAL != 0 {
            return; // suppressed — not first or periodic boundary
        }

        let name = subtype_name(hdr.subtype);
        let sid_hex = format!("{:016x}", hdr.stream_id);
        let mut attrs = media_attrs(hdr, name, &sid_hex);

        let (operation, summary) = if count == 1 {
            (
                format!("avtp_{name}_stream_open"),
                format!("AVTP {name} stream first observed stream_id={sid_hex}"),
            )
        } else {
            attrs.insert("packet_count_observed".to_string(), count.to_string());
            (
                format!("avtp_{name}_stream_periodic"),
                format!("AVTP {name} stream_id={sid_hex} packet_count={count}"),
            )
        };

        out.push(new_event(
            chunk.capture_id.to_string(),
            envelope,
            BronzeEventFamily::ProtocolTransaction(ProtocolTransaction {
                operation,
                status: "observed".to_string(),
                request_summary: Some(summary),
                response_summary: None,
                object_refs: vec![format!("stream_id:{sid_hex}")],
                values: Vec::new(),
                attributes: attrs,
                modbus: None,
                protocol_fields: None,
            }),
        ));
    }

    fn handle_control(
        &mut self,
        chunk: &StreamChunk<'_>,
        envelope: crate::bronze::EventEnvelope,
        hdr: &AvtpHdr,
        payload: &[u8],
        out: &mut Vec<BronzeEvent>,
    ) {
        if hdr.subtype == SUBTYPE_ADP {
            self.handle_adp(chunk, envelope, hdr, payload, out);
            return;
        }
        let name = subtype_name(hdr.subtype);
        let mut attrs = BTreeMap::new();
        attrs.insert("subtype".to_string(), format!("{:#04x}", hdr.subtype));
        attrs.insert("subtype_name".to_string(), name.to_string());
        attrs.insert(
            "stream_id_hex".to_string(),
            format!("{:016x}", hdr.stream_id),
        );
        out.push(new_event(
            chunk.capture_id.to_string(),
            envelope,
            BronzeEventFamily::ProtocolTransaction(ProtocolTransaction {
                operation: format!("avtp_{name}"),
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
    }

    fn handle_adp(
        &mut self,
        chunk: &StreamChunk<'_>,
        envelope: crate::bronze::EventEnvelope,
        hdr: &AvtpHdr,
        payload: &[u8],
        out: &mut Vec<BronzeEvent>,
    ) {
        // ADP-specific payload begins after 16-byte common header (12 common + 4 avtp_ts).
        let adp = if payload.len() > 16 {
            &payload[16..]
        } else {
            &[]
        };

        let message_type = adp.first().map(|b| (b >> 4) & 0x0F).unwrap_or(0);
        let entity_id = read_u64_be(adp, 4).unwrap_or(0);
        let entity_model_id = read_u64_be(adp, 12).unwrap_or(0);
        let entity_caps = read_u32_be(adp, 20).unwrap_or(0);
        let talker_sources = read_u16_be(adp, 24).unwrap_or(0);
        let listener_sinks = read_u16_be(adp, 28).unwrap_or(0);
        let gptp_gm_id = read_u64_be(adp, 40).unwrap_or(0);
        let gptp_domain = adp.get(48).copied().unwrap_or(0);

        let eid_hex = format!("{entity_id:016x}");
        let emid_hex = format!("{entity_model_id:016x}");
        let gm_hex = format!("{gptp_gm_id:016x}");

        let operation = match message_type {
            ADP_MSG_ENTITY_AVAILABLE => "avtp_adp_entity_available",
            ADP_MSG_ENTITY_DEPARTING => "avtp_adp_entity_departing",
            ADP_MSG_ENTITY_DISCOVER => "avtp_adp_entity_discover",
            _ => "avtp_adp_unknown",
        };

        let mut attrs = BTreeMap::new();
        attrs.insert("subtype".to_string(), format!("{:#04x}", hdr.subtype));
        attrs.insert("subtype_name".to_string(), "adp".to_string());
        attrs.insert("message_type".to_string(), message_type.to_string());
        attrs.insert("entity_id_hex".to_string(), eid_hex.clone());
        attrs.insert("entity_model_id_hex".to_string(), emid_hex.clone());
        attrs.insert(
            "entity_capabilities_hex".to_string(),
            format!("{entity_caps:#010x}"),
        );
        attrs.insert("gptp_grandmaster_id_hex".to_string(), gm_hex);
        attrs.insert("gptp_domain_number".to_string(), gptp_domain.to_string());
        attrs.insert(
            "talker_stream_sources".to_string(),
            talker_sources.to_string(),
        );
        attrs.insert(
            "listener_stream_sinks".to_string(),
            listener_sinks.to_string(),
        );

        out.push(new_event(
            chunk.capture_id.to_string(),
            envelope.clone(),
            BronzeEventFamily::ProtocolTransaction(ProtocolTransaction {
                operation: operation.to_string(),
                status: "observed".to_string(),
                request_summary: Some(format!("ADP entity_id={eid_hex} model={emid_hex}")),
                response_summary: None,
                object_refs: vec![
                    format!("entity_id:{eid_hex}"),
                    format!("entity_model_id:{emid_hex}"),
                ],
                values: Vec::new(),
                attributes: attrs,
                modbus: None,
                protocol_fields: None,
            }),
        ));

        if message_type == ADP_MSG_ENTITY_AVAILABLE {
            let role = match (talker_sources > 0, listener_sinks > 0) {
                (true, false) => "avtp_talker",
                (false, true) => "avtp_listener",
                _ => "avtp_entity",
            };
            let mut identifiers = BTreeMap::new();
            identifiers.insert("avtp_entity_id".to_string(), eid_hex.clone());
            identifiers.insert("avtp_entity_model_id".to_string(), emid_hex);
            out.push(new_event(
                chunk.capture_id.to_string(),
                envelope,
                BronzeEventFamily::AssetObservation(AssetObservation {
                    asset_key: format!("avtp_entity:{eid_hex}"),
                    role: Some(role.to_string()),
                    vendor: None,
                    model: None,
                    firmware: None,
                    hostnames: Vec::new(),
                    protocols: vec!["avtp".to_string()],
                    identifiers,
                }),
            ));
        }
    }

    fn handle_unknown(
        &mut self,
        chunk: &StreamChunk<'_>,
        envelope: crate::bronze::EventEnvelope,
        hdr: &AvtpHdr,
        payload: &[u8],
        out: &mut Vec<BronzeEvent>,
    ) {
        let s = hdr.subtype;
        let mut attrs = BTreeMap::new();
        attrs.insert("subtype".to_string(), format!("{s:#04x}"));
        attrs.insert("subtype_name".to_string(), format!("unknown_{s:#04x}"));
        out.push(new_event(
            chunk.capture_id.to_string(),
            envelope.clone(),
            BronzeEventFamily::ProtocolTransaction(ProtocolTransaction {
                operation: format!("avtp_unknown_subtype_{s:#04x}"),
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
        out.push(parse_anomaly_event(
            chunk.capture_id.to_string(),
            envelope,
            "avtp",
            "low",
            &format!("unknown AVTP subtype {s:#04x}"),
            payload,
        ));
    }
}

// ── Helpers ───────────────────────────────────────────────────────────────────

fn media_attrs(hdr: &AvtpHdr, name: &str, sid_hex: &str) -> BTreeMap<String, String> {
    let mut m = BTreeMap::new();
    m.insert("subtype".to_string(), format!("{:#04x}", hdr.subtype));
    m.insert("subtype_name".to_string(), name.to_string());
    m.insert("stream_id_hex".to_string(), sid_hex.to_string());
    m.insert("version".to_string(), hdr.version.to_string());
    m.insert("stream_valid".to_string(), bool_str(hdr.stream_valid));
    m.insert("timestamp_valid".to_string(), bool_str(hdr.timestamp_valid));
    m.insert(
        "media_clock_restart".to_string(),
        bool_str(hdr.media_clock_restart),
    );
    m
}

fn bool_str(b: bool) -> String {
    if b { "true" } else { "false" }.to_string()
}

fn read_u16_be(buf: &[u8], off: usize) -> Option<u16> {
    buf.get(off..off + 2)
        .map(|b| u16::from_be_bytes([b[0], b[1]]))
}

fn read_u32_be(buf: &[u8], off: usize) -> Option<u32> {
    buf.get(off..off + 4)
        .map(|b| u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
}

fn read_u64_be(buf: &[u8], off: usize) -> Option<u64> {
    buf.get(off..off + 8)
        .map(|b| u64::from_be_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]]))
}

// ── Self-registration ─────────────────────────────────────────────────────────

inventory::submit!(crate::engine::decoders::DecoderRegistration {
    name: "avtp",
    factory: || Box::new(AvtpDecoder::default()),
});

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    use chrono::Utc;

    use crate::bronze::{BronzeEventFamily, ParseAnomaly, ProtocolTransaction};
    use crate::engine::{DecoderInterest, SessionDecoder, StreamChunk};
    use crate::registry::PacketContext;

    // ── Helpers ───────────────────────────────────────────────────────────────

    /// 16-byte AVTP common header with sv=1, version=1 (2016), tv=1.
    fn avtp_hdr(subtype: u8, stream_id: u64) -> Vec<u8> {
        let mut v = Vec::with_capacity(16);
        v.push(subtype);
        v.push(0x91); // sv=1 | version=1 | tv=1
        v.push(0x00); // sequence_num
        v.push(0x00); // reserved
        v.extend_from_slice(&stream_id.to_be_bytes());
        v.extend_from_slice(&0x0001_2345u32.to_be_bytes()); // avtp_timestamp
        v
    }

    fn ctx() -> PacketContext {
        PacketContext {
            src_mac: [0x00, 0x1B, 0x21, 0xAA, 0xBB, 0xCC],
            dst_mac: [0x91, 0xE0, 0xF0, 0x00, 0x0E, 0x80],
            src_ip: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            dst_ip: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            src_port: 0,
            dst_port: 0,
            vlan_id: None,
            timestamp: 0,
        }
    }

    fn chunk<'a>(payload: &'a [u8], ctx: &'a PacketContext) -> StreamChunk<'a> {
        StreamChunk {
            capture_id: "test_cap",
            segment_hash: "deadbeef",
            interface_id: 0,
            frame_index: 1,
            timestamp: Utc::now(),
            context: ctx.clone(),
            ethertype: 0x22F0,
            ip_proto: None,
            llc: None,
            transport: TransportProtocol::Ethernet,
            payload,
            session_key: "avtp-sess-1".to_string(),
            captured_len: payload.len() as u64,
        }
    }

    fn tx(ev: &BronzeEvent) -> &ProtocolTransaction {
        match &ev.family {
            BronzeEventFamily::ProtocolTransaction(t) => t,
            other => panic!("expected ProtocolTransaction, got {other:?}"),
        }
    }
    fn asset(ev: &BronzeEvent) -> &AssetObservation {
        match &ev.family {
            BronzeEventFamily::AssetObservation(a) => a,
            other => panic!("expected AssetObservation, got {other:?}"),
        }
    }
    fn anomaly(ev: &BronzeEvent) -> &ParseAnomaly {
        match &ev.family {
            BronzeEventFamily::ParseAnomaly(a) => a,
            other => panic!("expected ParseAnomaly, got {other:?}"),
        }
    }

    // ── Test 1: AAF first packet ──────────────────────────────────────────────

    #[test]
    fn aaf_first_packet_stream_open() {
        let mut dec = AvtpDecoder::default();
        let mut out = Vec::new();
        let sid: u64 = 0x001B_21AA_BBCC_0001;
        let mut frame = avtp_hdr(SUBTYPE_AAF, sid);
        frame.extend_from_slice(&[0u8; 8]);
        let c = ctx();
        dec.on_datagram(&chunk(&frame, &c), &mut out);

        assert_eq!(out.len(), 1);
        let t = tx(&out[0]);
        assert_eq!(t.operation, "avtp_aaf_stream_open");
        assert_eq!(
            t.attributes.get("subtype_name").map(String::as_str),
            Some("aaf")
        );
        assert_eq!(
            t.attributes.get("stream_id_hex").map(String::as_str),
            Some(format!("{sid:016x}").as_str())
        );
        assert_eq!(
            t.attributes.get("stream_valid").map(String::as_str),
            Some("true")
        );
        assert_eq!(
            t.attributes.get("timestamp_valid").map(String::as_str),
            Some("true")
        );
    }

    // ── Test 2: CVF first packet ──────────────────────────────────────────────

    #[test]
    fn cvf_first_packet_stream_open() {
        let mut dec = AvtpDecoder::default();
        let mut out = Vec::new();
        let mut frame = avtp_hdr(SUBTYPE_CVF, 0xAABB_CCDD_EEFF_0002);
        frame.extend_from_slice(&[0u8; 8]);
        let c = ctx();
        dec.on_datagram(&chunk(&frame, &c), &mut out);
        assert_eq!(out.len(), 1);
        assert_eq!(tx(&out[0]).operation, "avtp_cvf_stream_open");
    }

    // ── Test 3: ADP ENTITY_AVAILABLE ─────────────────────────────────────────

    #[test]
    fn adp_entity_available_emits_tx_and_asset() {
        let mut dec = AvtpDecoder::default();
        let mut out = Vec::new();

        let entity_id: u64 = 0x001B21FFEEDDCC00;
        let entity_model: u64 = 0xABCD_EF01_2345_6789;
        let gptp_gm: u64 = 0x0011_2233_4455_6677;

        // ADP payload: 68 bytes after the 16-byte common header.
        let mut adp = vec![0u8; 68];
        adp[0] = 0x05; // message_type=0 (ENTITY_AVAILABLE, upper nibble) | valid_time=5
        adp[4..12].copy_from_slice(&entity_id.to_be_bytes());
        adp[12..20].copy_from_slice(&entity_model.to_be_bytes());
        adp[20..24].copy_from_slice(&0x0000_C596u32.to_be_bytes()); // entity_capabilities
        adp[24..26].copy_from_slice(&2u16.to_be_bytes()); // talker_stream_sources=2
        adp[40..48].copy_from_slice(&gptp_gm.to_be_bytes());
        adp[48] = 7; // gptp_domain_number

        let mut frame = avtp_hdr(SUBTYPE_ADP, entity_id);
        frame.extend_from_slice(&adp);
        let c = ctx();
        dec.on_datagram(&chunk(&frame, &c), &mut out);

        assert_eq!(out.len(), 2, "ADP ENTITY_AVAILABLE → tx + AssetObservation");

        let t = tx(&out[0]);
        assert_eq!(t.operation, "avtp_adp_entity_available");
        let eid_hex = format!("{entity_id:016x}");
        assert_eq!(
            t.attributes.get("entity_id_hex").map(String::as_str),
            Some(eid_hex.as_str())
        );
        assert_eq!(
            t.attributes.get("gptp_domain_number").map(String::as_str),
            Some("7")
        );

        let a = asset(&out[1]);
        assert_eq!(a.role.as_deref(), Some("avtp_talker")); // talker_sources=2 > 0
        assert_eq!(
            a.identifiers.get("avtp_entity_id").map(String::as_str),
            Some(eid_hex.as_str())
        );
        assert!(a.asset_key.contains(&eid_hex));
    }

    // ── Test 4: Unknown subtype 0x55 ─────────────────────────────────────────

    #[test]
    fn unknown_subtype_emits_tx_and_low_anomaly() {
        let mut dec = AvtpDecoder::default();
        let mut out = Vec::new();
        let mut frame = avtp_hdr(0x55, 0x0011_2233_4455_6677);
        frame.extend_from_slice(&[0xDE, 0xAD]);
        let c = ctx();
        dec.on_datagram(&chunk(&frame, &c), &mut out);

        assert_eq!(out.len(), 2, "unknown subtype → tx + low anomaly");
        assert_eq!(tx(&out[0]).operation, "avtp_unknown_subtype_0x55");
        let a = anomaly(&out[1]);
        assert_eq!(a.severity, "low");
        assert!(a.reason.contains("0x55"));
    }

    // ── Test 5: Truncated 6-byte frame ───────────────────────────────────────

    #[test]
    fn truncated_frame_emits_medium_anomaly() {
        let mut dec = AvtpDecoder::default();
        let mut out = Vec::new();
        let payload = [0x03u8, 0x91, 0x00, 0x00, 0xAA, 0xBB]; // only 6 bytes
        let c = ctx();
        dec.on_datagram(&chunk(&payload, &c), &mut out);

        assert_eq!(out.len(), 1);
        let a = anomaly(&out[0]);
        assert_eq!(a.severity, "medium");
        assert!(a.reason.contains("12-byte"));
    }

    // ── Test 6: AAF periodic heartbeat at 1000th packet ──────────────────────

    #[test]
    fn aaf_periodic_heartbeat_emitted_at_1000th_packet() {
        let mut dec = AvtpDecoder::default();
        let sid: u64 = 0xCAFE_BABE_DEAD_BEEF;
        let c = ctx();

        let mut ops: Vec<String> = Vec::new();
        let mut last_periodic_attrs: Option<BTreeMap<String, String>> = None;

        for _i in 0u32..1000 {
            let mut frame = avtp_hdr(SUBTYPE_AAF, sid);
            frame.extend_from_slice(&[0u8; 4]);
            let mut out = Vec::new();
            dec.on_datagram(&chunk(&frame, &c), &mut out);
            for ev in &out {
                if let BronzeEventFamily::ProtocolTransaction(t) = &ev.family {
                    ops.push(t.operation.clone());
                    if t.operation == "avtp_aaf_stream_periodic" {
                        last_periodic_attrs = Some(t.attributes.clone());
                    }
                }
            }
        }

        assert!(ops.contains(&"avtp_aaf_stream_open".to_string()));
        assert!(ops.contains(&"avtp_aaf_stream_periodic".to_string()));
        let attrs = last_periodic_attrs.expect("periodic event must have been emitted");
        assert_eq!(
            attrs.get("packet_count_observed").map(String::as_str),
            Some("1000")
        );
    }

    // ── Test 7: interest() ────────────────────────────────────────────────────

    #[test]
    fn decoder_interest_is_ethertype_22f0() {
        let dec = AvtpDecoder::default();
        assert!(dec.interest().contains(&DecoderInterest::EtherType(0x22F0)));
    }
}
