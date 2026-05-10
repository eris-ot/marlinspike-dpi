//! NetFlow v5 / v9 and IPFIX (v10) decoder.
//!
//! Listens on the conventional flow-export UDP ports and emits:
//!   - `ProtocolTransaction`  — one per datagram, carrying header-level metadata.
//!   - `AssetObservation`     — for the exporter (src IP) and collector (dst IP),
//!                              deduplicated per session via `HashSet`.
//!   - `ParseAnomaly`         — for unknown versions or wire-length mismatches.
//!
//! # NetFlow v9 template tracking
//! Template tracking across packets is intentionally not implemented. NetFlow v9
//! Data FlowSets reference template IDs advertised in Template FlowSets, which
//! may arrive in earlier datagrams or on a different UDP 5-tuple entirely.
//! Stateful correlation would require a shared, session-keyed store, is expensive
//! under lock contention, and is outside the scope of passive header-level
//! visibility. The decoder emits `flowset_ids` as-seen so downstream consumers
//! can determine whether a collector received its templates. Full template
//! correlation is a Silver-tier enrichment concern, not a Bronze DPI concern.

use std::collections::{BTreeMap, HashSet};

use crate::bronze::{
    AssetObservation, BronzeEvent, BronzeEventFamily, ProtocolTransaction, TransportProtocol,
};
use crate::engine::{
    build_envelope, new_event, parse_anomaly_event, DecoderInterest, SessionDecoder, StreamChunk,
};

// ── Layout constants ──────────────────────────────────────────────────────────

const NFV5_HEADER: usize = 24;
const NFV5_RECORD: usize = 48;
const NFV9_HEADER: usize = 20;
const IPFIX_HEADER: usize = 16;

// ── Decoder ───────────────────────────────────────────────────────────────────

/// Per-session de-duplication for `AssetObservation` events.
/// Each unique src/dst IP pair produces at most one observation per decoder
/// instance lifetime (i.e., one capture session).
#[derive(Default)]
struct Seen {
    exporters: HashSet<String>,
    collectors: HashSet<String>,
}

#[derive(Default)]
pub(crate) struct NetFlowDecoder {
    seen: Seen,
}

impl SessionDecoder for NetFlowDecoder {
    fn name(&self) -> &'static str { "netflow" }

    fn interest(&self) -> &'static [DecoderInterest] {
        &[
            DecoderInterest::UdpPort(2055),
            DecoderInterest::UdpPort(4739),
            DecoderInterest::UdpPort(9995),
            DecoderInterest::UdpPort(9996),
        ]
    }

    fn on_datagram(&mut self, chunk: &StreamChunk<'_>, out: &mut Vec<BronzeEvent>) {
        let data = chunk.payload;
        if data.len() < 2 {
            out.push(anomaly(chunk, "medium", "datagram too short for version field"));
            return;
        }
        match u16::from_be_bytes([data[0], data[1]]) {
            5 => self.handle_v5(chunk, out),
            9 => self.handle_v9(chunk, out),
            10 => self.handle_ipfix(chunk, out),
            v => {
                out.push(anomaly(chunk, "low",
                    &format!("unsupported NetFlow/IPFIX version {v}")));
                let mut attr = BTreeMap::new();
                attr.insert("version".into(), v.to_string());
                out.push(tx_event(chunk, format!("netflow_unknown_v{v}"), attr));
            }
        }
    }
}

// ── Per-version handlers ──────────────────────────────────────────────────────

impl NetFlowDecoder {
    fn handle_v5(&mut self, chunk: &StreamChunk<'_>, out: &mut Vec<BronzeEvent>) {
        let data = chunk.payload;
        if data.len() < NFV5_HEADER {
            out.push(anomaly(chunk, "medium", "NetFlow v5 too short for header"));
            return;
        }
        let count = u16::from_be_bytes([data[2], data[3]]) as usize;
        let sys_uptime_ms = u32be(&data[4..]);
        let unix_secs = u32be(&data[8..]);
        let flow_sequence = u32be(&data[16..]);
        let engine_type = data[20];
        let engine_id = data[21];
        let samp = u16::from_be_bytes([data[22], data[23]]);

        let expected = NFV5_HEADER + count * NFV5_RECORD;
        if data.len() != expected {
            out.push(anomaly(chunk, "medium", &format!(
                "NetFlow v5 length mismatch: count={count} expects {expected}B got {}B",
                data.len()
            )));
        }

        let mut attr = BTreeMap::new();
        attr.insert("version".into(), "5".into());
        attr.insert("record_count".into(), count.to_string());
        attr.insert("flow_sequence".into(), flow_sequence.to_string());
        attr.insert("engine_type".into(), engine_type.to_string());
        attr.insert("engine_id".into(), engine_id.to_string());
        attr.insert("sampling_mode".into(), (samp >> 14).to_string());
        attr.insert("sampling_interval".into(), (samp & 0x3FFF).to_string());
        attr.insert("unix_secs".into(), unix_secs.to_string());
        attr.insert("sys_uptime_ms".into(), sys_uptime_ms.to_string());

        out.push(tx_event(chunk, "netflow_v5_export".into(), attr));
        self.emit_assets(chunk, "5", out);
    }

    fn handle_v9(&mut self, chunk: &StreamChunk<'_>, out: &mut Vec<BronzeEvent>) {
        let data = chunk.payload;
        if data.len() < NFV9_HEADER {
            out.push(anomaly(chunk, "medium", "NetFlow v9 too short for header"));
            return;
        }
        let count = u16::from_be_bytes([data[2], data[3]]);
        let sys_uptime_ms = u32be(&data[4..]);
        let unix_secs = u32be(&data[8..]);
        let package_sequence = u32be(&data[12..]);
        let source_id = u32be(&data[16..]);

        let fs_ids = walk_sets(data, NFV9_HEADER);

        let mut attr = BTreeMap::new();
        attr.insert("version".into(), "9".into());
        attr.insert("flowset_count".into(), count.to_string());
        attr.insert("flowset_ids".into(), fs_ids.join(","));
        attr.insert("package_sequence".into(), package_sequence.to_string());
        attr.insert("source_id".into(), source_id.to_string());
        attr.insert("unix_secs".into(), unix_secs.to_string());
        attr.insert("sys_uptime_ms".into(), sys_uptime_ms.to_string());

        out.push(tx_event(chunk, "netflow_v9_export".into(), attr));
        self.emit_assets(chunk, "9", out);
    }

    fn handle_ipfix(&mut self, chunk: &StreamChunk<'_>, out: &mut Vec<BronzeEvent>) {
        let data = chunk.payload;
        if data.len() < IPFIX_HEADER {
            out.push(anomaly(chunk, "medium", "IPFIX too short for header"));
            return;
        }
        let total_length = u16::from_be_bytes([data[2], data[3]]) as usize;
        let export_time = u32be(&data[4..]);
        let sequence_number = u32be(&data[8..]);
        let observation_domain_id = u32be(&data[12..]);

        if total_length != data.len() {
            out.push(anomaly(chunk, "medium", &format!(
                "IPFIX length field {total_length} disagrees with datagram {}B",
                data.len()
            )));
        }

        let set_ids = walk_sets(data, IPFIX_HEADER);

        let mut attr = BTreeMap::new();
        attr.insert("version".into(), "10".into());
        attr.insert("set_ids".into(), set_ids.join(","));
        attr.insert("total_length".into(), total_length.to_string());
        attr.insert("export_time".into(), export_time.to_string());
        attr.insert("sequence_number".into(), sequence_number.to_string());
        attr.insert("observation_domain_id".into(), observation_domain_id.to_string());

        out.push(tx_event(chunk, "ipfix_export".into(), attr));
        self.emit_assets(chunk, "10", out);
    }

    /// Emit exporter + collector `AssetObservation`s, each at most once per
    /// unique IP per session.
    fn emit_assets(&mut self, chunk: &StreamChunk<'_>, version: &str, out: &mut Vec<BronzeEvent>) {
        let src = chunk.context.src_ip.to_string();
        let dst = chunk.context.dst_ip.to_string();

        if self.seen.exporters.insert(src.clone()) {
            let mut ids = BTreeMap::new();
            ids.insert("ip".into(), src.clone());
            ids.insert("flow_export_version".into(), version.into());
            out.push(asset_event(chunk, src, "netflow_exporter", ids));
        }

        if self.seen.collectors.insert(dst.clone()) {
            let mut ids = BTreeMap::new();
            ids.insert("ip".into(), dst.clone());
            out.push(asset_event(chunk, dst, "netflow_collector", ids));
        }
    }
}

// ── Wire helpers ──────────────────────────────────────────────────────────────

/// Read a big-endian u32 from an at-least-4-byte slice.
#[inline]
fn u32be(b: &[u8]) -> u32 {
    u32::from_be_bytes([b[0], b[1], b[2], b[3]])
}

/// Walk the FlowSet/Set list starting at `start`, returning each 2-byte
/// flowset_id/set_id as a string.  Stops on truncation or a zero-length entry.
fn walk_sets(data: &[u8], start: usize) -> Vec<String> {
    let mut ids = Vec::new();
    let mut off = start;
    while off + 4 <= data.len() {
        let id = u16::from_be_bytes([data[off], data[off + 1]]);
        let len = u16::from_be_bytes([data[off + 2], data[off + 3]]) as usize;
        ids.push(id.to_string());
        if len < 4 { break; }
        off += len;
    }
    ids
}

// ── Event construction helpers ────────────────────────────────────────────────

fn make_envelope(chunk: &StreamChunk<'_>) -> crate::bronze::EventEnvelope {
    build_envelope(
        &chunk.context,
        chunk.interface_id,
        chunk.frame_index,
        chunk.timestamp,
        chunk.segment_hash,
        TransportProtocol::Udp,
        Some("netflow"),
        chunk.captured_len,
        chunk.session_key.clone(),
    )
}

fn tx_event(chunk: &StreamChunk<'_>, operation: String, attributes: BTreeMap<String, String>) -> BronzeEvent {
    new_event(
        chunk.capture_id.to_string(),
        make_envelope(chunk),
        BronzeEventFamily::ProtocolTransaction(ProtocolTransaction {
            operation,
            status: "observed".into(),
            request_summary: None,
            response_summary: None,
            object_refs: vec![],
            values: vec![],
            attributes,
            modbus: None,
            protocol_fields: None,
        }),
    )
}

fn asset_event(
    chunk: &StreamChunk<'_>,
    asset_key: String,
    role: &str,
    identifiers: BTreeMap<String, String>,
) -> BronzeEvent {
    new_event(
        chunk.capture_id.to_string(),
        make_envelope(chunk),
        BronzeEventFamily::AssetObservation(AssetObservation {
            asset_key,
            role: Some(role.into()),
            vendor: None,
            model: None,
            firmware: None,
            hostnames: vec![],
            protocols: vec!["netflow".into()],
            identifiers,
        }),
    )
}

fn anomaly(chunk: &StreamChunk<'_>, severity: &str, reason: &str) -> BronzeEvent {
    parse_anomaly_event(
        chunk.capture_id.to_string(),
        make_envelope(chunk),
        "netflow",
        severity,
        reason,
        chunk.payload,
    )
}

// ── Inventory registration ────────────────────────────────────────────────────

inventory::submit!(crate::engine::decoders::DecoderRegistration {
    name: "netflow",
    factory: || Box::new(NetFlowDecoder::default()),
});

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    use crate::bronze::BronzeEventFamily;
    use crate::engine::{DecoderInterest, SessionDecoder, StreamChunk};
    use crate::registry::PacketContext;

    // ── Datagram builders ─────────────────────────────────────────────────────

    fn ctx(src: [u8; 4], dst: [u8; 4]) -> PacketContext {
        PacketContext {
            src_mac: [0u8; 6],
            dst_mac: [0u8; 6],
            src_ip: IpAddr::V4(Ipv4Addr::from(src)),
            dst_ip: IpAddr::V4(Ipv4Addr::from(dst)),
            src_port: 50123,
            dst_port: 2055,
            vlan_id: None,
            timestamp: 1_700_000_000,
        }
    }

    fn chunk<'a>(context: &'a PacketContext, payload: &'a [u8]) -> StreamChunk<'a> {
        StreamChunk {
            capture_id: "cap",
            segment_hash: "seg",
            interface_id: 0,
            frame_index: 0,
            timestamp: chrono::Utc::now(),
            context: context.clone(),
            ethertype: 0x0800,
            ip_proto: Some(17),
            llc: None,
            transport: TransportProtocol::Udp,
            payload,
            session_key: "sk".into(),
            captured_len: payload.len() as u64,
        }
    }

    /// NetFlow v5 datagram: 24-byte header + `count` × 48-byte zero records.
    fn v5_dgram(count: u16) -> Vec<u8> {
        let mut b = vec![0u8; NFV5_HEADER + count as usize * NFV5_RECORD];
        b[0..2].copy_from_slice(&5u16.to_be_bytes());
        b[2..4].copy_from_slice(&count.to_be_bytes());
        b[4..8].copy_from_slice(&60_000u32.to_be_bytes());   // sys_uptime_ms
        b[8..12].copy_from_slice(&1_700_000_000u32.to_be_bytes()); // unix_secs
        b[16..20].copy_from_slice(&42u32.to_be_bytes());     // flow_sequence
        b[20] = 1; b[21] = 7;                                 // engine_type / id
        b[22..24].copy_from_slice(&((1u16 << 14) | 500u16).to_be_bytes()); // sampling
        b
    }

    /// NetFlow v9 datagram with the given flowset IDs (each flowset is 4 bytes).
    fn v9_dgram(fs_ids: &[u16]) -> Vec<u8> {
        let mut b = vec![0u8; NFV9_HEADER + fs_ids.len() * 4];
        b[0..2].copy_from_slice(&9u16.to_be_bytes());
        b[2..4].copy_from_slice(&(fs_ids.len() as u16).to_be_bytes());
        b[4..8].copy_from_slice(&1000u32.to_be_bytes());
        b[8..12].copy_from_slice(&1_700_000_001u32.to_be_bytes());
        b[12..16].copy_from_slice(&99u32.to_be_bytes());     // package_sequence
        b[16..20].copy_from_slice(&1u32.to_be_bytes());      // source_id
        let mut off = NFV9_HEADER;
        for &id in fs_ids {
            b[off..off+2].copy_from_slice(&id.to_be_bytes());
            b[off+2..off+4].copy_from_slice(&4u16.to_be_bytes()); // length=4
            off += 4;
        }
        b
    }

    /// IPFIX datagram with the given set IDs (each set is 4 bytes).
    fn ipfix_dgram(set_ids: &[u16]) -> Vec<u8> {
        let total = (IPFIX_HEADER + set_ids.len() * 4) as u16;
        let mut b = vec![0u8; total as usize];
        b[0..2].copy_from_slice(&10u16.to_be_bytes());
        b[2..4].copy_from_slice(&total.to_be_bytes());
        b[4..8].copy_from_slice(&1_700_000_002u32.to_be_bytes()); // export_time
        b[8..12].copy_from_slice(&7u32.to_be_bytes());       // sequence_number
        b[12..16].copy_from_slice(&100u32.to_be_bytes());    // observation_domain_id
        let mut off = IPFIX_HEADER;
        for &id in set_ids {
            b[off..off+2].copy_from_slice(&id.to_be_bytes());
            b[off+2..off+4].copy_from_slice(&4u16.to_be_bytes());
            off += 4;
        }
        b
    }

    // ── Assertion helpers ─────────────────────────────────────────────────────

    fn find_tx(out: &[BronzeEvent]) -> &BronzeEvent {
        out.iter()
            .find(|e| matches!(&e.family, BronzeEventFamily::ProtocolTransaction(_)))
            .expect("ProtocolTransaction missing")
    }

    fn attrs(ev: &BronzeEvent) -> &BTreeMap<String, String> {
        match &ev.family {
            BronzeEventFamily::ProtocolTransaction(t) => &t.attributes,
            _ => panic!("not a ProtocolTransaction"),
        }
    }

    fn op(ev: &BronzeEvent) -> &str {
        match &ev.family {
            BronzeEventFamily::ProtocolTransaction(t) => &t.operation,
            _ => panic!("not a ProtocolTransaction"),
        }
    }

    fn has_asset(out: &[BronzeEvent], role: &str) -> bool {
        out.iter().any(|e| matches!(&e.family,
            BronzeEventFamily::AssetObservation(a) if a.role.as_deref() == Some(role)))
    }

    fn has_anomaly(out: &[BronzeEvent]) -> bool {
        out.iter().any(|e| matches!(&e.family, BronzeEventFamily::ParseAnomaly(_)))
    }

    fn anomaly_sev(ev: &BronzeEvent) -> &str {
        match &ev.family {
            BronzeEventFamily::ParseAnomaly(a) => &a.severity,
            _ => panic!("not ParseAnomaly"),
        }
    }

    // ── Test 1: v5 — header fields + exporter/collector observations ──────────

    #[test]
    fn v5_valid_two_records() {
        let mut dec = NetFlowDecoder::default();
        let c = ctx([10, 0, 0, 1], [10, 0, 0, 2]);
        let mut out = Vec::new();
        dec.on_datagram(&chunk(&c, &v5_dgram(2)), &mut out);

        let tx = find_tx(&out);
        assert_eq!(op(tx), "netflow_v5_export");
        let a = attrs(tx);
        assert_eq!(a["version"], "5");
        assert_eq!(a["record_count"], "2");
        assert_eq!(a["flow_sequence"], "42");
        assert_eq!(a["engine_type"], "1");
        assert_eq!(a["engine_id"], "7");
        assert_eq!(a["sampling_mode"], "1");
        assert_eq!(a["sampling_interval"], "500");
        assert_eq!(a["unix_secs"], "1700000000");
        assert_eq!(a["sys_uptime_ms"], "60000");
        assert!(has_asset(&out, "netflow_exporter"));
        assert!(has_asset(&out, "netflow_collector"));
        assert!(!has_anomaly(&out));
    }

    // ── Test 2: v9 — flowset_ids for Template + Data flowsets ────────────────

    #[test]
    fn v9_two_flowsets() {
        let mut dec = NetFlowDecoder::default();
        let c = ctx([192, 168, 1, 1], [192, 168, 1, 100]);
        let mut out = Vec::new();
        dec.on_datagram(&chunk(&c, &v9_dgram(&[0, 256])), &mut out);

        let tx = find_tx(&out);
        assert_eq!(op(tx), "netflow_v9_export");
        let a = attrs(tx);
        assert_eq!(a["version"], "9");
        assert_eq!(a["flowset_ids"], "0,256");
        assert_eq!(a["package_sequence"], "99");
        assert_eq!(a["source_id"], "1");
        assert!(!has_anomaly(&out));
    }

    // ── Test 3: IPFIX — Template set id=2 ────────────────────────────────────

    #[test]
    fn ipfix_template_set() {
        let mut dec = NetFlowDecoder::default();
        let c = ctx([172, 16, 0, 1], [172, 16, 0, 200]);
        let mut out = Vec::new();
        dec.on_datagram(&chunk(&c, &ipfix_dgram(&[2])), &mut out);

        let tx = find_tx(&out);
        assert_eq!(op(tx), "ipfix_export");
        let a = attrs(tx);
        assert_eq!(a["version"], "10");
        assert_eq!(a["set_ids"], "2");
        assert_eq!(a["export_time"], "1700000002");
        assert_eq!(a["sequence_number"], "7");
        assert_eq!(a["observation_domain_id"], "100");
        assert!(!has_anomaly(&out));
    }

    // ── Test 4: Unknown version → ParseAnomaly severity=low ──────────────────

    #[test]
    fn unknown_version_42() {
        let mut dec = NetFlowDecoder::default();
        let c = ctx([10, 1, 2, 3], [10, 1, 2, 99]);
        let mut dgram = vec![0u8; 24];
        dgram[1] = 42; // version = 42
        let mut out = Vec::new();
        dec.on_datagram(&chunk(&c, &dgram), &mut out);

        let an = out.iter().find(|e| matches!(&e.family, BronzeEventFamily::ParseAnomaly(_)))
            .expect("ParseAnomaly missing");
        assert_eq!(anomaly_sev(an), "low");
        assert_eq!(op(find_tx(&out)), "netflow_unknown_v42");
    }

    // ── Test 5: v5 count=5 but datagram only 100 bytes → medium anomaly ──────

    #[test]
    fn v5_length_mismatch() {
        let mut dec = NetFlowDecoder::default();
        let c = ctx([10, 0, 1, 1], [10, 0, 1, 2]);
        let mut dgram = v5_dgram(5);
        dgram.truncate(100); // expected = 24 + 5*48 = 264
        let mut out = Vec::new();
        dec.on_datagram(&chunk(&c, &dgram), &mut out);

        let an = out.iter().find(|e| matches!(&e.family, BronzeEventFamily::ParseAnomaly(_)))
            .expect("ParseAnomaly missing");
        assert_eq!(anomaly_sev(an), "medium");
        // ProtocolTransaction still emitted despite the anomaly.
        assert_eq!(op(find_tx(&out)), "netflow_v5_export");
    }

    // ── Test 6: Two distinct exporters → two AssetObservation events ──────────

    #[test]
    fn two_distinct_exporters() {
        let mut dec = NetFlowDecoder::default();
        let collector = [10, 0, 0, 99];

        let c1 = ctx([10, 0, 0, 1], collector);
        let mut out = Vec::new();
        dec.on_datagram(&chunk(&c1, &v5_dgram(1)), &mut out);

        let c2 = ctx([10, 0, 0, 2], collector);
        dec.on_datagram(&chunk(&c2, &v5_dgram(1)), &mut out);

        let exporter_obs: Vec<_> = out.iter().filter(|e| {
            matches!(&e.family, BronzeEventFamily::AssetObservation(a)
                if a.role.as_deref() == Some("netflow_exporter"))
        }).collect();

        assert_eq!(exporter_obs.len(), 2, "expected 2 distinct exporter observations");

        let ips: Vec<&str> = exporter_obs.iter().map(|e| match &e.family {
            BronzeEventFamily::AssetObservation(a) => a.asset_key.as_str(),
            _ => unreachable!(),
        }).collect();
        assert_ne!(ips[0], ips[1]);
    }

    // ── Test 7: interest() covers all four standard ports ─────────────────────

    #[test]
    fn interest_covers_standard_ports() {
        let dec = NetFlowDecoder::default();
        let ports: Vec<u16> = dec.interest().iter().filter_map(|i| match i {
            DecoderInterest::UdpPort(p) => Some(*p),
            _ => None,
        }).collect();
        for p in [2055u16, 4739, 9995, 9996] {
            assert!(ports.contains(&p), "missing port {p}");
        }
    }
}
