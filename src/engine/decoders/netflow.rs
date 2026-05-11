//! NetFlow v5 / v9 and IPFIX (v10) decoder.
//!
//! Listens on the conventional flow-export UDP ports and emits:
//!   - `ProtocolTransaction`  — one per datagram (header summary), plus one per
//!                              decoded data flow record and one per template
//!                              definition received.
//!   - `AssetObservation`     — for the exporter (src IP) and collector (dst IP),
//!                              deduplicated per session; also once per unique
//!                              source IP extracted from decoded flow records
//!                              (role `"flow_endpoint"`).
//!   - `ParseAnomaly`         — for unknown versions, wire-length mismatches, or
//!                              Data FlowSets that reference an unknown template.
//!
//! # NetFlow v9 / IPFIX template tracking
//! The decoder maintains a per-session `HashMap<TemplateKey, TemplateRecord>` keyed
//! on `(exporter_ip, domain_or_source_id, template_id)`. Templates arrive in
//! FlowSet ID 0 (v9 Template FlowSet), FlowSet ID 1 (v9 Options Template FlowSet),
//! IPFIX Set ID 2 (Template Set), or IPFIX Set ID 3 (Options Template Set). When a
//! Data FlowSet/Set (ID ≥ 256) arrives and its template is known, each record is
//! decoded into a named-field map using the curated IPFIX Information Element
//! mapping in `ipfix_field_name()`. Capped at 1 024 total templates with simple
//! LRU eviction (evict-oldest-inserted on overflow).
//!
//! # Curated IPFIX field set
//! Field types 1–22, 27–28, 56, 80, 152–153 are mapped to their IANA names.
//! IPv4 addresses (4 bytes) are formatted as dotted-decimal; IPv6 (16 bytes) as
//! colon-hex; MAC (6 bytes) as `aa:bb:cc:dd:ee:ff`; integers decoded big-endian
//! into u64 and stored as decimal strings; timestamps kept as u64 milliseconds.
//!
//! # Still deferred
//! - Options Template *contents* (scope + option fields) are not decoded; the
//!   template_id is stored so it does not collide with data template IDs.
//! - Enterprise-specific PEN field decoding (IPFIX high-bit field types) — the
//!   enterprise_number u32 is parsed and stored but the field bytes are treated
//!   opaquely (no name mapping, written as `field_<type>_pen_<pen>`).
//! - `scopeFieldCount` in Options Templates is ignored past the header.

use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};

use chrono::DateTime;
use chrono::Utc;

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

/// Hard cap on stored templates; oldest inserted is evicted when exceeded.
const TEMPLATE_CAP: usize = 1024;

// ── Template store types ──────────────────────────────────────────────────────

/// Uniquely identifies one template within a session.
/// `(exporter_ip_string, observation_domain_or_source_id, template_id)`
type TemplateKey = (String, u32, u16);

/// A single field descriptor from a Template FlowSet / Template Set.
#[derive(Debug, Clone)]
struct TemplateField {
    field_type: u16,
    field_length: u16,
    /// `Some(pen)` for IPFIX enterprise fields (high bit set on `field_type`).
    enterprise_number: Option<u32>,
}

/// Stored template record.
#[derive(Debug, Clone)]
#[allow(dead_code)] // template_id kept for diagnostics / future use
struct TemplateRecord {
    template_id: u16,
    fields: Vec<TemplateField>,
    /// `true` when this is an Options Template; option records are not decoded.
    is_options: bool,
}

// ── Decoder ───────────────────────────────────────────────────────────────────

/// Per-session de-duplication for `AssetObservation` events.
#[derive(Default)]
struct Seen {
    exporters: HashSet<String>,
    collectors: HashSet<String>,
    /// (exporter_ip, flow_src_ip) — rate-limits flow-endpoint observations.
    flow_endpoints: HashSet<(String, String)>,
}

pub(crate) struct NetFlowDecoder {
    seen: Seen,
    /// Template store keyed by (exporter, domain_or_source_id, template_id).
    templates: HashMap<TemplateKey, TemplateRecord>,
    /// Insertion-order queue for LRU eviction.
    template_order: VecDeque<TemplateKey>,
}

impl Default for NetFlowDecoder {
    fn default() -> Self {
        Self {
            seen: Seen::default(),
            templates: HashMap::new(),
            template_order: VecDeque::new(),
        }
    }
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
            5  => self.handle_v5(chunk, out),
            9  => self.handle_v9(chunk, out),
            10 => self.handle_ipfix(chunk, out),
            v  => {
                out.push(anomaly(chunk, "low",
                    &format!("unsupported NetFlow/IPFIX version {v}")));
                let mut attr = BTreeMap::new();
                attr.insert("version".into(), v.to_string());
                out.push(tx_event(chunk, format!("netflow_unknown_v{v}"), attr, vec![]));
            }
        }
    }

    fn on_idle_flush(&mut self, _timestamp: DateTime<Utc>, _out: &mut Vec<BronzeEvent>) {
        self.templates.clear();
        self.template_order.clear();
        self.seen.flow_endpoints.clear();
        // Exporter/collector de-dup sets are intentionally NOT cleared here;
        // those are cheap and semantically bound to the capture session lifetime.
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

        out.push(tx_event(chunk, "netflow_v5_export".into(), attr, vec![]));
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
        let exporter = chunk.context.src_ip.to_string();

        // Walk FlowSets, collecting IDs for the summary event.
        let mut fs_ids: Vec<String> = Vec::new();
        let mut off = NFV9_HEADER;
        while off + 4 <= data.len() {
            let fs_id = u16::from_be_bytes([data[off], data[off + 1]]);
            let fs_len = u16::from_be_bytes([data[off + 2], data[off + 3]]) as usize;
            fs_ids.push(fs_id.to_string());
            if fs_len < 4 { break; }

            let fs_data = if off + fs_len <= data.len() {
                &data[off..off + fs_len]
            } else {
                // truncated — skip
                off += fs_len;
                continue;
            };

            match fs_id {
                0 => self.parse_v9_template_flowset(fs_data, &exporter, source_id, false, chunk, out),
                1 => self.parse_v9_template_flowset(fs_data, &exporter, source_id, true, chunk, out),
                id if id >= 256 => {
                    self.decode_v9_data_flowset(fs_data, &exporter, source_id, id, chunk, out);
                }
                _ => {} // reserved IDs 2–255, ignore
            }

            off += fs_len;
        }

        let mut attr = BTreeMap::new();
        attr.insert("version".into(), "9".into());
        attr.insert("flowset_count".into(), count.to_string());
        attr.insert("flowset_ids".into(), fs_ids.join(","));
        attr.insert("package_sequence".into(), package_sequence.to_string());
        attr.insert("source_id".into(), source_id.to_string());
        attr.insert("unix_secs".into(), unix_secs.to_string());
        attr.insert("sys_uptime_ms".into(), sys_uptime_ms.to_string());

        out.push(tx_event(chunk, "netflow_v9_export".into(), attr, vec![]));
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
        let exporter = chunk.context.src_ip.to_string();

        if total_length != data.len() {
            out.push(anomaly(chunk, "medium", &format!(
                "IPFIX length field {total_length} disagrees with datagram {}B",
                data.len()
            )));
        }

        let mut set_ids: Vec<String> = Vec::new();
        let mut off = IPFIX_HEADER;
        while off + 4 <= data.len() {
            let set_id = u16::from_be_bytes([data[off], data[off + 1]]);
            let set_len = u16::from_be_bytes([data[off + 2], data[off + 3]]) as usize;
            set_ids.push(set_id.to_string());
            if set_len < 4 { break; }

            let set_data = if off + set_len <= data.len() {
                &data[off..off + set_len]
            } else {
                off += set_len;
                continue;
            };

            match set_id {
                2 => self.parse_ipfix_template_set(set_data, &exporter, observation_domain_id, false, chunk, out),
                3 => self.parse_ipfix_template_set(set_data, &exporter, observation_domain_id, true, chunk, out),
                id if id >= 256 => {
                    self.decode_ipfix_data_set(set_data, &exporter, observation_domain_id, id, chunk, out);
                }
                _ => {} // reserved IDs 4–255
            }

            off += set_len;
        }

        let mut attr = BTreeMap::new();
        attr.insert("version".into(), "10".into());
        attr.insert("set_ids".into(), set_ids.join(","));
        attr.insert("total_length".into(), total_length.to_string());
        attr.insert("export_time".into(), export_time.to_string());
        attr.insert("sequence_number".into(), sequence_number.to_string());
        attr.insert("observation_domain_id".into(), observation_domain_id.to_string());

        out.push(tx_event(chunk, "ipfix_export".into(), attr, vec![]));
        self.emit_assets(chunk, "10", out);
    }

    // ── Template parsing ──────────────────────────────────────────────────────

    /// Parse a NetFlow v9 Template FlowSet (ID 0) or Options Template FlowSet (ID 1).
    /// For Options Templates we record the template ID but skip field decoding.
    fn parse_v9_template_flowset(
        &mut self,
        data: &[u8],
        exporter: &str,
        source_id: u32,
        is_options: bool,
        chunk: &StreamChunk<'_>,
        out: &mut Vec<BronzeEvent>,
    ) {
        // data[0..4] = flowset_id + length (already validated by caller)
        let mut off = 4usize; // skip flowset header

        while off + 4 <= data.len() {
            let template_id = u16::from_be_bytes([data[off], data[off + 1]]);
            let field_count = u16::from_be_bytes([data[off + 2], data[off + 3]]) as usize;
            off += 4;

            if is_options {
                // Options Template: scope_field_count (2 bytes) + option_field_count (2 bytes)
                // We track the template ID but skip the field descriptors.
                // Minimum: 4 bytes for scope+option counts + field_count * 4 bytes
                let skip = 4 + field_count * 4;
                if off + skip > data.len() { break; }
                let key: TemplateKey = (exporter.to_string(), source_id, template_id);
                let record = TemplateRecord {
                    template_id,
                    fields: vec![],
                    is_options: true,
                };
                self.store_template(key.clone(), record);
                self.emit_template_lifecycle(chunk, "netflow_template_received", template_id, 0, true, out);
                off += skip;
                continue;
            }

            if off + field_count * 4 > data.len() { break; }

            let mut fields = Vec::with_capacity(field_count);
            for _ in 0..field_count {
                let ft = u16::from_be_bytes([data[off], data[off + 1]]);
                let fl = u16::from_be_bytes([data[off + 2], data[off + 3]]);
                fields.push(TemplateField { field_type: ft, field_length: fl, enterprise_number: None });
                off += 4;
            }

            let key: TemplateKey = (exporter.to_string(), source_id, template_id);
            let fc = fields.len();
            let record = TemplateRecord { template_id, fields, is_options: false };
            self.store_template(key, record);
            self.emit_template_lifecycle(chunk, "netflow_template_received", template_id, fc, false, out);
        }
    }

    /// Parse an IPFIX Template Set (Set ID 2) or Options Template Set (Set ID 3).
    fn parse_ipfix_template_set(
        &mut self,
        data: &[u8],
        exporter: &str,
        domain: u32,
        is_options: bool,
        chunk: &StreamChunk<'_>,
        out: &mut Vec<BronzeEvent>,
    ) {
        let mut off = 4usize; // skip set header

        while off + 4 <= data.len() {
            // Padding: IPFIX aligns sets to 4-byte boundary; 0x00 pad bytes.
            if data[off] == 0 && data[off + 1] == 0 { break; }

            let template_id = u16::from_be_bytes([data[off], data[off + 1]]);
            let field_count = u16::from_be_bytes([data[off + 2], data[off + 3]]) as usize;
            off += 4;

            if is_options {
                // Options Template: scope_field_count (2 bytes) precedes the field list.
                // We track the template but don't decode option records.
                if off + 2 > data.len() { break; }
                let scope_count = u16::from_be_bytes([data[off], data[off + 1]]) as usize;
                off += 2;
                // Skip all field specifiers (scope + option), each 4 bytes, plus
                // possible 2-byte enterprise numbers for enterprise fields.
                let total_fields = field_count; // field_count = scope + option count
                let mut skipped = 0;
                while skipped < total_fields && off + 4 <= data.len() {
                    let ft = u16::from_be_bytes([data[off], data[off + 1]]);
                    off += 4;
                    if ft & 0x8000 != 0 {
                        if off + 4 <= data.len() { off += 4; } // enterprise number
                    }
                    skipped += 1;
                }
                let _ = scope_count; // tracked for future use
                let key: TemplateKey = (exporter.to_string(), domain, template_id);
                let record = TemplateRecord { template_id, fields: vec![], is_options: true };
                self.store_template(key, record);
                self.emit_template_lifecycle(chunk, "ipfix_template_received", template_id, 0, true, out);
                continue;
            }

            let mut fields = Vec::with_capacity(field_count);
            let mut fi = 0;
            while fi < field_count && off + 4 <= data.len() {
                let raw_ft = u16::from_be_bytes([data[off], data[off + 1]]);
                let fl = u16::from_be_bytes([data[off + 2], data[off + 3]]);
                off += 4;
                let (field_type, enterprise_number) = if raw_ft & 0x8000 != 0 {
                    // Enterprise bit set — consume 4-byte PEN.
                    let pen = if off + 4 <= data.len() {
                        let v = u32be(&data[off..]);
                        off += 4;
                        Some(v)
                    } else {
                        Some(0)
                    };
                    (raw_ft & 0x7FFF, pen)
                } else {
                    (raw_ft, None)
                };
                fields.push(TemplateField { field_type, field_length: fl, enterprise_number });
                fi += 1;
            }

            let key: TemplateKey = (exporter.to_string(), domain, template_id);
            let fc = fields.len();
            let record = TemplateRecord { template_id, fields, is_options: false };
            self.store_template(key, record);
            self.emit_template_lifecycle(chunk, "ipfix_template_received", template_id, fc, false, out);
        }
    }

    // ── Template store management ─────────────────────────────────────────────

    fn store_template(&mut self, key: TemplateKey, record: TemplateRecord) {
        if self.templates.contains_key(&key) {
            // Update in place (template refresh); no eviction needed.
            self.templates.insert(key, record);
            return;
        }
        // Evict oldest if at cap.
        if self.templates.len() >= TEMPLATE_CAP {
            if let Some(oldest) = self.template_order.pop_front() {
                self.templates.remove(&oldest);
            }
        }
        self.template_order.push_back(key.clone());
        self.templates.insert(key, record);
    }

    // ── Data FlowSet / Set decode ─────────────────────────────────────────────

    fn decode_v9_data_flowset(
        &mut self,
        data: &[u8],
        exporter: &str,
        source_id: u32,
        template_id: u16,
        chunk: &StreamChunk<'_>,
        out: &mut Vec<BronzeEvent>,
    ) {
        let key: TemplateKey = (exporter.to_string(), source_id, template_id);
        let record = match self.templates.get(&key) {
            Some(r) if !r.is_options => r.clone(),
            _ => {
                out.push(anomaly(chunk, "low", &format!(
                    "template_unresolved: v9 source_id={source_id} template_id={template_id}"
                )));
                let mut attr = BTreeMap::new();
                attr.insert("source_id".into(), source_id.to_string());
                attr.insert("template_id".into(), template_id.to_string());
                attr.insert("reason".into(), "template_unresolved".into());
                out.push(tx_event(chunk, "netflow_data_flowset_skipped".into(), attr, vec![]));
                return;
            }
        };

        let record_len: usize = record.fields.iter().map(|f| f.field_length as usize).sum();
        if record_len == 0 { return; }

        let mut off = 4usize; // skip flowset header
        while off + record_len <= data.len() {
            let record_data = &data[off..off + record_len];
            let (attr, obj_refs) = decode_record_fields(record_data, &record.fields);
            if !attr.is_empty() {
                // Emit flow_endpoint AssetObservation for source IP.
                if let Some(src_ip) = attr.get("sourceIPv4Address").or_else(|| attr.get("sourceIPv6Address")) {
                    let ep_key = (exporter.to_string(), src_ip.clone());
                    if self.seen.flow_endpoints.insert(ep_key) {
                        let mut ids = BTreeMap::new();
                        ids.insert("ip".into(), src_ip.clone());
                        out.push(asset_event(chunk, src_ip.clone(), "flow_endpoint", ids));
                    }
                }
                out.push(tx_event(chunk, "netflow_flow_record".into(), attr, obj_refs));
            }
            off += record_len;
        }
    }

    fn decode_ipfix_data_set(
        &mut self,
        data: &[u8],
        exporter: &str,
        domain: u32,
        template_id: u16,
        chunk: &StreamChunk<'_>,
        out: &mut Vec<BronzeEvent>,
    ) {
        let key: TemplateKey = (exporter.to_string(), domain, template_id);
        let record = match self.templates.get(&key) {
            Some(r) if !r.is_options => r.clone(),
            _ => {
                out.push(anomaly(chunk, "low", &format!(
                    "template_unresolved: ipfix domain={domain} template_id={template_id}"
                )));
                let mut attr = BTreeMap::new();
                attr.insert("observation_domain_id".into(), domain.to_string());
                attr.insert("template_id".into(), template_id.to_string());
                attr.insert("reason".into(), "template_unresolved".into());
                out.push(tx_event(chunk, "ipfix_data_set_skipped".into(), attr, vec![]));
                return;
            }
        };

        let record_len: usize = record.fields.iter().map(|f| f.field_length as usize).sum();
        if record_len == 0 { return; }

        let mut off = 4usize; // skip set header
        while off + record_len <= data.len() {
            // Skip IPFIX padding (0-byte padding at end of set).
            if data[off] == 0 && record_len > 1 {
                // Allow up to 3 padding bytes at the tail; stop walking.
                break;
            }
            let record_data = &data[off..off + record_len];
            let (attr, obj_refs) = decode_record_fields(record_data, &record.fields);
            if !attr.is_empty() {
                if let Some(src_ip) = attr.get("sourceIPv4Address").or_else(|| attr.get("sourceIPv6Address")) {
                    let ep_key = (exporter.to_string(), src_ip.clone());
                    if self.seen.flow_endpoints.insert(ep_key) {
                        let mut ids = BTreeMap::new();
                        ids.insert("ip".into(), src_ip.clone());
                        out.push(asset_event(chunk, src_ip.clone(), "flow_endpoint", ids));
                    }
                }
                out.push(tx_event(chunk, "ipfix_flow_record".into(), attr, obj_refs));
            }
            off += record_len;
        }
    }

    // ── Asset emission ────────────────────────────────────────────────────────

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

    /// Emit a template lifecycle `ProtocolTransaction`.
    fn emit_template_lifecycle(
        &self,
        chunk: &StreamChunk<'_>,
        operation: &str,
        template_id: u16,
        field_count: usize,
        is_options: bool,
        out: &mut Vec<BronzeEvent>,
    ) {
        let mut attr = BTreeMap::new();
        attr.insert("template_id".into(), template_id.to_string());
        attr.insert("field_count".into(), field_count.to_string());
        attr.insert("is_options_template".into(), is_options.to_string());
        out.push(tx_event(chunk, operation.to_string(), attr, vec![]));
    }
}

// ── IPFIX field decode ────────────────────────────────────────────────────────

/// Map a well-known IPFIX Information Element ID to its IANA name.
/// Returns `None` for unmapped elements; callers fall back to `field_<type>`.
fn ipfix_field_name(field_type: u16) -> Option<&'static str> {
    match field_type {
        1   => Some("octetDeltaCount"),
        2   => Some("packetDeltaCount"),
        4   => Some("protocolIdentifier"),
        5   => Some("ipClassOfService"),
        6   => Some("tcpControlBits"),
        7   => Some("sourceTransportPort"),
        8   => Some("sourceIPv4Address"),
        9   => Some("sourceIPv4PrefixLength"),
        10  => Some("ingressInterface"),
        11  => Some("destinationTransportPort"),
        12  => Some("destinationIPv4Address"),
        13  => Some("destinationIPv4PrefixLength"),
        14  => Some("egressInterface"),
        15  => Some("ipNextHopIPv4Address"),
        16  => Some("bgpSourceAsNumber"),
        17  => Some("bgpDestinationAsNumber"),
        21  => Some("flowEndSysUpTime"),
        22  => Some("flowStartSysUpTime"),
        27  => Some("sourceIPv6Address"),
        28  => Some("destinationIPv6Address"),
        56  => Some("sourceMacAddress"),
        80  => Some("destinationMacAddress"),
        152 => Some("flowStartMilliseconds"),
        153 => Some("flowEndMilliseconds"),
        _   => None,
    }
}

/// Decode a raw record byte slice against its field list, returning:
/// - `BTreeMap<String, String>` — named attribute map
/// - `Vec<String>` — object refs (flow endpoint string if endpoints known)
fn decode_record_fields(
    data: &[u8],
    fields: &[TemplateField],
) -> (BTreeMap<String, String>, Vec<String>) {
    let mut attr = BTreeMap::new();
    let mut off = 0usize;

    for field in fields {
        let fl = field.field_length as usize;
        if off + fl > data.len() { break; }
        let bytes = &data[off..off + fl];
        off += fl;

        let name = if field.enterprise_number.is_some() {
            // Enterprise field: store opaquely.
            format!("field_{}_pen_{}", field.field_type, field.enterprise_number.unwrap_or(0))
        } else {
            match ipfix_field_name(field.field_type) {
                Some(n) => n.to_string(),
                None    => format!("field_{}", field.field_type),
            }
        };

        let value = format_field_value(field.field_type, field.enterprise_number, bytes);
        attr.insert(name, value);
    }

    // Build object_ref when both src and dst endpoints are present.
    let obj_refs = build_flow_ref(&attr);

    (attr, obj_refs)
}

/// Format a field value according to its IPFIX type and declared length.
fn format_field_value(field_type: u16, enterprise_number: Option<u32>, bytes: &[u8]) -> String {
    if enterprise_number.is_some() {
        return bytes_to_hex(bytes);
    }
    match field_type {
        // IPv4 addresses (4 bytes)
        8 | 12 | 15 => {
            if bytes.len() == 4 {
                format!("{}.{}.{}.{}", bytes[0], bytes[1], bytes[2], bytes[3])
            } else {
                bytes_to_hex(bytes)
            }
        }
        // IPv6 addresses (16 bytes)
        27 | 28 => {
            if bytes.len() == 16 {
                format_ipv6(bytes)
            } else {
                bytes_to_hex(bytes)
            }
        }
        // MAC addresses (6 bytes)
        56 | 80 => {
            if bytes.len() == 6 {
                format!("{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
                    bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5])
            } else {
                bytes_to_hex(bytes)
            }
        }
        // Everything else: big-endian integer or timestamp
        _ => {
            read_be_u64(bytes).to_string()
        }
    }
}

/// Build a flow object ref string when src/dst IP+port are available.
fn build_flow_ref(attr: &BTreeMap<String, String>) -> Vec<String> {
    let src_ip = attr.get("sourceIPv4Address")
        .or_else(|| attr.get("sourceIPv6Address"));
    let dst_ip = attr.get("destinationIPv4Address")
        .or_else(|| attr.get("destinationIPv6Address"));
    let src_port = attr.get("sourceTransportPort");
    let dst_port = attr.get("destinationTransportPort");

    match (src_ip, src_port, dst_ip, dst_port) {
        (Some(si), Some(sp), Some(di), Some(dp)) => {
            vec![format!("flow:{si}:{sp}->{di}:{dp}")]
        }
        _ => vec![],
    }
}

/// Read up to 8 bytes as a big-endian u64 (shorter lengths are zero-padded).
fn read_be_u64(bytes: &[u8]) -> u64 {
    let mut buf = [0u8; 8];
    let n = bytes.len().min(8);
    buf[8 - n..].copy_from_slice(&bytes[..n]);
    u64::from_be_bytes(buf)
}

/// Format 16 bytes as a compressed IPv6 string.
fn format_ipv6(b: &[u8]) -> String {
    assert!(b.len() == 16);
    let groups: Vec<u16> = (0..8)
        .map(|i| u16::from_be_bytes([b[i * 2], b[i * 2 + 1]]))
        .collect();

    // Find longest run of consecutive zero groups for :: compression.
    let (best_start, best_len) = {
        let (mut bs, mut bl, mut cs, mut cl) = (0usize, 0usize, 0usize, 0usize);
        for i in 0..8 {
            if groups[i] == 0 {
                if cl == 0 { cs = i; }
                cl += 1;
                if cl > bl { bl = cl; bs = cs; }
            } else {
                cl = 0;
            }
        }
        (bs, bl)
    };

    if best_len >= 2 {
        let left: Vec<String> = groups[..best_start].iter().map(|g| format!("{g:x}")).collect();
        let right: Vec<String> = groups[best_start + best_len..].iter().map(|g| format!("{g:x}")).collect();
        format!("{}::{}", left.join(":"), right.join(":"))
    } else {
        groups.iter().map(|g| format!("{g:x}")).collect::<Vec<_>>().join(":")
    }
}

fn bytes_to_hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect::<Vec<_>>().join("")
}

// ── Wire helpers ──────────────────────────────────────────────────────────────

/// Read a big-endian u32 from an at-least-4-byte slice.
#[inline]
fn u32be(b: &[u8]) -> u32 {
    u32::from_be_bytes([b[0], b[1], b[2], b[3]])
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

fn tx_event(
    chunk: &StreamChunk<'_>,
    operation: String,
    attributes: BTreeMap<String, String>,
    object_refs: Vec<String>,
) -> BronzeEvent {
    new_event(
        chunk.capture_id.to_string(),
        make_envelope(chunk),
        BronzeEventFamily::ProtocolTransaction(ProtocolTransaction {
            operation,
            status: "observed".into(),
            request_summary: None,
            response_summary: None,
            object_refs,
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

    /// NetFlow v9 datagram with a Template FlowSet (ID=0) defining one template,
    /// followed by one Data FlowSet using that template.
    ///
    /// Template fields: srcAddr (type 8, len 4), dstAddr (type 12, len 4),
    ///                  srcPort (type 7, len 2), dstPort (type 11, len 2),
    ///                  packets (type 2, len 4).
    fn v9_template_then_data(
        source_id: u32,
        template_id: u16,
        src_ip: [u8; 4],
        dst_ip: [u8; 4],
        src_port: u16,
        dst_port: u16,
        packets: u32,
    ) -> Vec<u8> {
        // Template FlowSet: header(4) + template_hdr(4) + 5 fields * 4 = 28 bytes total
        let tmpl_fs_len: u16 = 4 + 4 + 5 * 4; // 28
        // Data FlowSet: header(4) + 4+4+2+2+4 = 20 bytes
        let rec_len: usize = 4 + 4 + 2 + 2 + 4;
        let data_fs_len: u16 = 4 + rec_len as u16; // 20

        let total = NFV9_HEADER + tmpl_fs_len as usize + data_fs_len as usize;
        let mut b = vec![0u8; total];

        // v9 header
        b[0..2].copy_from_slice(&9u16.to_be_bytes());
        b[2..4].copy_from_slice(&2u16.to_be_bytes()); // count=2 flowsets
        b[4..8].copy_from_slice(&1000u32.to_be_bytes());
        b[8..12].copy_from_slice(&1_700_000_001u32.to_be_bytes());
        b[12..16].copy_from_slice(&1u32.to_be_bytes()); // package_sequence
        b[16..20].copy_from_slice(&source_id.to_be_bytes());

        let mut off = NFV9_HEADER;

        // Template FlowSet header
        b[off..off+2].copy_from_slice(&0u16.to_be_bytes()); // flowset_id=0
        b[off+2..off+4].copy_from_slice(&tmpl_fs_len.to_be_bytes());
        off += 4;

        // Template header: template_id + field_count=5
        b[off..off+2].copy_from_slice(&template_id.to_be_bytes());
        b[off+2..off+4].copy_from_slice(&5u16.to_be_bytes());
        off += 4;

        // Fields: (type, length)
        let fields: [(u16, u16); 5] = [(8, 4), (12, 4), (7, 2), (11, 2), (2, 4)];
        for (ft, fl) in fields {
            b[off..off+2].copy_from_slice(&ft.to_be_bytes());
            b[off+2..off+4].copy_from_slice(&fl.to_be_bytes());
            off += 4;
        }

        // Data FlowSet header
        b[off..off+2].copy_from_slice(&template_id.to_be_bytes());
        b[off+2..off+4].copy_from_slice(&data_fs_len.to_be_bytes());
        off += 4;

        // Record data
        b[off..off+4].copy_from_slice(&src_ip);   off += 4;
        b[off..off+4].copy_from_slice(&dst_ip);   off += 4;
        b[off..off+2].copy_from_slice(&src_port.to_be_bytes()); off += 2;
        b[off..off+2].copy_from_slice(&dst_port.to_be_bytes()); off += 2;
        b[off..off+4].copy_from_slice(&packets.to_be_bytes());

        b
    }

    /// IPFIX datagram with Template Set (ID=2) and Data Set using that template.
    /// Fields: srcAddr (8, 4), dstAddr (12, 4), srcPort (7, 2), dstPort (11, 2).
    fn ipfix_template_then_data(
        domain: u32,
        template_id: u16,
        src_ip: [u8; 4],
        dst_ip: [u8; 4],
        src_port: u16,
        dst_port: u16,
    ) -> Vec<u8> {
        // Template Set: set_hdr(4) + tmpl_hdr(4) + 4 fields*4 = 24
        let tmpl_set_len: u16 = 4 + 4 + 4 * 4;
        // Data Set: set_hdr(4) + 4+4+2+2 = 16
        let rec_len: usize = 4 + 4 + 2 + 2;
        let data_set_len: u16 = 4 + rec_len as u16;

        let total = IPFIX_HEADER + tmpl_set_len as usize + data_set_len as usize;
        let mut b = vec![0u8; total];

        // IPFIX header
        b[0..2].copy_from_slice(&10u16.to_be_bytes());
        b[2..4].copy_from_slice(&(total as u16).to_be_bytes());
        b[4..8].copy_from_slice(&1_700_000_002u32.to_be_bytes());
        b[8..12].copy_from_slice(&7u32.to_be_bytes());
        b[12..16].copy_from_slice(&domain.to_be_bytes());

        let mut off = IPFIX_HEADER;

        // Template Set header
        b[off..off+2].copy_from_slice(&2u16.to_be_bytes()); // set_id=2
        b[off+2..off+4].copy_from_slice(&tmpl_set_len.to_be_bytes());
        off += 4;

        // Template header: template_id + field_count=4
        b[off..off+2].copy_from_slice(&template_id.to_be_bytes());
        b[off+2..off+4].copy_from_slice(&4u16.to_be_bytes());
        off += 4;

        // Fields
        let fields: [(u16, u16); 4] = [(8, 4), (12, 4), (7, 2), (11, 2)];
        for (ft, fl) in fields {
            b[off..off+2].copy_from_slice(&ft.to_be_bytes());
            b[off+2..off+4].copy_from_slice(&fl.to_be_bytes());
            off += 4;
        }

        // Data Set header
        b[off..off+2].copy_from_slice(&template_id.to_be_bytes());
        b[off+2..off+4].copy_from_slice(&data_set_len.to_be_bytes());
        off += 4;

        // Record
        b[off..off+4].copy_from_slice(&src_ip);   off += 4;
        b[off..off+4].copy_from_slice(&dst_ip);   off += 4;
        b[off..off+2].copy_from_slice(&src_port.to_be_bytes()); off += 2;
        b[off..off+2].copy_from_slice(&dst_port.to_be_bytes());

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

    fn find_tx_by_op<'a>(out: &'a [BronzeEvent], op_name: &str) -> Option<&'a BronzeEvent> {
        out.iter().find(|e| match &e.family {
            BronzeEventFamily::ProtocolTransaction(t) => t.operation == op_name,
            _ => false,
        })
    }

    #[allow(dead_code)]
    fn all_tx_by_op<'a>(out: &'a [BronzeEvent], op_name: &str) -> Vec<&'a BronzeEvent> {
        out.iter().filter(|e| match &e.family {
            BronzeEventFamily::ProtocolTransaction(t) => t.operation == op_name,
            _ => false,
        }).collect()
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

    fn anomaly_reason(out: &[BronzeEvent]) -> String {
        out.iter().find_map(|e| match &e.family {
            BronzeEventFamily::ParseAnomaly(a) => Some(a.reason.clone()),
            _ => None,
        }).unwrap_or_default()
    }

    fn anomaly_sev(ev: &BronzeEvent) -> &str {
        match &ev.family {
            BronzeEventFamily::ParseAnomaly(a) => &a.severity,
            _ => panic!("not ParseAnomaly"),
        }
    }

    fn obj_refs(ev: &BronzeEvent) -> &[String] {
        match &ev.family {
            BronzeEventFamily::ProtocolTransaction(t) => &t.object_refs,
            _ => panic!("not a ProtocolTransaction"),
        }
    }

    // ── Existing tests (unchanged) ────────────────────────────────────────────

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

    // ── Test 2: v9 — flowset_ids for Template + Options Template flowsets ───────

    #[test]
    fn v9_two_flowsets() {
        let mut dec = NetFlowDecoder::default();
        let c = ctx([192, 168, 1, 1], [192, 168, 1, 100]);
        let mut out = Vec::new();
        // Use ID 0 (template) and ID 1 (options template) — no data flowsets so
        // no template_unresolved anomalies are emitted.
        dec.on_datagram(&chunk(&c, &v9_dgram(&[0, 1])), &mut out);

        let tx = find_tx_by_op(&out, "netflow_v9_export")
            .expect("netflow_v9_export missing");
        let a = attrs(tx);
        assert_eq!(a["version"], "9");
        assert_eq!(a["flowset_ids"], "0,1");
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

    // ── New tests ─────────────────────────────────────────────────────────────

    // ── Test 8: v9 template received → stored and lifecycle event emitted ─────

    #[test]
    fn v9_template_stored_and_lifecycle_event() {
        let mut dec = NetFlowDecoder::default();
        let c = ctx([10, 0, 0, 1], [10, 0, 0, 2]);
        let mut out = Vec::new();

        let dgram = v9_template_then_data(1, 256, [1,2,3,4], [5,6,7,8], 1234, 80, 10);
        dec.on_datagram(&chunk(&c, &dgram), &mut out);

        // Template lifecycle event
        let lifecycle = find_tx_by_op(&out, "netflow_template_received")
            .expect("netflow_template_received missing");
        let a = attrs(lifecycle);
        assert_eq!(a["template_id"], "256");
        assert_eq!(a["field_count"], "5");
        assert_eq!(a["is_options_template"], "false");

        // Template must be stored
        let key: TemplateKey = ("10.0.0.1".to_string(), 1, 256);
        assert!(dec.templates.contains_key(&key), "template not stored");
    }

    // ── Test 9: v9 data flowset decoded against stored template ───────────────

    #[test]
    fn v9_data_flowset_decoded() {
        let mut dec = NetFlowDecoder::default();
        let c = ctx([10, 0, 0, 1], [10, 0, 0, 2]);
        let mut out = Vec::new();

        let dgram = v9_template_then_data(
            1, 257,
            [192, 168, 1, 10], [10, 20, 30, 40],
            4567, 443, 99,
        );
        dec.on_datagram(&chunk(&c, &dgram), &mut out);

        let flow = find_tx_by_op(&out, "netflow_flow_record")
            .expect("netflow_flow_record missing");
        let a = attrs(flow);
        assert_eq!(a["sourceIPv4Address"], "192.168.1.10");
        assert_eq!(a["destinationIPv4Address"], "10.20.30.40");
        assert_eq!(a["sourceTransportPort"], "4567");
        assert_eq!(a["destinationTransportPort"], "443");
        assert_eq!(a["packetDeltaCount"], "99");

        // object_refs
        let refs = obj_refs(flow);
        assert_eq!(refs.len(), 1);
        assert_eq!(refs[0], "flow:192.168.1.10:4567->10.20.30.40:443");
    }

    // ── Test 10: v9 data flowset without template → template_unresolved anomaly

    #[test]
    fn v9_data_flowset_no_template_anomaly() {
        let mut dec = NetFlowDecoder::default();
        let c = ctx([10, 0, 0, 1], [10, 0, 0, 2]);
        let mut out = Vec::new();

        // Data-only datagram: flowset_id=300, length=8, 4 bytes of data
        let total = NFV9_HEADER + 8;
        let mut b = vec![0u8; total];
        b[0..2].copy_from_slice(&9u16.to_be_bytes());
        b[2..4].copy_from_slice(&1u16.to_be_bytes());
        b[4..8].copy_from_slice(&1000u32.to_be_bytes());
        b[8..12].copy_from_slice(&1_700_000_001u32.to_be_bytes());
        b[12..16].copy_from_slice(&1u32.to_be_bytes());
        b[16..20].copy_from_slice(&42u32.to_be_bytes()); // source_id=42
        b[20..22].copy_from_slice(&300u16.to_be_bytes()); // data flowset id=300
        b[22..24].copy_from_slice(&8u16.to_be_bytes());   // length=8
        // 4 bytes of zero data
        dec.on_datagram(&chunk(&c, &b), &mut out);

        assert!(has_anomaly(&out), "expected template_unresolved ParseAnomaly");
        let reason = anomaly_reason(&out);
        assert!(reason.contains("template_unresolved"), "reason: {reason}");
    }

    // ── Test 11: IPFIX template with enterprise fields → enterprise fields skipped

    #[test]
    fn ipfix_enterprise_field_skipped() {
        let mut dec = NetFlowDecoder::default();
        let c = ctx([172, 16, 0, 1], [172, 16, 0, 2]);
        let mut out = Vec::new();

        // Build IPFIX Template Set with 2 fields: regular (type 8, len 4) +
        // enterprise (type 0x8001 → type=1 with enterprise bit, len 4, pen=12345).
        // Template Set: set_hdr(4) + tmpl_hdr(4) + field1(4) + field2_type(4) + pen(4) = 20
        let tmpl_set_len: u16 = 4 + 4 + 4 + 4 + 4; // 20
        // Data Set with one record: 4 + 4 = 8 bytes
        let data_set_len: u16 = 4 + 4 + 4; // 12

        let total = IPFIX_HEADER + tmpl_set_len as usize + data_set_len as usize;
        let mut b = vec![0u8; total];
        let domain: u32 = 100;
        let template_id: u16 = 300;

        b[0..2].copy_from_slice(&10u16.to_be_bytes());
        b[2..4].copy_from_slice(&(total as u16).to_be_bytes());
        b[4..8].copy_from_slice(&1_700_000_002u32.to_be_bytes());
        b[8..12].copy_from_slice(&7u32.to_be_bytes());
        b[12..16].copy_from_slice(&domain.to_be_bytes());

        let mut off = IPFIX_HEADER;

        // Template Set header
        b[off..off+2].copy_from_slice(&2u16.to_be_bytes());
        b[off+2..off+4].copy_from_slice(&tmpl_set_len.to_be_bytes());
        off += 4;
        // Template header: template_id + field_count=2
        b[off..off+2].copy_from_slice(&template_id.to_be_bytes());
        b[off+2..off+4].copy_from_slice(&2u16.to_be_bytes());
        off += 4;
        // Field 1: regular srcAddr (type=8, len=4)
        b[off..off+2].copy_from_slice(&8u16.to_be_bytes());
        b[off+2..off+4].copy_from_slice(&4u16.to_be_bytes());
        off += 4;
        // Field 2: enterprise (type=0x8001, len=4, pen=12345)
        b[off..off+2].copy_from_slice(&0x8001u16.to_be_bytes());
        b[off+2..off+4].copy_from_slice(&4u16.to_be_bytes());
        off += 4;
        b[off..off+4].copy_from_slice(&12345u32.to_be_bytes()); // PEN
        off += 4;

        // Data Set: header + record (srcAddr=1.2.3.4, enterprise_field=0xDEADBEEF)
        b[off..off+2].copy_from_slice(&template_id.to_be_bytes());
        b[off+2..off+4].copy_from_slice(&data_set_len.to_be_bytes());
        off += 4;
        b[off..off+4].copy_from_slice(&[1, 2, 3, 4]); off += 4;
        b[off..off+4].copy_from_slice(&0xDEADBEEFu32.to_be_bytes());

        dec.on_datagram(&chunk(&c, &b), &mut out);

        // No anomaly for enterprise fields
        assert!(!has_anomaly(&out), "should not emit anomaly for enterprise fields");

        // Template stored
        let key: TemplateKey = ("172.16.0.1".to_string(), domain, template_id);
        assert!(dec.templates.contains_key(&key));

        // Flow record emitted with sourceIPv4Address
        let flow = find_tx_by_op(&out, "ipfix_flow_record")
            .expect("ipfix_flow_record missing");
        let a = attrs(flow);
        assert_eq!(a["sourceIPv4Address"], "1.2.3.4");
        // Enterprise field stored with pen suffix
        assert!(a.keys().any(|k| k.contains("pen_12345")), "enterprise field not stored: {a:?}");
    }

    // ── Test 12: IPFIX data set → ipfix_flow_record with named attributes ──────

    #[test]
    fn ipfix_data_set_flow_record() {
        let mut dec = NetFlowDecoder::default();
        let c = ctx([10, 1, 1, 1], [10, 1, 1, 2]);
        let mut out = Vec::new();

        let dgram = ipfix_template_then_data(
            99, 258,
            [172, 31, 0, 1], [8, 8, 8, 8],
            54321, 53,
        );
        dec.on_datagram(&chunk(&c, &dgram), &mut out);

        let flow = find_tx_by_op(&out, "ipfix_flow_record")
            .expect("ipfix_flow_record missing");
        let a = attrs(flow);
        assert_eq!(a["sourceIPv4Address"], "172.31.0.1");
        assert_eq!(a["destinationIPv4Address"], "8.8.8.8");
        assert_eq!(a["sourceTransportPort"], "54321");
        assert_eq!(a["destinationTransportPort"], "53");

        // operation status
        match &flow.family {
            BronzeEventFamily::ProtocolTransaction(t) => assert_eq!(t.status, "observed"),
            _ => panic!(),
        }
    }

    // ── Test 13: IPv4 address formatting ─────────────────────────────────────

    #[test]
    fn ipv4_address_format() {
        let fields = vec![TemplateField { field_type: 8, field_length: 4, enterprise_number: None }];
        let (attr, _) = decode_record_fields(&[192, 0, 2, 1], &fields);
        assert_eq!(attr["sourceIPv4Address"], "192.0.2.1");
    }

    // ── Test 14: MAC address formatting ──────────────────────────────────────

    #[test]
    fn mac_address_format() {
        let fields = vec![TemplateField { field_type: 56, field_length: 6, enterprise_number: None }];
        let data = [0x00, 0x1A, 0x2B, 0x3C, 0x4D, 0x5E];
        let (attr, _) = decode_record_fields(&data, &fields);
        assert_eq!(attr["sourceMacAddress"], "00:1a:2b:3c:4d:5e");
    }

    // ── Test 15: LRU eviction at cap ──────────────────────────────────────────

    #[test]
    fn lru_eviction_at_cap() {
        let mut dec = NetFlowDecoder::default();

        // Insert TEMPLATE_CAP templates with different template IDs.
        for i in 0..TEMPLATE_CAP {
            let key: TemplateKey = ("1.2.3.4".to_string(), 1, (256 + i) as u16);
            dec.store_template(key, TemplateRecord {
                template_id: (256 + i) as u16,
                fields: vec![],
                is_options: false,
            });
        }
        assert_eq!(dec.templates.len(), TEMPLATE_CAP);

        // Insert one more — should evict template_id=256.
        let key_new: TemplateKey = ("1.2.3.4".to_string(), 1, (256 + TEMPLATE_CAP) as u16);
        dec.store_template(key_new, TemplateRecord {
            template_id: (256 + TEMPLATE_CAP) as u16,
            fields: vec![],
            is_options: false,
        });

        assert_eq!(dec.templates.len(), TEMPLATE_CAP, "cap not maintained");
        let evicted_key: TemplateKey = ("1.2.3.4".to_string(), 1, 256u16);
        assert!(!dec.templates.contains_key(&evicted_key), "oldest template not evicted");
    }

    // ── Test 16: idle flush clears template state ─────────────────────────────

    #[test]
    fn idle_flush_clears_state() {
        let mut dec = NetFlowDecoder::default();
        let c = ctx([10, 0, 0, 1], [10, 0, 0, 2]);
        let mut out = Vec::new();

        // Store some templates via a datagram.
        let dgram = v9_template_then_data(1, 260, [1,2,3,4], [5,6,7,8], 100, 200, 1);
        dec.on_datagram(&chunk(&c, &dgram), &mut out);
        assert!(!dec.templates.is_empty(), "templates should be non-empty after datagram");
        assert!(!dec.seen.flow_endpoints.is_empty(), "flow_endpoints should be non-empty");

        dec.on_idle_flush(chrono::Utc::now(), &mut out);

        assert!(dec.templates.is_empty(), "templates not cleared after idle_flush");
        assert!(dec.template_order.is_empty(), "template_order not cleared after idle_flush");
        assert!(dec.seen.flow_endpoints.is_empty(), "flow_endpoints not cleared after idle_flush");
    }

    // ── Test 17: ipfix_field_name covers all curated IEs ─────────────────────

    #[test]
    fn ipfix_field_name_curated_set() {
        let expected: &[(u16, &str)] = &[
            (1, "octetDeltaCount"), (2, "packetDeltaCount"), (4, "protocolIdentifier"),
            (7, "sourceTransportPort"), (8, "sourceIPv4Address"), (11, "destinationTransportPort"),
            (12, "destinationIPv4Address"), (27, "sourceIPv6Address"), (28, "destinationIPv6Address"),
            (56, "sourceMacAddress"), (80, "destinationMacAddress"),
            (152, "flowStartMilliseconds"), (153, "flowEndMilliseconds"),
        ];
        for &(id, name) in expected {
            assert_eq!(ipfix_field_name(id), Some(name), "field {id} mismatch");
        }
        // Unknown returns None
        assert_eq!(ipfix_field_name(9999), None);
    }

    // ── Test 18: format_ipv6 correctness ─────────────────────────────────────

    #[test]
    fn ipv6_format_loopback() {
        let lo = [0u8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
        let s = format_ipv6(&lo);
        assert!(s.contains("::"), "loopback should compress: {s}");
        assert!(s.ends_with("1"), "loopback should end with 1: {s}");
    }
}
