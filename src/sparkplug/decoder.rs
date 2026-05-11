//! `SparkplugBDecoder` — implements [`MqttPayloadDecoder`] to extract VQT
//! readings from Sparkplug B traffic.
//!
//! Lifecycle:
//! - `NBIRTH` / `DBIRTH`: clear the alias table for the session, record
//!   `bdSeq`, populate alias→name bindings from each metric, emit one
//!   `ProtocolTransaction` (typed via
//!   [`crate::bronze::ProtocolFields::Sparkplug`]) for the session-management
//!   envelope, and emit `ProcessReading` for each metric (BIRTH carries
//!   initial values).
//! - `NDATA` / `DDATA`: resolve aliases from session state, emit one
//!   `ProtocolTransaction` for the data envelope, and emit `ProcessReading`
//!   for each metric. Metrics with unresolvable aliases are still emitted with
//!   `metric_name = None, alias = Some(_)` so a downstream consumer can
//!   backfill or surface the gap.
//! - `NDEATH` / `DDEATH`: clear aliases for the session. Emits one
//!   `ProtocolTransaction` for the death event; no `ProcessReading`.
//! - `NCMD` / `DCMD`: command messages directed at an edge node or device.
//!   Emit one `ProtocolTransaction` so defenders can observe commands.
//! - `STATE`: host-application state announcement. Emits one
//!   `ProtocolTransaction`.
//!
//! The `ProtocolTransaction` for each message carries `protocol_fields:
//! Some(ProtocolFields::Sparkplug(SparkplugBronzeFields {...}))` as the typed
//! surface; the legacy `attributes` map is also populated for backward
//! compatibility through the v1.x line.
//!
//! State eviction is decoupled from pcap-segment boundaries; sessions persist
//! across segment rotations because a Sparkplug session typically outlives
//! a single capture window. (TTL-based and memory-pressure eviction are
//! deliberate future work — not needed for v1.)

use std::collections::BTreeMap;

use chrono::{DateTime, Utc};
use prost::Message;

use crate::bronze::{
    BronzeEvent, BronzeEventFamily, EventEnvelope, ParseAnomaly, PointIdentifier, ProcessReading,
    ProtocolFields, ProtocolTransaction, SparkplugBronzeFields, TransportProtocol,
    BRONZE_SCHEMA_VERSION,
};
use crate::mqtt_payload::{MqttPayloadDecoder, MqttPublishContext};
use crate::sparkplug::proto::{payload::Metric as PbMetric, Payload as PbPayload};
use crate::sparkplug::state::{EvictionConfig, SessionKey, SessionStore};
use crate::sparkplug::topic::{parse_topic, MessageType, SparkplugTopic};
use crate::sparkplug::value::{metric_to_point_value, metric_to_raw_quality};

const SOURCE_PROTOCOL: &str = "sparkplug_b";

/// Sparkplug B session decoder.
#[derive(Default)]
pub struct SparkplugBDecoder {
    sessions: SessionStore,
    event_id_counter: u64,
}

impl SparkplugBDecoder {
    pub fn new() -> Self {
        Self::default()
    }

    /// Configure session eviction (TTL since last touch + max-session cap).
    pub fn with_eviction_config(mut self, config: EvictionConfig) -> Self {
        self.sessions = SessionStore::with_config(config);
        self
    }

    /// Number of live sessions in the store. Useful for telemetry / tests.
    pub fn session_count(&self) -> usize {
        self.sessions.len()
    }

    /// Force a TTL sweep. Returns the number of sessions evicted. Production
    /// callers normally rely on the amortized sweep inside `try_decode`; this
    /// method exists for explicit cleanup paths and for tests.
    pub fn evict_expired(&mut self, now_us: u64) -> usize {
        self.sessions.evict_expired(now_us)
    }

    fn next_event_id(&mut self) -> String {
        self.event_id_counter = self.event_id_counter.wrapping_add(1);
        format!("sparkplug-{}", self.event_id_counter)
    }

    fn session_key(&self, ctx: &MqttPublishContext<'_>, topic: &SparkplugTopic<'_>) -> SessionKey {
        SessionKey {
            broker_endpoint: ctx.broker_endpoint,
            group_id: topic.group_id.to_string(),
            edge_node_id: topic.edge_node_id.to_string(),
            device_id: topic.device_id.map(str::to_string),
        }
    }

    fn build_envelope(&self, ctx: &MqttPublishContext<'_>, capture_id: &str) -> EventEnvelope {
        let _ = capture_id; // capture_id not stamped per-event (Bronze envelope omits it)
        EventEnvelope {
            timestamp: timestamp_us_to_chrono(ctx.packet_ts_us),
            interface_id: 0,
            segment_hash: String::new(),
            frame_index: 0,
            session_key: format!(
                "{}|{}",
                ctx.flow_5tuple.src, ctx.flow_5tuple.dst
            ),
            src_mac: Some(format_mac(ctx.publisher_mac)),
            dst_mac: None,
            src_ip: Some(ctx.flow_5tuple.src.ip().to_string()),
            dst_ip: Some(ctx.flow_5tuple.dst.ip().to_string()),
            src_port: Some(ctx.flow_5tuple.src.port()),
            dst_port: Some(ctx.flow_5tuple.dst.port()),
            vlan_id: ctx.vlan_id,
            transport: TransportProtocol::Tcp,
            protocol: Some(SOURCE_PROTOCOL.into()),
            bytes_count: ctx.payload.len() as u64,
            packet_count: 1,
        }
    }

    fn make_event(&mut self, envelope: EventEnvelope, family: BronzeEventFamily) -> BronzeEvent {
        BronzeEvent {
            event_id: self.next_event_id(),
            capture_id: String::new(),
            schema_version: BRONZE_SCHEMA_VERSION.into(),
            envelope,
            family,
        }
    }

    fn handle_birth(
        &mut self,
        ctx: &MqttPublishContext<'_>,
        topic: &SparkplugTopic<'_>,
        payload: &PbPayload,
        out: &mut Vec<BronzeEvent>,
    ) {
        let key = self.session_key(ctx, topic);
        let session = self.sessions.entry_mut(key, ctx.packet_ts_us);
        let bd_seq = extract_bd_seq(payload);
        if !session.record_birth(bd_seq) {
            // Older or equal bdSeq when we already have a newer one — ignore.
            return;
        }
        session.clear_aliases();
        for metric in &payload.metrics {
            if let (Some(name), Some(alias)) = (metric.name.as_deref(), metric.alias) {
                session.bind(alias, name.to_string());
            }
        }
        // Emit one ProtocolTransaction for the session-management envelope.
        let metric_count = payload.metrics.len() as u32;
        let fields = build_sparkplug_fields(topic, payload, bd_seq, Some(metric_count), "n/a");
        out.push(self.session_tx_event(ctx, topic, fields, metric_count));
        // BIRTH carries initial values — emit them.
        emit_metrics(self, ctx, topic, payload, out);
    }

    fn handle_data(
        &mut self,
        ctx: &MqttPublishContext<'_>,
        topic: &SparkplugTopic<'_>,
        payload: &PbPayload,
        out: &mut Vec<BronzeEvent>,
    ) {
        // Pre-check whether there's an unresolved alias and we've never seen a
        // BIRTH for this session — emit the gap-anomaly signal at most once
        // per gap epoch.
        let key = self.session_key(ctx, topic);
        let any_unresolvable = {
            let s = self.sessions.entry_mut(key.clone(), ctx.packet_ts_us);
            payload.metrics.iter().any(|m| {
                m.name.is_none()
                    && m.alias.is_some()
                    && s.resolve(m.alias.unwrap()).is_none()
            })
        };
        if any_unresolvable {
            let fire = self
                .sessions
                .entry_mut(key, ctx.packet_ts_us)
                .note_gap_anomaly_if_first();
            if fire {
                out.push(self.gap_anomaly_event(ctx, topic));
            }
        }
        let alias_state = if any_unresolvable {
            "unresolved_no_birth"
        } else {
            "resolved"
        };
        let metric_count = payload.metrics.len() as u32;
        let fields = build_sparkplug_fields(
            topic,
            payload,
            None,
            Some(metric_count),
            alias_state,
        );
        out.push(self.session_tx_event(ctx, topic, fields, metric_count));
        emit_metrics(self, ctx, topic, payload, out);
    }

    fn handle_death(
        &mut self,
        ctx: &MqttPublishContext<'_>,
        topic: &SparkplugTopic<'_>,
        payload: &PbPayload,
        out: &mut Vec<BronzeEvent>,
    ) {
        let key = self.session_key(ctx, topic);
        self.sessions
            .entry_mut(key, ctx.packet_ts_us)
            .record_death();
        let bd_seq = extract_bd_seq(payload);
        let fields = build_sparkplug_fields(topic, payload, bd_seq, None, "n/a");
        out.push(self.session_tx_event(ctx, topic, fields, 0));
    }

    fn handle_cmd(
        &mut self,
        ctx: &MqttPublishContext<'_>,
        topic: &SparkplugTopic<'_>,
        payload: &PbPayload,
        out: &mut Vec<BronzeEvent>,
    ) {
        let metric_count = payload.metrics.len() as u32;
        let fields = build_sparkplug_fields(
            topic,
            payload,
            None,
            Some(metric_count),
            "n/a",
        );
        out.push(self.session_tx_event(ctx, topic, fields, metric_count));
    }

    fn handle_state(
        &mut self,
        ctx: &MqttPublishContext<'_>,
        topic: &SparkplugTopic<'_>,
        payload: &PbPayload,
        out: &mut Vec<BronzeEvent>,
    ) {
        let fields = build_sparkplug_fields(topic, payload, None, None, "n/a");
        out.push(self.session_tx_event(ctx, topic, fields, 0));
    }

    /// Build a `ProtocolTransaction` event for a Sparkplug session-management
    /// message. Populates both the typed `protocol_fields` surface and the
    /// legacy `attributes` map for backward compatibility.
    fn session_tx_event(
        &mut self,
        ctx: &MqttPublishContext<'_>,
        topic: &SparkplugTopic<'_>,
        fields: SparkplugBronzeFields,
        metric_count: u32,
    ) -> BronzeEvent {
        let envelope = self.build_envelope(ctx, "");
        let operation = fields.message_type.clone();

        // Legacy attributes — mirror key fields for consumers not yet on the
        // typed surface. Retained through v1.x; will be removed in v2.0.
        let mut attributes = BTreeMap::new();
        attributes.insert("message_type".to_string(), fields.message_type.clone());
        attributes.insert("group_id".to_string(), fields.group_id.clone());
        attributes.insert("edge_node_id".to_string(), fields.edge_node_id.clone());
        if let Some(did) = &fields.device_id {
            attributes.insert("device_id".to_string(), did.clone());
        }
        if let Some(bdseq) = fields.bdseq {
            attributes.insert("bdseq".to_string(), bdseq.to_string());
        }
        if let Some(seq) = fields.seq {
            attributes.insert("seq".to_string(), seq.to_string());
        }
        if let Some(ts) = fields.payload_timestamp {
            attributes.insert("payload_timestamp".to_string(), ts.to_string());
        }
        attributes.insert("metric_count".to_string(), metric_count.to_string());
        attributes.insert(
            "alias_resolution_state".to_string(),
            fields.alias_resolution_state.clone(),
        );

        let object_refs = build_object_refs(topic);

        self.make_event(
            envelope,
            BronzeEventFamily::ProtocolTransaction(ProtocolTransaction {
                operation,
                status: "ok".to_string(),
                request_summary: Some(sparkplug_summary(topic, metric_count)),
                response_summary: None,
                object_refs,
                values: vec![],
                attributes,
                modbus: None,
                protocol_fields: Some(ProtocolFields::Sparkplug(fields)),
            }),
        )
    }

    fn gap_anomaly_event(
        &mut self,
        ctx: &MqttPublishContext<'_>,
        topic: &SparkplugTopic<'_>,
    ) -> BronzeEvent {
        let envelope = self.build_envelope(ctx, "");
        let reason = format!(
            "sparkplug DATA arrived before BIRTH for group={} edge={} device={} \
             — request a Rebirth to resolve aliases",
            topic.group_id,
            topic.edge_node_id,
            topic.device_id.unwrap_or("-")
        );
        self.make_event(
            envelope,
            BronzeEventFamily::ParseAnomaly(ParseAnomaly {
                decoder: "sparkplug_b".into(),
                severity: "medium".into(),
                reason,
                raw_excerpt_hex: String::new(),
            }),
        )
    }
}

/// Free function to avoid borrow conflicts when we need both `&mut self` and
/// session state in `emit_metrics`.
fn emit_metrics(
    decoder: &mut SparkplugBDecoder,
    ctx: &MqttPublishContext<'_>,
    topic: &SparkplugTopic<'_>,
    payload: &PbPayload,
    out: &mut Vec<BronzeEvent>,
) {
    for metric in &payload.metrics {
        let envelope = decoder.build_envelope(ctx, "");
        let reading = build_reading(decoder, ctx, topic, payload, metric);
        out.push(decoder.make_event(envelope, BronzeEventFamily::ProcessReading(reading)));
    }
}

fn build_reading(
    decoder: &mut SparkplugBDecoder,
    ctx: &MqttPublishContext<'_>,
    topic: &SparkplugTopic<'_>,
    payload: &PbPayload,
    metric: &PbMetric,
) -> ProcessReading {
    let key = decoder.session_key(ctx, topic);
    // Resolve the metric name: if explicitly carried, use it (and learn the
    // alias for future DATA frames). Otherwise look up the alias.
    let (metric_name, alias_resolved) = match (metric.name.as_deref(), metric.alias) {
        (Some(name), Some(alias)) => {
            decoder
                .sessions
                .entry_mut(key.clone(), ctx.packet_ts_us)
                .bind(alias, name.to_string());
            (Some(name.to_string()), Some(alias))
        }
        (Some(name), None) => (Some(name.to_string()), None),
        (None, Some(alias)) => {
            let resolved = decoder
                .sessions
                .get(&key)
                .and_then(|s| s.resolve(alias))
                .map(str::to_string);
            (resolved, Some(alias))
        }
        (None, None) => (None, None),
    };

    let metric_name_raw = metric_name
        .as_ref()
        .filter(|s| !is_ascii_clean(s))
        .map(|s| s.as_bytes().to_vec());

    let point_id = PointIdentifier::SparkplugMetric {
        group_id: topic.group_id.to_string(),
        edge_node_id: topic.edge_node_id.to_string(),
        device_id: topic.device_id.map(str::to_string),
        metric_name,
        metric_name_raw,
        alias: alias_resolved,
    };

    // Source timestamp preference: per-metric > payload-level > none.
    // Sparkplug carries timestamps as milliseconds since epoch; we store
    // microseconds, so multiply by 1_000.
    let source_ts = metric
        .timestamp
        .or(payload.timestamp)
        .map(|ms| ms.saturating_mul(1_000));

    ProcessReading {
        source_protocol: SOURCE_PROTOCOL.into(),
        point_id,
        value: metric_to_point_value(metric),
        quality: metric_to_raw_quality(metric),
        source_ts,
        observed_ts: ctx.packet_ts_us,
    }
}

/// Sparkplug bdSeq lives as a metric named "bdSeq" in BIRTH/DEATH messages.
fn extract_bd_seq(payload: &PbPayload) -> Option<u64> {
    for m in &payload.metrics {
        if m.name.as_deref() == Some("bdSeq") {
            if let Some(crate::sparkplug::proto::payload::metric::Value::LongValue(v)) = m.value {
                return Some(v);
            }
            if let Some(crate::sparkplug::proto::payload::metric::Value::IntValue(v)) = m.value {
                return Some(v as u64);
            }
        }
    }
    None
}

impl MqttPayloadDecoder for SparkplugBDecoder {
    fn name(&self) -> &'static str {
        "sparkplug_b"
    }

    fn try_decode(&mut self, ctx: &MqttPublishContext<'_>) -> Vec<BronzeEvent> {
        // Topic gate.
        let Some(topic) = parse_topic(ctx.topic) else {
            return Vec::new();
        };
        // Amortized TTL sweep — runs once every N publishes to bound CPU.
        if self.sessions.should_sweep() {
            self.sessions.evict_expired(ctx.packet_ts_us);
        }
        let mut out = Vec::new();

        // Protobuf decode. A failure produces a parse anomaly so operators can
        // see malformed Sparkplug payloads.
        let payload = match PbPayload::decode(ctx.payload) {
            Ok(p) => p,
            Err(e) => {
                let envelope = self.build_envelope(ctx, "");
                out.push(self.make_event(
                    envelope,
                    BronzeEventFamily::ParseAnomaly(ParseAnomaly {
                        decoder: "sparkplug_b".into(),
                        severity: "high".into(),
                        reason: format!("protobuf decode failed: {e}"),
                        raw_excerpt_hex: hex::encode(
                            &ctx.payload[..ctx.payload.len().min(64)],
                        ),
                    }),
                ));
                return out;
            }
        };

        match topic.message_type {
            MessageType::NBirth | MessageType::DBirth => {
                self.handle_birth(ctx, &topic, &payload, &mut out);
            }
            MessageType::NData | MessageType::DData => {
                self.handle_data(ctx, &topic, &payload, &mut out);
            }
            MessageType::NDeath | MessageType::DDeath => {
                self.handle_death(ctx, &topic, &payload, &mut out);
            }
            MessageType::NCmd | MessageType::DCmd => {
                self.handle_cmd(ctx, &topic, &payload, &mut out);
            }
            MessageType::State => {
                self.handle_state(ctx, &topic, &payload, &mut out);
            }
        }
        out
    }
}

fn is_ascii_clean(s: &str) -> bool {
    s.bytes().all(|b| (0x20..=0x7E).contains(&b) || b == b'\t')
}

/// Construct [`SparkplugBronzeFields`] from topic + payload metadata.
///
/// `bd_seq` is passed in separately because it has already been extracted (or
/// will be `None` for message types that don't carry it).
/// `metric_count` is `None` for DEATH, STATE, and other non-metric messages.
/// `alias_resolution_state` is computed by the caller.
fn build_sparkplug_fields(
    topic: &SparkplugTopic<'_>,
    payload: &PbPayload,
    bd_seq: Option<u64>,
    metric_count: Option<u32>,
    alias_resolution_state: &str,
) -> SparkplugBronzeFields {
    let mt = topic.message_type;
    let message_type = match mt {
        MessageType::NBirth => "NBIRTH",
        MessageType::NDeath => "NDEATH",
        MessageType::NData  => "NDATA",
        MessageType::NCmd   => "NCMD",
        MessageType::DBirth => "DBIRTH",
        MessageType::DDeath => "DDEATH",
        MessageType::DData  => "DDATA",
        MessageType::DCmd   => "DCMD",
        MessageType::State  => "STATE",
    };
    SparkplugBronzeFields {
        message_type: message_type.to_string(),
        group_id: topic.group_id.to_string(),
        edge_node_id: topic.edge_node_id.to_string(),
        device_id: topic.device_id.map(str::to_string),
        bdseq: bd_seq,
        seq: payload.seq,
        payload_timestamp: payload.timestamp,
        metric_count,
        alias_resolution_state: alias_resolution_state.to_string(),
        is_birth: mt.is_birth(),
        is_death: mt.is_death(),
        is_command: matches!(mt, MessageType::NCmd | MessageType::DCmd),
    }
}

/// Build the object_refs list for a Sparkplug session-management transaction.
/// Always contains the fully-qualified node path; device path added when present.
fn build_object_refs(topic: &SparkplugTopic<'_>) -> Vec<String> {
    let node_ref = format!("sparkplug/{}/{}", topic.group_id, topic.edge_node_id);
    match topic.device_id {
        Some(d) => vec![
            node_ref.clone(),
            format!("{node_ref}/{d}"),
        ],
        None => vec![node_ref],
    }
}

/// One-line summary for a Sparkplug session-management transaction.
fn sparkplug_summary(topic: &SparkplugTopic<'_>, metric_count: u32) -> String {
    let mt = topic.message_type;
    let type_str = match mt {
        MessageType::NBirth => "NBIRTH",
        MessageType::NDeath => "NDEATH",
        MessageType::NData  => "NDATA",
        MessageType::NCmd   => "NCMD",
        MessageType::DBirth => "DBIRTH",
        MessageType::DDeath => "DDEATH",
        MessageType::DData  => "DDATA",
        MessageType::DCmd   => "DCMD",
        MessageType::State  => "STATE",
    };
    match topic.device_id {
        Some(d) => format!(
            "{type_str} {}/{}/{} metrics={}",
            topic.group_id, topic.edge_node_id, d, metric_count
        ),
        None => format!(
            "{type_str} {}/{} metrics={}",
            topic.group_id, topic.edge_node_id, metric_count
        ),
    }
}

fn timestamp_us_to_chrono(us: u64) -> DateTime<Utc> {
    let secs = (us / 1_000_000) as i64;
    let nanos = ((us % 1_000_000) as u32) * 1_000;
    DateTime::<Utc>::from_timestamp(secs, nanos).unwrap_or_else(|| {
        DateTime::<Utc>::from_timestamp(0, 0).expect("epoch timestamp always valid")
    })
}

fn format_mac(mac: [u8; 6]) -> String {
    format!(
        "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bronze::{ModbusRegKind, PointValue, RawQuality};
    use crate::mqtt_payload::{FlowFiveTuple, MqttPublishContext};
    use crate::sparkplug::proto::payload::{metric, Metric};
    use crate::sparkplug::proto::DataType;
    use std::net::SocketAddr;

    // Suppress unused-import warnings for ModbusRegKind / similar that some
    // tests don't reach.
    #[allow(dead_code)]
    fn _silence() -> ModbusRegKind {
        ModbusRegKind::HoldingRegister
    }

    fn broker() -> SocketAddr {
        "10.0.0.1:1883".parse().unwrap()
    }

    fn publisher() -> SocketAddr {
        "10.0.0.50:53212".parse().unwrap()
    }

    fn ctx<'a>(topic: &'a str, payload: &'a [u8]) -> MqttPublishContext<'a> {
        MqttPublishContext {
            broker_endpoint: broker(),
            flow_5tuple: FlowFiveTuple {
                src: publisher(),
                dst: broker(),
                transport: 6,
            },
            client_id: Some("edge-PLC-A"),
            topic,
            payload,
            retain: false,
            qos: 1,
            packet_ts_us: 1_700_000_000_000_001,
            vlan_id: None,
            publisher_mac: [0x02, 0x00, 0x00, 0x00, 0x00, 0x01],
        }
    }

    fn metric_named(name: &str, alias: u64, value: f64) -> Metric {
        Metric {
            name: Some(name.into()),
            alias: Some(alias),
            datatype: Some(DataType::Double as u32),
            timestamp: Some(1_700_000_000_500),
            value: Some(metric::Value::DoubleValue(value)),
            ..Default::default()
        }
    }

    fn metric_aliased(alias: u64, value: f64) -> Metric {
        Metric {
            alias: Some(alias),
            datatype: Some(DataType::Double as u32),
            timestamp: Some(1_700_000_001_500),
            value: Some(metric::Value::DoubleValue(value)),
            ..Default::default()
        }
    }

    fn bd_seq_metric(v: u64) -> Metric {
        Metric {
            name: Some("bdSeq".into()),
            datatype: Some(DataType::Int64 as u32),
            value: Some(metric::Value::LongValue(v)),
            ..Default::default()
        }
    }

    fn payload_bytes(payload: PbPayload) -> Vec<u8> {
        let mut buf = Vec::with_capacity(payload.encoded_len());
        payload.encode(&mut buf).expect("encode");
        buf
    }

    fn extract_reading(ev: &BronzeEvent) -> &ProcessReading {
        match &ev.family {
            BronzeEventFamily::ProcessReading(r) => r,
            other => panic!("expected ProcessReading, got {other:?}"),
        }
    }

    #[test]
    fn non_sparkplug_topic_returns_empty() {
        let mut d = SparkplugBDecoder::new();
        assert!(d.try_decode(&ctx("factory/line1/temp", &[1, 2, 3])).is_empty());
    }

    #[test]
    fn malformed_protobuf_emits_parse_anomaly() {
        let mut d = SparkplugBDecoder::new();
        let bytes = vec![0xff, 0xff, 0xff, 0xff, 0xff, 0xff];
        let events = d.try_decode(&ctx("spBv1.0/G/NDATA/E", &bytes));
        assert_eq!(events.len(), 1);
        match &events[0].family {
            BronzeEventFamily::ParseAnomaly(a) => {
                assert_eq!(a.decoder, "sparkplug_b");
                assert!(a.reason.contains("protobuf decode failed"));
            }
            other => panic!("expected ParseAnomaly, got {other:?}"),
        }
    }

    #[test]
    fn nbirth_emits_readings_and_binds_aliases() {
        let mut d = SparkplugBDecoder::new();
        let bytes = payload_bytes(PbPayload {
            timestamp: Some(1_700_000_000_000),
            seq: Some(0),
            metrics: vec![
                bd_seq_metric(1),
                metric_named("Tank1.Level", 10, 50.0),
                metric_named("BearingTemp", 11, 72.5),
            ],
            ..Default::default()
        });
        let events = d.try_decode(&ctx("spBv1.0/Plant1/NBIRTH/PLC-A", &bytes));
        // 1 ProtocolTransaction + 3 ProcessReadings.
        assert_eq!(events.len(), 4);
        assert!(matches!(events[0].family, BronzeEventFamily::ProtocolTransaction(_)));
        for ev in &events[1..] {
            assert_eq!(ev.family_name(), "process_reading");
        }
        // events[1] is the first ProcessReading (bdSeq metric), events[2] is Tank1.Level.
        let r = extract_reading(&events[2]);
        assert_eq!(r.source_protocol, "sparkplug_b");
        match &r.point_id {
            PointIdentifier::SparkplugMetric {
                group_id,
                edge_node_id,
                device_id,
                metric_name,
                alias,
                ..
            } => {
                assert_eq!(group_id, "Plant1");
                assert_eq!(edge_node_id, "PLC-A");
                assert!(device_id.is_none());
                assert_eq!(metric_name.as_deref(), Some("Tank1.Level"));
                assert_eq!(*alias, Some(10));
            }
            other => panic!("wrong PointId: {other:?}"),
        }
        assert_eq!(r.value, PointValue::Double(50.0));
        // observed_ts comes from packet, source_ts is metric's timestamp * 1000
        // (Sparkplug ms → our µs).
        assert_eq!(r.observed_ts, 1_700_000_000_000_001);
        assert_eq!(r.source_ts, Some(1_700_000_000_500_000));
    }

    #[test]
    fn ndata_resolves_aliases_from_prior_birth() {
        let mut d = SparkplugBDecoder::new();
        // BIRTH first.
        let birth = payload_bytes(PbPayload {
            metrics: vec![
                bd_seq_metric(1),
                metric_named("Tank1.Level", 10, 50.0),
            ],
            ..Default::default()
        });
        let _ = d.try_decode(&ctx("spBv1.0/Plant1/NBIRTH/PLC-A", &birth));
        // DATA frame with alias only.
        let data = payload_bytes(PbPayload {
            metrics: vec![metric_aliased(10, 51.5)],
            ..Default::default()
        });
        let events = d.try_decode(&ctx("spBv1.0/Plant1/NDATA/PLC-A", &data));
        // 1 ProtocolTransaction + 1 ProcessReading.
        assert_eq!(events.len(), 2);
        let r = extract_reading(
            events
                .iter()
                .find(|ev| matches!(ev.family, BronzeEventFamily::ProcessReading(_)))
                .unwrap(),
        );
        match &r.point_id {
            PointIdentifier::SparkplugMetric {
                metric_name, alias, ..
            } => {
                assert_eq!(metric_name.as_deref(), Some("Tank1.Level"));
                assert_eq!(*alias, Some(10));
            }
            _ => panic!(),
        }
        assert_eq!(r.value, PointValue::Double(51.5));
    }

    #[test]
    fn ndata_without_prior_birth_emits_unresolved_and_one_anomaly() {
        let mut d = SparkplugBDecoder::new();
        let data = payload_bytes(PbPayload {
            metrics: vec![metric_aliased(99, 1.0), metric_aliased(100, 2.0)],
            ..Default::default()
        });
        let events = d.try_decode(&ctx("spBv1.0/G/NDATA/E", &data));
        // 1 anomaly + 1 ProtocolTransaction + 2 ProcessReadings.
        assert_eq!(events.len(), 4);
        assert!(matches!(
            events[0].family,
            BronzeEventFamily::ParseAnomaly(_)
        ));
        assert!(matches!(
            events[1].family,
            BronzeEventFamily::ProtocolTransaction(_)
        ));
        for ev in &events[2..] {
            let r = extract_reading(ev);
            match &r.point_id {
                PointIdentifier::SparkplugMetric { metric_name, alias, .. } => {
                    assert!(metric_name.is_none(), "alias should not resolve");
                    assert!(alias.is_some());
                }
                _ => panic!(),
            }
        }

        // A second DATA with still-no-BIRTH should NOT re-fire the anomaly.
        let events2 = d.try_decode(&ctx("spBv1.0/G/NDATA/E", &data));
        // 1 ProtocolTransaction + 2 ProcessReadings — no anomaly on second DATA.
        assert_eq!(events2.len(), 3);
        assert!(matches!(
            events2[0].family,
            BronzeEventFamily::ProtocolTransaction(_)
        ));
        assert!(events2[1..]
            .iter()
            .all(|ev| matches!(ev.family, BronzeEventFamily::ProcessReading(_))));
    }

    #[test]
    fn birth_after_gap_resets_anomaly_signal() {
        let mut d = SparkplugBDecoder::new();
        // DATA without BIRTH → fires anomaly.
        let data = payload_bytes(PbPayload {
            metrics: vec![metric_aliased(1, 1.0)],
            ..Default::default()
        });
        let _ = d.try_decode(&ctx("spBv1.0/G/NDATA/E", &data));
        // BIRTH closes the gap.
        let birth = payload_bytes(PbPayload {
            metrics: vec![bd_seq_metric(1), metric_named("X", 1, 5.0)],
            ..Default::default()
        });
        let _ = d.try_decode(&ctx("spBv1.0/G/NBIRTH/E", &birth));
        // A subsequent gap (DATA referencing an unknown alias) should re-fire.
        let bad = payload_bytes(PbPayload {
            metrics: vec![metric_aliased(999, 9.0)],
            ..Default::default()
        });
        let events = d.try_decode(&ctx("spBv1.0/G/NDATA/E", &bad));
        assert!(events
            .iter()
            .any(|ev| matches!(ev.family, BronzeEventFamily::ParseAnomaly(_))));
    }

    #[test]
    fn newer_bdseq_supersedes_alias_table() {
        let mut d = SparkplugBDecoder::new();
        let birth1 = payload_bytes(PbPayload {
            metrics: vec![bd_seq_metric(1), metric_named("OldTag", 10, 1.0)],
            ..Default::default()
        });
        let _ = d.try_decode(&ctx("spBv1.0/G/NBIRTH/E", &birth1));
        let birth2 = payload_bytes(PbPayload {
            metrics: vec![bd_seq_metric(2), metric_named("NewTag", 10, 2.0)],
            ..Default::default()
        });
        let _ = d.try_decode(&ctx("spBv1.0/G/NBIRTH/E", &birth2));
        // DATA referring to alias 10 should now resolve to NewTag, not OldTag.
        let data = payload_bytes(PbPayload {
            metrics: vec![metric_aliased(10, 3.0)],
            ..Default::default()
        });
        let events = d.try_decode(&ctx("spBv1.0/G/NDATA/E", &data));
        // 1 ProtocolTransaction + 1 ProcessReading.
        assert_eq!(events.len(), 2);
        let r = extract_reading(
            events
                .iter()
                .find(|ev| matches!(ev.family, BronzeEventFamily::ProcessReading(_)))
                .unwrap(),
        );
        match &r.point_id {
            PointIdentifier::SparkplugMetric { metric_name, .. } => {
                assert_eq!(metric_name.as_deref(), Some("NewTag"));
            }
            _ => panic!(),
        }
    }

    #[test]
    fn ndeath_clears_aliases() {
        let mut d = SparkplugBDecoder::new();
        let birth = payload_bytes(PbPayload {
            metrics: vec![bd_seq_metric(1), metric_named("X", 7, 1.0)],
            ..Default::default()
        });
        let _ = d.try_decode(&ctx("spBv1.0/G/NBIRTH/E", &birth));
        // Death.
        let death = payload_bytes(PbPayload {
            metrics: vec![bd_seq_metric(1)],
            ..Default::default()
        });
        let events = d.try_decode(&ctx("spBv1.0/G/NDEATH/E", &death));
        // DEATH emits one ProtocolTransaction but no ProcessReadings.
        assert_eq!(events.len(), 1);
        assert!(matches!(events[0].family, BronzeEventFamily::ProtocolTransaction(_)));
        // DATA after DEATH should now fail to resolve alias 7.
        let data = payload_bytes(PbPayload {
            metrics: vec![metric_aliased(7, 99.0)],
            ..Default::default()
        });
        let events = d.try_decode(&ctx("spBv1.0/G/NDATA/E", &data));
        let r = extract_reading(events.iter().find(|ev| matches!(ev.family, BronzeEventFamily::ProcessReading(_))).unwrap());
        match &r.point_id {
            PointIdentifier::SparkplugMetric { metric_name, .. } => {
                assert!(metric_name.is_none());
            }
            _ => panic!(),
        }
    }

    #[test]
    fn dbirth_ddata_device_scope_keys_separately() {
        let mut d = SparkplugBDecoder::new();
        let dbirth = payload_bytes(PbPayload {
            metrics: vec![bd_seq_metric(1), metric_named("DriveCurrent", 5, 4.2)],
            ..Default::default()
        });
        let _ = d.try_decode(&ctx("spBv1.0/Plant1/DBIRTH/PLC-A/Drive-17", &dbirth));

        // Same alias number 5 at the node level (no device) should NOT collide
        // with the device-scoped binding.
        let nbirth = payload_bytes(PbPayload {
            metrics: vec![bd_seq_metric(1), metric_named("NodeMetric", 5, 99.0)],
            ..Default::default()
        });
        let _ = d.try_decode(&ctx("spBv1.0/Plant1/NBIRTH/PLC-A", &nbirth));

        // DDATA on the device scope resolves to DriveCurrent.
        let ddata = payload_bytes(PbPayload {
            metrics: vec![metric_aliased(5, 4.3)],
            ..Default::default()
        });
        let events = d.try_decode(&ctx("spBv1.0/Plant1/DDATA/PLC-A/Drive-17", &ddata));
        let r = extract_reading(
            events
                .iter()
                .find(|ev| matches!(ev.family, BronzeEventFamily::ProcessReading(_)))
                .unwrap(),
        );
        match &r.point_id {
            PointIdentifier::SparkplugMetric {
                metric_name,
                device_id,
                ..
            } => {
                assert_eq!(metric_name.as_deref(), Some("DriveCurrent"));
                assert_eq!(device_id.as_deref(), Some("Drive-17"));
            }
            _ => panic!(),
        }
    }

    #[test]
    fn lru_eviction_caps_session_count_under_pressure() {
        use crate::sparkplug::state::EvictionConfig;
        let cfg = EvictionConfig {
            ttl_us: u64::MAX,
            max_sessions: 2,
        };
        let mut d = SparkplugBDecoder::new().with_eviction_config(cfg);
        // 3 distinct edge nodes — third should evict the LRU first one.
        for edge in ["E1", "E2", "E3"] {
            let topic = format!("spBv1.0/G/NBIRTH/{edge}");
            let bytes = payload_bytes(PbPayload {
                metrics: vec![bd_seq_metric(1), metric_named("X", 1, 1.0)],
                ..Default::default()
            });
            let _ = d.try_decode(&ctx(&topic, &bytes));
        }
        assert_eq!(d.session_count(), 2);
    }

    #[test]
    fn ttl_eviction_drops_stale_sessions_after_sweep() {
        use crate::sparkplug::state::EvictionConfig;
        // Tiny TTL so we can step past it manually.
        let cfg = EvictionConfig {
            ttl_us: 1_000_000, // 1 second
            max_sessions: 1024,
        };
        let mut d = SparkplugBDecoder::new().with_eviction_config(cfg);

        // BIRTH at t=100 µs creates a session.
        let early_bytes = payload_bytes(PbPayload {
            metrics: vec![bd_seq_metric(1), metric_named("X", 1, 1.0)],
            ..Default::default()
        });
        let mut early_ctx = ctx("spBv1.0/G/NBIRTH/Stale", &early_bytes);
        early_ctx.packet_ts_us = 100;
        let _ = d.try_decode(&early_ctx);
        assert_eq!(d.session_count(), 1);

        // 5 seconds later, force eviction. Old session is past TTL.
        assert_eq!(d.evict_expired(5_000_000), 1);
        assert_eq!(d.session_count(), 0);

        // BIRTH for a new edge node — fresh session.
        let late_bytes = payload_bytes(PbPayload {
            metrics: vec![bd_seq_metric(1), metric_named("Y", 2, 2.0)],
            ..Default::default()
        });
        let mut late_ctx = ctx("spBv1.0/G/NBIRTH/Fresh", &late_bytes);
        late_ctx.packet_ts_us = 5_000_000;
        let _ = d.try_decode(&late_ctx);
        assert_eq!(d.session_count(), 1);
    }

    #[test]
    fn quality_property_carried_through() {
        use crate::sparkplug::proto::payload::{property_value, PropertySet, PropertyValue};
        let mut d = SparkplugBDecoder::new();
        let metric = Metric {
            name: Some("T".into()),
            alias: Some(1),
            datatype: Some(DataType::Double as u32),
            value: Some(metric::Value::DoubleValue(50.0)),
            properties: Some(PropertySet {
                keys: vec!["Quality".into()],
                values: vec![PropertyValue {
                    value: Some(property_value::Value::IntValue(192)),
                    ..Default::default()
                }],
            }),
            ..Default::default()
        };
        let bytes = payload_bytes(PbPayload {
            metrics: vec![bd_seq_metric(1), metric],
            ..Default::default()
        });
        let events = d.try_decode(&ctx("spBv1.0/G/NBIRTH/E", &bytes));
        // events[0] = ProtocolTransaction, events[1] = bdSeq reading, events[2] = T reading.
        let q = &extract_reading(&events[2]).quality;
        assert_eq!(
            q,
            &RawQuality::SparkplugQuality {
                value: Some(192),
                is_historical: false,
                is_transient: false,
                is_null: false,
            }
        );
    }

    // ── Typed ProtocolFields::Sparkplug surface tests ────────────────────────

    fn extract_sparkplug_fields(ev: &BronzeEvent) -> &crate::bronze::SparkplugBronzeFields {
        match &ev.family {
            BronzeEventFamily::ProtocolTransaction(tx) => match &tx.protocol_fields {
                Some(ProtocolFields::Sparkplug(f)) => f,
                other => panic!("expected ProtocolFields::Sparkplug, got {other:?}"),
            },
            other => panic!("expected ProtocolTransaction, got {other:?}"),
        }
    }

    #[test]
    fn nbirth_protocol_transaction_typed_fields() {
        let mut d = SparkplugBDecoder::new();
        let bytes = payload_bytes(PbPayload {
            timestamp: Some(1_700_000_000_000),
            seq: Some(0),
            metrics: vec![
                bd_seq_metric(5),
                metric_named("Pressure", 10, 101.3),
                metric_named("FlowRate", 11, 25.0),
                metric_named("Temp", 12, 72.0),
            ],
            ..Default::default()
        });
        let events = d.try_decode(&ctx("spBv1.0/SiteName/NBIRTH/PLC-B", &bytes));
        // First event must be the ProtocolTransaction.
        let f = extract_sparkplug_fields(&events[0]);
        assert_eq!(f.message_type, "NBIRTH");
        assert_eq!(f.group_id, "SiteName");
        assert_eq!(f.edge_node_id, "PLC-B");
        assert!(f.device_id.is_none());
        assert_eq!(f.bdseq, Some(5));
        assert_eq!(f.seq, Some(0));
        assert_eq!(f.payload_timestamp, Some(1_700_000_000_000));
        assert_eq!(f.metric_count, Some(4));
        assert_eq!(f.alias_resolution_state, "n/a");
        assert!(f.is_birth);
        assert!(!f.is_death);
        assert!(!f.is_command);
        // Legacy attributes backward-compat check.
        match &events[0].family {
            BronzeEventFamily::ProtocolTransaction(tx) => {
                assert_eq!(tx.attributes.get("message_type").map(String::as_str), Some("NBIRTH"));
                assert_eq!(tx.attributes.get("group_id").map(String::as_str), Some("SiteName"));
                assert_eq!(tx.attributes.get("bdseq").map(String::as_str), Some("5"));
                assert_eq!(tx.attributes.get("metric_count").map(String::as_str), Some("4"));
            }
            _ => panic!(),
        }
        // ProcessReadings still emitted (4 metrics).
        let readings: Vec<_> = events
            .iter()
            .filter(|ev| matches!(ev.family, BronzeEventFamily::ProcessReading(_)))
            .collect();
        assert_eq!(readings.len(), 4);
    }

    #[test]
    fn dbirth_with_device_id_typed_fields() {
        let mut d = SparkplugBDecoder::new();
        let bytes = payload_bytes(PbPayload {
            seq: Some(0),
            metrics: vec![
                bd_seq_metric(2),
                metric_named("DriveSpeed", 1, 1500.0),
                metric_named("DriveTemp", 2, 45.0),
            ],
            ..Default::default()
        });
        let events = d.try_decode(&ctx("spBv1.0/Factory/DBIRTH/Edge-1/Drive-7", &bytes));
        let f = extract_sparkplug_fields(&events[0]);
        assert_eq!(f.message_type, "DBIRTH");
        assert_eq!(f.group_id, "Factory");
        assert_eq!(f.edge_node_id, "Edge-1");
        assert_eq!(f.device_id.as_deref(), Some("Drive-7"));
        assert_eq!(f.bdseq, Some(2));
        assert_eq!(f.metric_count, Some(3));
        assert!(f.is_birth);
        assert!(!f.is_death);
        assert!(!f.is_command);
    }

    #[test]
    fn ndata_with_seq_typed_fields_resolved() {
        let mut d = SparkplugBDecoder::new();
        // Establish alias binding via BIRTH.
        let birth = payload_bytes(PbPayload {
            seq: Some(0),
            metrics: vec![bd_seq_metric(1), metric_named("Pressure", 7, 100.0)],
            ..Default::default()
        });
        let _ = d.try_decode(&ctx("spBv1.0/G/NBIRTH/E", &birth));
        // DATA message.
        let data = payload_bytes(PbPayload {
            seq: Some(3),
            timestamp: Some(1_700_000_001_000),
            metrics: vec![metric_aliased(7, 101.5)],
            ..Default::default()
        });
        let events = d.try_decode(&ctx("spBv1.0/G/NDATA/E", &data));
        let f = extract_sparkplug_fields(&events[0]);
        assert_eq!(f.message_type, "NDATA");
        assert_eq!(f.seq, Some(3));
        assert_eq!(f.payload_timestamp, Some(1_700_000_001_000));
        assert_eq!(f.metric_count, Some(1));
        assert_eq!(f.alias_resolution_state, "resolved");
        assert!(!f.is_birth);
        assert!(!f.is_death);
        assert!(!f.is_command);
    }

    #[test]
    fn ndeath_with_bdseq_typed_fields() {
        let mut d = SparkplugBDecoder::new();
        let birth = payload_bytes(PbPayload {
            metrics: vec![bd_seq_metric(3), metric_named("X", 1, 1.0)],
            ..Default::default()
        });
        let _ = d.try_decode(&ctx("spBv1.0/G/NBIRTH/E", &birth));
        let death = payload_bytes(PbPayload {
            metrics: vec![bd_seq_metric(3)],
            ..Default::default()
        });
        let events = d.try_decode(&ctx("spBv1.0/G/NDEATH/E", &death));
        assert_eq!(events.len(), 1);
        let f = extract_sparkplug_fields(&events[0]);
        assert_eq!(f.message_type, "NDEATH");
        assert_eq!(f.bdseq, Some(3));
        assert!(f.metric_count.is_none());
        assert!(!f.is_birth);
        assert!(f.is_death);
        assert!(!f.is_command);
    }

    #[test]
    fn ncmd_emits_command_transaction() {
        let mut d = SparkplugBDecoder::new();
        let cmd = payload_bytes(PbPayload {
            metrics: vec![metric_named("Node Control/Rebirth", 1, 1.0)],
            ..Default::default()
        });
        let events = d.try_decode(&ctx("spBv1.0/Plant1/NCMD/PLC-A", &cmd));
        assert_eq!(events.len(), 1);
        let f = extract_sparkplug_fields(&events[0]);
        assert_eq!(f.message_type, "NCMD");
        assert_eq!(f.group_id, "Plant1");
        assert_eq!(f.edge_node_id, "PLC-A");
        assert!(f.device_id.is_none());
        assert!(f.is_command);
        assert!(!f.is_birth);
        assert!(!f.is_death);
        assert_eq!(f.metric_count, Some(1));
    }

    #[test]
    fn dcmd_emits_command_transaction_with_device_id() {
        let mut d = SparkplugBDecoder::new();
        let cmd = payload_bytes(PbPayload {
            metrics: vec![metric_named("Output/Setpoint", 2, 50.0)],
            ..Default::default()
        });
        let events = d.try_decode(&ctx("spBv1.0/Plant1/DCMD/PLC-A/Pump-3", &cmd));
        assert_eq!(events.len(), 1);
        let f = extract_sparkplug_fields(&events[0]);
        assert_eq!(f.message_type, "DCMD");
        assert_eq!(f.device_id.as_deref(), Some("Pump-3"));
        assert!(f.is_command);
        assert_eq!(f.metric_count, Some(1));
        // operation field on the transaction should equal the message type.
        match &events[0].family {
            BronzeEventFamily::ProtocolTransaction(tx) => {
                assert_eq!(tx.operation, "DCMD");
                assert_eq!(tx.status, "ok");
            }
            _ => panic!(),
        }
    }

    #[test]
    fn ndata_unresolved_alias_resolution_state() {
        let mut d = SparkplugBDecoder::new();
        // Send DATA without any preceding BIRTH — alias cannot resolve.
        let data = payload_bytes(PbPayload {
            seq: Some(1),
            metrics: vec![metric_aliased(42, 9.9)],
            ..Default::default()
        });
        let events = d.try_decode(&ctx("spBv1.0/G/NDATA/E", &data));
        // anomaly + tx + 1 reading
        let tx_event = events
            .iter()
            .find(|ev| matches!(ev.family, BronzeEventFamily::ProtocolTransaction(_)))
            .expect("must have ProtocolTransaction");
        let f = extract_sparkplug_fields(tx_event);
        assert_eq!(f.alias_resolution_state, "unresolved_no_birth");
    }

    #[test]
    fn protocol_fields_sparkplug_roundtrip_serde() {
        use crate::bronze::{ProtocolFields, SparkplugBronzeFields};
        let fields = SparkplugBronzeFields {
            message_type: "NBIRTH".into(),
            group_id: "G1".into(),
            edge_node_id: "E1".into(),
            device_id: None,
            bdseq: Some(7),
            seq: Some(0),
            payload_timestamp: Some(1_700_000_000_000),
            metric_count: Some(3),
            alias_resolution_state: "n/a".into(),
            is_birth: true,
            is_death: false,
            is_command: false,
        };
        let wrapped = ProtocolFields::Sparkplug(fields.clone());
        let json = serde_json::to_string(&wrapped).expect("serialize");
        assert!(json.contains("\"protocol\":\"sparkplug\""));
        assert!(json.contains("\"message_type\":\"NBIRTH\""));
        let back: ProtocolFields = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(back, wrapped);
    }
}

