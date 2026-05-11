//! Bronze v2 streaming DPI engine.

use std::io::{self, Read, Seek, SeekFrom};
use std::net::{IpAddr, Ipv4Addr};

use chrono::{DateTime, TimeZone, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::bronze::{
    BronzeBatch, BronzeEvent, BronzeEventFamily, EventEnvelope,
    ExtractedArtifact, ParseAnomaly,
    SegmentCheckpoint, TransportProtocol, BRONZE_SCHEMA_VERSION,
};
use crate::bilgepump::alerts::BilgepumpAlert;
use crate::bilgepump::config::BilgepumpConfig;
use crate::bilgepump::monitor::BilgepumpMonitor;
use crate::dedup::DedupEngine;
use crate::icmpeeker::IcmpeekerConfig;
use crate::stovetop::config::StovetopConfig;
use crate::stovetop::findings::FrameFinding;
use crate::stovetop::frame_inspector::FrameInspector;
use crate::registry::{
    format_mac, PacketContext, ProtocolData, ProtocolDissector,
};

#[derive(Debug, thiserror::Error)]
pub enum DpiError {
    #[error("capture read error: {0}")]
    Io(#[from] io::Error),

    #[error("invalid capture format: {0}")]
    InvalidCapture(&'static str),

    #[error("serialization error: {0}")]
    SerdeJson(#[from] serde_json::Error),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SegmentMeta {
    pub capture_id: String,
}

impl SegmentMeta {
    pub fn new(capture_id: impl Into<String>) -> Self {
        Self {
            capture_id: capture_id.into(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DpiSegmentOutput {
    pub checkpoint: SegmentCheckpoint,
    pub events: Vec<BronzeEvent>,
}

pub trait BronzeSink {
    fn push_batch(&mut self, batch: BronzeBatch) -> Result<(), DpiError>;
}

#[derive(Default)]
struct VecBronzeSink {
    events: Vec<BronzeEvent>,
}

impl BronzeSink for VecBronzeSink {
    fn push_batch(&mut self, batch: BronzeBatch) -> Result<(), DpiError> {
        self.events.extend(batch.events);
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DecoderInterest {
    EtherType(u16),
    TcpPort(u16),
    UdpPort(u16),
    IpProto(u8),
    Llc { dsap: u8, ssap: u8 },
    Snap { oui: [u8; 3], pid: u16 },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct LlcInfo {
    pub(crate) dsap: u8,
    pub(crate) ssap: u8,
    pub(crate) snap_oui: Option<[u8; 3]>,
    pub(crate) snap_pid: Option<u16>,
}

#[derive(Debug, Clone)]
pub(crate) struct StreamChunk<'a> {
    pub(crate) capture_id: &'a str,
    pub(crate) segment_hash: &'a str,
    pub(crate) interface_id: u32,
    pub(crate) frame_index: u64,
    pub(crate) timestamp: DateTime<Utc>,
    pub(crate) context: PacketContext,
    pub(crate) ethertype: u16,
    pub(crate) ip_proto: Option<u8>,
    pub(crate) llc: Option<LlcInfo>,
    pub(crate) transport: TransportProtocol,
    pub(crate) payload: &'a [u8],
    pub(crate) session_key: String,
    pub(crate) captured_len: u64,
}

pub(crate) trait SessionDecoder: Send {
    fn name(&self) -> &'static str;
    fn interest(&self) -> &'static [DecoderInterest];
    fn on_datagram(&mut self, _chunk: &StreamChunk<'_>, _out: &mut Vec<BronzeEvent>) {}
    fn on_stream_chunk(&mut self, _chunk: &StreamChunk<'_>, _out: &mut Vec<BronzeEvent>) {}
    fn on_gap(
        &mut self,
        _session_key: &str,
        _timestamp: DateTime<Utc>,
        _out: &mut Vec<BronzeEvent>,
    ) {
    }
    fn on_idle_flush(&mut self, _timestamp: DateTime<Utc>, _out: &mut Vec<BronzeEvent>) {}
    fn evict_idle(&mut self, _timestamp: DateTime<Utc>, _out: &mut Vec<BronzeEvent>) {}
}

pub struct DpiEngine {
    dedup: DedupEngine,
    decoders: Vec<Box<dyn SessionDecoder>>,
    batch_size: usize,
    frame_inspector: FrameInspector,
    icmpeeker_config: IcmpeekerConfig,
    bilgepump: BilgepumpMonitor,
}

impl DpiEngine {
    pub fn new() -> Self {
        let stovetop_config = StovetopConfig::default();
        Self {
            dedup: DedupEngine::new(
                std::time::Duration::from_secs(5),
                std::time::Duration::from_secs(1),
            ),
            decoders: collect_registered_decoders(),
            frame_inspector: FrameInspector::new(stovetop_config),
            icmpeeker_config: IcmpeekerConfig::default(),
            bilgepump: BilgepumpMonitor::new(BilgepumpConfig::default()),
            batch_size: 256,
        }
    }

    pub fn with_batch_size(mut self, batch_size: usize) -> Self {
        self.batch_size = batch_size.max(1);
        self
    }

    pub fn process_segment_to_vec<R: Read + Seek>(
        &mut self,
        meta: &SegmentMeta,
        reader: R,
    ) -> Result<DpiSegmentOutput, DpiError> {
        let mut sink = VecBronzeSink::default();
        let checkpoint = self.process_segment(meta, reader, &mut sink)?;
        Ok(DpiSegmentOutput {
            checkpoint,
            events: sink.events,
        })
    }

    pub fn process_capture_to_vec<R: Read + Seek>(
        &mut self,
        meta: &SegmentMeta,
        reader: R,
    ) -> Result<DpiSegmentOutput, DpiError> {
        self.process_segment_to_vec(meta, reader)
    }

    /// Streaming-canonical API: processes a capture segment and emits Bronze
    /// events directly to `sink` as they are produced, returning only the
    /// checkpoint. Prefer this over `process_segment_to_vec` for live ingest
    /// or when memory-bounded back-pressure is required.
    pub fn process_streaming<R: Read + Seek, S: BronzeSink>(
        &mut self,
        meta: &SegmentMeta,
        reader: R,
        sink: &mut S,
    ) -> Result<SegmentCheckpoint, DpiError> {
        self.process_segment(meta, reader, sink)
    }

    pub fn process_segment<R: Read + Seek, S: BronzeSink>(
        &mut self,
        meta: &SegmentMeta,
        mut reader: R,
        sink: &mut S,
    ) -> Result<SegmentCheckpoint, DpiError> {
        let segment_hash = compute_segment_hash(&mut reader)?;
        let mut pending_events = Vec::new();
        let mut frames_processed = 0u64;
        let mut events_emitted = 0u64;
        let mut last_timestamp = Utc::now();

        read_capture_packets(&mut reader, |packet| {
            frames_processed += 1;
            let frame_events = self.process_packet_record(
                meta,
                &segment_hash,
                packet.interface_id,
                frames_processed,
                packet.timestamp,
                packet.captured_len,
                packet.orig_len,
                &packet.data,
            )?;
            if let Some(ts) = frame_events.first().map(|event| event.envelope.timestamp) {
                last_timestamp = ts;
            }

            for event in frame_events {
                if self.should_emit(&event) {
                    pending_events.push(event);
                }
            }

            for decoder in &mut self.decoders {
                decoder.evict_idle(last_timestamp, &mut pending_events);
            }

            if pending_events.len() >= self.batch_size {
                events_emitted += flush_batch(
                    meta.capture_id.clone(),
                    segment_hash.clone(),
                    &mut pending_events,
                    frames_processed,
                    sink,
                )? as u64;
            }
            Ok(())
        })?;

        for decoder in &mut self.decoders {
            decoder.on_idle_flush(last_timestamp, &mut pending_events);
            decoder.evict_idle(last_timestamp, &mut pending_events);
        }
        self.bilgepump.evict_expired(last_timestamp);

        let final_pending = pending_events.len() as u64;
        if !pending_events.is_empty() {
            events_emitted += flush_batch(
                meta.capture_id.clone(),
                segment_hash.clone(),
                &mut pending_events,
                frames_processed,
                sink,
            )? as u64;
        }

        Ok(SegmentCheckpoint {
            capture_id: meta.capture_id.clone(),
            schema_version: BRONZE_SCHEMA_VERSION.to_string(),
            segment_hash,
            frames_processed,
            events_emitted: events_emitted.max(final_pending),
        })
    }

    pub fn process_pcapng<R: Read + Seek>(
        &mut self,
        capture_id: impl Into<String>,
        reader: R,
    ) -> Result<Vec<BronzeEvent>, DpiError> {
        Ok(self
            .process_segment_to_vec(&SegmentMeta::new(capture_id), reader)?
            .events)
    }

    pub fn process_capture<R: Read + Seek>(
        &mut self,
        capture_id: impl Into<String>,
        reader: R,
    ) -> Result<Vec<BronzeEvent>, DpiError> {
        Ok(self
            .process_capture_to_vec(&SegmentMeta::new(capture_id), reader)?
            .events)
    }

    fn process_packet_record(
        &mut self,
        meta: &SegmentMeta,
        segment_hash: &str,
        interface_id: u32,
        frame_index: u64,
        timestamp: DateTime<Utc>,
        captured_len: usize,
        orig_len: u32,
        pkt_data: &[u8],
    ) -> Result<Vec<BronzeEvent>, DpiError> {
        let timestamp_ns = timestamp
            .timestamp_nanos_opt()
            .unwrap_or_else(|| timestamp.timestamp_micros() * 1_000)
            as u64;

        let mut dst_mac = [0u8; 6];
        let mut src_mac = [0u8; 6];
        let mut vlan_id = None;
        let (mut ethertype, mut l2_payload) = if pkt_data.len() >= 14 {
            dst_mac.copy_from_slice(&pkt_data[0..6]);
            src_mac.copy_from_slice(&pkt_data[6..12]);

            let mut ethertype = u16::from_be_bytes([pkt_data[12], pkt_data[13]]);
            let mut l2_payload = &pkt_data[14..];
            while matches!(ethertype, 0x8100 | 0x88A8 | 0x9100) && l2_payload.len() >= 4 {
                if vlan_id.is_none() {
                    vlan_id = Some(u16::from_be_bytes([l2_payload[0], l2_payload[1]]) & 0x0FFF);
                }
                ethertype = u16::from_be_bytes([l2_payload[2], l2_payload[3]]);
                l2_payload = &l2_payload[4..];
            }
            (ethertype, l2_payload)
        } else {
            (0, &[][..])
        };

        if !matches!(ethertype, 0x0800 | 0x0806 | 0x88CC) {
            let prefixed = if ethertype <= 1500 {
                detect_prefixed_l3_payload(l2_payload)
                    .or_else(|| detect_prefixed_l3_payload(pkt_data))
            } else {
                detect_prefixed_l3_payload(pkt_data)
            };
            if let Some((prefixed_ethertype, prefixed_payload)) = prefixed {
                // RiverFlow namespace capture can present packets with a small
                // pseudo-header ahead of the real L3 payload, either directly
                // or nested inside an 802.3-length frame. When there is no
                // outer Ethernet identity, leave src/dst MAC zeroed and let
                // IP/ARP-level identity drive asset correlation.
                src_mac = [0u8; 6];
                dst_mac = [0u8; 6];
                ethertype = prefixed_ethertype;
                l2_payload = prefixed_payload;
            }
        }

        if l2_payload.is_empty() {
            return Ok(vec![parse_anomaly_event(
                meta.capture_id.clone(),
                empty_envelope(interface_id, frame_index, timestamp, segment_hash),
                "engine",
                "medium",
                "ethernet frame shorter than 14 bytes",
                pkt_data,
            )]);
        }

        let base_context = PacketContext {
            src_mac,
            dst_mac,
            src_ip: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            dst_ip: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            src_port: 0,
            dst_port: 0,
            vlan_id,
            timestamp: timestamp_ns,
        };

        let mut out = Vec::new();

        // Stovetop: pre-dissector frame-level inspection
        let ethernet_header_len = pkt_data.len() - l2_payload.len();
        let frame_findings = self.frame_inspector.inspect_frame(
            pkt_data,
            captured_len,
            orig_len,
            ethertype,
            l2_payload,
            ethernet_header_len,
        );
        for finding in &frame_findings {
            out.push(stovetop_finding_to_event_raw(
                finding,
                &meta.capture_id,
                interface_id,
                frame_index,
                timestamp,
                segment_hash,
                &base_context,
                captured_len as u64,
                pkt_data,
            ));
        }

        // Bilgepump: pre-VLAN L2 frame inspection (VLAN hopping, MAC anomalies)
        let l2_alerts = self.bilgepump.inspect_l2_frame(pkt_data, &src_mac);
        for alert in &l2_alerts {
            out.push(bilgepump_alert_to_event(
                alert,
                &meta.capture_id,
                interface_id,
                frame_index,
                timestamp,
                segment_hash,
                &base_context,
                captured_len as u64,
                pkt_data,
            ));
        }

        match ethertype {
            0x0806 | 0x88CC => {
                let chunk = StreamChunk {
                    capture_id: &meta.capture_id,
                    segment_hash,
                    interface_id,
                    frame_index,
                    timestamp,
                    context: base_context,
                    ethertype,
                    ip_proto: None,
                    llc: None,
                    transport: if ethertype == 0x0806 {
                        TransportProtocol::Arp
                    } else {
                        TransportProtocol::Ethernet
                    },
                    payload: l2_payload,
                    session_key: make_layer2_session_key(
                        &src_mac,
                        &dst_mac,
                        &format!("ethertype:{ethertype:04x}"),
                    ),
                    captured_len: captured_len as u64,
                };

                for decoder in &mut self.decoders {
                    if interest_matches(decoder.interest(), &chunk) {
                        decoder.on_datagram(&chunk, &mut out);
                    }
                }

                // Bilgepump: stateful L2 observation for ARP and LLDP
                if ethertype == 0x0806 {
                    use crate::dissectors::arp::ArpDissector;
                    use crate::registry::ProtocolDissector as _;
                    let arp_d = ArpDissector;
                    if let Some(ProtocolData::Arp(ref fields)) =
                        arp_d.parse(l2_payload, &chunk.context)
                    {
                        let bp_alerts = self.bilgepump.observe_arp(
                            fields, &src_mac, vlan_id, timestamp,
                        );
                        for alert in &bp_alerts {
                            out.push(bilgepump_alert_to_event(
                                alert,
                                &meta.capture_id,
                                chunk.interface_id,
                                chunk.frame_index,
                                chunk.timestamp,
                                chunk.segment_hash,
                                &chunk.context,
                                chunk.captured_len,
                                l2_payload,
                            ));
                        }
                    }
                } else if ethertype == 0x88CC {
                    use crate::dissectors::lldp::LldpDissector;
                    use crate::registry::ProtocolDissector as _;
                    let lldp_d = LldpDissector;
                    if let Some(ProtocolData::Lldp(ref fields)) =
                        lldp_d.parse(l2_payload, &chunk.context)
                    {
                        let bp_alerts = self.bilgepump.observe_lldp(
                            fields, &src_mac, timestamp,
                        );
                        for alert in &bp_alerts {
                            out.push(bilgepump_alert_to_event(
                                alert,
                                &meta.capture_id,
                                chunk.interface_id,
                                chunk.frame_index,
                                chunk.timestamp,
                                chunk.segment_hash,
                                &chunk.context,
                                chunk.captured_len,
                                l2_payload,
                            ));
                        }
                    }
                }
            }
            0x0800 => {
                if l2_payload.len() < 20 {
                    out.push(parse_anomaly_event(
                        meta.capture_id.clone(),
                        empty_envelope(interface_id, frame_index, timestamp, segment_hash),
                        "engine",
                        "medium",
                        "ipv4 packet shorter than minimum header",
                        l2_payload,
                    ));
                    return Ok(out);
                }

                let ihl = ((l2_payload[0] & 0x0F) as usize) * 4;
                if ihl < 20 || l2_payload.len() < ihl {
                    out.push(parse_anomaly_event(
                        meta.capture_id.clone(),
                        empty_envelope(interface_id, frame_index, timestamp, segment_hash),
                        "engine",
                        "medium",
                        "invalid ipv4 header length",
                        l2_payload,
                    ));
                    return Ok(out);
                }

                let ip_proto = l2_payload[9];
                let src_ip = IpAddr::V4(Ipv4Addr::new(
                    l2_payload[12],
                    l2_payload[13],
                    l2_payload[14],
                    l2_payload[15],
                ));
                let dst_ip = IpAddr::V4(Ipv4Addr::new(
                    l2_payload[16],
                    l2_payload[17],
                    l2_payload[18],
                    l2_payload[19],
                ));
                let transport_payload = &l2_payload[ihl..];

                match ip_proto {
                    6 => {
                        if transport_payload.len() < 20 {
                            out.push(parse_anomaly_event(
                                meta.capture_id.clone(),
                                empty_envelope(interface_id, frame_index, timestamp, segment_hash),
                                "engine",
                                "medium",
                                "tcp header shorter than minimum length",
                                transport_payload,
                            ));
                            return Ok(out);
                        }

                        let src_port =
                            u16::from_be_bytes([transport_payload[0], transport_payload[1]]);
                        let dst_port =
                            u16::from_be_bytes([transport_payload[2], transport_payload[3]]);
                        let data_offset = ((transport_payload[12] >> 4) as usize) * 4;
                        if data_offset < 20 || transport_payload.len() < data_offset {
                            out.push(parse_anomaly_event(
                                meta.capture_id.clone(),
                                empty_envelope(interface_id, frame_index, timestamp, segment_hash),
                                "engine",
                                "medium",
                                "invalid tcp data offset",
                                transport_payload,
                            ));
                            return Ok(out);
                        }

                        let payload = &transport_payload[data_offset..];
                        let session_key =
                            make_ip_session_key(src_ip, dst_ip, src_port, dst_port, "tcp");
                        let chunk = StreamChunk {
                            capture_id: &meta.capture_id,
                            segment_hash,
                            interface_id,
                            frame_index,
                            timestamp,
                            context: PacketContext {
                                src_mac,
                                dst_mac,
                                src_ip,
                                dst_ip,
                                src_port,
                                dst_port,
                                vlan_id,
                                timestamp: timestamp_ns,
                            },
                            ethertype,
                            ip_proto: Some(6),
                            llc: None,
                            transport: TransportProtocol::Tcp,
                            payload,
                            session_key,
                            captured_len: captured_len as u64,
                        };

                        for decoder in &mut self.decoders {
                            if interest_matches(decoder.interest(), &chunk) {
                                decoder.on_stream_chunk(&chunk, &mut out);
                            }
                        }
                    }
                    17 => {
                        if transport_payload.len() < 8 {
                            out.push(parse_anomaly_event(
                                meta.capture_id.clone(),
                                empty_envelope(interface_id, frame_index, timestamp, segment_hash),
                                "engine",
                                "medium",
                                "udp header shorter than minimum length",
                                transport_payload,
                            ));
                            return Ok(out);
                        }

                        let src_port =
                            u16::from_be_bytes([transport_payload[0], transport_payload[1]]);
                        let dst_port =
                            u16::from_be_bytes([transport_payload[2], transport_payload[3]]);
                        let payload = &transport_payload[8..];
                        let session_key =
                            make_ip_session_key(src_ip, dst_ip, src_port, dst_port, "udp");
                        let chunk = StreamChunk {
                            capture_id: &meta.capture_id,
                            segment_hash,
                            interface_id,
                            frame_index,
                            timestamp,
                            context: PacketContext {
                                src_mac,
                                dst_mac,
                                src_ip,
                                dst_ip,
                                src_port,
                                dst_port,
                                vlan_id,
                                timestamp: timestamp_ns,
                            },
                            ethertype,
                            ip_proto: Some(17),
                            llc: None,
                            transport: TransportProtocol::Udp,
                            payload,
                            session_key,
                            captured_len: captured_len as u64,
                        };

                        for decoder in &mut self.decoders {
                            if interest_matches(decoder.interest(), &chunk) {
                                decoder.on_datagram(&chunk, &mut out);
                            }
                        }
                    }
                    1 => {
                        let session_key =
                            make_ip_session_key(src_ip, dst_ip, 0, 0, "icmp");
                        let chunk = StreamChunk {
                            capture_id: &meta.capture_id,
                            segment_hash,
                            interface_id,
                            frame_index,
                            timestamp,
                            context: PacketContext {
                                src_mac,
                                dst_mac,
                                src_ip,
                                dst_ip,
                                src_port: 0,
                                dst_port: 0,
                                vlan_id,
                                timestamp: timestamp_ns,
                            },
                            ethertype,
                            ip_proto: Some(1),
                            llc: None,
                            transport: TransportProtocol::Icmp,
                            payload: transport_payload,
                            session_key,
                            captured_len: captured_len as u64,
                        };

                        for decoder in &mut self.decoders {
                            if interest_matches(decoder.interest(), &chunk) {
                                decoder.on_datagram(&chunk, &mut out);
                            }
                        }

                        // ICMPeeker anomaly detection
                        let icmp_findings = crate::icmpeeker::inspect(
                            &self.icmpeeker_config,
                            transport_payload,
                        );
                        for finding in &icmp_findings {
                            out.push(stovetop_finding_to_event(
                                finding,
                                &meta.capture_id,
                                &chunk,
                            ));
                        }
                    }
                    other => {
                        // Any IpProto-interested decoder (e.g. IGMP) gets a
                        // chance here. If none claim the packet, emit a low-
                        // severity anomaly so the operator sees the unsupported
                        // transport.
                        let session_key =
                            make_ip_session_key(src_ip, dst_ip, 0, 0, "ip");
                        let chunk = StreamChunk {
                            capture_id: &meta.capture_id,
                            segment_hash,
                            interface_id,
                            frame_index,
                            timestamp,
                            context: PacketContext {
                                src_mac,
                                dst_mac,
                                src_ip,
                                dst_ip,
                                src_port: 0,
                                dst_port: 0,
                                vlan_id,
                                timestamp: timestamp_ns,
                            },
                            ethertype,
                            ip_proto: Some(other),
                            llc: None,
                            transport: TransportProtocol::Ipv4,
                            payload: transport_payload,
                            session_key: session_key.clone(),
                            captured_len: captured_len as u64,
                        };
                        let mut matched = false;
                        for decoder in &mut self.decoders {
                            if interest_matches(decoder.interest(), &chunk) {
                                matched = true;
                                decoder.on_datagram(&chunk, &mut out);
                            }
                        }
                        if !matched {
                            out.push(parse_anomaly_event(
                                meta.capture_id.clone(),
                                build_envelope(
                                    &base_context,
                                    interface_id,
                                    frame_index,
                                    timestamp,
                                    segment_hash,
                                    TransportProtocol::Ipv4,
                                    Some("ip"),
                                    captured_len as u64,
                                    session_key,
                                ),
                                "engine",
                                "low",
                                "unsupported ipv4 transport protocol",
                                transport_payload,
                            ));
                        }
                    }
                }
            }
            value if value > 1500 => {
                let chunk = StreamChunk {
                    capture_id: &meta.capture_id,
                    segment_hash,
                    interface_id,
                    frame_index,
                    timestamp,
                    context: base_context.clone(),
                    ethertype: value,
                    ip_proto: None,
                    llc: None,
                    transport: TransportProtocol::Ethernet,
                    payload: l2_payload,
                    session_key: make_layer2_session_key(
                        &src_mac,
                        &dst_mac,
                        &format!("ethertype:{value:04x}"),
                    ),
                    captured_len: captured_len as u64,
                };

                let mut matched = false;
                for decoder in &mut self.decoders {
                    if interest_matches(decoder.interest(), &chunk) {
                        matched = true;
                        decoder.on_datagram(&chunk, &mut out);
                    }
                }

                if !matched {
                    out.push(parse_anomaly_event(
                        meta.capture_id.clone(),
                        build_envelope(
                            &base_context,
                            interface_id,
                            frame_index,
                            timestamp,
                            segment_hash,
                            TransportProtocol::Ethernet,
                            None,
                            captured_len as u64,
                            chunk.session_key,
                        ),
                        "engine",
                        "low",
                        "unsupported ethertype",
                        l2_payload,
                    ));
                }
            }
            value if value <= 1500 => {
                if l2_payload.len() < 3 {
                    out.push(parse_anomaly_event(
                        meta.capture_id.clone(),
                        empty_envelope(interface_id, frame_index, timestamp, segment_hash),
                        "engine",
                        "medium",
                        "802.3 llc frame shorter than minimum header",
                        l2_payload,
                    ));
                    return Ok(out);
                }

                let dsap = l2_payload[0];
                let ssap = l2_payload[1];
                let control = l2_payload[2];

                let (payload, llc, session_key) = if dsap == 0xAA
                    && ssap == 0xAA
                    && control == 0x03
                    && l2_payload.len() >= 8
                {
                    let oui = [l2_payload[3], l2_payload[4], l2_payload[5]];
                    let pid = u16::from_be_bytes([l2_payload[6], l2_payload[7]]);
                    (
                        &l2_payload[8..],
                        Some(LlcInfo {
                            dsap,
                            ssap,
                            snap_oui: Some(oui),
                            snap_pid: Some(pid),
                        }),
                        make_layer2_session_key(
                            &src_mac,
                            &dst_mac,
                            &format!("snap:{:02x}{:02x}{:02x}:{pid:04x}", oui[0], oui[1], oui[2]),
                        ),
                    )
                } else {
                    (
                        &l2_payload[3..],
                        Some(LlcInfo {
                            dsap,
                            ssap,
                            snap_oui: None,
                            snap_pid: None,
                        }),
                        make_layer2_session_key(
                            &src_mac,
                            &dst_mac,
                            &format!("llc:{dsap:02x}:{ssap:02x}"),
                        ),
                    )
                };

                let chunk = StreamChunk {
                    capture_id: &meta.capture_id,
                    segment_hash,
                    interface_id,
                    frame_index,
                    timestamp,
                    context: base_context.clone(),
                    ethertype: value,
                    ip_proto: None,
                    llc,
                    transport: TransportProtocol::Ethernet,
                    payload,
                    session_key,
                    captured_len: captured_len as u64,
                };

                let mut matched = false;
                for decoder in &mut self.decoders {
                    if interest_matches(decoder.interest(), &chunk) {
                        matched = true;
                        decoder.on_datagram(&chunk, &mut out);
                    }
                }

                if !matched {
                    out.push(parse_anomaly_event(
                        meta.capture_id.clone(),
                        build_envelope(
                            &base_context,
                            interface_id,
                            frame_index,
                            timestamp,
                            segment_hash,
                            TransportProtocol::Ethernet,
                            None,
                            captured_len as u64,
                            chunk.session_key,
                        ),
                        "engine",
                        "low",
                        "unsupported 802.3 llc protocol",
                        l2_payload,
                    ));
                }
            }
            _ => {
                out.push(parse_anomaly_event(
                    meta.capture_id.clone(),
                    empty_envelope(interface_id, frame_index, timestamp, segment_hash),
                    "engine",
                    "low",
                    "unsupported ethertype",
                    l2_payload,
                ));
            }
        }

        Ok(out)
    }

    fn should_emit(&mut self, event: &BronzeEvent) -> bool {
        let src = event.src_ip().or(event.src_mac()).unwrap_or("unknown");
        let dst = event.dst_ip().or(event.dst_mac()).unwrap_or("unknown");
        let family_key = match &event.family {
            BronzeEventFamily::ProtocolTransaction(tx) => format!(
                "protocol_transaction:{}:{}",
                event.protocol().unwrap_or("unknown"),
                tx.operation
            ),
            BronzeEventFamily::AssetObservation(obs) => format!(
                "asset_observation:{}:{}",
                event.protocol().unwrap_or("unknown"),
                obs.asset_key
            ),
            BronzeEventFamily::TopologyObservation(obs) => format!(
                "topology_observation:{}:{}:{}:{}",
                event.protocol().unwrap_or("unknown"),
                obs.observation_type,
                obs.local_id,
                obs.remote_id.as_deref().unwrap_or("none")
            ),
            BronzeEventFamily::ParseAnomaly(anomaly) => {
                format!("parse_anomaly:{}:{}", anomaly.decoder, anomaly.reason)
            }
            BronzeEventFamily::ExtractedArtifact(artifact) => format!(
                "extracted_artifact:{}:{}",
                artifact.artifact_type, artifact.artifact_key
            ),
            BronzeEventFamily::ProcessReading(reading) => {
                let pid_key = match &reading.point_id {
                    crate::bronze::PointIdentifier::ModbusRegister {
                        unit_id,
                        addr,
                        register_type,
                    } => format!("modbus_register:{unit_id}:{addr}:{register_type:?}"),
                    crate::bronze::PointIdentifier::OpcUaNode {
                        namespace_index,
                        identifier,
                    } => format!("opc_ua_node:{namespace_index}:{identifier:?}"),
                    crate::bronze::PointIdentifier::CipSymbol { symbol, .. } => {
                        format!("cip_symbol:{symbol}")
                    }
                    crate::bronze::PointIdentifier::CipPath {
                        class,
                        instance,
                        attribute,
                    } => format!("cip_path:{class}:{instance}:{attribute:?}"),
                    crate::bronze::PointIdentifier::DnpPoint {
                        group,
                        variation,
                        index,
                    } => format!("dnp_point:{group}:{variation}:{index}"),
                    crate::bronze::PointIdentifier::Iec104Ioa {
                        common_addr,
                        ioa,
                        type_id,
                    } => format!("iec104_ioa:{common_addr}:{ioa}:{type_id}"),
                    crate::bronze::PointIdentifier::Iec61850Reference { reference, .. } => {
                        format!("iec61850_ref:{reference}")
                    }
                    crate::bronze::PointIdentifier::SparkplugMetric {
                        group_id,
                        edge_node_id,
                        device_id,
                        metric_name,
                        alias,
                        ..
                    } => format!(
                        "sparkplug:{group_id}:{edge_node_id}:{}:{}:{}",
                        device_id.as_deref().unwrap_or("-"),
                        metric_name.as_deref().unwrap_or("-"),
                        alias.map(|a| a.to_string()).unwrap_or_else(|| "-".to_string())
                    ),
                    crate::bronze::PointIdentifier::HartCommand { command, slot } => {
                        format!("hart_cmd:{command}:{slot:?}")
                    }
                    crate::bronze::PointIdentifier::PcccAddress {
                        file_type,
                        file_number,
                        element,
                        sub_element,
                    } => format!(
                        "pccc:{file_type:#04x}:{file_number}:{element}:{sub_element:?}"
                    ),
                    crate::bronze::PointIdentifier::SynchrophasorChannel {
                        idcode,
                        channel_index,
                        channel_type,
                        ..
                    } => format!(
                        "synphasor:{idcode}:{channel_index}:{channel_type:?}"
                    ),
                };
                format!("process_reading:{}:{pid_key}", reading.source_protocol)
            }
        };
        !self.dedup.is_duplicate(
            event
                .envelope
                .timestamp
                .timestamp_nanos_opt()
                .unwrap_or_default() as u64,
            src,
            dst,
            event.envelope.src_port.unwrap_or(0),
            event.envelope.dst_port.unwrap_or(0),
            &family_key,
        )
    }
}

impl Default for DpiEngine {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CaptureFormat {
    Pcapng,
    Pcap(PcapFlavor),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PcapFlavor {
    LittleMicro,
    BigMicro,
    LittleNano,
    BigNano,
}

impl PcapFlavor {
    fn is_little_endian(self) -> bool {
        matches!(self, Self::LittleMicro | Self::LittleNano)
    }

    fn timestamp_unit_nanos(self) -> u64 {
        match self {
            Self::LittleMicro | Self::BigMicro => 1_000,
            Self::LittleNano | Self::BigNano => 1,
        }
    }
}

#[derive(Debug, Clone)]
struct PacketRecord {
    interface_id: u32,
    timestamp: DateTime<Utc>,
    captured_len: usize,
    orig_len: u32,
    data: Vec<u8>,
}

fn flush_batch<S: BronzeSink>(
    capture_id: String,
    segment_hash: String,
    pending_events: &mut Vec<BronzeEvent>,
    frames_processed: u64,
    sink: &mut S,
) -> Result<usize, DpiError> {
    if pending_events.is_empty() {
        return Ok(0);
    }

    let checkpoint = SegmentCheckpoint {
        capture_id: capture_id.clone(),
        schema_version: BRONZE_SCHEMA_VERSION.to_string(),
        segment_hash: segment_hash.clone(),
        frames_processed,
        events_emitted: pending_events.len() as u64,
    };

    let batch = BronzeBatch {
        capture_id,
        schema_version: BRONZE_SCHEMA_VERSION.to_string(),
        segment_hash,
        events: std::mem::take(pending_events),
        checkpoint,
    };
    let count = batch.events.len();
    sink.push_batch(batch)?;
    Ok(count)
}

fn compute_segment_hash<R: Read + Seek>(reader: &mut R) -> Result<String, DpiError> {
    let start = reader.stream_position()?;
    reader.seek(SeekFrom::Start(start))?;
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 64 * 1024];

    loop {
        let read = reader.read(&mut buf)?;
        if read == 0 {
            break;
        }
        hasher.update(&buf[..read]);
    }

    reader.seek(SeekFrom::Start(start))?;
    Ok(format!("{:x}", hasher.finalize()))
}

fn read_capture_packets<R: Read + Seek, F>(reader: &mut R, mut on_packet: F) -> Result<(), DpiError>
where
    F: FnMut(PacketRecord) -> Result<(), DpiError>,
{
    let start = reader.stream_position()?;
    let format = detect_capture_format(reader)?;
    reader.seek(SeekFrom::Start(start))?;

    match format {
        CaptureFormat::Pcapng => loop {
            let Some(block) = read_pcapng_block(reader)? else {
                break;
            };
            if let Some(packet) = pcapng_packet_record(&block)? {
                on_packet(packet)?;
            }
        },
        CaptureFormat::Pcap(flavor) => {
            read_pcap_global_header(reader, flavor)?;
            loop {
                let Some(packet) = read_pcap_packet(reader, flavor)? else {
                    break;
                };
                on_packet(packet)?;
            }
        }
    }

    Ok(())
}

fn detect_prefixed_l3_payload(pkt_data: &[u8]) -> Option<(u16, &[u8])> {
    for offset in [6usize, 4usize] {
        let Some(payload) = pkt_data.get(offset..) else {
            continue;
        };
        if payload.len() >= 20 && payload[0] >> 4 == 4 {
            return Some((0x0800, payload));
        }
        if payload.len() >= 8 && payload.starts_with(&[0x00, 0x01, 0x08, 0x00, 0x06, 0x04]) {
            return Some((0x0806, payload));
        }
    }
    None
}

fn detect_capture_format<R: Read + Seek>(reader: &mut R) -> Result<CaptureFormat, DpiError> {
    let start = reader.stream_position()?;
    let mut magic = [0u8; 4];
    if !read_exact_or_eof(reader, &mut magic)? {
        return Err(DpiError::InvalidCapture("capture file is empty"));
    }
    reader.seek(SeekFrom::Start(start))?;

    match magic {
        [0x0A, 0x0D, 0x0D, 0x0A] => Ok(CaptureFormat::Pcapng),
        [0xD4, 0xC3, 0xB2, 0xA1] => Ok(CaptureFormat::Pcap(PcapFlavor::LittleMicro)),
        [0xA1, 0xB2, 0xC3, 0xD4] => Ok(CaptureFormat::Pcap(PcapFlavor::BigMicro)),
        [0x4D, 0x3C, 0xB2, 0xA1] => Ok(CaptureFormat::Pcap(PcapFlavor::LittleNano)),
        [0xA1, 0xB2, 0x3C, 0x4D] => Ok(CaptureFormat::Pcap(PcapFlavor::BigNano)),
        _ => Err(DpiError::InvalidCapture("unrecognized capture magic bytes")),
    }
}

fn read_pcapng_block<R: Read>(reader: &mut R) -> Result<Option<Vec<u8>>, DpiError> {
    let mut header = [0u8; 8];
    if !read_exact_or_eof(reader, &mut header)? {
        return Ok(None);
    }

    let block_len = u32::from_le_bytes([header[4], header[5], header[6], header[7]]) as usize;
    if block_len < 12 {
        return Err(DpiError::InvalidCapture(
            "pcapng block smaller than minimum",
        ));
    }

    let mut rest = vec![0u8; block_len - 8];
    reader.read_exact(&mut rest)?;
    let mut block = Vec::with_capacity(block_len);
    block.extend_from_slice(&header);
    block.extend_from_slice(&rest);
    Ok(Some(block))
}

fn pcapng_packet_record(block: &[u8]) -> Result<Option<PacketRecord>, DpiError> {
    if block.len() < 12 {
        return Err(DpiError::InvalidCapture("pcapng block shorter than header"));
    }

    let block_type = u32::from_le_bytes([block[0], block[1], block[2], block[3]]);
    if block_type != 0x0000_0006 {
        return Ok(None);
    }
    if block.len() < 32 {
        return Err(DpiError::InvalidCapture(
            "enhanced packet block shorter than minimum",
        ));
    }

    let interface_id = u32::from_le_bytes([block[8], block[9], block[10], block[11]]);
    let ts_high = u32::from_le_bytes([block[12], block[13], block[14], block[15]]) as u64;
    let ts_low = u32::from_le_bytes([block[16], block[17], block[18], block[19]]) as u64;
    let captured_len = u32::from_le_bytes([block[20], block[21], block[22], block[23]]) as usize;
    let orig_len = u32::from_le_bytes([block[24], block[25], block[26], block[27]]);
    let timestamp_us = (ts_high << 32) | ts_low;
    let timestamp = Utc
        .timestamp_opt(
            (timestamp_us / 1_000_000) as i64,
            ((timestamp_us % 1_000_000) * 1_000) as u32,
        )
        .single()
        .unwrap_or_else(Utc::now);

    let pkt_start = 28usize;
    if pkt_start + captured_len > block.len().saturating_sub(4) {
        return Err(DpiError::InvalidCapture(
            "enhanced packet block length exceeds packet data",
        ));
    }

    Ok(Some(PacketRecord {
        interface_id,
        timestamp,
        captured_len,
        orig_len,
        data: block[pkt_start..pkt_start + captured_len].to_vec(),
    }))
}

fn read_pcap_global_header<R: Read>(reader: &mut R, flavor: PcapFlavor) -> Result<(), DpiError> {
    let mut header = [0u8; 24];
    reader.read_exact(&mut header)?;
    let read_u16 = |bytes: [u8; 2]| -> u16 {
        if flavor.is_little_endian() {
            u16::from_le_bytes(bytes)
        } else {
            u16::from_be_bytes(bytes)
        }
    };
    let read_u32 = |bytes: [u8; 4]| -> u32 {
        if flavor.is_little_endian() {
            u32::from_le_bytes(bytes)
        } else {
            u32::from_be_bytes(bytes)
        }
    };

    let version_major = read_u16([header[4], header[5]]);
    let version_minor = read_u16([header[6], header[7]]);
    if version_major != 2 || version_minor != 4 {
        return Err(DpiError::InvalidCapture(
            "unsupported classic pcap version (expected 2.4)",
        ));
    }

    let network = read_u32([header[20], header[21], header[22], header[23]]);
    if network != 1 {
        return Err(DpiError::InvalidCapture(
            "unsupported classic pcap linktype (expected ethernet)",
        ));
    }

    Ok(())
}

fn read_pcap_packet<R: Read>(
    reader: &mut R,
    flavor: PcapFlavor,
) -> Result<Option<PacketRecord>, DpiError> {
    let mut header = [0u8; 16];
    if !read_exact_or_eof(reader, &mut header)? {
        return Ok(None);
    }

    let read_u32 = |bytes: [u8; 4]| -> u32 {
        if flavor.is_little_endian() {
            u32::from_le_bytes(bytes)
        } else {
            u32::from_be_bytes(bytes)
        }
    };

    let ts_sec = read_u32([header[0], header[1], header[2], header[3]]) as i64;
    let ts_frac = read_u32([header[4], header[5], header[6], header[7]]) as u64;
    let incl_len = read_u32([header[8], header[9], header[10], header[11]]) as usize;
    let orig_len = read_u32([header[12], header[13], header[14], header[15]]);
    let unit_nanos = flavor.timestamp_unit_nanos();
    let nanos_total = ts_frac
        .checked_mul(unit_nanos)
        .ok_or(DpiError::InvalidCapture("classic pcap timestamp overflow"))?;
    let seconds = ts_sec + (nanos_total / 1_000_000_000) as i64;
    let nanos = (nanos_total % 1_000_000_000) as u32;
    let timestamp = Utc
        .timestamp_opt(seconds, nanos)
        .single()
        .ok_or(DpiError::InvalidCapture(
            "classic pcap timestamp out of range",
        ))?;

    let mut data = vec![0u8; incl_len];
    reader.read_exact(&mut data)?;
    Ok(Some(PacketRecord {
        interface_id: 0,
        timestamp,
        captured_len: incl_len,
        orig_len,
        data,
    }))
}

fn read_exact_or_eof<R: Read>(reader: &mut R, buf: &mut [u8]) -> Result<bool, io::Error> {
    let mut offset = 0usize;
    while offset < buf.len() {
        let read = reader.read(&mut buf[offset..])?;
        if read == 0 {
            if offset == 0 {
                return Ok(false);
            }
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "unexpected eof while reading capture header",
            ));
        }
        offset += read;
    }
    Ok(true)
}

pub(crate) fn interest_matches(interests: &[DecoderInterest], chunk: &StreamChunk<'_>) -> bool {
    interests.iter().any(|interest| match interest {
        DecoderInterest::EtherType(value) => chunk.ethertype == *value,
        DecoderInterest::TcpPort(port) => {
            chunk.transport == TransportProtocol::Tcp
                && (chunk.context.src_port == *port || chunk.context.dst_port == *port)
        }
        DecoderInterest::UdpPort(port) => {
            chunk.transport == TransportProtocol::Udp
                && (chunk.context.src_port == *port || chunk.context.dst_port == *port)
        }
        DecoderInterest::IpProto(proto) => chunk.ip_proto == Some(*proto),
        DecoderInterest::Llc { dsap, ssap } => chunk
            .llc
            .map(|llc| llc.dsap == *dsap && llc.ssap == *ssap)
            .unwrap_or(false),
        DecoderInterest::Snap { oui, pid } => chunk
            .llc
            .map(|llc| llc.snap_oui == Some(*oui) && llc.snap_pid == Some(*pid))
            .unwrap_or(false),
    })
}

pub(crate) fn build_envelope(
    context: &PacketContext,
    interface_id: u32,
    frame_index: u64,
    timestamp: DateTime<Utc>,
    segment_hash: &str,
    transport: TransportProtocol,
    protocol: Option<&str>,
    captured_len: u64,
    session_key: String,
) -> EventEnvelope {
    EventEnvelope {
        timestamp,
        interface_id,
        segment_hash: segment_hash.to_string(),
        frame_index,
        session_key,
        src_mac: Some(format_mac(&context.src_mac)),
        dst_mac: Some(format_mac(&context.dst_mac)),
        src_ip: ip_to_string(context.src_ip),
        dst_ip: ip_to_string(context.dst_ip),
        src_port: non_zero_u16(context.src_port),
        dst_port: non_zero_u16(context.dst_port),
        vlan_id: context.vlan_id,
        transport,
        protocol: protocol.map(str::to_string),
        bytes_count: captured_len,
        packet_count: 1,
    }
}

pub(crate) fn empty_envelope(
    interface_id: u32,
    frame_index: u64,
    timestamp: DateTime<Utc>,
    segment_hash: &str,
) -> EventEnvelope {
    EventEnvelope {
        timestamp,
        interface_id,
        segment_hash: segment_hash.to_string(),
        frame_index,
        session_key: String::new(),
        src_mac: None,
        dst_mac: None,
        src_ip: None,
        dst_ip: None,
        src_port: None,
        dst_port: None,
        vlan_id: None,
        transport: TransportProtocol::Unknown,
        protocol: None,
        bytes_count: 0,
        packet_count: 0,
    }
}

/// Walk every `inventory::submit!`-registered decoder, sort by name for
/// deterministic ordering across builds, and instantiate via each
/// registration's factory closure. The fallback to alphabetical name order
/// keeps test assertions on emission ordering stable across the inventory
/// crate's link-time iteration order which is otherwise platform-dependent.
fn collect_registered_decoders() -> Vec<Box<dyn SessionDecoder>> {
    let mut regs: Vec<&decoders::DecoderRegistration> =
        inventory::iter::<decoders::DecoderRegistration>().collect();
    regs.sort_by_key(|r| r.name);
    regs.into_iter().map(|r| (r.factory)()).collect()
}

pub(crate) fn ip_to_string(ip: IpAddr) -> Option<String> {
    match ip {
        IpAddr::V4(v4) if v4 == Ipv4Addr::UNSPECIFIED => None,
        _ => Some(ip.to_string()),
    }
}

pub(crate) fn non_zero_u16(value: u16) -> Option<u16> {
    if value == 0 {
        None
    } else {
        Some(value)
    }
}

pub(crate) fn make_layer2_session_key(
    src_mac: &[u8; 6],
    dst_mac: &[u8; 6],
    protocol_key: &str,
) -> String {
    let mut peers = [format_mac(src_mac), format_mac(dst_mac)];
    peers.sort();
    format!("l2:{}:{}:{protocol_key}", peers[0], peers[1])
}

pub(crate) fn make_ip_session_key(
    src_ip: IpAddr,
    dst_ip: IpAddr,
    src_port: u16,
    dst_port: u16,
    transport: &str,
) -> String {
    let left = format!("{src_ip}:{src_port}");
    let right = format!("{dst_ip}:{dst_port}");
    if left <= right {
        format!("{transport}:{left}:{right}")
    } else {
        format!("{transport}:{right}:{left}")
    }
}

pub(crate) fn new_event(
    capture_id: String,
    envelope: EventEnvelope,
    family: BronzeEventFamily,
) -> BronzeEvent {
    BronzeEvent {
        event_id: Uuid::new_v4().to_string(),
        capture_id,
        schema_version: BRONZE_SCHEMA_VERSION.to_string(),
        envelope,
        family,
    }
}

pub(crate) fn parse_anomaly_event(
    capture_id: String,
    envelope: EventEnvelope,
    decoder: &str,
    severity: &str,
    reason: &str,
    raw_excerpt: &[u8],
) -> BronzeEvent {
    new_event(
        capture_id,
        envelope,
        BronzeEventFamily::ParseAnomaly(ParseAnomaly {
            decoder: decoder.to_string(),
            severity: severity.to_string(),
            reason: reason.to_string(),
            raw_excerpt_hex: hex::encode(&raw_excerpt[..raw_excerpt.len().min(32)]),
        }),
    )
}

pub(crate) fn artifact_event(
    capture_id: String,
    envelope: EventEnvelope,
    artifact_type: &str,
    artifact_key: &str,
    mime_type: Option<&str>,
    description: Option<&str>,
    bytes: &[u8],
) -> BronzeEvent {
    let sha256 = Sha256::digest(bytes);
    new_event(
        capture_id,
        envelope,
        BronzeEventFamily::ExtractedArtifact(ExtractedArtifact {
            artifact_type: artifact_type.to_string(),
            artifact_key: artifact_key.to_string(),
            sha256: format!("{sha256:x}"),
            mime_type: mime_type.map(str::to_string),
            content_hex: hex::encode(bytes),
            description: description.map(str::to_string),
        }),
    )
}


/// Convert a stovetop finding to a BronzeEvent using a StreamChunk for envelope.
fn stovetop_finding_to_event(
    finding: &FrameFinding,
    capture_id: &str,
    chunk: &StreamChunk<'_>,
) -> BronzeEvent {
    let envelope = build_envelope(
        &chunk.context,
        chunk.interface_id,
        chunk.frame_index,
        chunk.timestamp,
        chunk.segment_hash,
        chunk.transport,
        None,
        chunk.captured_len,
        chunk.session_key.clone(),
    );

    new_event(
        capture_id.to_string(),
        envelope,
        BronzeEventFamily::ParseAnomaly(ParseAnomaly {
            decoder: finding.decoder.to_string(),
            severity: finding.severity.as_str().to_string(),
            reason: finding.reason(),
            raw_excerpt_hex: String::new(),
        }),
    )
}

/// Convert a stovetop finding to a BronzeEvent using raw frame context
/// (for pre-dissector findings before a StreamChunk exists).
fn stovetop_finding_to_event_raw(
    finding: &FrameFinding,
    capture_id: &str,
    interface_id: u32,
    frame_index: u64,
    timestamp: DateTime<Utc>,
    segment_hash: &str,
    context: &PacketContext,
    captured_len: u64,
    raw_frame: &[u8],
) -> BronzeEvent {
    let envelope = build_envelope(
        context,
        interface_id,
        frame_index,
        timestamp,
        segment_hash,
        TransportProtocol::Ethernet,
        None,
        captured_len,
        String::new(),
    );

    new_event(
        capture_id.to_string(),
        envelope,
        BronzeEventFamily::ParseAnomaly(ParseAnomaly {
            decoder: finding.decoder.to_string(),
            severity: finding.severity.as_str().to_string(),
            reason: finding.reason(),
            raw_excerpt_hex: hex::encode(&raw_frame[..raw_frame.len().min(32)]),
        }),
    )
}

/// Convert a bilgepump alert to a BronzeEvent.
fn bilgepump_alert_to_event(
    alert: &BilgepumpAlert,
    capture_id: &str,
    interface_id: u32,
    frame_index: u64,
    timestamp: DateTime<Utc>,
    segment_hash: &str,
    context: &PacketContext,
    captured_len: u64,
    raw_excerpt: &[u8],
) -> BronzeEvent {
    let envelope = build_envelope(
        context,
        interface_id,
        frame_index,
        timestamp,
        segment_hash,
        TransportProtocol::Ethernet,
        None,
        captured_len,
        String::new(),
    );

    new_event(
        capture_id.to_string(),
        envelope,
        BronzeEventFamily::ParseAnomaly(ParseAnomaly {
            decoder: alert.decoder.to_string(),
            severity: alert.severity.as_str().to_string(),
            reason: alert.reason(),
            raw_excerpt_hex: hex::encode(&raw_excerpt[..raw_excerpt.len().min(32)]),
        }),
    )
}

pub(crate) mod decoders;

#[cfg(test)]
mod tests {
    use super::*;

    fn build_epb(packet: &[u8], timestamp_us: u64) -> Vec<u8> {
        let mut block = Vec::new();
        let block_len = 32 + packet.len() + ((4 - packet.len() % 4) % 4);
        block.extend_from_slice(&0x0000_0006u32.to_le_bytes());
        block.extend_from_slice(&(block_len as u32).to_le_bytes());
        block.extend_from_slice(&0u32.to_le_bytes()); // interface id
        block.extend_from_slice(&((timestamp_us >> 32) as u32).to_le_bytes());
        block.extend_from_slice(&(timestamp_us as u32).to_le_bytes());
        block.extend_from_slice(&(packet.len() as u32).to_le_bytes());
        block.extend_from_slice(&(packet.len() as u32).to_le_bytes());
        block.extend_from_slice(packet);
        while block.len() < block_len - 4 {
            block.push(0);
        }
        block.extend_from_slice(&(block_len as u32).to_le_bytes());
        block
    }

    fn build_pcapng(packet: &[u8]) -> Vec<u8> {
        let mut data = Vec::new();
        data.extend_from_slice(&0x0A0D0D0Au32.to_le_bytes());
        data.extend_from_slice(&28u32.to_le_bytes());
        data.extend_from_slice(&0x1A2B3C4Du32.to_le_bytes());
        data.extend_from_slice(&1u16.to_le_bytes());
        data.extend_from_slice(&0u16.to_le_bytes());
        data.extend_from_slice(&0xFFFF_FFFF_FFFF_FFFFu64.to_le_bytes());
        data.extend_from_slice(&28u32.to_le_bytes());
        data.extend_from_slice(&build_epb(packet, 1_700_000_000_000_000));
        data
    }

    fn build_pcap(packet: &[u8]) -> Vec<u8> {
        let mut data = Vec::new();
        data.extend_from_slice(&[0xD4, 0xC3, 0xB2, 0xA1]);
        data.extend_from_slice(&2u16.to_le_bytes());
        data.extend_from_slice(&4u16.to_le_bytes());
        data.extend_from_slice(&0i32.to_le_bytes());
        data.extend_from_slice(&0u32.to_le_bytes());
        data.extend_from_slice(&65535u32.to_le_bytes());
        data.extend_from_slice(&1u32.to_le_bytes());
        data.extend_from_slice(&1_700_000_000u32.to_le_bytes());
        data.extend_from_slice(&100_000u32.to_le_bytes());
        data.extend_from_slice(&(packet.len() as u32).to_le_bytes());
        data.extend_from_slice(&(packet.len() as u32).to_le_bytes());
        data.extend_from_slice(packet);
        data
    }

    fn ethernet_ipv4_tcp(
        src_mac: [u8; 6],
        dst_mac: [u8; 6],
        src_ip: [u8; 4],
        dst_ip: [u8; 4],
        src_port: u16,
        dst_port: u16,
        payload: &[u8],
        vlan_id: Option<u16>,
    ) -> Vec<u8> {
        let mut frame = Vec::new();
        frame.extend_from_slice(&dst_mac);
        frame.extend_from_slice(&src_mac);
        if let Some(vlan_id) = vlan_id {
            frame.extend_from_slice(&0x8100u16.to_be_bytes());
            frame.extend_from_slice(&(vlan_id & 0x0FFF).to_be_bytes());
            frame.extend_from_slice(&0x0800u16.to_be_bytes());
        } else {
            frame.extend_from_slice(&0x0800u16.to_be_bytes());
        }

        let total_len = 20 + 20 + payload.len();
        frame.extend_from_slice(&[
            0x45,
            0x00,
            ((total_len >> 8) & 0xFF) as u8,
            (total_len & 0xFF) as u8,
            0x00,
            0x01,
            0x00,
            0x00,
            64,
            6,
            0,
            0,
        ]);
        frame.extend_from_slice(&src_ip);
        frame.extend_from_slice(&dst_ip);
        frame.extend_from_slice(&src_port.to_be_bytes());
        frame.extend_from_slice(&dst_port.to_be_bytes());
        frame.extend_from_slice(&1u32.to_be_bytes());
        frame.extend_from_slice(&0u32.to_be_bytes());
        frame.push(0x50);
        frame.push(0x18);
        frame.extend_from_slice(&0x2000u16.to_be_bytes());
        frame.extend_from_slice(&0u16.to_be_bytes());
        frame.extend_from_slice(&0u16.to_be_bytes());
        frame.extend_from_slice(payload);
        frame
    }

    fn ethernet_ipv4_udp(src_port: u16, dst_port: u16, payload: &[u8]) -> Vec<u8> {
        let mut frame = Vec::new();
        frame.extend_from_slice(&[0x02, 0x00, 0x00, 0x00, 0x00, 0x01]);
        frame.extend_from_slice(&[0x02, 0x00, 0x00, 0x00, 0x00, 0x02]);
        frame.extend_from_slice(&0x0800u16.to_be_bytes());
        let total_len = 20 + 8 + payload.len();
        frame.extend_from_slice(&[
            0x45,
            0x00,
            ((total_len >> 8) & 0xFF) as u8,
            (total_len & 0xFF) as u8,
            0x00,
            0x01,
            0x00,
            0x00,
            64,
            17,
            0,
            0,
            10,
            0,
            0,
            1,
            10,
            0,
            0,
            2,
        ]);
        frame.extend_from_slice(&src_port.to_be_bytes());
        frame.extend_from_slice(&dst_port.to_be_bytes());
        frame.extend_from_slice(&((8 + payload.len()) as u16).to_be_bytes());
        frame.extend_from_slice(&0u16.to_be_bytes());
        frame.extend_from_slice(payload);
        frame
    }

    fn prefixed_ipv4_udp(src_port: u16, dst_port: u16, payload: &[u8]) -> Vec<u8> {
        let mut frame = vec![0x00, 0x07, 0x00, 0x03];
        frame.extend_from_slice(&ethernet_ipv4_udp(src_port, dst_port, payload)[14..]);
        frame
    }

    fn six_byte_prefixed_ipv4_udp(src_port: u16, dst_port: u16, payload: &[u8]) -> Vec<u8> {
        let mut frame = vec![0x00, 0x07, 0x00, 0x03, 0x00, 0x00];
        frame.extend_from_slice(&ethernet_ipv4_udp(src_port, dst_port, payload)[14..]);
        frame
    }

    fn ethernet_with_prefixed_ipv4_udp(src_port: u16, dst_port: u16, payload: &[u8]) -> Vec<u8> {
        let mut frame = vec![
            0x00, 0x10, 0x00, 0x2a, 0x00, 0x5f, // dst mac
            0x00, 0x10, 0x00, 0x2b, 0x00, 0x5f, // src mac
        ];
        frame.extend_from_slice(&0x0001u16.to_be_bytes());
        frame.extend_from_slice(&six_byte_prefixed_ipv4_udp(src_port, dst_port, payload));
        frame
    }

    fn ethernet_arp_with_vlans(
        src_mac: [u8; 6],
        dst_mac: [u8; 6],
        sender_ip: [u8; 4],
        target_ip: [u8; 4],
        vlan_tags: &[u16],
    ) -> Vec<u8> {
        let mut frame = Vec::new();
        frame.extend_from_slice(&dst_mac);
        frame.extend_from_slice(&src_mac);

        for vlan in vlan_tags {
            frame.extend_from_slice(&0x8100u16.to_be_bytes());
            frame.extend_from_slice(&(vlan & 0x0FFF).to_be_bytes());
        }
        frame.extend_from_slice(&0x0806u16.to_be_bytes());
        frame.extend_from_slice(&[
            0x00, 0x01, // Ethernet
            0x08, 0x00, // IPv4
            0x06, // hlen
            0x04, // plen
            0x00, 0x01, // request
        ]);
        frame.extend_from_slice(&src_mac);
        frame.extend_from_slice(&sender_ip);
        frame.extend_from_slice(&[0x00; 6]);
        frame.extend_from_slice(&target_ip);
        frame
    }

    fn ethernet_llc(
        dst_mac: [u8; 6],
        src_mac: [u8; 6],
        dsap: u8,
        ssap: u8,
        control: u8,
        payload: &[u8],
    ) -> Vec<u8> {
        let mut frame = Vec::new();
        frame.extend_from_slice(&dst_mac);
        frame.extend_from_slice(&src_mac);
        frame.extend_from_slice(&((3 + payload.len()) as u16).to_be_bytes());
        frame.extend_from_slice(&[dsap, ssap, control]);
        frame.extend_from_slice(payload);
        frame
    }

    fn ethernet_ethertype(
        dst_mac: [u8; 6],
        src_mac: [u8; 6],
        ethertype: u16,
        payload: &[u8],
    ) -> Vec<u8> {
        let mut frame = Vec::new();
        frame.extend_from_slice(&dst_mac);
        frame.extend_from_slice(&src_mac);
        frame.extend_from_slice(&ethertype.to_be_bytes());
        frame.extend_from_slice(payload);
        frame
    }

    fn ethernet_llc_snap(
        dst_mac: [u8; 6],
        src_mac: [u8; 6],
        oui: [u8; 3],
        pid: u16,
        payload: &[u8],
    ) -> Vec<u8> {
        let mut frame = Vec::new();
        frame.extend_from_slice(&dst_mac);
        frame.extend_from_slice(&src_mac);
        frame.extend_from_slice(&((8 + payload.len()) as u16).to_be_bytes());
        frame.extend_from_slice(&[0xAA, 0xAA, 0x03]);
        frame.extend_from_slice(&oui);
        frame.extend_from_slice(&pid.to_be_bytes());
        frame.extend_from_slice(payload);
        frame
    }

    fn build_dhcp_discover() -> Vec<u8> {
        let mut data = vec![0u8; 240];
        data[0] = 1;
        data[1] = 1;
        data[2] = 6;
        data[4..8].copy_from_slice(&0x3903_f326u32.to_be_bytes());
        data[28..34].copy_from_slice(&[0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
        data[236..240].copy_from_slice(&[0x63, 0x82, 0x53, 0x63]);
        data.extend_from_slice(&[
            53, 1, 1, 12, 6, b'p', b'l', b'c', b'-', b'0', b'1', 60, 7, b'S', b'i', b'e', b'm',
            b'e', b'n', b's', 61, 7, 1, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 50, 4, 10, 0, 0, 42,
            255,
        ]);
        data
    }

    fn snmp_tlv(tag: u8, value: &[u8]) -> Vec<u8> {
        let mut out = vec![tag];
        out.push(value.len() as u8);
        out.extend_from_slice(value);
        out
    }

    fn snmp_seq(children: Vec<u8>) -> Vec<u8> {
        snmp_tlv(0x30, &children)
    }

    fn snmp_int(v: i64) -> Vec<u8> {
        let mut bytes = v.to_be_bytes().to_vec();
        while bytes.len() > 1
            && ((bytes[0] == 0x00 && bytes[1] & 0x80 == 0)
                || (bytes[0] == 0xFF && bytes[1] & 0x80 != 0))
        {
            bytes.remove(0);
        }
        snmp_tlv(0x02, &bytes)
    }

    fn snmp_octets(s: &[u8]) -> Vec<u8> {
        snmp_tlv(0x04, s)
    }

    fn snmp_oid(arcs: &[u32]) -> Vec<u8> {
        let mut out = Vec::new();
        out.push((arcs[0] * 40 + arcs[1]) as u8);
        for &arc in &arcs[2..] {
            let mut stack = vec![(arc & 0x7F) as u8];
            let mut value = arc >> 7;
            while value > 0 {
                stack.push(((value & 0x7F) as u8) | 0x80);
                value >>= 7;
            }
            stack.reverse();
            out.extend_from_slice(&stack);
        }
        snmp_tlv(0x06, &out)
    }

    fn snmp_varbind(oid_arcs: &[u32], value: Vec<u8>) -> Vec<u8> {
        snmp_seq([snmp_oid(oid_arcs), value].concat())
    }

    fn build_snmp_get_response() -> Vec<u8> {
        let sys_name = snmp_varbind(&[1, 3, 6, 1, 2, 1, 1, 5, 0], snmp_octets(b"switch-01"));
        let sys_descr = snmp_varbind(
            &[1, 3, 6, 1, 2, 1, 1, 1, 0],
            snmp_octets(b"Industrial Ethernet Switch"),
        );
        let varbinds = snmp_seq([sys_name, sys_descr].concat());
        let pdu = snmp_tlv(
            0xA2,
            &[snmp_int(1), snmp_int(0), snmp_int(0), varbinds].concat(),
        );
        snmp_seq([snmp_int(1), snmp_octets(b"public"), pdu].concat())
    }

    fn push_cdp_tlv(pkt: &mut Vec<u8>, tlv_type: u16, value: &[u8]) {
        let len = (value.len() + 4) as u16;
        pkt.extend_from_slice(&tlv_type.to_be_bytes());
        pkt.extend_from_slice(&len.to_be_bytes());
        pkt.extend_from_slice(value);
    }

    fn build_cdp_payload() -> Vec<u8> {
        let mut pkt = vec![0x02, 0xB4, 0x00, 0x00];
        push_cdp_tlv(&mut pkt, 0x0001, b"dist-sw-01");
        push_cdp_tlv(&mut pkt, 0x0003, b"GigabitEthernet1/0/24");
        push_cdp_tlv(&mut pkt, 0x0004, &0x0000_0009u32.to_be_bytes());
        push_cdp_tlv(&mut pkt, 0x0005, b"Cisco IOS XE");
        push_cdp_tlv(&mut pkt, 0x0006, b"Catalyst 9300");
        push_cdp_tlv(&mut pkt, 0x000a, &20u16.to_be_bytes());
        push_cdp_tlv(&mut pkt, 0x000b, &[1]);
        pkt
    }

    fn build_stp_bpdu() -> Vec<u8> {
        let mut pkt = Vec::new();
        pkt.extend_from_slice(&0x0000u16.to_be_bytes());
        pkt.push(0x02);
        pkt.push(0x00);
        pkt.push(0x01);
        pkt.extend_from_slice(&[0x80, 0x00, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
        pkt.extend_from_slice(&0x0000_0A0Bu32.to_be_bytes());
        pkt.extend_from_slice(&[0x80, 0x00, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB]);
        pkt.extend_from_slice(&0x8001u16.to_be_bytes());
        pkt.extend_from_slice(&0x0100u16.to_be_bytes());
        pkt.extend_from_slice(&0x1400u16.to_be_bytes());
        pkt.extend_from_slice(&0x0200u16.to_be_bytes());
        pkt.extend_from_slice(&0x0F00u16.to_be_bytes());
        pkt
    }

    fn build_enip_encap(command: u16, session_handle: u32, data: &[u8]) -> Vec<u8> {
        let mut pkt = Vec::with_capacity(24 + data.len());
        pkt.extend_from_slice(&command.to_le_bytes());
        pkt.extend_from_slice(&(data.len() as u16).to_le_bytes());
        pkt.extend_from_slice(&session_handle.to_le_bytes());
        pkt.extend_from_slice(&0u32.to_le_bytes());
        pkt.extend_from_slice(&[0u8; 8]);
        pkt.extend_from_slice(&0u32.to_le_bytes());
        pkt.extend_from_slice(data);
        pkt
    }

    fn build_enip_list_identity_response() -> Vec<u8> {
        let product_name = b"1756-L85E";
        let mut item = Vec::new();
        item.extend_from_slice(&1u16.to_le_bytes());
        item.extend_from_slice(&2u16.to_le_bytes());
        item.extend_from_slice(&44818u16.to_be_bytes());
        item.extend_from_slice(&[10, 0, 0, 2]);
        item.extend_from_slice(&[0u8; 8]);
        item.extend_from_slice(&1u16.to_le_bytes());
        item.extend_from_slice(&0x000Eu16.to_le_bytes());
        item.extend_from_slice(&321u16.to_le_bytes());
        item.extend_from_slice(&[20, 11]);
        item.extend_from_slice(&0x1234u16.to_le_bytes());
        item.extend_from_slice(&0x1122_3344u32.to_le_bytes());
        item.push(product_name.len() as u8);
        item.extend_from_slice(product_name);
        item.push(3);

        let mut data = Vec::new();
        data.extend_from_slice(&1u16.to_le_bytes());
        data.extend_from_slice(&0x000Cu16.to_le_bytes());
        data.extend_from_slice(&(item.len() as u16).to_le_bytes());
        data.extend_from_slice(&item);
        build_enip_encap(0x0063, 0, &data)
    }

    fn build_enip_send_rr_data_identity_response() -> Vec<u8> {
        let product_name = b"1734-AENTR";
        let mut cip = Vec::new();
        cip.extend_from_slice(&[0x81, 0x00, 0x00, 0x00]);
        cip.extend_from_slice(&1u16.to_le_bytes());
        cip.extend_from_slice(&0x000Cu16.to_le_bytes());
        cip.extend_from_slice(&77u16.to_le_bytes());
        cip.extend_from_slice(&[5, 12]);
        cip.extend_from_slice(&0x0000u16.to_le_bytes());
        cip.extend_from_slice(&0x5566_7788u32.to_le_bytes());
        cip.push(product_name.len() as u8);
        cip.extend_from_slice(product_name);
        cip.push(3);

        let mut data = Vec::new();
        data.extend_from_slice(&0u32.to_le_bytes());
        data.extend_from_slice(&0u16.to_le_bytes());
        data.extend_from_slice(&2u16.to_le_bytes());
        data.extend_from_slice(&0u16.to_le_bytes());
        data.extend_from_slice(&0u16.to_le_bytes());
        data.extend_from_slice(&0x00B2u16.to_le_bytes());
        data.extend_from_slice(&(cip.len() as u16).to_le_bytes());
        data.extend_from_slice(&cip);
        build_enip_encap(0x006F, 0x1234_5678, &data)
    }

    fn build_modbus_device_identification_request() -> Vec<u8> {
        vec![
            0x00, 0x05, // transaction id
            0x00, 0x00, // protocol id
            0x00, 0x05, // length
            0x01, // unit id
            0x2B, // function code
            0x0E, // MEI type
            0x01, // read device id code
            0x00, // object id
        ]
    }

    fn build_modbus_device_identification_response() -> Vec<u8> {
        let mut pkt = vec![
            0x00, 0x05, // transaction id
            0x00, 0x00, // protocol id
            0x00, 0x00, // length placeholder
            0x01, // unit id
            0x2B, // function code
            0x0E, // MEI type
            0x01, // read device id code
            0x01, // conformity level
            0x00, // more follows
            0x00, // next object id
            0x03, // object count
            0x00, 0x09, // vendor name
        ];
        pkt.extend_from_slice(b"Schneider");
        pkt.extend_from_slice(&[0x05, 0x07]);
        pkt.extend_from_slice(b"M580CPU");
        pkt.extend_from_slice(&[0x02, 0x04]);
        pkt.extend_from_slice(b"2.30");
        let mbap_length = (pkt.len() - 6) as u16;
        pkt[4..6].copy_from_slice(&mbap_length.to_be_bytes());
        pkt
    }

    fn build_dnp3_read_request() -> Vec<u8> {
        vec![
            0x05, 0x64, 0x08, 0xC4, 0x01, 0x00, 0x03, 0x00, 0xAA, 0xBB, 0xC0, 0xC0, 0x01, 0x01,
            0x02, 0x00, 0x06,
        ]
    }

    fn build_opc_ua_hello() -> Vec<u8> {
        let mut payload = Vec::new();
        payload.extend_from_slice(b"HEL");
        payload.push(b'F');
        payload.extend_from_slice(&32u32.to_le_bytes());
        payload.extend_from_slice(&[0x00; 24]);
        payload
    }

    fn build_s7_setup_communication() -> Vec<u8> {
        let function = 0xF0u8;
        let param_extra = [0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0xF0];
        let mut parameter = vec![function];
        parameter.extend_from_slice(&param_extra);

        let mut pkt = Vec::new();
        let tpkt_total = (4 + 1 + 2 + 10 + parameter.len()) as u16;
        pkt.push(0x03);
        pkt.push(0x00);
        pkt.extend_from_slice(&tpkt_total.to_be_bytes());
        pkt.push(2);
        pkt.push(0xF0);
        pkt.push(0x80);
        pkt.push(0x32);
        pkt.push(0x01);
        pkt.extend_from_slice(&[0x00, 0x00]);
        pkt.extend_from_slice(&[0x00, 0x01]);
        pkt.extend_from_slice(&(parameter.len() as u16).to_be_bytes());
        pkt.extend_from_slice(&0u16.to_be_bytes());
        pkt.extend_from_slice(&parameter);
        pkt
    }

    fn build_profinet_identify_request() -> Vec<u8> {
        vec![
            0xFE, 0xFE, // frame id
            0x05, // service id identify
            0x00, // request
            0x00, 0x00, 0x00, 0x01, // xid
            0x00, 0x80, // response delay
            0x00, 0x04, // data length
            0x01, 0x02, 0x03, 0x04, // block payload
        ]
    }

    fn build_bacnet_i_am() -> Vec<u8> {
        vec![
            0x81, 0x0B, 0x00, 0x13, 0x01, 0x00, 0x10, 0x00, 0xC4, 0x02, 0x00, 0x00, 0x6F, 0x21,
            0x32, 0x91, 0x03, 0x21, 0x2A,
        ]
    }

    fn build_bacnet_l2_who_is() -> Vec<u8> {
        vec![0x01, 0x00, 0x10, 0x08]
    }

    fn build_iec104_interrogation_request() -> Vec<u8> {
        vec![
            0x68, 0x0E, 0x00, 0x00, 0x00, 0x00, 0x64, 0x01, 0x06, 0x00, 0x0A, 0x00, 0x00, 0x00,
            0x00, 0x14,
        ]
    }

    #[test]
    fn processes_vlan_modbus_request_and_response() {
        let mut engine = DpiEngine::new();
        let request = [
            0x00, 0x01, 0x00, 0x00, 0x00, 0x06, 0x01, 0x03, 0x00, 0x64, 0x00, 0x02,
        ];
        let response = [
            0x00, 0x01, 0x00, 0x00, 0x00, 0x07, 0x01, 0x03, 0x04, 0x00, 0x0A, 0x00, 0x14,
        ];
        let mut pcapng = build_pcapng(&ethernet_ipv4_tcp(
            [0x02, 0x00, 0x00, 0x00, 0x00, 0x02],
            [0x02, 0x00, 0x00, 0x00, 0x00, 0x01],
            [10, 0, 0, 1],
            [10, 0, 0, 2],
            49152,
            502,
            &request,
            Some(100),
        ));
        pcapng.extend_from_slice(&build_epb(
            &ethernet_ipv4_tcp(
                [0x02, 0x00, 0x00, 0x00, 0x00, 0x01],
                [0x02, 0x00, 0x00, 0x00, 0x00, 0x02],
                [10, 0, 0, 2],
                [10, 0, 0, 1],
                502,
                49152,
                &response,
                Some(100),
            ),
            1_700_000_000_100_000,
        ));

        let output = engine
            .process_segment_to_vec(&SegmentMeta::new("capture-1"), std::io::Cursor::new(pcapng))
            .unwrap();

        assert!(
            output.events.iter().any(|event| matches!(
                &event.family,
                BronzeEventFamily::ProtocolTransaction(tx)
                    if tx.operation == "read_holding_registers" && tx.status == "ok"
            )),
            "expected paired modbus transaction"
        );
        assert!(
            output
                .events
                .iter()
                .any(|event| event.envelope.vlan_id == Some(100)),
            "expected vlan id to survive into bronze"
        );
    }

    #[test]
    fn processes_classic_pcap_modbus_request() {
        let mut engine = DpiEngine::new();
        let request = [
            0x00, 0x01, 0x00, 0x00, 0x00, 0x06, 0x01, 0x03, 0x00, 0x64, 0x00, 0x02,
        ];
        let pcap = build_pcap(&ethernet_ipv4_tcp(
            [0x02, 0x00, 0x00, 0x00, 0x00, 0x02],
            [0x02, 0x00, 0x00, 0x00, 0x00, 0x01],
            [10, 0, 0, 1],
            [10, 0, 0, 2],
            49152,
            502,
            &request,
            None,
        ));

        let output = engine
            .process_capture_to_vec(
                &SegmentMeta::new("capture-pcap"),
                std::io::Cursor::new(pcap),
            )
            .unwrap();

        assert!(
            output.events.iter().any(|event| matches!(
                &event.family,
                BronzeEventFamily::ProtocolTransaction(tx)
                    if tx.operation == "read_holding_registers"
                        && tx.status == "partial_request"
            )),
            "expected modbus transaction from classic pcap"
        );
        assert_eq!(output.checkpoint.frames_processed, 1);
    }

    #[test]
    fn processes_qinq_arp_request() {
        let mut engine = DpiEngine::new();
        let pcapng = build_pcapng(&ethernet_arp_with_vlans(
            [0xCA, 0x03, 0x0D, 0xB4, 0x00, 0x1C],
            [0xFF; 6],
            [192, 168, 2, 200],
            [192, 168, 2, 254],
            &[100, 200],
        ));

        let output = engine
            .process_segment_to_vec(
                &SegmentMeta::new("capture-qinq-arp"),
                std::io::Cursor::new(pcapng),
            )
            .unwrap();

        assert!(
            output.events.iter().any(|event| matches!(
                &event.family,
                BronzeEventFamily::AssetObservation(obs)
                    if event.protocol() == Some("arp")
                        && obs.identifiers.get("ip").map(String::as_str)
                            == Some("192.168.2.200")
            )),
            "expected arp asset observation from qinq frame"
        );
        assert!(
            output.events.iter().any(|event| matches!(
                &event.family,
                BronzeEventFamily::TopologyObservation(obs)
                    if event.protocol() == Some("arp")
                        && obs.observation_type == "arp_request"
            )),
            "expected arp topology observation from qinq frame"
        );
        assert!(
            output
                .events
                .iter()
                .any(|event| event.envelope.vlan_id == Some(100)),
            "expected outer vlan id to survive into bronze"
        );
    }

    #[test]
    fn emits_dns_asset_observation() {
        let mut engine = DpiEngine::new();
        let dns_response = vec![
            0xAB, 0xCD, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x07, b'e',
            b'x', b'a', b'm', b'p', b'l', b'e', 0x03, b'c', b'o', b'm', 0x00, 0x00, 0x01, 0x00,
            0x01, 0xC0, 0x0C, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x3C, 0x00, 0x04, 93, 184,
            216, 34,
        ];
        let pcapng = build_pcapng(&ethernet_ipv4_udp(53, 53000, &dns_response));

        let output = engine
            .process_segment_to_vec(&SegmentMeta::new("capture-2"), std::io::Cursor::new(pcapng))
            .unwrap();

        assert!(
            output.events.iter().any(|event| matches!(
                &event.family,
                BronzeEventFamily::AssetObservation(obs)
                    if obs.hostnames.iter().any(|host| host == "example.com")
            )),
            "expected dns-derived asset observation"
        );
    }

    #[test]
    fn emits_dns_from_prefixed_ipv4_namespace_capture() {
        let mut engine = DpiEngine::new();
        let dns_response = vec![
            0xAB, 0xCD, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x07, b'e',
            b'x', b'a', b'm', b'p', b'l', b'e', 0x03, b'c', b'o', b'm', 0x00, 0x00, 0x01, 0x00,
            0x01, 0xC0, 0x0C, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x3C, 0x00, 0x04, 93, 184,
            216, 34,
        ];
        let pcapng = build_pcapng(&prefixed_ipv4_udp(53, 53000, &dns_response));

        let output = engine
            .process_segment_to_vec(
                &SegmentMeta::new("capture-prefixed-ipv4"),
                std::io::Cursor::new(pcapng),
            )
            .unwrap();

        assert!(
            output.events.iter().any(|event| matches!(
                &event.family,
                BronzeEventFamily::ProtocolTransaction(tx)
                    if event.protocol() == Some("dns") && tx.status == "response"
            )),
            "expected dns transaction from prefixed namespace packet"
        );
        assert!(
            output
                .events
                .iter()
                .any(|event| event.envelope.src_ip.as_deref() == Some("10.0.0.1")
                    && event.envelope.dst_ip.as_deref() == Some("10.0.0.2")),
            "expected IP envelope to survive prefixed namespace packet"
        );
    }

    #[test]
    fn emits_dns_from_six_byte_prefixed_namespace_capture() {
        let mut engine = DpiEngine::new();
        let dns_response = vec![
            0xAB, 0xCD, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x07, b'e',
            b'x', b'a', b'm', b'p', b'l', b'e', 0x03, b'c', b'o', b'm', 0x00, 0x00, 0x01, 0x00,
            0x01, 0xC0, 0x0C, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x3C, 0x00, 0x04, 93, 184,
            216, 34,
        ];
        let pcapng = build_pcapng(&six_byte_prefixed_ipv4_udp(53, 53000, &dns_response));

        let output = engine
            .process_segment_to_vec(
                &SegmentMeta::new("capture-prefixed-ipv4-6"),
                std::io::Cursor::new(pcapng),
            )
            .unwrap();

        assert!(
            output.events.iter().any(|event| matches!(
                &event.family,
                BronzeEventFamily::ProtocolTransaction(tx)
                    if event.protocol() == Some("dns") && tx.status == "response"
            )),
            "expected dns transaction from six-byte prefixed namespace packet"
        );
    }

    #[test]
    fn emits_dns_from_8023_nested_prefixed_namespace_capture() {
        let mut engine = DpiEngine::new();
        let dns_response = vec![
            0xAB, 0xCD, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x07, b'e',
            b'x', b'a', b'm', b'p', b'l', b'e', 0x03, b'c', b'o', b'm', 0x00, 0x00, 0x01, 0x00,
            0x01, 0xC0, 0x0C, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x3C, 0x00, 0x04, 93, 184,
            216, 34,
        ];
        let pcapng = build_pcapng(&ethernet_with_prefixed_ipv4_udp(53, 53000, &dns_response));

        let output = engine
            .process_segment_to_vec(
                &SegmentMeta::new("capture-prefixed-ipv4-8023"),
                std::io::Cursor::new(pcapng),
            )
            .unwrap();

        assert!(
            output.events.iter().any(|event| matches!(
                &event.family,
                BronzeEventFamily::ProtocolTransaction(tx)
                    if event.protocol() == Some("dns") && tx.status == "response"
            )),
            "expected dns transaction from 802.3 nested namespace packet"
        );
    }

    #[test]
    fn emits_dhcp_transaction_and_asset_observation() {
        let mut engine = DpiEngine::new();
        let pcapng = build_pcapng(&ethernet_ipv4_udp(68, 67, &build_dhcp_discover()));

        let output = engine
            .process_segment_to_vec(
                &SegmentMeta::new("capture-dhcp"),
                std::io::Cursor::new(pcapng),
            )
            .unwrap();

        assert!(
            output.events.iter().any(|event| matches!(
                &event.family,
                BronzeEventFamily::ProtocolTransaction(tx)
                    if event.protocol() == Some("dhcp")
                        && tx.operation == "discover"
                        && tx.status == "request"
            )),
            "expected dhcp transaction"
        );
        assert!(
            output.events.iter().any(|event| matches!(
                &event.family,
                BronzeEventFamily::AssetObservation(obs)
                    if event.protocol() == Some("dhcp")
                        && obs.hostnames.iter().any(|host| host == "plc-01")
            )),
            "expected dhcp-derived asset observation"
        );
    }

    #[test]
    fn emits_snmp_transaction_and_asset_observation() {
        let mut engine = DpiEngine::new();
        let pcapng = build_pcapng(&ethernet_ipv4_udp(161, 40000, &build_snmp_get_response()));

        let output = engine
            .process_segment_to_vec(
                &SegmentMeta::new("capture-snmp"),
                std::io::Cursor::new(pcapng),
            )
            .unwrap();

        assert!(
            output.events.iter().any(|event| matches!(
                &event.family,
                BronzeEventFamily::ProtocolTransaction(tx)
                    if event.protocol() == Some("snmp")
                        && tx.operation == "get_response"
                        && tx.status == "response"
            )),
            "expected snmp transaction"
        );
        assert!(
            output.events.iter().any(|event| matches!(
                &event.family,
                BronzeEventFamily::AssetObservation(obs)
                    if event.protocol() == Some("snmp")
                        && obs.hostnames.iter().any(|host| host == "switch-01")
            )),
            "expected snmp-derived asset observation"
        );
    }

    #[test]
    fn emits_cdp_topology_and_asset_observation() {
        let mut engine = DpiEngine::new();
        let pcapng = build_pcapng(&ethernet_llc_snap(
            [0x01, 0x00, 0x0C, 0xCC, 0xCC, 0xCC],
            [0x00, 0x25, 0x90, 0xAA, 0xBB, 0xCC],
            [0x00, 0x00, 0x0C],
            0x2000,
            &build_cdp_payload(),
        ));

        let output = engine
            .process_segment_to_vec(
                &SegmentMeta::new("capture-cdp"),
                std::io::Cursor::new(pcapng),
            )
            .unwrap();

        assert!(
            output.events.iter().any(|event| matches!(
                &event.family,
                BronzeEventFamily::TopologyObservation(obs)
                    if event.protocol() == Some("cdp")
                        && obs.observation_type == "cdp_neighbor"
            )),
            "expected cdp topology observation"
        );
        assert!(
            output.events.iter().any(|event| matches!(
                &event.family,
                BronzeEventFamily::AssetObservation(obs)
                    if event.protocol() == Some("cdp")
                        && obs.hostnames.iter().any(|host| host == "dist-sw-01")
            )),
            "expected cdp asset observation"
        );
    }

    #[test]
    fn emits_stp_topology_and_asset_observation() {
        let mut engine = DpiEngine::new();
        let pcapng = build_pcapng(&ethernet_llc(
            [0x01, 0x80, 0xC2, 0x00, 0x00, 0x00],
            [0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB],
            0x42,
            0x42,
            0x03,
            &build_stp_bpdu(),
        ));

        let output = engine
            .process_segment_to_vec(
                &SegmentMeta::new("capture-stp"),
                std::io::Cursor::new(pcapng),
            )
            .unwrap();

        assert!(
            output.events.iter().any(|event| matches!(
                &event.family,
                BronzeEventFamily::TopologyObservation(obs)
                    if event.protocol() == Some("stp")
                        && obs.observation_type == "stp_topology"
            )),
            "expected stp topology observation"
        );
        assert!(
            output.events.iter().any(|event| matches!(
                &event.family,
                BronzeEventFamily::AssetObservation(obs)
                    if event.protocol() == Some("stp")
                        && obs.identifiers.contains_key("bridge_id")
            )),
            "expected stp asset observation"
        );
    }

    #[test]
    fn emits_bacnet_ip_transaction_and_asset_observation() {
        let mut engine = DpiEngine::new();
        let pcapng = build_pcapng(&ethernet_ipv4_udp(47808, 47808, &build_bacnet_i_am()));

        let output = engine
            .process_segment_to_vec(
                &SegmentMeta::new("capture-bacnet-ip"),
                std::io::Cursor::new(pcapng),
            )
            .unwrap();

        assert!(
            output.events.iter().any(|event| matches!(
                &event.family,
                BronzeEventFamily::ProtocolTransaction(tx)
                    if event.protocol() == Some("bacnet")
                        && tx.operation == "i_am"
                        && tx.status == "request"
            )),
            "expected bacnet transaction"
        );
        assert!(
            output.events.iter().any(|event| matches!(
                &event.family,
                BronzeEventFamily::AssetObservation(obs)
                    if event.protocol() == Some("bacnet")
                        && obs.identifiers.get("bacnet_device_instance").map(String::as_str)
                            == Some("111")
            )),
            "expected bacnet asset observation"
        );
    }

    #[test]
    fn emits_bacnet_llc_transaction() {
        let mut engine = DpiEngine::new();
        let pcapng = build_pcapng(&ethernet_llc(
            [0x01, 0x80, 0xC2, 0x00, 0x00, 0x00],
            [0x00, 0x60, 0x2D, 0x00, 0x15, 0xD5],
            0x82,
            0x82,
            0x03,
            &build_bacnet_l2_who_is(),
        ));

        let output = engine
            .process_segment_to_vec(
                &SegmentMeta::new("capture-bacnet-llc"),
                std::io::Cursor::new(pcapng),
            )
            .unwrap();

        assert!(
            output.events.iter().any(|event| matches!(
                &event.family,
                BronzeEventFamily::ProtocolTransaction(tx)
                    if event.protocol() == Some("bacnet")
                        && tx.operation == "who_is"
            )),
            "expected bacnet llc transaction"
        );
    }

    #[test]
    fn emits_enip_list_identity_asset_observation() {
        let mut engine = DpiEngine::new();
        let pcapng = build_pcapng(&ethernet_ipv4_tcp(
            [0x02, 0x00, 0x00, 0x00, 0x00, 0x01],
            [0x02, 0x00, 0x00, 0x00, 0x00, 0x02],
            [10, 0, 0, 2],
            [10, 0, 0, 1],
            44818,
            49000,
            &build_enip_list_identity_response(),
            None,
        ));

        let output = engine
            .process_segment_to_vec(
                &SegmentMeta::new("capture-enip-list-identity"),
                std::io::Cursor::new(pcapng),
            )
            .unwrap();

        assert!(
            output.events.iter().any(|event| matches!(
                &event.family,
                BronzeEventFamily::AssetObservation(obs)
                    if event.protocol() == Some("ethernet_ip")
                        && obs.vendor.as_deref() == Some("Rockwell Automation/Allen-Bradley")
                        && obs.model.as_deref() == Some("1756-L85E")
                        && obs.firmware.as_deref() == Some("20.11")
                        && obs.protocols.iter().any(|p| p == "cip")
            )),
            "expected list identity asset observation"
        );
    }

    #[test]
    fn emits_modbus_device_identification_asset_observation() {
        let mut engine = DpiEngine::new();
        let mut pcapng = build_pcapng(&ethernet_ipv4_tcp(
            [0x02, 0x00, 0x00, 0x00, 0x00, 0x02],
            [0x02, 0x00, 0x00, 0x00, 0x00, 0x01],
            [10, 0, 0, 1],
            [10, 0, 0, 2],
            49152,
            502,
            &build_modbus_device_identification_request(),
            None,
        ));
        pcapng.extend_from_slice(&build_epb(
            &ethernet_ipv4_tcp(
                [0x02, 0x00, 0x00, 0x00, 0x00, 0x01],
                [0x02, 0x00, 0x00, 0x00, 0x00, 0x02],
                [10, 0, 0, 2],
                [10, 0, 0, 1],
                502,
                49152,
                &build_modbus_device_identification_response(),
                None,
            ),
            1_700_000_000_100_000,
        ));

        let output = engine
            .process_segment_to_vec(
                &SegmentMeta::new("capture-modbus-device-id"),
                std::io::Cursor::new(pcapng),
            )
            .unwrap();

        assert!(
            output.events.iter().any(|event| matches!(
                &event.family,
                BronzeEventFamily::AssetObservation(obs)
                    if event.protocol() == Some("modbus")
                        && obs.vendor.as_deref() == Some("Schneider")
                        && obs.model.as_deref() == Some("M580CPU")
                        && obs.firmware.as_deref() == Some("2.30")
            )),
            "expected modbus device identification asset observation"
        );
    }

    #[test]
    fn emits_cip_identity_asset_observation_under_enip() {
        let mut engine = DpiEngine::new();
        let pcapng = build_pcapng(&ethernet_ipv4_tcp(
            [0x02, 0x00, 0x00, 0x00, 0x00, 0x01],
            [0x02, 0x00, 0x00, 0x00, 0x00, 0x02],
            [10, 0, 0, 2],
            [10, 0, 0, 1],
            44818,
            49001,
            &build_enip_send_rr_data_identity_response(),
            None,
        ));

        let output = engine
            .process_segment_to_vec(
                &SegmentMeta::new("capture-enip-cip-identity"),
                std::io::Cursor::new(pcapng),
            )
            .unwrap();

        assert!(
            output.events.iter().any(|event| matches!(
                &event.family,
                BronzeEventFamily::ProtocolTransaction(tx)
                    if event.protocol() == Some("ethernet_ip")
                        && tx.operation == "send_rr_data"
                        && tx.object_refs.iter().any(|r| r == "cip_object:identity")
            )),
            "expected enip transaction with cip identity object ref"
        );
        assert!(
            output.events.iter().any(|event| matches!(
                &event.family,
                BronzeEventFamily::AssetObservation(obs)
                    if event.protocol() == Some("ethernet_ip")
                        && obs.model.as_deref() == Some("1734-AENTR")
                        && obs.firmware.as_deref() == Some("5.12")
                        && obs.identifiers.get("cip_serial_number").map(String::as_str)
                            == Some("1432778632")
            )),
            "expected cip identity asset observation"
        );
    }

    #[test]
    fn emits_dnp3_role_asset_observations() {
        let mut engine = DpiEngine::new();
        let pcapng = build_pcapng(&ethernet_ipv4_tcp(
            [0x02, 0x00, 0x00, 0x00, 0x00, 0x02],
            [0x02, 0x00, 0x00, 0x00, 0x00, 0x01],
            [10, 0, 0, 1],
            [10, 0, 0, 2],
            49152,
            20000,
            &build_dnp3_read_request(),
            None,
        ));

        let output = engine
            .process_segment_to_vec(
                &SegmentMeta::new("capture-dnp3-role"),
                std::io::Cursor::new(pcapng),
            )
            .unwrap();

        assert!(
            output.events.iter().any(|event| matches!(
                &event.family,
                BronzeEventFamily::AssetObservation(obs)
                    if event.protocol() == Some("dnp3")
                        && obs.asset_key == "10.0.0.1"
                        && obs.role.as_deref() == Some("master")
            )),
            "expected dnp3 master observation"
        );
        assert!(
            output.events.iter().any(|event| matches!(
                &event.family,
                BronzeEventFamily::AssetObservation(obs)
                    if event.protocol() == Some("dnp3")
                        && obs.asset_key == "10.0.0.2"
                        && obs.role.as_deref() == Some("outstation")
            )),
            "expected dnp3 outstation observation"
        );
    }

    #[test]
    fn emits_iec104_transaction_and_role_observations() {
        let mut engine = DpiEngine::new();
        let pcapng = build_pcapng(&ethernet_ipv4_tcp(
            [0x02, 0x00, 0x00, 0x00, 0x00, 0x02],
            [0x02, 0x00, 0x00, 0x00, 0x00, 0x01],
            [10, 20, 102, 1],
            [10, 20, 100, 108],
            46413,
            2404,
            &build_iec104_interrogation_request(),
            None,
        ));

        let output = engine
            .process_segment_to_vec(
                &SegmentMeta::new("capture-iec104"),
                std::io::Cursor::new(pcapng),
            )
            .unwrap();

        assert!(
            output.events.iter().any(|event| matches!(
                &event.family,
                BronzeEventFamily::ProtocolTransaction(tx)
                    if event.protocol() == Some("iec104")
                        && tx.operation == "interrogation_command"
                        && tx.status == "request"
            )),
            "expected iec104 transaction"
        );
        assert!(
            output.events.iter().any(|event| matches!(
                &event.family,
                BronzeEventFamily::AssetObservation(obs)
                    if event.protocol() == Some("iec104")
                        && obs.asset_key == "10.20.102.1"
                        && obs.role.as_deref() == Some("master")
            )),
            "expected iec104 master observation"
        );
        assert!(
            output.events.iter().any(|event| matches!(
                &event.family,
                BronzeEventFamily::AssetObservation(obs)
                    if event.protocol() == Some("iec104")
                        && obs.asset_key == "10.20.100.108"
                        && obs.identifiers.get("iec104_common_address").map(String::as_str)
                            == Some("10")
            )),
            "expected iec104 outstation observation"
        );
    }

    #[test]
    fn emits_opc_ua_transaction() {
        let mut engine = DpiEngine::new();
        let pcapng = build_pcapng(&ethernet_ipv4_tcp(
            [0x02, 0x00, 0x00, 0x00, 0x00, 0x02],
            [0x02, 0x00, 0x00, 0x00, 0x00, 0x01],
            [10, 0, 0, 1],
            [10, 0, 0, 2],
            49500,
            4840,
            &build_opc_ua_hello(),
            None,
        ));

        let output = engine
            .process_segment_to_vec(
                &SegmentMeta::new("capture-opcua"),
                std::io::Cursor::new(pcapng),
            )
            .unwrap();

        assert!(
            output.events.iter().any(|event| matches!(
                &event.family,
                BronzeEventFamily::ProtocolTransaction(tx)
                    if event.protocol() == Some("opc_ua")
                        && tx.operation == "hello"
                        && tx.status == "request"
            )),
            "expected opc ua transaction"
        );
    }

    #[test]
    fn emits_opc_ua_transaction_on_alternate_port() {
        let mut engine = DpiEngine::new();
        let pcapng = build_pcapng(&ethernet_ipv4_tcp(
            [0x02, 0x00, 0x00, 0x00, 0x00, 0x02],
            [0x02, 0x00, 0x00, 0x00, 0x00, 0x01],
            [10, 0, 0, 1],
            [10, 0, 0, 2],
            49500,
            12001,
            &build_opc_ua_hello(),
            None,
        ));

        let output = engine
            .process_segment_to_vec(
                &SegmentMeta::new("capture-opcua-alt-port"),
                std::io::Cursor::new(pcapng),
            )
            .unwrap();

        assert!(
            output.events.iter().any(|event| matches!(
                &event.family,
                BronzeEventFamily::ProtocolTransaction(tx)
                    if event.protocol() == Some("opc_ua")
                        && tx.operation == "hello"
                        && tx.status == "request"
            )),
            "expected opc ua transaction on alternate server port"
        );
    }

    #[test]
    fn emits_s7comm_transaction() {
        let mut engine = DpiEngine::new();
        let pcapng = build_pcapng(&ethernet_ipv4_tcp(
            [0x02, 0x00, 0x00, 0x00, 0x00, 0x02],
            [0x02, 0x00, 0x00, 0x00, 0x00, 0x01],
            [10, 0, 0, 1],
            [10, 0, 0, 2],
            49300,
            102,
            &build_s7_setup_communication(),
            None,
        ));

        let output = engine
            .process_segment_to_vec(
                &SegmentMeta::new("capture-s7"),
                std::io::Cursor::new(pcapng),
            )
            .unwrap();

        assert!(
            output.events.iter().any(|event| matches!(
                &event.family,
                BronzeEventFamily::ProtocolTransaction(tx)
                    if event.protocol() == Some("s7comm")
                        && tx.operation == "setup_communication"
                        && tx.status == "request"
            )),
            "expected s7comm transaction"
        );
    }

    #[test]
    fn emits_profinet_transaction_and_artifact() {
        let mut engine = DpiEngine::new();
        let pcapng = build_pcapng(&ethernet_ipv4_udp(
            40000,
            34964,
            &build_profinet_identify_request(),
        ));

        let output = engine
            .process_segment_to_vec(
                &SegmentMeta::new("capture-profinet"),
                std::io::Cursor::new(pcapng),
            )
            .unwrap();

        assert!(
            output.events.iter().any(|event| matches!(
                &event.family,
                BronzeEventFamily::ProtocolTransaction(tx)
                    if event.protocol() == Some("profinet")
                        && tx.operation == "dcp_identify_request"
                        && tx.status == "request"
            )),
            "expected profinet transaction"
        );
        assert!(
            output.events.iter().any(|event| matches!(
                &event.family,
                BronzeEventFamily::ExtractedArtifact(artifact)
                    if artifact.artifact_type == "profinet_payload"
            )),
            "expected profinet artifact"
        );
    }

    #[test]
    fn emits_profinet_ethertype_transaction_and_artifact() {
        let mut engine = DpiEngine::new();
        let pcapng = build_pcapng(&ethernet_ethertype(
            [0x08, 0x00, 0x06, 0x93, 0xCF, 0x32],
            [0x00, 0x0C, 0x29, 0xBA, 0x09, 0xEA],
            0x8892,
            &build_profinet_identify_request(),
        ));

        let output = engine
            .process_segment_to_vec(
                &SegmentMeta::new("capture-profinet-ethertype"),
                std::io::Cursor::new(pcapng),
            )
            .unwrap();

        assert!(
            output.events.iter().any(|event| matches!(
                &event.family,
                BronzeEventFamily::ProtocolTransaction(tx)
                    if event.protocol() == Some("profinet")
                        && event.envelope.transport == TransportProtocol::Ethernet
                        && tx.operation == "dcp_identify_request"
                        && tx.status == "request"
            )),
            "expected profinet transaction from raw ethertype frame"
        );
        assert!(
            output.events.iter().any(|event| matches!(
                &event.family,
                BronzeEventFamily::ExtractedArtifact(artifact)
                    if artifact.artifact_type == "profinet_payload"
            )),
            "expected profinet artifact from raw ethertype frame"
        );
    }

    // ── ICMP integration tests ────────────────────────────────

    fn ethernet_ipv4_icmp(icmp_payload: &[u8]) -> Vec<u8> {
        let mut frame = Vec::new();
        // Ethernet header
        frame.extend_from_slice(&[0x02, 0x00, 0x00, 0x00, 0x00, 0x01]); // dst mac
        frame.extend_from_slice(&[0x02, 0x00, 0x00, 0x00, 0x00, 0x02]); // src mac
        frame.extend_from_slice(&0x0800u16.to_be_bytes()); // ethertype IPv4
        // IPv4 header (20 bytes)
        let total_len = 20 + icmp_payload.len();
        frame.extend_from_slice(&[
            0x45,                                    // version + IHL
            0x00,                                    // DSCP
            ((total_len >> 8) & 0xFF) as u8,         // total length hi
            (total_len & 0xFF) as u8,                // total length lo
            0x00, 0x01,                              // identification
            0x00, 0x00,                              // flags + fragment offset
            64,                                      // TTL
            1,                                       // protocol = ICMP
            0, 0,                                    // header checksum (skip)
            10, 0, 0, 1,                             // src IP
            10, 0, 0, 2,                             // dst IP
        ]);
        frame.extend_from_slice(icmp_payload);
        frame
    }

    #[test]
    fn icmp_echo_request_produces_transaction() {
        let icmp = vec![8, 0, 0x00, 0x00, 0, 1, 0, 1, 0xAA, 0xBB, 0xCC, 0xDD];
        let frame = ethernet_ipv4_icmp(&icmp);
        let pcapng = build_pcapng(&frame);
        let mut engine = DpiEngine::new();
        let output = engine
            .process_segment_to_vec(&SegmentMeta::new("test"), std::io::Cursor::new(pcapng))
            .unwrap();
        assert!(
            output.events.iter().any(|event| matches!(
                &event.family,
                BronzeEventFamily::ProtocolTransaction(tx)
                    if tx.operation == "Echo Request"
            )),
            "expected ICMP Echo Request transaction"
        );
        assert!(
            output.events.iter().any(|event| event.protocol() == Some("icmp")),
            "expected protocol=icmp"
        );
    }

    #[test]
    fn icmp_redirect_produces_stovetop_finding() {
        // ICMP Redirect: type 5, code 1, gateway 10.0.0.99
        let icmp = vec![5, 1, 0, 0, 10, 0, 0, 99, 0x45, 0x00, 0x00, 0x28];
        let frame = ethernet_ipv4_icmp(&icmp);
        let pcapng = build_pcapng(&frame);
        let mut engine = DpiEngine::new();
        let output = engine
            .process_segment_to_vec(&SegmentMeta::new("test"), std::io::Cursor::new(pcapng))
            .unwrap();
        // Should have both a protocol transaction AND a stovetop anomaly
        assert!(
            output.events.iter().any(|event| matches!(
                &event.family,
                BronzeEventFamily::ProtocolTransaction(tx)
                    if tx.operation == "Redirect"
            )),
            "expected ICMP Redirect transaction"
        );
        assert!(
            output.events.iter().any(|event| matches!(
                &event.family,
                BronzeEventFamily::ParseAnomaly(anomaly)
                    if anomaly.decoder == "icmpeeker:redirect"
            )),
            "expected stovetop ICMP redirect anomaly"
        );
    }

    #[test]
    fn icmp_dest_unreachable_produces_transaction() {
        let icmp = vec![3, 3, 0, 0, 0, 0, 0, 0]; // port unreachable
        let frame = ethernet_ipv4_icmp(&icmp);
        let pcapng = build_pcapng(&frame);
        let mut engine = DpiEngine::new();
        let output = engine
            .process_segment_to_vec(&SegmentMeta::new("test"), std::io::Cursor::new(pcapng))
            .unwrap();
        assert!(
            output.events.iter().any(|event| matches!(
                &event.family,
                BronzeEventFamily::ProtocolTransaction(tx)
                    if tx.operation == "Destination Unreachable"
                    && tx.status == "Port Unreachable"
            )),
            "expected ICMP Destination Unreachable / Port Unreachable"
        );
    }

    #[test]
    fn icmp_router_advertisement_flags_suspicious() {
        let icmp = vec![9, 0, 0, 0, 1, 2, 0, 30]; // router advertisement
        let frame = ethernet_ipv4_icmp(&icmp);
        let pcapng = build_pcapng(&frame);
        let mut engine = DpiEngine::new();
        let output = engine
            .process_segment_to_vec(&SegmentMeta::new("test"), std::io::Cursor::new(pcapng))
            .unwrap();
        assert!(
            output.events.iter().any(|event| matches!(
                &event.family,
                BronzeEventFamily::ParseAnomaly(anomaly)
                    if anomaly.decoder == "icmpeeker:suspicious"
            )),
            "expected stovetop suspicious ICMP type anomaly"
        );
    }

    // ── Stovetop frame-level integration tests ────────────────

    #[test]
    fn stovetop_runt_frame_detected() {
        // Build a tiny frame (30 bytes, well below 60 minimum)
        let mut frame = vec![0u8; 30];
        // Valid enough ethernet header
        frame[12] = 0x08;
        frame[13] = 0x00; // ethertype IPv4
        frame[14] = 0x45; // IP version+IHL
        frame[16] = 0x00;
        frame[17] = 16; // tiny IP total_length

        let pcapng = build_pcapng(&frame);
        let mut engine = DpiEngine::new();
        let output = engine
            .process_segment_to_vec(&SegmentMeta::new("test"), std::io::Cursor::new(pcapng))
            .unwrap();
        assert!(
            output.events.iter().any(|event| matches!(
                &event.family,
                BronzeEventFamily::ParseAnomaly(anomaly)
                    if anomaly.decoder == "stovetop:runt"
            )),
            "expected stovetop runt frame anomaly"
        );
    }

    // ── Bilgepump integration tests ───────────────────────────

    fn ethernet_arp_reply(
        src_mac: [u8; 6],
        sender_mac: [u8; 6],
        sender_ip: [u8; 4],
    ) -> Vec<u8> {
        let mut frame = Vec::new();
        frame.extend_from_slice(&[0xFF; 6]); // dst mac (broadcast)
        frame.extend_from_slice(&src_mac);
        frame.extend_from_slice(&0x0806u16.to_be_bytes());
        frame.extend_from_slice(&[
            0x00, 0x01, // hardware type: Ethernet
            0x08, 0x00, // protocol type: IPv4
            0x06,       // hardware size
            0x04,       // protocol size
            0x00, 0x02, // operation: reply
        ]);
        frame.extend_from_slice(&sender_mac);
        frame.extend_from_slice(&sender_ip);
        frame.extend_from_slice(&[0x00; 6]); // target mac
        frame.extend_from_slice(&[0x00; 4]); // target ip
        frame
    }

    #[test]
    fn bilgepump_arp_spoof_detected() {
        // Two ARP replies for the same IP from different MACs
        let mac_a = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55];
        let mac_b = [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF];
        let ip = [10, 0, 0, 1];

        let frame_a = ethernet_arp_reply(mac_a, mac_a, ip);
        let frame_b = ethernet_arp_reply(mac_b, mac_b, ip);

        // Build pcapng with both frames
        let mut data = Vec::new();
        // SHB
        data.extend_from_slice(&0x0A0D0D0Au32.to_le_bytes());
        data.extend_from_slice(&28u32.to_le_bytes());
        data.extend_from_slice(&0x1A2B3C4Du32.to_le_bytes());
        data.extend_from_slice(&1u16.to_le_bytes());
        data.extend_from_slice(&0u16.to_le_bytes());
        data.extend_from_slice(&0xFFFF_FFFF_FFFF_FFFFu64.to_le_bytes());
        data.extend_from_slice(&28u32.to_le_bytes());
        // Frame A
        data.extend_from_slice(&build_epb(&frame_a, 1_000_000));
        // Frame B (1 second later)
        data.extend_from_slice(&build_epb(&frame_b, 2_000_000));

        let mut engine = DpiEngine::new();
        let output = engine
            .process_segment_to_vec(&SegmentMeta::new("test"), std::io::Cursor::new(data))
            .unwrap();

        assert!(
            output.events.iter().any(|event| matches!(
                &event.family,
                BronzeEventFamily::ParseAnomaly(anomaly)
                    if anomaly.decoder == "bilgepump:arp_spoof"
            )),
            "expected bilgepump ARP spoof alert"
        );
    }

    #[test]
    fn bilgepump_vlan_hopping_detected() {
        let mut frame = Vec::new();
        // Ethernet header
        frame.extend_from_slice(&[0xFF; 6]); // dst mac
        frame.extend_from_slice(&[0x00, 0x11, 0x22, 0x33, 0x44, 0x55]); // src mac
        // Outer 802.1Q: VLAN 100
        frame.extend_from_slice(&0x8100u16.to_be_bytes());
        frame.extend_from_slice(&100u16.to_be_bytes());
        // Inner 802.1Q: VLAN 200
        frame.extend_from_slice(&0x8100u16.to_be_bytes());
        frame.extend_from_slice(&200u16.to_be_bytes());
        // Ethertype IPv4
        frame.extend_from_slice(&0x0800u16.to_be_bytes());
        // Minimal IPv4 header
        let total_len = 20u16;
        frame.extend_from_slice(&[
            0x45, 0x00,
            (total_len >> 8) as u8, (total_len & 0xFF) as u8,
            0x00, 0x01, 0x00, 0x00, 64, 6, 0, 0,
            10, 0, 0, 1,  // src
            10, 0, 0, 2,  // dst
        ]);

        let pcapng = build_pcapng(&frame);
        let mut engine = DpiEngine::new();
        let output = engine
            .process_segment_to_vec(&SegmentMeta::new("test"), std::io::Cursor::new(pcapng))
            .unwrap();

        assert!(
            output.events.iter().any(|event| matches!(
                &event.family,
                BronzeEventFamily::ParseAnomaly(anomaly)
                    if anomaly.decoder == "bilgepump:vlan_hop"
            )),
            "expected bilgepump VLAN hopping alert"
        );
    }

    #[test]
    fn mqtt_decoder_dispatches_sparkplug_publish_to_payload_decoder() {
        use crate::sparkplug::proto::payload::{metric, Metric as PbMetric};
        use crate::sparkplug::proto::{DataType, Payload as PbPayload};
        use prost::Message as _;
        use std::net::{IpAddr, Ipv4Addr};

        // Build a Sparkplug NBIRTH protobuf payload with one bdSeq metric and
        // one named metric.
        let pb_payload = PbPayload {
            timestamp: Some(1_700_000_000_000),
            seq: Some(0),
            metrics: vec![
                PbMetric {
                    name: Some("bdSeq".into()),
                    datatype: Some(DataType::Int64 as u32),
                    value: Some(metric::Value::LongValue(1)),
                    ..Default::default()
                },
                PbMetric {
                    name: Some("Tank1.Level".into()),
                    alias: Some(10),
                    datatype: Some(DataType::Double as u32),
                    timestamp: Some(1_700_000_000_500),
                    value: Some(metric::Value::DoubleValue(72.5)),
                    ..Default::default()
                },
            ],
            ..Default::default()
        };
        let sparkplug_bytes = pb_payload.encode_to_vec();

        // Wrap in an MQTT PUBLISH frame. QoS 0 (no packet identifier).
        let topic = b"spBv1.0/Plant1/NBIRTH/PLC-A";
        let mut variable = Vec::new();
        variable.extend_from_slice(&(topic.len() as u16).to_be_bytes());
        variable.extend_from_slice(topic);
        variable.extend_from_slice(&sparkplug_bytes);
        let mut mqtt_frame = Vec::new();
        mqtt_frame.push(0x30); // PUBLISH, QoS 0, no retain
        // Variable-length remaining length encoding for >127.
        let mut remaining = variable.len();
        loop {
            let mut byte = (remaining & 0x7F) as u8;
            remaining >>= 7;
            if remaining > 0 {
                byte |= 0x80;
            }
            mqtt_frame.push(byte);
            if remaining == 0 {
                break;
            }
        }
        mqtt_frame.extend_from_slice(&variable);

        // Drive MqttDecoder directly with a synthetic StreamChunk.
        let timestamp = chrono::DateTime::<chrono::Utc>::from_timestamp(1_700_000_000, 1_000)
            .unwrap();
        let chunk = StreamChunk {
            capture_id: "test-cap",
            segment_hash: "seg",
            interface_id: 0,
            frame_index: 1,
            timestamp,
            context: PacketContext {
                src_mac: [0x02, 0x00, 0x00, 0x00, 0x00, 0x01],
                dst_mac: [0x02, 0x00, 0x00, 0x00, 0x00, 0x02],
                src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 50)),
                dst_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
                src_port: 53212,
                dst_port: 1883,
                vlan_id: None,
                // PacketContext.timestamp is nanoseconds since epoch.
                timestamp: 1_700_000_000_000_001_000,
            },
            ethertype: 0x0800,
            ip_proto: Some(6),
            llc: None,
            transport: TransportProtocol::Tcp,
            payload: &mqtt_frame,
            session_key: "sess".into(),
            captured_len: mqtt_frame.len() as u64,
        };

        let mut decoder = decoders::it_app::MqttDecoder::default();
        let mut out = Vec::new();
        decoder.on_stream_chunk(&chunk, &mut out);

        // Expect: 1 ProtocolTransaction (PUBLISH) + 2 ProcessReadings (one per metric).
        let publish = out
            .iter()
            .find(|ev| matches!(&ev.family, BronzeEventFamily::ProtocolTransaction(tx) if tx.operation == "publish"))
            .expect("publish ProtocolTransaction");
        assert_eq!(publish.protocol(), Some("mqtt"));

        let readings: Vec<_> = out
            .iter()
            .filter_map(|ev| match &ev.family {
                BronzeEventFamily::ProcessReading(r) => Some(r),
                _ => None,
            })
            .collect();
        assert_eq!(readings.len(), 2, "expected 2 ProcessReadings, got {}", readings.len());
        // Find Tank1.Level and verify it decoded correctly.
        let tank = readings
            .iter()
            .find(|r| matches!(
                &r.point_id,
                crate::bronze::PointIdentifier::SparkplugMetric { metric_name: Some(n), .. }
                    if n == "Tank1.Level"
            ))
            .expect("Tank1.Level reading");
        assert_eq!(tank.source_protocol, "sparkplug_b");
        assert_eq!(tank.value, crate::bronze::PointValue::Double(72.5));
        // observed_ts is microseconds; chunk timestamp ns / 1000.
        assert_eq!(tank.observed_ts, 1_700_000_000_000_001);
        // source_ts is metric timestamp (ms) * 1000.
        assert_eq!(tank.source_ts, Some(1_700_000_000_500_000));
    }

    /// Wrap a Sparkplug protobuf payload in an MQTT PUBLISH frame (QoS 0,
    /// no packet identifier).
    fn mqtt_publish_frame(topic: &[u8], payload: &[u8]) -> Vec<u8> {
        let mut variable = Vec::new();
        variable.extend_from_slice(&(topic.len() as u16).to_be_bytes());
        variable.extend_from_slice(topic);
        variable.extend_from_slice(payload);
        let mut frame = Vec::new();
        frame.push(0x30); // PUBLISH, QoS 0, no retain
        let mut remaining = variable.len();
        loop {
            let mut byte = (remaining & 0x7F) as u8;
            remaining >>= 7;
            if remaining > 0 {
                byte |= 0x80;
            }
            frame.push(byte);
            if remaining == 0 {
                break;
            }
        }
        frame.extend_from_slice(&variable);
        frame
    }

    #[test]
    fn engine_end_to_end_sparkplug_birth_then_data() {
        use crate::sparkplug::proto::payload::{metric, Metric as PbMetric};
        use crate::sparkplug::proto::{DataType, Payload as PbPayload};
        use prost::Message as _;

        let nbirth = PbPayload {
            timestamp: Some(1_700_000_000_000),
            seq: Some(0),
            metrics: vec![
                PbMetric {
                    name: Some("bdSeq".into()),
                    datatype: Some(DataType::Int64 as u32),
                    value: Some(metric::Value::LongValue(1)),
                    ..Default::default()
                },
                PbMetric {
                    name: Some("Tank1.Level".into()),
                    alias: Some(10),
                    datatype: Some(DataType::Double as u32),
                    timestamp: Some(1_700_000_000_500),
                    value: Some(metric::Value::DoubleValue(50.0)),
                    ..Default::default()
                },
            ],
            ..Default::default()
        };
        let ndata = PbPayload {
            timestamp: Some(1_700_000_001_000),
            seq: Some(1),
            metrics: vec![PbMetric {
                alias: Some(10),
                datatype: Some(DataType::Double as u32),
                timestamp: Some(1_700_000_001_500),
                value: Some(metric::Value::DoubleValue(51.5)),
                ..Default::default()
            }],
            ..Default::default()
        };

        let frame_birth = ethernet_ipv4_tcp(
            [0x02, 0, 0, 0, 0, 0x01],
            [0x02, 0, 0, 0, 0, 0x02],
            [10, 0, 0, 50],
            [10, 0, 0, 1],
            53212,
            1883,
            &mqtt_publish_frame(b"spBv1.0/Plant1/NBIRTH/PLC-A", &nbirth.encode_to_vec()),
            None,
        );
        let frame_data = ethernet_ipv4_tcp(
            [0x02, 0, 0, 0, 0, 0x01],
            [0x02, 0, 0, 0, 0, 0x02],
            [10, 0, 0, 50],
            [10, 0, 0, 1],
            53212,
            1883,
            &mqtt_publish_frame(b"spBv1.0/Plant1/NDATA/PLC-A", &ndata.encode_to_vec()),
            None,
        );

        // Build a PCAPNG with both frames so they share segment + flow state.
        let mut pcapng = Vec::new();
        // SHB
        pcapng.extend_from_slice(&0x0A0D0D0Au32.to_le_bytes());
        pcapng.extend_from_slice(&28u32.to_le_bytes());
        pcapng.extend_from_slice(&0x1A2B3C4Du32.to_le_bytes());
        pcapng.extend_from_slice(&1u16.to_le_bytes());
        pcapng.extend_from_slice(&0u16.to_le_bytes());
        pcapng.extend_from_slice(&0xFFFF_FFFF_FFFF_FFFFu64.to_le_bytes());
        pcapng.extend_from_slice(&28u32.to_le_bytes());
        // IDB (Ethernet linktype)
        pcapng.extend_from_slice(&0x0000_0001u32.to_le_bytes());
        pcapng.extend_from_slice(&20u32.to_le_bytes());
        pcapng.extend_from_slice(&1u16.to_le_bytes());
        pcapng.extend_from_slice(&0u16.to_le_bytes());
        pcapng.extend_from_slice(&65535u32.to_le_bytes());
        pcapng.extend_from_slice(&20u32.to_le_bytes());
        // EPBs
        pcapng.extend_from_slice(&build_epb(&frame_birth, 1_700_000_000_000_001));
        pcapng.extend_from_slice(&build_epb(&frame_data, 1_700_000_001_000_001));

        let mut engine = DpiEngine::new();
        let output = engine
            .process_segment_to_vec(&SegmentMeta::new("sparkplug-corpus"), std::io::Cursor::new(pcapng))
            .expect("process");

        let readings: Vec<_> = output
            .events
            .iter()
            .filter_map(|ev| match &ev.family {
                BronzeEventFamily::ProcessReading(r) => Some(r),
                _ => None,
            })
            .collect();
        // BIRTH carries 2 metrics (bdSeq + Tank1.Level), DATA carries 1.
        assert_eq!(readings.len(), 3, "expected 3 ProcessReadings, got {}", readings.len());
        // The DATA reading should resolve alias 10 to "Tank1.Level" via state
        // populated by the prior BIRTH frame.
        let data_reading = readings
            .iter()
            .find(|r| r.observed_ts == 1_700_000_001_000_001)
            .expect("DATA-frame reading");
        match &data_reading.point_id {
            crate::bronze::PointIdentifier::SparkplugMetric { metric_name, alias, .. } => {
                assert_eq!(metric_name.as_deref(), Some("Tank1.Level"));
                assert_eq!(*alias, Some(10));
            }
            other => panic!("wrong PointId: {other:?}"),
        }
        assert_eq!(data_reading.value, crate::bronze::PointValue::Double(51.5));
        assert_eq!(data_reading.source_ts, Some(1_700_000_001_500_000));
    }

    #[test]
    fn smb_recognizer_detects_smb2_with_netbios_prefix() {
        // 4-byte NetBIOS-style length prefix + SMB2 header (0xFE 'SMB').
        let mut payload = vec![0x00, 0x00, 0x00, 0x40];
        payload.extend_from_slice(&[0xFE, b'S', b'M', b'B']);
        payload.extend(std::iter::repeat(0u8).take(60));
        let frame = ethernet_ipv4_tcp(
            [0x02, 0, 0, 0, 0, 0x01],
            [0x02, 0, 0, 0, 0, 0x02],
            [10, 0, 0, 50],
            [10, 0, 0, 1],
            53212,
            445,
            &payload,
            None,
        );
        let pcapng = build_pcapng(&frame);
        let mut engine = DpiEngine::new();
        let output = engine
            .process_segment_to_vec(&SegmentMeta::new("smb-test"), std::io::Cursor::new(pcapng))
            .unwrap();
        assert!(
            output.events.iter().any(|ev| matches!(
                &ev.family,
                BronzeEventFamily::ProtocolTransaction(tx)
                    if tx.operation == "smb2_message"
            )),
            "expected smb2_message transaction"
        );
    }

    #[test]
    fn smb_recognizer_detects_smb1() {
        let payload: Vec<u8> = std::iter::once(0u8)
            .chain(std::iter::once(0))
            .chain(std::iter::once(0))
            .chain(std::iter::once(0x40))
            .chain([0xFF, b'S', b'M', b'B'])
            .chain(std::iter::repeat(0).take(40))
            .collect();
        let frame = ethernet_ipv4_tcp(
            [0x02, 0, 0, 0, 0, 0x01],
            [0x02, 0, 0, 0, 0, 0x02],
            [10, 0, 0, 50],
            [10, 0, 0, 1],
            53212,
            445,
            &payload,
            None,
        );
        let pcapng = build_pcapng(&frame);
        let mut engine = DpiEngine::new();
        let output = engine
            .process_segment_to_vec(&SegmentMeta::new("smb-test"), std::io::Cursor::new(pcapng))
            .unwrap();
        assert!(output.events.iter().any(|ev| matches!(
            &ev.family,
            BronzeEventFamily::ProtocolTransaction(tx) if tx.operation == "smb1_message"
        )));
    }

    #[test]
    fn kerberos_decoder_detects_as_req() {
        // ASN.1 application-tag 0x6A (KRB-AS-REQ) with correct TCP framing.
        // 4-byte BE length prefix = 1 (just the tag byte itself; will parse as
        // a truncated ASN.1 message and emit either a ProtocolTransaction or a
        // ParseAnomaly — either confirms the Kerberos decoder fired).
        let asn1_tag: u8 = 0x6A;
        let asn1_body = vec![asn1_tag, 0x01, 0x00]; // tag + minimal length + no content
        let msg_len = asn1_body.len() as u32;
        let mut payload = msg_len.to_be_bytes().to_vec();
        payload.extend_from_slice(&asn1_body);
        let frame = ethernet_ipv4_tcp(
            [0x02, 0, 0, 0, 0, 0x01],
            [0x02, 0, 0, 0, 0, 0x02],
            [10, 0, 0, 50],
            [10, 0, 0, 1],
            53212,
            88,
            &payload,
            None,
        );
        let pcapng = build_pcapng(&frame);
        let mut engine = DpiEngine::new();
        let output = engine
            .process_segment_to_vec(&SegmentMeta::new("krb-test"), std::io::Cursor::new(pcapng))
            .unwrap();
        // Full decoder now emits kerberos_as_req (or a ParseAnomaly for
        // malformed payloads); either indicates the Kerberos decoder handled
        // the traffic on port 88.
        let has_kerberos_event = output.events.iter().any(|ev| match &ev.family {
            BronzeEventFamily::ProtocolTransaction(tx) => tx.operation.starts_with("kerberos"),
            BronzeEventFamily::ParseAnomaly(a) => a.decoder == "kerberos",
            _ => false,
        });
        assert!(has_kerberos_event, "expected a Kerberos decoder event");
    }

    #[test]
    fn ldap_recognizer_detects_sequence() {
        // ASN.1 SEQUENCE 0x30 + short length.
        let mut payload = vec![0x30, 0x40];
        payload.extend(std::iter::repeat(0u8).take(64));
        let frame = ethernet_ipv4_tcp(
            [0x02, 0, 0, 0, 0, 0x01],
            [0x02, 0, 0, 0, 0, 0x02],
            [10, 0, 0, 50],
            [10, 0, 0, 1],
            53212,
            389,
            &payload,
            None,
        );
        let pcapng = build_pcapng(&frame);
        let mut engine = DpiEngine::new();
        let output = engine
            .process_segment_to_vec(&SegmentMeta::new("ldap-test"), std::io::Cursor::new(pcapng))
            .unwrap();
        assert!(output.events.iter().any(|ev| matches!(
            &ev.family,
            BronzeEventFamily::ProtocolTransaction(tx) if tx.operation == "ldap_message"
        )));
    }

    #[test]
    fn ldap_recognizer_emits_ldaps_for_port_636() {
        let payload = vec![0x16, 0x03, 0x01, 0x00, 0x40, 0x01, 0x00, 0x00, 0x3C];
        let frame = ethernet_ipv4_tcp(
            [0x02, 0, 0, 0, 0, 0x01],
            [0x02, 0, 0, 0, 0, 0x02],
            [10, 0, 0, 50],
            [10, 0, 0, 1],
            53212,
            636,
            &payload,
            None,
        );
        let pcapng = build_pcapng(&frame);
        let mut engine = DpiEngine::new();
        let output = engine
            .process_segment_to_vec(&SegmentMeta::new("ldaps-test"), std::io::Cursor::new(pcapng))
            .unwrap();
        assert!(output.events.iter().any(|ev| matches!(
            &ev.family,
            BronzeEventFamily::ProtocolTransaction(tx) if tx.operation == "ldaps_traffic"
        )));
    }

    #[test]
    fn engine_end_to_end_opc_ua_read_request_then_response() {
        use crate::opc_ua::services::{READ_REQUEST_TYPE_ID, READ_RESPONSE_TYPE_ID};

        // Build the raw OPC UA `MSG` body for a ReadRequest of two NodeIds.
        fn null_node_id() -> Vec<u8> {
            vec![0x00, 0x00]
        }
        fn build_request_header(handle: u32) -> Vec<u8> {
            let mut b = Vec::new();
            b.extend_from_slice(&null_node_id());
            b.extend_from_slice(&0i64.to_le_bytes());
            b.extend_from_slice(&handle.to_le_bytes());
            b.extend_from_slice(&0u32.to_le_bytes());
            b.extend_from_slice(&(-1i32).to_le_bytes());
            b.extend_from_slice(&0u32.to_le_bytes());
            b.extend_from_slice(&null_node_id());
            b.push(0x00);
            b
        }
        fn build_response_header(handle: u32, status: u32) -> Vec<u8> {
            let mut b = Vec::new();
            b.extend_from_slice(&0i64.to_le_bytes());
            b.extend_from_slice(&handle.to_le_bytes());
            b.extend_from_slice(&status.to_le_bytes());
            b.push(0x00);
            b.extend_from_slice(&(-1i32).to_le_bytes());
            b.extend_from_slice(&null_node_id());
            b.push(0x00);
            b
        }

        let mut req_body = Vec::new();
        // ReadRequest TypeId (FourByte: ns=0, id=631).
        req_body.push(0x01);
        req_body.push(0x00);
        req_body.extend_from_slice(&(READ_REQUEST_TYPE_ID as u16).to_le_bytes());
        req_body.extend_from_slice(&build_request_header(1));
        req_body.extend_from_slice(&0.0f64.to_le_bytes());
        req_body.extend_from_slice(&0u32.to_le_bytes());
        req_body.extend_from_slice(&2i32.to_le_bytes()); // 2 nodes
        for id in [1234u16, 5678u16] {
            req_body.push(0x01);
            req_body.push(0x02); // ns=2
            req_body.extend_from_slice(&id.to_le_bytes());
            req_body.extend_from_slice(&13u32.to_le_bytes()); // attribute = Value
            req_body.extend_from_slice(&(-1i32).to_le_bytes());
            req_body.extend_from_slice(&0u16.to_le_bytes());
            req_body.extend_from_slice(&(-1i32).to_le_bytes());
        }

        let mut resp_body = Vec::new();
        resp_body.push(0x01);
        resp_body.push(0x00);
        resp_body.extend_from_slice(&(READ_RESPONSE_TYPE_ID as u16).to_le_bytes());
        resp_body.extend_from_slice(&build_response_header(1, 0));
        resp_body.extend_from_slice(&2i32.to_le_bytes());
        for v in [50.0f64, 51.5f64] {
            resp_body.push(0x01); // HAS_VALUE
            resp_body.push(11); // T_DOUBLE
            resp_body.extend_from_slice(&v.to_le_bytes());
        }

        // Build full OPC UA MSG chunks: 8-byte header + 16-byte secure fields
        // + body. secure_channel_id matches between request and response so
        // the decoder pairs them.
        fn build_msg_chunk(secure_channel_id: u32, request_id: u32, body: &[u8]) -> Vec<u8> {
            let total = 24 + body.len();
            let mut out = Vec::with_capacity(total);
            out.extend_from_slice(b"MSG");
            out.push(b'F');
            out.extend_from_slice(&(total as u32).to_le_bytes());
            out.extend_from_slice(&secure_channel_id.to_le_bytes());
            out.extend_from_slice(&7u32.to_le_bytes()); // security_token_id
            out.extend_from_slice(&1u32.to_le_bytes()); // sequence_number
            out.extend_from_slice(&request_id.to_le_bytes());
            out.extend_from_slice(body);
            out
        }

        let req_chunk = build_msg_chunk(42, 100, &req_body);
        let resp_chunk = build_msg_chunk(42, 100, &resp_body);

        // Request: client → server (dst port 4840).
        let req_frame = ethernet_ipv4_tcp(
            [0x02, 0, 0, 0, 0, 0x01],
            [0x02, 0, 0, 0, 0, 0x02],
            [10, 0, 0, 50],
            [10, 0, 0, 1],
            53212,
            4840,
            &req_chunk,
            None,
        );
        // Response: server → client (src port 4840).
        let resp_frame = ethernet_ipv4_tcp(
            [0x02, 0, 0, 0, 0, 0x02],
            [0x02, 0, 0, 0, 0, 0x01],
            [10, 0, 0, 1],
            [10, 0, 0, 50],
            4840,
            53212,
            &resp_chunk,
            None,
        );

        let mut pcapng = Vec::new();
        pcapng.extend_from_slice(&0x0A0D0D0Au32.to_le_bytes());
        pcapng.extend_from_slice(&28u32.to_le_bytes());
        pcapng.extend_from_slice(&0x1A2B3C4Du32.to_le_bytes());
        pcapng.extend_from_slice(&1u16.to_le_bytes());
        pcapng.extend_from_slice(&0u16.to_le_bytes());
        pcapng.extend_from_slice(&0xFFFF_FFFF_FFFF_FFFFu64.to_le_bytes());
        pcapng.extend_from_slice(&28u32.to_le_bytes());
        pcapng.extend_from_slice(&0x0000_0001u32.to_le_bytes());
        pcapng.extend_from_slice(&20u32.to_le_bytes());
        pcapng.extend_from_slice(&1u16.to_le_bytes());
        pcapng.extend_from_slice(&0u16.to_le_bytes());
        pcapng.extend_from_slice(&65535u32.to_le_bytes());
        pcapng.extend_from_slice(&20u32.to_le_bytes());
        pcapng.extend_from_slice(&build_epb(&req_frame, 1_700_000_000_000_001));
        pcapng.extend_from_slice(&build_epb(&resp_frame, 1_700_000_000_500_001));

        let mut engine = DpiEngine::new();
        let output = engine
            .process_segment_to_vec(&SegmentMeta::new("opcua-corpus"), std::io::Cursor::new(pcapng))
            .expect("process");

        let readings: Vec<_> = output
            .events
            .iter()
            .filter_map(|ev| match &ev.family {
                BronzeEventFamily::ProcessReading(r) => Some(r),
                _ => None,
            })
            .collect();
        assert_eq!(readings.len(), 2, "expected 2 ProcessReadings, got {}", readings.len());

        // First reading: NodeId ns=2 id=1234 paired with value 50.0.
        let first = readings
            .iter()
            .find(|r| matches!(
                &r.point_id,
                crate::bronze::PointIdentifier::OpcUaNode { namespace_index: 2, identifier }
                    if *identifier == crate::bronze::OpcUaNodeId::Numeric(1234)
            ))
            .expect("expected NodeId 1234");
        assert_eq!(first.source_protocol, "opc_ua");
        assert_eq!(first.value, crate::bronze::PointValue::Double(50.0));
        assert!(matches!(first.quality, crate::bronze::RawQuality::OpcUaStatusCode(0)));
        assert_eq!(first.observed_ts, 1_700_000_000_500_001);

        // Second reading should be 5678 → 51.5.
        let second = readings
            .iter()
            .find(|r| matches!(
                &r.point_id,
                crate::bronze::PointIdentifier::OpcUaNode { namespace_index: 2, identifier }
                    if *identifier == crate::bronze::OpcUaNodeId::Numeric(5678)
            ))
            .expect("expected NodeId 5678");
        assert_eq!(second.value, crate::bronze::PointValue::Double(51.5));
    }

    #[test]
    fn engine_end_to_end_sparkplug_data_without_birth_emits_anomaly() {
        use crate::sparkplug::proto::payload::{metric, Metric as PbMetric};
        use crate::sparkplug::proto::{DataType, Payload as PbPayload};
        use prost::Message as _;

        let ndata = PbPayload {
            metrics: vec![PbMetric {
                alias: Some(99),
                datatype: Some(DataType::Double as u32),
                value: Some(metric::Value::DoubleValue(1.0)),
                ..Default::default()
            }],
            ..Default::default()
        };
        let frame = ethernet_ipv4_tcp(
            [0x02, 0, 0, 0, 0, 0x01],
            [0x02, 0, 0, 0, 0, 0x02],
            [10, 0, 0, 50],
            [10, 0, 0, 1],
            53212,
            1883,
            &mqtt_publish_frame(b"spBv1.0/Plant1/NDATA/Edge", &ndata.encode_to_vec()),
            None,
        );
        let pcapng = build_pcapng(&frame);

        let mut engine = DpiEngine::new();
        let output = engine
            .process_segment_to_vec(&SegmentMeta::new("sparkplug-corpus-gap"), std::io::Cursor::new(pcapng))
            .expect("process");

        // Should see one ProcessReading (with metric_name=None) and one
        // sparkplug_b ParseAnomaly for the gap.
        assert!(output.events.iter().any(|ev| matches!(
            &ev.family,
            BronzeEventFamily::ParseAnomaly(a) if a.decoder == "sparkplug_b"
        )));
        let unresolved = output.events.iter().find_map(|ev| match &ev.family {
            BronzeEventFamily::ProcessReading(r) => Some(r),
            _ => None,
        }).expect("ProcessReading present");
        match &unresolved.point_id {
            crate::bronze::PointIdentifier::SparkplugMetric { metric_name, alias, .. } => {
                assert!(metric_name.is_none());
                assert_eq!(*alias, Some(99));
            }
            _ => panic!(),
        }
    }
}
