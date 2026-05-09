//! Bronze v2 streaming DPI engine.

use std::collections::{BTreeMap, HashMap};
use std::io::{self, Read, Seek, SeekFrom};
use std::net::{IpAddr, Ipv4Addr};

use chrono::{DateTime, TimeZone, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::bronze::{
    AssetObservation, BronzeBatch, BronzeEvent, BronzeEventFamily, EventEnvelope,
    ExtractedArtifact, ModbusBronzeFields, ObjectValue, ParseAnomaly, ProtocolTransaction,
    SegmentCheckpoint, TopologyObservation, TransportProtocol, BRONZE_SCHEMA_VERSION,
};
use crate::bilgepump::alerts::BilgepumpAlert;
use crate::bilgepump::config::BilgepumpConfig;
use crate::bilgepump::monitor::BilgepumpMonitor;
use crate::dedup::DedupEngine;
use crate::icmpeeker::IcmpeekerConfig;
use crate::stovetop::config::StovetopConfig;
use crate::stovetop::findings::FrameFinding;
use crate::stovetop::frame_inspector::FrameInspector;
use crate::dissectors::{
    arp::ArpDissector,
    bacnet::BacnetDissector,
    cdp::CdpDissector,
    dhcp::DhcpDissector,
    dnp3::Dnp3Dissector,
    dns::DnsDissector,
    ethercat::EthercatDissector,
    ethernet_ip::EthernetIpDissector,
    fins::OmronFinsDissector,
    hart_ip::{parse_hart_ip_frames, HartIpBody, HartIpDissector, HartIpFields},
    http::HttpDissector,
    iec104::parse_iec104_frames,
    iec61850::{
        Iec61850Dissector, Iec61850Fields, Iec61850Profile, IEC61850_GOOSE_ETHERTYPE,
        IEC61850_MMS_PORT, IEC61850_SV_ETHERTYPE,
    },
    lacp::LacpDissector,
    lldp::LldpDissector,
    modbus::ModbusDissector,
    mqtt::MqttDissector,
    mrp::MrpDissector,
    mstp::MstpDissector,
    ntp::NtpDissector,
    opc_ua::OpcUaDissector,
    profinet::ProfinetDissector,
    prp::PrpDissector,
    pvst::PvstDissector,
    radius::RadiusDissector,
    s7comm::S7commDissector,
    snmp::SnmpDissector,
    ssh::SshDissector,
    stp::StpDissector,
    syslog::SyslogDissector,
    vtp::VtpDissector,
};
use crate::dissectors::ftp::FtpDissector;
use crate::dissectors::icmp::IcmpDissector;
use crate::registry::{
    format_mac, ArpFields, BacnetFields, CdpFields, DhcpFields, Dnp3Fields, DnsFields,
    EthernetIpFields, FtpFields, HttpFields, Iec104Fields, LacpFields, LldpFields,
    ModbusFields, ModbusPdu,
    MqttFields, MrpFields, NtpFields, OmronFinsFields, OpcUaFields, PacketContext,
    ProfinetFields, ProtocolData, ProtocolDissector, PrpFields, PvstFields, RadiusFields,
    S7commFields, SnmpFields, SshFields, StpFields, SyslogFields, VtpFields,
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
struct LlcInfo {
    dsap: u8,
    ssap: u8,
    snap_oui: Option<[u8; 3]>,
    snap_pid: Option<u16>,
}

#[derive(Debug, Clone)]
struct StreamChunk<'a> {
    capture_id: &'a str,
    segment_hash: &'a str,
    interface_id: u32,
    frame_index: u64,
    timestamp: DateTime<Utc>,
    context: PacketContext,
    ethertype: u16,
    ip_proto: Option<u8>,
    llc: Option<LlcInfo>,
    transport: TransportProtocol,
    payload: &'a [u8],
    session_key: String,
    captured_len: u64,
}

trait SessionDecoder: Send {
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
            decoders: vec![
                Box::new(ArpDecoder::default()),
                Box::new(LldpDecoder::default()),
                Box::new(CdpDecoder::default()),
                Box::new(StpDecoder::default()),
                Box::new(BacnetDecoder::default()),
                Box::new(DnsDecoder::default()),
                Box::new(DhcpDecoder::default()),
                Box::new(SnmpDecoder::default()),
                Box::new(HttpDecoder::default()),
                Box::new(TlsDecoder),
                Box::new(ModbusDecoder::default()),
                Box::new(Dnp3DecoderWrapper::default()),
                Box::new(Iec104DecoderWrapper::default()),
                Box::new(OmronFinsDecoder::default()),
                Box::new(HartIpDecoderWrapper::default()),
                Box::new(EthernetIpDecoderWrapper::default()),
                Box::new(OpcUaDecoderWrapper::default()),
                Box::new(Iec61850DecoderWrapper::default()),
                Box::new(S7commDecoderWrapper::default()),
                Box::new(EthercatDecoderWrapper::default()),
                Box::new(ProfinetDecoderWrapper::default()),
                Box::new(NtpDecoder::default()),
                Box::new(SynchrophasorDecoderWrapper::default()),
                Box::new(SmbRecognizer),
                Box::new(KerberosRecognizer),
                Box::new(LdapRecognizer),
                Box::new(CcLinkRecognizer),
                Box::new(CodesysRecognizer),
                Box::new(IoLinkRecognizer),
                Box::new(IgmpRecognizer),
                Box::new(MqttDecoder::default()),
                Box::new(SyslogDecoder::default()),
                Box::new(FtpDecoder::default()),
                Box::new(SshDecoder::default()),
                Box::new(RadiusDecoder::default()),
                Box::new(VtpDecoder::default()),
                Box::new(MrpDecoder::default()),
                Box::new(MstpDecoder::default()),
                Box::new(PvstDecoder::default()),
                Box::new(PrpDecoder::default()),
                Box::new(LacpDecoder::default()),
                Box::new(IcmpDecoder::default()),
            ],
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

fn interest_matches(interests: &[DecoderInterest], chunk: &StreamChunk<'_>) -> bool {
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

fn build_envelope(
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

fn empty_envelope(
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

fn ip_to_string(ip: IpAddr) -> Option<String> {
    match ip {
        IpAddr::V4(v4) if v4 == Ipv4Addr::UNSPECIFIED => None,
        _ => Some(ip.to_string()),
    }
}

fn non_zero_u16(value: u16) -> Option<u16> {
    if value == 0 {
        None
    } else {
        Some(value)
    }
}

fn make_layer2_session_key(src_mac: &[u8; 6], dst_mac: &[u8; 6], protocol_key: &str) -> String {
    let mut peers = [format_mac(src_mac), format_mac(dst_mac)];
    peers.sort();
    format!("l2:{}:{}:{protocol_key}", peers[0], peers[1])
}

fn make_ip_session_key(
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

fn new_event(
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

fn parse_anomaly_event(
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

fn artifact_event(
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

#[derive(Default)]
struct ArpDecoder {
    dissector: ArpDissector,
}

impl SessionDecoder for ArpDecoder {
    fn name(&self) -> &'static str {
        "arp"
    }

    fn interest(&self) -> &'static [DecoderInterest] {
        &[DecoderInterest::EtherType(0x0806)]
    }

    fn on_datagram(&mut self, chunk: &StreamChunk<'_>, out: &mut Vec<BronzeEvent>) {
        match self.dissector.parse(chunk.payload, &chunk.context) {
            Some(ProtocolData::Arp(ArpFields {
                sender_mac,
                sender_ip,
                target_mac,
                target_ip,
                operation,
            })) => {
                let envelope = build_envelope(
                    &chunk.context,
                    chunk.interface_id,
                    chunk.frame_index,
                    chunk.timestamp,
                    chunk.segment_hash,
                    TransportProtocol::Arp,
                    Some("arp"),
                    chunk.captured_len,
                    chunk.session_key.clone(),
                );
                let sender_ip = format!(
                    "{}.{}.{}.{}",
                    sender_ip[0], sender_ip[1], sender_ip[2], sender_ip[3]
                );
                let target_ip = format!(
                    "{}.{}.{}.{}",
                    target_ip[0], target_ip[1], target_ip[2], target_ip[3]
                );
                out.push(new_event(
                    chunk.capture_id.to_string(),
                    envelope.clone(),
                    BronzeEventFamily::AssetObservation(AssetObservation {
                        asset_key: format_mac(&sender_mac),
                        role: None,
                        vendor: None,
                        model: None,
                        firmware: None,
                        hostnames: Vec::new(),
                        protocols: vec!["arp".to_string()],
                        identifiers: BTreeMap::from([
                            ("mac".to_string(), format_mac(&sender_mac)),
                            ("ip".to_string(), sender_ip.clone()),
                        ]),
                    }),
                ));
                out.push(new_event(
                    chunk.capture_id.to_string(),
                    envelope,
                    BronzeEventFamily::TopologyObservation(TopologyObservation {
                        observation_type: if operation == 2 {
                            "arp_reply".to_string()
                        } else {
                            "arp_request".to_string()
                        },
                        local_id: sender_ip,
                        remote_id: Some(target_ip),
                        description: Some(format!(
                            "ARP op={operation} {} -> {}",
                            format_mac(&sender_mac),
                            format_mac(&target_mac)
                        )),
                        capabilities: Vec::new(),
                        metadata: BTreeMap::new(),
                    }),
                ));
            }
            _ => out.push(parse_anomaly_event(
                chunk.capture_id.to_string(),
                build_envelope(
                    &chunk.context,
                    chunk.interface_id,
                    chunk.frame_index,
                    chunk.timestamp,
                    chunk.segment_hash,
                    TransportProtocol::Arp,
                    Some("arp"),
                    chunk.captured_len,
                    chunk.session_key.clone(),
                ),
                self.name(),
                "medium",
                "failed to parse arp payload",
                chunk.payload,
            )),
        }
    }
}

#[derive(Default)]
struct LldpDecoder {
    dissector: LldpDissector,
}

impl SessionDecoder for LldpDecoder {
    fn name(&self) -> &'static str {
        "lldp"
    }

    fn interest(&self) -> &'static [DecoderInterest] {
        &[DecoderInterest::EtherType(0x88CC)]
    }

    fn on_datagram(&mut self, chunk: &StreamChunk<'_>, out: &mut Vec<BronzeEvent>) {
        match self.dissector.parse(chunk.payload, &chunk.context) {
            Some(ProtocolData::Lldp(LldpFields {
                chassis_id,
                port_id,
                system_name,
                system_description,
                capabilities,
                ..
            })) => {
                let envelope = build_envelope(
                    &chunk.context,
                    chunk.interface_id,
                    chunk.frame_index,
                    chunk.timestamp,
                    chunk.segment_hash,
                    TransportProtocol::Ethernet,
                    Some("lldp"),
                    chunk.captured_len,
                    chunk.session_key.clone(),
                );
                out.push(new_event(
                    chunk.capture_id.to_string(),
                    envelope.clone(),
                    BronzeEventFamily::AssetObservation(AssetObservation {
                        asset_key: chassis_id.clone(),
                        role: Some("switch".to_string()),
                        vendor: (!system_name.is_empty()).then_some(system_name.clone()),
                        model: (!system_description.is_empty())
                            .then_some(system_description.clone()),
                        firmware: None,
                        hostnames: Vec::new(),
                        protocols: vec!["lldp".to_string()],
                        identifiers: BTreeMap::from([
                            ("chassis_id".to_string(), chassis_id.clone()),
                            ("port_id".to_string(), port_id.clone()),
                        ]),
                    }),
                ));
                out.push(new_event(
                    chunk.capture_id.to_string(),
                    envelope,
                    BronzeEventFamily::TopologyObservation(TopologyObservation {
                        observation_type: "lldp_neighbor".to_string(),
                        local_id: format_mac(&chunk.context.src_mac),
                        remote_id: Some(chassis_id),
                        description: Some(port_id),
                        capabilities,
                        metadata: BTreeMap::new(),
                    }),
                ));
            }
            _ => out.push(parse_anomaly_event(
                chunk.capture_id.to_string(),
                build_envelope(
                    &chunk.context,
                    chunk.interface_id,
                    chunk.frame_index,
                    chunk.timestamp,
                    chunk.segment_hash,
                    TransportProtocol::Ethernet,
                    Some("lldp"),
                    chunk.captured_len,
                    chunk.session_key.clone(),
                ),
                self.name(),
                "medium",
                "failed to parse lldp payload",
                chunk.payload,
            )),
        }
    }
}

#[derive(Default)]
struct CdpDecoder {
    dissector: CdpDissector,
}

impl SessionDecoder for CdpDecoder {
    fn name(&self) -> &'static str {
        "cdp"
    }

    fn interest(&self) -> &'static [DecoderInterest] {
        &[DecoderInterest::Snap {
            oui: [0x00, 0x00, 0x0C],
            pid: 0x2000,
        }]
    }

    fn on_datagram(&mut self, chunk: &StreamChunk<'_>, out: &mut Vec<BronzeEvent>) {
        match self.dissector.parse(chunk.payload, &chunk.context) {
            Some(ProtocolData::Cdp(CdpFields {
                device_id,
                port_id,
                platform,
                software_version,
                capabilities,
                native_vlan,
                duplex,
                ..
            })) => {
                let envelope = build_envelope(
                    &chunk.context,
                    chunk.interface_id,
                    chunk.frame_index,
                    chunk.timestamp,
                    chunk.segment_hash,
                    TransportProtocol::Ethernet,
                    Some("cdp"),
                    chunk.captured_len,
                    chunk.session_key.clone(),
                );
                let role = if capabilities.iter().any(|c| c == "switch") {
                    Some("switch".to_string())
                } else if capabilities.iter().any(|c| c == "router") {
                    Some("router".to_string())
                } else {
                    None
                };
                let mut identifiers = BTreeMap::from([
                    ("mac".to_string(), format_mac(&chunk.context.src_mac)),
                    ("device_id".to_string(), device_id.clone()),
                ]);
                if !port_id.is_empty() {
                    identifiers.insert("port_id".to_string(), port_id.clone());
                }
                if let Some(vlan) = native_vlan {
                    identifiers.insert("native_vlan".to_string(), vlan.to_string());
                }
                out.push(new_event(
                    chunk.capture_id.to_string(),
                    envelope.clone(),
                    BronzeEventFamily::AssetObservation(AssetObservation {
                        asset_key: device_id.clone(),
                        role,
                        vendor: Some("Cisco".to_string()),
                        model: platform,
                        firmware: software_version,
                        hostnames: vec![device_id.clone()],
                        protocols: vec!["cdp".to_string()],
                        identifiers,
                    }),
                ));

                let mut metadata = BTreeMap::new();
                if let Some(vlan) = native_vlan {
                    metadata.insert("native_vlan".to_string(), vlan.to_string());
                }
                if let Some(duplex) = duplex {
                    metadata.insert("duplex".to_string(), duplex);
                }
                out.push(new_event(
                    chunk.capture_id.to_string(),
                    envelope,
                    BronzeEventFamily::TopologyObservation(TopologyObservation {
                        observation_type: "cdp_neighbor".to_string(),
                        local_id: format_mac(&chunk.context.src_mac),
                        remote_id: Some(device_id),
                        description: (!port_id.is_empty()).then_some(port_id),
                        capabilities,
                        metadata,
                    }),
                ));
            }
            _ => out.push(parse_anomaly_event(
                chunk.capture_id.to_string(),
                build_envelope(
                    &chunk.context,
                    chunk.interface_id,
                    chunk.frame_index,
                    chunk.timestamp,
                    chunk.segment_hash,
                    TransportProtocol::Ethernet,
                    Some("cdp"),
                    chunk.captured_len,
                    chunk.session_key.clone(),
                ),
                self.name(),
                "medium",
                "failed to parse cdp payload",
                chunk.payload,
            )),
        }
    }
}

#[derive(Default)]
struct StpDecoder {
    dissector: StpDissector,
}

impl SessionDecoder for StpDecoder {
    fn name(&self) -> &'static str {
        "stp"
    }

    fn interest(&self) -> &'static [DecoderInterest] {
        &[DecoderInterest::Llc {
            dsap: 0x42,
            ssap: 0x42,
        }]
    }

    fn on_datagram(&mut self, chunk: &StreamChunk<'_>, out: &mut Vec<BronzeEvent>) {
        match self.dissector.parse(chunk.payload, &chunk.context) {
            Some(ProtocolData::Stp(StpFields {
                protocol_version,
                bpdu_type,
                flags,
                root_id,
                root_path_cost,
                bridge_id,
                port_id,
                ..
            })) => {
                let envelope = build_envelope(
                    &chunk.context,
                    chunk.interface_id,
                    chunk.frame_index,
                    chunk.timestamp,
                    chunk.segment_hash,
                    TransportProtocol::Ethernet,
                    Some("stp"),
                    chunk.captured_len,
                    chunk.session_key.clone(),
                );
                let mut identifiers = BTreeMap::from([
                    ("mac".to_string(), format_mac(&chunk.context.src_mac)),
                    ("bridge_id".to_string(), bridge_id.clone()),
                    ("root_id".to_string(), root_id.clone()),
                    ("port_id".to_string(), format!("{port_id:#06x}")),
                ]);
                identifiers.insert("root_path_cost".to_string(), root_path_cost.to_string());
                out.push(new_event(
                    chunk.capture_id.to_string(),
                    envelope.clone(),
                    BronzeEventFamily::AssetObservation(AssetObservation {
                        asset_key: bridge_id.clone(),
                        role: Some("switch".to_string()),
                        vendor: None,
                        model: None,
                        firmware: None,
                        hostnames: Vec::new(),
                        protocols: vec!["stp".to_string()],
                        identifiers,
                    }),
                ));

                let mut metadata = BTreeMap::new();
                metadata.insert("protocol_version".to_string(), protocol_version.to_string());
                metadata.insert("bpdu_type".to_string(), format!("{bpdu_type:#04x}"));
                metadata.insert("flags".to_string(), format!("{flags:#04x}"));
                metadata.insert("root_path_cost".to_string(), root_path_cost.to_string());
                metadata.insert("port_id".to_string(), format!("{port_id:#06x}"));
                out.push(new_event(
                    chunk.capture_id.to_string(),
                    envelope,
                    BronzeEventFamily::TopologyObservation(TopologyObservation {
                        observation_type: "stp_topology".to_string(),
                        local_id: bridge_id,
                        remote_id: Some(root_id),
                        description: Some("spanning_tree_bpdu".to_string()),
                        capabilities: Vec::new(),
                        metadata,
                    }),
                ));
            }
            _ => out.push(parse_anomaly_event(
                chunk.capture_id.to_string(),
                build_envelope(
                    &chunk.context,
                    chunk.interface_id,
                    chunk.frame_index,
                    chunk.timestamp,
                    chunk.segment_hash,
                    TransportProtocol::Ethernet,
                    Some("stp"),
                    chunk.captured_len,
                    chunk.session_key.clone(),
                ),
                self.name(),
                "medium",
                "failed to parse stp payload",
                chunk.payload,
            )),
        }
    }
}

#[derive(Default)]
struct BacnetDecoder {
    dissector: BacnetDissector,
}

impl SessionDecoder for BacnetDecoder {
    fn name(&self) -> &'static str {
        "bacnet"
    }

    fn interest(&self) -> &'static [DecoderInterest] {
        static INTERESTS: [DecoderInterest; 2] = [
            DecoderInterest::UdpPort(47808),
            DecoderInterest::Llc {
                dsap: 0x82,
                ssap: 0x82,
            },
        ];
        &INTERESTS
    }

    fn on_datagram(&mut self, chunk: &StreamChunk<'_>, out: &mut Vec<BronzeEvent>) {
        match self.dissector.parse(chunk.payload, &chunk.context) {
            Some(ProtocolData::Bacnet(BacnetFields {
                link_variant,
                bvlc_function,
                npdu_control,
                apdu_type,
                service,
                invoke_id,
                device_instance,
                vendor_id,
                payload,
            })) => {
                let transport = if chunk.transport == TransportProtocol::Udp {
                    TransportProtocol::Udp
                } else {
                    TransportProtocol::Ethernet
                };
                let envelope = build_envelope(
                    &chunk.context,
                    chunk.interface_id,
                    chunk.frame_index,
                    chunk.timestamp,
                    chunk.segment_hash,
                    transport,
                    Some("bacnet"),
                    chunk.captured_len,
                    chunk.session_key.clone(),
                );
                let mut attributes = BTreeMap::new();
                attributes.insert("link_variant".to_string(), link_variant.clone());
                attributes.insert("npdu_control".to_string(), format!("{npdu_control:#04x}"));
                attributes.insert("apdu_type".to_string(), apdu_type.clone());
                if let Some(function) = &bvlc_function {
                    attributes.insert("bvlc_function".to_string(), function.clone());
                }
                if let Some(invoke_id) = invoke_id {
                    attributes.insert("invoke_id".to_string(), invoke_id.to_string());
                }
                if let Some(vendor_id) = vendor_id {
                    attributes.insert("vendor_id".to_string(), vendor_id.to_string());
                }
                if let Some(device_instance) = device_instance {
                    attributes.insert("device_instance".to_string(), device_instance.to_string());
                }

                out.push(new_event(
                    chunk.capture_id.to_string(),
                    envelope.clone(),
                    BronzeEventFamily::ProtocolTransaction(ProtocolTransaction {
                        operation: normalize_operation_name(&service, "bacnet_message"),
                        status: bacnet_status(&apdu_type).to_string(),
                        request_summary: Some(format!("{apdu_type} {service}")),
                        response_summary: None,
                        object_refs: bacnet_object_refs(device_instance, invoke_id),
                        values: Vec::new(),
                        attributes,
                                        modbus: None,
}),
                ));

                if let Some(device_instance) = device_instance {
                    let mut identifiers = BTreeMap::from([
                        ("ip".to_string(), chunk.context.src_ip.to_string()),
                        (
                            "bacnet_device_instance".to_string(),
                            device_instance.to_string(),
                        ),
                    ]);
                    if let Some(vendor_id) = vendor_id {
                        identifiers.insert("bacnet_vendor_id".to_string(), vendor_id.to_string());
                    }
                    out.push(new_event(
                        chunk.capture_id.to_string(),
                        envelope.clone(),
                        BronzeEventFamily::AssetObservation(AssetObservation {
                            asset_key: chunk.context.src_ip.to_string(),
                            role: Some("device".to_string()),
                            vendor: None,
                            model: None,
                            firmware: None,
                            hostnames: Vec::new(),
                            protocols: vec!["bacnet".to_string()],
                            identifiers,
                        }),
                    ));
                }

                out.push(new_event(
                    chunk.capture_id.to_string(),
                    envelope.clone(),
                    BronzeEventFamily::TopologyObservation(TopologyObservation {
                        observation_type: "bacnet_transaction".to_string(),
                        local_id: chunk.context.src_ip.to_string(),
                        remote_id: Some(chunk.context.dst_ip.to_string()),
                        description: Some(service.clone()),
                        capabilities: Vec::new(),
                        metadata: BTreeMap::from([
                            ("link_variant".to_string(), link_variant),
                            ("apdu_type".to_string(), apdu_type.clone()),
                        ]),
                    }),
                ));

                if !payload.is_empty() {
                    out.push(artifact_event(
                        chunk.capture_id.to_string(),
                        envelope,
                        "bacnet_apdu",
                        &format!("{}:{}", service, chunk.frame_index),
                        Some("application/octet-stream"),
                        Some("BACnet APDU payload"),
                        &payload,
                    ));
                }
            }
            _ => out.push(parse_anomaly_event(
                chunk.capture_id.to_string(),
                build_envelope(
                    &chunk.context,
                    chunk.interface_id,
                    chunk.frame_index,
                    chunk.timestamp,
                    chunk.segment_hash,
                    chunk.transport,
                    Some("bacnet"),
                    chunk.captured_len,
                    chunk.session_key.clone(),
                ),
                self.name(),
                "medium",
                "failed to parse bacnet payload",
                chunk.payload,
            )),
        }
    }
}

#[derive(Default)]
struct DnsDecoder {
    dissector: DnsDissector,
}

impl SessionDecoder for DnsDecoder {
    fn name(&self) -> &'static str {
        "dns"
    }

    fn interest(&self) -> &'static [DecoderInterest] {
        &[
            DecoderInterest::UdpPort(53),
            DecoderInterest::TcpPort(53),
            DecoderInterest::UdpPort(5353), // mDNS — same wire format, local hostnames
        ]
    }

    fn on_datagram(&mut self, chunk: &StreamChunk<'_>, out: &mut Vec<BronzeEvent>) {
        let payload = dns_payload(chunk);
        match self.dissector.parse(payload, &chunk.context) {
            Some(ProtocolData::Dns(DnsFields {
                is_response,
                transaction_id,
                queries,
                answers,
                records,
            })) => {
                let mut attributes = BTreeMap::new();
                attributes.insert("transaction_id".to_string(), transaction_id.to_string());
                let envelope = build_envelope(
                    &chunk.context,
                    chunk.interface_id,
                    chunk.frame_index,
                    chunk.timestamp,
                    chunk.segment_hash,
                    chunk.transport,
                    Some("dns"),
                    chunk.captured_len,
                    chunk.session_key.clone(),
                );
                out.push(new_event(
                    chunk.capture_id.to_string(),
                    envelope.clone(),
                    BronzeEventFamily::ProtocolTransaction(ProtocolTransaction {
                        operation: if is_response {
                            "response".to_string()
                        } else {
                            "query".to_string()
                        },
                        status: if is_response {
                            "response".to_string()
                        } else {
                            "request".to_string()
                        },
                        request_summary: (!queries.is_empty()).then_some(queries.join(", ")),
                        response_summary: (!answers.is_empty()).then_some(answers.join(", ")),
                        object_refs: queries.clone(),
                        values: answers
                            .iter()
                            .map(|answer| ObjectValue {
                                object_ref: "answer".to_string(),
                                value: Some(answer.clone()),
                            })
                            .collect(),
                        attributes,
                                        modbus: None,
}),
                ));
                if is_response {
                    use crate::registry::{DnsRecordData, DnsRecordType};

                    let is_mdns = chunk.context.dst_port == 5353 || chunk.context.src_port == 5353;

                    // ── Standard DNS: pair queries with answers ──
                    if !is_mdns {
                        for (query, answer) in queries.iter().zip(answers.iter()) {
                            let hostname = dns_hostname_from_query(query);
                            if let Some(ip) = dns_ip_from_answer(answer) {
                                out.push(new_event(
                                    chunk.capture_id.to_string(),
                                    envelope.clone(),
                                    BronzeEventFamily::AssetObservation(AssetObservation {
                                        asset_key: ip.clone(),
                                        role: None,
                                        vendor: None,
                                        model: None,
                                        firmware: None,
                                        hostnames: vec![hostname],
                                        protocols: vec!["dns".to_string()],
                                        identifiers: BTreeMap::from([("ip".to_string(), ip)]),
                                    }),
                                ));
                            }
                        }
                    }

                    // ── mDNS: use structured records for rich extraction ──
                    if is_mdns {
                        let src_ip = chunk.context.src_ip.to_string();

                        // Collect A record bindings: hostname.local → IP
                        let mut hostname_ips: Vec<(String, String)> = Vec::new();
                        for rec in &records {
                            if let DnsRecordData::A(ip) = &rec.data {
                                if rec.name.ends_with(".local") {
                                    hostname_ips.push((rec.name.clone(), ip.clone()));
                                }
                            }
                        }

                        // Emit hostname observations from A records
                        for (hostname, ip) in &hostname_ips {
                            // Skip service discovery names
                            if hostname.contains("._tcp.") || hostname.contains("._udp.") {
                                continue;
                            }
                            out.push(new_event(
                                chunk.capture_id.to_string(),
                                envelope.clone(),
                                BronzeEventFamily::AssetObservation(AssetObservation {
                                    asset_key: ip.clone(),
                                    role: None,
                                    vendor: None,
                                    model: None,
                                    firmware: None,
                                    hostnames: vec![hostname.clone()],
                                    protocols: vec!["mdns".to_string()],
                                    identifiers: BTreeMap::from([("ip".to_string(), ip.clone())]),
                                }),
                            ));
                        }

                        // If no A records matched, enrich src_ip with the
                        // first clean .local PTR name
                        if hostname_ips.is_empty() {
                            for rec in &records {
                                if let DnsRecordData::Ptr(name) = &rec.data {
                                    if name.ends_with(".local")
                                        && !name.contains("._tcp.")
                                        && !name.contains("._udp.")
                                        && !rec.name.contains(".ip6.arpa")
                                    {
                                        out.push(new_event(
                                            chunk.capture_id.to_string(),
                                            envelope.clone(),
                                            BronzeEventFamily::AssetObservation(AssetObservation {
                                                asset_key: src_ip.clone(),
                                                role: None,
                                                vendor: None,
                                                model: None,
                                                firmware: None,
                                                hostnames: vec![name.clone()],
                                                protocols: vec!["mdns".to_string()],
                                                identifiers: BTreeMap::from([(
                                                    "ip".to_string(),
                                                    src_ip.clone(),
                                                )]),
                                            }),
                                        ));
                                        break;
                                    }
                                }
                            }
                        }

                        // Extract device metadata from TXT records.
                        // Covers: AirPlay, RAOP, Google Cast, Roku, printers (IPP),
                        // HomeKit (HAP), Sonos, Hue, ESPHome, Samsung, Home Assistant.
                        let mut mdns_vendor: Option<String> = None;
                        let mut mdns_model: Option<String> = None;
                        let mut mdns_firmware: Option<String> = None;
                        let mut mdns_device_name: Option<String> = None;
                        let mut service_types: Vec<String> = Vec::new();

                        for rec in &records {
                            // Track which service types are advertised
                            if rec.rtype == DnsRecordType::PTR {
                                if let DnsRecordData::Ptr(instance) = &rec.data {
                                    if rec.name.contains("._tcp.") || rec.name.contains("._udp.") {
                                        service_types.push(rec.name.clone());
                                    }
                                    // Extract friendly name from service instance
                                    // e.g. "Bathroom TV._airplay._tcp.local" → "Bathroom TV"
                                    if let Some(name) = instance.split("._").next().filter(|n| {
                                        !n.is_empty()
                                            && n.len() > 2
                                            && (n.contains(' ') || n.len() > 6)
                                    }) {
                                        // Skip UUID-style names
                                        if !name.chars().all(|c| c.is_ascii_hexdigit() || c == '-')
                                        {
                                            if mdns_device_name.is_none() {
                                                mdns_device_name = Some(name.to_string());
                                            }
                                        }
                                    }
                                }
                            }

                            if let DnsRecordData::Txt(entries) = &rec.data {
                                for entry in entries {
                                    let Some((key, val)) = entry.split_once('=') else {
                                        continue;
                                    };
                                    if val.is_empty() {
                                        continue;
                                    }
                                    match key {
                                        // Vendor / manufacturer
                                        "manufacturer" | "usb_MFG" | "integrator" => {
                                            if mdns_vendor.is_none() {
                                                mdns_vendor = Some(val.to_string());
                                            }
                                        }
                                        // Model (priority order handled by first-wins)
                                        "md" | "model" | "am" | "mdl" | "modelid" | "usb_MDL"
                                        | "mn" => {
                                            if mdns_model.is_none() {
                                                mdns_model = Some(val.to_string());
                                            }
                                        }
                                        // Printer type string (very descriptive)
                                        "ty" | "product" => {
                                            if mdns_model.is_none() {
                                                let cleaned =
                                                    val.trim_matches(|c| c == '(' || c == ')');
                                                mdns_model = Some(cleaned.to_string());
                                            }
                                        }
                                        // Friendly name
                                        "fn" | "n" | "friendly_name" | "name" => {
                                            mdns_device_name = Some(val.to_string());
                                        }
                                        // Firmware / software version
                                        "fv" | "srcvers" | "vs" | "vers" | "swversion"
                                        | "version" => {
                                            if mdns_firmware.is_none() {
                                                mdns_firmware = Some(val.to_string());
                                            }
                                        }
                                        _ => {}
                                    }
                                }
                            }
                        }

                        // Infer vendor from service type when TXT doesn't have it
                        if mdns_vendor.is_none() {
                            for svc in &service_types {
                                if svc.contains("_googlecast.") {
                                    mdns_vendor = Some("Google".into());
                                    break;
                                }
                                if svc.contains("_sonos.") {
                                    mdns_vendor = Some("Sonos".into());
                                    break;
                                }
                                if svc.contains("_hue.") {
                                    mdns_vendor = Some("Philips".into());
                                    break;
                                }
                                if svc.contains("_samsungtv.") {
                                    mdns_vendor = Some("Samsung".into());
                                    break;
                                }
                                if svc.contains("_amzn-wplay.") {
                                    mdns_vendor = Some("Amazon".into());
                                    break;
                                }
                            }
                        }

                        // Emit enriched observation with vendor/model/firmware if found
                        if mdns_vendor.is_some()
                            || mdns_model.is_some()
                            || mdns_device_name.is_some()
                            || mdns_firmware.is_some()
                        {
                            let mut identifiers = BTreeMap::new();
                            identifiers.insert("ip".to_string(), src_ip.clone());
                            if let Some(ref name) = mdns_device_name {
                                identifiers.insert("device_name".to_string(), name.clone());
                            }
                            // Use device name as hostname if we have one
                            let hostnames = mdns_device_name
                                .as_ref()
                                .map(|n| vec![n.clone()])
                                .unwrap_or_default();
                            out.push(new_event(
                                chunk.capture_id.to_string(),
                                envelope.clone(),
                                BronzeEventFamily::AssetObservation(AssetObservation {
                                    asset_key: src_ip.clone(),
                                    role: None,
                                    vendor: mdns_vendor,
                                    model: mdns_model,
                                    firmware: mdns_firmware,
                                    hostnames,
                                    protocols: vec!["mdns".to_string()],
                                    identifiers,
                                }),
                            ));
                        }

                        // Reverse PTR records (in-addr.arpa)
                        for rec in &records {
                            if rec.name.ends_with(".in-addr.arpa") {
                                if let DnsRecordData::Ptr(ptr_name) = &rec.data {
                                    let octets: Vec<&str> = rec
                                        .name
                                        .trim_end_matches(".in-addr.arpa")
                                        .split('.')
                                        .collect();
                                    if octets.len() == 4 {
                                        let reversed_ip = format!(
                                            "{}.{}.{}.{}",
                                            octets[3], octets[2], octets[1], octets[0]
                                        );
                                        out.push(new_event(
                                            chunk.capture_id.to_string(),
                                            envelope.clone(),
                                            BronzeEventFamily::AssetObservation(AssetObservation {
                                                asset_key: reversed_ip.clone(),
                                                role: None,
                                                vendor: None,
                                                model: None,
                                                firmware: None,
                                                hostnames: vec![ptr_name.clone()],
                                                protocols: vec!["mdns".to_string()],
                                                identifiers: BTreeMap::from([(
                                                    "ip".to_string(),
                                                    reversed_ip,
                                                )]),
                                            }),
                                        ));
                                    }
                                }
                            }
                        }
                    }
                }
            }
            _ => out.push(parse_anomaly_event(
                chunk.capture_id.to_string(),
                build_envelope(
                    &chunk.context,
                    chunk.interface_id,
                    chunk.frame_index,
                    chunk.timestamp,
                    chunk.segment_hash,
                    chunk.transport,
                    Some("dns"),
                    chunk.captured_len,
                    chunk.session_key.clone(),
                ),
                self.name(),
                "medium",
                "failed to parse dns payload",
                payload,
            )),
        }
    }
}

#[derive(Default)]
struct DhcpDecoder {
    dissector: DhcpDissector,
}

impl SessionDecoder for DhcpDecoder {
    fn name(&self) -> &'static str {
        "dhcp"
    }

    fn interest(&self) -> &'static [DecoderInterest] {
        &[DecoderInterest::UdpPort(67), DecoderInterest::UdpPort(68)]
    }

    fn on_datagram(&mut self, chunk: &StreamChunk<'_>, out: &mut Vec<BronzeEvent>) {
        match self.dissector.parse(chunk.payload, &chunk.context) {
            Some(ProtocolData::Dhcp(DhcpFields {
                op,
                xid,
                client_mac,
                ciaddr,
                yiaddr,
                siaddr,
                giaddr,
                message_type,
                hostname,
                client_id,
                vendor_class,
                requested_ip,
                server_id,
            })) => {
                let envelope = build_envelope(
                    &chunk.context,
                    chunk.interface_id,
                    chunk.frame_index,
                    chunk.timestamp,
                    chunk.segment_hash,
                    TransportProtocol::Udp,
                    Some("dhcp"),
                    chunk.captured_len,
                    chunk.session_key.clone(),
                );
                let operation = dhcp_message_type_name(message_type);
                let mut attributes = BTreeMap::new();
                attributes.insert("xid".to_string(), format!("{xid:#010x}"));
                attributes.insert("bootp_op".to_string(), op.to_string());
                if let Some(ip) = requested_ip.clone() {
                    attributes.insert("requested_ip".to_string(), ip);
                }
                if let Some(ip) = yiaddr.clone() {
                    attributes.insert("your_ip".to_string(), ip);
                }
                if let Some(ip) = server_id.clone() {
                    attributes.insert("server_id".to_string(), ip);
                }
                if let Some(ip) = giaddr.clone() {
                    attributes.insert("relay_ip".to_string(), ip);
                }
                if let Some(vendor_class) = vendor_class.clone() {
                    attributes.insert("vendor_class".to_string(), vendor_class);
                }
                out.push(new_event(
                    chunk.capture_id.to_string(),
                    envelope.clone(),
                    BronzeEventFamily::ProtocolTransaction(ProtocolTransaction {
                        operation: operation.to_string(),
                        status: dhcp_status(&chunk.context).to_string(),
                        request_summary: hostname.as_ref().map(|name| format!("{name} via DHCP")),
                        response_summary: yiaddr.clone(),
                        object_refs: requested_ip
                            .clone()
                            .or_else(|| yiaddr.clone())
                            .into_iter()
                            .collect(),
                        values: Vec::new(),
                        attributes,
                                        modbus: None,
}),
                ));

                let mut identifiers =
                    BTreeMap::from([("mac".to_string(), format_mac(&client_mac))]);
                if let Some(ip) = yiaddr.clone().or(ciaddr.clone()).or(requested_ip.clone()) {
                    identifiers.insert("ip".to_string(), ip);
                }
                if let Some(client_id) = client_id.clone() {
                    identifiers.insert("client_id".to_string(), client_id);
                }
                if let Some(vendor_class) = vendor_class.clone() {
                    identifiers.insert("vendor_class".to_string(), vendor_class);
                }
                let hostnames = hostname.clone().into_iter().collect();
                out.push(new_event(
                    chunk.capture_id.to_string(),
                    envelope.clone(),
                    BronzeEventFamily::AssetObservation(AssetObservation {
                        asset_key: format_mac(&client_mac),
                        role: None,
                        vendor: None,
                        model: None,
                        firmware: None,
                        hostnames,
                        protocols: vec!["dhcp".to_string()],
                        identifiers,
                    }),
                ));

                if let Some(server_ip) = server_id.clone().or(siaddr.clone()) {
                    out.push(new_event(
                        chunk.capture_id.to_string(),
                        envelope.clone(),
                        BronzeEventFamily::AssetObservation(AssetObservation {
                            asset_key: server_ip.clone(),
                            role: Some("server".to_string()),
                            vendor: None,
                            model: None,
                            firmware: None,
                            hostnames: Vec::new(),
                            protocols: vec!["dhcp".to_string()],
                            identifiers: BTreeMap::from([("ip".to_string(), server_ip)]),
                        }),
                    ));
                }

                if server_id.is_some() || giaddr.is_some() {
                    let mut metadata = BTreeMap::new();
                    if let Some(ip) = yiaddr.or(requested_ip) {
                        metadata.insert("lease_ip".to_string(), ip);
                    }
                    if let Some(ip) = giaddr.clone() {
                        metadata.insert("relay_ip".to_string(), ip);
                    }
                    out.push(new_event(
                        chunk.capture_id.to_string(),
                        envelope,
                        BronzeEventFamily::TopologyObservation(TopologyObservation {
                            observation_type: "dhcp_lease".to_string(),
                            local_id: format_mac(&client_mac),
                            remote_id: server_id.or(giaddr),
                            description: Some(operation.to_string()),
                            capabilities: Vec::new(),
                            metadata,
                        }),
                    ));
                }
            }
            _ => out.push(parse_anomaly_event(
                chunk.capture_id.to_string(),
                build_envelope(
                    &chunk.context,
                    chunk.interface_id,
                    chunk.frame_index,
                    chunk.timestamp,
                    chunk.segment_hash,
                    TransportProtocol::Udp,
                    Some("dhcp"),
                    chunk.captured_len,
                    chunk.session_key.clone(),
                ),
                self.name(),
                "medium",
                "failed to parse dhcp payload",
                chunk.payload,
            )),
        }
    }
}

#[derive(Default)]
struct SnmpDecoder {
    dissector: SnmpDissector,
}

impl SessionDecoder for SnmpDecoder {
    fn name(&self) -> &'static str {
        "snmp"
    }

    fn interest(&self) -> &'static [DecoderInterest] {
        &[DecoderInterest::UdpPort(161), DecoderInterest::UdpPort(162)]
    }

    fn on_datagram(&mut self, chunk: &StreamChunk<'_>, out: &mut Vec<BronzeEvent>) {
        match self.dissector.parse(chunk.payload, &chunk.context) {
            Some(ProtocolData::Snmp(SnmpFields {
                version,
                pdu_type,
                request_id,
                var_binds,
                sys_name,
                sys_descr,
                sys_object_id,
                engine_id,
                ..
            })) => {
                let envelope = build_envelope(
                    &chunk.context,
                    chunk.interface_id,
                    chunk.frame_index,
                    chunk.timestamp,
                    chunk.segment_hash,
                    TransportProtocol::Udp,
                    Some("snmp"),
                    chunk.captured_len,
                    chunk.session_key.clone(),
                );
                let mut attributes = BTreeMap::from([("version".to_string(), version.clone())]);
                if let Some(id) = request_id {
                    attributes.insert("request_id".to_string(), id.to_string());
                }
                if let Some(engine_id) = engine_id.clone() {
                    attributes.insert("engine_id".to_string(), engine_id);
                }
                out.push(new_event(
                    chunk.capture_id.to_string(),
                    envelope.clone(),
                    BronzeEventFamily::ProtocolTransaction(ProtocolTransaction {
                        operation: normalize_operation_name(&pdu_type, "snmp_message"),
                        status: snmp_status(&pdu_type),
                        request_summary: (!var_binds.is_empty()).then(|| {
                            var_binds
                                .iter()
                                .map(|vb| vb.oid.clone())
                                .collect::<Vec<_>>()
                                .join(", ")
                        }),
                        response_summary: sys_name.clone().or(sys_descr.clone()),
                        object_refs: var_binds.iter().map(|vb| vb.oid.clone()).collect(),
                        values: var_binds
                            .iter()
                            .map(|vb| ObjectValue {
                                object_ref: vb.oid.clone(),
                                value: vb.value.clone(),
                            })
                            .collect(),
                        attributes,
                                        modbus: None,
}),
                ));

                if sys_name.is_some()
                    || sys_descr.is_some()
                    || sys_object_id.is_some()
                    || engine_id.is_some()
                {
                    let asset_ip = if chunk.context.src_port == 161 || chunk.context.src_port == 162
                    {
                        chunk.context.src_ip.to_string()
                    } else {
                        chunk.context.dst_ip.to_string()
                    };
                    let mut identifiers = BTreeMap::from([("ip".to_string(), asset_ip.clone())]);
                    if let Some(object_id) = sys_object_id.clone() {
                        identifiers.insert("sys_object_id".to_string(), object_id);
                    }
                    if let Some(engine_id) = engine_id {
                        identifiers.insert("engine_id".to_string(), engine_id);
                    }
                    if let Some(sys_descr) = sys_descr.clone() {
                        identifiers.insert("sys_descr".to_string(), sys_descr);
                    }
                    out.push(new_event(
                        chunk.capture_id.to_string(),
                        envelope,
                        BronzeEventFamily::AssetObservation(AssetObservation {
                            asset_key: asset_ip,
                            role: None,
                            vendor: None,
                            model: None,
                            firmware: None,
                            hostnames: sys_name.into_iter().collect(),
                            protocols: vec!["snmp".to_string()],
                            identifiers,
                        }),
                    ));
                }
            }
            _ => out.push(parse_anomaly_event(
                chunk.capture_id.to_string(),
                build_envelope(
                    &chunk.context,
                    chunk.interface_id,
                    chunk.frame_index,
                    chunk.timestamp,
                    chunk.segment_hash,
                    TransportProtocol::Udp,
                    Some("snmp"),
                    chunk.captured_len,
                    chunk.session_key.clone(),
                ),
                self.name(),
                "medium",
                "failed to parse snmp payload",
                chunk.payload,
            )),
        }
    }
}

#[derive(Default)]
struct HttpDecoder {
    dissector: HttpDissector,
}

impl SessionDecoder for HttpDecoder {
    fn name(&self) -> &'static str {
        "http"
    }

    fn interest(&self) -> &'static [DecoderInterest] {
        &[DecoderInterest::TcpPort(80), DecoderInterest::TcpPort(8080)]
    }

    fn on_stream_chunk(&mut self, chunk: &StreamChunk<'_>, out: &mut Vec<BronzeEvent>) {
        if chunk.payload.is_empty() {
            return;
        }
        match self.dissector.parse(chunk.payload, &chunk.context) {
            Some(ProtocolData::Http(HttpFields {
                method,
                host,
                uri,
                status_code,
                content_type,
                content_length,
            })) => {
                let mut attributes = BTreeMap::new();
                attributes.insert("content_type".to_string(), content_type);
                attributes.insert("content_length".to_string(), content_length.to_string());
                if !host.is_empty() {
                    attributes.insert("host".to_string(), host);
                }
                let is_request = !method.is_empty();
                let operation = if is_request {
                    method.clone()
                } else {
                    "response".to_string()
                };
                out.push(new_event(
                    chunk.capture_id.to_string(),
                    build_envelope(
                        &chunk.context,
                        chunk.interface_id,
                        chunk.frame_index,
                        chunk.timestamp,
                        chunk.segment_hash,
                        TransportProtocol::Tcp,
                        Some("http"),
                        chunk.captured_len,
                        chunk.session_key.clone(),
                    ),
                    BronzeEventFamily::ProtocolTransaction(ProtocolTransaction {
                        operation,
                        status: if status_code > 0 {
                            status_code.to_string()
                        } else {
                            "request".to_string()
                        },
                        request_summary: is_request.then_some(uri.clone()),
                        response_summary: (status_code > 0).then_some(status_code.to_string()),
                        object_refs: (!uri.is_empty()).then_some(uri).into_iter().collect(),
                        values: Vec::new(),
                        attributes,
                                        modbus: None,
}),
                ));
            }
            _ => {}
        }
    }
}

struct TlsDecoder;

impl SessionDecoder for TlsDecoder {
    fn name(&self) -> &'static str {
        "tls"
    }

    fn interest(&self) -> &'static [DecoderInterest] {
        &[
            DecoderInterest::TcpPort(443),
            DecoderInterest::TcpPort(4840),
        ]
    }

    fn on_stream_chunk(&mut self, chunk: &StreamChunk<'_>, out: &mut Vec<BronzeEvent>) {
        let Some(tls) = parse_tls_client_hello(chunk.payload) else {
            return;
        };
        let mut attributes = BTreeMap::new();
        attributes.insert("version".to_string(), tls.version.clone());
        if let Some(ref cipher) = tls.cipher_suite {
            attributes.insert("cipher_suite".to_string(), cipher.clone());
        }
        let envelope = build_envelope(
            &chunk.context,
            chunk.interface_id,
            chunk.frame_index,
            chunk.timestamp,
            chunk.segment_hash,
            TransportProtocol::Tcp,
            Some("tls"),
            chunk.captured_len,
            chunk.session_key.clone(),
        );
        out.push(new_event(
            chunk.capture_id.to_string(),
            envelope.clone(),
            BronzeEventFamily::ProtocolTransaction(ProtocolTransaction {
                operation: "client_hello".to_string(),
                status: "observed".to_string(),
                request_summary: tls.sni.clone(),
                response_summary: None,
                object_refs: tls.sni.clone().into_iter().collect(),
                values: Vec::new(),
                attributes,
                        modbus: None,
}),
        ));
        if let Some(sni) = tls.sni {
            out.push(new_event(
                chunk.capture_id.to_string(),
                envelope,
                BronzeEventFamily::AssetObservation(AssetObservation {
                    asset_key: chunk.context.dst_ip.to_string(),
                    role: None,
                    vendor: None,
                    model: None,
                    firmware: None,
                    hostnames: vec![sni],
                    protocols: vec!["tls".to_string()],
                    identifiers: BTreeMap::from([(
                        "ip".to_string(),
                        chunk.context.dst_ip.to_string(),
                    )]),
                }),
            ));
        }
    }
}

#[derive(Default)]
struct Dnp3DecoderWrapper {
    dissector: Dnp3Dissector,
}

impl SessionDecoder for Dnp3DecoderWrapper {
    fn name(&self) -> &'static str {
        "dnp3"
    }

    fn interest(&self) -> &'static [DecoderInterest] {
        &[DecoderInterest::TcpPort(20000)]
    }

    fn on_stream_chunk(&mut self, chunk: &StreamChunk<'_>, out: &mut Vec<BronzeEvent>) {
        match self.dissector.parse(chunk.payload, &chunk.context) {
            Some(ProtocolData::Dnp3(Dnp3Fields {
                source_address,
                destination_address,
                function_code,
                application_data,
            })) => {
                let operation = dnp3_function_name(function_code);
                let envelope = build_envelope(
                    &chunk.context,
                    chunk.interface_id,
                    chunk.frame_index,
                    chunk.timestamp,
                    chunk.segment_hash,
                    TransportProtocol::Tcp,
                    Some("dnp3"),
                    chunk.captured_len,
                    chunk.session_key.clone(),
                );
                let mut attributes = BTreeMap::new();
                attributes.insert("source_address".to_string(), source_address.to_string());
                attributes.insert(
                    "destination_address".to_string(),
                    destination_address.to_string(),
                );
                out.push(new_event(
                    chunk.capture_id.to_string(),
                    envelope.clone(),
                    BronzeEventFamily::ProtocolTransaction(ProtocolTransaction {
                        operation: operation.to_string(),
                        status: if function_code >= 0x80 {
                            "response".to_string()
                        } else {
                            "request".to_string()
                        },
                        request_summary: Some(format!(
                            "{operation} {source_address}->{destination_address}"
                        )),
                        response_summary: None,
                        object_refs: vec![format!("dnp3_fc:{function_code:#04x}")],
                        values: Vec::new(),
                        attributes,
                                        modbus: None,
}),
                ));
                for event in dnp3_role_observations(
                    chunk.capture_id,
                    &envelope,
                    &chunk.context,
                    source_address,
                    destination_address,
                    function_code,
                ) {
                    out.push(event);
                }
                if is_dnp3_artifact(function_code) && !application_data.is_empty() {
                    out.push(artifact_event(
                        chunk.capture_id.to_string(),
                        envelope,
                        "dnp3_application_data",
                        &format!("{}:{function_code:#04x}", chunk.session_key),
                        Some("application/octet-stream"),
                        Some("DNP3 application payload"),
                        &application_data,
                    ));
                }
            }
            _ => out.push(parse_anomaly_event(
                chunk.capture_id.to_string(),
                build_envelope(
                    &chunk.context,
                    chunk.interface_id,
                    chunk.frame_index,
                    chunk.timestamp,
                    chunk.segment_hash,
                    TransportProtocol::Tcp,
                    Some("dnp3"),
                    chunk.captured_len,
                    chunk.session_key.clone(),
                ),
                self.name(),
                "medium",
                "failed to parse dnp3 payload",
                chunk.payload,
            )),
        }
    }
}

#[derive(Default)]
struct Iec104DecoderWrapper;

impl SessionDecoder for Iec104DecoderWrapper {
    fn name(&self) -> &'static str {
        "iec104"
    }

    fn interest(&self) -> &'static [DecoderInterest] {
        &[DecoderInterest::TcpPort(2404)]
    }

    fn on_stream_chunk(&mut self, chunk: &StreamChunk<'_>, out: &mut Vec<BronzeEvent>) {
        let frames = parse_iec104_frames(chunk.payload);
        if frames.is_empty() {
            out.push(parse_anomaly_event(
                chunk.capture_id.to_string(),
                build_envelope(
                    &chunk.context,
                    chunk.interface_id,
                    chunk.frame_index,
                    chunk.timestamp,
                    chunk.segment_hash,
                    TransportProtocol::Tcp,
                    Some("iec104"),
                    chunk.captured_len,
                    chunk.session_key.clone(),
                ),
                self.name(),
                "medium",
                "failed to parse iec104 payload",
                chunk.payload,
            ));
            return;
        }

        for fields in frames {
            let Iec104Fields {
                frame_type,
                send_sequence,
                receive_sequence,
                u_format,
                type_id,
                cause_of_transmission,
                common_address,
                information_object_address,
                payload,
            } = fields;

            let envelope = build_envelope(
                &chunk.context,
                chunk.interface_id,
                chunk.frame_index,
                chunk.timestamp,
                chunk.segment_hash,
                TransportProtocol::Tcp,
                Some("iec104"),
                chunk.captured_len,
                chunk.session_key.clone(),
            );
            let mut attributes = BTreeMap::new();
            attributes.insert("frame_type".to_string(), frame_type.clone());
            if let Some(send_sequence) = send_sequence {
                attributes.insert("send_sequence".to_string(), send_sequence.to_string());
            }
            if let Some(receive_sequence) = receive_sequence {
                attributes.insert("receive_sequence".to_string(), receive_sequence.to_string());
            }
            if let Some(type_id) = type_id {
                attributes.insert("type_id".to_string(), type_id.to_string());
                attributes.insert(
                    "type_name".to_string(),
                    iec104_type_name(type_id).to_string(),
                );
            }
            if let Some(cause) = cause_of_transmission {
                attributes.insert("cause".to_string(), cause.to_string());
                attributes.insert(
                    "cause_name".to_string(),
                    iec104_cause_name(cause).to_string(),
                );
            }
            if let Some(common_address) = common_address {
                attributes.insert("common_address".to_string(), common_address.to_string());
            }
            if let Some(ioa) = information_object_address {
                attributes.insert("information_object_address".to_string(), ioa.to_string());
            }
            if let Some(u_format) = &u_format {
                attributes.insert("u_format".to_string(), u_format.clone());
            }

            let operation = iec104_operation_name(&frame_type, type_id, u_format.as_deref());

            out.push(new_event(
                chunk.capture_id.to_string(),
                envelope.clone(),
                BronzeEventFamily::ProtocolTransaction(ProtocolTransaction {
                    operation,
                    status: iec104_status(
                        &frame_type,
                        u_format.as_deref(),
                        cause_of_transmission,
                        &chunk.context,
                    )
                    .to_string(),
                    request_summary: Some(iec104_summary(
                        &frame_type,
                        type_id,
                        cause_of_transmission,
                        common_address,
                    )),
                    response_summary: None,
                    object_refs: iec104_object_refs(
                        type_id,
                        common_address,
                        information_object_address,
                    ),
                    values: Vec::new(),
                    attributes,
                                modbus: None,
}),
            ));

            for event in iec104_role_observations(
                chunk.capture_id,
                &envelope,
                &chunk.context,
                &frame_type,
                common_address,
            ) {
                out.push(event);
            }

            if !payload.is_empty() {
                out.push(artifact_event(
                    chunk.capture_id.to_string(),
                    envelope,
                    "iec104_asdu",
                    &format!("{}:{}", chunk.session_key, chunk.frame_index),
                    Some("application/octet-stream"),
                    Some("IEC 60870-5-104 ASDU payload"),
                    &payload,
                ));
            }
        }
    }
}

#[derive(Default)]
struct OmronFinsDecoder {
    dissector: OmronFinsDissector,
}

impl SessionDecoder for OmronFinsDecoder {
    fn name(&self) -> &'static str {
        "omron_fins"
    }

    fn interest(&self) -> &'static [DecoderInterest] {
        static INTERESTS: [DecoderInterest; 2] = [
            DecoderInterest::UdpPort(9600),
            DecoderInterest::TcpPort(9600),
        ];
        &INTERESTS
    }

    fn on_datagram(&mut self, chunk: &StreamChunk<'_>, out: &mut Vec<BronzeEvent>) {
        self.handle(chunk, TransportProtocol::Udp, out);
    }

    fn on_stream_chunk(&mut self, chunk: &StreamChunk<'_>, out: &mut Vec<BronzeEvent>) {
        self.handle(chunk, TransportProtocol::Tcp, out);
    }
}

impl OmronFinsDecoder {
    fn handle(
        &mut self,
        chunk: &StreamChunk<'_>,
        transport: TransportProtocol,
        out: &mut Vec<BronzeEvent>,
    ) {
        if !self.dissector.can_parse(
            chunk.payload,
            chunk.context.src_port,
            chunk.context.dst_port,
        ) {
            return;
        }

        match self.dissector.parse(chunk.payload, &chunk.context) {
            Some(ProtocolData::OmronFins(fields)) => {
                self.emit_fields(chunk, transport, fields, out)
            }
            _ => out.push(parse_anomaly_event(
                chunk.capture_id.to_string(),
                build_envelope(
                    &chunk.context,
                    chunk.interface_id,
                    chunk.frame_index,
                    chunk.timestamp,
                    chunk.segment_hash,
                    transport,
                    Some("omron_fins"),
                    chunk.captured_len,
                    chunk.session_key.clone(),
                ),
                self.name(),
                "medium",
                "failed to parse omron fins payload",
                chunk.payload,
            )),
        }
    }

    fn emit_fields(
        &self,
        chunk: &StreamChunk<'_>,
        transport: TransportProtocol,
        fields: OmronFinsFields,
        out: &mut Vec<BronzeEvent>,
    ) {
        let OmronFinsFields {
            frame_variant,
            tcp_command,
            tcp_error_code,
            icf,
            rsv,
            gateway_count,
            destination_network,
            destination_node,
            destination_unit,
            source_network,
            source_node,
            source_unit,
            service_id,
            command_code,
            command_name,
            memory_area,
            memory_word,
            memory_bit,
            item_count,
            payload,
        } = fields;

        let envelope = build_envelope(
            &chunk.context,
            chunk.interface_id,
            chunk.frame_index,
            chunk.timestamp,
            chunk.segment_hash,
            transport,
            Some("omron_fins"),
            chunk.captured_len,
            chunk.session_key.clone(),
        );

        let mut attributes = BTreeMap::new();
        attributes.insert("frame_variant".to_string(), frame_variant.clone());
        if let Some(tcp_command) = tcp_command {
            attributes.insert("tcp_command".to_string(), format!("{tcp_command:#010x}"));
        }
        if let Some(tcp_error_code) = tcp_error_code {
            attributes.insert(
                "tcp_error_code".to_string(),
                format!("{tcp_error_code:#010x}"),
            );
        }
        if let Some(icf) = icf {
            attributes.insert("icf".to_string(), format!("{icf:#04x}"));
        }
        if let Some(rsv) = rsv {
            attributes.insert("rsv".to_string(), format!("{rsv:#04x}"));
        }
        if let Some(gateway_count) = gateway_count {
            attributes.insert("gateway_count".to_string(), gateway_count.to_string());
        }
        if let Some(service_id) = service_id {
            attributes.insert("service_id".to_string(), format!("{service_id:#04x}"));
        }
        if let Some(command_code) = command_code {
            attributes.insert("command_code".to_string(), format!("{command_code:#06x}"));
        }
        if let Some(command_name) = &command_name {
            attributes.insert("command_name".to_string(), command_name.clone());
        }
        if let Some(memory_area) = memory_area {
            attributes.insert("memory_area".to_string(), format!("{memory_area:#04x}"));
        }
        if let Some(memory_word) = memory_word {
            attributes.insert("memory_word".to_string(), memory_word.to_string());
        }
        if let Some(memory_bit) = memory_bit {
            attributes.insert("memory_bit".to_string(), memory_bit.to_string());
        }
        if let Some(item_count) = item_count {
            attributes.insert("item_count".to_string(), item_count.to_string());
        }
        if let Some(destination_network) = destination_network {
            attributes.insert(
                "destination_network".to_string(),
                destination_network.to_string(),
            );
        }
        if let Some(destination_node) = destination_node {
            attributes.insert("destination_node".to_string(), destination_node.to_string());
        }
        if let Some(destination_unit) = destination_unit {
            attributes.insert("destination_unit".to_string(), destination_unit.to_string());
        }
        if let Some(source_network) = source_network {
            attributes.insert("source_network".to_string(), source_network.to_string());
        }
        if let Some(source_node) = source_node {
            attributes.insert("source_node".to_string(), source_node.to_string());
        }
        if let Some(source_unit) = source_unit {
            attributes.insert("source_unit".to_string(), source_unit.to_string());
        }

        let operation = omron_fins_operation_name(command_name.as_deref(), command_code);
        out.push(new_event(
            chunk.capture_id.to_string(),
            envelope.clone(),
            BronzeEventFamily::ProtocolTransaction(ProtocolTransaction {
                operation,
                status: omron_fins_status(&chunk.context).to_string(),
                request_summary: Some(omron_fins_summary(
                    command_name.as_deref(),
                    source_node,
                    destination_node,
                )),
                response_summary: None,
                object_refs: omron_fins_object_refs(
                    memory_area,
                    memory_word,
                    memory_bit,
                    item_count,
                ),
                values: Vec::new(),
                attributes,
                        modbus: None,
}),
        ));

        if source_node.is_some() || source_network.is_some() || source_unit.is_some() {
            let mut identifiers = BTreeMap::new();
            identifiers.insert("ip".to_string(), chunk.context.src_ip.to_string());
            if let Some(network) = source_network {
                identifiers.insert("fins_network".to_string(), network.to_string());
            }
            if let Some(node) = source_node {
                identifiers.insert("fins_node".to_string(), node.to_string());
            }
            if let Some(unit) = source_unit {
                identifiers.insert("fins_unit".to_string(), unit.to_string());
            }
            out.push(new_event(
                chunk.capture_id.to_string(),
                envelope.clone(),
                BronzeEventFamily::AssetObservation(AssetObservation {
                    asset_key: chunk.context.src_ip.to_string(),
                    role: omron_fins_source_role(&chunk.context).map(str::to_string),
                    vendor: Some("OMRON".to_string()),
                    model: None,
                    firmware: None,
                    hostnames: Vec::new(),
                    protocols: vec!["omron_fins".to_string()],
                    identifiers,
                }),
            ));
        }

        if destination_node.is_some() || destination_network.is_some() || destination_unit.is_some()
        {
            let mut identifiers = BTreeMap::new();
            identifiers.insert("ip".to_string(), chunk.context.dst_ip.to_string());
            if let Some(network) = destination_network {
                identifiers.insert("fins_network".to_string(), network.to_string());
            }
            if let Some(node) = destination_node {
                identifiers.insert("fins_node".to_string(), node.to_string());
            }
            if let Some(unit) = destination_unit {
                identifiers.insert("fins_unit".to_string(), unit.to_string());
            }
            out.push(new_event(
                chunk.capture_id.to_string(),
                envelope.clone(),
                BronzeEventFamily::AssetObservation(AssetObservation {
                    asset_key: chunk.context.dst_ip.to_string(),
                    role: omron_fins_destination_role(&chunk.context).map(str::to_string),
                    vendor: Some("OMRON".to_string()),
                    model: None,
                    firmware: None,
                    hostnames: Vec::new(),
                    protocols: vec!["omron_fins".to_string()],
                    identifiers,
                }),
            ));
        }

        out.push(new_event(
            chunk.capture_id.to_string(),
            envelope.clone(),
            BronzeEventFamily::TopologyObservation(TopologyObservation {
                observation_type: "omron_fins_transaction".to_string(),
                local_id: chunk.context.src_ip.to_string(),
                remote_id: Some(chunk.context.dst_ip.to_string()),
                description: command_name.clone(),
                capabilities: Vec::new(),
                metadata: BTreeMap::from([("frame_variant".to_string(), frame_variant)]),
            }),
        ));

        if !payload.is_empty() {
            out.push(artifact_event(
                chunk.capture_id.to_string(),
                envelope,
                "omron_fins_payload",
                &format!("{}:{}", chunk.session_key, chunk.frame_index),
                Some("application/octet-stream"),
                Some("OMRON FINS command payload"),
                &payload,
            ));
        }
    }
}

#[derive(Default)]
struct HartIpDecoderWrapper {
    dissector: HartIpDissector,
}

impl SessionDecoder for HartIpDecoderWrapper {
    fn name(&self) -> &'static str {
        "hart_ip"
    }

    fn interest(&self) -> &'static [DecoderInterest] {
        static INTERESTS: [DecoderInterest; 2] = [
            DecoderInterest::TcpPort(5094),
            DecoderInterest::UdpPort(5094),
        ];
        &INTERESTS
    }

    fn on_datagram(&mut self, chunk: &StreamChunk<'_>, out: &mut Vec<BronzeEvent>) {
        if !self.dissector.can_parse(
            chunk.payload,
            chunk.context.src_port,
            chunk.context.dst_port,
        ) {
            return;
        }

        match self.dissector.parse(chunk.payload, &chunk.context) {
            Some(ProtocolData::HartIp(fields)) => {
                self.emit_frame(chunk, TransportProtocol::Udp, fields, out)
            }
            _ => out.push(parse_anomaly_event(
                chunk.capture_id.to_string(),
                build_envelope(
                    &chunk.context,
                    chunk.interface_id,
                    chunk.frame_index,
                    chunk.timestamp,
                    chunk.segment_hash,
                    TransportProtocol::Udp,
                    Some("hart_ip"),
                    chunk.captured_len,
                    chunk.session_key.clone(),
                ),
                self.name(),
                "medium",
                "failed to parse hart ip payload",
                chunk.payload,
            )),
        }
    }

    fn on_stream_chunk(&mut self, chunk: &StreamChunk<'_>, out: &mut Vec<BronzeEvent>) {
        if !self.dissector.can_parse(
            chunk.payload,
            chunk.context.src_port,
            chunk.context.dst_port,
        ) {
            return;
        }

        let frames = parse_hart_ip_frames(chunk.payload);
        if frames.is_empty() {
            out.push(parse_anomaly_event(
                chunk.capture_id.to_string(),
                build_envelope(
                    &chunk.context,
                    chunk.interface_id,
                    chunk.frame_index,
                    chunk.timestamp,
                    chunk.segment_hash,
                    TransportProtocol::Tcp,
                    Some("hart_ip"),
                    chunk.captured_len,
                    chunk.session_key.clone(),
                ),
                self.name(),
                "medium",
                "failed to parse hart ip payload",
                chunk.payload,
            ));
            return;
        }

        for fields in frames {
            self.emit_frame(chunk, TransportProtocol::Tcp, fields, out);
        }
    }
}

impl HartIpDecoderWrapper {
    fn emit_frame(
        &self,
        chunk: &StreamChunk<'_>,
        transport: TransportProtocol,
        fields: HartIpFields,
        out: &mut Vec<BronzeEvent>,
    ) {
        let envelope = build_envelope(
            &chunk.context,
            chunk.interface_id,
            chunk.frame_index,
            chunk.timestamp,
            chunk.segment_hash,
            transport,
            Some("hart_ip"),
            chunk.captured_len,
            chunk.session_key.clone(),
        );

        let mut attributes = BTreeMap::new();
        attributes.insert("version".to_string(), fields.version.to_string());
        attributes.insert("message_type".to_string(), fields.message_type.clone());
        attributes.insert("message_id".to_string(), fields.message_id.clone());
        attributes.insert("status".to_string(), format!("{:#04x}", fields.status));
        attributes.insert(
            "transaction_id".to_string(),
            fields.transaction_id.to_string(),
        );
        attributes.insert(
            "message_length".to_string(),
            fields.message_length.to_string(),
        );

        let mut object_refs = Vec::new();
        let mut device_identity = None;
        let mut device_tag = None;
        let body_summary = match &fields.body {
            HartIpBody::SessionInitiate {
                master_type,
                inactivity_close_timer,
            } => {
                attributes.insert("master_type".to_string(), master_type.clone());
                attributes.insert(
                    "inactivity_close_timer".to_string(),
                    inactivity_close_timer.to_string(),
                );
                Some(format!("session_initiate {master_type}"))
            }
            HartIpBody::SessionClose => Some("session_close".to_string()),
            HartIpBody::KeepAlive => Some("keep_alive".to_string()),
            HartIpBody::Error { error_code, .. } => {
                if let Some(error_code) = error_code {
                    attributes.insert("error_code".to_string(), format!("{error_code:#04x}"));
                }
                Some("error".to_string())
            }
            HartIpBody::PassThrough(pass) => {
                attributes.insert("frame_type".to_string(), pass.frame_type.clone());
                attributes.insert(
                    "physical_layer_type".to_string(),
                    pass.physical_layer_type.clone(),
                );
                attributes.insert("address_type".to_string(), pass.address_type.clone());
                attributes.insert("command".to_string(), pass.command.to_string());
                attributes.insert("payload_length".to_string(), pass.payload.len().to_string());
                object_refs.push(format!("hart_command:{}", pass.command));
                if let Some(identity) = &pass.identity {
                    if let Some(manufacturer_id) = identity.manufacturer_id {
                        object_refs.push(format!("hart_manufacturer:{manufacturer_id}"));
                    }
                    if let Some(device_type) = identity.device_type {
                        object_refs.push(format!("hart_device_type:{device_type}"));
                    }
                    device_tag = identity.tag.clone();
                    device_identity = Some(identity.clone());
                }
                Some(format!(
                    "{} {}",
                    pass.frame_type,
                    hart_passthrough_command_name(pass.command)
                ))
            }
            HartIpBody::Raw(body) => Some(format!("raw {} bytes", body.len())),
        };

        out.push(new_event(
            chunk.capture_id.to_string(),
            envelope.clone(),
            BronzeEventFamily::ProtocolTransaction(ProtocolTransaction {
                operation: hart_ip_operation_name(&fields),
                status: hart_ip_status(&fields).to_string(),
                request_summary: body_summary,
                response_summary: None,
                object_refs,
                values: Vec::new(),
                attributes,
                        modbus: None,
}),
        ));

        if let Some(identity) = device_identity {
            let mut identifiers = BTreeMap::new();
            identifiers.insert(
                "ip".to_string(),
                hart_ip_device_asset_key(&chunk.context, &fields).to_string(),
            );
            if let Some(manufacturer_id) = identity.manufacturer_id {
                identifiers.insert(
                    "hart_manufacturer_id".to_string(),
                    manufacturer_id.to_string(),
                );
            }
            if let Some(device_type) = identity.device_type {
                identifiers.insert("hart_device_type".to_string(), device_type.to_string());
            }
            if let Some(tag) = &identity.tag {
                identifiers.insert("hart_tag".to_string(), tag.clone());
            }
            if let Some(revision) = identity.hart_universal_revision {
                identifiers.insert("hart_universal_revision".to_string(), revision.to_string());
            }
            if let Some(revision) = identity.device_revision {
                identifiers.insert("hart_device_revision".to_string(), revision.to_string());
            }
            if let Some(revision) = identity.software_revision {
                identifiers.insert("hart_software_revision".to_string(), revision.to_string());
            }
            if let Some(revision) = identity.hardware_revision {
                identifiers.insert("hart_hardware_revision".to_string(), revision.to_string());
            }
            if let Some(counter) = identity.configuration_change_counter {
                identifiers.insert(
                    "hart_configuration_change_counter".to_string(),
                    counter.to_string(),
                );
            }
            if let Some(status) = identity.extended_device_status {
                identifiers.insert(
                    "hart_extended_device_status".to_string(),
                    status.to_string(),
                );
            }
            if let Some(device_id) = identity.device_id {
                identifiers.insert("hart_device_id".to_string(), hex::encode(device_id));
            }
            out.push(new_event(
                chunk.capture_id.to_string(),
                envelope.clone(),
                BronzeEventFamily::AssetObservation(AssetObservation {
                    asset_key: hart_ip_device_asset_key(&chunk.context, &fields),
                    role: Some("field_device".to_string()),
                    vendor: None,
                    model: identity
                        .device_type
                        .map(|device_type| format!("device_type_{device_type}")),
                    firmware: identity
                        .software_revision
                        .map(|revision| revision.to_string()),
                    hostnames: device_tag.into_iter().collect(),
                    protocols: vec!["hart_ip".to_string()],
                    identifiers,
                }),
            ));
        }

        if matches!(fields.body, HartIpBody::SessionInitiate { .. }) {
            out.push(new_event(
                chunk.capture_id.to_string(),
                envelope.clone(),
                BronzeEventFamily::AssetObservation(AssetObservation {
                    asset_key: context_asset_key(&chunk.context),
                    role: Some("host".to_string()),
                    vendor: None,
                    model: None,
                    firmware: None,
                    hostnames: Vec::new(),
                    protocols: vec!["hart_ip".to_string()],
                    identifiers: BTreeMap::from([(
                        "ip".to_string(),
                        chunk.context.src_ip.to_string(),
                    )]),
                }),
            ));
        }

        out.push(new_event(
            chunk.capture_id.to_string(),
            envelope.clone(),
            BronzeEventFamily::TopologyObservation(TopologyObservation {
                observation_type: "hart_ip_transaction".to_string(),
                local_id: context_asset_key(&chunk.context),
                remote_id: Some(context_remote_asset_key(&chunk.context)),
                description: Some(fields.message_id.clone()),
                capabilities: Vec::new(),
                metadata: BTreeMap::from([(
                    "message_type".to_string(),
                    fields.message_type.clone(),
                )]),
            }),
        ));

        if !fields.payload.is_empty() {
            out.push(artifact_event(
                chunk.capture_id.to_string(),
                envelope,
                "hart_ip_payload",
                &format!("{}:{}", chunk.session_key, fields.transaction_id),
                Some("application/octet-stream"),
                Some("HART-IP message payload"),
                &fields.payload,
            ));
        }
    }
}

#[derive(Default)]
struct Iec61850DecoderWrapper {
    dissector: Iec61850Dissector,
}

impl SessionDecoder for Iec61850DecoderWrapper {
    fn name(&self) -> &'static str {
        "iec61850"
    }

    fn interest(&self) -> &'static [DecoderInterest] {
        static INTERESTS: [DecoderInterest; 3] = [
            DecoderInterest::TcpPort(IEC61850_MMS_PORT),
            DecoderInterest::EtherType(IEC61850_GOOSE_ETHERTYPE),
            DecoderInterest::EtherType(IEC61850_SV_ETHERTYPE),
        ];
        &INTERESTS
    }

    fn on_datagram(&mut self, chunk: &StreamChunk<'_>, out: &mut Vec<BronzeEvent>) {
        let ethertype = chunk.ethertype;
        if !self.dissector.can_parse(
            chunk.payload,
            chunk.context.src_port,
            chunk.context.dst_port,
            Some(ethertype),
        ) {
            return;
        }

        match self.dissector.parse(
            chunk.payload,
            chunk.context.src_port,
            chunk.context.dst_port,
            Some(ethertype),
        ) {
            Some(fields) => self.emit_fields(chunk, TransportProtocol::Ethernet, fields, out),
            None => out.push(parse_anomaly_event(
                chunk.capture_id.to_string(),
                build_envelope(
                    &chunk.context,
                    chunk.interface_id,
                    chunk.frame_index,
                    chunk.timestamp,
                    chunk.segment_hash,
                    TransportProtocol::Ethernet,
                    Some("iec61850"),
                    chunk.captured_len,
                    chunk.session_key.clone(),
                ),
                self.name(),
                "medium",
                "failed to parse iec61850 ethernet payload",
                chunk.payload,
            )),
        }
    }

    fn on_stream_chunk(&mut self, chunk: &StreamChunk<'_>, out: &mut Vec<BronzeEvent>) {
        if !self.dissector.can_parse(
            chunk.payload,
            chunk.context.src_port,
            chunk.context.dst_port,
            None,
        ) {
            return;
        }

        match self.dissector.parse(
            chunk.payload,
            chunk.context.src_port,
            chunk.context.dst_port,
            None,
        ) {
            Some(fields) => self.emit_fields(chunk, TransportProtocol::Tcp, fields, out),
            None => out.push(parse_anomaly_event(
                chunk.capture_id.to_string(),
                build_envelope(
                    &chunk.context,
                    chunk.interface_id,
                    chunk.frame_index,
                    chunk.timestamp,
                    chunk.segment_hash,
                    TransportProtocol::Tcp,
                    Some("iec61850"),
                    chunk.captured_len,
                    chunk.session_key.clone(),
                ),
                self.name(),
                "medium",
                "failed to parse iec61850 tcp payload",
                chunk.payload,
            )),
        }
    }
}

impl Iec61850DecoderWrapper {
    fn emit_fields(
        &self,
        chunk: &StreamChunk<'_>,
        transport: TransportProtocol,
        fields: Iec61850Fields,
        out: &mut Vec<BronzeEvent>,
    ) {
        let envelope = build_envelope(
            &chunk.context,
            chunk.interface_id,
            chunk.frame_index,
            chunk.timestamp,
            chunk.segment_hash,
            transport,
            Some("iec61850"),
            chunk.captured_len,
            chunk.session_key.clone(),
        );

        let mut attributes = BTreeMap::new();
        attributes.insert(
            "profile".to_string(),
            iec61850_profile_name(fields.profile).to_string(),
        );
        attributes.insert("transport".to_string(), fields.transport.clone());
        attributes.insert("message_type".to_string(), fields.message_type.clone());
        if let Some(tpkt_length) = fields.tpkt_length {
            attributes.insert("tpkt_length".to_string(), tpkt_length.to_string());
        }
        if let Some(cotp_pdu_type) = &fields.cotp_pdu_type {
            attributes.insert("cotp_pdu_type".to_string(), cotp_pdu_type.clone());
        }
        if let Some(app_id) = fields.app_id {
            attributes.insert("app_id".to_string(), format!("{app_id:#06x}"));
        }
        if let Some(called_tsap) = &fields.called_tsap {
            attributes.insert("called_tsap".to_string(), called_tsap.clone());
        }
        if let Some(calling_tsap) = &fields.calling_tsap {
            attributes.insert("calling_tsap".to_string(), calling_tsap.clone());
        }
        if let Some(service) = &fields.service {
            attributes.insert("service".to_string(), service.clone());
        }
        if let Some(ied_name) = &fields.ied_name {
            attributes.insert("ied_name".to_string(), ied_name.clone());
        }
        if let Some(logical_device) = &fields.logical_device {
            attributes.insert("logical_device".to_string(), logical_device.clone());
        }
        if let Some(logical_node) = &fields.logical_node {
            attributes.insert("logical_node".to_string(), logical_node.clone());
        }
        if let Some(dataset) = &fields.dataset {
            attributes.insert("dataset".to_string(), dataset.clone());
        }
        attributes.insert(
            "visible_string_count".to_string(),
            fields.visible_strings.len().to_string(),
        );

        out.push(new_event(
            chunk.capture_id.to_string(),
            envelope.clone(),
            BronzeEventFamily::ProtocolTransaction(ProtocolTransaction {
                operation: iec61850_operation_name(&fields),
                status: iec61850_status(&fields).to_string(),
                request_summary: Some(iec61850_summary(&fields)),
                response_summary: None,
                object_refs: fields.object_references.clone(),
                values: Vec::new(),
                attributes,
                        modbus: None,
}),
        ));

        if fields.ied_name.is_some() || fields.logical_device.is_some() || fields.dataset.is_some()
        {
            let mut identifiers = BTreeMap::new();
            identifiers.insert("endpoint".to_string(), context_asset_key(&chunk.context));
            if let Some(ied_name) = &fields.ied_name {
                identifiers.insert("ied_name".to_string(), ied_name.clone());
            }
            if let Some(logical_device) = &fields.logical_device {
                identifiers.insert("logical_device".to_string(), logical_device.clone());
            }
            if let Some(logical_node) = &fields.logical_node {
                identifiers.insert("logical_node".to_string(), logical_node.clone());
            }
            if let Some(dataset) = &fields.dataset {
                identifiers.insert("dataset".to_string(), dataset.clone());
            }
            if let Some(app_id) = fields.app_id {
                identifiers.insert("app_id".to_string(), app_id.to_string());
            }
            out.push(new_event(
                chunk.capture_id.to_string(),
                envelope.clone(),
                BronzeEventFamily::AssetObservation(AssetObservation {
                    asset_key: context_asset_key(&chunk.context),
                    role: Some("ied".to_string()),
                    vendor: None,
                    model: None,
                    firmware: None,
                    hostnames: fields.ied_name.clone().into_iter().collect(),
                    protocols: vec!["iec61850".to_string()],
                    identifiers,
                }),
            ));
        }

        out.push(new_event(
            chunk.capture_id.to_string(),
            envelope.clone(),
            BronzeEventFamily::TopologyObservation(TopologyObservation {
                observation_type: "iec61850_transaction".to_string(),
                local_id: context_asset_key(&chunk.context),
                remote_id: Some(context_remote_asset_key(&chunk.context)),
                description: fields.service.clone().or(Some(fields.message_type.clone())),
                capabilities: Vec::new(),
                metadata: BTreeMap::from([(
                    "profile".to_string(),
                    iec61850_profile_name(fields.profile).to_string(),
                )]),
            }),
        ));

        if !fields.payload.is_empty() {
            out.push(artifact_event(
                chunk.capture_id.to_string(),
                envelope,
                "iec61850_payload",
                &format!("{}:{}", chunk.session_key, chunk.frame_index),
                Some("application/octet-stream"),
                Some("IEC 61850 payload"),
                &fields.payload,
            ));
        }
    }
}

#[derive(Default)]
struct EthercatDecoderWrapper {
    dissector: EthercatDissector,
}

impl SessionDecoder for EthercatDecoderWrapper {
    fn name(&self) -> &'static str {
        "ethercat"
    }

    fn interest(&self) -> &'static [DecoderInterest] {
        &[DecoderInterest::EtherType(0x88A4)]
    }

    fn on_datagram(&mut self, chunk: &StreamChunk<'_>, out: &mut Vec<BronzeEvent>) {
        if !self.dissector.can_parse(
            chunk.payload,
            chunk.context.src_port,
            chunk.context.dst_port,
        ) {
            return;
        }

        match self.dissector.parse(chunk.payload, &chunk.context) {
            Some(ProtocolData::Ethercat(fields)) => {
                let envelope = build_envelope(
                    &chunk.context,
                    chunk.interface_id,
                    chunk.frame_index,
                    chunk.timestamp,
                    chunk.segment_hash,
                    TransportProtocol::Ethernet,
                    Some("ethercat"),
                    chunk.captured_len,
                    chunk.session_key.clone(),
                );

                let mut attributes = BTreeMap::new();
                attributes.insert(
                    "datagram_count".to_string(),
                    fields.datagrams.len().to_string(),
                );
                if let Some(first) = fields.datagrams.first() {
                    attributes.insert("first_command".to_string(), first.command.clone());
                    attributes.insert("first_adp".to_string(), first.adp.to_string());
                    attributes.insert("first_ado".to_string(), format!("{:#06x}", first.ado));
                }

                out.push(new_event(
                    chunk.capture_id.to_string(),
                    envelope.clone(),
                    BronzeEventFamily::ProtocolTransaction(ProtocolTransaction {
                        operation: ethercat_operation_name(&fields),
                        status: "observed".to_string(),
                        request_summary: Some(format!("{} datagrams", fields.datagrams.len())),
                        response_summary: None,
                        object_refs: ethercat_object_refs(&fields),
                        values: Vec::new(),
                        attributes,
                                        modbus: None,
}),
                ));

                out.push(new_event(
                    chunk.capture_id.to_string(),
                    envelope.clone(),
                    BronzeEventFamily::AssetObservation(AssetObservation {
                        asset_key: format_mac(&chunk.context.src_mac),
                        role: Some("master".to_string()),
                        vendor: None,
                        model: None,
                        firmware: None,
                        hostnames: Vec::new(),
                        protocols: vec!["ethercat".to_string()],
                        identifiers: BTreeMap::from([(
                            "mac".to_string(),
                            format_mac(&chunk.context.src_mac),
                        )]),
                    }),
                ));

                for datagram in &fields.datagrams {
                    if let Some(asset_key) =
                        ethercat_slave_asset_key(datagram.adp, datagram.identity.alias_address)
                    {
                        let mut identifiers = BTreeMap::new();
                        identifiers.insert("ethercat_adp".to_string(), datagram.adp.to_string());
                        identifiers
                            .insert("ethercat_ado".to_string(), format!("{:#06x}", datagram.ado));
                        if let Some(alias_address) = datagram.identity.alias_address {
                            identifiers.insert(
                                "ethercat_alias_address".to_string(),
                                alias_address.to_string(),
                            );
                        }
                        if let Some(vendor_id) = datagram.identity.vendor_id {
                            identifiers
                                .insert("ethercat_vendor_id".to_string(), vendor_id.to_string());
                        }
                        if let Some(product_code) = datagram.identity.product_code {
                            identifiers.insert(
                                "ethercat_product_code".to_string(),
                                product_code.to_string(),
                            );
                        }
                        if let Some(revision) = datagram.identity.revision {
                            identifiers
                                .insert("ethercat_revision".to_string(), revision.to_string());
                        }
                        if let Some(serial_number) = datagram.identity.serial_number {
                            identifiers.insert(
                                "ethercat_serial_number".to_string(),
                                serial_number.to_string(),
                            );
                        }
                        out.push(new_event(
                            chunk.capture_id.to_string(),
                            envelope.clone(),
                            BronzeEventFamily::AssetObservation(AssetObservation {
                                asset_key: asset_key.clone(),
                                role: Some("slave".to_string()),
                                vendor: datagram
                                    .identity
                                    .vendor_id
                                    .map(|vendor_id| format!("vendor_{vendor_id}")),
                                model: datagram
                                    .identity
                                    .product_code
                                    .map(|product_code| format!("product_{product_code}")),
                                firmware: datagram
                                    .identity
                                    .revision
                                    .map(|revision| revision.to_string()),
                                hostnames: Vec::new(),
                                protocols: vec!["ethercat".to_string()],
                                identifiers,
                            }),
                        ));
                        out.push(new_event(
                            chunk.capture_id.to_string(),
                            envelope.clone(),
                            BronzeEventFamily::TopologyObservation(TopologyObservation {
                                observation_type: "ethercat_master_slave".to_string(),
                                local_id: format_mac(&chunk.context.src_mac),
                                remote_id: Some(asset_key),
                                description: Some(datagram.command.clone()),
                                capabilities: Vec::new(),
                                metadata: BTreeMap::from([(
                                    "address_mode".to_string(),
                                    datagram.address_mode.clone(),
                                )]),
                            }),
                        ));
                    }
                }

                let mut artifact_payload = Vec::new();
                for datagram in &fields.datagrams {
                    artifact_payload.extend_from_slice(&datagram.payload);
                }
                if !artifact_payload.is_empty() {
                    out.push(artifact_event(
                        chunk.capture_id.to_string(),
                        envelope,
                        "ethercat_payload",
                        &format!("{}:{}", chunk.session_key, chunk.frame_index),
                        Some("application/octet-stream"),
                        Some("EtherCAT datagram payload"),
                        &artifact_payload,
                    ));
                }
            }
            _ => out.push(parse_anomaly_event(
                chunk.capture_id.to_string(),
                build_envelope(
                    &chunk.context,
                    chunk.interface_id,
                    chunk.frame_index,
                    chunk.timestamp,
                    chunk.segment_hash,
                    TransportProtocol::Ethernet,
                    Some("ethercat"),
                    chunk.captured_len,
                    chunk.session_key.clone(),
                ),
                self.name(),
                "medium",
                "failed to parse ethercat payload",
                chunk.payload,
            )),
        }
    }
}

#[derive(Default)]
struct EthernetIpDecoderWrapper {
    dissector: EthernetIpDissector,
    pccc_decoder: crate::pccc::PcccDecoder,
}

impl SessionDecoder for EthernetIpDecoderWrapper {
    fn name(&self) -> &'static str {
        "ethernet_ip"
    }

    fn interest(&self) -> &'static [DecoderInterest] {
        &[DecoderInterest::TcpPort(44818)]
    }

    fn on_stream_chunk(&mut self, chunk: &StreamChunk<'_>, out: &mut Vec<BronzeEvent>) {
        match self.dissector.parse(chunk.payload, &chunk.context) {
            Some(ProtocolData::EthernetIp(EthernetIpFields {
                command,
                session_handle,
                cip_data,
            })) => {
                let command_name = ethernet_ip_command_name(command);
                let mut attributes = BTreeMap::new();
                attributes.insert("session_handle".to_string(), session_handle.to_string());
                attributes.insert(
                    "encapsulation_command".to_string(),
                    format!("{command:#06x}"),
                );
                if let Some(service) = cip_service_name(&cip_data) {
                    attributes.insert("cip_service".to_string(), service.to_string());
                }
                if let Some(identity) = parse_cip_identity_claim(command, &cip_data) {
                    attributes.insert("cip_vendor_id".to_string(), identity.vendor_id.to_string());
                    attributes.insert(
                        "cip_product_code".to_string(),
                        identity.product_code.to_string(),
                    );
                    attributes.insert(
                        "cip_serial_number".to_string(),
                        identity.serial_number.to_string(),
                    );
                    attributes.insert("cip_revision".to_string(), identity.revision.clone());
                }
                let envelope = build_envelope(
                    &chunk.context,
                    chunk.interface_id,
                    chunk.frame_index,
                    chunk.timestamp,
                    chunk.segment_hash,
                    TransportProtocol::Tcp,
                    Some("ethernet_ip"),
                    chunk.captured_len,
                    chunk.session_key.clone(),
                );
                out.push(new_event(
                    chunk.capture_id.to_string(),
                    envelope.clone(),
                    BronzeEventFamily::ProtocolTransaction(ProtocolTransaction {
                        operation: command_name.to_string(),
                        status: if chunk.context.dst_port == 44818 {
                            "request".to_string()
                        } else {
                            "response".to_string()
                        },
                        request_summary: Some(format!("{command_name} session={session_handle}")),
                        response_summary: None,
                        object_refs: cip_object_refs(&cip_data),
                        values: Vec::new(),
                        attributes,
                                        modbus: None,
}),
                ));
                for identity in parse_cip_identity_claims(command, &cip_data) {
                    let asset_key = identity
                        .ip_address
                        .clone()
                        .unwrap_or_else(|| chunk.context.src_ip.to_string());
                    let mut identifiers = BTreeMap::from([
                        ("ip".to_string(), asset_key.clone()),
                        ("cip_vendor_id".to_string(), identity.vendor_id.to_string()),
                        (
                            "cip_device_type".to_string(),
                            identity.device_type.to_string(),
                        ),
                        (
                            "cip_product_code".to_string(),
                            identity.product_code.to_string(),
                        ),
                        (
                            "cip_serial_number".to_string(),
                            identity.serial_number.to_string(),
                        ),
                    ]);
                    identifiers.insert("cip_revision".to_string(), identity.revision.clone());
                    identifiers.insert("cip_status".to_string(), identity.status.to_string());
                    if let Some(state) = identity.state {
                        identifiers.insert("cip_state".to_string(), state.to_string());
                    }
                    out.push(new_event(
                        chunk.capture_id.to_string(),
                        envelope.clone(),
                        BronzeEventFamily::AssetObservation(AssetObservation {
                            asset_key,
                            role: cip_role_from_device_type(identity.device_type)
                                .map(str::to_string),
                            vendor: cip_vendor_name(identity.vendor_id).map(str::to_string),
                            model: Some(identity.product_name.clone()),
                            firmware: Some(identity.revision.clone()),
                            hostnames: Vec::new(),
                            protocols: vec!["ethernet_ip".to_string(), "cip".to_string()],
                            identifiers,
                        }),
                    ));
                }
                if matches!(command, 0x006F | 0x0070) && !cip_data.is_empty() {
                    // PCCC dispatch: if the CIP service is Execute PCCC
                    // (request 0x4B / response 0xCB), pull the embedded PCCC
                    // PDU and let the PcccDecoder produce ProcessReadings.
                    if let Some(message) = cip_explicit_message(&cip_data) {
                        if let Some((is_request, pccc_pdu)) =
                            extract_pccc_pdu(message)
                        {
                            let mut events = self.pccc_decoder.handle_pdu(
                                pccc_pdu,
                                is_request,
                                chunk.context.src_ip,
                                &envelope,
                                chunk.capture_id,
                            );
                            out.append(&mut events);
                        }
                    }
                    out.push(artifact_event(
                        chunk.capture_id.to_string(),
                        envelope,
                        "cip_payload",
                        &format!("{session_handle}:{}", chunk.frame_index),
                        Some("application/octet-stream"),
                        Some("EtherNet/IP CIP payload"),
                        &cip_data,
                    ));
                }
            }
            _ => out.push(parse_anomaly_event(
                chunk.capture_id.to_string(),
                build_envelope(
                    &chunk.context,
                    chunk.interface_id,
                    chunk.frame_index,
                    chunk.timestamp,
                    chunk.segment_hash,
                    TransportProtocol::Tcp,
                    Some("ethernet_ip"),
                    chunk.captured_len,
                    chunk.session_key.clone(),
                ),
                self.name(),
                "medium",
                "failed to parse ethernet/ip payload",
                chunk.payload,
            )),
        }
    }
}

struct OpcUaDecoderWrapper {
    dissector: OpcUaDissector,
    service_decoder: crate::opc_ua::OpcUaServiceDecoder,
    event_id_counter: u64,
}

impl Default for OpcUaDecoderWrapper {
    fn default() -> Self {
        Self {
            dissector: OpcUaDissector,
            service_decoder: crate::opc_ua::OpcUaServiceDecoder::new(),
            event_id_counter: 0,
        }
    }
}

impl SessionDecoder for OpcUaDecoderWrapper {
    fn name(&self) -> &'static str {
        "opc_ua"
    }

    fn interest(&self) -> &'static [DecoderInterest] {
        &[
            DecoderInterest::TcpPort(4840),
            DecoderInterest::TcpPort(12001),
        ]
    }

    fn on_stream_chunk(&mut self, chunk: &StreamChunk<'_>, out: &mut Vec<BronzeEvent>) {
        if !self.dissector.can_parse(
            chunk.payload,
            chunk.context.src_port,
            chunk.context.dst_port,
        ) {
            return;
        }

        match self.dissector.parse(chunk.payload, &chunk.context) {
            Some(ProtocolData::OpcUa(OpcUaFields {
                message_type,
                request_id,
                service_type,
            })) => {
                let mut attributes = BTreeMap::new();
                attributes.insert("message_type".to_string(), message_type.clone());
                attributes.insert("service_type".to_string(), service_type.clone());
                if request_id != 0 {
                    attributes.insert("request_id".to_string(), request_id.to_string());
                }

                let envelope = build_envelope(
                    &chunk.context,
                    chunk.interface_id,
                    chunk.frame_index,
                    chunk.timestamp,
                    chunk.segment_hash,
                    TransportProtocol::Tcp,
                    Some("opc_ua"),
                    chunk.captured_len,
                    chunk.session_key.clone(),
                );

                out.push(new_event(
                    chunk.capture_id.to_string(),
                    envelope.clone(),
                    BronzeEventFamily::ProtocolTransaction(ProtocolTransaction {
                        operation: opc_ua_operation_name(&service_type),
                        status: if service_type.starts_with("Error") {
                            "error".to_string()
                        } else if matches!(chunk.context.dst_port, 4840 | 12001) {
                            "request".to_string()
                        } else {
                            "response".to_string()
                        },
                        request_summary: Some(format!("{message_type} {service_type}")),
                        response_summary: None,
                        object_refs: if request_id == 0 {
                            vec![format!("opcua_message:{message_type}")]
                        } else {
                            vec![format!("opcua_request:{request_id}")]
                        },
                        values: Vec::new(),
                        attributes,
                                        modbus: None,
}),
                ));

                // For MSG chunks with the full 24-byte secure header, hand
                // the body to the OPC UA service decoder. Read* services
                // produce ProcessReading events; others are ignored.
                if message_type == "MSG" && chunk.payload.len() >= 24 {
                    let secure_channel_id = u32::from_le_bytes([
                        chunk.payload[8],
                        chunk.payload[9],
                        chunk.payload[10],
                        chunk.payload[11],
                    ]);
                    let body = &chunk.payload[24..];
                    let now_us = chunk.context.timestamp / 1_000;
                    let counter = &mut self.event_id_counter;
                    let mut next_id = || {
                        *counter = counter.wrapping_add(1);
                        format!("opcua-{}", *counter)
                    };
                    let mut events = self.service_decoder.handle_msg_body(
                        body,
                        secure_channel_id,
                        request_id,
                        &envelope,
                        now_us,
                        &mut next_id,
                        chunk.capture_id,
                    );
                    out.append(&mut events);
                }
            }
            _ => out.push(parse_anomaly_event(
                chunk.capture_id.to_string(),
                build_envelope(
                    &chunk.context,
                    chunk.interface_id,
                    chunk.frame_index,
                    chunk.timestamp,
                    chunk.segment_hash,
                    TransportProtocol::Tcp,
                    Some("opc_ua"),
                    chunk.captured_len,
                    chunk.session_key.clone(),
                ),
                self.name(),
                "medium",
                "failed to parse opc ua payload",
                chunk.payload,
            )),
        }
    }
}

struct S7commDecoderWrapper {
    dissector: S7commDissector,
}

impl Default for S7commDecoderWrapper {
    fn default() -> Self {
        Self {
            dissector: S7commDissector,
        }
    }
}

impl SessionDecoder for S7commDecoderWrapper {
    fn name(&self) -> &'static str {
        "s7comm"
    }

    fn interest(&self) -> &'static [DecoderInterest] {
        &[DecoderInterest::TcpPort(102)]
    }

    fn on_stream_chunk(&mut self, chunk: &StreamChunk<'_>, out: &mut Vec<BronzeEvent>) {
        if !self.dissector.can_parse(
            chunk.payload,
            chunk.context.src_port,
            chunk.context.dst_port,
        ) {
            return;
        }

        match self.dissector.parse(chunk.payload, &chunk.context) {
            Some(ProtocolData::S7comm(S7commFields {
                rosctr,
                function,
                parameter,
                data,
            })) => {
                let operation = s7comm_function_name(function).to_string();
                let mut attributes = BTreeMap::new();
                attributes.insert("rosctr".to_string(), format!("{rosctr:#04x}"));
                attributes.insert(
                    "rosctr_name".to_string(),
                    s7comm_rosctr_name(rosctr).to_string(),
                );
                attributes.insert("function".to_string(), format!("{function:#04x}"));
                attributes.insert("parameter_length".to_string(), parameter.len().to_string());
                attributes.insert("data_length".to_string(), data.len().to_string());

                let envelope = build_envelope(
                    &chunk.context,
                    chunk.interface_id,
                    chunk.frame_index,
                    chunk.timestamp,
                    chunk.segment_hash,
                    TransportProtocol::Tcp,
                    Some("s7comm"),
                    chunk.captured_len,
                    chunk.session_key.clone(),
                );

                out.push(new_event(
                    chunk.capture_id.to_string(),
                    envelope.clone(),
                    BronzeEventFamily::ProtocolTransaction(ProtocolTransaction {
                        operation,
                        status: s7comm_status(rosctr, &chunk.context).to_string(),
                        request_summary: Some(format!(
                            "{} {}",
                            s7comm_rosctr_name(rosctr),
                            s7comm_function_name(function)
                        )),
                        response_summary: None,
                        object_refs: vec![
                            format!("s7_function:{function:#04x}"),
                            format!("s7_rosctr:{rosctr:#04x}"),
                        ],
                        values: Vec::new(),
                        attributes,
                                        modbus: None,
}),
                ));

                if !data.is_empty() {
                    out.push(artifact_event(
                        chunk.capture_id.to_string(),
                        envelope,
                        "s7comm_data",
                        &format!("{}:{function:#04x}", chunk.session_key),
                        Some("application/octet-stream"),
                        Some("S7comm data payload"),
                        &data,
                    ));
                }
            }
            _ => out.push(parse_anomaly_event(
                chunk.capture_id.to_string(),
                build_envelope(
                    &chunk.context,
                    chunk.interface_id,
                    chunk.frame_index,
                    chunk.timestamp,
                    chunk.segment_hash,
                    TransportProtocol::Tcp,
                    Some("s7comm"),
                    chunk.captured_len,
                    chunk.session_key.clone(),
                ),
                self.name(),
                "medium",
                "failed to parse s7comm payload",
                chunk.payload,
            )),
        }
    }
}

struct ProfinetDecoderWrapper {
    dissector: ProfinetDissector,
}

impl Default for ProfinetDecoderWrapper {
    fn default() -> Self {
        Self {
            dissector: ProfinetDissector,
        }
    }
}

impl SessionDecoder for ProfinetDecoderWrapper {
    fn name(&self) -> &'static str {
        "profinet"
    }

    fn interest(&self) -> &'static [DecoderInterest] {
        &[
            DecoderInterest::UdpPort(34964),
            DecoderInterest::EtherType(0x8892),
        ]
    }

    fn on_datagram(&mut self, chunk: &StreamChunk<'_>, out: &mut Vec<BronzeEvent>) {
        if !self.dissector.can_parse(
            chunk.payload,
            chunk.context.src_port,
            chunk.context.dst_port,
        ) {
            return;
        }

        match self.dissector.parse(chunk.payload, &chunk.context) {
            Some(ProtocolData::Profinet(ProfinetFields {
                frame_id,
                service_type,
                payload,
            })) => {
                let transport = chunk.transport;
                let mut attributes = BTreeMap::new();
                attributes.insert("frame_id".to_string(), format!("{frame_id:#06x}"));
                attributes.insert("service_type".to_string(), service_type.clone());
                attributes.insert("payload_length".to_string(), payload.len().to_string());

                let envelope = build_envelope(
                    &chunk.context,
                    chunk.interface_id,
                    chunk.frame_index,
                    chunk.timestamp,
                    chunk.segment_hash,
                    transport,
                    Some("profinet"),
                    chunk.captured_len,
                    chunk.session_key.clone(),
                );

                out.push(new_event(
                    chunk.capture_id.to_string(),
                    envelope.clone(),
                    BronzeEventFamily::ProtocolTransaction(ProtocolTransaction {
                        operation: profinet_operation_name(&service_type),
                        status: if service_type.contains("Response") {
                            "response".to_string()
                        } else if service_type.contains("Request")
                            || chunk.context.dst_port == 34964
                        {
                            "request".to_string()
                        } else {
                            "observed".to_string()
                        },
                        request_summary: Some(format!("{service_type} frame={frame_id:#06x}")),
                        response_summary: None,
                        object_refs: vec![format!("profinet_frame:{frame_id:#06x}")],
                        values: Vec::new(),
                        attributes,
                                        modbus: None,
}),
                ));

                if !payload.is_empty() {
                    out.push(artifact_event(
                        chunk.capture_id.to_string(),
                        envelope,
                        "profinet_payload",
                        &format!("{frame_id:#06x}:{}", chunk.frame_index),
                        Some("application/octet-stream"),
                        Some("PROFINET payload"),
                        &payload,
                    ));
                }
            }
            _ => out.push(parse_anomaly_event(
                chunk.capture_id.to_string(),
                build_envelope(
                    &chunk.context,
                    chunk.interface_id,
                    chunk.frame_index,
                    chunk.timestamp,
                    chunk.segment_hash,
                    chunk.transport,
                    Some("profinet"),
                    chunk.captured_len,
                    chunk.session_key.clone(),
                ),
                self.name(),
                "medium",
                "failed to parse profinet payload",
                chunk.payload,
            )),
        }
    }
}

#[derive(Clone)]
struct PendingModbus {
    capture_id: String,
    envelope: EventEnvelope,
    transaction_id: u16,
    unit_id: u8,
    operation: String,
    request_summary: String,
    object_refs: Vec<String>,
    values: Vec<ObjectValue>,
    attributes: BTreeMap<String, String>,
    raw_payload: Vec<u8>,
    last_seen: DateTime<Utc>,
    /// Structured request PDU; used to build `ModbusBronzeFields` on response.
    request_pdu: Option<ModbusPdu>,
}

#[derive(Debug, Clone)]
struct CipIdentityClaim {
    vendor_id: u16,
    device_type: u16,
    product_code: u16,
    revision: String,
    serial_number: u32,
    product_name: String,
    status: u16,
    state: Option<u8>,
    ip_address: Option<String>,
}

#[derive(Default)]
struct ModbusDecoder {
    dissector: ModbusDissector,
    pending: HashMap<String, PendingModbus>,
}

impl SessionDecoder for ModbusDecoder {
    fn name(&self) -> &'static str {
        "modbus"
    }

    fn interest(&self) -> &'static [DecoderInterest] {
        &[DecoderInterest::TcpPort(502)]
    }

    fn on_stream_chunk(&mut self, chunk: &StreamChunk<'_>, out: &mut Vec<BronzeEvent>) {
        match self.dissector.parse(chunk.payload, &chunk.context) {
            Some(ProtocolData::Modbus(fields)) => {
                let operation = modbus_function_name(fields.function_code).to_string();
                let is_request = chunk.context.dst_port == 502 && chunk.context.src_port != 502;
                let envelope = build_envelope(
                    &chunk.context,
                    chunk.interface_id,
                    chunk.frame_index,
                    chunk.timestamp,
                    chunk.segment_hash,
                    TransportProtocol::Tcp,
                    Some("modbus"),
                    chunk.captured_len,
                    chunk.session_key.clone(),
                );
                let key = format!(
                    "{}:{}:{}",
                    chunk.session_key, fields.transaction_id, fields.unit_id
                );
                if is_request {
                    self.pending.insert(
                        key,
                        PendingModbus {
                            capture_id: chunk.capture_id.to_string(),
                            envelope,
                            transaction_id: fields.transaction_id,
                            unit_id: fields.unit_id,
                            operation: operation.clone(),
                            request_summary: modbus_summary(&fields),
                            object_refs: modbus_object_refs(&fields),
                            values: modbus_values(&fields),
                            attributes: modbus_attributes(&fields),
                            raw_payload: chunk.payload.to_vec(),
                            last_seen: chunk.timestamp,
                            request_pdu: fields.pdu.clone(),
                        },
                    );
                } else if let Some(pending) = self.pending.remove(&key) {
                    let mut values = pending.values.clone();
                    values.extend(modbus_values(&fields));
                    let mut attributes = pending.attributes.clone();
                    attributes.extend(modbus_attributes(&fields));
                    let mut merged_envelope = pending.envelope.clone();
                    merged_envelope.bytes_count += envelope.bytes_count;
                    merged_envelope.packet_count += 1;

                    out.push(new_event(
                        pending.capture_id.clone(),
                        merged_envelope.clone(),
                        BronzeEventFamily::ProtocolTransaction(ProtocolTransaction {
                            operation: pending.operation.clone(),
                            status: if fields.is_exception {
                                format!("exception:{}", fields.exception_code)
                            } else {
                                "ok".to_string()
                            },
                            request_summary: Some(pending.request_summary),
                            response_summary: Some(modbus_summary(&fields)),
                            object_refs: pending.object_refs.clone(),
                            values,
                            attributes,
                            modbus: modbus_bronze_fields(
                                pending.request_pdu.as_ref(),
                                fields.pdu.as_ref(),
                                fields.is_exception,
                                fields.exception_code,
                            ),
                        }),
                    ));
                    if !fields.device_identification.is_empty() {
                        out.push(modbus_identity_observation(
                            pending.capture_id.clone(),
                            merged_envelope.clone(),
                            chunk.context.src_ip.to_string(),
                            fields.unit_id,
                            &fields.device_identification,
                        ));
                    }
                    if is_modbus_write(fields.function_code) {
                        out.push(artifact_event(
                            pending.capture_id,
                            merged_envelope,
                            "modbus_write_payload",
                            &format!(
                                "{}:{}:{}",
                                chunk.session_key, fields.transaction_id, fields.unit_id
                            ),
                            Some("application/octet-stream"),
                            Some("Modbus write request payload"),
                            &pending.raw_payload,
                        ));
                    }
                } else {
                    out.push(new_event(
                        chunk.capture_id.to_string(),
                        envelope,
                        BronzeEventFamily::ProtocolTransaction(ProtocolTransaction {
                            operation,
                            status: "response_without_request".to_string(),
                            request_summary: None,
                            response_summary: Some(modbus_summary(&fields)),
                            object_refs: modbus_object_refs(&fields),
                            values: modbus_values(&fields),
                            attributes: modbus_attributes(&fields),
                            modbus: modbus_bronze_fields(
                                None,
                                fields.pdu.as_ref(),
                                fields.is_exception,
                                fields.exception_code,
                            ),
                        }),
                    ));
                    if !fields.device_identification.is_empty() {
                        out.push(modbus_identity_observation(
                            chunk.capture_id.to_string(),
                            build_envelope(
                                &chunk.context,
                                chunk.interface_id,
                                chunk.frame_index,
                                chunk.timestamp,
                                chunk.segment_hash,
                                TransportProtocol::Tcp,
                                Some("modbus"),
                                chunk.captured_len,
                                chunk.session_key.clone(),
                            ),
                            chunk.context.src_ip.to_string(),
                            fields.unit_id,
                            &fields.device_identification,
                        ));
                    }
                }
            }
            _ => out.push(parse_anomaly_event(
                chunk.capture_id.to_string(),
                build_envelope(
                    &chunk.context,
                    chunk.interface_id,
                    chunk.frame_index,
                    chunk.timestamp,
                    chunk.segment_hash,
                    TransportProtocol::Tcp,
                    Some("modbus"),
                    chunk.captured_len,
                    chunk.session_key.clone(),
                ),
                self.name(),
                "medium",
                "failed to parse modbus payload",
                chunk.payload,
            )),
        }
    }

    fn on_idle_flush(&mut self, timestamp: DateTime<Utc>, out: &mut Vec<BronzeEvent>) {
        let expired: Vec<String> = self
            .pending
            .iter()
            .filter_map(|(key, pending)| {
                if (timestamp - pending.last_seen).num_seconds() >= 0 {
                    Some(key.clone())
                } else {
                    None
                }
            })
            .collect();

        for key in expired {
            if let Some(pending) = self.pending.remove(&key) {
                out.push(new_event(
                    pending.capture_id,
                    pending.envelope,
                    BronzeEventFamily::ProtocolTransaction(ProtocolTransaction {
                        operation: pending.operation,
                        status: "partial_request".to_string(),
                        request_summary: Some(pending.request_summary),
                        response_summary: None,
                        object_refs: pending.object_refs,
                        values: pending.values,
                        attributes: pending.attributes,
                        modbus: modbus_bronze_fields(
                            pending.request_pdu.as_ref(),
                            None,
                            false,
                            0,
                        ),
                    }),
                ));
            }
        }
    }
}

fn dns_payload<'a>(chunk: &'a StreamChunk<'_>) -> &'a [u8] {
    if chunk.transport == TransportProtocol::Tcp && chunk.payload.len() > 2 {
        let advertised = u16::from_be_bytes([chunk.payload[0], chunk.payload[1]]) as usize;
        if advertised + 2 <= chunk.payload.len() {
            return &chunk.payload[2..2 + advertised];
        }
    }
    chunk.payload
}

fn dns_hostname_from_query(query: &str) -> String {
    query.split_whitespace().next().unwrap_or(query).to_string()
}

fn dns_ip_from_answer(answer: &str) -> Option<String> {
    let candidate = answer.split_whitespace().last()?;
    candidate
        .parse::<IpAddr>()
        .ok()
        .map(|_| candidate.to_string())
}

fn dhcp_message_type_name(message_type: Option<u8>) -> &'static str {
    match message_type {
        Some(1) => "discover",
        Some(2) => "offer",
        Some(3) => "request",
        Some(4) => "decline",
        Some(5) => "ack",
        Some(6) => "nak",
        Some(7) => "release",
        Some(8) => "inform",
        _ => "bootp",
    }
}

fn dhcp_status(context: &PacketContext) -> &'static str {
    if context.dst_port == 67 {
        "request"
    } else if context.src_port == 67 {
        "response"
    } else {
        "observed"
    }
}

fn snmp_status(pdu_type: &str) -> String {
    if pdu_type.contains("response") {
        "response".to_string()
    } else if pdu_type.contains("trap") || pdu_type.contains("inform") || pdu_type == "report" {
        "observed".to_string()
    } else {
        "request".to_string()
    }
}

fn dnp3_function_name(code: u8) -> &'static str {
    match code {
        0x01 => "read",
        0x02 => "write",
        0x03 => "select",
        0x04 => "operate",
        0x05 => "direct_operate",
        0x06 => "direct_operate_no_ack",
        0x81 => "response",
        0x82 => "unsolicited_response",
        _ => "dnp3_message",
    }
}

fn is_dnp3_artifact(code: u8) -> bool {
    matches!(code, 0x02 | 0x03 | 0x04 | 0x05 | 0x06)
}

fn dnp3_role_observations(
    capture_id: &str,
    envelope: &EventEnvelope,
    context: &PacketContext,
    source_address: u16,
    destination_address: u16,
    function_code: u8,
) -> Vec<BronzeEvent> {
    let (src_role, dst_role, observation_type) =
        if function_code >= 0x80 || context.src_port == 20000 {
            ("outstation", "master", "dnp3_response")
        } else {
            ("master", "outstation", "dnp3_request")
        };

    vec![
        new_event(
            capture_id.to_string(),
            envelope.clone(),
            BronzeEventFamily::AssetObservation(AssetObservation {
                asset_key: context.src_ip.to_string(),
                role: Some(src_role.to_string()),
                vendor: None,
                model: None,
                firmware: None,
                hostnames: Vec::new(),
                protocols: vec!["dnp3".to_string()],
                identifiers: BTreeMap::from([
                    ("ip".to_string(), context.src_ip.to_string()),
                    ("dnp3_address".to_string(), source_address.to_string()),
                ]),
            }),
        ),
        new_event(
            capture_id.to_string(),
            envelope.clone(),
            BronzeEventFamily::AssetObservation(AssetObservation {
                asset_key: context.dst_ip.to_string(),
                role: Some(dst_role.to_string()),
                vendor: None,
                model: None,
                firmware: None,
                hostnames: Vec::new(),
                protocols: vec!["dnp3".to_string()],
                identifiers: BTreeMap::from([
                    ("ip".to_string(), context.dst_ip.to_string()),
                    ("dnp3_address".to_string(), destination_address.to_string()),
                ]),
            }),
        ),
        new_event(
            capture_id.to_string(),
            envelope.clone(),
            BronzeEventFamily::TopologyObservation(TopologyObservation {
                observation_type: observation_type.to_string(),
                local_id: source_address.to_string(),
                remote_id: Some(destination_address.to_string()),
                description: Some(dnp3_function_name(function_code).to_string()),
                capabilities: Vec::new(),
                metadata: BTreeMap::from([
                    ("src_ip".to_string(), context.src_ip.to_string()),
                    ("dst_ip".to_string(), context.dst_ip.to_string()),
                ]),
            }),
        ),
    ]
}

fn bacnet_status(apdu_type: &str) -> &'static str {
    match apdu_type {
        "confirmed_request" | "unconfirmed_request" => "request",
        "simple_ack" | "complex_ack" => "response",
        "error" | "reject" | "abort" => "error",
        _ => "observed",
    }
}

fn bacnet_object_refs(device_instance: Option<u32>, invoke_id: Option<u8>) -> Vec<String> {
    let mut refs = Vec::new();
    if let Some(device_instance) = device_instance {
        refs.push(format!("bacnet_device:{device_instance}"));
    }
    if let Some(invoke_id) = invoke_id {
        refs.push(format!("bacnet_invoke:{invoke_id}"));
    }
    refs
}

fn iec104_type_name(type_id: u8) -> &'static str {
    match type_id {
        1 => "single_point_information",
        3 => "double_point_information",
        9 => "measured_value_normalized",
        11 => "measured_value_scaled",
        13 => "measured_value_short_float",
        30 => "single_point_with_time",
        45 => "single_command",
        46 => "double_command",
        50 => "set_point_normalized",
        100 => "interrogation_command",
        103 => "clock_sync_command",
        _ => "asdu_type",
    }
}

fn iec104_cause_name(cause: u16) -> &'static str {
    match cause {
        1 => "periodic",
        3 => "spontaneous",
        5 => "request",
        6 => "activation",
        7 => "activation_confirmation",
        10 => "activation_termination",
        20 => "interrogated_by_station",
        _ => "cause",
    }
}

fn iec104_operation_name(frame_type: &str, type_id: Option<u8>, u_format: Option<&str>) -> String {
    match frame_type {
        "u" => u_format.unwrap_or("u_format").to_string(),
        "s" => "supervisory".to_string(),
        _ => type_id
            .map(iec104_type_name)
            .unwrap_or("iec104_asdu")
            .to_string(),
    }
}

fn iec104_status(
    frame_type: &str,
    u_format: Option<&str>,
    cause: Option<u16>,
    context: &PacketContext,
) -> &'static str {
    match frame_type {
        "u" => match u_format {
            Some(value) if value.ends_with("_act") => "request",
            Some(value) if value.ends_with("_con") => "response",
            _ => "observed",
        },
        "s" => "response",
        _ => match cause {
            Some(6) if context.dst_port == 2404 => "request",
            Some(7 | 10) if context.src_port == 2404 => "response",
            _ if context.dst_port == 2404 => "request",
            _ if context.src_port == 2404 => "response",
            _ => "observed",
        },
    }
}

fn iec104_summary(
    frame_type: &str,
    type_id: Option<u8>,
    cause: Option<u16>,
    common_address: Option<u16>,
) -> String {
    match frame_type {
        "u" => "u_format_control".to_string(),
        "s" => "supervisory_ack".to_string(),
        _ => format!(
            "{} cause={} ca={}",
            type_id.map(iec104_type_name).unwrap_or("iec104_asdu"),
            cause
                .map(|value| value.to_string())
                .unwrap_or_else(|| "?".to_string()),
            common_address
                .map(|value| value.to_string())
                .unwrap_or_else(|| "?".to_string())
        ),
    }
}

fn iec104_object_refs(
    type_id: Option<u8>,
    common_address: Option<u16>,
    information_object_address: Option<u32>,
) -> Vec<String> {
    let mut refs = Vec::new();
    if let Some(type_id) = type_id {
        refs.push(format!("iec104_type:{type_id}"));
    }
    if let Some(common_address) = common_address {
        refs.push(format!("iec104_common_address:{common_address}"));
    }
    if let Some(ioa) = information_object_address {
        refs.push(format!("iec104_ioa:{ioa}"));
    }
    refs
}

fn iec104_role_observations(
    capture_id: &str,
    envelope: &EventEnvelope,
    context: &PacketContext,
    frame_type: &str,
    common_address: Option<u16>,
) -> Vec<BronzeEvent> {
    let (src_role, dst_role) = match frame_type {
        "u" | "s" => {
            if context.src_port == 2404 {
                ("outstation", "master")
            } else {
                ("master", "outstation")
            }
        }
        _ if context.dst_port == 2404 => ("master", "outstation"),
        _ if context.src_port == 2404 => ("outstation", "master"),
        _ => ("peer", "peer"),
    };

    let mut src_identifiers = BTreeMap::from([("ip".to_string(), context.src_ip.to_string())]);
    if src_role == "outstation" {
        if let Some(common_address) = common_address {
            src_identifiers.insert(
                "iec104_common_address".to_string(),
                common_address.to_string(),
            );
        }
    }

    let mut dst_identifiers = BTreeMap::from([("ip".to_string(), context.dst_ip.to_string())]);
    if dst_role == "outstation" {
        if let Some(common_address) = common_address {
            dst_identifiers.insert(
                "iec104_common_address".to_string(),
                common_address.to_string(),
            );
        }
    }

    vec![
        new_event(
            capture_id.to_string(),
            envelope.clone(),
            BronzeEventFamily::AssetObservation(AssetObservation {
                asset_key: context.src_ip.to_string(),
                role: Some(src_role.to_string()),
                vendor: None,
                model: None,
                firmware: None,
                hostnames: Vec::new(),
                protocols: vec!["iec104".to_string()],
                identifiers: src_identifiers,
            }),
        ),
        new_event(
            capture_id.to_string(),
            envelope.clone(),
            BronzeEventFamily::AssetObservation(AssetObservation {
                asset_key: context.dst_ip.to_string(),
                role: Some(dst_role.to_string()),
                vendor: None,
                model: None,
                firmware: None,
                hostnames: Vec::new(),
                protocols: vec!["iec104".to_string()],
                identifiers: dst_identifiers,
            }),
        ),
        new_event(
            capture_id.to_string(),
            envelope.clone(),
            BronzeEventFamily::TopologyObservation(TopologyObservation {
                observation_type: "iec104_link".to_string(),
                local_id: context.src_ip.to_string(),
                remote_id: Some(context.dst_ip.to_string()),
                description: Some(frame_type.to_string()),
                capabilities: Vec::new(),
                metadata: common_address
                    .map(|value| {
                        BTreeMap::from([("common_address".to_string(), value.to_string())])
                    })
                    .unwrap_or_default(),
            }),
        ),
    ]
}

fn opc_ua_operation_name(service_type: &str) -> String {
    normalize_operation_name(service_type, "opc_ua_message")
}

fn s7comm_rosctr_name(code: u8) -> &'static str {
    match code {
        0x01 => "job",
        0x02 => "ack",
        0x03 => "ack_data",
        0x07 => "userdata",
        _ => "unknown",
    }
}

fn s7comm_function_name(code: u8) -> &'static str {
    match code {
        0x00 => "cpu_services",
        0x04 => "read_var",
        0x05 => "write_var",
        0x1A => "request_download",
        0x1B => "download_block",
        0x1C => "download_ended",
        0x1D => "start_upload",
        0x1E => "upload",
        0x1F => "end_upload",
        0x28 => "pi_service",
        0x29 => "plc_stop",
        0xF0 => "setup_communication",
        _ => "s7comm_message",
    }
}

fn s7comm_status(rosctr: u8, context: &PacketContext) -> &'static str {
    match rosctr {
        0x02 | 0x03 => "response",
        0x01 if context.dst_port == 102 => "request",
        0x01 => "observed",
        _ => "observed",
    }
}

fn profinet_operation_name(service_type: &str) -> String {
    normalize_operation_name(service_type, "profinet_frame")
}

fn context_asset_key(context: &PacketContext) -> String {
    match context.src_ip {
        IpAddr::V4(ip) if ip != Ipv4Addr::UNSPECIFIED => ip.to_string(),
        _ => format_mac(&context.src_mac),
    }
}

fn context_remote_asset_key(context: &PacketContext) -> String {
    match context.dst_ip {
        IpAddr::V4(ip) if ip != Ipv4Addr::UNSPECIFIED => ip.to_string(),
        _ => format_mac(&context.dst_mac),
    }
}

fn omron_fins_operation_name(command_name: Option<&str>, command_code: Option<u16>) -> String {
    command_name
        .map(|name| normalize_operation_name(name, "omron_fins"))
        .or_else(|| command_code.map(|code| format!("command_{code:04x}")))
        .unwrap_or_else(|| "omron_fins".to_string())
}

fn omron_fins_status(context: &PacketContext) -> &'static str {
    if context.dst_port == 9600 && context.src_port != 9600 {
        "request"
    } else if context.src_port == 9600 && context.dst_port != 9600 {
        "response"
    } else {
        "observed"
    }
}

fn omron_fins_summary(
    command_name: Option<&str>,
    source_node: Option<u8>,
    destination_node: Option<u8>,
) -> String {
    let mut summary = command_name.unwrap_or("fins_command").to_string();
    if let (Some(source_node), Some(destination_node)) = (source_node, destination_node) {
        summary.push_str(&format!(" {source_node}->{destination_node}"));
    }
    summary
}

fn omron_fins_object_refs(
    memory_area: Option<u8>,
    memory_word: Option<u16>,
    memory_bit: Option<u8>,
    item_count: Option<u16>,
) -> Vec<String> {
    let mut refs = Vec::new();
    if let Some(memory_area) = memory_area {
        refs.push(format!("memory_area:{memory_area:#04x}"));
    }
    if let Some(memory_word) = memory_word {
        refs.push(format!("memory_word:{memory_word}"));
    }
    if let Some(memory_bit) = memory_bit {
        refs.push(format!("memory_bit:{memory_bit}"));
    }
    if let Some(item_count) = item_count {
        refs.push(format!("item_count:{item_count}"));
    }
    refs
}

fn omron_fins_source_role(context: &PacketContext) -> Option<&'static str> {
    if context.dst_port == 9600 && context.src_port != 9600 {
        Some("controller")
    } else if context.src_port == 9600 && context.dst_port != 9600 {
        Some("plc")
    } else {
        None
    }
}

fn omron_fins_destination_role(context: &PacketContext) -> Option<&'static str> {
    if context.dst_port == 9600 && context.src_port != 9600 {
        Some("plc")
    } else if context.src_port == 9600 && context.dst_port != 9600 {
        Some("controller")
    } else {
        None
    }
}

fn hart_ip_operation_name(fields: &HartIpFields) -> String {
    match &fields.body {
        HartIpBody::PassThrough(pass) => normalize_operation_name(
            hart_passthrough_command_name(pass.command),
            "hart_pass_through",
        ),
        _ => normalize_operation_name(&fields.message_id, "hart_ip"),
    }
}

fn hart_ip_status(fields: &HartIpFields) -> &'static str {
    match fields.message_type.as_str() {
        "request" => "request",
        "response" => "response",
        "publish" => "publish",
        "error" | "nak" => "error",
        _ => "observed",
    }
}

fn hart_passthrough_command_name(command: u8) -> &'static str {
    match command {
        0 => "read_unique_identifier",
        11 => "read_device_identity",
        20 => "read_long_tag",
        21 => "read_tag_descriptor",
        22 => "read_message",
        _ => "pass_through_command",
    }
}

fn hart_ip_device_asset_key(context: &PacketContext, fields: &HartIpFields) -> String {
    if hart_ip_status(fields) == "response" {
        context_asset_key(context)
    } else {
        context_remote_asset_key(context)
    }
}

fn iec61850_profile_name(profile: Iec61850Profile) -> &'static str {
    match profile {
        Iec61850Profile::MmsIsoOnTcp => "mms",
        Iec61850Profile::Goose => "goose",
        Iec61850Profile::SampledValues => "sampled_values",
    }
}

fn iec61850_operation_name(fields: &Iec61850Fields) -> String {
    normalize_operation_name(
        fields
            .service
            .as_deref()
            .unwrap_or(fields.message_type.as_str()),
        "iec61850",
    )
}

fn iec61850_status(fields: &Iec61850Fields) -> &'static str {
    match fields.profile {
        Iec61850Profile::Goose | Iec61850Profile::SampledValues => "publish",
        Iec61850Profile::MmsIsoOnTcp => match fields.service.as_deref() {
            Some(service) if service.contains("response") => "response",
            Some(service) if service.contains("request") => "request",
            _ => "observed",
        },
    }
}

fn iec61850_summary(fields: &Iec61850Fields) -> String {
    let mut summary = fields
        .service
        .clone()
        .unwrap_or_else(|| fields.message_type.clone());
    if let Some(ied_name) = &fields.ied_name {
        summary.push_str(&format!(" {ied_name}"));
    }
    if let Some(dataset) = &fields.dataset {
        summary.push_str(&format!(" dataset={dataset}"));
    }
    summary
}

fn ethercat_operation_name(fields: &crate::dissectors::ethercat::EthercatFields) -> String {
    match fields.datagrams.as_slice() {
        [] => "ethercat_frame".to_string(),
        [single] => normalize_operation_name(&single.command, "ethercat_frame"),
        _ => "ethercat_multi_datagram".to_string(),
    }
}

fn ethercat_object_refs(fields: &crate::dissectors::ethercat::EthercatFields) -> Vec<String> {
    let mut refs = Vec::new();
    for datagram in &fields.datagrams {
        refs.push(format!("command:{}", datagram.command));
        refs.push(format!("adp:{}", datagram.adp));
        refs.push(format!("ado:{:#06x}", datagram.ado));
    }
    refs
}

fn ethercat_slave_asset_key(adp: u16, alias_address: Option<u16>) -> Option<String> {
    if let Some(alias_address) = alias_address {
        Some(format!("ethercat_alias:{alias_address}"))
    } else if adp != 0 {
        Some(format!("ethercat_adp:{adp}"))
    } else {
        None
    }
}

fn normalize_operation_name(label: &str, fallback: &str) -> String {
    let mut normalized = String::new();
    let mut last_was_separator = true;

    for ch in label.chars() {
        if ch.is_ascii_alphanumeric() {
            normalized.push(ch.to_ascii_lowercase());
            last_was_separator = false;
        } else if !last_was_separator {
            normalized.push('_');
            last_was_separator = true;
        }
    }

    while normalized.ends_with('_') {
        normalized.pop();
    }

    if normalized.is_empty() {
        fallback.to_string()
    } else {
        normalized
    }
}

fn ethernet_ip_command_name(command: u16) -> &'static str {
    match command {
        0x0001 => "nop",
        0x0004 => "list_services",
        0x0063 => "list_identity",
        0x0064 => "list_interfaces",
        0x0065 => "register_session",
        0x0066 => "unregister_session",
        0x006F => "send_rr_data",
        0x0070 => "send_unit_data",
        _ => "encapsulation_command",
    }
}

fn cip_service_name(cip_data: &[u8]) -> Option<&'static str> {
    let service = cip_explicit_message(cip_data)
        .and_then(|message| message.first().copied())
        .or_else(|| cip_data.iter().find(|byte| **byte != 0).copied())?;
    match service & 0x7F {
        0x01 => Some("get_attributes_all"),
        0x4C => Some("read_tag_service"),
        0x4D => Some("write_tag_service"),
        0x0E => Some("get_attribute_single"),
        0x10 => Some("set_attribute_single"),
        0x54 => Some("forward_open"),
        0x52 => Some("unconnected_send"),
        _ => None,
    }
}

fn cip_object_refs(cip_data: &[u8]) -> Vec<String> {
    let mut refs = Vec::new();
    if let Some(service) = cip_service_name(cip_data) {
        refs.push(format!("cip_service:{service}"));
    }
    if parse_cip_identity_response(cip_data).is_some() {
        refs.push("cip_object:identity".to_string());
    }
    refs
}

fn parse_cip_identity_claim(command: u16, cip_data: &[u8]) -> Option<CipIdentityClaim> {
    parse_cip_identity_claims(command, cip_data)
        .into_iter()
        .next()
}

fn parse_cip_identity_claims(command: u16, cip_data: &[u8]) -> Vec<CipIdentityClaim> {
    match command {
        0x0063 => parse_enip_list_identity(cip_data),
        0x006F | 0x0070 => parse_cip_identity_response(cip_data).into_iter().collect(),
        _ => Vec::new(),
    }
}

fn parse_enip_list_identity(data: &[u8]) -> Vec<CipIdentityClaim> {
    if data.len() < 2 {
        return Vec::new();
    }
    let item_count = u16::from_le_bytes([data[0], data[1]]) as usize;
    let mut offset = 2;
    let mut claims = Vec::new();
    for _ in 0..item_count {
        if offset + 4 > data.len() {
            break;
        }
        let item_type = u16::from_le_bytes([data[offset], data[offset + 1]]);
        let item_len = u16::from_le_bytes([data[offset + 2], data[offset + 3]]) as usize;
        offset += 4;
        if offset + item_len > data.len() {
            break;
        }
        let item = &data[offset..offset + item_len];
        if item_type == 0x000C {
            if let Some(claim) = parse_list_identity_item(item) {
                claims.push(claim);
            }
        }
        offset += item_len;
    }
    claims
}

fn parse_list_identity_item(item: &[u8]) -> Option<CipIdentityClaim> {
    if item.len() < 34 {
        return None;
    }
    let vendor_id = u16::from_le_bytes([item[18], item[19]]);
    let device_type = u16::from_le_bytes([item[20], item[21]]);
    let product_code = u16::from_le_bytes([item[22], item[23]]);
    let revision = format!("{}.{}", item[24], item[25]);
    let status = u16::from_le_bytes([item[26], item[27]]);
    let serial_number = u32::from_le_bytes([item[28], item[29], item[30], item[31]]);
    let name_len = item[32] as usize;
    if 33 + name_len > item.len() {
        return None;
    }
    let product_name = String::from_utf8_lossy(&item[33..33 + name_len]).to_string();
    let state = item.get(33 + name_len).copied();
    let ip_address = if item.len() >= 10 {
        Some(format!("{}.{}.{}.{}", item[6], item[7], item[8], item[9]))
    } else {
        None
    };
    Some(CipIdentityClaim {
        vendor_id,
        device_type,
        product_code,
        revision,
        serial_number,
        product_name,
        status,
        state,
        ip_address,
    })
}

fn parse_cip_identity_response(cip_data: &[u8]) -> Option<CipIdentityClaim> {
    let message = cip_explicit_message(cip_data)?;
    if message.len() < 4 || message[0] != 0x81 || message[2] != 0 {
        return None;
    }
    let additional_status_words = message[3] as usize;
    let data_offset = 4 + additional_status_words * 2;
    if data_offset + 15 > message.len() {
        return None;
    }
    let body = &message[data_offset..];
    let vendor_id = u16::from_le_bytes([body[0], body[1]]);
    let device_type = u16::from_le_bytes([body[2], body[3]]);
    let product_code = u16::from_le_bytes([body[4], body[5]]);
    let revision = format!("{}.{}", body[6], body[7]);
    let status = u16::from_le_bytes([body[8], body[9]]);
    let serial_number = u32::from_le_bytes([body[10], body[11], body[12], body[13]]);
    let name_len = body[14] as usize;
    if 15 + name_len > body.len() {
        return None;
    }
    let product_name = String::from_utf8_lossy(&body[15..15 + name_len]).to_string();
    let state = body.get(15 + name_len).copied();
    Some(CipIdentityClaim {
        vendor_id,
        device_type,
        product_code,
        revision,
        serial_number,
        product_name,
        status,
        state,
        ip_address: None,
    })
}

/// Detect CIP service 0x4B (Execute PCCC) inside an explicit CIP message and
/// return `(is_request, pccc_pdu_bytes)`. Returns None for any other service
/// or for malformed messages.
fn extract_pccc_pdu(message: &[u8]) -> Option<(bool, &[u8])> {
    if message.is_empty() {
        return None;
    }
    let service = message[0];
    let is_request = service & 0x80 == 0;
    if service & 0x7F != 0x4B {
        return None;
    }
    if is_request {
        if message.len() < 2 {
            return None;
        }
        let path_size_words = message[1] as usize;
        let header_len = 2 + path_size_words * 2;
        if message.len() < header_len {
            return None;
        }
        Some((true, &message[header_len..]))
    } else {
        // Response: service (1) + reserved (1) + general_status (1)
        // + ext_status_size (1) + ext status words
        if message.len() < 4 {
            return None;
        }
        let ext_status_words = message[3] as usize;
        let header_len = 4 + ext_status_words * 2;
        if message.len() < header_len {
            return None;
        }
        Some((false, &message[header_len..]))
    }
}

fn cip_explicit_message(cip_data: &[u8]) -> Option<&[u8]> {
    if cip_data.len() < 8 {
        return None;
    }
    let item_count = u16::from_le_bytes([cip_data[6], cip_data[7]]) as usize;
    let mut offset = 8;
    for _ in 0..item_count {
        if offset + 4 > cip_data.len() {
            return None;
        }
        let item_type = u16::from_le_bytes([cip_data[offset], cip_data[offset + 1]]);
        let item_len = u16::from_le_bytes([cip_data[offset + 2], cip_data[offset + 3]]) as usize;
        offset += 4;
        if offset + item_len > cip_data.len() {
            return None;
        }
        let item = &cip_data[offset..offset + item_len];
        if matches!(item_type, 0x00B1 | 0x00B2) {
            return Some(item);
        }
        offset += item_len;
    }
    None
}

fn cip_vendor_name(vendor_id: u16) -> Option<&'static str> {
    match vendor_id {
        1 => Some("Rockwell Automation/Allen-Bradley"),
        _ => None,
    }
}

fn cip_role_from_device_type(device_type: u16) -> Option<&'static str> {
    match device_type {
        0x000E => Some("plc"),
        0x000C => Some("adapter"),
        _ => None,
    }
}

/// Build a [`ModbusBronzeFields`] from the request and response PDUs.
///
/// `request_pdu` is `None` for unpaired response-only events. `response_pdu`
/// is `None` for partial-request (idle-flushed) events.
fn modbus_bronze_fields(
    request_pdu: Option<&ModbusPdu>,
    response_pdu: Option<&ModbusPdu>,
    is_exception: bool,
    exception_code: u8,
) -> Option<ModbusBronzeFields> {
    // Determine which PDU carries the register address (always the request).
    let req = request_pdu;
    let resp = response_pdu;

    let fc = req
        .map(|p| p.function_code)
        .or_else(|| resp.map(|p| p.function_code))?;

    let start_addr = req.and_then(|p| p.start_addr);
    let qty = req.and_then(|p| p.qty);

    // Values come from the response for read FCs, from the request for write FCs.
    let values: Vec<u16> = if let Some(r) = resp {
        if !r.values.is_empty() {
            r.values.clone()
        } else if let Some(req_pdu) = req {
            req_pdu.values.clone()
        } else {
            Vec::new()
        }
    } else if let Some(req_pdu) = req {
        req_pdu.values.clone()
    } else {
        Vec::new()
    };

    let direction = if req.is_some() && resp.is_some() {
        "paired".to_string()
    } else if req.is_some() {
        "request".to_string()
    } else {
        "response".to_string()
    };

    Some(ModbusBronzeFields {
        fc,
        start_addr,
        qty,
        values,
        exception_code: if is_exception { Some(exception_code) } else { None },
        direction,
    })
}

fn modbus_function_name(code: u8) -> &'static str {
    match code {
        1 => "read_coils",
        3 => "read_holding_registers",
        5 => "write_single_coil",
        6 => "write_single_register",
        15 => "write_multiple_coils",
        16 => "write_multiple_registers",
        43 => "read_device_identification",
        _ => "modbus_function",
    }
}

fn is_modbus_write(code: u8) -> bool {
    matches!(code, 5 | 6 | 15 | 16)
}

fn modbus_object_refs(fields: &ModbusFields) -> Vec<String> {
    let mut refs: Vec<String> = fields
        .registers
        .iter()
        .map(|(address, _)| format!("register:{address}"))
        .collect();
    if !fields.device_identification.is_empty() {
        refs.push("modbus_device_identification".to_string());
    }
    refs
}

fn modbus_values(fields: &ModbusFields) -> Vec<ObjectValue> {
    fields
        .registers
        .iter()
        .map(|(address, value)| ObjectValue {
            object_ref: format!("register:{address}"),
            value: Some(value.to_string()),
        })
        .collect()
}

fn modbus_attributes(fields: &ModbusFields) -> BTreeMap<String, String> {
    let mut attributes = BTreeMap::new();
    attributes.insert("unit_id".to_string(), fields.unit_id.to_string());
    attributes.insert(
        "transaction_id".to_string(),
        fields.transaction_id.to_string(),
    );
    attributes.insert(
        "function_code".to_string(),
        fields.function_code.to_string(),
    );
    for (key, value) in &fields.device_identification {
        attributes.insert(format!("device_id_{key}"), value.clone());
    }
    attributes
}

fn modbus_summary(fields: &ModbusFields) -> String {
    if fields.is_exception {
        return format!(
            "{} exception {}",
            modbus_function_name(fields.function_code),
            fields.exception_code
        );
    }
    if fields.function_code == 43 && !fields.device_identification.is_empty() {
        return fields
            .device_identification
            .get("model_name")
            .or_else(|| fields.device_identification.get("product_name"))
            .or_else(|| fields.device_identification.get("product_code"))
            .cloned()
            .unwrap_or_else(|| "device_identification".to_string());
    }
    if fields.registers.is_empty() {
        modbus_function_name(fields.function_code).to_string()
    } else {
        format!(
            "{} {}",
            modbus_function_name(fields.function_code),
            fields
                .registers
                .iter()
                .map(|(address, value)| format!("{address}={value}"))
                .collect::<Vec<_>>()
                .join(", ")
        )
    }
}

fn modbus_identity_observation(
    capture_id: String,
    envelope: EventEnvelope,
    asset_ip: String,
    unit_id: u8,
    device_identification: &BTreeMap<String, String>,
) -> BronzeEvent {
    let mut identifiers = BTreeMap::from([
        ("ip".to_string(), asset_ip.clone()),
        ("unit_id".to_string(), unit_id.to_string()),
    ]);
    for (key, value) in device_identification {
        identifiers.insert(format!("modbus_{key}"), value.clone());
    }
    new_event(
        capture_id,
        envelope,
        BronzeEventFamily::AssetObservation(AssetObservation {
            asset_key: asset_ip,
            role: Some("server".to_string()),
            vendor: device_identification.get("vendor_name").cloned(),
            model: device_identification
                .get("model_name")
                .cloned()
                .or_else(|| device_identification.get("product_name").cloned())
                .or_else(|| device_identification.get("product_code").cloned()),
            firmware: device_identification.get("revision").cloned(),
            hostnames: Vec::new(),
            protocols: vec!["modbus".to_string()],
            identifiers,
        }),
    )
}

#[derive(Debug)]
struct ParsedTls {
    version: String,
    sni: Option<String>,
    cipher_suite: Option<String>,
}

fn parse_tls_client_hello(payload: &[u8]) -> Option<ParsedTls> {
    if payload.len() < 9 {
        return None;
    }
    let content_type = payload[0];
    if content_type != 22 {
        return None;
    }
    let version = format!("TLS {:02x}{:02x}", payload[1], payload[2]);
    let record_len = u16::from_be_bytes([payload[3], payload[4]]) as usize;
    if payload.len() < 5 + record_len || payload[5] != 1 {
        return None;
    }

    let mut offset = 9; // record header + handshake header
    if payload.len() < offset + 34 {
        return None;
    }
    offset += 2; // client version
    offset += 32; // random
    let session_id_len = *payload.get(offset)? as usize;
    offset += 1 + session_id_len;
    let cipher_len =
        u16::from_be_bytes([*payload.get(offset)?, *payload.get(offset + 1)?]) as usize;
    offset += 2;
    let cipher_suite = if cipher_len >= 2 && offset + 2 <= payload.len() {
        Some(format!(
            "0x{:02x}{:02x}",
            payload[offset],
            payload[offset + 1]
        ))
    } else {
        None
    };
    offset += cipher_len;
    let compression_len = *payload.get(offset)? as usize;
    offset += 1 + compression_len;
    let ext_len = u16::from_be_bytes([*payload.get(offset)?, *payload.get(offset + 1)?]) as usize;
    offset += 2;
    let ext_end = offset.checked_add(ext_len)?.min(payload.len());

    let mut sni = None;
    while offset + 4 <= ext_end {
        let ext_type = u16::from_be_bytes([payload[offset], payload[offset + 1]]);
        let item_len = u16::from_be_bytes([payload[offset + 2], payload[offset + 3]]) as usize;
        offset += 4;
        if offset + item_len > ext_end {
            break;
        }
        if ext_type == 0x0000 && item_len >= 5 {
            let list_len = u16::from_be_bytes([payload[offset], payload[offset + 1]]) as usize;
            if list_len + 2 <= item_len && payload[offset + 2] == 0 {
                let name_len =
                    u16::from_be_bytes([payload[offset + 3], payload[offset + 4]]) as usize;
                if offset + 5 + name_len <= ext_end {
                    sni = std::str::from_utf8(&payload[offset + 5..offset + 5 + name_len])
                        .ok()
                        .map(str::to_string);
                }
            }
        }
        offset += item_len;
    }

    Some(ParsedTls {
        version,
        sni,
        cipher_suite,
    })
}

// ── NTP decoder ──────────────────────────────────────────────────

#[derive(Default)]
struct NtpDecoder {
    dissector: NtpDissector,
}

impl SessionDecoder for NtpDecoder {
    fn name(&self) -> &'static str {
        "ntp"
    }

    fn interest(&self) -> &'static [DecoderInterest] {
        &[DecoderInterest::UdpPort(123)]
    }

    fn on_datagram(&mut self, chunk: &StreamChunk<'_>, out: &mut Vec<BronzeEvent>) {
        match self.dissector.parse(chunk.payload, &chunk.context) {
            Some(ProtocolData::Ntp(NtpFields {
                version,
                mode,
                mode_name,
                stratum,
                reference_id,
                ..
            })) => {
                let envelope = build_envelope(
                    &chunk.context,
                    chunk.interface_id,
                    chunk.frame_index,
                    chunk.timestamp,
                    chunk.segment_hash,
                    TransportProtocol::Udp,
                    Some("ntp"),
                    chunk.captured_len,
                    chunk.session_key.clone(),
                );

                let mut attributes = BTreeMap::new();
                attributes.insert("version".to_string(), version.to_string());
                attributes.insert("stratum".to_string(), stratum.to_string());
                attributes.insert("reference_id".to_string(), reference_id.clone());

                out.push(new_event(
                    chunk.capture_id.to_string(),
                    envelope.clone(),
                    BronzeEventFamily::ProtocolTransaction(ProtocolTransaction {
                        operation: mode_name.clone(),
                        status: if mode == 4 { "response" } else { "request" }.to_string(),
                        request_summary: Some(format!("NTPv{version} {mode_name}")),
                        response_summary: None,
                        object_refs: vec![],
                        values: vec![],
                        attributes,
                                        modbus: None,
}),
                ));

                // NTP servers (mode 4, stratum 1-15) are worth identifying.
                if mode == 4 && stratum > 0 && stratum < 16 {
                    let mut identifiers = BTreeMap::from([(
                        "ip".to_string(),
                        chunk.context.src_ip.to_string(),
                    )]);
                    identifiers
                        .insert("reference_id".to_string(), reference_id);
                    out.push(new_event(
                        chunk.capture_id.to_string(),
                        envelope,
                        BronzeEventFamily::AssetObservation(AssetObservation {
                            asset_key: chunk.context.src_ip.to_string(),
                            role: Some("ntp_server".to_string()),
                            vendor: None,
                            model: None,
                            firmware: None,
                            hostnames: vec![],
                            protocols: vec!["ntp".to_string()],
                            identifiers,
                        }),
                    ));
                }
            }
            _ => out.push(parse_anomaly_event(
                chunk.capture_id.to_string(),
                build_envelope(
                    &chunk.context,
                    chunk.interface_id,
                    chunk.frame_index,
                    chunk.timestamp,
                    chunk.segment_hash,
                    TransportProtocol::Udp,
                    Some("ntp"),
                    chunk.captured_len,
                    chunk.session_key.clone(),
                ),
                self.name(),
                "low",
                "failed to parse ntp payload",
                chunk.payload,
            )),
        }
    }
}

// ── MQTT decoder ─────────────────────────────────────────────────

struct MqttDecoder {
    dissector: MqttDissector,
    payload_decoders: Vec<Box<dyn crate::mqtt_payload::MqttPayloadDecoder>>,
}

impl Default for MqttDecoder {
    fn default() -> Self {
        Self {
            dissector: MqttDissector,
            payload_decoders: vec![Box::new(crate::sparkplug::SparkplugBDecoder::new())],
        }
    }
}

impl SessionDecoder for MqttDecoder {
    fn name(&self) -> &'static str {
        "mqtt"
    }

    fn interest(&self) -> &'static [DecoderInterest] {
        &[
            DecoderInterest::TcpPort(1883),
            DecoderInterest::TcpPort(8883),
        ]
    }

    fn on_stream_chunk(&mut self, chunk: &StreamChunk<'_>, out: &mut Vec<BronzeEvent>) {
        match self.dissector.parse(chunk.payload, &chunk.context) {
            Some(ProtocolData::Mqtt(MqttFields {
                packet_type,
                packet_type_name,
                protocol_name,
                protocol_version,
                client_id,
                username,
                topic,
                qos,
                retain,
                payload: mqtt_payload,
                ..
            })) => {
                let envelope = build_envelope(
                    &chunk.context,
                    chunk.interface_id,
                    chunk.frame_index,
                    chunk.timestamp,
                    chunk.segment_hash,
                    TransportProtocol::Tcp,
                    Some("mqtt"),
                    chunk.captured_len,
                    chunk.session_key.clone(),
                );

                let mut attributes = BTreeMap::new();
                if let Some(ref proto) = protocol_name {
                    attributes.insert("protocol_name".to_string(), proto.clone());
                }
                if let Some(ver) = protocol_version {
                    attributes.insert("protocol_version".to_string(), ver.to_string());
                }
                if let Some(ref cid) = client_id {
                    attributes.insert("client_id".to_string(), cid.clone());
                }
                if let Some(ref user) = username {
                    attributes.insert("username".to_string(), user.clone());
                }
                if let Some(q) = qos {
                    attributes.insert("qos".to_string(), q.to_string());
                }

                let operation = packet_type_name.to_lowercase();
                let summary = match packet_type {
                    1 => {
                        let cid_str = client_id.as_deref().unwrap_or("?");
                        format!("CONNECT client_id={cid_str}")
                    }
                    3 => {
                        let t = topic.as_deref().unwrap_or("?");
                        format!("PUBLISH topic={t}")
                    }
                    8 => {
                        let t = topic.as_deref().unwrap_or("?");
                        format!("SUBSCRIBE topic={t}")
                    }
                    _ => packet_type_name.clone(),
                };

                let object_refs = topic.clone().into_iter().collect();

                out.push(new_event(
                    chunk.capture_id.to_string(),
                    envelope.clone(),
                    BronzeEventFamily::ProtocolTransaction(ProtocolTransaction {
                        operation,
                        status: "ok".to_string(),
                        request_summary: Some(summary),
                        response_summary: None,
                        object_refs,
                        values: vec![],
                        attributes,
                                        modbus: None,
}),
                ));

                // CONNECT packets identify the client device.
                if packet_type == 1 {
                    let mut identifiers = BTreeMap::from([(
                        "ip".to_string(),
                        chunk.context.src_ip.to_string(),
                    )]);
                    if let Some(ref cid) = client_id {
                        identifiers.insert("client_id".to_string(), cid.clone());
                    }
                    out.push(new_event(
                        chunk.capture_id.to_string(),
                        envelope,
                        BronzeEventFamily::AssetObservation(AssetObservation {
                            asset_key: chunk.context.src_ip.to_string(),
                            role: Some("mqtt_client".to_string()),
                            vendor: None,
                            model: None,
                            firmware: None,
                            hostnames: username.into_iter().collect(),
                            protocols: vec!["mqtt".to_string()],
                            identifiers,
                        }),
                    ));
                }

                // PUBLISH payloads fan out to registered MqttPayloadDecoders
                // (Sparkplug B, future UADP / vendor schemas).
                if packet_type == 3 {
                    if let (Some(topic_str), Some(payload_bytes)) =
                        (topic.as_deref(), mqtt_payload.as_deref())
                    {
                        let ctx = build_mqtt_publish_context(
                            chunk,
                            topic_str,
                            payload_bytes,
                            client_id.as_deref(),
                            qos.unwrap_or(0),
                            retain.unwrap_or(false),
                        );
                        for decoder in self.payload_decoders.iter_mut() {
                            let mut events = decoder.try_decode(&ctx);
                            if !events.is_empty() {
                                out.append(&mut events);
                                break; // first decoder that claims the payload wins
                            }
                        }
                    }
                }
            }
            _ => out.push(parse_anomaly_event(
                chunk.capture_id.to_string(),
                build_envelope(
                    &chunk.context,
                    chunk.interface_id,
                    chunk.frame_index,
                    chunk.timestamp,
                    chunk.segment_hash,
                    TransportProtocol::Tcp,
                    Some("mqtt"),
                    chunk.captured_len,
                    chunk.session_key.clone(),
                ),
                self.name(),
                "medium",
                "failed to parse mqtt payload",
                chunk.payload,
            )),
        }
    }
}

/// Build an [`MqttPublishContext`] from a [`StreamChunk`] for fanout to
/// registered [`crate::mqtt_payload::MqttPayloadDecoder`] implementations.
///
/// `broker_endpoint` is whichever side of the flow uses port 1883/8883; if
/// neither matches (unusual) we default to the destination side.
fn build_mqtt_publish_context<'a>(
    chunk: &'a StreamChunk<'a>,
    topic: &'a str,
    payload: &'a [u8],
    client_id: Option<&'a str>,
    qos: u8,
    retain: bool,
) -> crate::mqtt_payload::MqttPublishContext<'a> {
    use crate::mqtt_payload::{FlowFiveTuple, MqttPublishContext};
    use std::net::SocketAddr;

    let src = SocketAddr::new(chunk.context.src_ip, chunk.context.src_port);
    let dst = SocketAddr::new(chunk.context.dst_ip, chunk.context.dst_port);
    let broker_endpoint = if matches!(chunk.context.dst_port, 1883 | 8883) {
        dst
    } else if matches!(chunk.context.src_port, 1883 | 8883) {
        src
    } else {
        dst
    };
    let publisher_mac = if broker_endpoint == dst {
        chunk.context.src_mac
    } else {
        chunk.context.dst_mac
    };
    MqttPublishContext {
        broker_endpoint,
        flow_5tuple: FlowFiveTuple {
            src,
            dst,
            transport: 6, // TCP
        },
        client_id,
        topic,
        payload,
        retain,
        qos,
        // chunk.context.timestamp is nanoseconds since epoch; the publish
        // context API uses microseconds.
        packet_ts_us: chunk.context.timestamp / 1_000,
        vlan_id: chunk.context.vlan_id,
        publisher_mac,
    }
}

// ── Syslog decoder ───────────────────────────────────────────────

#[derive(Default)]
struct SyslogDecoder {
    dissector: SyslogDissector,
}

impl SessionDecoder for SyslogDecoder {
    fn name(&self) -> &'static str {
        "syslog"
    }

    fn interest(&self) -> &'static [DecoderInterest] {
        &[DecoderInterest::UdpPort(514)]
    }

    fn on_datagram(&mut self, chunk: &StreamChunk<'_>, out: &mut Vec<BronzeEvent>) {
        match self.dissector.parse(chunk.payload, &chunk.context) {
            Some(ProtocolData::Syslog(SyslogFields {
                facility: _,
                facility_name,
                severity,
                severity_name,
                hostname,
                app_name,
                message,
            })) => {
                let envelope = build_envelope(
                    &chunk.context,
                    chunk.interface_id,
                    chunk.frame_index,
                    chunk.timestamp,
                    chunk.segment_hash,
                    TransportProtocol::Udp,
                    Some("syslog"),
                    chunk.captured_len,
                    chunk.session_key.clone(),
                );

                let mut attributes = BTreeMap::new();
                attributes.insert("facility".to_string(), facility_name.clone());
                attributes.insert("severity".to_string(), severity_name.clone());
                if let Some(ref app) = app_name {
                    attributes.insert("app_name".to_string(), app.clone());
                }

                out.push(new_event(
                    chunk.capture_id.to_string(),
                    envelope.clone(),
                    BronzeEventFamily::ProtocolTransaction(ProtocolTransaction {
                        operation: "syslog_message".to_string(),
                        status: severity_name,
                        request_summary: message,
                        response_summary: None,
                        object_refs: vec![format!("{facility_name}.{severity}")],
                        values: vec![],
                        attributes,
                                        modbus: None,
}),
                ));

                // Hostname in syslog = asset identification.
                if let Some(hostname) = hostname {
                    let mut identifiers = BTreeMap::from([(
                        "ip".to_string(),
                        chunk.context.src_ip.to_string(),
                    )]);
                    identifiers.insert("hostname".to_string(), hostname.clone());
                    let protocols = if let Some(ref app) = app_name {
                        vec!["syslog".to_string(), app.clone()]
                    } else {
                        vec!["syslog".to_string()]
                    };
                    out.push(new_event(
                        chunk.capture_id.to_string(),
                        envelope,
                        BronzeEventFamily::AssetObservation(AssetObservation {
                            asset_key: chunk.context.src_ip.to_string(),
                            role: None,
                            vendor: None,
                            model: None,
                            firmware: None,
                            hostnames: vec![hostname],
                            protocols,
                            identifiers,
                        }),
                    ));
                }
            }
            _ => out.push(parse_anomaly_event(
                chunk.capture_id.to_string(),
                build_envelope(
                    &chunk.context,
                    chunk.interface_id,
                    chunk.frame_index,
                    chunk.timestamp,
                    chunk.segment_hash,
                    TransportProtocol::Udp,
                    Some("syslog"),
                    chunk.captured_len,
                    chunk.session_key.clone(),
                ),
                self.name(),
                "low",
                "failed to parse syslog payload",
                chunk.payload,
            )),
        }
    }
}

// ── FTP decoder ──────────────────────────────────────────────────

#[derive(Default)]
struct FtpDecoder {
    dissector: FtpDissector,
}

impl SessionDecoder for FtpDecoder {
    fn name(&self) -> &'static str {
        "ftp"
    }

    fn interest(&self) -> &'static [DecoderInterest] {
        &[DecoderInterest::TcpPort(21)]
    }

    fn on_stream_chunk(&mut self, chunk: &StreamChunk<'_>, out: &mut Vec<BronzeEvent>) {
        match self.dissector.parse(chunk.payload, &chunk.context) {
            Some(ProtocolData::Ftp(FtpFields {
                is_response,
                command,
                argument,
                reply_code,
                reply_text,
                banner,
            })) => {
                let envelope = build_envelope(
                    &chunk.context,
                    chunk.interface_id,
                    chunk.frame_index,
                    chunk.timestamp,
                    chunk.segment_hash,
                    TransportProtocol::Tcp,
                    Some("ftp"),
                    chunk.captured_len,
                    chunk.session_key.clone(),
                );

                let (operation, status, summary) = if is_response {
                    let code = reply_code.unwrap_or(0);
                    let text = reply_text.as_deref().unwrap_or("");
                    (
                        "reply".to_string(),
                        format!("{code}"),
                        format!("{code} {text}"),
                    )
                } else {
                    let cmd = command.as_deref().unwrap_or("?");
                    let arg = argument.as_deref().unwrap_or("");
                    (
                        cmd.to_lowercase(),
                        "request".to_string(),
                        format!("{cmd} {arg}").trim().to_string(),
                    )
                };

                let mut attributes = BTreeMap::new();
                if let Some(ref cmd) = command {
                    attributes.insert("command".to_string(), cmd.clone());
                }
                if let Some(ref arg) = argument {
                    attributes.insert("argument".to_string(), arg.clone());
                }

                out.push(new_event(
                    chunk.capture_id.to_string(),
                    envelope.clone(),
                    BronzeEventFamily::ProtocolTransaction(ProtocolTransaction {
                        operation,
                        status,
                        request_summary: Some(summary),
                        response_summary: None,
                        object_refs: argument.into_iter().collect(),
                        values: vec![],
                        attributes,
                                        modbus: None,
}),
                ));

                // Banner (220) identifies the FTP server.
                if let Some(banner_text) = banner {
                    out.push(new_event(
                        chunk.capture_id.to_string(),
                        envelope,
                        BronzeEventFamily::AssetObservation(AssetObservation {
                            asset_key: chunk.context.src_ip.to_string(),
                            role: Some("ftp_server".to_string()),
                            vendor: None,
                            model: None,
                            firmware: Some(banner_text),
                            hostnames: vec![],
                            protocols: vec!["ftp".to_string()],
                            identifiers: BTreeMap::from([(
                                "ip".to_string(),
                                chunk.context.src_ip.to_string(),
                            )]),
                        }),
                    ));
                }
            }
            _ => out.push(parse_anomaly_event(
                chunk.capture_id.to_string(),
                build_envelope(
                    &chunk.context,
                    chunk.interface_id,
                    chunk.frame_index,
                    chunk.timestamp,
                    chunk.segment_hash,
                    TransportProtocol::Tcp,
                    Some("ftp"),
                    chunk.captured_len,
                    chunk.session_key.clone(),
                ),
                self.name(),
                "medium",
                "failed to parse ftp payload",
                chunk.payload,
            )),
        }
    }
}

// ── SSH decoder ──────────────────────────────────────────────────

#[derive(Default)]
struct SshDecoder {
    dissector: SshDissector,
}

impl SessionDecoder for SshDecoder {
    fn name(&self) -> &'static str {
        "ssh"
    }

    fn interest(&self) -> &'static [DecoderInterest] {
        &[DecoderInterest::TcpPort(22)]
    }

    fn on_stream_chunk(&mut self, chunk: &StreamChunk<'_>, out: &mut Vec<BronzeEvent>) {
        // Only parse banner packets (contain "SSH-").
        if !chunk.payload.windows(4).any(|w| w == b"SSH-") {
            return;
        }
        match self.dissector.parse(chunk.payload, &chunk.context) {
            Some(ProtocolData::Ssh(SshFields {
                protocol_version,
                software_version,
                comments,
                banner,
            })) => {
                let envelope = build_envelope(
                    &chunk.context,
                    chunk.interface_id,
                    chunk.frame_index,
                    chunk.timestamp,
                    chunk.segment_hash,
                    TransportProtocol::Tcp,
                    Some("ssh"),
                    chunk.captured_len,
                    chunk.session_key.clone(),
                );

                let mut attributes = BTreeMap::new();
                attributes
                    .insert("protocol_version".to_string(), protocol_version.clone());
                attributes
                    .insert("software_version".to_string(), software_version.clone());
                if let Some(ref c) = comments {
                    attributes.insert("comments".to_string(), c.clone());
                }

                out.push(new_event(
                    chunk.capture_id.to_string(),
                    envelope.clone(),
                    BronzeEventFamily::ProtocolTransaction(ProtocolTransaction {
                        operation: "banner".to_string(),
                        status: "ok".to_string(),
                        request_summary: Some(banner),
                        response_summary: None,
                        object_refs: vec![],
                        values: vec![],
                        attributes,
                                        modbus: None,
}),
                ));

                // The banner sender is the SSH server — identify it.
                let is_server = chunk.context.src_port == 22;
                let firmware = Some(software_version.clone());
                let role = if is_server {
                    "ssh_server"
                } else {
                    "ssh_client"
                };
                let ip = if is_server {
                    chunk.context.src_ip.to_string()
                } else {
                    chunk.context.dst_ip.to_string()
                };
                let mut identifiers =
                    BTreeMap::from([("ip".to_string(), ip.clone())]);
                identifiers.insert(
                    "software_version".to_string(),
                    software_version,
                );
                if let Some(c) = comments {
                    identifiers.insert("os_hint".to_string(), c);
                }

                out.push(new_event(
                    chunk.capture_id.to_string(),
                    envelope,
                    BronzeEventFamily::AssetObservation(AssetObservation {
                        asset_key: ip,
                        role: Some(role.to_string()),
                        vendor: None,
                        model: None,
                        firmware,
                        hostnames: vec![],
                        protocols: vec!["ssh".to_string()],
                        identifiers,
                    }),
                ));
            }
            _ => {}
        }
    }
}

// ── RADIUS decoder ───────────────────────────────────────────────

#[derive(Default)]
struct RadiusDecoder {
    dissector: RadiusDissector,
}

impl SessionDecoder for RadiusDecoder {
    fn name(&self) -> &'static str {
        "radius"
    }

    fn interest(&self) -> &'static [DecoderInterest] {
        &[
            DecoderInterest::UdpPort(1812),
            DecoderInterest::UdpPort(1813),
        ]
    }

    fn on_datagram(&mut self, chunk: &StreamChunk<'_>, out: &mut Vec<BronzeEvent>) {
        match self.dissector.parse(chunk.payload, &chunk.context) {
            Some(ProtocolData::Radius(RadiusFields {
                code,
                code_name,
                identifier,
                username,
                nas_ip_address,
                nas_identifier,
                calling_station_id,
                called_station_id,
                nas_port_type,
                framed_ip_address,
                service_type,
            })) => {
                let envelope = build_envelope(
                    &chunk.context,
                    chunk.interface_id,
                    chunk.frame_index,
                    chunk.timestamp,
                    chunk.segment_hash,
                    TransportProtocol::Udp,
                    Some("radius"),
                    chunk.captured_len,
                    chunk.session_key.clone(),
                );

                let mut attributes = BTreeMap::new();
                attributes.insert("identifier".to_string(), identifier.to_string());
                if let Some(ref user) = username {
                    attributes.insert("username".to_string(), user.clone());
                }
                if let Some(ref nas_ip) = nas_ip_address {
                    attributes.insert("nas_ip_address".to_string(), nas_ip.clone());
                }
                if let Some(ref nas_id) = nas_identifier {
                    attributes.insert("nas_identifier".to_string(), nas_id.clone());
                }
                if let Some(ref csi) = calling_station_id {
                    attributes.insert("calling_station_id".to_string(), csi.clone());
                }
                if let Some(ref csi) = called_station_id {
                    attributes.insert("called_station_id".to_string(), csi.clone());
                }
                if let Some(npt) = nas_port_type {
                    attributes.insert("nas_port_type".to_string(), npt.to_string());
                }
                if let Some(ref fip) = framed_ip_address {
                    attributes.insert("framed_ip_address".to_string(), fip.clone());
                }
                if let Some(st) = service_type {
                    attributes.insert("service_type".to_string(), st.to_string());
                }

                let status = match code {
                    2 | 5 | 41 | 44 => "accept",
                    3 | 42 | 45 => "reject",
                    _ => "request",
                };

                out.push(new_event(
                    chunk.capture_id.to_string(),
                    envelope.clone(),
                    BronzeEventFamily::ProtocolTransaction(ProtocolTransaction {
                        operation: code_name.to_lowercase().replace('-', "_"),
                        status: status.to_string(),
                        request_summary: Some(format!(
                            "{code_name} id={identifier}{}",
                            username
                                .as_ref()
                                .map(|u| format!(" user={u}"))
                                .unwrap_or_default()
                        )),
                        response_summary: None,
                        object_refs: username.clone().into_iter().collect(),
                        values: vec![],
                        attributes,
                                        modbus: None,
}),
                ));

                // NAS identification from Access-Request.
                if code == 1 {
                    if let Some(nas_ip) = nas_ip_address {
                        let hostnames = nas_identifier.clone().into_iter().collect();
                        let mut identifiers =
                            BTreeMap::from([("ip".to_string(), nas_ip.clone())]);
                        if let Some(nas_id) = nas_identifier {
                            identifiers
                                .insert("nas_identifier".to_string(), nas_id.clone());
                        }
                        out.push(new_event(
                            chunk.capture_id.to_string(),
                            envelope,
                            BronzeEventFamily::AssetObservation(AssetObservation {
                                asset_key: nas_ip,
                                role: Some("network_device".to_string()),
                                vendor: None,
                                model: None,
                                firmware: None,
                                hostnames,
                                protocols: vec!["radius".to_string()],
                                identifiers,
                            }),
                        ));
                    }
                }
            }
            _ => out.push(parse_anomaly_event(
                chunk.capture_id.to_string(),
                build_envelope(
                    &chunk.context,
                    chunk.interface_id,
                    chunk.frame_index,
                    chunk.timestamp,
                    chunk.segment_hash,
                    TransportProtocol::Udp,
                    Some("radius"),
                    chunk.captured_len,
                    chunk.session_key.clone(),
                ),
                self.name(),
                "medium",
                "failed to parse radius payload",
                chunk.payload,
            )),
        }
    }
}

// ── VTP decoder ──────────────────────────────────────────────────

#[derive(Default)]
struct VtpDecoder {
    dissector: VtpDissector,
}

impl SessionDecoder for VtpDecoder {
    fn name(&self) -> &'static str {
        "vtp"
    }

    fn interest(&self) -> &'static [DecoderInterest] {
        &[DecoderInterest::Snap {
            oui: [0x00, 0x00, 0x0C],
            pid: 0x2003,
        }]
    }

    fn on_datagram(&mut self, chunk: &StreamChunk<'_>, out: &mut Vec<BronzeEvent>) {
        match self.dissector.parse(chunk.payload, &chunk.context) {
            Some(ProtocolData::Vtp(VtpFields {
                version,
                message_type: _,
                message_type_name,
                domain_name,
                revision,
                vlans,
            })) => {
                let envelope = build_envelope(
                    &chunk.context,
                    chunk.interface_id,
                    chunk.frame_index,
                    chunk.timestamp,
                    chunk.segment_hash,
                    TransportProtocol::Ethernet,
                    Some("vtp"),
                    chunk.captured_len,
                    chunk.session_key.clone(),
                );

                let mut attributes = BTreeMap::new();
                attributes.insert("version".to_string(), version.to_string());
                attributes.insert("domain_name".to_string(), domain_name.clone());
                if let Some(rev) = revision {
                    attributes.insert("revision".to_string(), rev.to_string());
                }
                if !vlans.is_empty() {
                    attributes.insert(
                        "vlans".to_string(),
                        vlans.iter().map(|v| v.to_string()).collect::<Vec<_>>().join(","),
                    );
                }

                out.push(new_event(
                    chunk.capture_id.to_string(),
                    envelope.clone(),
                    BronzeEventFamily::ProtocolTransaction(ProtocolTransaction {
                        operation: message_type_name,
                        status: "ok".to_string(),
                        request_summary: Some(format!("VTP domain={domain_name}")),
                        response_summary: None,
                        object_refs: vec![domain_name.clone()],
                        values: vec![],
                        attributes,
                                        modbus: None,
}),
                ));

                out.push(new_event(
                    chunk.capture_id.to_string(),
                    envelope,
                    BronzeEventFamily::AssetObservation(AssetObservation {
                        asset_key: format_mac(&chunk.context.src_mac),
                        role: Some("switch".to_string()),
                        vendor: Some("Cisco".to_string()),
                        model: None,
                        firmware: None,
                        hostnames: vec![],
                        protocols: vec!["vtp".to_string()],
                        identifiers: BTreeMap::from([
                            ("mac".to_string(), format_mac(&chunk.context.src_mac)),
                            ("vtp_domain".to_string(), domain_name),
                        ]),
                    }),
                ));
            }
            _ => {}
        }
    }
}

// ── MRP decoder ──────────────────────────────────────────────────

#[derive(Default)]
struct MrpDecoder {
    dissector: MrpDissector,
}

impl SessionDecoder for MrpDecoder {
    fn name(&self) -> &'static str {
        "mrp"
    }

    fn interest(&self) -> &'static [DecoderInterest] {
        &[DecoderInterest::EtherType(0x88E3)]
    }

    fn on_datagram(&mut self, chunk: &StreamChunk<'_>, out: &mut Vec<BronzeEvent>) {
        match self.dissector.parse(chunk.payload, &chunk.context) {
            Some(ProtocolData::Mrp(MrpFields {
                version: _,
                frame_type: _,
                frame_type_name,
                domain_uuid,
                ring_state,
                priority,
                source_mac,
            })) => {
                let envelope = build_envelope(
                    &chunk.context,
                    chunk.interface_id,
                    chunk.frame_index,
                    chunk.timestamp,
                    chunk.segment_hash,
                    TransportProtocol::Ethernet,
                    Some("mrp"),
                    chunk.captured_len,
                    chunk.session_key.clone(),
                );

                let mut metadata = BTreeMap::new();
                if let Some(ref uuid) = domain_uuid {
                    metadata.insert("domain_uuid".to_string(), uuid.clone());
                }
                if let Some(ref state) = ring_state {
                    metadata.insert("ring_state".to_string(), state.clone());
                }
                if let Some(prio) = priority {
                    metadata.insert("priority".to_string(), prio.to_string());
                }

                let local_id = source_mac
                    .clone()
                    .unwrap_or_else(|| format_mac(&chunk.context.src_mac));

                out.push(new_event(
                    chunk.capture_id.to_string(),
                    envelope.clone(),
                    BronzeEventFamily::TopologyObservation(TopologyObservation {
                        observation_type: format!("mrp_{}", frame_type_name.to_lowercase()),
                        local_id: local_id.clone(),
                        remote_id: domain_uuid,
                        description: ring_state.clone(),
                        capabilities: vec!["mrp".to_string()],
                        metadata,
                    }),
                ));

                out.push(new_event(
                    chunk.capture_id.to_string(),
                    envelope,
                    BronzeEventFamily::AssetObservation(AssetObservation {
                        asset_key: local_id,
                        role: Some("switch".to_string()),
                        vendor: None,
                        model: None,
                        firmware: None,
                        hostnames: vec![],
                        protocols: vec!["mrp".to_string()],
                        identifiers: BTreeMap::from([(
                            "mac".to_string(),
                            format_mac(&chunk.context.src_mac),
                        )]),
                    }),
                ));
            }
            _ => {}
        }
    }
}

// ── MSTP decoder ─────────────────────────────────────────────────

#[derive(Default)]
struct MstpDecoder {
    dissector: MstpDissector,
}

impl SessionDecoder for MstpDecoder {
    fn name(&self) -> &'static str {
        "mstp"
    }

    fn interest(&self) -> &'static [DecoderInterest] {
        &[DecoderInterest::Llc {
            dsap: 0x42,
            ssap: 0x42,
        }]
    }

    fn on_datagram(&mut self, chunk: &StreamChunk<'_>, out: &mut Vec<BronzeEvent>) {
        // Only handle version >= 3; regular STP/RSTP falls through to StpDecoder.
        let fields = match self.dissector.parse(chunk.payload, &chunk.context) {
            Some(ProtocolData::Mstp(f)) => f,
            _ => return,
        };

        let envelope = build_envelope(
            &chunk.context,
            chunk.interface_id,
            chunk.frame_index,
            chunk.timestamp,
            chunk.segment_hash,
            TransportProtocol::Ethernet,
            Some("mstp"),
            chunk.captured_len,
            chunk.session_key.clone(),
        );

        let mut metadata = BTreeMap::new();
        metadata.insert("protocol_version".to_string(), fields.protocol_version.to_string());
        if let Some(ref name) = fields.config_name {
            metadata.insert("config_name".to_string(), name.clone());
        }
        if let Some(rev) = fields.revision_level {
            metadata.insert("revision_level".to_string(), rev.to_string());
        }
        metadata.insert("msti_count".to_string(), fields.msti_records.len().to_string());

        out.push(new_event(
            chunk.capture_id.to_string(),
            envelope.clone(),
            BronzeEventFamily::TopologyObservation(TopologyObservation {
                observation_type: "mstp_bpdu".to_string(),
                local_id: fields.bridge_id.clone(),
                remote_id: Some(fields.root_id.clone()),
                description: fields.config_name.clone(),
                capabilities: vec!["mstp".to_string()],
                metadata,
            }),
        ));

        out.push(new_event(
            chunk.capture_id.to_string(),
            envelope,
            BronzeEventFamily::AssetObservation(AssetObservation {
                asset_key: fields.bridge_id.clone(),
                role: Some("switch".to_string()),
                vendor: None,
                model: None,
                firmware: None,
                hostnames: vec![],
                protocols: vec!["mstp".to_string()],
                identifiers: BTreeMap::from([
                    ("mac".to_string(), format_mac(&chunk.context.src_mac)),
                    ("bridge_id".to_string(), fields.bridge_id),
                ]),
            }),
        ));
    }
}

// ── PVST+ decoder ────────────────────────────────────────────────

#[derive(Default)]
struct PvstDecoder {
    dissector: PvstDissector,
}

impl SessionDecoder for PvstDecoder {
    fn name(&self) -> &'static str {
        "pvst"
    }

    fn interest(&self) -> &'static [DecoderInterest] {
        &[DecoderInterest::Snap {
            oui: [0x00, 0x00, 0x0C],
            pid: 0x010B,
        }]
    }

    fn on_datagram(&mut self, chunk: &StreamChunk<'_>, out: &mut Vec<BronzeEvent>) {
        match self.dissector.parse(chunk.payload, &chunk.context) {
            Some(ProtocolData::Pvst(PvstFields {
                protocol_version,
                bpdu_type: _,
                flags: _,
                root_id,
                root_path_cost,
                bridge_id,
                port_id,
                originating_vlan,
            })) => {
                let envelope = build_envelope(
                    &chunk.context,
                    chunk.interface_id,
                    chunk.frame_index,
                    chunk.timestamp,
                    chunk.segment_hash,
                    TransportProtocol::Ethernet,
                    Some("pvst"),
                    chunk.captured_len,
                    chunk.session_key.clone(),
                );

                let mut metadata = BTreeMap::new();
                metadata.insert("protocol_version".to_string(), protocol_version.to_string());
                metadata.insert("root_path_cost".to_string(), root_path_cost.to_string());
                metadata.insert("port_id".to_string(), format!("{port_id:#06x}"));
                if let Some(vlan) = originating_vlan {
                    metadata.insert("originating_vlan".to_string(), vlan.to_string());
                }

                out.push(new_event(
                    chunk.capture_id.to_string(),
                    envelope.clone(),
                    BronzeEventFamily::TopologyObservation(TopologyObservation {
                        observation_type: "pvst_bpdu".to_string(),
                        local_id: bridge_id.clone(),
                        remote_id: Some(root_id),
                        description: originating_vlan.map(|v| format!("VLAN {v}")),
                        capabilities: vec!["pvst".to_string()],
                        metadata,
                    }),
                ));

                let mut identifiers = BTreeMap::from([
                    ("mac".to_string(), format_mac(&chunk.context.src_mac)),
                    ("bridge_id".to_string(), bridge_id.clone()),
                ]);
                if let Some(vlan) = originating_vlan {
                    identifiers.insert("originating_vlan".to_string(), vlan.to_string());
                }

                out.push(new_event(
                    chunk.capture_id.to_string(),
                    envelope,
                    BronzeEventFamily::AssetObservation(AssetObservation {
                        asset_key: bridge_id,
                        role: Some("switch".to_string()),
                        vendor: Some("Cisco".to_string()),
                        model: None,
                        firmware: None,
                        hostnames: vec![],
                        protocols: vec!["pvst".to_string()],
                        identifiers,
                    }),
                ));
            }
            _ => {}
        }
    }
}

// ── PRP decoder ──────────────────────────────────────────────────

#[derive(Default)]
struct PrpDecoder {
    dissector: PrpDissector,
}

impl SessionDecoder for PrpDecoder {
    fn name(&self) -> &'static str {
        "prp"
    }

    fn interest(&self) -> &'static [DecoderInterest] {
        &[DecoderInterest::EtherType(0x88FB)]
    }

    fn on_datagram(&mut self, chunk: &StreamChunk<'_>, out: &mut Vec<BronzeEvent>) {
        match self.dissector.parse(chunk.payload, &chunk.context) {
            Some(ProtocolData::Prp(PrpFields {
                supervision_type_name,
                source_mac,
                red_box_mac,
                sequence_nr,
                ..
            })) => {
                let envelope = build_envelope(
                    &chunk.context,
                    chunk.interface_id,
                    chunk.frame_index,
                    chunk.timestamp,
                    chunk.segment_hash,
                    TransportProtocol::Ethernet,
                    Some("prp"),
                    chunk.captured_len,
                    chunk.session_key.clone(),
                );

                let local_id = source_mac
                    .clone()
                    .unwrap_or_else(|| format_mac(&chunk.context.src_mac));

                let mut metadata = BTreeMap::new();
                if let Some(seq) = sequence_nr {
                    metadata.insert("sequence_nr".to_string(), seq.to_string());
                }
                if let Some(ref rb) = red_box_mac {
                    metadata.insert("red_box_mac".to_string(), rb.clone());
                }

                out.push(new_event(
                    chunk.capture_id.to_string(),
                    envelope.clone(),
                    BronzeEventFamily::TopologyObservation(TopologyObservation {
                        observation_type: format!(
                            "prp_{}",
                            supervision_type_name.to_lowercase()
                        ),
                        local_id: local_id.clone(),
                        remote_id: red_box_mac,
                        description: Some("PRP supervision".to_string()),
                        capabilities: vec!["prp".to_string()],
                        metadata,
                    }),
                ));

                out.push(new_event(
                    chunk.capture_id.to_string(),
                    envelope,
                    BronzeEventFamily::AssetObservation(AssetObservation {
                        asset_key: local_id,
                        role: Some("prp_node".to_string()),
                        vendor: None,
                        model: None,
                        firmware: None,
                        hostnames: vec![],
                        protocols: vec!["prp".to_string()],
                        identifiers: BTreeMap::from([(
                            "mac".to_string(),
                            format_mac(&chunk.context.src_mac),
                        )]),
                    }),
                ));
            }
            _ => {}
        }
    }
}

// ── LACP decoder ─────────────────────────────────────────────────

#[derive(Default)]
struct LacpDecoder {
    dissector: LacpDissector,
}

impl SessionDecoder for LacpDecoder {
    fn name(&self) -> &'static str {
        "lacp"
    }

    fn interest(&self) -> &'static [DecoderInterest] {
        &[DecoderInterest::EtherType(0x8809)]
    }

    fn on_datagram(&mut self, chunk: &StreamChunk<'_>, out: &mut Vec<BronzeEvent>) {
        match self.dissector.parse(chunk.payload, &chunk.context) {
            Some(ProtocolData::Lacp(LacpFields {
                version: _,
                ref actor,
                ref partner,
                max_delay,
            })) => {
                let envelope = build_envelope(
                    &chunk.context,
                    chunk.interface_id,
                    chunk.frame_index,
                    chunk.timestamp,
                    chunk.segment_hash,
                    TransportProtocol::Ethernet,
                    Some("lacp"),
                    chunk.captured_len,
                    chunk.session_key.clone(),
                );

                let mut metadata = BTreeMap::new();
                metadata.insert("actor_system".to_string(), actor.system.clone());
                metadata.insert("actor_key".to_string(), actor.key.to_string());
                metadata.insert("actor_port".to_string(), actor.port.to_string());
                metadata.insert("partner_system".to_string(), partner.system.clone());
                metadata.insert("partner_key".to_string(), partner.key.to_string());
                metadata.insert("partner_port".to_string(), partner.port.to_string());
                if let Some(delay) = max_delay {
                    metadata.insert("max_delay".to_string(), delay.to_string());
                }

                out.push(new_event(
                    chunk.capture_id.to_string(),
                    envelope.clone(),
                    BronzeEventFamily::TopologyObservation(TopologyObservation {
                        observation_type: "lacp_bond".to_string(),
                        local_id: actor.system.clone(),
                        remote_id: Some(partner.system.clone()),
                        description: Some(format!(
                            "key={} port={} <-> key={} port={}",
                            actor.key, actor.port, partner.key, partner.port
                        )),
                        capabilities: actor.state_flags.clone(),
                        metadata,
                    }),
                ));

                // Identify both actor and partner as switches.
                for (sys_mac, role_prefix) in
                    [(&actor.system, "actor"), (&partner.system, "partner")]
                {
                    out.push(new_event(
                        chunk.capture_id.to_string(),
                        envelope.clone(),
                        BronzeEventFamily::AssetObservation(AssetObservation {
                            asset_key: sys_mac.clone(),
                            role: Some("switch".to_string()),
                            vendor: None,
                            model: None,
                            firmware: None,
                            hostnames: vec![],
                            protocols: vec!["lacp".to_string()],
                            identifiers: BTreeMap::from([
                                ("system".to_string(), sys_mac.clone()),
                                ("lacp_role".to_string(), role_prefix.to_string()),
                            ]),
                        }),
                    ));
                }
            }
            _ => {}
        }
    }
}

// ── ICMP Decoder ──────────────────────────────────────────────

#[derive(Default)]
struct IcmpDecoder {
    dissector: IcmpDissector,
}

impl SessionDecoder for IcmpDecoder {
    fn name(&self) -> &'static str {
        "icmp"
    }

    fn interest(&self) -> &'static [DecoderInterest] {
        &[DecoderInterest::IpProto(1)]
    }

    fn on_datagram(&mut self, chunk: &StreamChunk<'_>, out: &mut Vec<BronzeEvent>) {
        let context = &chunk.context;
        if !self.dissector.can_parse(chunk.payload, 0, 0) {
            return;
        }
        let Some(proto_data) = self.dissector.parse(chunk.payload, context) else {
            return;
        };
        let ProtocolData::Icmp(fields) = &proto_data else {
            return;
        };

        let envelope = build_envelope(
            context,
            chunk.interface_id,
            chunk.frame_index,
            chunk.timestamp,
            chunk.segment_hash,
            TransportProtocol::Icmp,
            Some("icmp"),
            chunk.captured_len,
            chunk.session_key.clone(),
        );

        let mut attrs = BTreeMap::new();
        attrs.insert("icmp_type".to_string(), fields.icmp_type.to_string());
        attrs.insert("icmp_code".to_string(), fields.icmp_code.to_string());
        attrs.insert("type_name".to_string(), fields.type_name.clone());
        if !fields.code_name.is_empty() {
            attrs.insert("code_name".to_string(), fields.code_name.clone());
        }
        if let Some(id) = fields.identifier {
            attrs.insert("identifier".to_string(), id.to_string());
        }
        if let Some(seq) = fields.sequence {
            attrs.insert("sequence".to_string(), seq.to_string());
        }
        if let Some(gw) = &fields.gateway_ip {
            attrs.insert("gateway_ip".to_string(), gw.clone());
        }
        attrs.insert("payload_len".to_string(), fields.payload_len.to_string());

        let operation = fields.type_name.clone();
        let status = if fields.icmp_type == 3 {
            fields.code_name.clone()
        } else {
            "ok".to_string()
        };

        out.push(new_event(
            chunk.capture_id.to_string(),
            envelope,
            BronzeEventFamily::ProtocolTransaction(ProtocolTransaction {
                operation,
                status,
                request_summary: Some(format!(
                    "ICMP type {} code {}",
                    fields.icmp_type, fields.icmp_code
                )),
                response_summary: None,
                object_refs: Vec::new(),
                values: Vec::new(),
                attributes: attrs,
                        modbus: None,
}),
        ));
    }
}

// ── Stovetop finding → BronzeEvent helpers ────────────────────

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

// ── SMB / Kerberos / LDAP recognition-only decoders ───────────────────
//
// These produce ProtocolTransaction events for traffic classification only.
// No deep PDU parsing — port + signature byte check.

/// Helper to emit a single ProtocolTransaction recognition event.
fn emit_recognition(
    chunk: &StreamChunk<'_>,
    out: &mut Vec<BronzeEvent>,
    protocol: &'static str,
    operation: &'static str,
    summary: &str,
) {
    let envelope = build_envelope(
        &chunk.context,
        chunk.interface_id,
        chunk.frame_index,
        chunk.timestamp,
        chunk.segment_hash,
        chunk.transport,
        Some(protocol),
        chunk.captured_len,
        chunk.session_key.clone(),
    );
    let mut attributes = BTreeMap::new();
    attributes.insert("protocol".to_string(), protocol.to_string());
    out.push(new_event(
        chunk.capture_id.to_string(),
        envelope,
        BronzeEventFamily::ProtocolTransaction(ProtocolTransaction {
            operation: operation.to_string(),
            status: "ok".to_string(),
            request_summary: Some(summary.to_string()),
            response_summary: None,
            object_refs: Vec::new(),
            values: Vec::new(),
            attributes,
            modbus: None,
        }),
    ));
}

struct SmbRecognizer;

impl SessionDecoder for SmbRecognizer {
    fn name(&self) -> &'static str {
        "smb"
    }

    fn interest(&self) -> &'static [DecoderInterest] {
        &[DecoderInterest::TcpPort(445), DecoderInterest::TcpPort(139)]
    }

    fn on_stream_chunk(&mut self, chunk: &StreamChunk<'_>, out: &mut Vec<BronzeEvent>) {
        let p = chunk.payload;
        // SMB direct (port 445): the SMB header may start at offset 4 if a
        // 4-byte NetBIOS-style length prefix is present (always for 139,
        // sometimes for 445), or at offset 0.
        let candidates: [usize; 2] = [4, 0];
        for &off in &candidates {
            if off + 4 > p.len() {
                continue;
            }
            let sig = &p[off..off + 4];
            if sig == [0xFF, b'S', b'M', b'B'] {
                emit_recognition(chunk, out, "smb", "smb1_message", "SMB1 traffic");
                return;
            }
            if sig == [0xFE, b'S', b'M', b'B'] {
                emit_recognition(chunk, out, "smb", "smb2_message", "SMB2 traffic");
                return;
            }
        }
    }
}

struct KerberosRecognizer;

impl SessionDecoder for KerberosRecognizer {
    fn name(&self) -> &'static str {
        "kerberos"
    }

    fn interest(&self) -> &'static [DecoderInterest] {
        &[
            DecoderInterest::TcpPort(88),
            DecoderInterest::UdpPort(88),
            DecoderInterest::TcpPort(464),
            DecoderInterest::UdpPort(464),
        ]
    }

    fn on_stream_chunk(&mut self, chunk: &StreamChunk<'_>, out: &mut Vec<BronzeEvent>) {
        if looks_like_kerberos(chunk.payload) {
            emit_recognition(chunk, out, "kerberos", "kerberos_message", "Kerberos traffic");
        }
    }

    fn on_datagram(&mut self, chunk: &StreamChunk<'_>, out: &mut Vec<BronzeEvent>) {
        if looks_like_kerberos(chunk.payload) {
            emit_recognition(chunk, out, "kerberos", "kerberos_message", "Kerberos traffic");
        }
    }
}

/// Light Kerberos signature: ASN.1 BER application-tagged messages. KRB
/// messages start with application-tag bytes 0x6A (AS-REQ), 0x6B (AS-REP),
/// 0x6C (TGS-REQ), 0x6D (TGS-REP), 0x6E (AP-REQ), 0x6F (AP-REP), 0x7E
/// (KRB-ERROR). For TCP, a 4-byte length precedes the ASN.1.
fn looks_like_kerberos(p: &[u8]) -> bool {
    if p.is_empty() {
        return false;
    }
    let candidates = [0usize, 4];
    for &off in &candidates {
        if let Some(b) = p.get(off) {
            if matches!(*b, 0x6A..=0x6F | 0x7E) {
                return true;
            }
        }
    }
    false
}

struct LdapRecognizer;

impl SessionDecoder for LdapRecognizer {
    fn name(&self) -> &'static str {
        "ldap"
    }

    fn interest(&self) -> &'static [DecoderInterest] {
        &[DecoderInterest::TcpPort(389), DecoderInterest::TcpPort(636)]
    }

    fn on_stream_chunk(&mut self, chunk: &StreamChunk<'_>, out: &mut Vec<BronzeEvent>) {
        if chunk.context.dst_port == 636 || chunk.context.src_port == 636 {
            // LDAPS is TLS-encrypted; recognition only by port.
            emit_recognition(chunk, out, "ldap", "ldaps_traffic", "LDAPS traffic");
            return;
        }
        if looks_like_ldap(chunk.payload) {
            emit_recognition(chunk, out, "ldap", "ldap_message", "LDAP traffic");
        }
    }
}

/// LDAP messages are ASN.1 BER SEQUENCEs starting with 0x30, followed by
/// a length encoding. Reject obviously-too-short payloads.
fn looks_like_ldap(p: &[u8]) -> bool {
    if p.len() < 2 {
        return false;
    }
    if p[0] != 0x30 {
        return false;
    }
    // Reasonable length byte: short form (< 128) or long-form prefix (0x81..0x84).
    matches!(p[1], 0x00..=0x7F | 0x81..=0x84)
}

// CC-Link IE Field — UDP 61450, often multicast (239.192.0.0/16).
struct CcLinkRecognizer;

impl SessionDecoder for CcLinkRecognizer {
    fn name(&self) -> &'static str {
        "cclink"
    }

    fn interest(&self) -> &'static [DecoderInterest] {
        &[DecoderInterest::UdpPort(61450)]
    }

    fn on_datagram(&mut self, chunk: &StreamChunk<'_>, out: &mut Vec<BronzeEvent>) {
        emit_recognition(chunk, out, "cclink", "cclink_ie_traffic", "CC-Link IE Field traffic");
    }
}

// CODESYS — TCP 1217 (V3 Gateway), 1740 (V2), 2455 (V3 alt), 11740 (V3 Runtime).
struct CodesysRecognizer;

impl SessionDecoder for CodesysRecognizer {
    fn name(&self) -> &'static str {
        "codesys"
    }

    fn interest(&self) -> &'static [DecoderInterest] {
        &[
            DecoderInterest::TcpPort(1217),
            DecoderInterest::TcpPort(1740),
            DecoderInterest::TcpPort(2455),
            DecoderInterest::TcpPort(11740),
        ]
    }

    fn on_stream_chunk(&mut self, chunk: &StreamChunk<'_>, out: &mut Vec<BronzeEvent>) {
        let summary = match chunk.context.dst_port.max(chunk.context.src_port) {
            1217 => "CODESYS V3 Gateway traffic",
            1740 => "CODESYS V2 traffic",
            2455 => "CODESYS V3 (alternate) traffic",
            11740 => "CODESYS V3 Runtime traffic",
            _ => "CODESYS traffic",
        };
        emit_recognition(chunk, out, "codesys", "codesys_traffic", summary);
    }
}

// IO-Link Wireless — UDP 59152.
struct IoLinkRecognizer;

impl SessionDecoder for IoLinkRecognizer {
    fn name(&self) -> &'static str {
        "iolink"
    }

    fn interest(&self) -> &'static [DecoderInterest] {
        &[DecoderInterest::UdpPort(59152)]
    }

    fn on_datagram(&mut self, chunk: &StreamChunk<'_>, out: &mut Vec<BronzeEvent>) {
        emit_recognition(chunk, out, "iolink", "iolink_traffic", "IO-Link Wireless traffic");
    }
}

// IGMP — IP protocol 2. Light parse to extract type byte for Membership Query
// vs Report distinction; full v3 group records left for future work.
struct IgmpRecognizer;

impl SessionDecoder for IgmpRecognizer {
    fn name(&self) -> &'static str {
        "igmp"
    }

    fn interest(&self) -> &'static [DecoderInterest] {
        &[DecoderInterest::IpProto(2)]
    }

    fn on_datagram(&mut self, chunk: &StreamChunk<'_>, out: &mut Vec<BronzeEvent>) {
        if chunk.payload.is_empty() {
            return;
        }
        let igmp_type = chunk.payload[0];
        let (operation, summary) = match igmp_type {
            0x11 => ("igmp_membership_query", "IGMP Membership Query"),
            0x12 => ("igmp_v1_membership_report", "IGMPv1 Membership Report"),
            0x16 => ("igmp_v2_membership_report", "IGMPv2 Membership Report"),
            0x17 => ("igmp_leave_group", "IGMPv2 Leave Group"),
            0x22 => ("igmp_v3_membership_report", "IGMPv3 Membership Report"),
            _ => ("igmp_message", "IGMP traffic"),
        };
        emit_recognition(chunk, out, "igmp", operation, summary);
    }
}

// ── Synchrophasor (IEEE C37.118) decoder ──────────────────────────────

#[derive(Default)]
struct SynchrophasorDecoderWrapper {
    decoder: crate::synchrophasor::SynchrophasorDecoder,
}

impl SessionDecoder for SynchrophasorDecoderWrapper {
    fn name(&self) -> &'static str {
        "synchrophasor"
    }

    fn interest(&self) -> &'static [DecoderInterest] {
        &[
            DecoderInterest::TcpPort(4712),
            DecoderInterest::TcpPort(4713),
            DecoderInterest::UdpPort(4712),
            DecoderInterest::UdpPort(4713),
        ]
    }

    fn on_stream_chunk(&mut self, chunk: &StreamChunk<'_>, out: &mut Vec<BronzeEvent>) {
        self.handle(chunk, out);
    }

    fn on_datagram(&mut self, chunk: &StreamChunk<'_>, out: &mut Vec<BronzeEvent>) {
        self.handle(chunk, out);
    }
}

impl SynchrophasorDecoderWrapper {
    fn handle(&mut self, chunk: &StreamChunk<'_>, out: &mut Vec<BronzeEvent>) {
        if !crate::synchrophasor::looks_like_synchrophasor(chunk.payload) {
            return;
        }
        let envelope = build_envelope(
            &chunk.context,
            chunk.interface_id,
            chunk.frame_index,
            chunk.timestamp,
            chunk.segment_hash,
            chunk.transport,
            Some("synchrophasor"),
            chunk.captured_len,
            chunk.session_key.clone(),
        );
        let mut events =
            self.decoder
                .handle_frame(chunk.payload, chunk.context.src_ip, &envelope, chunk.capture_id);
        out.append(&mut events);
    }
}

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

        let mut decoder = MqttDecoder::default();
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
    fn kerberos_recognizer_detects_as_req() {
        // ASN.1 application-tag 0x6A (KRB-AS-REQ).
        let payload: Vec<u8> = std::iter::once(0u8)
            .chain(std::iter::once(0))
            .chain(std::iter::once(0))
            .chain(std::iter::once(0x40))
            .chain([0x6A])
            .chain(std::iter::repeat(0).take(60))
            .collect();
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
        assert!(output.events.iter().any(|ev| matches!(
            &ev.family,
            BronzeEventFamily::ProtocolTransaction(tx) if tx.operation == "kerberos_message"
        )));
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
