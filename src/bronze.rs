//! Native Bronze v2 event model.
//!
//! Bronze is the semantic event layer derived from Iron. The hot path uses
//! these native Rust types; protobuf is only used at the Historian boundary.

use std::collections::BTreeMap;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

pub const BRONZE_SCHEMA_VERSION: &str = "v2";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TransportProtocol {
    Ethernet,
    Arp,
    Ipv4,
    Tcp,
    Udp,
    Icmp,
    Unknown,
}

impl TransportProtocol {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Ethernet => "ethernet",
            Self::Arp => "arp",
            Self::Ipv4 => "ipv4",
            Self::Tcp => "tcp",
            Self::Udp => "udp",
            Self::Icmp => "icmp",
            Self::Unknown => "unknown",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EventEnvelope {
    pub timestamp: DateTime<Utc>,
    pub interface_id: u32,
    pub segment_hash: String,
    pub frame_index: u64,
    pub session_key: String,
    pub src_mac: Option<String>,
    pub dst_mac: Option<String>,
    pub src_ip: Option<String>,
    pub dst_ip: Option<String>,
    pub src_port: Option<u16>,
    pub dst_port: Option<u16>,
    pub vlan_id: Option<u16>,
    pub transport: TransportProtocol,
    pub protocol: Option<String>,
    pub bytes_count: u64,
    pub packet_count: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ObjectValue {
    pub object_ref: String,
    pub value: Option<String>,
}

/// Modbus-specific fields carried on a paired request/response
/// []. Present only when .
///
/// All fields use primitive types so they serialise cleanly to JSON for the
/// Silver register profile and the forensic workbench API.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ModbusBronzeFields {
    /// Base function code (0x80 bit stripped).
    pub fc: u8,
    /// Starting register or coil address from the request PDU.  when
    /// the request was not paired (response without request).
    pub start_addr: Option<u16>,
    /// Quantity of registers / coils from the request.  for single-item
    /// writes (FC 05, 06) and unpaired responses.
    pub qty: Option<u16>,
    /// Register or coil values. For read FCs these come from the response; for
    /// write FCs from the request.
    pub values: Vec<u16>,
    /// Exception code when the server returned an exception response.
    pub exception_code: Option<u8>,
    ///  or  (for unpaired half-transactions).
    pub direction: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProtocolTransaction {
    pub operation: String,
    pub status: String,
    pub request_summary: Option<String>,
    pub response_summary: Option<String>,
    pub object_refs: Vec<String>,
    pub values: Vec<ObjectValue>,
    pub attributes: BTreeMap<String, String>,
    /// Modbus-specific fields;  only when .
    #[serde(skip_serializing_if = "Option::is_none")]
    pub modbus: Option<ModbusBronzeFields>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AssetObservation {
    pub asset_key: String,
    pub role: Option<String>,
    pub vendor: Option<String>,
    pub model: Option<String>,
    pub firmware: Option<String>,
    pub hostnames: Vec<String>,
    pub protocols: Vec<String>,
    pub identifiers: BTreeMap<String, String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TopologyObservation {
    pub observation_type: String,
    pub local_id: String,
    pub remote_id: Option<String>,
    pub description: Option<String>,
    pub capabilities: Vec<String>,
    pub metadata: BTreeMap<String, String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ParseAnomaly {
    pub decoder: String,
    pub severity: String,
    pub reason: String,
    pub raw_excerpt_hex: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExtractedArtifact {
    pub artifact_type: String,
    pub artifact_key: String,
    pub sha256: String,
    pub mime_type: Option<String>,
    pub content_hex: String,
    pub description: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BronzeEventFamily {
    ProtocolTransaction(ProtocolTransaction),
    AssetObservation(AssetObservation),
    TopologyObservation(TopologyObservation),
    ParseAnomaly(ParseAnomaly),
    ExtractedArtifact(ExtractedArtifact),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BronzeEvent {
    pub event_id: String,
    pub capture_id: String,
    pub schema_version: String,
    pub envelope: EventEnvelope,
    pub family: BronzeEventFamily,
}

impl BronzeEvent {
    pub fn family_name(&self) -> &'static str {
        match &self.family {
            BronzeEventFamily::ProtocolTransaction(_) => "protocol_transaction",
            BronzeEventFamily::AssetObservation(_) => "asset_observation",
            BronzeEventFamily::TopologyObservation(_) => "topology_observation",
            BronzeEventFamily::ParseAnomaly(_) => "parse_anomaly",
            BronzeEventFamily::ExtractedArtifact(_) => "extracted_artifact",
        }
    }

    pub fn protocol(&self) -> Option<&str> {
        self.envelope.protocol.as_deref()
    }

    pub fn operation(&self) -> Option<&str> {
        match &self.family {
            BronzeEventFamily::ProtocolTransaction(tx) => Some(tx.operation.as_str()),
            _ => None,
        }
    }

    pub fn status(&self) -> Option<&str> {
        match &self.family {
            BronzeEventFamily::ProtocolTransaction(tx) => Some(tx.status.as_str()),
            _ => None,
        }
    }

    pub fn src_mac(&self) -> Option<&str> {
        self.envelope.src_mac.as_deref()
    }

    pub fn dst_mac(&self) -> Option<&str> {
        self.envelope.dst_mac.as_deref()
    }

    pub fn src_ip(&self) -> Option<&str> {
        self.envelope.src_ip.as_deref()
    }

    pub fn dst_ip(&self) -> Option<&str> {
        self.envelope.dst_ip.as_deref()
    }

    pub fn to_payload_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string(&self.family)
    }

    pub fn from_payload_json(
        event_id: String,
        capture_id: String,
        schema_version: String,
        envelope: EventEnvelope,
        payload_json: &str,
    ) -> Result<Self, serde_json::Error> {
        let family = serde_json::from_str(payload_json)?;
        Ok(Self {
            event_id,
            capture_id,
            schema_version,
            envelope,
            family,
        })
    }

    pub fn activity_record(&self) -> Option<ActivityRecord> {
        let protocol = self.protocol()?.to_string();
        let src_ip = self.src_ip()?.to_string();
        let dst_ip = self.dst_ip()?.to_string();

        match &self.family {
            BronzeEventFamily::ProtocolTransaction(tx) => Some(ActivityRecord {
                timestamp: self.envelope.timestamp,
                src_mac: self.envelope.src_mac.clone().unwrap_or_default(),
                dst_mac: self.envelope.dst_mac.clone().unwrap_or_default(),
                src_ip,
                dst_ip,
                src_port: self.envelope.src_port,
                dst_port: self.envelope.dst_port,
                protocol,
                operation: Some(tx.operation.clone()),
                object_refs: tx.object_refs.clone(),
                status: Some(tx.status.clone()),
                bytes_count: self.envelope.bytes_count,
                packet_count: self.envelope.packet_count,
                zone_id: None,
            }),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ActivityRecord {
    pub timestamp: DateTime<Utc>,
    pub src_mac: String,
    pub dst_mac: String,
    pub src_ip: String,
    pub dst_ip: String,
    pub src_port: Option<u16>,
    pub dst_port: Option<u16>,
    pub protocol: String,
    pub operation: Option<String>,
    pub object_refs: Vec<String>,
    pub status: Option<String>,
    pub bytes_count: u64,
    pub packet_count: u64,
    pub zone_id: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SegmentCheckpoint {
    pub capture_id: String,
    pub schema_version: String,
    pub segment_hash: String,
    pub frames_processed: u64,
    pub events_emitted: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BronzeBatch {
    pub capture_id: String,
    pub schema_version: String,
    pub segment_hash: String,
    pub events: Vec<BronzeEvent>,
    pub checkpoint: SegmentCheckpoint,
}

pub fn activity_records(events: &[BronzeEvent]) -> Vec<ActivityRecord> {
    events
        .iter()
        .filter_map(BronzeEvent::activity_record)
        .collect()
}
