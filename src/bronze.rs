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

<<<<<<< HEAD
/// DNP3-specific fields carried on a `ProtocolTransaction`. Present when the
/// DNP3 decoder successfully parses a frame.
///
/// Fields cover the data link layer addressing, transport-layer framing bits,
/// application-layer function code, IIN flags (response only), and a summary
/// of object groups referenced in the application payload. Rare edge-case
/// attributes (e.g. data-link reset acknowledgements) remain in `attributes`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Dnp3BronzeFields {
    /// DNP3 data link layer source address.
    pub source_addr: u16,
    /// DNP3 data link layer destination address.
    pub destination_addr: u16,
    /// Raw DLL control byte (DIR/PRM/FCB/FCV/FC nibble).
    pub dll_control: u8,
    /// Transport-layer sequence number (0–63).
    pub transport_seq: u8,
    /// Transport FIR bit — this fragment is the first of a multi-block message.
    pub transport_fir: bool,
    /// Transport FIN bit — this fragment is the last of a multi-block message.
    pub transport_fin: bool,
    /// Application-layer function code.
    pub application_function_code: u8,
    /// Human-readable name for `application_function_code`, e.g. `"Read"`,
    /// `"Response"`, `"UnsolicitedResponse"`.
    pub application_function_name: String,
    /// Application-layer sequence number extracted from the control byte (bits 0–3).
    pub application_seq: u8,
    /// Internal Indication flags word (IIN1 | IIN2 << 8). Present on `Response`
    /// (0x81) and `UnsolicitedResponse` (0x82) only.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub iin_flags: Option<u16>,
    /// Transaction direction: `"request"`, `"response"`, or `"unsolicited"`.
    pub direction: String,
    /// Object group numbers referenced in the application data payload.
    /// Empty for messages with no object headers (Confirm, restart commands, etc.).
    pub object_groups: Vec<u8>,
}

/// IEC 60870-5-104 typed fields carried on a [`ProtocolTransaction`].
///
/// Covers APCI frame classification (I/S/U), sequence numbers, U-function
/// names, ASDU type, cause-of-transmission, and addressing. All fields use
/// primitive types so they serialise cleanly to JSON.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Iec104BronzeFields {
    /// APCI frame type: "i_frame", "s_frame", or "u_frame".
    pub apci_type: String,
    /// N(S) send sequence number — present for I-frames only.
    pub send_sequence: Option<u16>,
    /// N(R) receive sequence number — present for I-frames and S-frames.
    pub receive_sequence: Option<u16>,
    /// U-frame function name (e.g. "startdt_act", "testfr_con") — present for
    /// U-frames only.
    pub u_function: Option<String>,
    /// ASDU type identifier (e.g. 1 = M_SP_NA_1, 45 = C_SC_NA_1).
    pub asdu_type_id: Option<u8>,
    /// Human-readable ASDU type name where known.
    pub asdu_type_name: Option<String>,
    /// Cause of transmission (6-bit field, 0–63).
    pub cause_of_transmission: Option<u8>,
    /// Human-readable cause name where known.
    pub cause_of_transmission_name: Option<String>,
    /// Negative-confirm bit from COT byte 1.
    pub is_negative_confirm: bool,
    /// Test bit from COT byte 1.
    pub is_test: bool,
    /// Originator address from COT byte 2 (0 = absent).
    pub originator_address: Option<u8>,
    /// ASDU common address (station address).
    pub common_address: Option<u16>,
    /// Number of information objects (variable-structure qualifier count).
    pub num_objects: Option<u8>,
    /// SQ bit — true when objects are addressed as a contiguous sequence.
    pub is_sequence: bool,
    /// Transaction direction derived from port and COT: "request", "response",
    /// "spontaneous", or "observed".
    pub direction: String,
}

/// S7comm-specific fields carried on a parsed S7 PDU transaction.
///
/// Populated for all S7comm messages regardless of ROSCTR type. Optional fields
/// are `None` when not applicable to the specific PDU type (e.g., `error_class`
/// only appears on Ack-Data responses; `userdata_function_group` only on
/// Userdata messages).
///
/// Memory-area fields (`area`) are `None` for PDU types that carry no item list
/// (Setup Communication, Stop PLC, etc.) and are derived from the first item in
/// the parameter block for Read/Write Var requests.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct S7commBronzeFields {
    /// Raw ROSCTR byte: Job=0x01, Ack=0x02, Ack_Data=0x03, Userdata=0x07.
    pub rosctr: u8,
    /// Human-readable ROSCTR label: "job", "ack", "ack_data", "userdata", "unknown".
    pub rosctr_name: String,
    /// PDU reference number used to pair requests and responses.
    pub protocol_data_unit_ref: u16,
    /// Function code from the parameter block's first byte. `None` when the
    /// parameter block is empty (bare Ack frames).
    pub function_code: Option<u8>,
    /// Human-readable function name derived from the function code.
    pub function_name: Option<String>,
    /// Error class byte from the Ack-Data extended header. `None` for non-Ack-Data PDUs.
    pub error_class: Option<u8>,
    /// Error code byte from the Ack-Data extended header. `None` for non-Ack-Data PDUs.
    pub error_code: Option<u8>,
    /// Userdata function group (high nibble of parameter byte 7). Populated only
    /// when rosctr == 0x07.
    pub userdata_function_group: Option<u8>,
    /// Userdata function subcode (low nibble of parameter byte 7). Populated only
    /// when rosctr == 0x07.
    pub userdata_function_subcode: Option<u8>,
    /// Number of items in the Read/Write Var parameter list. `None` for other
    /// function codes or when the parameter block is too short.
    pub item_count: Option<u8>,
    /// Memory area code from the first S7 Any-Pointer item (Read/Write Var).
    /// Common values: 0x81=I (inputs), 0x82=Q (outputs), 0x83=M (bit memory),
    /// 0x84=DB (data block), 0x1C=C (counters), 0x1D=T (timers).
    /// `None` when no item is present or for other function codes.
    pub area: Option<u8>,
    /// Transaction direction relative to the observed flow:
    /// "request", "response", or "observed".
    pub direction: String,
}

/// Typed protocol-specific fields on a [`ProtocolTransaction`]. Replaces the
/// ad-hoc `attributes: BTreeMap<String, String>` escape hatch with a tagged
/// enum that downstream consumers can pattern-match without string lookups.
///
/// Variants are added per protocol as decoders migrate from `attributes` to
/// typed emission. Protocols with no variant yet keep populating `attributes`;
/// migrating them is a follow-up. The `attributes` field is retained for
/// backward compatibility through this transition.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "protocol", content = "fields", rename_all = "snake_case")]
pub enum ProtocolFields {
    Modbus(ModbusBronzeFields),
    Dnp3(Dnp3BronzeFields),
    Iec104(Iec104BronzeFields),
    S7comm(S7commBronzeFields),
    // Future variants land here as decoders migrate. Expected next:
    //   OpcUa(OpcUaBronzeFields), EthernetIp(EthernetIpBronzeFields),
    //   Iec61850(Iec61850BronzeFields), HartIp(HartIpBronzeFields),
    //   Sparkplug(SparkplugBronzeFields).
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
    /// Modbus-specific fields. Deprecated — populate `protocol_fields` with
    /// `ProtocolFields::Modbus(...)` instead. Retained for backward compat
    /// through the v1.x line; will be removed in v2.0.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub modbus: Option<ModbusBronzeFields>,
    /// Typed protocol-specific payload. Populated by decoders migrated to
    /// the typed surface; `None` for protocols still using `attributes`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub protocol_fields: Option<ProtocolFields>,
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

/// Modbus register kind — coil/discrete-input/holding/input.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ModbusRegKind {
    Coil,
    DiscreteInput,
    HoldingRegister,
    InputRegister,
}

/// OPC UA NodeId identifier portion. `StringRaw` and `Opaque` carry raw bytes for
/// non-UTF-8 round-trips (the OPC UA spec allows null bytes mid-string).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", content = "value", rename_all = "snake_case")]
pub enum OpcUaNodeId {
    Numeric(u32),
    String(String),
    StringRaw(Vec<u8>),
    Guid([u8; 16]),
    Opaque(Vec<u8>),
}

/// Typed point identifier preserving each protocol's native addressing.
///
/// Variants that carry strings (`CipSymbol`, `Iec61850Reference`, `SparkplugMetric`)
/// also carry a `*_raw: Option<Vec<u8>>` companion populated only when the wire
/// bytes were not valid UTF-8, so the embedder gets lossless round-trip.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum PointIdentifier {
    ModbusRegister {
        unit_id: u8,
        addr: u16,
        register_type: ModbusRegKind,
    },
    OpcUaNode {
        namespace_index: u16,
        identifier: OpcUaNodeId,
    },
    CipSymbol {
        symbol: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        symbol_raw: Option<Vec<u8>>,
    },
    CipPath {
        class: u16,
        instance: u32,
        #[serde(skip_serializing_if = "Option::is_none")]
        attribute: Option<u16>,
    },
    DnpPoint {
        group: u8,
        variation: u8,
        index: u32,
    },
    Iec104Ioa {
        common_addr: u16,
        ioa: u32,
        type_id: u8,
    },
    Iec61850Reference {
        reference: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        reference_raw: Option<Vec<u8>>,
    },
    SparkplugMetric {
        group_id: String,
        edge_node_id: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        device_id: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        metric_name: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        metric_name_raw: Option<Vec<u8>>,
        #[serde(skip_serializing_if = "Option::is_none")]
        alias: Option<u64>,
    },
    HartCommand {
        command: u8,
        #[serde(skip_serializing_if = "Option::is_none")]
        slot: Option<u8>,
    },
    /// Allen-Bradley PCCC data-table address (legacy SLC-500, PLC-5,
    /// MicroLogix). Encoded over CIP service 0x4B (Execute PCCC) inside
    /// EtherNet/IP. `file_type` is the PCCC type code (0x82=B, 0x84=N,
    /// 0x85=F, 0x86=ST, etc.); `file_number` selects the file; `element`
    /// is the element index within that file.
    PcccAddress {
        file_type: u8,
        file_number: u8,
        element: u16,
        #[serde(skip_serializing_if = "Option::is_none")]
        sub_element: Option<u8>,
    },
    /// IEEE C37.118 (synchrophasor) per-channel reading. One per phasor
    /// magnitude, phasor angle, frequency, analog, or digital sample on a
    /// given PMU.
    SynchrophasorChannel {
        idcode: u16,
        #[serde(skip_serializing_if = "Option::is_none")]
        station_name: Option<String>,
        channel_index: u16,
        #[serde(skip_serializing_if = "Option::is_none")]
        channel_name: Option<String>,
        channel_type: SynchrophasorChannelType,
    },
}

/// Kind of synchrophasor channel a `ProcessReading` corresponds to. Phasors
/// produce two readings per phasor (magnitude + angle).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SynchrophasorChannelType {
    PhasorMagnitude,
    PhasorAngle,
    Frequency,
    FrequencyDerivative,
    Analog,
    Digital,
}

/// Typed value union for a process reading. Primitives only; aggregate types
/// (DataSet, Template, arrays) are deferred until a protocol needs them.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", content = "value", rename_all = "snake_case")]
pub enum PointValue {
    Null,
    Bool(bool),
    Int8(i8),
    Int16(i16),
    Int32(i32),
    Int64(i64),
    UInt8(u8),
    UInt16(u16),
    UInt32(u32),
    UInt64(u64),
    Float(f32),
    Double(f64),
    Text(String),
    Bytes(Vec<u8>),
    /// Microseconds since Unix epoch.
    DateTime(u64),
}

/// Protocol-native quality bits, preserved verbatim from the wire.
///
/// Intentionally minimal API: this enum exposes raw bits and nothing else. No
/// `is_good()`, no `severity()`, no `to_normalized()` — quality interpretation
/// is operator policy and lives in the embedder, not in the DPI engine.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", content = "data", rename_all = "snake_case")]
pub enum RawQuality {
    /// Protocol carries no native quality on the wire (Modbus, classic S7).
    None,
    DnpFlags(u8),
    Iec104Qds(u8),
    OpcUaStatusCode(u32),
    Iec61850Quality(u16),
    SparkplugQuality {
        #[serde(skip_serializing_if = "Option::is_none")]
        value: Option<u32>,
        is_historical: bool,
        is_transient: bool,
        is_null: bool,
    },
    CipGeneralStatus(u8),
    HartFieldDeviceStatus(u8),
}

/// Process variable Value/Quality/Timestamp reading extracted from the wire.
///
/// Emitted by VQT-bearing dissectors (Sparkplug B, OPC UA ReadResponse, CIP
/// Read Tag, Modbus, DNP3, IEC 104, IEC 61850 MMS, HART-IP). The point identifier,
/// value type, and quality are preserved as protocol-native; downstream embedders
/// own naming and quality normalization.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ProcessReading {
    /// Source protocol slug, e.g. "sparkplug_b", "modbus", "opc_ua".
    pub source_protocol: String,
    pub point_id: PointIdentifier,
    pub value: PointValue,
    pub quality: RawQuality,
    /// Microseconds since Unix epoch when the device sampled the value, when the
    /// protocol carries a source timestamp. None for protocols that don't.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_ts: Option<u64>,
    /// Microseconds since Unix epoch when the capture observed the frame.
    pub observed_ts: u64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BronzeEventFamily {
    ProtocolTransaction(ProtocolTransaction),
    AssetObservation(AssetObservation),
    TopologyObservation(TopologyObservation),
    ParseAnomaly(ParseAnomaly),
    ExtractedArtifact(ExtractedArtifact),
    ProcessReading(ProcessReading),
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
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
            BronzeEventFamily::ProcessReading(_) => "process_reading",
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

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
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

#[cfg(test)]
mod tests {
    use super::*;

    fn envelope() -> EventEnvelope {
        EventEnvelope {
            timestamp: DateTime::<Utc>::from_timestamp(1_700_000_000, 0).unwrap(),
            interface_id: 0,
            segment_hash: "seg".into(),
            frame_index: 0,
            session_key: "k".into(),
            src_mac: None,
            dst_mac: None,
            src_ip: None,
            dst_ip: None,
            src_port: None,
            dst_port: None,
            vlan_id: None,
            transport: TransportProtocol::Tcp,
            protocol: Some("sparkplug_b".into()),
            bytes_count: 0,
            packet_count: 1,
        }
    }

    fn reading(point_id: PointIdentifier, value: PointValue, quality: RawQuality) -> BronzeEvent {
        BronzeEvent {
            event_id: "e".into(),
            capture_id: "c".into(),
            schema_version: BRONZE_SCHEMA_VERSION.into(),
            envelope: envelope(),
            family: BronzeEventFamily::ProcessReading(ProcessReading {
                source_protocol: "sparkplug_b".into(),
                point_id,
                value,
                quality,
                source_ts: Some(1_700_000_000_000_000),
                observed_ts: 1_700_000_000_000_001,
            }),
        }
    }

    fn assert_roundtrip(ev: &BronzeEvent) {
        let json = serde_json::to_string(ev).expect("serialize");
        let back: BronzeEvent = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(ev, &back);
    }

    #[test]
    fn family_name_for_process_reading() {
        let ev = reading(
            PointIdentifier::ModbusRegister {
                unit_id: 1,
                addr: 100,
                register_type: ModbusRegKind::HoldingRegister,
            },
            PointValue::UInt16(42),
            RawQuality::None,
        );
        assert_eq!(ev.family_name(), "process_reading");
        assert_eq!(ev.operation(), None);
        assert_eq!(ev.status(), None);
        assert_eq!(ev.activity_record(), None);
    }

    #[test]
    fn modbus_register_roundtrip() {
        assert_roundtrip(&reading(
            PointIdentifier::ModbusRegister {
                unit_id: 7,
                addr: 40001,
                register_type: ModbusRegKind::HoldingRegister,
            },
            PointValue::UInt16(2350),
            RawQuality::None,
        ));
    }

    #[test]
    fn opc_ua_node_roundtrip_all_id_kinds() {
        for id in [
            OpcUaNodeId::Numeric(1234),
            OpcUaNodeId::String("ns=2;s=Boiler/Temp".into()),
            OpcUaNodeId::StringRaw(vec![0xff, 0x00, 0x80]),
            OpcUaNodeId::Guid([0u8; 16]),
            OpcUaNodeId::Opaque(vec![0xde, 0xad, 0xbe, 0xef]),
        ] {
            assert_roundtrip(&reading(
                PointIdentifier::OpcUaNode {
                    namespace_index: 2,
                    identifier: id,
                },
                PointValue::Double(72.5),
                RawQuality::OpcUaStatusCode(0),
            ));
        }
    }

    #[test]
    fn cip_symbol_with_and_without_raw() {
        assert_roundtrip(&reading(
            PointIdentifier::CipSymbol {
                symbol: "Tank1.Level".into(),
                symbol_raw: None,
            },
            PointValue::Float(3.14),
            RawQuality::CipGeneralStatus(0),
        ));
        assert_roundtrip(&reading(
            PointIdentifier::CipSymbol {
                symbol: String::from_utf8_lossy(&[0xff, b'X']).into_owned(),
                symbol_raw: Some(vec![0xff, b'X']),
            },
            PointValue::Float(3.14),
            RawQuality::CipGeneralStatus(0),
        ));
    }

    #[test]
    fn cip_path_roundtrip() {
        assert_roundtrip(&reading(
            PointIdentifier::CipPath {
                class: 0x6B,
                instance: 1,
                attribute: Some(2),
            },
            PointValue::Int32(-1),
            RawQuality::CipGeneralStatus(0x04),
        ));
    }

    #[test]
    fn dnp_iec104_iec61850_roundtrip() {
        assert_roundtrip(&reading(
            PointIdentifier::DnpPoint {
                group: 30,
                variation: 1,
                index: 5,
            },
            PointValue::Int32(123),
            RawQuality::DnpFlags(0x01),
        ));
        assert_roundtrip(&reading(
            PointIdentifier::Iec104Ioa {
                common_addr: 1,
                ioa: 4001,
                type_id: 36,
            },
            PointValue::Float(50.123),
            RawQuality::Iec104Qds(0x00),
        ));
        assert_roundtrip(&reading(
            PointIdentifier::Iec61850Reference {
                reference: "IED1LD0/MMXU1.A.phsA.cVal.mag.f".into(),
                reference_raw: None,
            },
            PointValue::Float(12.7),
            RawQuality::Iec61850Quality(0x0000),
        ));
    }

    #[test]
    fn sparkplug_metric_resolved_and_aliased() {
        // Resolved (BIRTH-derived): metric_name present, alias may or may not be.
        assert_roundtrip(&reading(
            PointIdentifier::SparkplugMetric {
                group_id: "Plant1".into(),
                edge_node_id: "PLC-A".into(),
                device_id: Some("Drive-17".into()),
                metric_name: Some("BearingTemp".into()),
                metric_name_raw: None,
                alias: Some(42),
            },
            PointValue::Double(74.2),
            RawQuality::SparkplugQuality {
                value: Some(192),
                is_historical: false,
                is_transient: false,
                is_null: false,
            },
        ));
        // Unresolved alias (no BIRTH seen): metric_name None, alias Some.
        assert_roundtrip(&reading(
            PointIdentifier::SparkplugMetric {
                group_id: "Plant1".into(),
                edge_node_id: "PLC-A".into(),
                device_id: None,
                metric_name: None,
                metric_name_raw: None,
                alias: Some(42),
            },
            PointValue::Null,
            RawQuality::SparkplugQuality {
                value: None,
                is_historical: true,
                is_transient: false,
                is_null: true,
            },
        ));
    }

    #[test]
    fn hart_command_roundtrip() {
        assert_roundtrip(&reading(
            PointIdentifier::HartCommand {
                command: 3,
                slot: Some(0),
            },
            PointValue::Float(20.0),
            RawQuality::HartFieldDeviceStatus(0x00),
        ));
    }

    #[test]
    fn point_value_all_primitive_variants_roundtrip() {
        for v in [
            PointValue::Null,
            PointValue::Bool(true),
            PointValue::Int8(-1),
            PointValue::Int16(-2),
            PointValue::Int32(-3),
            PointValue::Int64(-4),
            PointValue::UInt8(1),
            PointValue::UInt16(2),
            PointValue::UInt32(3),
            PointValue::UInt64(4),
            PointValue::Float(1.5),
            PointValue::Double(2.5),
            PointValue::Text("ok".into()),
            PointValue::Bytes(vec![0x01, 0x02, 0x03]),
            PointValue::DateTime(1_700_000_000_000_000),
        ] {
            assert_roundtrip(&reading(
                PointIdentifier::ModbusRegister {
                    unit_id: 1,
                    addr: 0,
                    register_type: ModbusRegKind::HoldingRegister,
                },
                v,
                RawQuality::None,
            ));
        }
    }

    #[test]
    fn raw_quality_skip_serializing_value_none() {
        // SparkplugQuality { value: None, .. } should omit the "value" key.
        let q = RawQuality::SparkplugQuality {
            value: None,
            is_historical: false,
            is_transient: false,
            is_null: false,
        };
        let json = serde_json::to_string(&q).expect("serialize");
        assert!(!json.contains("\"value\""), "value: None should be skipped, got: {json}");
        // Roundtrip still works:
        let back: RawQuality = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(q, back);
    }

    #[test]
    fn point_identifier_skip_serializing_optional_raw_fields() {
        let pid = PointIdentifier::SparkplugMetric {
            group_id: "g".into(),
            edge_node_id: "e".into(),
            device_id: None,
            metric_name: Some("Temp".into()),
            metric_name_raw: None,
            alias: None,
        };
        let json = serde_json::to_string(&pid).expect("serialize");
        assert!(!json.contains("device_id"));
        assert!(!json.contains("metric_name_raw"));
        assert!(!json.contains("alias"));
        assert!(json.contains("metric_name"));
    }
}
