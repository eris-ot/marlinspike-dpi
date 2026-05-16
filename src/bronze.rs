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

/// OPC UA Binary (TCP) transaction fields lifted from the wire header.
///
/// Covers the transport-level handshake (HEL/ACK), secure-channel lifecycle
/// (OPN/CLO), application-layer messages (MSG), and error frames (ERR). The
/// full Variant payload is carried by [`ProcessReading`]; this struct is
/// scoped to the *transaction*, not the values.
///
/// All fields use primitive types so they serialise cleanly to JSON for the
/// Silver register profile and the forensic workbench API.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OpcUaBronzeFields {
    /// Three-character message type code: "HEL", "ACK", "OPN", "CLO", "MSG",
    /// "ERR", or "RHE".
    pub message_type: String,
    /// Chunk type byte decoded as a single-character string: "F" (final),
    /// "C" (continuation), or "A" (abort). Represented as `String` because
    /// `char` serde round-trips are fiddly across JSON implementations.
    pub chunk_type: String,
    /// Secure channel identifier from the OPN/CLO/MSG extended header.
    /// `None` for HEL/ACK/ERR frames that do not carry this field.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub secure_channel_id: Option<u32>,
    /// Request identifier from the MSG full header (bytes 20–23).
    /// `None` when the frame type has no request-id field or header is truncated.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_id: Option<u32>,
    /// Sequence number from the MSG full header (bytes 16–19).
    /// `None` when the frame type has no sequence-number field.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sequence_number: Option<u32>,
    /// Numeric NodeId of the service request/response (e.g. ReadRequest=629,
    /// WriteRequest=671, BrowseRequest=525). Decoded from the MSG body.
    /// `None` when not yet decoded or for non-MSG frame types.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub service_node_id: Option<u32>,
    /// Human-readable service name where known (e.g. "ReadRequest",
    /// "WriteResponse", "BrowseRequest"). Derived from `service_node_id`
    /// or from the `service_type` string parsed by the dissector.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub service_name: Option<String>,
    /// Status/error code for ACK, ERR, and response frames. For ERR frames
    /// this is the 32-bit error code at bytes 8–11; for MSG responses it is
    /// the service-level status code where present.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status_code: Option<u32>,
    /// True when the direction heuristic identified this frame as a client
    /// request (dst_port is 4840 or 12001).
    pub is_request: bool,
    /// True when the direction heuristic identified this frame as a server
    /// response (src_port is 4840 or 12001).
    pub is_response: bool,
    /// Coarse direction label: "request", "response", "session" (HEL/ACK/OPN/CLO),
    /// or "error".
    pub direction: String,
}

/// EtherNet/IP (explicit messaging, TCP/44818) fields carried on a
/// [`ProtocolTransaction`]. Covers the encapsulation header and the CIP
/// request/response layer for the EIP explicit message channel.
///
/// All optional fields are `None` when the corresponding layer is absent
/// (e.g. `cip_service` is `None` for a bare `RegisterSession` whose payload
/// carries no CIP PDU).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EthernetIpBronzeFields {
    /// EIP encapsulation command code (e.g. 0x65 = RegisterSession,
    /// 0x6F = SendRRData, 0x63 = ListIdentity).
    pub encap_command: u16,
    /// Human-readable name for the encapsulation command.
    pub encap_command_name: String,
    /// Session handle assigned by the target after RegisterSession.
    /// `None` before a session is established (i.e. the RegisterSession
    /// request itself carries 0).
    pub session_handle: Option<u32>,
    /// Encapsulation status from the response header (0 = success).
    pub encap_status: Option<u32>,
    /// Encapsulation options field.
    pub encap_options: Option<u32>,
    /// CIP service code with the reply bit (0x80) stripped.
    /// `None` when the encapsulation payload carries no CIP PDU.
    pub cip_service: Option<u8>,
    /// Human-readable name for the CIP service (e.g. "read_tag",
    /// "forward_open"). `None` when `cip_service` is `None`.
    pub cip_service_name: Option<String>,
    /// CIP class ID from the logical path segment (e.g. 0x01 = Identity,
    /// 0x06 = Connection Manager, 0x6B = Symbol).
    pub cip_class_id: Option<u32>,
    /// CIP instance ID from the logical path segment.
    pub cip_instance_id: Option<u32>,
    /// CIP attribute ID from the logical path segment.
    pub cip_attribute_id: Option<u32>,
    /// CIP general status byte from the response (0x00 = Success).
    /// `None` for requests and encapsulation-only exchanges.
    pub cip_general_status: Option<u8>,
    /// CIP extended status word, present when `cip_general_status` carries
    /// a code that includes extended status (e.g. 0x1F).
    pub cip_extended_status: Option<u16>,
    /// `true` when this is a CIP request, `false` for a reply. Derived from
    /// the service byte high bit (0 = request, 1 = reply).
    pub is_request: bool,
    /// `"request"`, `"response"`, or `"paired"` (encoder merges req+resp).
    pub direction: String,
}

/// IEC 61850-family typed fields covering MMS (TCP/102), GOOSE (0x88B8), and
/// Sampled Values (0x88BA). Sub-protocol is indicated by `sub_protocol`; fields
/// that do not apply to the active sub-protocol are `None` / default.
///
/// All integer types are chosen to match the wire width defined by the standard:
/// APPID is 16-bit, stNum/sqNum are 32-bit, smp_cnt is 16-bit, smp_synch is 8-bit.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Iec61850BronzeFields {
    /// Active sub-protocol: `"mms"`, `"goose"`, or `"sv"`.
    pub sub_protocol: String,

    // --- MMS (ISO-on-TCP) fields ---
    /// MMS service name, e.g. `"initiate_request"`, `"confirmed_request_pdu"`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mms_service: Option<String>,
    /// MMS invoke-ID from the confirmed-request/response PDU header.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mms_invoke_id: Option<u32>,
    /// First VisibleString found in the MMS payload; carries device-identification
    /// strings such as the IED name or a dataset reference.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mms_visible_string: Option<String>,

    // --- GOOSE fields ---
    /// GOOSE APPID from the Ethernet payload header.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub goose_appid: Option<u16>,
    /// Dataset reference / gocbRef string extracted from the GOOSE PDU.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub goose_dataset_ref: Option<String>,
    /// stNum (state number) — increments on every state change event.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub goose_state_number: Option<u32>,
    /// sqNum (sequence number) — increments for every retransmission within a state.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub goose_sequence_number: Option<u32>,
    /// Test bit — when `true` the GOOSE message is a test/simulation signal.
    /// Defenders can use this to detect unexpected test-mode traffic.
    pub goose_test: bool,

    // --- Sampled Values fields ---
    /// SV APPID from the Ethernet payload header.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sv_appid: Option<u16>,
    /// SmpCnt — sample count from the first ASDU in the SV PDU.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sv_smp_cnt: Option<u16>,
    /// SmpSynch — sample synchronisation flag (0 = none, 1 = local, 2 = global).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sv_smp_synch: Option<u8>,

    /// Traffic direction: `"request"`, `"response"`, `"publish"`, or `"observed"`.
    pub direction: String,
}

/// HART-IP–specific fields carried on every `ProtocolTransaction` emitted by
/// the HART-IP decoder. Present when `protocol_fields` is
/// `Some(ProtocolFields::HartIp(...))`.
///
/// Numeric wire values are preserved alongside their human-readable names so
/// consumers can pattern-match on integers or display strings without a second
/// lookup table.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HartIpBronzeFields {
    /// Wire message-type byte (0=Request, 1=Response, 2=Publish/Notify,
    /// 3=Error, 15=NAK).
    pub message_type: u8,
    /// Human-readable name derived from `message_type`.
    pub message_type_name: String,
    /// Wire message-id byte (0=Session-Initiate, 1=Session-Close,
    /// 2=Keep-Alive, 3=Pass-Through).
    pub message_id: u8,
    /// Human-readable name derived from `message_id`.
    pub message_id_name: String,
    /// Status/error byte from the HART-IP header.
    pub status_byte: u8,
    /// Sequence number from the HART-IP header (called `transaction_id` on
    /// the wire).
    pub sequence_number: u16,
    /// Total message length as encoded in the HART-IP header.
    pub payload_length: u16,
    /// HART Universal/Common/Device-Specific command number carried inside a
    /// Pass-Through frame. `None` for session-management messages.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub passthrough_command: Option<u8>,
    /// Human-readable name for `passthrough_command`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub passthrough_command_name: Option<String>,
    /// HART field-device-status byte from the response payload of a
    /// Pass-Through frame. `None` when not present.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub device_status: Option<u8>,
    /// 5-byte long-frame (unique) address when the Pass-Through frame uses
    /// unique addressing. `None` for polling-address or non-Pass-Through
    /// frames.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub field_device_address: Option<Vec<u8>>,
    /// `"request"`, `"response"`, `"publish"`, `"error"`, `"nak"`, or
    /// `"observed"`.
    pub direction: String,
}

/// Sparkplug B session-management fields carried on a [`ProtocolTransaction`].
///
/// Emitted for every Sparkplug B session-management message (NBIRTH, NDEATH,
/// DBIRTH, DDEATH, NDATA, DDATA, NCMD, DCMD, STATE). `ProcessReading` events
/// are emitted separately for metric-bearing messages and are already typed via
/// [`PointIdentifier::SparkplugMetric`] + [`RawQuality::SparkplugQuality`];
/// this struct covers only the session/control envelope.
///
/// All fields use primitive types so they serialise cleanly to JSON for the
/// Silver register profile and the forensic workbench API.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SparkplugBronzeFields {
    /// Sparkplug B message type: "NBIRTH" / "NDEATH" / "DBIRTH" / "DDEATH" /
    /// "NDATA" / "DDATA" / "NCMD" / "DCMD" / "STATE".
    pub message_type: String,
    /// Sparkplug B group identifier from the topic (e.g. "Plant1").
    pub group_id: String,
    /// Edge node identifier from the topic (e.g. "PLC-A").
    pub edge_node_id: String,
    /// Device identifier, present only for D* messages (DBIRTH, DDEATH, DDATA,
    /// DCMD). `None` for node-scoped messages (N*) and STATE.
    pub device_id: Option<String>,
    /// Birth/death sequence number from the `bdSeq` metric in BIRTH/DEATH
    /// messages. Used as the supersession key to order session restarts.
    /// `None` when absent (e.g. DATA, CMD, STATE messages).
    pub bdseq: Option<u64>,
    /// Per-message sequence counter from the payload `seq` field.
    /// Sparkplug uses this to detect out-of-order or missing messages within
    /// an alive session lifetime. `None` when absent (e.g. DEATH messages).
    pub seq: Option<u64>,
    /// Payload-level timestamp, milliseconds since Unix epoch, when the
    /// Sparkplug payload carries one. `None` if the payload omits it.
    pub payload_timestamp: Option<u64>,
    /// Number of metrics in the payload. `None` for messages that carry no
    /// metrics (DEATH, NCMD without targets, STATE).
    pub metric_count: Option<u32>,
    /// Alias resolution state for DATA messages, indicating whether the
    /// decoder had a prior BIRTH to resolve metric aliases:
    /// - `"resolved"` — all aliases mapped from a prior BIRTH
    /// - `"unresolved_no_birth"` — at least one alias could not be resolved
    /// - `"n/a"` — not applicable (BIRTH, DEATH, CMD, STATE)
    pub alias_resolution_state: String,
    /// True for BIRTH messages (NBIRTH, DBIRTH).
    pub is_birth: bool,
    /// True for DEATH messages (NDEATH, DDEATH).
    pub is_death: bool,
    /// True for command messages (NCMD, DCMD).
    pub is_command: bool,
}

/// MELSEC SLMP (Seamless Message Protocol) typed fields carried on a [`ProtocolTransaction`].
///
/// Covers the 4E binary frame header (serial number, network/PC addressing, command +
/// subcommand) and the end-code present in paired responses. All integer types match
/// the wire width (little-endian throughout SLMP).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MelsecBronzeFields {
    /// SLMP 4E serial number used to pair requests and responses.
    pub serial_number: u16,
    /// Network number (0x00 = local network).
    pub network_number: u8,
    /// PC number (0xFF = self).
    pub pc_number: u8,
    /// Raw 2-byte command code (e.g. 0x0401 = Batch Read).
    pub command: u16,
    /// Raw 2-byte subcommand code (0x0001 = word units, 0x0003 = bit units).
    pub subcommand: u16,
    /// End code from the response header (0x0000 = success). `None` for unpaired requests.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub end_code: Option<u16>,
    /// `"request"`, `"ok"`, `"request_only"`, `"response_only"`, or `"slmp_error_0x<hhhh>"`.
    pub direction: String,
}

/// OPC UA PubSub (UADP over UDP/4840) typed fields carried on a [`ProtocolTransaction`].
///
/// Covers the UADP NetworkMessage header fields (Part 14 §7.2): version, optional
/// publisher identity, writer-group addressing, and the list of DataSetWriter IDs
/// present in the message. DataValue/Variant payloads are emitted as separate
/// `ProcessReading` events and are not duplicated here.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OpcUaPubsubBronzeFields {
    /// UADP version from the low 4 bits of the first flags byte (expected: 1).
    pub ua_version: u8,
    /// Publisher ID string. `None` when the PublisherId flag is not set.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub publisher_id: Option<String>,
    /// Publisher ID type name (e.g. `"uint16"`, `"string"`). `None` when publisher_id is absent.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub publisher_id_type: Option<String>,
    /// WriterGroup ID. `None` when the GroupHeader flag is not set.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub writer_group_id: Option<u16>,
    /// WriterGroup version. `None` when not present.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub group_version: Option<u32>,
    /// Network message number within the WriterGroup. `None` when not present.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub network_message_number: Option<u16>,
    /// Sequence number for the NetworkMessage. `None` when not present.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sequence_number: Option<u16>,
    /// DataSet class GUID. `None` when the DataSetClassId flag is not set.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dataset_class_id: Option<String>,
    /// Count of DataSetMessages (DataSetWriters) present in this NetworkMessage.
    pub dataset_writer_count: u32,
    /// DataSetWriter IDs for each DataSetMessage in the payload.
    pub dataset_writer_ids: Vec<u16>,
}

/// Beckhoff ADS/AMS typed fields carried on a [`ProtocolTransaction`].
///
/// Covers the AMS/TCP framing and the AMS packet header. Direction is derived from
/// the state-flags response bit. Paired request/answer transactions emit the
/// request-side fields since the response carries no additional AMS-level data.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AdsBronzeFields {
    /// AMS NetID of the target (destination) runtime (e.g. `"192.168.1.1.1.1"`).
    pub target_netid: String,
    /// AMS port of the target (e.g. 851 = PLC Runtime 1).
    pub target_port: u16,
    /// AMS NetID of the source runtime.
    pub source_netid: String,
    /// AMS port of the source.
    pub source_port: u16,
    /// ADS command ID (1–9: ReadDeviceInfo/Read/Write/ReadState/WriteControl/
    /// AddNotification/DeleteNotification/DeviceNotification/ReadWrite).
    pub cmd_id: u16,
    /// Raw AMS state-flags word. Bit 0 set = response; bit 2 set = ADS command.
    pub state_flags: u16,
    /// ADS error code from the AMS packet header (0 = success).
    pub error_code: u32,
    /// Invoke ID used to correlate request/response pairs.
    pub invoke_id: u32,
    /// `"request"`, `"ok"`, `"request_only"`, `"response_only"`, or `"ads_error_0x<hhhhhhhh>"`.
    pub direction: String,
}

/// GE SRTP (Service Request Transport Protocol) typed fields.
///
/// Covers the 56-byte fixed header on port 18245/TCP. Request/response pairs are
/// correlated by sequence number; unpaired halves set direction accordingly.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GeSrtpBronzeFields {
    /// Raw SRTP message type byte (0x02 = Request, 0x03 = Response).
    pub msg_type: u8,
    /// Sequence number used to pair requests and responses (LE u16 at offset 9).
    pub sequence_number: u16,
    /// SRTP service request code byte (e.g. 0x03 = Read System Memory).
    pub service_code: u8,
    /// Human-readable name for `service_code`.
    pub service_code_name: String,
    /// Major status byte from the response header (0x00 = success).
    pub status_code: u8,
    /// Minor status byte from the response header.
    pub minor_status: u8,
    /// `"request"`, `"ok"`, `"request_only"`, `"response_only"`, or `"srtp_status_0x<hh>_minor_0x<hh>"`.
    pub direction: String,
}

/// TriStation (Triconex Safety SIS) typed fields.
///
/// Covers the 4-byte header only — payload bytes are not decoded to avoid false
/// positives from protocol ambiguity (proprietary, no public spec). The
/// `SetControlProgram` (0x70) command is associated with TRITON/TRISIS malware.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TriStationBronzeFields {
    /// Raw command type byte (function code), e.g. 0x70 = Set Control Program.
    pub command_type: u8,
    /// Human-readable name for `command_type` (e.g. `"tristation_set_control_program"`).
    pub command_type_name: String,
    /// Command subtype byte (semantics vary per command_type; not publicly documented).
    pub command_subtype: u8,
    /// Declared payload length from bytes 2–3 (LE u16).
    pub payload_length: u16,
}

/// Diameter (RFC 6733) typed fields carried on a [`ProtocolTransaction`].
///
/// Covers the 20-byte fixed header and the subset of AVPs extracted by the
/// decoder: User-Name (1), Session-Id (263), Origin-Host (264), Origin-Realm
/// (296), Result-Code (268). All integer types are wire width.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DiameterBronzeFields {
    /// Diameter command code (e.g. 257 = Capabilities-Exchange, 280 = Device-Watchdog).
    pub command_code: u32,
    /// Human-readable command operation string (e.g. `"diameter_capabilities_exchange_request"`).
    pub command_code_name: String,
    /// Diameter Application-ID (0 = Base, 1 = NASREQ, 3 = Accounting, etc.).
    pub application_id: u32,
    /// Hop-by-Hop Identifier — used to pair request/answer within a session.
    pub hop_by_hop_id: u32,
    /// End-to-End Identifier — globally unique per message origin.
    pub end_to_end_id: u32,
    /// Raw command flags byte (R=b7, P=b6, E=b5, T=b4).
    pub command_flags: u8,
    /// True when the R (Request) flag is set.
    pub is_request: bool,
    /// True when the E (Error) flag is set.
    pub is_error: bool,
    /// AVP 1 — User-Name string.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub avp_user_name: Option<String>,
    /// AVP 263 — Session-Id string.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub avp_session_id: Option<String>,
    /// AVP 264 — Origin-Host string.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub avp_origin_host: Option<String>,
    /// AVP 296 — Origin-Realm string.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub avp_origin_realm: Option<String>,
    /// AVP 268 — Result-Code (2xxx = success, 3xxx = redirect, 4xxx/5xxx = error).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub avp_result_code: Option<u32>,
    /// `"request"`, `"ok"`, `"request_only"`, `"response_only"`, or `"error"`.
    pub direction: String,
}

/// PROFINET typed fields carried on a [`ProtocolTransaction`].
///
/// Covers the PROFINET frame identifier class and the DCP service-type string
/// produced by the dissector. All integer types match the wire width.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProfinetBronzeFields {
    /// Raw 16-bit PROFINET Frame ID (e.g. 0xFEFE = DCP-Identify, 0x8000–0xBFFF = cyclic RT).
    pub frame_id: u16,
    /// Human-readable service type from the dissector (e.g. `"dcp_identify_request"`).
    pub service_type: String,
    /// Payload byte count from the dissected frame.
    pub payload_length: u32,
    /// `"request"`, `"response"`, or `"observed"`.
    pub direction: String,
}

/// BACnet/IP and BACnet/MSTP typed fields carried on a [`ProtocolTransaction`].
///
/// Covers the BVLC/LLC link layer, NPDU control byte, APDU type, and the
/// service name decoded from the APDU. Device-instance and vendor-id appear
/// only in I-Am / Who-Is exchanges.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BacnetBronzeFields {
    /// Link variant: `"bvlp"` (UDP/IP) or `"mstp"` (LLC/802.2).
    pub link_variant: String,
    /// BVLC function name when present (e.g. `"original_unicast_npdu"`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bvlc_function: Option<String>,
    /// Raw NPDU control byte (network-layer flags).
    pub npdu_control: u8,
    /// APDU type: `"confirmed_request"`, `"unconfirmed_request"`, `"simple_ack"`,
    /// `"complex_ack"`, `"error"`, `"reject"`, or `"abort"`.
    pub apdu_type: String,
    /// BACnet service name (e.g. `"read_property"`, `"who_is"`, `"i_am"`).
    pub service: String,
    /// Invoke ID from confirmed-service exchanges; `None` for unconfirmed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub invoke_id: Option<u8>,
    /// BACnet device instance number from I-Am / Read-Property responses.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub device_instance: Option<u32>,
    /// BACnet vendor ID from I-Am responses.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub vendor_id: Option<u16>,
    /// `"request"`, `"response"`, `"error"`, or `"observed"`.
    pub direction: String,
}

/// Per-datagram fields from an EtherCAT frame.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EthercatDatagramBronzeFields {
    /// EtherCAT command mnemonic (e.g. `"LRW"`, `"BRD"`, `"APRD"`).
    pub command: String,
    /// Raw command code byte.
    pub command_code: u8,
    /// Address mode: `"logical"`, `"configured_station"`, or `"auto_increment"`.
    pub address_mode: String,
    /// ADP — address/position field (slave station address or logical address high word).
    pub adp: u16,
    /// ADO — address offset within the slave memory map.
    pub ado: u16,
    /// Length of the datagram data section in bytes.
    pub data_length: u16,
    /// Working counter incremented by each slave that processes the command.
    pub working_counter: u16,
}

/// EtherCAT (EtherType 0x88A4) typed fields carried on a [`ProtocolTransaction`].
///
/// An EtherCAT frame carries one or more datagrams; this struct exposes
/// per-datagram addressing so consumers can identify which slaves were targeted.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EthercatBronzeFields {
    /// Total number of datagrams in the EtherCAT frame.
    pub datagram_count: u32,
    /// Per-datagram fields for every datagram in the frame.
    pub datagrams: Vec<EthercatDatagramBronzeFields>,
}

/// OMRON FINS typed fields carried on a [`ProtocolTransaction`].
///
/// Covers the FINS/TCP command header, network addressing (network/node/unit),
/// and the command-code with its human-readable name. Memory-area fields
/// appear only for memory read/write commands.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OmronFinsBronzeFields {
    /// Frame variant: `"fins_udp"`, `"fins_tcp"`, etc.
    pub frame_variant: String,
    /// FINS/TCP command code (present for TCP sessions only).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tcp_command: Option<u32>,
    /// FINS/TCP error code from the TCP header (non-zero on error).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tcp_error_code: Option<u32>,
    /// ICF (Information Control Field) byte from the FINS header.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub icf: Option<u8>,
    /// RSV reserved byte (should be 0x00).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rsv: Option<u8>,
    /// Gateway count — number of gateways the frame passed through.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub gateway_count: Option<u8>,
    /// Destination network number (0x00 = local).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub destination_network: Option<u8>,
    /// Destination node number.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub destination_node: Option<u8>,
    /// Destination unit address.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub destination_unit: Option<u8>,
    /// Source network number.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_network: Option<u8>,
    /// Source node number.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_node: Option<u8>,
    /// Source unit address.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_unit: Option<u8>,
    /// Service ID used to match request/response pairs.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub service_id: Option<u8>,
    /// 2-byte FINS command code (high byte = main code, low byte = sub code).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub command_code: Option<u16>,
    /// Human-readable command name (e.g. `"memory_area_read"`, `"cpu_unit_status_read"`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub command_name: Option<String>,
    /// Memory area code for memory read/write commands.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub memory_area: Option<u8>,
    /// Starting word address within the memory area.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub memory_word: Option<u16>,
    /// Starting bit address within the word.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub memory_bit: Option<u8>,
    /// Number of items to read or write.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub item_count: Option<u16>,
    /// `"request"`, `"response"`, or `"observed"`.
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
    OpcUa(OpcUaBronzeFields),
    EthernetIp(EthernetIpBronzeFields),
    Iec61850(Iec61850BronzeFields),
    HartIp(HartIpBronzeFields),
    Sparkplug(SparkplugBronzeFields),
    Profinet(ProfinetBronzeFields),
    Bacnet(BacnetBronzeFields),
    Ethercat(EthercatBronzeFields),
    OmronFins(OmronFinsBronzeFields),
    Melsec(MelsecBronzeFields),
    OpcUaPubsub(OpcUaPubsubBronzeFields),
    Ads(AdsBronzeFields),
    GeSrtp(GeSrtpBronzeFields),
    TriStation(TriStationBronzeFields),
    Diameter(DiameterBronzeFields),
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
        assert!(
            !json.contains("\"value\""),
            "value: None should be skipped, got: {json}"
        );
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
