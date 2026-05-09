//! Dissector registry — dispatches packets to protocol-specific parsers.

use std::collections::BTreeMap;
use std::net::IpAddr;

use crate::dissectors::{
    ethercat::EthercatFields, hart_ip::HartIpFields, iec61850::Iec61850Fields,
};

/// Context extracted from lower-layer headers for a single packet.
#[derive(Debug, Clone)]
pub struct PacketContext {
    pub src_mac: [u8; 6],
    pub dst_mac: [u8; 6],
    pub src_ip: IpAddr,
    pub dst_ip: IpAddr,
    pub src_port: u16,
    pub dst_port: u16,
    pub vlan_id: Option<u16>,
    pub timestamp: u64,
}

/// Protocol-specific parsed data, matching `bronze.proto` oneof variants.
#[derive(Debug, Clone)]
pub enum ProtocolData {
    Bacnet(BacnetFields),
    Iec104(Iec104Fields),
    OmronFins(OmronFinsFields),
    HartIp(HartIpFields),
    Iec61850(Iec61850Fields),
    Ethercat(EthercatFields),
    Modbus(ModbusFields),
    Dnp3(Dnp3Fields),
    EthernetIp(EthernetIpFields),
    OpcUa(OpcUaFields),
    S7comm(S7commFields),
    Profinet(ProfinetFields),
    Dhcp(DhcpFields),
    Snmp(SnmpFields),
    Cdp(CdpFields),
    Stp(StpFields),
    Dns(DnsFields),
    Tls(TlsFields),
    Http(HttpFields),
    Arp(ArpFields),
    Lldp(LldpFields),
    Ntp(NtpFields),
    Mqtt(MqttFields),
    Syslog(SyslogFields),
    Ftp(FtpFields),
    Ssh(SshFields),
    Radius(RadiusFields),
    Vtp(VtpFields),
    Mrp(MrpFields),
    Mstp(MstpFields),
    Pvst(PvstFields),
    Prp(PrpFields),
    Lacp(LacpFields),
    Icmp(IcmpFields),
}

impl ProtocolData {
    /// Returns the protocol name string used in `BronzeRecord.protocol`.
    pub fn protocol_name(&self) -> &'static str {
        match self {
            Self::Bacnet(_) => "bacnet",
            Self::Iec104(_) => "iec104",
            Self::OmronFins(_) => "omron_fins",
            Self::HartIp(_) => "hart_ip",
            Self::Iec61850(_) => "iec61850",
            Self::Ethercat(_) => "ethercat",
            Self::Modbus(_) => "modbus",
            Self::Dnp3(_) => "dnp3",
            Self::EthernetIp(_) => "ethernet_ip",
            Self::OpcUa(_) => "opc_ua",
            Self::S7comm(_) => "s7comm",
            Self::Profinet(_) => "profinet",
            Self::Dhcp(_) => "dhcp",
            Self::Snmp(_) => "snmp",
            Self::Cdp(_) => "cdp",
            Self::Stp(_) => "stp",
            Self::Dns(_) => "dns",
            Self::Tls(_) => "tls",
            Self::Http(_) => "http",
            Self::Arp(_) => "arp",
            Self::Lldp(_) => "lldp",
            Self::Ntp(_) => "ntp",
            Self::Mqtt(_) => "mqtt",
            Self::Syslog(_) => "syslog",
            Self::Ftp(_) => "ftp",
            Self::Ssh(_) => "ssh",
            Self::Radius(_) => "radius",
            Self::Vtp(_) => "vtp",
            Self::Mrp(_) => "mrp",
            Self::Mstp(_) => "mstp",
            Self::Pvst(_) => "pvst",
            Self::Prp(_) => "prp",
            Self::Lacp(_) => "lacp",
            Self::Icmp(_) => "icmp",
        }
    }
}

// ── Field structs ──────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct BacnetFields {
    pub link_variant: String,
    pub bvlc_function: Option<String>,
    pub npdu_control: u8,
    pub apdu_type: String,
    pub service: String,
    pub invoke_id: Option<u8>,
    pub device_instance: Option<u32>,
    pub vendor_id: Option<u16>,
    pub payload: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct Iec104Fields {
    pub frame_type: String,
    pub send_sequence: Option<u16>,
    pub receive_sequence: Option<u16>,
    pub u_format: Option<String>,
    pub type_id: Option<u8>,
    pub cause_of_transmission: Option<u16>,
    pub common_address: Option<u16>,
    pub information_object_address: Option<u32>,
    pub payload: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct OmronFinsFields {
    pub frame_variant: String,
    pub tcp_command: Option<u32>,
    pub tcp_error_code: Option<u32>,
    pub icf: Option<u8>,
    pub rsv: Option<u8>,
    pub gateway_count: Option<u8>,
    pub destination_network: Option<u8>,
    pub destination_node: Option<u8>,
    pub destination_unit: Option<u8>,
    pub source_network: Option<u8>,
    pub source_node: Option<u8>,
    pub source_unit: Option<u8>,
    pub service_id: Option<u8>,
    pub command_code: Option<u16>,
    pub command_name: Option<String>,
    pub memory_area: Option<u8>,
    pub memory_word: Option<u16>,
    pub memory_bit: Option<u8>,
    pub item_count: Option<u16>,
    pub payload: Vec<u8>,
}

/// Direction of a Modbus PDU relative to the server (unit).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ModbusDirection {
    /// Client → server (master → slave).
    Request,
    /// Server → client (slave → master).
    Response,
}

/// Structured Modbus PDU extracted from a single MBAP frame.
///
/// Carries the full semantic content needed by Silver for register profiling:
/// start address, quantity, values, direction, and exception code.
#[derive(Debug, Clone)]
pub struct ModbusPdu {
    /// Base function code (high-bit stripped).
    pub function_code: u8,
    /// Request or response frame.
    pub direction: ModbusDirection,
    /// Starting register / coil address (0-based). None for response frames
    /// where the server does not echo the address (FC 01/02/03/04 response).
    pub start_addr: Option<u16>,
    /// Quantity of registers or coils. Populated on requests for read FCs and
    /// on both request and response for write-multiple FCs.
    pub qty: Option<u16>,
    /// Register or coil values. Write FCs populate this on the request;
    /// read FCs populate this on the response. Coil bits are packed per the
    /// Modbus spec and stored one-per-u16 (0 or 1) for uniform handling.
    pub values: Vec<u16>,
    /// Exception code present when the frame is an exception response.
    pub exception_code: Option<u8>,
}

#[derive(Debug, Clone)]
pub struct ModbusFields {
    pub transaction_id: u16,
    pub unit_id: u8,
    pub function_code: u8,
    pub is_exception: bool,
    pub exception_code: u8,
    /// Structured PDU — the authoritative source for Silver register profiling.
    pub pdu: Option<ModbusPdu>,
    /// Legacy flat register pairs kept for backward compat with engine helpers.
    pub registers: Vec<(u16, u16)>,
    pub device_identification: BTreeMap<String, String>,
}

#[derive(Debug, Clone)]
pub struct Dnp3Fields {
    pub source_address: u16,
    pub destination_address: u16,
    pub function_code: u8,
    pub application_data: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct EthernetIpFields {
    pub command: u16,
    pub session_handle: u32,
    pub cip_data: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct OpcUaFields {
    pub message_type: String,
    pub request_id: u32,
    pub service_type: String,
}

#[derive(Debug, Clone)]
pub struct S7commFields {
    pub rosctr: u8,
    pub function: u8,
    pub parameter: Vec<u8>,
    pub data: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct ProfinetFields {
    pub frame_id: u16,
    pub service_type: String,
    pub payload: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct DhcpFields {
    pub op: u8,
    pub xid: u32,
    pub client_mac: [u8; 6],
    pub ciaddr: Option<String>,
    pub yiaddr: Option<String>,
    pub siaddr: Option<String>,
    pub giaddr: Option<String>,
    pub message_type: Option<u8>,
    pub hostname: Option<String>,
    pub client_id: Option<String>,
    pub vendor_class: Option<String>,
    pub requested_ip: Option<String>,
    pub server_id: Option<String>,
}

#[derive(Debug, Clone)]
pub struct SnmpFields {
    pub version: String,
    pub community: Option<String>,
    pub pdu_type: String,
    pub request_id: Option<i32>,
    pub var_binds: Vec<SnmpVarBind>,
    pub sys_name: Option<String>,
    pub sys_descr: Option<String>,
    pub sys_object_id: Option<String>,
    pub engine_id: Option<String>,
}

#[derive(Debug, Clone)]
pub struct SnmpVarBind {
    pub oid: String,
    pub value: Option<String>,
}

#[derive(Debug, Clone)]
pub struct CdpFields {
    pub version: u8,
    pub ttl: u8,
    pub checksum: u16,
    pub device_id: String,
    pub port_id: String,
    pub platform: Option<String>,
    pub software_version: Option<String>,
    pub capabilities: Vec<String>,
    pub native_vlan: Option<u16>,
    pub duplex: Option<String>,
    pub management_addresses: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct StpFields {
    pub protocol_version: u8,
    pub bpdu_type: u8,
    pub flags: u8,
    pub root_id: String,
    pub root_path_cost: u32,
    pub bridge_id: String,
    pub port_id: u16,
    pub hello_time: u16,
    pub max_age: u16,
    pub forward_delay: u16,
}

#[derive(Debug, Clone)]
pub struct DnsFields {
    pub transaction_id: u16,
    pub is_response: bool,
    pub queries: Vec<String>,
    pub answers: Vec<String>,
    /// Structured DNS resource records from answer + additional sections.
    /// Populated for mDNS responses; gives access to TXT key=value, SRV
    /// targets, and A/AAAA bindings that the flat `answers` strings lose.
    pub records: Vec<DnsRecord>,
}

/// A parsed DNS resource record (answer, authority, or additional).
#[derive(Debug, Clone)]
pub struct DnsRecord {
    /// Owner name (e.g. "Bathroom TV._airplay._tcp.local").
    pub name: String,
    /// Record type: A, AAAA, PTR, TXT, SRV, etc.
    pub rtype: DnsRecordType,
    /// Parsed data — varies by record type.
    pub data: DnsRecordData,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DnsRecordType {
    A,
    AAAA,
    PTR,
    TXT,
    SRV,
    Other(u16),
}

#[derive(Debug, Clone)]
pub enum DnsRecordData {
    /// A record: IPv4 address.
    A(String),
    /// AAAA record: IPv6 address.
    Aaaa(String),
    /// PTR record: domain name.
    Ptr(String),
    /// TXT record: key=value pairs.
    Txt(Vec<String>),
    /// SRV record: target host and port.
    Srv {
        target: String,
        port: u16,
        priority: u16,
        weight: u16,
    },
    /// Unparsed record.
    Raw(Vec<u8>),
}

#[derive(Debug, Clone)]
pub struct TlsFields {
    pub version: String,
    pub cipher_suite: String,
    pub sni: String,
    pub certificate_subjects: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct HttpFields {
    pub method: String,
    pub host: String,
    pub uri: String,
    pub status_code: u16,
    pub content_type: String,
    pub content_length: u64,
}

#[derive(Debug, Clone)]
pub struct ArpFields {
    pub operation: u16,
    pub sender_mac: [u8; 6],
    pub sender_ip: [u8; 4],
    pub target_mac: [u8; 6],
    pub target_ip: [u8; 4],
}

#[derive(Debug, Clone)]
pub struct LldpFields {
    pub chassis_id: String,
    pub port_id: String,
    pub ttl: u16,
    pub system_name: String,
    pub system_description: String,
    pub capabilities: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct NtpFields {
    pub version: u8,
    pub mode: u8,
    pub mode_name: String,
    pub leap_indicator: u8,
    pub stratum: u8,
    pub poll: i8,
    pub precision: i8,
    pub root_delay_ms: f64,
    pub root_dispersion_ms: f64,
    pub reference_id: String,
    pub reference_timestamp: f64,
}

#[derive(Debug, Clone)]
pub struct MqttFields {
    pub packet_type: u8,
    pub packet_type_name: String,
    pub protocol_name: Option<String>,
    pub protocol_version: Option<u8>,
    pub client_id: Option<String>,
    pub username: Option<String>,
    pub topic: Option<String>,
    pub qos: Option<u8>,
    pub retain: Option<bool>,
    pub clean_session: Option<bool>,
    /// Post-topic publish payload bytes, populated only for PUBLISH (packet_type == 3).
    /// `None` for all other packet types. Empty Vec means "PUBLISH with zero-byte payload".
    pub payload: Option<Vec<u8>>,
}

#[derive(Debug, Clone)]
pub struct SyslogFields {
    pub facility: u8,
    pub facility_name: String,
    pub severity: u8,
    pub severity_name: String,
    pub hostname: Option<String>,
    pub app_name: Option<String>,
    pub message: Option<String>,
}

#[derive(Debug, Clone)]
pub struct FtpFields {
    pub is_response: bool,
    pub command: Option<String>,
    pub argument: Option<String>,
    pub reply_code: Option<u16>,
    pub reply_text: Option<String>,
    pub banner: Option<String>,
}

#[derive(Debug, Clone)]
pub struct SshFields {
    pub protocol_version: String,
    pub software_version: String,
    pub comments: Option<String>,
    pub banner: String,
}

#[derive(Debug, Clone)]
pub struct RadiusFields {
    pub code: u8,
    pub code_name: String,
    pub identifier: u8,
    pub username: Option<String>,
    pub nas_ip_address: Option<String>,
    pub nas_identifier: Option<String>,
    pub calling_station_id: Option<String>,
    pub called_station_id: Option<String>,
    pub nas_port_type: Option<u32>,
    pub framed_ip_address: Option<String>,
    pub service_type: Option<u32>,
}

#[derive(Debug, Clone)]
pub struct VtpFields {
    pub version: u8,
    pub message_type: u8,
    pub message_type_name: String,
    pub domain_name: String,
    pub revision: Option<u32>,
    pub vlans: Vec<u16>,
}

#[derive(Debug, Clone)]
pub struct MrpFields {
    pub version: u16,
    pub frame_type: u16,
    pub frame_type_name: String,
    pub domain_uuid: Option<String>,
    pub ring_state: Option<String>,
    pub priority: Option<u16>,
    pub source_mac: Option<String>,
}

#[derive(Debug, Clone)]
pub struct MstpFields {
    pub protocol_version: u8,
    pub bpdu_type: u8,
    pub flags: u8,
    pub root_id: String,
    pub root_path_cost: u32,
    pub bridge_id: String,
    pub port_id: u16,
    pub config_name: Option<String>,
    pub revision_level: Option<u16>,
    pub msti_records: Vec<MstiRecord>,
}

#[derive(Debug, Clone)]
pub struct MstiRecord {
    pub flags: u8,
    pub regional_root: String,
    pub internal_path_cost: u32,
    pub bridge_priority: u8,
    pub remaining_hops: u8,
}

#[derive(Debug, Clone)]
pub struct PvstFields {
    pub protocol_version: u8,
    pub bpdu_type: u8,
    pub flags: u8,
    pub root_id: String,
    pub root_path_cost: u32,
    pub bridge_id: String,
    pub port_id: u16,
    pub originating_vlan: Option<u16>,
}

#[derive(Debug, Clone)]
pub struct PrpFields {
    pub supervision_path: u16,
    pub supervision_version: u16,
    pub supervision_type: u16,
    pub supervision_type_name: String,
    pub source_mac: Option<String>,
    pub red_box_mac: Option<String>,
    pub sequence_nr: Option<u16>,
}

#[derive(Debug, Clone)]
pub struct LacpFields {
    pub version: u8,
    pub actor: LacpPartner,
    pub partner: LacpPartner,
    pub max_delay: Option<u16>,
}

#[derive(Debug, Clone)]
pub struct LacpPartner {
    pub system_priority: u16,
    pub system: String,
    pub key: u16,
    pub port_priority: u16,
    pub port: u16,
    pub state: u8,
    pub state_flags: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct IcmpFields {
    pub icmp_type: u8,
    pub icmp_code: u8,
    pub checksum: u16,
    pub type_name: String,
    pub code_name: String,
    pub identifier: Option<u16>,
    pub sequence: Option<u16>,
    pub gateway_ip: Option<String>,
    pub payload_len: usize,
}

// ── Trait + Registry ───────────────────────────────────────────

/// Trait implemented by each protocol dissector.
pub trait ProtocolDissector: Send + Sync {
    /// Human-readable name (e.g. `"modbus"`).
    fn name(&self) -> &str;

    /// Quick check: can this dissector handle the packet?
    fn can_parse(&self, data: &[u8], src_port: u16, dst_port: u16) -> bool;

    /// Attempt full parse. Returns `None` if the data turns out to be invalid.
    fn parse(&self, data: &[u8], context: &PacketContext) -> Option<ProtocolData>;
}

/// Holds all registered dissectors and dispatches packets through them.
pub struct DissectorRegistry {
    dissectors: Vec<Box<dyn ProtocolDissector>>,
}

impl DissectorRegistry {
    pub fn new() -> Self {
        Self {
            dissectors: Vec::new(),
        }
    }

    /// Create a registry pre-loaded with all built-in dissectors.
    pub fn with_defaults() -> Self {
        use crate::dissectors::*;

        let mut reg = Self::new();
        reg.register(Box::new(bacnet::BacnetDissector));
        reg.register(Box::new(iec104::Iec104Dissector));
        reg.register(Box::new(fins::OmronFinsDissector));
        reg.register(Box::new(hart_ip::HartIpDissector));
        reg.register(Box::new(modbus::ModbusDissector));
        reg.register(Box::new(dns::DnsDissector));
        reg.register(Box::new(arp::ArpDissector));
        reg.register(Box::new(lldp::LldpDissector));
        reg.register(Box::new(cdp::CdpDissector));
        reg.register(Box::new(stp::StpDissector));
        reg.register(Box::new(http::HttpDissector));
        reg.register(Box::new(dhcp::DhcpDissector));
        reg.register(Box::new(snmp::SnmpDissector));
        reg.register(Box::new(dnp3::Dnp3Dissector));
        reg.register(Box::new(opc_ua::OpcUaDissector));
        reg.register(Box::new(s7comm::S7commDissector));
        reg.register(Box::new(iec61850::Iec61850Dissector));
        reg.register(Box::new(profinet::ProfinetDissector));
        reg.register(Box::new(ethercat::EthercatDissector));
        reg.register(Box::new(ethernet_ip::EthernetIpDissector));
        reg.register(Box::new(ntp::NtpDissector));
        reg.register(Box::new(mqtt::MqttDissector));
        reg.register(Box::new(syslog::SyslogDissector));
        reg.register(Box::new(ftp::FtpDissector));
        reg.register(Box::new(ssh::SshDissector));
        reg.register(Box::new(radius::RadiusDissector));
        reg.register(Box::new(vtp::VtpDissector));
        reg.register(Box::new(mrp::MrpDissector));
        reg.register(Box::new(mstp::MstpDissector));
        reg.register(Box::new(pvst::PvstDissector));
        reg.register(Box::new(prp::PrpDissector));
        reg.register(Box::new(lacp::LacpDissector));
        reg
    }

    pub fn register(&mut self, dissector: Box<dyn ProtocolDissector>) {
        self.dissectors.push(dissector);
    }

    /// Try each dissector in order; return the first successful parse.
    pub fn dispatch(&self, data: &[u8], context: &PacketContext) -> Option<ProtocolData> {
        for d in &self.dissectors {
            if d.can_parse(data, context.src_port, context.dst_port) {
                if let Some(result) = d.parse(data, context) {
                    return Some(result);
                }
            }
        }
        None
    }

    /// Classification-only dispatch: walks dissectors in order and returns
    /// the `name()` of the first one whose `can_parse` accepts the payload.
    /// No `parse()` is invoked. Used by [`crate::classify::Classifier`].
    pub fn classify_name(&self, data: &[u8], src_port: u16, dst_port: u16) -> Option<&str> {
        for d in &self.dissectors {
            if d.can_parse(data, src_port, dst_port) {
                return Some(d.name());
            }
        }
        None
    }
}

impl Default for DissectorRegistry {
    fn default() -> Self {
        Self::new()
    }
}

// ── Helpers ────────────────────────────────────────────────────

/// Format a 6-byte MAC address as `"aa:bb:cc:dd:ee:ff"`.
pub fn format_mac(mac: &[u8; 6]) -> String {
    format!(
        "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]
    )
}

/// Format a 4-byte IPv4 address as dotted decimal.
pub fn format_ipv4(ip: &[u8; 4]) -> String {
    format!("{}.{}.{}.{}", ip[0], ip[1], ip[2], ip[3])
}
