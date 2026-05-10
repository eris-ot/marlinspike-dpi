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

pub use crate::dissectors::bacnet::BacnetFields;

pub use crate::dissectors::iec104::Iec104Fields;

pub use crate::dissectors::fins::OmronFinsFields;

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

pub use crate::dissectors::dnp3::Dnp3Fields;

pub use crate::dissectors::ethernet_ip::EthernetIpFields;

pub use crate::dissectors::opc_ua::OpcUaFields;

pub use crate::dissectors::s7comm::S7commFields;

pub use crate::dissectors::profinet::ProfinetFields;

pub use crate::dissectors::dhcp::DhcpFields;

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

pub use crate::dissectors::cdp::CdpFields;

pub use crate::dissectors::stp::StpFields;

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

pub use crate::dissectors::tcp::TlsFields;

pub use crate::dissectors::http::HttpFields;

pub use crate::dissectors::arp::ArpFields;

pub use crate::dissectors::lldp::LldpFields;

pub use crate::dissectors::ntp::NtpFields;

pub use crate::dissectors::mqtt::MqttFields;

pub use crate::dissectors::syslog::SyslogFields;

pub use crate::dissectors::ftp::FtpFields;

pub use crate::dissectors::ssh::SshFields;

pub use crate::dissectors::radius::RadiusFields;

pub use crate::dissectors::vtp::VtpFields;

pub use crate::dissectors::mrp::MrpFields;

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

pub use crate::dissectors::pvst::PvstFields;

pub use crate::dissectors::prp::PrpFields;

pub use crate::dissectors::lacp::LacpFields;

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
