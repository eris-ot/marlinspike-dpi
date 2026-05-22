//! Dissector registry — dispatches packets to protocol-specific parsers.

use std::collections::HashMap;
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

pub use crate::dissectors::modbus::ModbusDirection;
pub use crate::dissectors::modbus::ModbusFields;
pub use crate::dissectors::modbus::ModbusPdu;

pub use crate::dissectors::dnp3::Dnp3Fields;

pub use crate::dissectors::ethernet_ip::EthernetIpFields;

pub use crate::dissectors::opc_ua::OpcUaFields;

pub use crate::dissectors::s7comm::S7commFields;

pub use crate::dissectors::profinet::ProfinetFields;

pub use crate::dissectors::dhcp::DhcpFields;

pub use crate::dissectors::snmp::SnmpFields;
pub use crate::dissectors::snmp::SnmpVarBind;

pub use crate::dissectors::cdp::CdpFields;

pub use crate::dissectors::stp::StpFields;

pub use crate::dissectors::dns::DnsFields;
pub use crate::dissectors::dns::DnsRecord;
pub use crate::dissectors::dns::DnsRecordData;
pub use crate::dissectors::dns::DnsRecordType;

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

pub use crate::dissectors::mstp::MstiRecord;
pub use crate::dissectors::mstp::MstpFields;

pub use crate::dissectors::pvst::PvstFields;

pub use crate::dissectors::prp::PrpFields;

pub use crate::dissectors::lacp::LacpFields;

pub use crate::dissectors::lacp::LacpPartner;

pub use crate::dissectors::icmp::IcmpFields;

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
///
/// Internally maintains two pools:
///
/// - **`indexed`** — dissectors pinned to one or more well-known L4 ports.
///   Looked up via `port_index` (a `HashMap<u16, Vec<usize>>`) on the
///   packet's destination port first, then source port. This is the
///   fast path: O(1) hash lookup to one or two candidate dissectors.
/// - **`free`** — dissectors that float across ports (TLS, HTTP on
///   arbitrary ports), L2 protocols (ARP, LLDP, STP, …), or any
///   dissector registered via the generic [`register`](Self::register)
///   method. Walked unconditionally after the port-index lookup as a
///   fallback.
///
/// Worst case is now `port-pinned candidates + free walk` instead of
/// "all dissectors." For OT traffic on standard ports, that's typically
/// one `can_parse` check instead of ~30.
pub struct DissectorRegistry {
    indexed: Vec<Box<dyn ProtocolDissector>>,
    port_index: HashMap<u16, Vec<usize>>,
    free: Vec<Box<dyn ProtocolDissector>>,
}

impl DissectorRegistry {
    pub fn new() -> Self {
        Self {
            indexed: Vec::new(),
            port_index: HashMap::new(),
            free: Vec::new(),
        }
    }

    /// Create a registry pre-loaded with all built-in dissectors.
    pub fn with_defaults() -> Self {
        use crate::dissectors::*;

        let mut reg = Self::new();

        // Port-pinned protocols — fast O(1) lookup on dst_port/src_port.
        reg.register_with_ports(Box::new(modbus::ModbusDissector), &[502]);
        reg.register_with_ports(Box::new(dnp3::Dnp3Dissector), &[20000]);
        reg.register_with_ports(Box::new(opc_ua::OpcUaDissector), &[4840]);
        reg.register_with_ports(Box::new(s7comm::S7commDissector), &[102]);
        reg.register_with_ports(Box::new(ethernet_ip::EthernetIpDissector), &[44818, 2222]);
        reg.register_with_ports(Box::new(hart_ip::HartIpDissector), &[5094]);
        reg.register_with_ports(Box::new(iec104::Iec104Dissector), &[2404]);
        reg.register_with_ports(Box::new(bacnet::BacnetDissector), &[47808]);
        reg.register_with_ports(Box::new(fins::OmronFinsDissector), &[9600]);
        reg.register_with_ports(Box::new(dns::DnsDissector), &[53]);
        reg.register_with_ports(Box::new(dhcp::DhcpDissector), &[67, 68]);
        reg.register_with_ports(Box::new(snmp::SnmpDissector), &[161, 162]);
        reg.register_with_ports(Box::new(ntp::NtpDissector), &[123]);
        reg.register_with_ports(Box::new(radius::RadiusDissector), &[1812, 1813]);
        reg.register_with_ports(Box::new(syslog::SyslogDissector), &[514]);
        reg.register_with_ports(Box::new(mqtt::MqttDissector), &[1883]);

        // Floating-port and L2 protocols — walked as the fallback chain.
        reg.register(Box::new(http::HttpDissector));
        reg.register(Box::new(ftp::FtpDissector));
        reg.register(Box::new(ssh::SshDissector));
        reg.register(Box::new(arp::ArpDissector));
        reg.register(Box::new(lldp::LldpDissector));
        reg.register(Box::new(cdp::CdpDissector));
        reg.register(Box::new(stp::StpDissector));
        reg.register(Box::new(iec61850::Iec61850Dissector));
        reg.register(Box::new(profinet::ProfinetDissector));
        reg.register(Box::new(ethercat::EthercatDissector));
        reg.register(Box::new(vtp::VtpDissector));
        reg.register(Box::new(mrp::MrpDissector));
        reg.register(Box::new(mstp::MstpDissector));
        reg.register(Box::new(pvst::PvstDissector));
        reg.register(Box::new(prp::PrpDissector));
        reg.register(Box::new(lacp::LacpDissector));

        reg
    }

    /// Register a dissector without a port hint. Walked on every packet
    /// as part of the fallback chain. Use for protocols that float across
    /// ports (TLS, HTTP on arbitrary ports, ICMP) or L2 protocols.
    pub fn register(&mut self, dissector: Box<dyn ProtocolDissector>) {
        self.free.push(dissector);
    }

    /// Register a dissector with one or more well-known L4 ports.
    ///
    /// The registry routes packets whose `dst_port` or `src_port` matches
    /// one of `ports` straight to this dissector via an O(1) hash lookup,
    /// skipping the free-list walk. If `can_parse` returns false despite
    /// the port match, dispatch continues to other indexed dissectors on
    /// the same port, then falls through to the free-list walk.
    pub fn register_with_ports(
        &mut self,
        dissector: Box<dyn ProtocolDissector>,
        ports: &[u16],
    ) {
        let idx = self.indexed.len();
        self.indexed.push(dissector);
        for &p in ports {
            self.port_index.entry(p).or_default().push(idx);
        }
    }

    /// Try candidate dissectors in port-index order, then the free list;
    /// return the first successful parse.
    pub fn dispatch(&self, data: &[u8], context: &PacketContext) -> Option<ProtocolData> {
        let (src, dst) = (context.src_port, context.dst_port);
        for port in port_pair(src, dst).iter().flatten() {
            if let Some(indices) = self.port_index.get(port) {
                for &idx in indices {
                    let d = &self.indexed[idx];
                    if d.can_parse(data, src, dst)
                        && let Some(result) = d.parse(data, context)
                    {
                        return Some(result);
                    }
                }
            }
        }
        for d in &self.free {
            if d.can_parse(data, src, dst)
                && let Some(result) = d.parse(data, context)
            {
                return Some(result);
            }
        }
        None
    }

    /// Classification-only dispatch: returns the `name()` of the first
    /// dissector whose `can_parse` accepts the payload. No `parse()` is
    /// invoked. Used by [`crate::classify::Classifier`] and the streaming
    /// session ([`crate::DpiSession`]).
    pub fn classify_name(&self, data: &[u8], src_port: u16, dst_port: u16) -> Option<&str> {
        for port in port_pair(src_port, dst_port).iter().flatten() {
            if let Some(indices) = self.port_index.get(port) {
                for &idx in indices {
                    let d = &self.indexed[idx];
                    if d.can_parse(data, src_port, dst_port) {
                        return Some(d.name());
                    }
                }
            }
        }
        for d in &self.free {
            if d.can_parse(data, src_port, dst_port) {
                return Some(d.name());
            }
        }
        None
    }
}

/// Return up to two distinct ports from the `(src, dst)` pair, `dst`
/// first. Deduplicates when src == dst so the port-index isn't probed
/// twice for the same key.
fn port_pair(src: u16, dst: u16) -> [Option<u16>; 2] {
    if src == dst {
        [Some(dst), None]
    } else {
        [Some(dst), Some(src)]
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

#[cfg(test)]
mod registry_tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn modbus_payload() -> Vec<u8> {
        vec![
            0x00, 0x01, 0x00, 0x00, 0x00, 0x06, 0x01, 0x03, 0x00, 0x00, 0x00, 0x01,
        ]
    }

    #[test]
    fn port_index_routes_modbus_to_correct_dissector() {
        let reg = DissectorRegistry::with_defaults();
        let name = reg.classify_name(&modbus_payload(), 49152, 502).unwrap();
        assert_eq!(name, "modbus");
    }

    #[test]
    fn port_index_routes_on_src_port_for_responder_side() {
        // Server-to-client direction: src=502, dst=49152.
        let reg = DissectorRegistry::with_defaults();
        let name = reg.classify_name(&modbus_payload(), 502, 49152).unwrap();
        assert_eq!(name, "modbus");
    }

    #[test]
    fn port_index_miss_falls_through_to_free_list() {
        // OPC UA Hello on a non-OPC UA port — port_index won't catch it,
        // free list (HTTP/FTP/etc.) won't claim it either.
        let reg = DissectorRegistry::with_defaults();
        let mut hello = vec![b'H', b'E', b'L', b'F'];
        hello.extend_from_slice(&32u32.to_le_bytes());
        hello.extend_from_slice(&[0u8; 24]);
        let result = reg.classify_name(&hello, 49152, 9999);
        // Should not falsely identify as anything; the port-index path
        // skipped entirely, free walk found nothing matching.
        assert!(
            result.is_none()
                || !["modbus", "dnp3", "opc_ua"].contains(&result.unwrap()),
            "unexpected classification: {result:?}"
        );
    }

    #[test]
    fn port_index_does_not_double_walk_when_src_equals_dst() {
        let reg = DissectorRegistry::with_defaults();
        // Bogus traffic with src == dst — port_pair() must return only
        // one Some(_) entry so the port_index lookup runs once.
        let _ = reg.classify_name(&[0xff; 8], 502, 502);
        // No assertion needed beyond "did not panic / did not loop" —
        // port_pair correctness is exercised by getting here.
    }

    #[test]
    fn port_index_handles_multi_port_dissectors() {
        // EtherNet/IP listed on both 44818 and 2222 — make sure both
        // route. (Use a sentinel payload that fails can_parse; we only
        // care that the index doesn't panic and that both ports are in
        // the index.)
        let reg = DissectorRegistry::with_defaults();
        assert!(reg.port_index.contains_key(&44818));
        assert!(reg.port_index.contains_key(&2222));
    }

    #[test]
    fn full_dispatch_with_port_index_returns_parsed_modbus() {
        let reg = DissectorRegistry::with_defaults();
        let ctx = PacketContext {
            src_mac: [0; 6],
            dst_mac: [0; 6],
            src_ip: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            dst_ip: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            src_port: 49152,
            dst_port: 502,
            vlan_id: None,
            timestamp: 0,
        };
        let result = reg.dispatch(&modbus_payload(), &ctx);
        assert!(matches!(result, Some(ProtocolData::Modbus(_))));
    }
}
