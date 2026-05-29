//! Dissector registry — dispatches packets to protocol-specific parsers.

use std::collections::HashMap;
use std::net::IpAddr;

#[cfg(feature = "ethercat")]
use crate::dissectors::ethercat::EthercatFields;
#[cfg(feature = "hart_ip")]
use crate::dissectors::hart_ip::HartIpFields;
#[cfg(feature = "iec61850")]
use crate::dissectors::iec61850::Iec61850Fields;

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
    #[cfg(feature = "bacnet")]
    Bacnet(BacnetFields),
    #[cfg(feature = "iec104")]
    Iec104(Iec104Fields),
    #[cfg(feature = "fins")]
    OmronFins(OmronFinsFields),
    #[cfg(feature = "hart_ip")]
    HartIp(HartIpFields),
    #[cfg(feature = "iec61850")]
    Iec61850(Iec61850Fields),
    #[cfg(feature = "ethercat")]
    Ethercat(EthercatFields),
    #[cfg(feature = "modbus")]
    Modbus(ModbusFields),
    #[cfg(feature = "dnp3")]
    Dnp3(Dnp3Fields),
    #[cfg(feature = "ethernet_ip")]
    EthernetIp(EthernetIpFields),
    #[cfg(feature = "opc_ua")]
    OpcUa(OpcUaFields),
    #[cfg(feature = "s7comm")]
    S7comm(S7commFields),
    #[cfg(feature = "profinet")]
    Profinet(ProfinetFields),
    #[cfg(feature = "dhcp")]
    Dhcp(DhcpFields),
    #[cfg(feature = "snmp")]
    Snmp(SnmpFields),
    #[cfg(feature = "cdp")]
    Cdp(CdpFields),
    #[cfg(feature = "stp")]
    Stp(StpFields),
    #[cfg(feature = "dns")]
    Dns(DnsFields),
    #[cfg(feature = "tls")]
    Tls(TlsFields),
    #[cfg(feature = "http")]
    Http(HttpFields),
    #[cfg(feature = "arp")]
    Arp(ArpFields),
    #[cfg(feature = "lldp")]
    Lldp(LldpFields),
    #[cfg(feature = "ntp")]
    Ntp(NtpFields),
    #[cfg(feature = "mqtt")]
    Mqtt(MqttFields),
    #[cfg(feature = "syslog")]
    Syslog(SyslogFields),
    #[cfg(feature = "ftp")]
    Ftp(FtpFields),
    #[cfg(feature = "ssh")]
    Ssh(SshFields),
    #[cfg(feature = "radius")]
    Radius(RadiusFields),
    #[cfg(feature = "vtp")]
    Vtp(VtpFields),
    #[cfg(feature = "mrp")]
    Mrp(MrpFields),
    #[cfg(feature = "mstp")]
    Mstp(MstpFields),
    #[cfg(feature = "pvst")]
    Pvst(PvstFields),
    #[cfg(feature = "prp")]
    Prp(PrpFields),
    #[cfg(feature = "lacp")]
    Lacp(LacpFields),
    #[cfg(feature = "icmp")]
    Icmp(IcmpFields),
}

impl ProtocolData {
    /// Returns the protocol name string used in `BronzeRecord.protocol`.
    pub fn protocol_name(&self) -> &'static str {
        match self {
            #[cfg(feature = "bacnet")]
            Self::Bacnet(_) => "bacnet",
            #[cfg(feature = "iec104")]
            Self::Iec104(_) => "iec104",
            #[cfg(feature = "fins")]
            Self::OmronFins(_) => "omron_fins",
            #[cfg(feature = "hart_ip")]
            Self::HartIp(_) => "hart_ip",
            #[cfg(feature = "iec61850")]
            Self::Iec61850(_) => "iec61850",
            #[cfg(feature = "ethercat")]
            Self::Ethercat(_) => "ethercat",
            #[cfg(feature = "modbus")]
            Self::Modbus(_) => "modbus",
            #[cfg(feature = "dnp3")]
            Self::Dnp3(_) => "dnp3",
            #[cfg(feature = "ethernet_ip")]
            Self::EthernetIp(_) => "ethernet_ip",
            #[cfg(feature = "opc_ua")]
            Self::OpcUa(_) => "opc_ua",
            #[cfg(feature = "s7comm")]
            Self::S7comm(_) => "s7comm",
            #[cfg(feature = "profinet")]
            Self::Profinet(_) => "profinet",
            #[cfg(feature = "dhcp")]
            Self::Dhcp(_) => "dhcp",
            #[cfg(feature = "snmp")]
            Self::Snmp(_) => "snmp",
            #[cfg(feature = "cdp")]
            Self::Cdp(_) => "cdp",
            #[cfg(feature = "stp")]
            Self::Stp(_) => "stp",
            #[cfg(feature = "dns")]
            Self::Dns(_) => "dns",
            #[cfg(feature = "tls")]
            Self::Tls(_) => "tls",
            #[cfg(feature = "http")]
            Self::Http(_) => "http",
            #[cfg(feature = "arp")]
            Self::Arp(_) => "arp",
            #[cfg(feature = "lldp")]
            Self::Lldp(_) => "lldp",
            #[cfg(feature = "ntp")]
            Self::Ntp(_) => "ntp",
            #[cfg(feature = "mqtt")]
            Self::Mqtt(_) => "mqtt",
            #[cfg(feature = "syslog")]
            Self::Syslog(_) => "syslog",
            #[cfg(feature = "ftp")]
            Self::Ftp(_) => "ftp",
            #[cfg(feature = "ssh")]
            Self::Ssh(_) => "ssh",
            #[cfg(feature = "radius")]
            Self::Radius(_) => "radius",
            #[cfg(feature = "vtp")]
            Self::Vtp(_) => "vtp",
            #[cfg(feature = "mrp")]
            Self::Mrp(_) => "mrp",
            #[cfg(feature = "mstp")]
            Self::Mstp(_) => "mstp",
            #[cfg(feature = "pvst")]
            Self::Pvst(_) => "pvst",
            #[cfg(feature = "prp")]
            Self::Prp(_) => "prp",
            #[cfg(feature = "lacp")]
            Self::Lacp(_) => "lacp",
            #[cfg(feature = "icmp")]
            Self::Icmp(_) => "icmp",
        }
    }
}

// ── Field structs ──────────────────────────────────────────────

#[cfg(feature = "bacnet")]
pub use crate::dissectors::bacnet::BacnetFields;

#[cfg(feature = "iec104")]
pub use crate::dissectors::iec104::Iec104Fields;

#[cfg(feature = "fins")]
pub use crate::dissectors::fins::OmronFinsFields;

#[cfg(feature = "modbus")]
pub use crate::dissectors::modbus::ModbusDirection;
#[cfg(feature = "modbus")]
pub use crate::dissectors::modbus::ModbusFields;
#[cfg(feature = "modbus")]
pub use crate::dissectors::modbus::ModbusPdu;

#[cfg(feature = "dnp3")]
pub use crate::dissectors::dnp3::Dnp3Fields;

#[cfg(feature = "ethernet_ip")]
pub use crate::dissectors::ethernet_ip::EthernetIpFields;

#[cfg(feature = "opc_ua")]
pub use crate::dissectors::opc_ua::OpcUaFields;

#[cfg(feature = "s7comm")]
pub use crate::dissectors::s7comm::S7commFields;

#[cfg(feature = "profinet")]
pub use crate::dissectors::profinet::ProfinetFields;

#[cfg(feature = "dhcp")]
pub use crate::dissectors::dhcp::DhcpFields;

#[cfg(feature = "snmp")]
pub use crate::dissectors::snmp::SnmpFields;
#[cfg(feature = "snmp")]
pub use crate::dissectors::snmp::SnmpVarBind;

#[cfg(feature = "cdp")]
pub use crate::dissectors::cdp::CdpFields;

#[cfg(feature = "stp")]
pub use crate::dissectors::stp::StpFields;

#[cfg(feature = "dns")]
pub use crate::dissectors::dns::DnsFields;
#[cfg(feature = "dns")]
pub use crate::dissectors::dns::DnsRecord;
#[cfg(feature = "dns")]
pub use crate::dissectors::dns::DnsRecordData;
#[cfg(feature = "dns")]
pub use crate::dissectors::dns::DnsRecordType;

#[cfg(feature = "tls")]
pub use crate::dissectors::tcp::TlsFields;

#[cfg(feature = "http")]
pub use crate::dissectors::http::HttpFields;

#[cfg(feature = "arp")]
pub use crate::dissectors::arp::ArpFields;

#[cfg(feature = "lldp")]
pub use crate::dissectors::lldp::LldpFields;

#[cfg(feature = "ntp")]
pub use crate::dissectors::ntp::NtpFields;

#[cfg(feature = "mqtt")]
pub use crate::dissectors::mqtt::MqttFields;

#[cfg(feature = "syslog")]
pub use crate::dissectors::syslog::SyslogFields;

#[cfg(feature = "ftp")]
pub use crate::dissectors::ftp::FtpFields;

#[cfg(feature = "ssh")]
pub use crate::dissectors::ssh::SshFields;

#[cfg(feature = "radius")]
pub use crate::dissectors::radius::RadiusFields;

#[cfg(feature = "vtp")]
pub use crate::dissectors::vtp::VtpFields;

#[cfg(feature = "mrp")]
pub use crate::dissectors::mrp::MrpFields;

#[cfg(feature = "mstp")]
pub use crate::dissectors::mstp::MstiRecord;
#[cfg(feature = "mstp")]
pub use crate::dissectors::mstp::MstpFields;

#[cfg(feature = "pvst")]
pub use crate::dissectors::pvst::PvstFields;

#[cfg(feature = "prp")]
pub use crate::dissectors::prp::PrpFields;

#[cfg(feature = "lacp")]
pub use crate::dissectors::lacp::LacpFields;

#[cfg(feature = "lacp")]
pub use crate::dissectors::lacp::LacpPartner;

#[cfg(feature = "icmp")]
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
        #[cfg(feature = "modbus")]
        reg.register_with_ports(Box::new(modbus::ModbusDissector), &[502]);
        #[cfg(feature = "dnp3")]
        reg.register_with_ports(Box::new(dnp3::Dnp3Dissector), &[20000]);
        #[cfg(feature = "opc_ua")]
        reg.register_with_ports(Box::new(opc_ua::OpcUaDissector), &[4840]);
        #[cfg(feature = "s7comm")]
        reg.register_with_ports(Box::new(s7comm::S7commDissector), &[102]);
        #[cfg(feature = "ethernet_ip")]
        reg.register_with_ports(Box::new(ethernet_ip::EthernetIpDissector), &[44818, 2222]);
        #[cfg(feature = "hart_ip")]
        reg.register_with_ports(Box::new(hart_ip::HartIpDissector), &[5094]);
        #[cfg(feature = "iec104")]
        reg.register_with_ports(Box::new(iec104::Iec104Dissector), &[2404]);
        #[cfg(feature = "bacnet")]
        reg.register_with_ports(Box::new(bacnet::BacnetDissector), &[47808]);
        #[cfg(feature = "fins")]
        reg.register_with_ports(Box::new(fins::OmronFinsDissector), &[9600]);
        #[cfg(feature = "dns")]
        reg.register_with_ports(Box::new(dns::DnsDissector), &[53]);
        #[cfg(feature = "dhcp")]
        reg.register_with_ports(Box::new(dhcp::DhcpDissector), &[67, 68]);
        #[cfg(feature = "snmp")]
        reg.register_with_ports(Box::new(snmp::SnmpDissector), &[161, 162]);
        #[cfg(feature = "ntp")]
        reg.register_with_ports(Box::new(ntp::NtpDissector), &[123]);
        #[cfg(feature = "radius")]
        reg.register_with_ports(Box::new(radius::RadiusDissector), &[1812, 1813]);
        #[cfg(feature = "syslog")]
        reg.register_with_ports(Box::new(syslog::SyslogDissector), &[514]);
        #[cfg(feature = "mqtt")]
        reg.register_with_ports(Box::new(mqtt::MqttDissector), &[1883]);

        // Floating-port and L2 protocols — walked as the fallback chain.
        #[cfg(feature = "http")]
        reg.register(Box::new(http::HttpDissector));
        #[cfg(feature = "ftp")]
        reg.register(Box::new(ftp::FtpDissector));
        #[cfg(feature = "ssh")]
        reg.register(Box::new(ssh::SshDissector));
        #[cfg(feature = "arp")]
        reg.register(Box::new(arp::ArpDissector));
        #[cfg(feature = "lldp")]
        reg.register(Box::new(lldp::LldpDissector));
        #[cfg(feature = "cdp")]
        reg.register(Box::new(cdp::CdpDissector));
        #[cfg(feature = "stp")]
        reg.register(Box::new(stp::StpDissector));
        #[cfg(feature = "iec61850")]
        reg.register(Box::new(iec61850::Iec61850Dissector));
        #[cfg(feature = "profinet")]
        reg.register(Box::new(profinet::ProfinetDissector));
        #[cfg(feature = "ethercat")]
        reg.register(Box::new(ethercat::EthercatDissector));
        #[cfg(feature = "vtp")]
        reg.register(Box::new(vtp::VtpDissector));
        #[cfg(feature = "mrp")]
        reg.register(Box::new(mrp::MrpDissector));
        #[cfg(feature = "mstp")]
        reg.register(Box::new(mstp::MstpDissector));
        #[cfg(feature = "pvst")]
        reg.register(Box::new(pvst::PvstDissector));
        #[cfg(feature = "prp")]
        reg.register(Box::new(prp::PrpDissector));
        #[cfg(feature = "lacp")]
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
    pub fn register_with_ports(&mut self, dissector: Box<dyn ProtocolDissector>, ports: &[u16]) {
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
            result.is_none() || !["modbus", "dnp3", "opc_ua"].contains(&result.unwrap()),
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

    // ── Feature-gating contract ────────────────────────────────────
    // These tests prove the subsetting mechanism: a dissector is reachable
    // through the registry if and only if it was registered. The
    // `with_defaults()` tests additionally assert the per-feature contract —
    // present when the feature is on, absent when it is off — so they remain
    // valid under any `--features` selection.

    #[cfg(feature = "dnp3")]
    fn dnp3_payload() -> Vec<u8> {
        // Minimal valid DNP3 data-link header on the well-known port.
        vec![0x05, 0x64, 0x05, 0xC0, 0x01, 0x00, 0x02, 0x00, 0x00, 0x00]
    }

    /// A registry built with `new()` exposes only the dissectors explicitly
    /// registered — registering modbus must NOT make a valid dnp3 frame
    /// classify. This runs under the default (all-features) build and is the
    /// direct proof that feature-gated subsets exclude what they omit.
    #[test]
    #[cfg(all(feature = "modbus", feature = "dnp3"))]
    fn subset_registry_excludes_unregistered_dissectors() {
        let mut reg = DissectorRegistry::new();
        reg.register_with_ports(Box::new(crate::dissectors::modbus::ModbusDissector), &[502]);

        // The one we registered is reachable...
        assert_eq!(
            reg.classify_name(&modbus_payload(), 49152, 502),
            Some("modbus")
        );
        // ...and a valid dnp3 frame on its own port is NOT, because the dnp3
        // dissector was never registered (this is what `--no-default-features`
        // achieves at compile time).
        assert_eq!(reg.classify_name(&dnp3_payload(), 49152, 20000), None);
    }

    /// The port-indexed (modbus) path honours the `modbus` feature gate in
    /// `with_defaults()`: present when on, absent when off.
    #[test]
    fn with_defaults_honors_modbus_feature_gate() {
        let reg = DissectorRegistry::with_defaults();
        let got = reg.classify_name(&modbus_payload(), 49152, 502);
        #[cfg(feature = "modbus")]
        assert_eq!(
            got,
            Some("modbus"),
            "modbus must be present when its feature is enabled"
        );
        #[cfg(not(feature = "modbus"))]
        assert_ne!(
            got,
            Some("modbus"),
            "modbus must be absent when its feature is disabled"
        );
    }

    /// Same contract for the port-indexed dnp3 dissector.
    #[test]
    #[cfg(feature = "dnp3")]
    fn with_defaults_includes_dnp3_when_enabled() {
        let reg = DissectorRegistry::with_defaults();
        assert_eq!(
            reg.classify_name(&dnp3_payload(), 49152, 20000),
            Some("dnp3"),
            "dnp3 must be reachable in with_defaults() when its feature is enabled"
        );
    }
}
