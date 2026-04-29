use serde::{Deserialize, Serialize};

/// Stable protocol identifier shared across classifier, dissectors, retention
/// policy, and operator-facing config.
///
/// Variants are added but never reordered or renamed: the string form is part
/// of the public config contract (collector retention rules reference these
/// names verbatim).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProtocolId {
    // ── L7 ICS / OT ─────────────────────────────────────────────────────
    Modbus,
    Dnp3,
    EthernetIp,
    OpcUa,
    S7comm,
    Profinet,
    Iec104,
    Iec61850,
    Bacnet,
    HartIp,
    OmronFins,
    Ethercat,
    Mrp,
    Prp,

    // ── L7 IT ──────────────────────────────────────────────────────────
    Http,
    Tls,
    Ssh,
    Ftp,
    Dns,
    Mdns,
    Dhcp,
    Ntp,
    Snmp,
    Syslog,
    Mqtt,
    Radius,

    // ── L2 / management ────────────────────────────────────────────────
    Arp,
    Lldp,
    Cdp,
    Stp,
    Pvst,
    Lacp,
    Vtp,
    Mstp,
    Icmp,

    // ── Catch-all ──────────────────────────────────────────────────────
    Unknown,
}

impl ProtocolId {
    /// Stable snake_case name, identical to the serde representation.
    /// Use for config keys, log fields, and metric labels.
    pub fn as_str(self) -> &'static str {
        match self {
            ProtocolId::Modbus => "modbus",
            ProtocolId::Dnp3 => "dnp3",
            ProtocolId::EthernetIp => "ethernet_ip",
            ProtocolId::OpcUa => "opc_ua",
            ProtocolId::S7comm => "s7comm",
            ProtocolId::Profinet => "profinet",
            ProtocolId::Iec104 => "iec104",
            ProtocolId::Iec61850 => "iec61850",
            ProtocolId::Bacnet => "bacnet",
            ProtocolId::HartIp => "hart_ip",
            ProtocolId::OmronFins => "omron_fins",
            ProtocolId::Ethercat => "ethercat",
            ProtocolId::Mrp => "mrp",
            ProtocolId::Prp => "prp",
            ProtocolId::Http => "http",
            ProtocolId::Tls => "tls",
            ProtocolId::Ssh => "ssh",
            ProtocolId::Ftp => "ftp",
            ProtocolId::Dns => "dns",
            ProtocolId::Mdns => "mdns",
            ProtocolId::Dhcp => "dhcp",
            ProtocolId::Ntp => "ntp",
            ProtocolId::Snmp => "snmp",
            ProtocolId::Syslog => "syslog",
            ProtocolId::Mqtt => "mqtt",
            ProtocolId::Radius => "radius",
            ProtocolId::Arp => "arp",
            ProtocolId::Lldp => "lldp",
            ProtocolId::Cdp => "cdp",
            ProtocolId::Stp => "stp",
            ProtocolId::Pvst => "pvst",
            ProtocolId::Lacp => "lacp",
            ProtocolId::Vtp => "vtp",
            ProtocolId::Mstp => "mstp",
            ProtocolId::Icmp => "icmp",
            ProtocolId::Unknown => "unknown",
        }
    }
}

impl std::fmt::Display for ProtocolId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn as_str_matches_serde() {
        let id = ProtocolId::EthernetIp;
        let json = serde_json::to_string(&id).unwrap();
        assert_eq!(json, "\"ethernet_ip\"");
        assert_eq!(id.as_str(), "ethernet_ip");
    }
}
