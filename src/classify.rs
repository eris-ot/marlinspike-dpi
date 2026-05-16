//! L7 protocol classification — magic-byte recognition without parsing.
//!
//! The classifier is a *lighter surface* than the full DPI engine: it returns
//! `Option<ProtocolId>` from the shared `fathom-contracts` enum, allocates
//! nothing, emits no Bronze events, and does no enrichment. It exists so
//! collectors can make per-protocol retention decisions at capture time
//! without dragging the full Iron→Bronze pipeline onto constrained hardware.
//!
//! The default implementation reuses the existing `DissectorRegistry`'s
//! `can_parse` checks and maps the dissector name back to a stable
//! `ProtocolId`. A future feature flag may expose a leaner classifier built
//! from extracted magic-byte rules only, but the default impl is correct by
//! construction since it shares its detection logic with the dissectors that
//! produce Bronze.

use fathom_contracts::{Classifier, ProtocolId};

use crate::registry::DissectorRegistry;

/// Default classifier that delegates to the full dissector registry's
/// `can_parse` checks. Correct by construction (shares logic with the
/// Bronze-producing dissectors) but pulls the full marlinspike-dpi crate.
///
/// For embedded collectors that only need classification, a leaner impl can
/// be added behind a feature flag in a follow-up.
pub struct RegistryClassifier {
    registry: DissectorRegistry,
}

impl RegistryClassifier {
    pub fn new() -> Self {
        Self {
            registry: DissectorRegistry::with_defaults(),
        }
    }

    pub fn from_registry(registry: DissectorRegistry) -> Self {
        Self { registry }
    }
}

impl Default for RegistryClassifier {
    fn default() -> Self {
        Self::new()
    }
}

impl Classifier for RegistryClassifier {
    fn classify(&self, payload: &[u8], src_port: u16, dst_port: u16) -> Option<ProtocolId> {
        let name = self.registry.classify_name(payload, src_port, dst_port)?;
        name_to_protocol_id(name)
    }
}

/// Map a dissector's `name()` string to a stable `ProtocolId`.
///
/// The mapping is exhaustive over current dissector names. Adding a new
/// dissector requires adding an arm here AND a variant in
/// `fathom_contracts::ProtocolId`.
pub fn name_to_protocol_id(name: &str) -> Option<ProtocolId> {
    Some(match name {
        "modbus" => ProtocolId::Modbus,
        "dnp3" => ProtocolId::Dnp3,
        "ethernet_ip" => ProtocolId::EthernetIp,
        "opc_ua" => ProtocolId::OpcUa,
        "s7comm" => ProtocolId::S7comm,
        "profinet" => ProtocolId::Profinet,
        "iec104" => ProtocolId::Iec104,
        "iec61850" => ProtocolId::Iec61850,
        "bacnet" => ProtocolId::Bacnet,
        "hart_ip" => ProtocolId::HartIp,
        "omron_fins" => ProtocolId::OmronFins,
        "ethercat" => ProtocolId::Ethercat,
        "mrp" => ProtocolId::Mrp,
        "prp" => ProtocolId::Prp,
        "http" => ProtocolId::Http,
        "ssh" => ProtocolId::Ssh,
        "ftp" => ProtocolId::Ftp,
        "dns" => ProtocolId::Dns,
        "dhcp" => ProtocolId::Dhcp,
        "ntp" => ProtocolId::Ntp,
        "snmp" => ProtocolId::Snmp,
        "syslog" => ProtocolId::Syslog,
        "mqtt" => ProtocolId::Mqtt,
        "radius" => ProtocolId::Radius,
        "arp" => ProtocolId::Arp,
        "lldp" => ProtocolId::Lldp,
        "cdp" => ProtocolId::Cdp,
        "stp" => ProtocolId::Stp,
        "pvst" => ProtocolId::Pvst,
        "lacp" => ProtocolId::Lacp,
        "vtp" => ProtocolId::Vtp,
        "mstp" => ProtocolId::Mstp,
        "icmp" => ProtocolId::Icmp,
        _ => return None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn modbus_request_classifies() {
        // Minimal MBAP-framed Read Holding Registers request.
        let payload = [
            0x00, 0x01, // transaction id
            0x00, 0x00, // protocol id (must be 0)
            0x00, 0x06, // length
            0x01, // unit id
            0x03, // FC: read holding registers
            0x00, 0x00, 0x00, 0x0A, // start addr, qty
        ];
        let c = RegistryClassifier::new();
        assert_eq!(c.classify(&payload, 12345, 502), Some(ProtocolId::Modbus),);
    }

    #[test]
    fn unknown_payload_returns_none() {
        let c = RegistryClassifier::new();
        assert_eq!(c.classify(b"random garbage", 1234, 5678), None);
    }
}
