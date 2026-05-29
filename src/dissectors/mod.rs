//! Protocol dissector implementations.
//!
//! Each protocol module is gated behind its per-protocol Cargo feature so
//! that `--no-default-features --features "..."` compiles only the selected
//! dissectors. `tcp` and `udp` are L4 infrastructure used throughout the
//! engine and are always compiled.

#[cfg(feature = "arp")]
pub mod arp;
#[cfg(feature = "bacnet")]
pub mod bacnet;
#[cfg(feature = "cdp")]
pub mod cdp;
#[cfg(feature = "dhcp")]
pub mod dhcp;
#[cfg(feature = "dns")]
pub mod dns;
#[cfg(feature = "ethercat")]
pub mod ethercat;
#[cfg(feature = "ftp")]
pub mod ftp;
#[cfg(feature = "hart_ip")]
pub mod hart_ip;
#[cfg(feature = "http")]
pub mod http;
#[cfg(feature = "iec104")]
pub mod iec104;
#[cfg(feature = "iec61850")]
pub mod iec61850;
#[cfg(feature = "lacp")]
pub mod lacp;
#[cfg(feature = "lldp")]
pub mod lldp;
#[cfg(feature = "modbus")]
pub mod modbus;
#[cfg(feature = "mqtt")]
pub mod mqtt;
#[cfg(feature = "mrp")]
pub mod mrp;
#[cfg(feature = "mstp")]
pub mod mstp;
#[cfg(feature = "ntp")]
pub mod ntp;
#[cfg(feature = "prp")]
pub mod prp;
#[cfg(feature = "pvst")]
pub mod pvst;
#[cfg(feature = "radius")]
pub mod radius;
#[cfg(feature = "snmp")]
pub mod snmp;
#[cfg(feature = "ssh")]
pub mod ssh;
#[cfg(feature = "stp")]
pub mod stp;
#[cfg(feature = "syslog")]
pub mod syslog;

// L4 infrastructure — always compiled. `tcp` also hosts `TlsFields`.
pub mod tcp;
pub mod udp;

#[cfg(feature = "vtp")]
pub mod vtp;

#[cfg(feature = "icmp")]
pub mod icmp;

// OT protocol dissectors
#[cfg(feature = "dnp3")]
pub mod dnp3;
#[cfg(feature = "ethernet_ip")]
pub mod ethernet_ip;
#[cfg(feature = "fins")]
pub mod fins;
#[cfg(feature = "opc_ua")]
pub mod opc_ua;
#[cfg(feature = "profinet")]
pub mod profinet;
#[cfg(feature = "s7comm")]
pub mod s7comm;
