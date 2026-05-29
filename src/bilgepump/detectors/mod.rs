//! Individual L2 anomaly detectors.

#[cfg(feature = "arp")]
pub mod arp;
#[cfg(feature = "dhcp")]
pub mod dhcp;
#[cfg(any(feature = "lldp", feature = "cdp"))]
pub mod identity;
pub mod mac;
#[cfg(feature = "stp")]
pub mod stp;
pub mod vlan;
