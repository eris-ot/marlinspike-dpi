//! Layer-2 / link-layer `SessionDecoder` impls.
//!
//! Members: ARP, LLDP, CDP, STP, RSTP, MSTP, PVST+, LACP, PRP, MRP, VTP.
//! Each is a small, mostly-self-contained decoder; they're grouped here
//! because they share the L2 frame surface and have minimal interaction
//! beyond emitting AssetObservation + TopologyObservation events.

#[cfg(feature = "arp")]
pub(crate) mod arp;
#[cfg(feature = "cdp")]
pub(crate) mod cdp;
#[cfg(feature = "lacp")]
pub(crate) mod lacp;
#[cfg(feature = "lldp")]
pub(crate) mod lldp;
#[cfg(feature = "mrp")]
pub(crate) mod mrp;
#[cfg(feature = "mstp")]
pub(crate) mod mstp;
#[cfg(feature = "prp")]
pub(crate) mod prp;
#[cfg(feature = "pvst")]
pub(crate) mod pvst;
#[cfg(feature = "stp")]
pub(crate) mod stp;
#[cfg(feature = "vtp")]
pub(crate) mod vtp;
