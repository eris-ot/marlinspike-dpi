use crate::ProtocolId;

/// Trait for L4-payload protocol classification.
///
/// A `Classifier` answers the question "what protocol is this packet?"
/// without parsing payloads or producing Bronze events. Collectors use it
/// to make per-protocol retention decisions at capture time; appliances
/// use it to dispatch packets to dissectors.
///
/// Implementations must be allocation-free in the hot path and side-effect
/// free: a classifier is allowed to be called on every packet a collector
/// captures. They must also be `Send + Sync` so capture sessions can hold
/// them behind shared references across threads.
pub trait Classifier: Send + Sync {
    /// Identify the application-layer protocol carried by `payload`.
    ///
    /// `src_port` / `dst_port` are the L4 ports (TCP or UDP). For protocols
    /// that don't ride on TCP/UDP (ARP, LLDP, STP, ...) callers pass `0` for
    /// both ports.
    fn classify(&self, payload: &[u8], src_port: u16, dst_port: u16) -> Option<ProtocolId>;
}
