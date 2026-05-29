//! Streaming per-packet DPI session for inline consumers.
//!
//! The batch engine ([`crate::DpiEngine`]) consumes a whole pcap and emits
//! Bronze events. Inline consumers — firewall divert sockets, Linux
//! `nfqueue`, DPDK applications — can't wait for end-of-capture. They hold
//! one IP packet and need a classification decision *now* so they can
//! reinject (or hand off to a policy layer) without adding latency.
//!
//! [`DpiSession`] is that path. It wraps the same [`DissectorRegistry`] the
//! batch engine uses, so any protocol the engine can identify in a pcap can
//! be identified inline.
//!
//! # Boundary of responsibility
//!
//! This module **classifies**. It does not enforce policy. Allow/drop
//! decisions belong to the consumer (the firewall, the IDS rule engine,
//! whatever sits above the transport). `DpiSession` answers "what is this
//! flow?" — the caller answers "what should I do about it?"
//!
//! # Usage
//!
//! ```no_run
//! use std::net::{IpAddr, Ipv4Addr};
//! use std::time::Duration;
//! use fm_dpi::{Classification, DpiSession, FlowKey};
//!
//! let mut session = DpiSession::new();
//! let flow = FlowKey {
//!     src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
//!     dst_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
//!     src_port: 49152,
//!     dst_port: 502,
//!     l4_proto: 6,
//! };
//! let ip_packet: &[u8] = &[/* raw IPv4 datagram from divert socket */];
//! match session.feed(flow, ip_packet, Duration::from_micros(100)) {
//!     Classification::NeedMore => { /* reinject, keep diverting */ }
//!     Classification::Classified(tag) => { /* reinject, stop diverting */ }
//!     Classification::Unknown => { /* reinject, stop diverting */ }
//! }
//! ```

use std::collections::HashMap;
use std::net::IpAddr;
use std::time::Duration;

use crate::registry::{DissectorRegistry, PacketContext};

/// 5-tuple identifying a flow. The caller extracts this from the diverted
/// packet (or whatever transport surface) and is responsible for passing
/// both directions of the same conversation with consistent key shape.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct FlowKey {
    pub src_ip: IpAddr,
    pub dst_ip: IpAddr,
    pub src_port: u16,
    pub dst_port: u16,
    /// IANA L4 protocol number (6 = TCP, 17 = UDP, 1 = ICMP, …).
    pub l4_proto: u8,
}

/// Outcome of feeding a packet to [`DpiSession::feed`].
#[derive(Debug, Clone)]
pub enum Classification {
    /// Engine has not classified the flow yet. Feed more packets.
    NeedMore,
    /// Protocol identified. The caller MAY now stop diverting this flow to
    /// avoid per-packet syscall cost on the kernel side.
    Classified(FlowTag),
    /// Engine examined `max_classify_attempts` packets and could not
    /// classify. The caller SHOULD stop diverting — no useful classification
    /// is coming.
    Unknown,
}

/// Identification result attached to a classified flow.
#[derive(Debug, Clone)]
pub struct FlowTag {
    /// Dissector name (e.g. `"modbus"`, `"opc_ua"`, `"dnp3"`).
    pub protocol: String,
}

/// Tunables for [`DpiSession`].
#[derive(Debug, Clone)]
pub struct DpiSessionConfig {
    /// Packets to attempt classification on before declaring the flow
    /// [`Classification::Unknown`]. Most protocols identify on the first
    /// L7 packet; a handful (TLS over non-443, certain handshakes) need a
    /// few. 16 is a generous default.
    pub max_classify_attempts: u32,

    /// Hard cap on tracked flow count. When hit, the least-recently-used
    /// entry is evicted to make room for a new flow.
    pub max_flows: usize,
}

impl Default for DpiSessionConfig {
    fn default() -> Self {
        Self {
            max_classify_attempts: 16,
            max_flows: 65_536,
        }
    }
}

#[derive(Debug)]
struct FlowState {
    attempts: u32,
    classification: Option<FlowTag>,
    /// Monotonic tick at last `feed` call. Used by LRU eviction.
    last_seen: u64,
}

/// Per-process streaming DPI session.
///
/// Not internally synchronized. Wrap in a `Mutex` if shared across threads,
/// or shard by flow hash if you want lock-free parallelism.
pub struct DpiSession {
    registry: DissectorRegistry,
    flows: HashMap<FlowKey, FlowState>,
    config: DpiSessionConfig,
    tick: u64,
}

impl DpiSession {
    /// Build a session with the default dissector registry and config.
    pub fn new() -> Self {
        Self::with_config(DpiSessionConfig::default())
    }

    pub fn with_config(config: DpiSessionConfig) -> Self {
        Self {
            registry: DissectorRegistry::with_defaults(),
            flows: HashMap::new(),
            config,
            tick: 0,
        }
    }

    /// Number of flows currently tracked. Useful for sizing alerts.
    pub fn flow_count(&self) -> usize {
        self.flows.len()
    }

    /// Feed one IPv4/IPv6 datagram and get a [`Classification`].
    ///
    /// `ip_packet` is a raw IP packet — the kind a FreeBSD `divert(4)`
    /// socket or Linux `nfqueue` hands you. The session strips L3 + L4
    /// headers and dispatches the payload through the dissector registry.
    ///
    /// `_budget` is reserved for future async deferral. Today classification
    /// is a single registry walk, well under any sane budget.
    pub fn feed(&mut self, flow: FlowKey, ip_packet: &[u8], _budget: Duration) -> Classification {
        self.tick = self.tick.wrapping_add(1);
        let tick = self.tick;

        // Fast path: classification already cached.
        if let Some(state) = self.flows.get_mut(&flow) {
            state.last_seen = tick;
            if let Some(tag) = state.classification.as_ref() {
                return Classification::Classified(tag.clone());
            }
            if state.attempts >= self.config.max_classify_attempts {
                return Classification::Unknown;
            }
        }

        let Some((payload, src_port, dst_port)) = extract_l4_payload(ip_packet) else {
            let state = self.touch_flow(flow, tick);
            state.attempts = state.attempts.saturating_add(1);
            return Classification::NeedMore;
        };

        // PacketContext mirrors the batch engine's, but with L2 fields
        // zeroed (divert strips Ethernet). Dissectors that depend on MACs
        // are L2-only (ARP/LLDP/CDP/STP) and don't appear on divert anyway.
        let _context = PacketContext {
            src_mac: [0u8; 6],
            dst_mac: [0u8; 6],
            src_ip: flow.src_ip,
            dst_ip: flow.dst_ip,
            src_port,
            dst_port,
            vlan_id: None,
            timestamp: 0,
        };

        // Resolve classification name into an owned String to release the
        // immutable borrow on `self.registry` before touching `self.flows`.
        let name = self
            .registry
            .classify_name(payload, src_port, dst_port)
            .map(str::to_owned);

        let state = self.touch_flow(flow, tick);
        if let Some(name) = name {
            let tag = FlowTag { protocol: name };
            state.classification = Some(tag.clone());
            return Classification::Classified(tag);
        }

        state.attempts = state.attempts.saturating_add(1);
        if state.attempts >= self.config.max_classify_attempts {
            Classification::Unknown
        } else {
            Classification::NeedMore
        }
    }

    /// Get-or-create a `FlowState`, evicting the LRU entry when at capacity.
    fn touch_flow(&mut self, flow: FlowKey, tick: u64) -> &mut FlowState {
        if !self.flows.contains_key(&flow) && self.flows.len() >= self.config.max_flows {
            self.evict_lru();
        }
        let state = self.flows.entry(flow).or_insert(FlowState {
            attempts: 0,
            classification: None,
            last_seen: tick,
        });
        state.last_seen = tick;
        state
    }

    fn evict_lru(&mut self) {
        if let Some(oldest) = self
            .flows
            .iter()
            .min_by_key(|(_, s)| s.last_seen)
            .map(|(k, _)| *k)
        {
            self.flows.remove(&oldest);
        }
    }
}

impl Default for DpiSession {
    fn default() -> Self {
        Self::new()
    }
}

/// Strip IPv4/IPv6 + TCP/UDP headers from a raw IP packet and return the
/// L7 payload plus the source/destination ports. Returns `None` for
/// non-IP, fragmented, encrypted (AH/ESP), or truncated packets.
fn extract_l4_payload(ip_packet: &[u8]) -> Option<(&[u8], u16, u16)> {
    if ip_packet.is_empty() {
        return None;
    }
    match ip_packet[0] >> 4 {
        4 => extract_l4_payload_v4(ip_packet),
        6 => extract_l4_payload_v6(ip_packet),
        _ => None,
    }
}

fn extract_l4_payload_v4(pkt: &[u8]) -> Option<(&[u8], u16, u16)> {
    if pkt.len() < 20 {
        return None;
    }
    let ihl = (pkt[0] & 0x0f) as usize * 4;
    if ihl < 20 || pkt.len() < ihl {
        return None;
    }
    // MF bit or non-zero fragment offset → later fragment, no L4 header.
    let frag = u16::from_be_bytes([pkt[6], pkt[7]]);
    if frag & 0x1fff != 0 {
        return None;
    }
    let proto = pkt[9];
    parse_l4_ports(&pkt[ihl..], proto)
}

fn extract_l4_payload_v6(pkt: &[u8]) -> Option<(&[u8], u16, u16)> {
    if pkt.len() < 40 {
        return None;
    }
    let mut next_hdr = pkt[6];
    let mut offset = 40usize;

    // Walk a bounded chain of extension headers. Anything deeper than this
    // is almost certainly evasion and not worth chasing inline.
    for _ in 0..8 {
        match next_hdr {
            // Hop-by-Hop (0), Routing (43), Destination Options (60) share
            // a length format: byte 0 = next header, byte 1 = (len in
            // 8-octet units, not counting the first 8).
            0 | 43 | 60 => {
                if pkt.len() < offset + 2 {
                    return None;
                }
                let nh = pkt[offset];
                let len = (pkt[offset + 1] as usize + 1) * 8;
                offset = offset.checked_add(len)?;
                if pkt.len() < offset {
                    return None;
                }
                next_hdr = nh;
            }
            // Fragment (44), ESP (50), AH (51) — bail. Fragment needs
            // reassembly state we don't carry inline; AH/ESP are encrypted
            // or authenticated and we can't see the L7 payload anyway.
            44 | 50 | 51 => return None,
            // TCP / UDP — done with extension headers.
            6 | 17 => return parse_l4_ports(&pkt[offset..], next_hdr),
            // Anything else (ICMPv6, SCTP, ...): no L7 surface our
            // dissectors expect via divert.
            _ => return None,
        }
    }
    None
}

fn parse_l4_ports(l4: &[u8], proto: u8) -> Option<(&[u8], u16, u16)> {
    match proto {
        // TCP
        6 => {
            if l4.len() < 20 {
                return None;
            }
            let src_port = u16::from_be_bytes([l4[0], l4[1]]);
            let dst_port = u16::from_be_bytes([l4[2], l4[3]]);
            let data_off = (l4[12] >> 4) as usize * 4;
            if data_off < 20 || l4.len() < data_off {
                return None;
            }
            Some((&l4[data_off..], src_port, dst_port))
        }
        // UDP
        17 => {
            if l4.len() < 8 {
                return None;
            }
            let src_port = u16::from_be_bytes([l4[0], l4[1]]);
            let dst_port = u16::from_be_bytes([l4[2], l4[3]]);
            Some((&l4[8..], src_port, dst_port))
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn flow(src: u16, dst: u16) -> FlowKey {
        FlowKey {
            src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            dst_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            src_port: src,
            dst_port: dst,
            l4_proto: 6,
        }
    }

    /// Build a minimal IPv4 + TCP packet wrapping `payload`. Used by the
    /// classifier round-trip tests.
    fn tcp_packet(src_port: u16, dst_port: u16, payload: &[u8]) -> Vec<u8> {
        let total_len = 20 + 20 + payload.len();
        let mut pkt = vec![0u8; total_len];
        // IPv4 header
        pkt[0] = 0x45; // version 4, IHL 5
        pkt[2..4].copy_from_slice(&(total_len as u16).to_be_bytes());
        pkt[8] = 64; // TTL
        pkt[9] = 6; // proto = TCP
        pkt[12..16].copy_from_slice(&[10, 0, 0, 1]);
        pkt[16..20].copy_from_slice(&[10, 0, 0, 2]);
        // TCP header
        pkt[20..22].copy_from_slice(&src_port.to_be_bytes());
        pkt[22..24].copy_from_slice(&dst_port.to_be_bytes());
        pkt[32] = 5 << 4; // data offset = 5 words
        // payload
        pkt[40..].copy_from_slice(payload);
        pkt
    }

    #[test]
    fn unparseable_packet_returns_need_more() {
        let mut session = DpiSession::new();
        let result = session.feed(flow(49152, 502), &[], Duration::from_micros(100));
        assert!(matches!(result, Classification::NeedMore));
    }

    #[test]
    fn classified_flow_short_circuits_on_subsequent_packets() {
        let mut session = DpiSession::new();
        // Modbus MBAP: transaction id, protocol id 0, length 6, unit id 1,
        // function code 3 (read holding registers), addr 0, qty 1.
        let modbus = [
            0x00, 0x01, 0x00, 0x00, 0x00, 0x06, 0x01, 0x03, 0x00, 0x00, 0x00, 0x01,
        ];
        let pkt = tcp_packet(49152, 502, &modbus);
        let f = flow(49152, 502);
        let first = session.feed(f, &pkt, Duration::from_micros(100));
        assert!(matches!(first, Classification::Classified(_)));
        // Second call should hit the cached classification without
        // re-dispatching.
        let second = session.feed(f, &[], Duration::from_micros(100));
        assert!(matches!(second, Classification::Classified(_)));
    }

    #[test]
    fn exhausting_attempts_yields_unknown() {
        let cfg = DpiSessionConfig {
            max_classify_attempts: 2,
            max_flows: 16,
        };
        let mut session = DpiSession::with_config(cfg);
        let f = flow(49152, 12345);
        let pkt = tcp_packet(49152, 12345, &[0xff; 16]);
        // First attempt: NeedMore (random bytes don't match any dissector).
        let _ = session.feed(f, &pkt, Duration::from_micros(100));
        // Second attempt: still NeedMore but hits the cap.
        let _ = session.feed(f, &pkt, Duration::from_micros(100));
        // Third: should now report Unknown.
        let third = session.feed(f, &pkt, Duration::from_micros(100));
        assert!(matches!(third, Classification::Unknown));
    }

    #[test]
    fn extract_l4_payload_skips_fragmented_packets() {
        let mut pkt = tcp_packet(49152, 502, &[0xaa; 8]);
        // Set fragment offset to non-zero.
        pkt[6] = 0x00;
        pkt[7] = 0x10; // offset = 16 * 8 bytes
        assert!(extract_l4_payload(&pkt).is_none());
    }

    /// Build a minimal IPv6 + TCP packet wrapping `payload`.
    fn tcp_packet_v6(src_port: u16, dst_port: u16, payload: &[u8]) -> Vec<u8> {
        let l4_len = 20 + payload.len();
        let total_len = 40 + l4_len;
        let mut pkt = vec![0u8; total_len];
        pkt[0] = 0x60; // version 6
        pkt[4..6].copy_from_slice(&(l4_len as u16).to_be_bytes());
        pkt[6] = 6; // next header = TCP
        pkt[7] = 64; // hop limit
        pkt[40..42].copy_from_slice(&src_port.to_be_bytes());
        pkt[42..44].copy_from_slice(&dst_port.to_be_bytes());
        pkt[52] = 5 << 4;
        pkt[60..].copy_from_slice(payload);
        pkt
    }

    #[test]
    fn classifies_ipv6_modbus() {
        let mut session = DpiSession::new();
        let modbus = [
            0x00, 0x01, 0x00, 0x00, 0x00, 0x06, 0x01, 0x03, 0x00, 0x00, 0x00, 0x01,
        ];
        let pkt = tcp_packet_v6(49152, 502, &modbus);
        let f = FlowKey {
            src_ip: IpAddr::V6(std::net::Ipv6Addr::LOCALHOST),
            dst_ip: IpAddr::V6(std::net::Ipv6Addr::LOCALHOST),
            src_port: 49152,
            dst_port: 502,
            l4_proto: 6,
        };
        let result = session.feed(f, &pkt, Duration::from_micros(100));
        assert!(matches!(result, Classification::Classified(_)));
    }

    #[test]
    fn lru_eviction_drops_oldest_flow() {
        let mut session = DpiSession::with_config(DpiSessionConfig {
            max_classify_attempts: 16,
            max_flows: 2,
        });
        // Three distinct flows; only the most recent two should survive.
        let f1 = flow(10001, 502);
        let f2 = flow(10002, 502);
        let f3 = flow(10003, 502);
        let bogus = tcp_packet(0, 0, &[0xff; 8]);
        let _ = session.feed(f1, &bogus, Duration::from_micros(100));
        let _ = session.feed(f2, &bogus, Duration::from_micros(100));
        assert_eq!(session.flow_count(), 2);
        let _ = session.feed(f3, &bogus, Duration::from_micros(100));
        assert_eq!(session.flow_count(), 2, "should evict to make room");
        // f1 was LRU at the time f3 arrived → should be gone.
        let _ = session.feed(f2, &bogus, Duration::from_micros(100));
        let _ = session.feed(f3, &bogus, Duration::from_micros(100));
        assert_eq!(session.flow_count(), 2);
    }

    #[test]
    fn touched_flow_is_not_evicted() {
        let mut session = DpiSession::with_config(DpiSessionConfig {
            max_classify_attempts: 16,
            max_flows: 2,
        });
        let f1 = flow(10001, 502);
        let f2 = flow(10002, 502);
        let f3 = flow(10003, 502);
        let bogus = tcp_packet(0, 0, &[0xff; 8]);
        let _ = session.feed(f1, &bogus, Duration::from_micros(100));
        let _ = session.feed(f2, &bogus, Duration::from_micros(100));
        // Touch f1 so it's no longer the LRU.
        let _ = session.feed(f1, &bogus, Duration::from_micros(100));
        // Now f2 is LRU — adding f3 should evict f2 (not f1).
        let _ = session.feed(f3, &bogus, Duration::from_micros(100));
        assert_eq!(session.flow_count(), 2);
        // Modbus on f1 should still classify (state preserved).
        let modbus = [
            0x00, 0x01, 0x00, 0x00, 0x00, 0x06, 0x01, 0x03, 0x00, 0x00, 0x00, 0x01,
        ];
        // Use a fresh flow shape pointing at port 502 to trigger Modbus.
        let modbus_pkt = tcp_packet(10001, 502, &modbus);
        let result = session.feed(f1, &modbus_pkt, Duration::from_micros(100));
        assert!(matches!(result, Classification::Classified(_)));
    }

    #[test]
    fn classifies_ipv6_modbus_through_hop_by_hop_ext_header() {
        // Build IPv6 with a single 8-byte Hop-by-Hop extension header
        // between the v6 header and the TCP segment.
        let modbus = [
            0x00, 0x01, 0x00, 0x00, 0x00, 0x06, 0x01, 0x03, 0x00, 0x00, 0x00, 0x01,
        ];
        let tcp_len = 20 + modbus.len();
        let ext_len = 8;
        let l4_plus_ext = ext_len + tcp_len;
        let mut pkt = vec![0u8; 40 + l4_plus_ext];
        // v6 header
        pkt[0] = 0x60;
        pkt[4..6].copy_from_slice(&(l4_plus_ext as u16).to_be_bytes());
        pkt[6] = 0; // next header = Hop-by-Hop
        pkt[7] = 64;
        // Hop-by-Hop at offset 40: 8 bytes total (len field = 0 → 8 octets)
        pkt[40] = 6; // next header = TCP
        pkt[41] = 0; // hdr ext len: 0 → 8 octets
        // TCP at offset 48
        pkt[48..50].copy_from_slice(&49152u16.to_be_bytes());
        pkt[50..52].copy_from_slice(&502u16.to_be_bytes());
        pkt[60] = 5 << 4; // data offset = 5 words
        // payload
        pkt[68..].copy_from_slice(&modbus);

        let f = FlowKey {
            src_ip: IpAddr::V6(std::net::Ipv6Addr::LOCALHOST),
            dst_ip: IpAddr::V6(std::net::Ipv6Addr::LOCALHOST),
            src_port: 49152,
            dst_port: 502,
            l4_proto: 6,
        };
        let mut session = DpiSession::new();
        let result = session.feed(f, &pkt, Duration::from_micros(100));
        assert!(
            matches!(result, Classification::Classified(_)),
            "expected Classified, got {result:?}"
        );
    }
}
