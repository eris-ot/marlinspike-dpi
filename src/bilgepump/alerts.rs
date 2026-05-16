//! Bilgepump alert finding types.

/// Severity of an L2 monitoring finding.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AlertSeverity {
    Low,
    Medium,
    High,
    Critical,
}

impl AlertSeverity {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Low => "low",
            Self::Medium => "medium",
            Self::High => "high",
            Self::Critical => "critical",
        }
    }
}

/// Specific kind of L2 anomaly detected.
#[derive(Debug, Clone)]
pub enum AlertKind {
    /// ARP reply claims an IP already bound to a different MAC.
    ArpSpoofDetected {
        claimed_ip: String,
        new_mac: String,
        previous_mac: String,
    },
    /// Unsolicited ARP reply — no request was observed.
    ArpGratuitous {
        sender_mac: String,
        sender_ip: String,
    },
    /// Gratuitous ARP flood from a single source.
    ArpFlood {
        source_mac: String,
        count: usize,
        window_secs: u64,
    },
    /// Source MAC has the locally-administered bit set (bit 1 of first octet).
    MacLocallyAdministered { mac: String },
    /// Source MAC is a multicast address (should never be source).
    MacMulticastSource { mac: String },
    /// MAC rapidly changing IP associations.
    MacFlapping {
        mac: String,
        distinct_ips: usize,
        window_secs: u64,
    },
    /// Double-tagged 802.1Q frame — possible VLAN hopping.
    VlanHopping { outer_vlan: u16, inner_vlan: u16 },
    /// STP root bridge changed.
    StpRootChange {
        previous_root: String,
        new_root: String,
        claiming_bridge: String,
    },
    /// STP root claim from a bridge not on the whitelist.
    StpUnauthorizedRoot {
        bridge_id: String,
        claimed_root: String,
    },
    /// DHCP server responding that is not in the known-good list.
    RogueDhcpServer {
        server_id: String,
        server_mac: String,
        offered_ip: Option<String>,
    },
    /// Excessive DHCP discover/request volume from varied MACs.
    DhcpStarvation {
        request_count: usize,
        window_secs: u64,
    },
    /// LLDP chassis_id from a source MAC conflicts with previous identity.
    LldpIdentityConflict {
        src_mac: String,
        current_chassis_id: String,
        previous_chassis_id: String,
    },
    /// CDP device_id from a source MAC conflicts with previous identity.
    CdpIdentityConflict {
        src_mac: String,
        current_device_id: String,
        previous_device_id: String,
    },
}

/// A single finding from bilgepump.
#[derive(Debug, Clone)]
pub struct BilgepumpAlert {
    pub kind: AlertKind,
    pub severity: AlertSeverity,
    /// Decoder tag for the Bronze `ParseAnomaly` event.
    pub decoder: &'static str,
}

impl BilgepumpAlert {
    /// Human-readable reason string.
    pub fn reason(&self) -> String {
        match &self.kind {
            AlertKind::ArpSpoofDetected {
                claimed_ip,
                new_mac,
                previous_mac,
            } => format!("ARP spoof: {claimed_ip} moved from {previous_mac} to {new_mac}"),
            AlertKind::ArpGratuitous {
                sender_mac,
                sender_ip,
            } => format!("gratuitous ARP from {sender_mac} claiming {sender_ip}"),
            AlertKind::ArpFlood {
                source_mac,
                count,
                window_secs,
            } => format!("ARP flood: {count} replies from {source_mac} in {window_secs}s"),
            AlertKind::MacLocallyAdministered { mac } => {
                format!("locally-administered source MAC: {mac}")
            }
            AlertKind::MacMulticastSource { mac } => {
                format!("multicast source MAC: {mac}")
            }
            AlertKind::MacFlapping {
                mac,
                distinct_ips,
                window_secs,
            } => {
                format!("MAC flapping: {mac} associated with {distinct_ips} IPs in {window_secs}s")
            }
            AlertKind::VlanHopping {
                outer_vlan,
                inner_vlan,
            } => format!("VLAN hopping: double-tagged frame outer={outer_vlan} inner={inner_vlan}"),
            AlertKind::StpRootChange {
                previous_root,
                new_root,
                claiming_bridge,
            } => format!(
                "STP root change: {previous_root} -> {new_root} (claimed by {claiming_bridge})"
            ),
            AlertKind::StpUnauthorizedRoot {
                bridge_id,
                claimed_root,
            } => format!(
                "unauthorized STP root claim: bridge {bridge_id} claiming root {claimed_root}"
            ),
            AlertKind::RogueDhcpServer {
                server_id,
                server_mac,
                ..
            } => format!("rogue DHCP server: {server_id} from {server_mac}"),
            AlertKind::DhcpStarvation {
                request_count,
                window_secs,
            } => format!("DHCP starvation: {request_count} requests in {window_secs}s"),
            AlertKind::LldpIdentityConflict {
                src_mac,
                current_chassis_id,
                previous_chassis_id,
            } => format!(
                "LLDP identity conflict: {src_mac} was {previous_chassis_id}, now {current_chassis_id}"
            ),
            AlertKind::CdpIdentityConflict {
                src_mac,
                current_device_id,
                previous_device_id,
            } => format!(
                "CDP identity conflict: {src_mac} was {previous_device_id}, now {current_device_id}"
            ),
        }
    }
}
