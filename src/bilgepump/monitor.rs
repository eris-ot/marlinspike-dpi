//! BilgepumpMonitor — the orchestrator for all L2 detectors.
//!
//! Owned directly by `DpiEngine`, called at two points:
//! - `inspect_l2_frame`: pre-VLAN-unwrap (VLAN hopping, MAC anomalies)
//! - `observe_arp`, `observe_stp`, `observe_dhcp`, `observe_lldp`, `observe_cdp`:
//!   post-decoder with parsed protocol fields

use chrono::{DateTime, Utc};

use crate::registry::{ArpFields, CdpFields, DhcpFields, LldpFields, StpFields};

use super::alerts::BilgepumpAlert;
use super::config::BilgepumpConfig;
use super::detectors::{
    arp::ArpDetector, dhcp::DhcpDetector, identity::IdentityDetector, mac::MacDetector,
    stp::StpDetector, vlan::inspect_vlan_tags,
};

/// Stateful L2 monitor. Accumulates state across frames and captures.
pub struct BilgepumpMonitor {
    pub config: BilgepumpConfig,
    arp: ArpDetector,
    mac: MacDetector,
    stp: StpDetector,
    dhcp: DhcpDetector,
    identity: IdentityDetector,
}

impl BilgepumpMonitor {
    pub fn new(config: BilgepumpConfig) -> Self {
        Self {
            config,
            arp: ArpDetector::default(),
            mac: MacDetector::default(),
            stp: StpDetector::default(),
            dhcp: DhcpDetector::default(),
            identity: IdentityDetector::default(),
        }
    }

    /// Pre-VLAN-unwrap inspection of raw Ethernet frame.
    /// Called before the engine strips VLAN tags and before protocol dispatch.
    pub fn inspect_l2_frame(&self, raw_frame: &[u8], src_mac: &[u8; 6]) -> Vec<BilgepumpAlert> {
        if !self.config.enabled {
            return Vec::new();
        }

        let mut alerts = Vec::new();

        // VLAN hopping detection
        alerts.extend(inspect_vlan_tags(raw_frame, &self.config));

        // MAC header anomalies
        alerts.extend(self.mac.inspect_mac(src_mac, &self.config));

        alerts
    }

    /// Observe a parsed ARP frame.
    pub fn observe_arp(
        &mut self,
        fields: &ArpFields,
        src_mac: &[u8; 6],
        vlan_id: Option<u16>,
        now: DateTime<Utc>,
    ) -> Vec<BilgepumpAlert> {
        if !self.config.enabled {
            return Vec::new();
        }

        let mut alerts = Vec::new();

        // ARP spoofing / flood detection
        alerts.extend(self.arp.observe(fields, &self.config, now));

        // MAC flapping — track the ARP sender's IP association
        alerts.extend(self.mac.observe_ip_association(
            src_mac,
            fields.sender_ip,
            vlan_id,
            &self.config,
            now,
        ));

        alerts
    }

    /// Observe a parsed STP BPDU.
    pub fn observe_stp(&mut self, fields: &StpFields, now: DateTime<Utc>) -> Vec<BilgepumpAlert> {
        if !self.config.enabled {
            return Vec::new();
        }
        self.stp.observe(fields, &self.config, now)
    }

    /// Observe a parsed DHCP message.
    pub fn observe_dhcp(
        &mut self,
        fields: &DhcpFields,
        src_mac: &[u8; 6],
        now: DateTime<Utc>,
    ) -> Vec<BilgepumpAlert> {
        if !self.config.enabled {
            return Vec::new();
        }

        let mut alerts = Vec::new();
        alerts.extend(self.dhcp.observe(fields, src_mac, &self.config, now));

        // If DHCP Ack with yiaddr, record the binding in ARP detector
        if fields.message_type == Some(5)
            && let Some(ref yiaddr) = fields.yiaddr
            && let Some(ip) = parse_ipv4(yiaddr)
        {
            self.arp.record_dhcp_binding(fields.client_mac, ip, now);
        }

        alerts
    }

    /// Observe a parsed LLDP frame.
    pub fn observe_lldp(
        &mut self,
        fields: &LldpFields,
        src_mac: &[u8; 6],
        now: DateTime<Utc>,
    ) -> Vec<BilgepumpAlert> {
        if !self.config.enabled {
            return Vec::new();
        }
        self.identity
            .observe_lldp(fields, src_mac, &self.config, now)
    }

    /// Observe a parsed CDP frame.
    pub fn observe_cdp(
        &mut self,
        fields: &CdpFields,
        src_mac: &[u8; 6],
        now: DateTime<Utc>,
    ) -> Vec<BilgepumpAlert> {
        if !self.config.enabled {
            return Vec::new();
        }
        self.identity
            .observe_cdp(fields, src_mac, &self.config, now)
    }

    /// Evict expired state across all detectors.
    pub fn evict_expired(&mut self, now: DateTime<Utc>) {
        let ttl = self.config.default_state_ttl_secs;
        self.arp.evict(now, ttl);
        self.mac.evict(now, ttl);
        self.dhcp.evict(now, ttl);
        self.identity.evict(now, self.config.identity_ttl_secs);
    }
}

impl Default for BilgepumpMonitor {
    fn default() -> Self {
        Self::new(BilgepumpConfig::default())
    }
}

/// Parse a dotted-decimal IPv4 string to 4-byte array.
fn parse_ipv4(s: &str) -> Option<[u8; 4]> {
    let parts: Vec<&str> = s.split('.').collect();
    if parts.len() != 4 {
        return None;
    }
    let a = parts[0].parse().ok()?;
    let b = parts[1].parse().ok()?;
    let c = parts[2].parse().ok()?;
    let d = parts[3].parse().ok()?;
    Some([a, b, c, d])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_ipv4_valid() {
        assert_eq!(parse_ipv4("10.0.0.1"), Some([10, 0, 0, 1]));
        assert_eq!(parse_ipv4("255.255.255.0"), Some([255, 255, 255, 0]));
    }

    #[test]
    fn parse_ipv4_invalid() {
        assert_eq!(parse_ipv4("not.an.ip"), None);
        assert_eq!(parse_ipv4("10.0.0"), None);
        assert_eq!(parse_ipv4("256.0.0.1"), None);
    }

    #[test]
    fn disabled_returns_nothing() {
        let mut config = BilgepumpConfig::default();
        config.enabled = false;
        let monitor = BilgepumpMonitor::new(config);
        let mac = [0x02, 0x00, 0x00, 0x00, 0x00, 0x01]; // LA bit set
        let alerts = monitor.inspect_l2_frame(&[0u8; 64], &mac);
        assert!(alerts.is_empty());
    }
}
