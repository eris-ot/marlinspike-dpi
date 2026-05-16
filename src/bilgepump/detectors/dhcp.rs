//! DHCP abuse detection — rogue servers and starvation.

use std::collections::HashMap;

use chrono::{DateTime, Utc};

use crate::bilgepump::alerts::{AlertKind, AlertSeverity, BilgepumpAlert};
use crate::bilgepump::config::BilgepumpConfig;
use crate::bilgepump::state::{DhcpServerRecord, RateCounter};
use crate::registry::{DhcpFields, format_mac};

/// Stateful DHCP abuse detector.
#[derive(Debug, Default)]
pub struct DhcpDetector {
    /// Known DHCP servers observed on the network.
    servers: HashMap<String, DhcpServerRecord>,
    /// Global DHCP request rate (for starvation detection).
    request_counter: RateCounter,
}

impl DhcpDetector {
    pub fn observe(
        &mut self,
        fields: &DhcpFields,
        src_mac: &[u8; 6],
        config: &BilgepumpConfig,
        now: DateTime<Utc>,
    ) -> Vec<BilgepumpAlert> {
        if !config.check_dhcp_abuse {
            return Vec::new();
        }

        let mut alerts = Vec::new();

        let msg_type = fields.message_type.unwrap_or(0);

        // DHCP Offer (2) or Ack (5) — server responding
        if (msg_type == 2 || msg_type == 5)
            && let Some(ref server_id) = fields.server_id
        {
            let mac_str = format_mac(src_mac);

            // Rogue server detection
            if !config.known_dhcp_servers.is_empty()
                && !config.known_dhcp_servers.contains(server_id)
            {
                alerts.push(BilgepumpAlert {
                    kind: AlertKind::RogueDhcpServer {
                        server_id: server_id.clone(),
                        server_mac: mac_str.clone(),
                        offered_ip: fields.yiaddr.clone(),
                    },
                    severity: AlertSeverity::Critical,
                    decoder: "bilgepump:dhcp_rogue",
                });
            }

            // Track server
            let record =
                self.servers
                    .entry(server_id.clone())
                    .or_insert_with(|| DhcpServerRecord {
                        server_id: server_id.clone(),
                        src_mac: *src_mac,
                        first_seen: now,
                        last_seen: now,
                        offer_count: 0,
                    });
            record.last_seen = now;
            record.offer_count += 1;
        }

        // DHCP Discover (1) or Request (3) — client requesting
        if msg_type == 1 || msg_type == 3 {
            let count = self
                .request_counter
                .record(now, config.dhcp_starvation_window_secs);

            if count >= config.dhcp_starvation_threshold {
                alerts.push(BilgepumpAlert {
                    kind: AlertKind::DhcpStarvation {
                        request_count: count,
                        window_secs: config.dhcp_starvation_window_secs,
                    },
                    severity: AlertSeverity::High,
                    decoder: "bilgepump:dhcp_starvation",
                });
            }
        }

        alerts
    }

    pub fn evict(&mut self, now: DateTime<Utc>, ttl_secs: u64) {
        let cutoff = now - chrono::Duration::seconds(ttl_secs as i64);
        self.servers.retain(|_, s| s.last_seen >= cutoff);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    fn now() -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 1, 1, 12, 0, 0).unwrap()
    }

    fn dhcp_offer(server_id: &str) -> DhcpFields {
        DhcpFields {
            op: 2,
            xid: 0x1234,
            client_mac: [0x00, 0x11, 0x22, 0x33, 0x44, 0x55],
            ciaddr: None,
            yiaddr: Some("10.0.0.100".to_string()),
            siaddr: None,
            giaddr: None,
            message_type: Some(2), // Offer
            hostname: None,
            client_id: None,
            vendor_class: None,
            requested_ip: None,
            server_id: Some(server_id.to_string()),
        }
    }

    fn dhcp_discover() -> DhcpFields {
        DhcpFields {
            op: 1,
            xid: 0x5678,
            client_mac: [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF],
            ciaddr: None,
            yiaddr: None,
            siaddr: None,
            giaddr: None,
            message_type: Some(1), // Discover
            hostname: None,
            client_id: None,
            vendor_class: None,
            requested_ip: None,
            server_id: None,
        }
    }

    #[test]
    fn detect_rogue_dhcp() {
        let mut det = DhcpDetector::default();
        let mut config = BilgepumpConfig::default();
        config.known_dhcp_servers = vec!["10.0.0.1".to_string()];
        let t = now();

        let mac = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55];
        let alerts = det.observe(&dhcp_offer("10.0.0.99"), &mac, &config, t);
        assert!(
            alerts.iter().any(|a| a.decoder == "bilgepump:dhcp_rogue"),
            "expected rogue DHCP alert"
        );
    }

    #[test]
    fn known_server_ok() {
        let mut det = DhcpDetector::default();
        let mut config = BilgepumpConfig::default();
        config.known_dhcp_servers = vec!["10.0.0.1".to_string()];
        let t = now();

        let mac = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55];
        let alerts = det.observe(&dhcp_offer("10.0.0.1"), &mac, &config, t);
        assert!(!alerts.iter().any(|a| a.decoder == "bilgepump:dhcp_rogue"));
    }

    #[test]
    fn detect_starvation() {
        let mut det = DhcpDetector::default();
        let mut config = BilgepumpConfig::default();
        config.dhcp_starvation_threshold = 3;
        config.dhcp_starvation_window_secs = 10;
        let t = now();

        let mac = [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF];
        for i in 0..3 {
            let t_i = t + chrono::Duration::milliseconds(i * 100);
            let alerts = det.observe(&dhcp_discover(), &mac, &config, t_i);
            if i == 2 {
                assert!(
                    alerts
                        .iter()
                        .any(|a| a.decoder == "bilgepump:dhcp_starvation"),
                    "expected starvation alert"
                );
            }
        }
    }
}
