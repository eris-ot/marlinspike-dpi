//! MAC header anomaly detection.

use std::collections::HashMap;

use chrono::{DateTime, Utc};

use crate::bilgepump::alerts::{AlertKind, AlertSeverity, BilgepumpAlert};
use crate::bilgepump::config::BilgepumpConfig;
use crate::bilgepump::state::MacFlapTracker;
use crate::registry::format_mac;

/// Stateful MAC anomaly detector.
#[derive(Debug, Default)]
pub struct MacDetector {
    flap_trackers: HashMap<[u8; 6], MacFlapTracker>,
}

impl MacDetector {
    /// Inspect a source MAC from an Ethernet frame header.
    pub fn inspect_mac(&self, src_mac: &[u8; 6], config: &BilgepumpConfig) -> Vec<BilgepumpAlert> {
        if !config.check_mac_anomalies {
            return Vec::new();
        }

        let mut alerts = Vec::new();
        let mac_str = format_mac(src_mac);

        // Locally-administered bit (bit 1 of first octet)
        if src_mac[0] & 0x02 != 0 && *src_mac != [0; 6] {
            alerts.push(BilgepumpAlert {
                kind: AlertKind::MacLocallyAdministered {
                    mac: mac_str.clone(),
                },
                severity: AlertSeverity::Low,
                decoder: "bilgepump:mac_local",
            });
        }

        // Multicast source (bit 0 of first octet) — should never be a source MAC
        if src_mac[0] & 0x01 != 0 && *src_mac != [0xFF; 6] {
            alerts.push(BilgepumpAlert {
                kind: AlertKind::MacMulticastSource { mac: mac_str },
                severity: AlertSeverity::High,
                decoder: "bilgepump:mac_multicast",
            });
        }

        alerts
    }

    /// Track a MAC/IP association and detect flapping.
    pub fn observe_ip_association(
        &mut self,
        mac: &[u8; 6],
        ip: [u8; 4],
        vlan_id: Option<u16>,
        config: &BilgepumpConfig,
        now: DateTime<Utc>,
    ) -> Vec<BilgepumpAlert> {
        if !config.check_mac_anomalies {
            return Vec::new();
        }

        let tracker = self.flap_trackers.entry(*mac).or_default();
        let distinct = tracker.record(ip, vlan_id, now, config.mac_flap_window_secs);

        if distinct >= config.mac_flap_threshold {
            vec![BilgepumpAlert {
                kind: AlertKind::MacFlapping {
                    mac: format_mac(mac),
                    distinct_ips: distinct,
                    window_secs: config.mac_flap_window_secs,
                },
                severity: AlertSeverity::High,
                decoder: "bilgepump:mac_flap",
            }]
        } else {
            Vec::new()
        }
    }

    pub fn evict(&mut self, now: DateTime<Utc>, ttl_secs: u64) {
        self.flap_trackers.retain(|_, t| {
            t.observations
                .back()
                .is_some_and(|o| (now - o.timestamp) < chrono::Duration::seconds(ttl_secs as i64))
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    #[test]
    fn detect_locally_administered() {
        let det = MacDetector::default();
        let config = BilgepumpConfig::default();
        let mac = [0x02, 0x00, 0x00, 0x00, 0x00, 0x01]; // LA bit set
        let alerts = det.inspect_mac(&mac, &config);
        assert!(alerts.iter().any(|a| a.decoder == "bilgepump:mac_local"));
    }

    #[test]
    fn detect_multicast_source() {
        let det = MacDetector::default();
        let config = BilgepumpConfig::default();
        let mac = [0x01, 0x00, 0x5E, 0x00, 0x00, 0x01]; // multicast
        let alerts = det.inspect_mac(&mac, &config);
        assert!(
            alerts
                .iter()
                .any(|a| a.decoder == "bilgepump:mac_multicast")
        );
    }

    #[test]
    fn normal_mac_no_alert() {
        let det = MacDetector::default();
        let config = BilgepumpConfig::default();
        let mac = [0x00, 0x1C, 0x06, 0xAA, 0xBB, 0xCC]; // normal OUI
        let alerts = det.inspect_mac(&mac, &config);
        assert!(alerts.is_empty());
    }

    #[test]
    fn detect_mac_flapping() {
        let mut det = MacDetector::default();
        let mut config = BilgepumpConfig::default();
        config.mac_flap_threshold = 3;
        config.mac_flap_window_secs = 10;
        let t = Utc.with_ymd_and_hms(2026, 1, 1, 12, 0, 0).unwrap();

        let mac = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55];

        for i in 0..3 {
            let ip = [10, 0, 0, (i + 1) as u8];
            let t_i = t + chrono::Duration::seconds(i);
            let alerts = det.observe_ip_association(&mac, ip, None, &config, t_i);
            if i == 2 {
                assert!(
                    alerts.iter().any(|a| a.decoder == "bilgepump:mac_flap"),
                    "expected flap alert at 3 distinct IPs"
                );
            }
        }
    }
}
