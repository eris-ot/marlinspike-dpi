//! ARP spoofing and flood detection.

use std::collections::HashMap;

use chrono::{DateTime, Utc};

use crate::bilgepump::alerts::{AlertKind, AlertSeverity, BilgepumpAlert};
use crate::bilgepump::config::BilgepumpConfig;
use crate::bilgepump::state::{BindingSource, MacIpBinding, RateCounter};
use crate::registry::{ArpFields, format_mac};

/// Stateful ARP monitor.
#[derive(Debug, Default)]
pub struct ArpDetector {
    /// IP -> binding (who owns this IP).
    ip_bindings: HashMap<[u8; 4], MacIpBinding>,
    /// Per-source-MAC ARP reply rate counter.
    reply_counters: HashMap<[u8; 6], RateCounter>,
}

impl ArpDetector {
    pub fn observe(
        &mut self,
        fields: &ArpFields,
        config: &BilgepumpConfig,
        now: DateTime<Utc>,
    ) -> Vec<BilgepumpAlert> {
        if !config.check_arp_spoofing {
            return Vec::new();
        }

        let mut alerts = Vec::new();

        let sender_mac_str = format_mac(&fields.sender_mac);
        let sender_ip_str = format!(
            "{}.{}.{}.{}",
            fields.sender_ip[0], fields.sender_ip[1], fields.sender_ip[2], fields.sender_ip[3]
        );

        // Check if this is a blessed binding
        let is_blessed = config
            .blessed_bindings
            .iter()
            .any(|b| b.mac.eq_ignore_ascii_case(&sender_mac_str) && b.ip == sender_ip_str);

        // ARP reply (operation 2) or gratuitous ARP (operation 1 with sender=target)
        let is_reply = fields.operation == 2;
        let is_gratuitous = fields.operation == 1 && fields.sender_ip == fields.target_ip;

        // Gratuitous ARP detection
        if is_gratuitous {
            alerts.push(BilgepumpAlert {
                kind: AlertKind::ArpGratuitous {
                    sender_mac: sender_mac_str.clone(),
                    sender_ip: sender_ip_str.clone(),
                },
                severity: AlertSeverity::Medium,
                decoder: "bilgepump:arp_gratuitous",
            });
        }

        // ARP flood detection (reply rate)
        if is_reply || is_gratuitous {
            let counter = self.reply_counters.entry(fields.sender_mac).or_default();
            let count = counter.record(now, config.arp_flood_window_secs);
            if count >= config.arp_flood_threshold {
                alerts.push(BilgepumpAlert {
                    kind: AlertKind::ArpFlood {
                        source_mac: sender_mac_str.clone(),
                        count,
                        window_secs: config.arp_flood_window_secs,
                    },
                    severity: AlertSeverity::High,
                    decoder: "bilgepump:arp_flood",
                });
            }
        }

        // Binding change detection (ARP spoofing)
        if let Some(existing) = self.ip_bindings.get(&fields.sender_ip)
            && existing.mac != fields.sender_mac
            && !is_blessed
            && !existing.blessed
        {
            let ttl = chrono::Duration::seconds(config.arp_binding_ttl_secs as i64);
            let binding_expired = (now - existing.last_seen) > ttl;

            if !binding_expired {
                alerts.push(BilgepumpAlert {
                    kind: AlertKind::ArpSpoofDetected {
                        claimed_ip: sender_ip_str.clone(),
                        new_mac: sender_mac_str.clone(),
                        previous_mac: format_mac(&existing.mac),
                    },
                    severity: AlertSeverity::Critical,
                    decoder: "bilgepump:arp_spoof",
                });
            }
        }

        // Update or create binding
        let binding = self
            .ip_bindings
            .entry(fields.sender_ip)
            .or_insert_with(|| MacIpBinding {
                mac: fields.sender_mac,
                ip: fields.sender_ip,
                first_seen: now,
                last_seen: now,
                source: if is_blessed {
                    BindingSource::Blessed
                } else {
                    BindingSource::Arp
                },
                blessed: is_blessed,
            });
        binding.mac = fields.sender_mac;
        binding.last_seen = now;

        alerts
    }

    /// Evict expired state entries.
    pub fn evict(&mut self, now: DateTime<Utc>, ttl_secs: u64) {
        let cutoff = now - chrono::Duration::seconds(ttl_secs as i64);
        self.ip_bindings.retain(|_, b| b.last_seen >= cutoff);
        self.reply_counters.retain(|_, c| c.count() > 0);
    }

    /// Record a DHCP-learned binding (higher trust than ARP).
    pub fn record_dhcp_binding(&mut self, mac: [u8; 6], ip: [u8; 4], now: DateTime<Utc>) {
        let binding = self.ip_bindings.entry(ip).or_insert_with(|| MacIpBinding {
            mac,
            ip,
            first_seen: now,
            last_seen: now,
            source: BindingSource::Dhcp,
            blessed: false,
        });
        binding.mac = mac;
        binding.last_seen = now;
        binding.source = BindingSource::Dhcp;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    fn now() -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 1, 1, 12, 0, 0).unwrap()
    }

    fn arp_reply(sender_mac: [u8; 6], sender_ip: [u8; 4]) -> ArpFields {
        ArpFields {
            operation: 2,
            sender_mac,
            sender_ip,
            target_mac: [0xFF; 6],
            target_ip: [0; 4],
        }
    }

    #[test]
    fn detect_arp_spoof() {
        let mut det = ArpDetector::default();
        let config = BilgepumpConfig::default();
        let t = now();

        // First binding: 10.0.0.1 = MAC A
        let mac_a = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55];
        let mac_b = [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF];
        let ip = [10, 0, 0, 1];

        let alerts = det.observe(&arp_reply(mac_a, ip), &config, t);
        assert!(!alerts.iter().any(|a| a.decoder == "bilgepump:arp_spoof"));

        // Second binding: 10.0.0.1 = MAC B (spoof!)
        let t2 = t + chrono::Duration::seconds(1);
        let alerts = det.observe(&arp_reply(mac_b, ip), &config, t2);
        assert!(
            alerts.iter().any(|a| a.decoder == "bilgepump:arp_spoof"),
            "expected ARP spoof alert"
        );
    }

    #[test]
    fn no_spoof_after_ttl_expires() {
        let mut det = ArpDetector::default();
        let mut config = BilgepumpConfig::default();
        config.arp_binding_ttl_secs = 60;
        let t = now();

        let mac_a = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55];
        let mac_b = [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF];
        let ip = [10, 0, 0, 1];

        det.observe(&arp_reply(mac_a, ip), &config, t);

        // After TTL expires, binding change is not flagged
        let t2 = t + chrono::Duration::seconds(120);
        let alerts = det.observe(&arp_reply(mac_b, ip), &config, t2);
        assert!(
            !alerts.iter().any(|a| a.decoder == "bilgepump:arp_spoof"),
            "should not flag after TTL expiry"
        );
    }

    #[test]
    fn detect_arp_flood() {
        let mut det = ArpDetector::default();
        let mut config = BilgepumpConfig::default();
        config.arp_flood_threshold = 3;
        config.arp_flood_window_secs = 10;
        let t = now();

        let mac = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55];

        for i in 0..3 {
            let ip = [10, 0, 0, (i + 1) as u8];
            let t_i = t + chrono::Duration::milliseconds(i * 100);
            let alerts = det.observe(&arp_reply(mac, ip), &config, t_i);
            if i == 2 {
                assert!(
                    alerts.iter().any(|a| a.decoder == "bilgepump:arp_flood"),
                    "expected flood alert at count 3"
                );
            }
        }
    }

    #[test]
    fn blessed_binding_not_flagged() {
        let mut det = ArpDetector::default();
        let mut config = BilgepumpConfig::default();
        config
            .blessed_bindings
            .push(crate::bilgepump::config::BlessedBinding {
                mac: "aa:bb:cc:dd:ee:ff".to_string(),
                ip: "10.0.0.1".to_string(),
                description: None,
            });
        let t = now();
        let ip = [10, 0, 0, 1];

        let mac_a = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55];
        det.observe(&arp_reply(mac_a, ip), &config, t);

        let mac_b = [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF];
        let t2 = t + chrono::Duration::seconds(1);
        let alerts = det.observe(&arp_reply(mac_b, ip), &config, t2);
        assert!(
            !alerts.iter().any(|a| a.decoder == "bilgepump:arp_spoof"),
            "blessed binding should not trigger spoof alert"
        );
    }
}
