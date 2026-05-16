//! LLDP/CDP identity conflict detection.

use std::collections::HashMap;

use chrono::{DateTime, Utc};

use crate::bilgepump::alerts::{AlertKind, AlertSeverity, BilgepumpAlert};
use crate::bilgepump::config::BilgepumpConfig;
use crate::bilgepump::state::{CdpIdentityRecord, LldpIdentityRecord};
use crate::registry::{CdpFields, LldpFields, format_mac};

/// Stateful identity conflict detector.
#[derive(Debug, Default)]
pub struct IdentityDetector {
    /// Source MAC -> last LLDP identity.
    lldp: HashMap<[u8; 6], LldpIdentityRecord>,
    /// Source MAC -> last CDP identity.
    cdp: HashMap<[u8; 6], CdpIdentityRecord>,
}

impl IdentityDetector {
    pub fn observe_lldp(
        &mut self,
        fields: &LldpFields,
        src_mac: &[u8; 6],
        config: &BilgepumpConfig,
        now: DateTime<Utc>,
    ) -> Vec<BilgepumpAlert> {
        if !config.check_identity_conflicts {
            return Vec::new();
        }

        let mut alerts = Vec::new();

        if let Some(existing) = self.lldp.get(src_mac)
            && existing.chassis_id != fields.chassis_id
            && !fields.chassis_id.is_empty()
        {
            alerts.push(BilgepumpAlert {
                kind: AlertKind::LldpIdentityConflict {
                    src_mac: format_mac(src_mac),
                    current_chassis_id: fields.chassis_id.clone(),
                    previous_chassis_id: existing.chassis_id.clone(),
                },
                severity: AlertSeverity::High,
                decoder: "bilgepump:lldp_conflict",
            });
        }

        self.lldp.insert(
            *src_mac,
            LldpIdentityRecord {
                chassis_id: fields.chassis_id.clone(),
                system_name: fields.system_name.clone(),
                src_mac: *src_mac,
                first_seen: self.lldp.get(src_mac).map(|r| r.first_seen).unwrap_or(now),
                last_seen: now,
            },
        );

        alerts
    }

    pub fn observe_cdp(
        &mut self,
        fields: &CdpFields,
        src_mac: &[u8; 6],
        config: &BilgepumpConfig,
        now: DateTime<Utc>,
    ) -> Vec<BilgepumpAlert> {
        if !config.check_identity_conflicts {
            return Vec::new();
        }

        let mut alerts = Vec::new();

        if let Some(existing) = self.cdp.get(src_mac)
            && existing.device_id != fields.device_id
            && !fields.device_id.is_empty()
        {
            alerts.push(BilgepumpAlert {
                kind: AlertKind::CdpIdentityConflict {
                    src_mac: format_mac(src_mac),
                    current_device_id: fields.device_id.clone(),
                    previous_device_id: existing.device_id.clone(),
                },
                severity: AlertSeverity::High,
                decoder: "bilgepump:cdp_conflict",
            });
        }

        self.cdp.insert(
            *src_mac,
            CdpIdentityRecord {
                device_id: fields.device_id.clone(),
                platform: fields.platform.clone(),
                src_mac: *src_mac,
                first_seen: self.cdp.get(src_mac).map(|r| r.first_seen).unwrap_or(now),
                last_seen: now,
            },
        );

        alerts
    }

    pub fn evict(&mut self, now: DateTime<Utc>, ttl_secs: u64) {
        let cutoff = now - chrono::Duration::seconds(ttl_secs as i64);
        self.lldp.retain(|_, r| r.last_seen >= cutoff);
        self.cdp.retain(|_, r| r.last_seen >= cutoff);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    fn now() -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 1, 1, 12, 0, 0).unwrap()
    }

    #[test]
    fn detect_lldp_conflict() {
        let mut det = IdentityDetector::default();
        let config = BilgepumpConfig::default();
        let t = now();
        let mac = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55];

        let fields1 = LldpFields {
            chassis_id: "switch-A".to_string(),
            port_id: "Gi0/1".to_string(),
            ttl: 120,
            system_name: "switch-A".to_string(),
            system_description: String::new(),
            capabilities: Vec::new(),
        };
        let alerts = det.observe_lldp(&fields1, &mac, &config, t);
        assert!(alerts.is_empty());

        // Same MAC, different chassis_id
        let t2 = t + chrono::Duration::seconds(30);
        let fields2 = LldpFields {
            chassis_id: "rogue-switch".to_string(),
            port_id: "Gi0/1".to_string(),
            ttl: 120,
            system_name: "rogue-switch".to_string(),
            system_description: String::new(),
            capabilities: Vec::new(),
        };
        let alerts = det.observe_lldp(&fields2, &mac, &config, t2);
        assert!(
            alerts
                .iter()
                .any(|a| a.decoder == "bilgepump:lldp_conflict"),
            "expected LLDP identity conflict"
        );
    }

    #[test]
    fn detect_cdp_conflict() {
        let mut det = IdentityDetector::default();
        let config = BilgepumpConfig::default();
        let t = now();
        let mac = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55];

        let fields1 = CdpFields {
            version: 2,
            ttl: 180,
            checksum: 0,
            device_id: "real-switch".to_string(),
            port_id: "GigabitEthernet0/1".to_string(),
            platform: Some("WS-C3560".to_string()),
            software_version: None,
            capabilities: Vec::new(),
            native_vlan: None,
            duplex: None,
            management_addresses: Vec::new(),
        };
        det.observe_cdp(&fields1, &mac, &config, t);

        let t2 = t + chrono::Duration::seconds(30);
        let fields2 = CdpFields {
            device_id: "evil-switch".to_string(),
            ..fields1.clone()
        };
        let alerts = det.observe_cdp(&fields2, &mac, &config, t2);
        assert!(
            alerts.iter().any(|a| a.decoder == "bilgepump:cdp_conflict"),
            "expected CDP identity conflict"
        );
    }
}
