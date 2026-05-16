//! STP root manipulation detection.

use chrono::{DateTime, Utc};

use crate::bilgepump::alerts::{AlertKind, AlertSeverity, BilgepumpAlert};
use crate::bilgepump::config::BilgepumpConfig;
use crate::bilgepump::state::StpRootRecord;
use crate::registry::StpFields;

/// Stateful STP root monitor.
#[derive(Debug, Default)]
pub struct StpDetector {
    current_root: Option<StpRootRecord>,
}

impl StpDetector {
    pub fn observe(
        &mut self,
        fields: &StpFields,
        config: &BilgepumpConfig,
        now: DateTime<Utc>,
    ) -> Vec<BilgepumpAlert> {
        if !config.check_stp_manipulation {
            return Vec::new();
        }

        let mut alerts = Vec::new();

        // Check whitelist
        if !config.stp_root_whitelist.is_empty()
            && !config.stp_root_whitelist.contains(&fields.root_id)
        {
            alerts.push(BilgepumpAlert {
                kind: AlertKind::StpUnauthorizedRoot {
                    bridge_id: fields.bridge_id.clone(),
                    claimed_root: fields.root_id.clone(),
                },
                severity: AlertSeverity::High,
                decoder: "bilgepump:stp_unauthorized",
            });
        }

        // Root change detection
        if let Some(ref current) = self.current_root
            && current.root_id != fields.root_id
        {
            alerts.push(BilgepumpAlert {
                kind: AlertKind::StpRootChange {
                    previous_root: current.root_id.clone(),
                    new_root: fields.root_id.clone(),
                    claiming_bridge: fields.bridge_id.clone(),
                },
                severity: AlertSeverity::High,
                decoder: "bilgepump:stp_root_change",
            });
        }

        // Update current root
        self.current_root = Some(StpRootRecord {
            root_id: fields.root_id.clone(),
            claiming_bridge: fields.bridge_id.clone(),
            first_seen: self
                .current_root
                .as_ref()
                .filter(|r| r.root_id == fields.root_id)
                .map(|r| r.first_seen)
                .unwrap_or(now),
            last_seen: now,
            root_path_cost: fields.root_path_cost,
        });

        alerts
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    fn now() -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 1, 1, 12, 0, 0).unwrap()
    }

    fn stp_bpdu(root_id: &str, bridge_id: &str) -> StpFields {
        StpFields {
            protocol_version: 2,
            bpdu_type: 2,
            flags: 0,
            root_id: root_id.to_string(),
            root_path_cost: 0,
            bridge_id: bridge_id.to_string(),
            port_id: 0x8001,
            hello_time: 2,
            max_age: 20,
            forward_delay: 15,
        }
    }

    #[test]
    fn detect_root_change() {
        let mut det = StpDetector::default();
        let config = BilgepumpConfig::default();
        let t = now();

        // Establish root
        let alerts = det.observe(
            &stp_bpdu("8000.aabbccddeeff", "8000.aabbccddeeff"),
            &config,
            t,
        );
        assert!(
            !alerts
                .iter()
                .any(|a| a.decoder == "bilgepump:stp_root_change")
        );

        // Root changes
        let t2 = t + chrono::Duration::seconds(1);
        let alerts = det.observe(
            &stp_bpdu("4000.112233445566", "4000.112233445566"),
            &config,
            t2,
        );
        assert!(
            alerts
                .iter()
                .any(|a| a.decoder == "bilgepump:stp_root_change"),
            "expected STP root change alert"
        );
    }

    #[test]
    fn unauthorized_root() {
        let mut det = StpDetector::default();
        let mut config = BilgepumpConfig::default();
        config.stp_root_whitelist = vec!["8000.aabbccddeeff".to_string()];
        let t = now();

        let alerts = det.observe(
            &stp_bpdu("4000.112233445566", "4000.112233445566"),
            &config,
            t,
        );
        assert!(
            alerts
                .iter()
                .any(|a| a.decoder == "bilgepump:stp_unauthorized"),
            "expected unauthorized root alert"
        );
    }

    #[test]
    fn whitelisted_root_ok() {
        let mut det = StpDetector::default();
        let mut config = BilgepumpConfig::default();
        config.stp_root_whitelist = vec!["8000.aabbccddeeff".to_string()];
        let t = now();

        let alerts = det.observe(
            &stp_bpdu("8000.aabbccddeeff", "8000.aabbccddeeff"),
            &config,
            t,
        );
        assert!(
            !alerts
                .iter()
                .any(|a| a.decoder == "bilgepump:stp_unauthorized")
        );
    }
}
