//! VLAN hopping detection.

use crate::bilgepump::alerts::{AlertKind, AlertSeverity, BilgepumpAlert};
use crate::bilgepump::config::BilgepumpConfig;

/// Inspect raw Ethernet frame bytes for double-tagged 802.1Q (VLAN hopping).
///
/// Must be called BEFORE VLAN tags are unwrapped by the engine. Examines
/// the raw frame starting at the ethertype field (bytes 12-13).
pub fn inspect_vlan_tags(raw_frame: &[u8], config: &BilgepumpConfig) -> Vec<BilgepumpAlert> {
    if !config.check_vlan_hopping || raw_frame.len() < 22 {
        return Vec::new();
    }

    let ethertype = u16::from_be_bytes([raw_frame[12], raw_frame[13]]);

    // First tag must be 802.1Q (0x8100), 802.1ad (0x88A8), or QinQ (0x9100)
    if !matches!(ethertype, 0x8100 | 0x88A8 | 0x9100) {
        return Vec::new();
    }

    let outer_vlan = u16::from_be_bytes([raw_frame[14], raw_frame[15]]) & 0x0FFF;
    let inner_ethertype = u16::from_be_bytes([raw_frame[16], raw_frame[17]]);

    // Double-tagged: second ethertype is also a VLAN tag
    if matches!(inner_ethertype, 0x8100 | 0x88A8 | 0x9100) && raw_frame.len() >= 22 {
        let inner_vlan = u16::from_be_bytes([raw_frame[18], raw_frame[19]]) & 0x0FFF;

        if outer_vlan != inner_vlan {
            return vec![BilgepumpAlert {
                kind: AlertKind::VlanHopping {
                    outer_vlan,
                    inner_vlan,
                },
                severity: AlertSeverity::Critical,
                decoder: "bilgepump:vlan_hop",
            }];
        }
    }

    Vec::new()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_double_tagged(outer_vlan: u16, inner_vlan: u16) -> Vec<u8> {
        let mut frame = Vec::new();
        frame.extend_from_slice(&[0xFF; 6]); // dst mac
        frame.extend_from_slice(&[0x00; 6]); // src mac
        // Outer 802.1Q tag
        frame.extend_from_slice(&0x8100u16.to_be_bytes());
        frame.extend_from_slice(&outer_vlan.to_be_bytes());
        // Inner 802.1Q tag
        frame.extend_from_slice(&0x8100u16.to_be_bytes());
        frame.extend_from_slice(&inner_vlan.to_be_bytes());
        // Inner ethertype (IPv4)
        frame.extend_from_slice(&0x0800u16.to_be_bytes());
        // Some payload
        frame.extend_from_slice(&[0u8; 20]);
        frame
    }

    #[test]
    fn detect_vlan_hopping() {
        let config = BilgepumpConfig::default();
        let frame = make_double_tagged(100, 200);
        let alerts = inspect_vlan_tags(&frame, &config);
        assert!(
            alerts.iter().any(|a| a.decoder == "bilgepump:vlan_hop"),
            "expected VLAN hopping alert"
        );
    }

    #[test]
    fn same_vlan_double_tag_no_alert() {
        let config = BilgepumpConfig::default();
        let frame = make_double_tagged(100, 100);
        let alerts = inspect_vlan_tags(&frame, &config);
        assert!(alerts.is_empty(), "same VLAN double-tag should not alert");
    }

    #[test]
    fn single_tag_no_alert() {
        let config = BilgepumpConfig::default();
        let mut frame = Vec::new();
        frame.extend_from_slice(&[0xFF; 6]);
        frame.extend_from_slice(&[0x00; 6]);
        frame.extend_from_slice(&0x8100u16.to_be_bytes());
        frame.extend_from_slice(&100u16.to_be_bytes());
        frame.extend_from_slice(&0x0800u16.to_be_bytes()); // IPv4, not another VLAN
        frame.extend_from_slice(&[0u8; 20]);
        let alerts = inspect_vlan_tags(&frame, &config);
        assert!(alerts.is_empty());
    }
}
