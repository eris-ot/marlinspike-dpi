//! ICMPeeker — ICMP anomaly detection for routing manipulation, tunneling, and recon.
//!
//! Inspects ICMP packets for malicious patterns that protocol-level dissection
//! alone cannot flag. Runs post-decoder alongside the ICMP dissector: the
//! dissector provides protocol visibility (ProtocolTransaction), ICMPeeker
//! provides the threat signal (ParseAnomaly).

use crate::stovetop::findings::{FindingKind, FindingSeverity, FrameFinding};
use crate::stovetop::padding::shannon_entropy;

/// ICMP type constants.
const ICMP_ECHO_REPLY: u8 = 0;
const ICMP_REDIRECT: u8 = 5;
const ICMP_ECHO_REQUEST: u8 = 8;
const ICMP_ROUTER_ADVERTISEMENT: u8 = 9;
const ICMP_ROUTER_SOLICITATION: u8 = 10;
const ICMP_TIMESTAMP_REQUEST: u8 = 13;
const ICMP_TIMESTAMP_REPLY: u8 = 14;
const ICMP_ADDRESS_MASK_REQUEST: u8 = 17;
const ICMP_ADDRESS_MASK_REPLY: u8 = 18;

/// Minimum ICMP echo payload size to consider for tunnel detection.
const TUNNEL_MIN_PAYLOAD: usize = 64;

/// Entropy threshold for echo payloads — above this is suspicious.
const TUNNEL_ENTROPY_THRESHOLD: f64 = 6.0;

/// Configuration for ICMPeeker anomaly detection.
#[derive(Debug, Clone)]
pub struct IcmpeekerConfig {
    /// Master enable switch.
    pub enabled: bool,
    /// Flag ICMP redirect messages (routing manipulation).
    pub check_redirects: bool,
    /// Flag high-entropy echo payloads (tunnel detection).
    pub check_tunnels: bool,
    /// Flag deprecated/suspicious ICMP types (recon/fingerprinting).
    pub check_suspicious_types: bool,
    /// Minimum echo payload size for tunnel analysis (bytes).
    pub tunnel_min_payload: usize,
    /// Shannon entropy threshold for tunnel detection (0.0-8.0).
    pub tunnel_entropy_threshold: f64,
}

impl Default for IcmpeekerConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            check_redirects: true,
            check_tunnels: true,
            check_suspicious_types: true,
            tunnel_min_payload: TUNNEL_MIN_PAYLOAD,
            tunnel_entropy_threshold: TUNNEL_ENTROPY_THRESHOLD,
        }
    }
}

/// Inspect an ICMP packet for anomalies.
///
/// `icmp_payload` starts at the ICMP header (type, code, checksum, ...).
pub fn inspect(config: &IcmpeekerConfig, icmp_payload: &[u8]) -> Vec<FrameFinding> {
    if !config.enabled || icmp_payload.len() < 4 {
        return Vec::new();
    }

    let mut findings = Vec::new();
    let icmp_type = icmp_payload[0];
    let icmp_code = icmp_payload[1];

    // ICMP Redirect — routing manipulation
    if config.check_redirects && icmp_type == ICMP_REDIRECT {
        let gateway_ip = if icmp_payload.len() >= 8 {
            format!(
                "{}.{}.{}.{}",
                icmp_payload[4], icmp_payload[5], icmp_payload[6], icmp_payload[7]
            )
        } else {
            "unknown".to_string()
        };
        findings.push(FrameFinding {
            kind: FindingKind::IcmpRedirect {
                icmp_type,
                icmp_code,
                gateway_ip,
            },
            severity: FindingSeverity::Critical,
            decoder: "icmpeeker:redirect",
        });
    }

    // ICMP Echo tunnel detection
    if config.check_tunnels && (icmp_type == ICMP_ECHO_REQUEST || icmp_type == ICMP_ECHO_REPLY) {
        // Echo header: type(1) + code(1) + checksum(2) + id(2) + seq(2) = 8 bytes
        if icmp_payload.len() > 8 {
            let echo_data = &icmp_payload[8..];
            if echo_data.len() >= config.tunnel_min_payload {
                let entropy = shannon_entropy(echo_data);
                if entropy > config.tunnel_entropy_threshold {
                    findings.push(FrameFinding {
                        kind: FindingKind::IcmpTunnel {
                            icmp_type,
                            payload_len: echo_data.len(),
                            entropy,
                        },
                        severity: FindingSeverity::High,
                        decoder: "icmpeeker:tunnel",
                    });
                }
            }
        }
    }

    // Router advertisement / solicitation — rogue router injection
    if config.check_suspicious_types
        && (icmp_type == ICMP_ROUTER_ADVERTISEMENT || icmp_type == ICMP_ROUTER_SOLICITATION)
    {
        findings.push(FrameFinding {
            kind: FindingKind::IcmpSuspiciousType {
                icmp_type,
                icmp_code,
                type_name: icmp_type_name(icmp_type).to_string(),
            },
            severity: FindingSeverity::High,
            decoder: "icmpeeker:suspicious",
        });
    }

    // Deprecated types — info leakage / fingerprinting
    if config.check_suspicious_types
        && matches!(
            icmp_type,
            ICMP_TIMESTAMP_REQUEST
                | ICMP_TIMESTAMP_REPLY
                | ICMP_ADDRESS_MASK_REQUEST
                | ICMP_ADDRESS_MASK_REPLY
        )
    {
        findings.push(FrameFinding {
            kind: FindingKind::IcmpSuspiciousType {
                icmp_type,
                icmp_code,
                type_name: icmp_type_name(icmp_type).to_string(),
            },
            severity: FindingSeverity::Medium,
            decoder: "icmpeeker:suspicious",
        });
    }

    findings
}

/// Human-readable ICMP type name.
pub fn icmp_type_name(icmp_type: u8) -> &'static str {
    match icmp_type {
        0 => "Echo Reply",
        3 => "Destination Unreachable",
        4 => "Source Quench",
        5 => "Redirect",
        8 => "Echo Request",
        9 => "Router Advertisement",
        10 => "Router Solicitation",
        11 => "Time Exceeded",
        12 => "Parameter Problem",
        13 => "Timestamp Request",
        14 => "Timestamp Reply",
        17 => "Address Mask Request",
        18 => "Address Mask Reply",
        _ => "Unknown",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn default_config() -> IcmpeekerConfig {
        IcmpeekerConfig::default()
    }

    #[test]
    fn detect_icmp_redirect() {
        let config = default_config();
        let icmp = vec![5, 1, 0, 0, 10, 0, 0, 1];
        let findings = inspect(&config, &icmp);
        assert!(findings.iter().any(|f| f.decoder == "icmpeeker:redirect"));
        if let FindingKind::IcmpRedirect { gateway_ip, .. } = &findings[0].kind {
            assert_eq!(gateway_ip, "10.0.0.1");
        } else {
            panic!("expected IcmpRedirect finding");
        }
    }

    #[test]
    fn detect_icmp_tunnel() {
        let config = default_config();
        let mut icmp = vec![8, 0, 0, 0, 0, 1, 0, 1];
        for i in 0..128u8 {
            icmp.push(i.wrapping_mul(137).wrapping_add(43));
        }
        let findings = inspect(&config, &icmp);
        assert!(
            findings.iter().any(|f| f.decoder == "icmpeeker:tunnel"),
            "expected tunnel finding for high-entropy echo payload"
        );
    }

    #[test]
    fn no_tunnel_for_normal_ping() {
        let config = default_config();
        let mut icmp = vec![8, 0, 0, 0, 0, 1, 0, 1];
        icmp.extend_from_slice(&[0u8; 64]);
        let findings = inspect(&config, &icmp);
        assert!(
            !findings.iter().any(|f| f.decoder == "icmpeeker:tunnel"),
            "should not flag zero-payload ping as tunnel"
        );
    }

    #[test]
    fn detect_router_advertisement() {
        let config = default_config();
        let icmp = vec![9, 0, 0, 0];
        let findings = inspect(&config, &icmp);
        assert!(findings.iter().any(|f| f.decoder == "icmpeeker:suspicious"));
    }

    #[test]
    fn detect_timestamp_request() {
        let config = default_config();
        let icmp = vec![13, 0, 0, 0];
        let findings = inspect(&config, &icmp);
        assert!(findings.iter().any(|f| f.decoder == "icmpeeker:suspicious"));
    }

    #[test]
    fn detect_address_mask_request() {
        let config = default_config();
        let icmp = vec![17, 0, 0, 0];
        let findings = inspect(&config, &icmp);
        assert!(findings.iter().any(|f| f.decoder == "icmpeeker:suspicious"));
    }

    #[test]
    fn disabled_returns_nothing() {
        let mut config = default_config();
        config.enabled = false;
        let icmp = vec![5, 1, 0, 0, 10, 0, 0, 1];
        let findings = inspect(&config, &icmp);
        assert!(findings.is_empty());
    }
}
