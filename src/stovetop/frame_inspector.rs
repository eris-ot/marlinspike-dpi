//! Pre-dissector frame-level inspection.

use super::config::StovetopConfig;
use super::findings::{FindingKind, FindingSeverity, FrameFinding};
use super::padding::{extract_padding, has_nonzero_padding, shannon_entropy};

/// Inspects raw Ethernet frames for structural anomalies before protocol
/// dissection. Runs on every packet in the engine's hot path.
pub struct FrameInspector {
    config: StovetopConfig,
}

impl FrameInspector {
    pub fn new(config: StovetopConfig) -> Self {
        Self { config }
    }

    /// Inspect a raw frame and return any findings.
    ///
    /// - `raw_frame`: the full captured frame bytes (starting at Ethernet header)
    /// - `captured_len`: number of bytes actually captured
    /// - `orig_len`: original frame length on the wire (from pcap/pcapng header)
    /// - `ethertype`: parsed ethertype (after VLAN unwrapping)
    /// - `l2_payload`: payload after Ethernet header + VLAN tags
    /// - `ethernet_header_len`: bytes consumed by Ethernet header + VLANs
    pub fn inspect_frame(
        &self,
        raw_frame: &[u8],
        captured_len: usize,
        orig_len: u32,
        ethertype: u16,
        l2_payload: &[u8],
        ethernet_header_len: usize,
    ) -> Vec<FrameFinding> {
        if !self.config.enabled {
            return Vec::new();
        }

        let mut findings = Vec::new();

        if self.config.check_runt_frames {
            self.check_runt(orig_len, &mut findings);
        }
        if self.config.check_oversized_frames {
            self.check_oversized(orig_len, &mut findings);
        }
        if self.config.check_truncation {
            self.check_truncation(captured_len, orig_len, &mut findings);
        }
        if self.config.check_padding {
            self.check_padding(
                ethertype,
                l2_payload,
                ethernet_header_len,
                raw_frame.len(),
                &mut findings,
            );
        }
        if self.config.check_fcs {
            self.check_fcs(raw_frame, captured_len, orig_len, &mut findings);
        }

        findings
    }

    fn check_runt(&self, orig_len: u32, findings: &mut Vec<FrameFinding>) {
        if (orig_len as usize) < self.config.min_ethernet_frame && orig_len > 0 {
            findings.push(FrameFinding {
                kind: FindingKind::RuntFrame {
                    actual_len: orig_len,
                    min_expected: self.config.min_ethernet_frame,
                },
                severity: FindingSeverity::Medium,
                decoder: "stovetop:runt",
            });
        }
    }

    fn check_oversized(&self, orig_len: u32, findings: &mut Vec<FrameFinding>) {
        if (orig_len as usize) > self.config.max_ethernet_frame {
            let severity = if (orig_len as usize) > self.config.max_jumbo_frame {
                FindingSeverity::High
            } else {
                FindingSeverity::Low // within jumbo range, just noting it
            };
            findings.push(FrameFinding {
                kind: FindingKind::OversizedFrame {
                    actual_len: orig_len,
                    max_expected: self.config.max_ethernet_frame,
                },
                severity,
                decoder: "stovetop:oversized",
            });
        }
    }

    fn check_truncation(
        &self,
        captured_len: usize,
        orig_len: u32,
        findings: &mut Vec<FrameFinding>,
    ) {
        if captured_len < orig_len as usize {
            findings.push(FrameFinding {
                kind: FindingKind::TruncatedCapture {
                    captured_len,
                    orig_len,
                },
                severity: FindingSeverity::Low,
                decoder: "stovetop:truncated",
            });
        }
    }

    fn check_padding(
        &self,
        ethertype: u16,
        l2_payload: &[u8],
        ethernet_header_len: usize,
        total_frame_len: usize,
        findings: &mut Vec<FrameFinding>,
    ) {
        let Some((offset, padding)) =
            extract_padding(ethertype, l2_payload, ethernet_header_len, total_frame_len)
        else {
            return;
        };

        if !has_nonzero_padding(padding) {
            return;
        }

        let entropy = shannon_entropy(padding);
        let severity = if entropy > self.config.padding_entropy_threshold {
            FindingSeverity::High // high entropy non-zero padding = possible covert channel
        } else {
            FindingSeverity::Medium // non-zero but low entropy = implementation quirk or leak
        };

        findings.push(FrameFinding {
            kind: FindingKind::NonZeroPadding {
                padding_offset: offset,
                padding_len: padding.len(),
                entropy,
                padding_hex: hex::encode(&padding[..padding.len().min(32)]),
            },
            severity,
            decoder: "stovetop:padding",
        });
    }

    fn check_fcs(
        &self,
        raw_frame: &[u8],
        captured_len: usize,
        orig_len: u32,
        findings: &mut Vec<FrameFinding>,
    ) {
        use super::integrity::validate_ethernet_fcs;

        if let Some((expected, actual, valid)) =
            validate_ethernet_fcs(raw_frame, captured_len, orig_len)
            && !valid
        {
            findings.push(FrameFinding {
                kind: FindingKind::FcsInvalid { expected, actual },
                severity: FindingSeverity::High,
                decoder: "stovetop:fcs",
            });
        }
    }
}

impl Default for FrameInspector {
    fn default() -> Self {
        Self::new(StovetopConfig::default())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_inspector() -> FrameInspector {
        FrameInspector::default()
    }

    #[test]
    fn detect_runt_frame() {
        let inspector = make_inspector();
        let frame = vec![0u8; 40]; // way below 60
        let findings = inspector.inspect_frame(&frame, 40, 40, 0x0800, &frame[14..], 14);
        assert!(
            findings.iter().any(|f| f.decoder == "stovetop:runt"),
            "expected runt finding"
        );
    }

    #[test]
    fn no_runt_for_normal_frame() {
        let inspector = make_inspector();
        let frame = vec![0u8; 64];
        let findings = inspector.inspect_frame(&frame, 64, 64, 0x0800, &frame[14..], 14);
        assert!(
            !findings.iter().any(|f| f.decoder == "stovetop:runt"),
            "should not flag normal-sized frame as runt"
        );
    }

    #[test]
    fn detect_oversized_frame() {
        let inspector = make_inspector();
        let frame = vec![0u8; 64];
        // orig_len says 2000 bytes on wire
        let findings = inspector.inspect_frame(&frame, 64, 2000, 0x0800, &frame[14..], 14);
        assert!(
            findings.iter().any(|f| f.decoder == "stovetop:oversized"),
            "expected oversized finding"
        );
    }

    #[test]
    fn detect_truncation() {
        let inspector = make_inspector();
        let frame = vec![0u8; 64];
        let findings = inspector.inspect_frame(&frame, 64, 128, 0x0800, &frame[14..], 14);
        assert!(
            findings.iter().any(|f| f.decoder == "stovetop:truncated"),
            "expected truncation finding"
        );
    }

    #[test]
    fn detect_nonzero_padding() {
        let inspector = make_inspector();
        // Build a frame with a short IPv4 packet padded to 60 bytes
        let mut frame = vec![0u8; 60];
        // Ethernet header (14 bytes)
        frame[12] = 0x08;
        frame[13] = 0x00; // ethertype = 0x0800
        // IP header at offset 14
        frame[14] = 0x45; // version 4, IHL 5
        frame[16] = 0x00;
        frame[17] = 0x1C; // total_length = 28 (20 header + 8 payload)
        // Padding starts at 14 + 28 = 42. Put non-zero data there.
        for byte in frame.iter_mut().take(60).skip(42) {
            *byte = 0xAA;
        }
        let l2_payload = &frame[14..];
        let findings = inspector.inspect_frame(&frame, 60, 60, 0x0800, l2_payload, 14);
        assert!(
            findings.iter().any(|f| f.decoder == "stovetop:padding"),
            "expected non-zero padding finding"
        );
    }

    #[test]
    fn disabled_returns_nothing() {
        let mut config = StovetopConfig::default();
        config.enabled = false;
        let inspector = FrameInspector::new(config);
        let frame = vec![0u8; 20]; // runt
        let findings = inspector.inspect_frame(&frame, 20, 20, 0x0800, &frame[14..], 14);
        assert!(findings.is_empty());
    }
}
