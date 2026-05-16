//! Stovetop finding types and their conversion to Bronze events.

/// Severity of a frame-level finding.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FindingSeverity {
    Low,
    Medium,
    High,
    Critical,
}

impl FindingSeverity {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Low => "low",
            Self::Medium => "medium",
            Self::High => "high",
            Self::Critical => "critical",
        }
    }
}

/// Specific kind of frame-level anomaly detected.
#[derive(Debug, Clone)]
pub enum FindingKind {
    /// Frame on wire was shorter than Ethernet minimum.
    RuntFrame {
        actual_len: u32,
        min_expected: usize,
    },
    /// Frame on wire exceeded maximum Ethernet size.
    OversizedFrame {
        actual_len: u32,
        max_expected: usize,
    },
    /// Capture snapped the frame — captured bytes < original length.
    TruncatedCapture { captured_len: usize, orig_len: u32 },
    /// Ethernet padding region contains non-zero bytes.
    NonZeroPadding {
        padding_offset: usize,
        padding_len: usize,
        entropy: f64,
        padding_hex: String,
    },
    /// Ethernet FCS present and invalid.
    FcsInvalid { expected: u32, actual: u32 },
    /// DNP3 DLL CRC mismatch.
    Dnp3CrcInvalid {
        block_offset: usize,
        expected: u16,
        actual: u16,
    },
    /// ICMP redirect — routing manipulation attempt.
    IcmpRedirect {
        icmp_type: u8,
        icmp_code: u8,
        gateway_ip: String,
    },
    /// ICMP echo with high-entropy or oversized payload — possible tunnel.
    IcmpTunnel {
        icmp_type: u8,
        payload_len: usize,
        entropy: f64,
    },
    /// Deprecated or unusual ICMP type observed.
    IcmpSuspiciousType {
        icmp_type: u8,
        icmp_code: u8,
        type_name: String,
    },
    /// ICMP unreachable flood indicator — many in a short window.
    IcmpUnreachableFlood { count: usize },
}

/// A single finding from the stovetop inspector.
#[derive(Debug, Clone)]
pub struct FrameFinding {
    pub kind: FindingKind,
    pub severity: FindingSeverity,
    /// Decoder tag for the Bronze `ParseAnomaly` event.
    pub decoder: &'static str,
}

impl FrameFinding {
    /// Human-readable reason string for the Bronze `ParseAnomaly`.
    pub fn reason(&self) -> String {
        match &self.kind {
            FindingKind::RuntFrame {
                actual_len,
                min_expected,
            } => {
                format!("runt frame: {actual_len} bytes on wire, minimum {min_expected}")
            }
            FindingKind::OversizedFrame {
                actual_len,
                max_expected,
            } => {
                format!("oversized frame: {actual_len} bytes on wire, maximum {max_expected}")
            }
            FindingKind::TruncatedCapture {
                captured_len,
                orig_len,
            } => {
                format!("truncated capture: {captured_len} bytes captured of {orig_len} original")
            }
            FindingKind::NonZeroPadding {
                padding_offset,
                padding_len,
                entropy,
                ..
            } => {
                format!(
                    "non-zero ethernet padding at offset {padding_offset}, \
                     {padding_len} bytes, entropy {entropy:.2}"
                )
            }
            FindingKind::FcsInvalid { expected, actual } => {
                format!("ethernet FCS invalid: expected {expected:#010x}, got {actual:#010x}")
            }
            FindingKind::Dnp3CrcInvalid {
                block_offset,
                expected,
                actual,
            } => {
                format!(
                    "DNP3 DLL CRC invalid at offset {block_offset}: \
                     expected {expected:#06x}, got {actual:#06x}"
                )
            }
            FindingKind::IcmpRedirect {
                icmp_type,
                icmp_code,
                gateway_ip,
            } => {
                format!(
                    "ICMP redirect (type {icmp_type}, code {icmp_code}) \
                     via gateway {gateway_ip}"
                )
            }
            FindingKind::IcmpTunnel {
                icmp_type,
                payload_len,
                entropy,
            } => {
                format!(
                    "possible ICMP tunnel: type {icmp_type}, \
                     {payload_len} byte payload, entropy {entropy:.2}"
                )
            }
            FindingKind::IcmpSuspiciousType {
                icmp_type,
                icmp_code,
                type_name,
            } => {
                format!("suspicious ICMP type {icmp_type} code {icmp_code}: {type_name}")
            }
            FindingKind::IcmpUnreachableFlood { count } => {
                format!("ICMP unreachable flood: {count} messages in window")
            }
        }
    }
}
