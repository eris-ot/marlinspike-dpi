//! Configuration for stovetop frame-level inspection.

/// Controls which stovetop checks are enabled and their thresholds.
#[derive(Debug, Clone)]
pub struct StovetopConfig {
    /// Master enable switch.
    pub enabled: bool,
    /// Flag frames whose original length is below the Ethernet minimum (64 bytes).
    pub check_runt_frames: bool,
    /// Flag frames whose original length exceeds the Ethernet maximum.
    pub check_oversized_frames: bool,
    /// Flag frames where captured length < original length.
    pub check_truncation: bool,
    /// Inspect Ethernet padding bytes for non-zero content.
    pub check_padding: bool,
    /// Validate Ethernet FCS when present.
    pub check_fcs: bool,
    /// Validate protocol-level CRCs (e.g. DNP3 DLL CRC-16).
    pub check_protocol_crc: bool,
    /// Minimum Ethernet frame size on the wire (including FCS).
    pub min_ethernet_frame: usize,
    /// Maximum Ethernet frame size (standard, not jumbo).
    pub max_ethernet_frame: usize,
    /// Maximum Ethernet frame size when jumbo frames are allowed.
    pub max_jumbo_frame: usize,
    /// Padding bytes with Shannon entropy above this are flagged as suspicious.
    pub padding_entropy_threshold: f64,
}

impl Default for StovetopConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            check_runt_frames: true,
            check_oversized_frames: true,
            check_truncation: true,
            check_padding: true,
            check_fcs: true,
            check_protocol_crc: true,
            min_ethernet_frame: 60, // 64 on wire minus 4-byte FCS (captures typically strip FCS)
            max_ethernet_frame: 1514, // 1518 minus FCS
            max_jumbo_frame: 9018,  // 9022 minus FCS
            padding_entropy_threshold: 0.5,
        }
    }
}
