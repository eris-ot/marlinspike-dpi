//! Ethernet padding extraction and analysis.

/// Extract the padding region from an Ethernet frame payload.
///
/// Returns `Some((offset, padding_bytes))` if the frame has padding, where
/// `offset` is relative to `l2_payload` (the bytes after the Ethernet header).
///
/// Padding detection works differently based on the frame type:
/// - For IPv4 (`ethertype == 0x0800`): real payload ends at IP total length.
///   Anything beyond that in the Ethernet frame is padding.
/// - For 802.3 length frames (`ethertype <= 1500`): the ethertype field *is*
///   the payload length. Bytes beyond that are padding.
/// - For other ethertypes: no reliable padding boundary, returns `None`.
pub fn extract_padding(
    ethertype: u16,
    l2_payload: &[u8],
    ethernet_header_len: usize,
    _total_frame_len: usize,
) -> Option<(usize, &[u8])> {
    let real_payload_len = if ethertype == 0x0800 && l2_payload.len() >= 4 {
        // IPv4: total length is at bytes 2..4 of the IP header
        u16::from_be_bytes([l2_payload[2], l2_payload[3]]) as usize
    } else if ethertype <= 1500 {
        // 802.3 length field
        ethertype as usize
    } else {
        return None;
    };

    // Minimum Ethernet payload is 46 bytes (60-byte frame minus 14-byte header).
    // If the real payload is smaller, the frame was padded to reach 46 bytes.
    let min_payload = 46;
    let actual_payload_len = l2_payload.len();

    if real_payload_len < actual_payload_len && real_payload_len < min_payload {
        let padding_start = real_payload_len;
        // Padding runs from end of real payload to end of captured L2 payload,
        // but not beyond the minimum Ethernet payload boundary.
        let padding_end = actual_payload_len.min(min_payload);
        if padding_start < padding_end {
            return Some((
                ethernet_header_len + padding_start,
                &l2_payload[padding_start..padding_end],
            ));
        }
    } else if real_payload_len < actual_payload_len {
        // Payload is >= 46 but frame has trailing bytes beyond IP total length.
        // This can happen when FCS is captured or there's genuine extra data.
        let padding_start = real_payload_len;
        if padding_start < actual_payload_len {
            return Some((
                ethernet_header_len + padding_start,
                &l2_payload[padding_start..],
            ));
        }
    }

    None
}

/// Compute Shannon entropy of a byte slice, normalized to [0.0, 8.0].
///
/// Returns 0.0 for empty slices. All-zero padding has entropy 0.0.
/// Random data approaches 8.0.
pub fn shannon_entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }

    let mut counts = [0u64; 256];
    for &b in data {
        counts[b as usize] += 1;
    }

    let len = data.len() as f64;
    let mut entropy = 0.0;
    for &count in &counts {
        if count > 0 {
            let p = count as f64 / len;
            entropy -= p * p.log2();
        }
    }

    entropy
}

/// Check if a padding region contains any non-zero bytes.
pub fn has_nonzero_padding(padding: &[u8]) -> bool {
    padding.iter().any(|&b| b != 0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn entropy_all_zeros() {
        assert_eq!(shannon_entropy(&[0u8; 32]), 0.0);
    }

    #[test]
    fn entropy_uniform() {
        // All 256 byte values equally represented
        let data: Vec<u8> = (0..=255).collect();
        let e = shannon_entropy(&data);
        assert!((e - 8.0).abs() < 0.01, "expected ~8.0, got {e}");
    }

    #[test]
    fn entropy_two_values() {
        let data = vec![0u8, 1, 0, 1, 0, 1, 0, 1];
        let e = shannon_entropy(&data);
        assert!((e - 1.0).abs() < 0.01, "expected ~1.0, got {e}");
    }

    #[test]
    fn entropy_empty() {
        assert_eq!(shannon_entropy(&[]), 0.0);
    }

    #[test]
    fn extract_ipv4_padding() {
        // IP header with total_length = 28 (20 header + 8 payload)
        // sitting in a 46-byte L2 payload (frame was padded to min 60)
        let mut l2 = vec![0u8; 46];
        l2[0] = 0x45; // version + IHL
        l2[2] = 0x00;
        l2[3] = 28; // total length = 28
        // Bytes 28..46 should be padding
        let result = extract_padding(0x0800, &l2, 14, 60);
        assert!(result.is_some());
        let (offset, padding) = result.unwrap();
        assert_eq!(offset, 14 + 28); // ethernet header + IP total length
        assert_eq!(padding.len(), 46 - 28);
    }

    #[test]
    fn no_padding_full_payload() {
        // IP total_length == l2_payload length — no padding
        let mut l2 = vec![0u8; 100];
        l2[0] = 0x45;
        l2[2] = 0x00;
        l2[3] = 100; // total_length matches actual
        let result = extract_padding(0x0800, &l2, 14, 114);
        assert!(result.is_none());
    }

    #[test]
    fn nonzero_padding_detected() {
        assert!(has_nonzero_padding(&[0, 0, 0x42, 0]));
        assert!(!has_nonzero_padding(&[0, 0, 0, 0]));
    }
}
