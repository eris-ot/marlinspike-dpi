//! CRC and integrity validation for frame and protocol layers.

/// Compute Ethernet CRC-32 (IEEE 802.3) over a frame.
///
/// Standard polynomial: 0x04C11DB7 (reflected: 0xEDB88320).
/// The FCS is the CRC-32 of all bytes in the frame (excluding the FCS itself).
pub fn ethernet_crc32(data: &[u8]) -> u32 {
    let mut crc: u32 = 0xFFFF_FFFF;
    for &byte in data {
        crc ^= byte as u32;
        for _ in 0..8 {
            if crc & 1 != 0 {
                crc = (crc >> 1) ^ 0xEDB8_8320;
            } else {
                crc >>= 1;
            }
        }
    }
    crc ^ 0xFFFF_FFFF
}

/// Validate Ethernet FCS (last 4 bytes of frame).
///
/// Returns `Some((expected, actual))` if FCS is present and can be checked.
/// Returns `None` if the frame is too short or FCS detection is inconclusive.
///
/// # Heuristic
/// Many capture tools strip FCS. We only check if `captured_len` matches
/// `orig_len` (no truncation) and the frame is at least 64 bytes (the
/// standard minimum including FCS).
pub fn validate_ethernet_fcs(
    frame: &[u8],
    captured_len: usize,
    orig_len: u32,
) -> Option<(u32, u32, bool)> {
    // FCS is only present if the capture didn't truncate and frame >= 64 bytes
    if captured_len < orig_len as usize || frame.len() < 64 {
        return None;
    }

    // If captured_len == orig_len and frame is >= 64 bytes, the last 4 bytes
    // might be FCS. Compute and check.
    let fcs_offset = frame.len() - 4;
    let actual_fcs = u32::from_le_bytes([
        frame[fcs_offset],
        frame[fcs_offset + 1],
        frame[fcs_offset + 2],
        frame[fcs_offset + 3],
    ]);
    let expected_fcs = ethernet_crc32(&frame[..fcs_offset]);

    Some((expected_fcs, actual_fcs, expected_fcs == actual_fcs))
}

/// DNP3 CRC-16 polynomial: 0x3D65 (reflected: 0xA6BC).
///
/// DNP3 uses CRC-16/DNP on each 16-byte data-link block plus a 2-byte CRC.
pub fn dnp3_crc16(data: &[u8]) -> u16 {
    let mut crc: u16 = 0x0000;
    for &byte in data {
        let mut temp = byte as u16;
        for _ in 0..8 {
            if (crc ^ temp) & 0x0001 != 0 {
                crc = (crc >> 1) ^ 0xA6BC;
            } else {
                crc >>= 1;
            }
            temp >>= 1;
        }
    }
    crc ^ 0xFFFF
}

/// Validate DNP3 data-link layer CRCs.
///
/// DNP3 DLL structure:
/// - Header block: 8 bytes (start + length + control + dst + src) + 2-byte CRC
/// - User data blocks: up to 16 data bytes + 2-byte CRC each
///
/// Returns a list of `(block_offset, expected_crc, actual_crc)` for invalid blocks.
pub fn validate_dnp3_dll_crcs(data: &[u8]) -> Vec<(usize, u16, u16)> {
    let mut failures = Vec::new();

    // Need at least start(2) + length(1) + control(1) + dst(2) + src(2) + CRC(2) = 10
    if data.len() < 10 || data[0] != 0x05 || data[1] != 0x64 {
        return failures;
    }

    // Validate header CRC (bytes 0..8, CRC at bytes 8..10)
    let header_crc = u16::from_le_bytes([data[8], data[9]]);
    let expected_header_crc = dnp3_crc16(&data[0..8]);
    if header_crc != expected_header_crc {
        failures.push((0, expected_header_crc, header_crc));
    }

    // Validate user data block CRCs
    // DLL length field (data[2]) gives the number of bytes after the length
    // field up to but not including the CRCs. The user data starts at offset 10.
    let mut offset = 10;
    while offset < data.len() {
        let remaining = data.len() - offset;
        if remaining < 3 {
            // Need at least 1 data byte + 2-byte CRC
            break;
        }

        // Each user data block is up to 16 bytes + 2-byte CRC
        let block_data_len = remaining.saturating_sub(2).min(16);
        let crc_offset = offset + block_data_len;
        if crc_offset + 2 > data.len() {
            break;
        }

        let block_crc = u16::from_le_bytes([data[crc_offset], data[crc_offset + 1]]);
        let expected_crc = dnp3_crc16(&data[offset..offset + block_data_len]);
        if block_crc != expected_crc {
            failures.push((offset, expected_crc, block_crc));
        }

        offset = crc_offset + 2;
    }

    failures
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn crc32_known_value() {
        // "123456789" has a well-known CRC-32 of 0xCBF43926
        let data = b"123456789";
        assert_eq!(ethernet_crc32(data), 0xCBF4_3926);
    }

    #[test]
    fn crc32_empty() {
        assert_eq!(ethernet_crc32(&[]), 0x0000_0000);
    }

    #[test]
    fn dnp3_crc16_header() {
        // DNP3 header block: start(05 64) + len(05) + ctrl(C0) + dst(01 00) + src(02 00)
        let header = [0x05, 0x64, 0x05, 0xC0, 0x01, 0x00, 0x02, 0x00];
        let crc = dnp3_crc16(&header);
        // Just verify it produces a deterministic non-zero value
        assert_ne!(crc, 0);
    }

    #[test]
    fn validate_dnp3_with_correct_crc() {
        let header_data = [0x05u8, 0x64, 0x05, 0xC0, 0x01, 0x00, 0x02, 0x00];
        let crc = dnp3_crc16(&header_data);
        let mut frame = header_data.to_vec();
        frame.extend_from_slice(&crc.to_le_bytes());

        let failures = validate_dnp3_dll_crcs(&frame);
        assert!(failures.is_empty(), "expected no CRC failures");
    }

    #[test]
    fn validate_dnp3_with_bad_crc() {
        let frame = vec![0x05, 0x64, 0x05, 0xC0, 0x01, 0x00, 0x02, 0x00, 0xAA, 0xBB];
        let failures = validate_dnp3_dll_crcs(&frame);
        assert_eq!(failures.len(), 1);
        assert_eq!(failures[0].0, 0); // header block
        assert_eq!(failures[0].2, 0xBBAA); // actual CRC (little-endian)
    }
}
