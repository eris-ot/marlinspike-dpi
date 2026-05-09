//! IEEE C37.118 common frame header. Every frame starts with this 14-byte
//! header followed by a frame-type-specific body and a 2-byte CRC-CCITT
//! checksum at the end.

use crate::synchrophasor::reader::{Reader, ReaderError};

/// First sync byte — always 0xAA for IEEE C37.118 frames.
pub const SYNC_BYTE: u8 = 0xAA;

/// Frame type, extracted from bits 4-6 of the second sync byte.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FrameType {
    Data,
    Header,
    Config1,
    Config2,
    Config3,
    Command,
}

impl FrameType {
    fn from_byte(b: u8) -> Option<Self> {
        match (b >> 4) & 0x07 {
            0 => Some(Self::Data),
            1 => Some(Self::Header),
            2 => Some(Self::Config1),
            3 => Some(Self::Config2),
            4 => Some(Self::Command),
            5 => Some(Self::Config3),
            _ => None,
        }
    }
}

/// Decoded common header.
#[derive(Debug, Clone)]
pub struct CommonHeader {
    pub frame_type: FrameType,
    /// Protocol version (low 4 bits of sync byte 1). 1 = IEEE Std 1344-1995,
    /// 2 = IEEE Std C37.118-2005, 3 = IEEE Std C37.118.2-2011.
    pub version: u8,
    pub framesize: u16,
    pub idcode: u16,
    /// Second-of-century (UNIX timestamp from 1970-01-01 in C37.118.2).
    pub soc: u32,
    /// 24-bit fraction-of-second.
    pub fracsec: u32,
    /// Message time-quality byte.
    pub time_quality: u8,
}

impl CommonHeader {
    /// Convert SOC + FRACSEC + time_base into microseconds since Unix epoch.
    /// `time_base` is the resolution of FRACSEC declared in the CFG frame
    /// (default 1_000_000 if no CFG yet seen).
    pub fn timestamp_us(&self, time_base: u32) -> u64 {
        let secs = self.soc as u64 * 1_000_000;
        if time_base == 0 {
            return secs;
        }
        let frac_us = (self.fracsec as u64 * 1_000_000) / time_base as u64;
        secs + frac_us
    }
}

pub fn read_common_header(r: &mut Reader<'_>) -> Result<CommonHeader, ReaderError> {
    let sync0 = r.read_u8()?;
    if sync0 != SYNC_BYTE {
        return Err(ReaderError::OutOfBounds);
    }
    let sync1 = r.read_u8()?;
    let frame_type =
        FrameType::from_byte(sync1).ok_or(ReaderError::OutOfBounds)?;
    let version = sync1 & 0x0F;
    let framesize = r.read_u16()?;
    let idcode = r.read_u16()?;
    let soc = r.read_u32()?;
    let fracsec_word = r.read_u32()?;
    let time_quality = (fracsec_word >> 24) as u8;
    let fracsec = fracsec_word & 0x00FF_FFFF;
    Ok(CommonHeader {
        frame_type,
        version,
        framesize,
        idcode,
        soc,
        fracsec,
        time_quality,
    })
}

/// Quick sniff for whether a TCP/UDP payload looks like a C37.118 frame:
/// starts with 0xAA and a recognized frame type.
pub fn looks_like_synchrophasor(data: &[u8]) -> bool {
    if data.len() < 14 {
        return false;
    }
    if data[0] != SYNC_BYTE {
        return false;
    }
    FrameType::from_byte(data[1]).is_some()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn build_header(frame_type: u8, idcode: u16, soc: u32, fracsec: u32) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.push(SYNC_BYTE);
        bytes.push((frame_type << 4) | 0x01); // version 1
        bytes.extend_from_slice(&100u16.to_be_bytes()); // framesize
        bytes.extend_from_slice(&idcode.to_be_bytes());
        bytes.extend_from_slice(&soc.to_be_bytes());
        bytes.extend_from_slice(&fracsec.to_be_bytes());
        bytes
    }

    #[test]
    fn parses_data_frame_header() {
        let bytes = build_header(0, 7, 1_700_000_000, 0x0050_0000);
        let mut r = Reader::new(&bytes);
        let h = read_common_header(&mut r).unwrap();
        assert_eq!(h.frame_type, FrameType::Data);
        assert_eq!(h.idcode, 7);
        assert_eq!(h.soc, 1_700_000_000);
        // time_quality is high byte (0x00), fracsec is low 24 bits.
        assert_eq!(h.time_quality, 0x00);
        assert_eq!(h.fracsec, 0x0050_0000);
    }

    #[test]
    fn parses_config2_frame_header() {
        let bytes = build_header(3, 1, 0, 0);
        let mut r = Reader::new(&bytes);
        let h = read_common_header(&mut r).unwrap();
        assert_eq!(h.frame_type, FrameType::Config2);
    }

    #[test]
    fn rejects_invalid_sync() {
        let mut bytes = build_header(0, 1, 0, 0);
        bytes[0] = 0xBB;
        let mut r = Reader::new(&bytes);
        assert!(read_common_header(&mut r).is_err());
    }

    #[test]
    fn timestamp_us_with_default_base() {
        let h = CommonHeader {
            frame_type: FrameType::Data,
            version: 1,
            framesize: 0,
            idcode: 0,
            soc: 1_700_000_000,
            fracsec: 500_000, // half a second at base 1_000_000
            time_quality: 0,
        };
        assert_eq!(h.timestamp_us(1_000_000), 1_700_000_000_500_000);
    }

    #[test]
    fn looks_like_recognizer() {
        let valid = build_header(0, 1, 0, 0);
        assert!(looks_like_synchrophasor(&valid));
        let bad = vec![0xFF, 0x01, 0x00, 0x10];
        assert!(!looks_like_synchrophasor(&bad));
        let too_short = vec![0xAA, 0x01];
        assert!(!looks_like_synchrophasor(&too_short));
    }
}
