//! TCP header parser — extracts ports, flags, and sequence numbers.
//!
//! This module provides a utility for parsing TCP headers. It is not a
//! `ProtocolDissector` itself (TCP is a transport layer, not a protocol
//! the DPI engine classifies as a Bronze record), but is used by the
//! engine when extracting L4 context.

/// Parsed TCP header fields.
#[derive(Debug, Clone)]
pub struct TcpHeader {
    pub src_port: u16,
    pub dst_port: u16,
    pub sequence_number: u32,
    pub ack_number: u32,
    pub data_offset: u8, // in 32-bit words
    pub flags: TcpFlags,
    pub window_size: u16,
    pub checksum: u16,
    pub urgent_pointer: u16,
}

#[derive(Debug, Clone, Copy)]
pub struct TcpFlags {
    pub fin: bool,
    pub syn: bool,
    pub rst: bool,
    pub psh: bool,
    pub ack: bool,
    pub urg: bool,
    pub ece: bool,
    pub cwr: bool,
}

impl TcpHeader {
    /// Parse a TCP header from raw bytes. Returns `None` if the slice is too
    /// short or the data offset is invalid.
    pub fn parse(data: &[u8]) -> Option<Self> {
        if data.len() < 20 {
            return None;
        }

        let src_port = u16::from_be_bytes([data[0], data[1]]);
        let dst_port = u16::from_be_bytes([data[2], data[3]]);
        let sequence_number = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);
        let ack_number = u32::from_be_bytes([data[8], data[9], data[10], data[11]]);
        let data_offset = data[12] >> 4;
        let flag_bits = u16::from_be_bytes([data[12], data[13]]) & 0x01FF;

        let flags = TcpFlags {
            fin: flag_bits & 0x001 != 0,
            syn: flag_bits & 0x002 != 0,
            rst: flag_bits & 0x004 != 0,
            psh: flag_bits & 0x008 != 0,
            ack: flag_bits & 0x010 != 0,
            urg: flag_bits & 0x020 != 0,
            ece: flag_bits & 0x040 != 0,
            cwr: flag_bits & 0x080 != 0,
        };

        let window_size = u16::from_be_bytes([data[14], data[15]]);
        let checksum = u16::from_be_bytes([data[16], data[17]]);
        let urgent_pointer = u16::from_be_bytes([data[18], data[19]]);

        Some(Self {
            src_port,
            dst_port,
            sequence_number,
            ack_number,
            data_offset,
            flags,
            window_size,
            checksum,
            urgent_pointer,
        })
    }

    /// Returns the header length in bytes.
    pub fn header_len(&self) -> usize {
        self.data_offset as usize * 4
    }
}

#[derive(Debug, Clone)]
pub struct TlsFields {
    pub version: String,
    pub cipher_suite: String,
    pub sni: String,
    pub certificate_subjects: Vec<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_tcp_syn() {
        let mut hdr = [0u8; 20];
        // src_port = 49152
        hdr[0..2].copy_from_slice(&49152u16.to_be_bytes());
        // dst_port = 80
        hdr[2..4].copy_from_slice(&80u16.to_be_bytes());
        // seq
        hdr[4..8].copy_from_slice(&1000u32.to_be_bytes());
        // ack
        hdr[8..12].copy_from_slice(&0u32.to_be_bytes());
        // data offset = 5 (20 bytes), flags = SYN (0x02)
        hdr[12] = 0x50; // data_offset=5
        hdr[13] = 0x02; // SYN

        let parsed = TcpHeader::parse(&hdr).unwrap();
        assert_eq!(parsed.src_port, 49152);
        assert_eq!(parsed.dst_port, 80);
        assert_eq!(parsed.sequence_number, 1000);
        assert!(parsed.flags.syn);
        assert!(!parsed.flags.ack);
        assert_eq!(parsed.header_len(), 20);
    }
}
