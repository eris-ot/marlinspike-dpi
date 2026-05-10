//! NTP dissector — extracts time synchronisation metadata from NTP packets.

use crate::registry::{PacketContext, ProtocolData, ProtocolDissector};

#[derive(Default)]
pub struct NtpDissector;

/// NTP mode names.
fn mode_name(mode: u8) -> &'static str {
    match mode {
        1 => "symmetric_active",
        2 => "symmetric_passive",
        3 => "client",
        4 => "server",
        5 => "broadcast",
        6 => "control",
        7 => "private",
        _ => "reserved",
    }
}

/// Decode the 4-byte reference ID field based on stratum.
fn decode_reference_id(stratum: u8, bytes: &[u8; 4]) -> String {
    if stratum == 0 || stratum == 1 {
        // Kiss-of-Death or primary reference — ASCII identifier.
        let s: String = bytes
            .iter()
            .take_while(|&&b| b != 0)
            .map(|&b| b as char)
            .collect();
        s
    } else {
        // Secondary reference — IPv4 address of upstream server.
        format!("{}.{}.{}.{}", bytes[0], bytes[1], bytes[2], bytes[3])
    }
}

/// Convert NTP 64-bit timestamp (seconds since 1900-01-01) to floating-point seconds.
fn ntp_timestamp_secs(hi: u32, lo: u32) -> f64 {
    hi as f64 + lo as f64 / 4_294_967_296.0
}

impl NtpDissector {
    pub fn parse_fields(&self, data: &[u8]) -> Option<NtpFields> {
        // NTP packet is exactly 48 bytes minimum (without extensions/MAC).
        if data.len() < 48 {
            return None;
        }

        let li_vn_mode = data[0];
        let version = (li_vn_mode >> 3) & 0x07;
        let mode = li_vn_mode & 0x07;
        let leap_indicator = (li_vn_mode >> 6) & 0x03;

        // Only NTP versions 2-4 are valid.
        if !(2..=4).contains(&version) {
            return None;
        }

        let stratum = data[1];
        let poll = data[2] as i8;
        let precision = data[3] as i8;

        let root_delay = i32::from_be_bytes([data[4], data[5], data[6], data[7]]);
        let root_dispersion = u32::from_be_bytes([data[8], data[9], data[10], data[11]]);

        let ref_id_bytes: [u8; 4] = [data[12], data[13], data[14], data[15]];
        let reference_id = decode_reference_id(stratum, &ref_id_bytes);

        let ref_ts_hi = u32::from_be_bytes([data[16], data[17], data[18], data[19]]);
        let ref_ts_lo = u32::from_be_bytes([data[20], data[21], data[22], data[23]]);
        let reference_timestamp = ntp_timestamp_secs(ref_ts_hi, ref_ts_lo);

        Some(NtpFields {
            version,
            mode,
            mode_name: mode_name(mode).to_string(),
            leap_indicator,
            stratum,
            poll,
            precision,
            root_delay_ms: (root_delay as f64) / 65536.0 * 1000.0,
            root_dispersion_ms: (root_dispersion as f64) / 65536.0 * 1000.0,
            reference_id,
            reference_timestamp,
        })
    }
}

impl ProtocolDissector for NtpDissector {
    fn name(&self) -> &str {
        "ntp"
    }

    fn can_parse(&self, data: &[u8], src_port: u16, dst_port: u16) -> bool {
        (src_port == 123 || dst_port == 123) && data.len() >= 48
    }

    fn parse(&self, data: &[u8], _context: &PacketContext) -> Option<ProtocolData> {
        Some(ProtocolData::Ntp(self.parse_fields(data)?))
    }
}

#[derive(Debug, Clone)]
pub struct NtpFields {
    pub version: u8,
    pub mode: u8,
    pub mode_name: String,
    pub leap_indicator: u8,
    pub stratum: u8,
    pub poll: i8,
    pub precision: i8,
    pub root_delay_ms: f64,
    pub root_dispersion_ms: f64,
    pub reference_id: String,
    pub reference_timestamp: f64,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    fn ctx() -> PacketContext {
        PacketContext {
            src_mac: [0; 6],
            dst_mac: [0; 6],
            src_ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
            dst_ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 2)),
            src_port: 123,
            dst_port: 123,
            vlan_id: None,
            timestamp: 0,
        }
    }

    fn build_ntp_server_response() -> Vec<u8> {
        let mut pkt = vec![0u8; 48];
        // LI=0, VN=4, Mode=4 (server)
        pkt[0] = 0b00_100_100;
        pkt[1] = 1; // stratum 1 (primary)
        pkt[2] = 6; // poll interval
        pkt[3] = 0xEC_u8; // precision (-20 as i8)
        // root delay = 0
        // root dispersion = 0
        // reference ID = "GPS\0"
        pkt[12] = b'G';
        pkt[13] = b'P';
        pkt[14] = b'S';
        pkt[15] = 0;
        pkt
    }

    #[test]
    fn parses_ntp_server_response() {
        let dissector = NtpDissector;
        let pkt = build_ntp_server_response();
        assert!(dissector.can_parse(&pkt, 123, 123));

        let fields = dissector.parse_fields(&pkt).expect("ntp fields");
        assert_eq!(fields.version, 4);
        assert_eq!(fields.mode, 4);
        assert_eq!(fields.mode_name, "server");
        assert_eq!(fields.stratum, 1);
        assert_eq!(fields.reference_id, "GPS");
    }

    #[test]
    fn rejects_wrong_port() {
        let dissector = NtpDissector;
        let pkt = build_ntp_server_response();
        assert!(!dissector.can_parse(&pkt, 1234, 5678));
    }

    #[test]
    fn rejects_short_packet() {
        let dissector = NtpDissector;
        assert!(!dissector.can_parse(&[0u8; 20], 123, 123));
    }

    #[test]
    fn rejects_invalid_version() {
        let dissector = NtpDissector;
        let mut pkt = build_ntp_server_response();
        // LI=0, VN=0, Mode=4
        pkt[0] = 0b00_000_100;
        assert!(dissector.parse_fields(&pkt).is_none());
    }

    #[test]
    fn stratum2_reference_id_is_ipv4() {
        let dissector = NtpDissector;
        let mut pkt = build_ntp_server_response();
        pkt[1] = 2; // stratum 2
        pkt[12] = 10;
        pkt[13] = 0;
        pkt[14] = 0;
        pkt[15] = 1;
        let fields = dissector.parse_fields(&pkt).expect("ntp fields");
        assert_eq!(fields.reference_id, "10.0.0.1");
    }

    #[test]
    fn trait_parse_returns_ntp_variant() {
        let dissector = NtpDissector;
        let pkt = build_ntp_server_response();
        assert!(matches!(
            dissector.parse(&pkt, &ctx()),
            Some(ProtocolData::Ntp(_))
        ));
    }
}
