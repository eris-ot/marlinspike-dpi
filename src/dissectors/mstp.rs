//! MSTP dissector — IEEE 802.1s Multiple Spanning Tree Protocol.
//!
//! Same LLC (DSAP=0x42, SSAP=0x42) as STP/RSTP, but version >= 3 with MSTI
//! configuration records appended after the standard 35-byte BPDU.

use crate::registry::{PacketContext, ProtocolData, ProtocolDissector};

#[derive(Debug, Clone)]
pub struct MstpFields {
    pub protocol_version: u8,
    pub bpdu_type: u8,
    pub flags: u8,
    pub root_id: String,
    pub root_path_cost: u32,
    pub bridge_id: String,
    pub port_id: u16,
    pub config_name: Option<String>,
    pub revision_level: Option<u16>,
    pub msti_records: Vec<MstiRecord>,
}

#[derive(Debug, Clone)]
pub struct MstiRecord {
    pub flags: u8,
    pub regional_root: String,
    pub internal_path_cost: u32,
    pub bridge_priority: u8,
    pub remaining_hops: u8,
}

#[derive(Default)]
pub struct MstpDissector;

impl MstpDissector {
    pub fn parse_fields(&self, data: &[u8]) -> Option<MstpFields> {
        // Standard BPDU (35 bytes) + version_3_length(2) = 37 minimum.
        // Full MST BPDU with MCID = 35 + 2 + 1 + 32 + 2 + 16 + CIST fields.
        if data.len() < 38 {
            return None;
        }

        // Protocol identifier must be 0x0000.
        if u16::from_be_bytes([data[0], data[1]]) != 0x0000 {
            return None;
        }

        let protocol_version = data[2];
        // MSTP requires version >= 3.
        if protocol_version < 3 {
            return None;
        }

        let bpdu_type = data[3];
        let flags = data[4];

        let root_id = format_bridge_id(&data[5..13]);
        let root_path_cost = u32::from_be_bytes([data[13], data[14], data[15], data[16]]);
        let bridge_id = format_bridge_id(&data[17..25]);
        let port_id = u16::from_be_bytes([data[25], data[26]]);

        let version_3_length = u16::from_be_bytes([data[35], data[36]]) as usize;

        // Parse MST Configuration Identifier (MCID) if present.
        // MCID starts at offset 37: format_selector(1) + config_name(32) + revision_level(2) + config_digest(16)
        let mut config_name = None;
        let mut revision_level = None;
        let mut msti_records = Vec::new();

        let mcid_start = 37;
        if data.len() >= mcid_start + 51 {
            // format_selector at mcid_start (skip)
            let name_bytes = &data[mcid_start + 1..mcid_start + 33];
            config_name = Some(
                String::from_utf8_lossy(name_bytes)
                    .trim_end_matches('\0')
                    .to_string(),
            );
            revision_level = Some(u16::from_be_bytes([
                data[mcid_start + 33],
                data[mcid_start + 34],
            ]));
            // config_digest: 16 bytes at mcid_start + 35 (skip)

            // CIST fields follow MCID: cist_internal_root_path_cost(4) + cist_bridge_id(8) + cist_remaining_hops(1) = 13 bytes.
            let msti_start = mcid_start + 51 + 13;

            // MSTI records: 16 bytes each, fill the rest of version_3_length.
            let msti_end = 37 + version_3_length;
            let mut offset = msti_start;
            while offset + 16 <= data.len().min(msti_end) {
                let msti_flags = data[offset];
                let regional_root = format_bridge_id(&data[offset + 1..offset + 9]);
                let internal_path_cost = u32::from_be_bytes([
                    data[offset + 9],
                    data[offset + 10],
                    data[offset + 11],
                    data[offset + 12],
                ]);
                let bridge_priority = data[offset + 13];
                let remaining_hops = data[offset + 15];

                msti_records.push(MstiRecord {
                    flags: msti_flags,
                    regional_root,
                    internal_path_cost,
                    bridge_priority,
                    remaining_hops,
                });
                offset += 16;
            }
        }

        Some(MstpFields {
            protocol_version,
            bpdu_type,
            flags,
            root_id,
            root_path_cost,
            bridge_id,
            port_id,
            config_name,
            revision_level,
            msti_records,
        })
    }
}

fn format_bridge_id(bytes: &[u8]) -> String {
    if bytes.len() != 8 {
        return hex::encode(bytes);
    }
    let priority = u16::from_be_bytes([bytes[0], bytes[1]]);
    format!(
        "{priority}/{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7]
    )
}

impl ProtocolDissector for MstpDissector {
    fn name(&self) -> &str {
        "mstp"
    }

    fn can_parse(&self, data: &[u8], src_port: u16, dst_port: u16) -> bool {
        if src_port != 0 || dst_port != 0 {
            return false;
        }
        // Must be at least 38 bytes, protocol_id=0x0000, version >= 3.
        data.len() >= 38 && u16::from_be_bytes([data[0], data[1]]) == 0x0000 && data[2] >= 3
    }

    fn parse(&self, data: &[u8], _context: &PacketContext) -> Option<ProtocolData> {
        Some(ProtocolData::Mstp(self.parse_fields(data)?))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    fn ctx() -> PacketContext {
        PacketContext {
            src_mac: [0; 6],
            dst_mac: [0x01, 0x80, 0xC2, 0x00, 0x00, 0x00],
            src_ip: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            dst_ip: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            src_port: 0,
            dst_port: 0,
            vlan_id: None,
            timestamp: 0,
        }
    }

    fn build_mstp_bpdu() -> Vec<u8> {
        let mut pkt = vec![0u8; 102]; // 37 + 51 (MCID) + 13 (CIST) + 1 padding
        // Protocol identifier
        pkt[0] = 0x00;
        pkt[1] = 0x00;
        // Version 3 (MSTP)
        pkt[2] = 3;
        // BPDU type 0x02 (RST)
        pkt[3] = 0x02;
        // Flags
        pkt[4] = 0x3C;
        // Root ID: priority 0x8000 + MAC
        pkt[5..13].copy_from_slice(&[0x80, 0x00, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
        // Root path cost
        pkt[13..17].copy_from_slice(&100u32.to_be_bytes());
        // Bridge ID
        pkt[17..25].copy_from_slice(&[0x80, 0x00, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]);
        // Port ID
        pkt[25..27].copy_from_slice(&0x8001u16.to_be_bytes());
        // Timers (message_age, max_age, hello_time, forward_delay)
        pkt[27..35].copy_from_slice(&[0x00, 0x00, 0x14, 0x00, 0x02, 0x00, 0x0F, 0x00]);
        // version_3_length = 64 (MCID=51 + CIST=13)
        pkt[35..37].copy_from_slice(&64u16.to_be_bytes());
        // MCID: format_selector(1) + config_name(32) + revision(2) + digest(16)
        pkt[37] = 0; // format selector
        pkt[38..49].copy_from_slice(b"PLANT-MSTP\0");
        // revision level = 5
        pkt[70..72].copy_from_slice(&5u16.to_be_bytes());
        pkt
    }

    #[test]
    fn parses_mstp_bpdu() {
        let dissector = MstpDissector;
        let pkt = build_mstp_bpdu();
        assert!(dissector.can_parse(&pkt, 0, 0));

        let fields = dissector.parse_fields(&pkt).expect("mstp fields");
        assert_eq!(fields.protocol_version, 3);
        assert_eq!(fields.root_id, "32768/00:11:22:33:44:55");
        assert_eq!(fields.bridge_id, "32768/aa:bb:cc:dd:ee:ff");
        assert_eq!(fields.config_name.as_deref(), Some("PLANT-MSTP"));
        assert_eq!(fields.revision_level, Some(5));
    }

    #[test]
    fn rejects_stp_version() {
        let dissector = MstpDissector;
        let mut pkt = build_mstp_bpdu();
        pkt[2] = 2; // RSTP, not MSTP
        assert!(!dissector.can_parse(&pkt, 0, 0));
    }

    #[test]
    fn trait_parse_returns_mstp_variant() {
        let dissector = MstpDissector;
        assert!(matches!(
            dissector.parse(&build_mstp_bpdu(), &ctx()),
            Some(ProtocolData::Mstp(_))
        ));
    }
}
