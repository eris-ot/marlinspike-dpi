//! PROFINET protocol dissector with Frame ID classification and DCP parsing.

use crate::registry::{PacketContext, ProtocolData, ProtocolDissector};

pub struct ProfinetDissector;

const PROFINET_PORT: u16 = 34964;

/// Minimum packet size: frame_id(2) + at least some payload.
const MIN_FRAME_SIZE: usize = 2;

/// DCP header size after the frame ID: service_id(1) + service_type(1) + xid(4) +
/// response_delay(2) + data_length(2) = 10 bytes.
const DCP_HEADER_SIZE: usize = 10;

/// Classify a PROFINET frame by its Frame ID.
fn classify_frame(frame_id: u16) -> &'static str {
    match frame_id {
        0x0020..=0x007F => "RT Cyclic (Class 1/2/3)",
        0x0080..=0x0081 => "RT Cyclic (Class 3 redundant)",
        0x0100..=0x7FFF => "RT Cyclic (Class 1 unicast)",
        0x8000..=0xBFFF => "RT Cyclic (Class 1 multicast)",
        0xC000..=0xFBFF => "RT Cyclic (Reserved)",
        0xFC01 => "Alarm High",
        0xFC02..=0xFCFF => "Alarm/Reserved",
        0xFE01 => "PTCP Announce",
        0xFE02 => "PTCP Follow-Up",
        0xFE03 => "PTCP Delay Request",
        0xFE04 => "PTCP Delay Response",
        0xFEFC => "DCP Hello Request",
        0xFEFD => "DCP Get/Set",
        0xFEFE => "DCP Identify Request",
        0xFEFF => "DCP Identify Response",
        0xFF00..=0xFF01 => "LLDP extension",
        _ => "Unknown",
    }
}

fn looks_like_profinet_frame(data: &[u8]) -> bool {
    if data.len() < MIN_FRAME_SIZE {
        return false;
    }

    let frame_id = u16::from_be_bytes([data[0], data[1]]);
    classify_frame(frame_id) != "Unknown"
}

/// Returns a human-readable DCP service ID name.
fn dcp_service_name(service_id: u8) -> &'static str {
    match service_id {
        0x03 => "Get",
        0x04 => "Set",
        0x05 => "Identify",
        0x06 => "Hello",
        _ => "Unknown",
    }
}

/// Returns a human-readable DCP service type name.
fn dcp_service_type_name(service_type: u8) -> &'static str {
    match service_type {
        0x00 => "Request",
        0x01 => "Response (Success)",
        0x05 => "Response (Unsupported)",
        _ => "Unknown",
    }
}

impl ProtocolDissector for ProfinetDissector {
    fn name(&self) -> &str {
        "profinet"
    }

    fn can_parse(&self, data: &[u8], src_port: u16, dst_port: u16) -> bool {
        if src_port == PROFINET_PORT || dst_port == PROFINET_PORT {
            return data.len() >= MIN_FRAME_SIZE;
        }

        if src_port == 0 && dst_port == 0 {
            return looks_like_profinet_frame(data);
        }

        false
    }

    fn parse(&self, data: &[u8], _context: &PacketContext) -> Option<ProtocolData> {
        if data.len() < MIN_FRAME_SIZE {
            return None;
        }

        let frame_id = u16::from_be_bytes([data[0], data[1]]);
        let frame_class = classify_frame(frame_id);

        // Determine service_type string and payload based on frame type.
        let is_dcp = matches!(frame_id, 0xFEFC..=0xFEFF);

        if is_dcp && data.len() >= MIN_FRAME_SIZE + DCP_HEADER_SIZE {
            let dcp_offset = MIN_FRAME_SIZE;
            let service_id = data[dcp_offset];
            let service_type_byte = data[dcp_offset + 1];
            let _xid = u32::from_be_bytes([
                data[dcp_offset + 2],
                data[dcp_offset + 3],
                data[dcp_offset + 4],
                data[dcp_offset + 5],
            ]);
            let _response_delay = u16::from_be_bytes([data[dcp_offset + 6], data[dcp_offset + 7]]);
            let dcp_data_length =
                u16::from_be_bytes([data[dcp_offset + 8], data[dcp_offset + 9]]) as usize;

            let blocks_start = dcp_offset + DCP_HEADER_SIZE;
            let blocks_end = (blocks_start + dcp_data_length).min(data.len());
            let payload = data[blocks_start..blocks_end].to_vec();

            let service_type = format!(
                "DCP {} {}",
                dcp_service_name(service_id),
                dcp_service_type_name(service_type_byte)
            );

            Some(ProtocolData::Profinet(ProfinetFields {
                frame_id,
                service_type,
                payload,
            }))
        } else {
            // Non-DCP frame (cyclic IO, alarm, etc.)
            let payload = if data.len() > MIN_FRAME_SIZE {
                data[MIN_FRAME_SIZE..].to_vec()
            } else {
                Vec::new()
            };

            Some(ProtocolData::Profinet(ProfinetFields {
                frame_id,
                service_type: frame_class.to_string(),
                payload,
            }))
        }
    }
}

#[derive(Debug, Clone)]
pub struct ProfinetFields {
    pub frame_id: u16,
    pub service_type: String,
    pub payload: Vec<u8>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::registry::PacketContext;

    fn ctx() -> PacketContext {
        use std::net::{IpAddr, Ipv4Addr};
        PacketContext {
            src_mac: [0; 6],
            dst_mac: [0; 6],
            src_port: 34964,
            dst_port: 49400,
            src_ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
            dst_ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 2)),
            vlan_id: None,
            timestamp: 0,
        }
    }

    #[test]
    fn can_parse_valid() {
        let dissector = ProfinetDissector;
        let data = [0xFE, 0xFE, 0x05, 0x00];
        assert!(dissector.can_parse(&data, PROFINET_PORT, 49400));
    }

    #[test]
    fn can_parse_wrong_port() {
        let dissector = ProfinetDissector;
        let data = [0xFE, 0xFE, 0x05, 0x00];
        assert!(!dissector.can_parse(&data, 1111, 2222));
    }

    #[test]
    fn parse_cyclic_io() {
        let dissector = ProfinetDissector;
        // Frame ID 0x0020 = RT Cyclic Class 1/2/3
        let data = vec![0x00, 0x20, 0xAA, 0xBB, 0xCC];
        let result = dissector.parse(&data, &ctx());
        if let Some(ProtocolData::Profinet(fields)) = result {
            assert_eq!(fields.frame_id, 0x0020);
            assert_eq!(fields.service_type, "RT Cyclic (Class 1/2/3)");
            assert_eq!(fields.payload, vec![0xAA, 0xBB, 0xCC]);
        } else {
            panic!("Expected Profinet protocol data");
        }
    }

    #[test]
    fn parse_alarm_high() {
        let dissector = ProfinetDissector;
        let data = vec![0xFC, 0x01, 0x01, 0x02];
        let result = dissector.parse(&data, &ctx());
        if let Some(ProtocolData::Profinet(fields)) = result {
            assert_eq!(fields.frame_id, 0xFC01);
            assert_eq!(fields.service_type, "Alarm High");
        } else {
            panic!("Expected Profinet protocol data");
        }
    }

    #[test]
    fn parse_dcp_identify_request() {
        let dissector = ProfinetDissector;
        // Frame ID 0xFEFE = DCP Identify Request
        let data = vec![
            0xFE, 0xFE, // frame_id
            0x05, // service_id = Identify
            0x00, // service_type = Request
            0x00, 0x00, 0x00, 0x01, // xid
            0x00, 0x80, // response delay
            0x00, 0x04, // data_length = 4
            0x01, 0x02, 0x03, 0x04, // block data
        ];
        let result = dissector.parse(&data, &ctx());
        if let Some(ProtocolData::Profinet(fields)) = result {
            assert_eq!(fields.frame_id, 0xFEFE);
            assert_eq!(fields.service_type, "DCP Identify Request");
            assert_eq!(fields.payload, vec![0x01, 0x02, 0x03, 0x04]);
        } else {
            panic!("Expected Profinet protocol data");
        }
    }

    #[test]
    fn parse_dcp_identify_response() {
        let dissector = ProfinetDissector;
        let data = vec![
            0xFE, 0xFF, // frame_id = DCP Identify Response
            0x05, // service_id = Identify
            0x01, // service_type = Response (Success)
            0x00, 0x00, 0x00, 0x02, // xid
            0x00, 0x00, // response delay
            0x00, 0x02, // data_length = 2
            0xAA, 0xBB, // block data
        ];
        let result = dissector.parse(&data, &ctx());
        if let Some(ProtocolData::Profinet(fields)) = result {
            assert_eq!(fields.frame_id, 0xFEFF);
            assert_eq!(fields.service_type, "DCP Identify Response (Success)");
            assert_eq!(fields.payload, vec![0xAA, 0xBB]);
        } else {
            panic!("Expected Profinet protocol data");
        }
    }

    #[test]
    fn parse_dcp_too_short_falls_back() {
        let dissector = ProfinetDissector;
        // DCP frame ID but not enough data for DCP header
        let data = vec![0xFE, 0xFE, 0x05];
        let result = dissector.parse(&data, &ctx());
        if let Some(ProtocolData::Profinet(fields)) = result {
            assert_eq!(fields.frame_id, 0xFEFE);
            assert_eq!(fields.service_type, "DCP Identify Request");
            assert_eq!(fields.payload, vec![0x05]);
        } else {
            panic!("Expected Profinet protocol data");
        }
    }

    #[test]
    fn can_parse_raw_ethertype_dcp_frame() {
        let dissector = ProfinetDissector;
        let data = vec![
            0xFE, 0xFE, // frame_id = DCP Identify Request
            0x05, // service_id = Identify
            0x00, // service_type = Request
            0x01, 0x00, 0x00, 0x01, // xid
            0x00, 0x01, // response delay
            0x00, 0x04, // data_length = 4
            0xFF, 0xFF, 0x00, 0x00, // DCP block header from the real corpus sample
        ];

        assert!(dissector.can_parse(&data, 0, 0));
        assert!(!dissector.can_parse(&data, 1234, 5678));
    }

    #[test]
    fn parse_raw_ethertype_dcp_identify_request() {
        let dissector = ProfinetDissector;
        let data = vec![
            0xFE, 0xFE, // frame_id = DCP Identify Request
            0x05, // service_id = Identify
            0x00, // service_type = Request
            0x01, 0x00, 0x00, 0x01, // xid
            0x00, 0x01, // response delay
            0x00, 0x04, // data_length = 4
            0xFF, 0xFF, 0x00, 0x00, // block data
        ];

        let result = dissector.parse(&data, &ctx());
        if let Some(ProtocolData::Profinet(fields)) = result {
            assert_eq!(fields.frame_id, 0xFEFE);
            assert_eq!(fields.service_type, "DCP Identify Request");
            assert_eq!(fields.payload, vec![0xFF, 0xFF, 0x00, 0x00]);
        } else {
            panic!("Expected Profinet protocol data");
        }
    }
}
