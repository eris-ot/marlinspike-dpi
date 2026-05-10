//! IEC 60870-5-104 dissector with lightweight APCI/ASDU parsing.

use crate::registry::{PacketContext, ProtocolData, ProtocolDissector};

#[derive(Default)]
pub struct Iec104Dissector;

const IEC104_PORT: u16 = 2404;

impl ProtocolDissector for Iec104Dissector {
    fn name(&self) -> &str {
        "iec104"
    }

    fn can_parse(&self, data: &[u8], src_port: u16, dst_port: u16) -> bool {
        (src_port == IEC104_PORT || dst_port == IEC104_PORT)
            && data.len() >= 6
            && data[0] == 0x68
            && data[1] as usize + 2 <= data.len()
    }

    fn parse(&self, data: &[u8], _context: &PacketContext) -> Option<ProtocolData> {
        parse_iec104_frames(data)
            .into_iter()
            .next()
            .map(ProtocolData::Iec104)
    }
}

pub fn parse_iec104_frames(data: &[u8]) -> Vec<Iec104Fields> {
    let mut frames = Vec::new();
    let mut offset = 0usize;

    while offset + 2 <= data.len() {
        if data[offset] != 0x68 {
            break;
        }
        let apdu_len = data[offset + 1] as usize;
        if apdu_len < 4 || offset + 2 + apdu_len > data.len() {
            break;
        }
        let apdu = &data[offset..offset + 2 + apdu_len];
        if let Some(frame) = parse_iec104_frame(apdu) {
            frames.push(frame);
        } else {
            break;
        }
        offset += 2 + apdu_len;
    }

    frames
}

fn parse_iec104_frame(data: &[u8]) -> Option<Iec104Fields> {
    if data.len() < 6 || data[0] != 0x68 {
        return None;
    }

    let control = &data[2..6];
    if control[0] & 0x01 == 0 {
        let send_sequence = u16::from_le_bytes([control[0], control[1]]) >> 1;
        let receive_sequence = u16::from_le_bytes([control[2], control[3]]) >> 1;
        let asdu = &data[6..];
        let (type_id, cause_of_transmission, common_address, information_object_address) =
            if asdu.len() >= 6 {
                (
                    Some(asdu[0]),
                    Some(u16::from_le_bytes([asdu[2], asdu[3]]) & 0x003F),
                    Some(u16::from_le_bytes([asdu[4], asdu[5]])),
                    if asdu.len() >= 9 {
                        Some(asdu[6] as u32 | ((asdu[7] as u32) << 8) | ((asdu[8] as u32) << 16))
                    } else {
                        None
                    },
                )
            } else {
                (None, None, None, None)
            };

        Some(Iec104Fields {
            frame_type: "i".to_string(),
            send_sequence: Some(send_sequence),
            receive_sequence: Some(receive_sequence),
            u_format: None,
            type_id,
            cause_of_transmission,
            common_address,
            information_object_address,
            payload: asdu.to_vec(),
        })
    } else if control[0] & 0x03 == 0x01 {
        let receive_sequence = u16::from_le_bytes([control[2], control[3]]) >> 1;
        Some(Iec104Fields {
            frame_type: "s".to_string(),
            send_sequence: None,
            receive_sequence: Some(receive_sequence),
            u_format: None,
            type_id: None,
            cause_of_transmission: None,
            common_address: None,
            information_object_address: None,
            payload: Vec::new(),
        })
    } else if control[0] & 0x03 == 0x03 {
        Some(Iec104Fields {
            frame_type: "u".to_string(),
            send_sequence: None,
            receive_sequence: None,
            u_format: Some(iec104_u_format_name(control[0]).to_string()),
            type_id: None,
            cause_of_transmission: None,
            common_address: None,
            information_object_address: None,
            payload: Vec::new(),
        })
    } else {
        None
    }
}

fn iec104_u_format_name(code: u8) -> &'static str {
    match code {
        0x07 => "startdt_act",
        0x0B => "startdt_con",
        0x13 => "stopdt_act",
        0x23 => "stopdt_con",
        0x43 => "testfr_act",
        0x83 => "testfr_con",
        _ => "u_format",
    }
}

#[derive(Debug, Clone)]
pub struct Iec104Fields {
    pub frame_type: String,
    pub send_sequence: Option<u16>,
    pub receive_sequence: Option<u16>,
    pub u_format: Option<String>,
    pub type_id: Option<u8>,
    pub cause_of_transmission: Option<u16>,
    pub common_address: Option<u16>,
    pub information_object_address: Option<u32>,
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
            src_port: 50000,
            dst_port: IEC104_PORT,
            src_ip: IpAddr::V4(Ipv4Addr::new(10, 20, 102, 1)),
            dst_ip: IpAddr::V4(Ipv4Addr::new(10, 20, 100, 108)),
            vlan_id: None,
            timestamp: 0,
        }
    }

    #[test]
    fn can_parse_i_frame() {
        let dissector = Iec104Dissector;
        let data = [0x68, 0x04, 0x07, 0x00, 0x00, 0x00];
        assert!(dissector.can_parse(&data, 50000, IEC104_PORT));
    }

    #[test]
    fn parse_startdt_act_u_frame() {
        let dissector = Iec104Dissector;
        let data = [0x68, 0x04, 0x07, 0x00, 0x00, 0x00];

        let result = dissector.parse(&data, &ctx());
        if let Some(ProtocolData::Iec104(fields)) = result {
            assert_eq!(fields.frame_type, "u");
            assert_eq!(fields.u_format.as_deref(), Some("startdt_act"));
        } else {
            panic!("expected iec104 fields");
        }
    }

    #[test]
    fn parse_interrogation_command_i_frame() {
        let dissector = Iec104Dissector;
        let data = [
            0x68, 0x0E, 0x00, 0x00, 0x00, 0x00, 0x64, 0x01, 0x06, 0x00, 0x0A, 0x00, 0x00, 0x00,
            0x00, 0x14,
        ];

        let result = dissector.parse(&data, &ctx());
        if let Some(ProtocolData::Iec104(fields)) = result {
            assert_eq!(fields.frame_type, "i");
            assert_eq!(fields.send_sequence, Some(0));
            assert_eq!(fields.receive_sequence, Some(0));
            assert_eq!(fields.type_id, Some(100));
            assert_eq!(fields.cause_of_transmission, Some(6));
            assert_eq!(fields.common_address, Some(10));
            assert_eq!(fields.information_object_address, Some(0));
        } else {
            panic!("expected iec104 fields");
        }
    }

    #[test]
    fn parse_multiple_frames_from_single_tcp_chunk() {
        let data = [
            0x68, 0x04, 0x07, 0x00, 0x00, 0x00, 0x68, 0x0E, 0x00, 0x00, 0x00, 0x00, 0x64, 0x01,
            0x06, 0x00, 0x0A, 0x00, 0x00, 0x00, 0x00, 0x14,
        ];
        let frames = parse_iec104_frames(&data);
        assert_eq!(frames.len(), 2);
        assert_eq!(frames[0].frame_type, "u");
        assert_eq!(frames[1].type_id, Some(100));
    }
}
