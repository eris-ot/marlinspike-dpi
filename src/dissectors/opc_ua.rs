//! OPC UA Binary protocol dissector with message header and MSG-type field extraction.

use crate::registry::{PacketContext, ProtocolData, ProtocolDissector};

pub struct OpcUaDissector;

const OPC_UA_PORT: u16 = 4840;
const OPC_UA_ALT_PORT: u16 = 12001;

/// Minimum OPC UA message header: message_type(3) + chunk_type(1) + message_size(4) = 8 bytes.
const MSG_HEADER_SIZE: usize = 8;

/// Extended header for MSG/OPN/CLO: header(8) + secure_channel_id(4) = 12 bytes.
const SECURE_HEADER_SIZE: usize = 12;

/// Full MSG header with security and sequence fields:
/// header(8) + secure_channel_id(4) + security_token_id(4) + sequence_number(4) + request_id(4) = 24 bytes.
const MSG_FULL_HEADER_SIZE: usize = 24;

/// Recognized OPC UA message type prefixes.
const VALID_MSG_TYPES: &[&[u8; 3]] = &[b"HEL", b"ACK", b"OPN", b"CLO", b"MSG", b"ERR", b"RHE"];

/// Check if the first 3 bytes are a valid OPC UA message type.
fn is_valid_message_type(data: &[u8]) -> bool {
    if data.len() < 3 {
        return false;
    }
    let prefix: &[u8] = &data[0..3];
    VALID_MSG_TYPES.iter().any(|t| prefix == t.as_slice())
}

impl ProtocolDissector for OpcUaDissector {
    fn name(&self) -> &str {
        "opc_ua"
    }

    fn can_parse(&self, data: &[u8], src_port: u16, dst_port: u16) -> bool {
        if src_port != OPC_UA_PORT
            && dst_port != OPC_UA_PORT
            && src_port != OPC_UA_ALT_PORT
            && dst_port != OPC_UA_ALT_PORT
        {
            return false;
        }
        // OPC UA binary messages start with a 3-byte ASCII type and need at least 8 bytes.
        data.len() >= MSG_HEADER_SIZE && is_valid_message_type(data)
    }

    fn parse(&self, data: &[u8], _context: &PacketContext) -> Option<ProtocolData> {
        if data.len() < MSG_HEADER_SIZE {
            return None;
        }

        // --- Message Header ---
        let message_type = std::str::from_utf8(&data[0..3])
            .unwrap_or("UNK")
            .to_string();

        let chunk_type = data[3] as char; // 'F' = Final, 'C' = Continuation, 'A' = Abort
        let _message_size = u32::from_le_bytes([data[4], data[5], data[6], data[7]]);

        // --- Extended parsing for MSG, OPN, CLO ---
        let (request_id, service_type) = match message_type.as_str() {
            "MSG" => {
                if data.len() >= MSG_FULL_HEADER_SIZE {
                    let _secure_channel_id =
                        u32::from_le_bytes([data[8], data[9], data[10], data[11]]);
                    let _security_token_id =
                        u32::from_le_bytes([data[12], data[13], data[14], data[15]]);
                    let _sequence_number =
                        u32::from_le_bytes([data[16], data[17], data[18], data[19]]);
                    let req_id = u32::from_le_bytes([data[20], data[21], data[22], data[23]]);
                    (req_id, format!("MSG chunk={}", chunk_type))
                } else {
                    (0, format!("MSG chunk={} (truncated)", chunk_type))
                }
            }
            "OPN" => {
                if data.len() >= SECURE_HEADER_SIZE {
                    let _secure_channel_id =
                        u32::from_le_bytes([data[8], data[9], data[10], data[11]]);
                    (0, "OpenSecureChannel".to_string())
                } else {
                    (0, "OpenSecureChannel (truncated)".to_string())
                }
            }
            "CLO" => {
                if data.len() >= SECURE_HEADER_SIZE {
                    let _secure_channel_id =
                        u32::from_le_bytes([data[8], data[9], data[10], data[11]]);
                    (0, "CloseSecureChannel".to_string())
                } else {
                    (0, "CloseSecureChannel (truncated)".to_string())
                }
            }
            "HEL" => (0, "Hello".to_string()),
            "ACK" => (0, "Acknowledge".to_string()),
            "ERR" => {
                let error_code = if data.len() >= 12 {
                    u32::from_le_bytes([data[8], data[9], data[10], data[11]])
                } else {
                    0
                };
                (0, format!("Error (0x{:08X})", error_code))
            }
            "RHE" => (0, "ReverseHello".to_string()),
            _ => (0, "Unknown".to_string()),
        };

        Some(ProtocolData::OpcUa(OpcUaFields {
            message_type,
            request_id,
            service_type,
        }))
    }
}

#[derive(Debug, Clone)]
pub struct OpcUaFields {
    pub message_type: String,
    pub request_id: u32,
    pub service_type: String,
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
            src_port: 49500,
            dst_port: OPC_UA_PORT,
            src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            dst_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            vlan_id: None,
            timestamp: 0,
        }
    }

    fn build_msg_header(msg_type: &[u8; 3], chunk: u8, size: u32) -> Vec<u8> {
        let mut pkt = Vec::new();
        pkt.extend_from_slice(msg_type);
        pkt.push(chunk);
        pkt.extend_from_slice(&size.to_le_bytes());
        pkt
    }

    #[test]
    fn can_parse_hello() {
        let dissector = OpcUaDissector;
        let data = build_msg_header(b"HEL", b'F', 32);
        assert!(dissector.can_parse(&data, 49500, OPC_UA_PORT));
    }

    #[test]
    fn can_parse_rejects_invalid_type() {
        let dissector = OpcUaDissector;
        let data = build_msg_header(b"XYZ", b'F', 32);
        assert!(!dissector.can_parse(&data, 49500, OPC_UA_PORT));
    }

    #[test]
    fn can_parse_wrong_port() {
        let dissector = OpcUaDissector;
        let data = build_msg_header(b"HEL", b'F', 32);
        assert!(!dissector.can_parse(&data, 1111, 2222));
    }

    #[test]
    fn can_parse_alternate_port() {
        let dissector = OpcUaDissector;
        let data = build_msg_header(b"HEL", b'F', 32);
        assert!(dissector.can_parse(&data, 49500, OPC_UA_ALT_PORT));
    }

    #[test]
    fn parse_hello() {
        let dissector = OpcUaDissector;
        let mut data = build_msg_header(b"HEL", b'F', 64);
        // Hello payload: protocol_version(4) + various sizes
        data.extend_from_slice(&[0x00; 24]);

        let result = dissector.parse(&data, &ctx());
        if let Some(ProtocolData::OpcUa(fields)) = result {
            assert_eq!(fields.message_type, "HEL");
            assert_eq!(fields.service_type, "Hello");
            assert_eq!(fields.request_id, 0);
        } else {
            panic!("Expected OpcUa protocol data");
        }
    }

    #[test]
    fn parse_acknowledge() {
        let dissector = OpcUaDissector;
        let data = build_msg_header(b"ACK", b'F', 28);

        let result = dissector.parse(&data, &ctx());
        if let Some(ProtocolData::OpcUa(fields)) = result {
            assert_eq!(fields.message_type, "ACK");
            assert_eq!(fields.service_type, "Acknowledge");
        } else {
            panic!("Expected OpcUa protocol data");
        }
    }

    #[test]
    fn parse_msg_with_full_header() {
        let dissector = OpcUaDissector;
        let mut data = build_msg_header(b"MSG", b'F', 100);
        // secure_channel_id
        data.extend_from_slice(&42u32.to_le_bytes());
        // security_token_id
        data.extend_from_slice(&7u32.to_le_bytes());
        // sequence_number
        data.extend_from_slice(&1u32.to_le_bytes());
        // request_id
        data.extend_from_slice(&99u32.to_le_bytes());

        let result = dissector.parse(&data, &ctx());
        if let Some(ProtocolData::OpcUa(fields)) = result {
            assert_eq!(fields.message_type, "MSG");
            assert_eq!(fields.request_id, 99);
            assert_eq!(fields.service_type, "MSG chunk=F");
        } else {
            panic!("Expected OpcUa protocol data");
        }
    }

    #[test]
    fn parse_msg_truncated() {
        let dissector = OpcUaDissector;
        // MSG with only 8 bytes — not enough for extended fields
        let data = build_msg_header(b"MSG", b'C', 8);

        let result = dissector.parse(&data, &ctx());
        if let Some(ProtocolData::OpcUa(fields)) = result {
            assert_eq!(fields.message_type, "MSG");
            assert_eq!(fields.request_id, 0);
            assert!(fields.service_type.contains("truncated"));
        } else {
            panic!("Expected OpcUa protocol data");
        }
    }

    #[test]
    fn parse_open_secure_channel() {
        let dissector = OpcUaDissector;
        let mut data = build_msg_header(b"OPN", b'F', 132);
        data.extend_from_slice(&1u32.to_le_bytes()); // secure_channel_id

        let result = dissector.parse(&data, &ctx());
        if let Some(ProtocolData::OpcUa(fields)) = result {
            assert_eq!(fields.message_type, "OPN");
            assert_eq!(fields.service_type, "OpenSecureChannel");
        } else {
            panic!("Expected OpcUa protocol data");
        }
    }

    #[test]
    fn parse_close_secure_channel() {
        let dissector = OpcUaDissector;
        let mut data = build_msg_header(b"CLO", b'F', 12);
        data.extend_from_slice(&5u32.to_le_bytes()); // secure_channel_id

        let result = dissector.parse(&data, &ctx());
        if let Some(ProtocolData::OpcUa(fields)) = result {
            assert_eq!(fields.message_type, "CLO");
            assert_eq!(fields.service_type, "CloseSecureChannel");
        } else {
            panic!("Expected OpcUa protocol data");
        }
    }

    #[test]
    fn parse_error() {
        let dissector = OpcUaDissector;
        let mut data = build_msg_header(b"ERR", b'F', 16);
        data.extend_from_slice(&0x800D0000u32.to_le_bytes()); // error code

        let result = dissector.parse(&data, &ctx());
        if let Some(ProtocolData::OpcUa(fields)) = result {
            assert_eq!(fields.message_type, "ERR");
            assert_eq!(fields.service_type, "Error (0x800D0000)");
        } else {
            panic!("Expected OpcUa protocol data");
        }
    }
}
