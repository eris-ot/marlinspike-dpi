//! S7comm protocol dissector with TPKT, COTP, and S7 PDU parsing.
//!
//! The dissector returns [`crate::registry::S7commFields`] containing the raw
//! ROSCTR, function code, parameter block, and data block. The decoder layer in
//! `crate::engine::decoders::ot::s7comm` lifts these into a typed
//! [`crate::bronze::S7commBronzeFields`] carried on
//! [`crate::bronze::ProtocolTransaction::protocol_fields`] as
//! `ProtocolFields::S7comm(...)`, alongside the legacy `attributes` map for
//! backward compatibility through the v1.x line.

use crate::registry::{PacketContext, ProtocolData, ProtocolDissector};

pub struct S7commDissector;

const S7COMM_PORT: u16 = 102;

/// TPKT header size: version(1) + reserved(1) + length(2) = 4 bytes.
const TPKT_HEADER_SIZE: usize = 4;

/// S7comm protocol identifier byte.
const S7_PROTOCOL_ID: u8 = 0x32;

/// Minimum S7 header size: protocol_id(1) + rosctr(1) + reserved(2) + pdu_ref(2) +
/// param_length(2) + data_length(2) = 10 bytes.
const S7_HEADER_MIN: usize = 10;

/// S7 header size for Ack-Data responses (includes error_class + error_code): 12 bytes.
const S7_HEADER_ACKDATA: usize = 12;

/// Returns the human-readable name for an S7 ROSCTR value.
fn rosctr_name(rosctr: u8) -> &'static str {
    match rosctr {
        0x01 => "Job",
        0x02 => "Ack",
        0x03 => "Ack-Data",
        0x07 => "Userdata",
        _ => "Unknown",
    }
}

/// Returns the human-readable name for an S7 function code.
fn function_name(fc: u8) -> &'static str {
    match fc {
        0x00 => "CPU services",
        0x04 => "Read Var",
        0x05 => "Write Var",
        0x1A => "Request download",
        0x1B => "Download block",
        0x1C => "Download ended",
        0x1D => "Start upload",
        0x1E => "Upload",
        0x1F => "End upload",
        0x28 => "PI-Service",
        0x29 => "PLC Stop",
        0xF0 => "Setup Communication",
        _ => "Unknown",
    }
}

impl ProtocolDissector for S7commDissector {
    fn name(&self) -> &str {
        "s7comm"
    }

    fn can_parse(&self, data: &[u8], src_port: u16, dst_port: u16) -> bool {
        if src_port != S7COMM_PORT && dst_port != S7COMM_PORT {
            return false;
        }
        if data.len() < TPKT_HEADER_SIZE + 3 || data[0] != 0x03 {
            return false;
        }
        let cotp_length = data[TPKT_HEADER_SIZE] as usize;
        let s7_offset = TPKT_HEADER_SIZE + 1 + cotp_length;
        data.get(s7_offset).copied() == Some(S7_PROTOCOL_ID)
    }

    fn parse(&self, data: &[u8], _context: &PacketContext) -> Option<ProtocolData> {
        // --- TPKT Header ---
        if data.len() < TPKT_HEADER_SIZE || data[0] != 0x03 {
            return None;
        }
        let _tpkt_length = u16::from_be_bytes([data[2], data[3]]) as usize;

        // --- COTP Header ---
        // COTP starts at offset 4. First byte is the COTP length indicator (excludes itself).
        if data.len() < TPKT_HEADER_SIZE + 1 {
            return None;
        }
        let cotp_length = data[TPKT_HEADER_SIZE] as usize;
        let _cotp_pdu_type = if data.len() > TPKT_HEADER_SIZE + 1 {
            data[TPKT_HEADER_SIZE + 1]
        } else {
            return None;
        };

        // S7 data begins after TPKT header + COTP length indicator byte + COTP data
        let s7_offset = TPKT_HEADER_SIZE + 1 + cotp_length;
        if s7_offset + S7_HEADER_MIN > data.len() {
            return None;
        }

        // --- S7 Header ---
        if data[s7_offset] != S7_PROTOCOL_ID {
            return None;
        }

        let rosctr = data[s7_offset + 1];
        // reserved: data[s7_offset + 2..4]
        // pdu_reference: data[s7_offset + 4..6]
        let parameter_length =
            u16::from_be_bytes([data[s7_offset + 6], data[s7_offset + 7]]) as usize;
        let data_length = u16::from_be_bytes([data[s7_offset + 8], data[s7_offset + 9]]) as usize;

        // Ack-Data (0x03) and Ack (0x02) have 2 extra bytes: error_class + error_code.
        let s7_header_size = if rosctr == 0x02 || rosctr == 0x03 {
            S7_HEADER_ACKDATA
        } else {
            S7_HEADER_MIN
        };

        if s7_offset + s7_header_size > data.len() {
            return None;
        }

        let param_offset = s7_offset + s7_header_size;
        let param_end = (param_offset + parameter_length).min(data.len());
        let data_start = param_end;
        let data_end = (data_start + data_length).min(data.len());

        let parameter = data[param_offset..param_end].to_vec();
        let s7_data = data[data_start..data_end].to_vec();

        // Function code is the first byte of the parameter block (if present).
        let function = if !parameter.is_empty() {
            parameter[0]
        } else {
            0
        };

        let _ = rosctr_name(rosctr);
        let _ = function_name(function);

        Some(ProtocolData::S7comm(S7commFields {
            rosctr,
            function,
            parameter,
            data: s7_data,
        }))
    }
}

#[derive(Debug, Clone)]
pub struct S7commFields {
    pub rosctr: u8,
    pub function: u8,
    pub parameter: Vec<u8>,
    pub data: Vec<u8>,
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
            src_port: 49300,
            dst_port: S7COMM_PORT,
            src_ip: IpAddr::V4(Ipv4Addr::new(192, 168, 0, 1)),
            dst_ip: IpAddr::V4(Ipv4Addr::new(192, 168, 0, 100)),
            vlan_id: None,
            timestamp: 0,
        }
    }

    /// Build a minimal S7comm packet: TPKT + COTP DT + S7 header + parameter + data.
    fn build_s7_packet(rosctr: u8, function: u8, param_extra: &[u8], s7_data: &[u8]) -> Vec<u8> {
        let mut parameter = vec![function];
        parameter.extend_from_slice(param_extra);

        let s7_header_size: usize = if rosctr == 0x02 || rosctr == 0x03 {
            12
        } else {
            10
        };
        let cotp_len: u8 = 2; // COTP DT header: length_indicator=2, pdu_type=0xF0, TPDU#=0x00
        let tpkt_payload = 1 + cotp_len as usize + s7_header_size + parameter.len() + s7_data.len();
        let tpkt_total = (TPKT_HEADER_SIZE + tpkt_payload) as u16;

        let mut pkt = Vec::new();
        // TPKT
        pkt.push(0x03); // version
        pkt.push(0x00); // reserved
        pkt.extend_from_slice(&tpkt_total.to_be_bytes());
        // COTP DT
        pkt.push(cotp_len); // length indicator
        pkt.push(0xF0); // PDU type: DT Data
        pkt.push(0x80); // last data unit, TPDU number 0
        // S7 header
        pkt.push(S7_PROTOCOL_ID);
        pkt.push(rosctr);
        pkt.extend_from_slice(&[0x00, 0x00]); // reserved
        pkt.extend_from_slice(&[0x00, 0x01]); // PDU reference
        pkt.extend_from_slice(&(parameter.len() as u16).to_be_bytes());
        pkt.extend_from_slice(&(s7_data.len() as u16).to_be_bytes());
        if rosctr == 0x02 || rosctr == 0x03 {
            pkt.push(0x00); // error class
            pkt.push(0x00); // error code
        }
        pkt.extend_from_slice(&parameter);
        pkt.extend_from_slice(s7_data);
        pkt
    }

    #[test]
    fn can_parse_valid_s7() {
        let dissector = S7commDissector;
        let pkt = build_s7_packet(0x01, 0xF0, &[], &[]);
        assert!(dissector.can_parse(&pkt, 49300, S7COMM_PORT));
    }

    #[test]
    fn can_parse_wrong_port() {
        let dissector = S7commDissector;
        let pkt = build_s7_packet(0x01, 0xF0, &[], &[]);
        assert!(!dissector.can_parse(&pkt, 1111, 2222));
    }

    #[test]
    fn parse_setup_communication_job() {
        let dissector = S7commDissector;
        // Setup Communication (0xF0) with extra parameter bytes
        let param_extra = vec![0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0xF0]; // reserved + max_amq + max_amq + pdu_size
        let pkt = build_s7_packet(0x01, 0xF0, &param_extra, &[]);

        let result = dissector.parse(&pkt, &ctx());
        if let Some(ProtocolData::S7comm(fields)) = result {
            assert_eq!(fields.rosctr, 0x01);
            assert_eq!(rosctr_name(fields.rosctr), "Job");
            assert_eq!(fields.function, 0xF0);
            assert_eq!(function_name(fields.function), "Setup Communication");
            assert!(fields.data.is_empty());
        } else {
            panic!("Expected S7comm protocol data");
        }
    }

    #[test]
    fn parse_read_var_ack_data() {
        let dissector = S7commDissector;
        let param_extra = vec![0x01]; // item count = 1
        let s7_data = vec![0xFF, 0x04, 0x00, 0x08, 0x01, 0x02, 0x03, 0x04]; // return code + transport_size + length + data

        let pkt = build_s7_packet(0x03, 0x04, &param_extra, &s7_data);
        let result = dissector.parse(&pkt, &ctx());
        if let Some(ProtocolData::S7comm(fields)) = result {
            assert_eq!(fields.rosctr, 0x03);
            assert_eq!(rosctr_name(fields.rosctr), "Ack-Data");
            assert_eq!(fields.function, 0x04);
            assert_eq!(function_name(fields.function), "Read Var");
            assert_eq!(fields.data, s7_data);
        } else {
            panic!("Expected S7comm protocol data");
        }
    }

    #[test]
    fn parse_write_var_job() {
        let dissector = S7commDissector;
        let pkt = build_s7_packet(0x01, 0x05, &[0x01], &[0xAA, 0xBB]);

        let result = dissector.parse(&pkt, &ctx());
        if let Some(ProtocolData::S7comm(fields)) = result {
            assert_eq!(fields.rosctr, 0x01);
            assert_eq!(fields.function, 0x05);
            assert_eq!(function_name(fields.function), "Write Var");
            assert_eq!(fields.data, vec![0xAA, 0xBB]);
        } else {
            panic!("Expected S7comm protocol data");
        }
    }

    #[test]
    fn parse_too_short_rejected() {
        let dissector = S7commDissector;
        let data = vec![0x03, 0x00, 0x00, 0x05, 0x01];
        assert!(dissector.parse(&data, &ctx()).is_none());
    }

    #[test]
    fn parse_bad_protocol_id_rejected() {
        let dissector = S7commDissector;
        // Valid TPKT + COTP but wrong S7 magic byte
        let mut pkt = build_s7_packet(0x01, 0xF0, &[], &[]);
        // COTP is at offset 4, length indicator is 2, so S7 starts at 4+1+2=7
        pkt[7] = 0x99; // corrupt protocol_id
        assert!(dissector.parse(&pkt, &ctx()).is_none());
    }
}
