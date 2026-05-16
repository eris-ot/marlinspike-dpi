//! DNP3 protocol dissector with full data link, transport, and application layer parsing.

use crate::registry::{PacketContext, ProtocolData, ProtocolDissector};

#[derive(Default)]
pub struct Dnp3Dissector;

const DNP3_PORT: u16 = 20000;

/// DNP3 start bytes.
const DNP3_START_1: u8 = 0x05;
const DNP3_START_2: u8 = 0x64;

/// Data link layer header size: start(2) + length(1) + control(1) + destination(2) + source(2) + CRC(2) = 10
const DLL_HEADER_SIZE: usize = 10;

/// Returns the human-readable name of a DNP3 application-layer function code.
#[cfg(test)]
fn function_code_name(fc: u8) -> &'static str {
    match fc {
        0x00 => "Confirm",
        0x01 => "Read",
        0x02 => "Write",
        0x03 => "Select",
        0x04 => "Operate",
        0x05 => "DirectOperate",
        0x06 => "DirectOperateNoAck",
        0x07 => "ImmediateFreeze",
        0x08 => "ImmediateFreezeNoAck",
        0x09 => "FreezeAndClear",
        0x0A => "FreezeAndClearNoAck",
        0x0B => "FreezeAtTime",
        0x0C => "FreezeAtTimeNoAck",
        0x0D => "ColdRestart",
        0x0E => "WarmRestart",
        0x0F => "InitializeData",
        0x10 => "InitializeApplication",
        0x11 => "StartApplication",
        0x12 => "StopApplication",
        0x15 => "EnableUnsolicited",
        0x16 => "DisableUnsolicited",
        0x81 => "Response",
        0x82 => "UnsolicitedResponse",
        _ => "Unknown",
    }
}

impl ProtocolDissector for Dnp3Dissector {
    fn name(&self) -> &str {
        "dnp3"
    }

    fn can_parse(&self, data: &[u8], src_port: u16, dst_port: u16) -> bool {
        if src_port != DNP3_PORT && dst_port != DNP3_PORT {
            return false;
        }
        // DNP3 data link layer starts with 0x0564 and needs at least a full DLL header.
        data.len() >= DLL_HEADER_SIZE && data[0] == DNP3_START_1 && data[1] == DNP3_START_2
    }

    fn parse(&self, data: &[u8], _context: &PacketContext) -> Option<ProtocolData> {
        if data.len() < DLL_HEADER_SIZE || data[0] != DNP3_START_1 || data[1] != DNP3_START_2 {
            return None;
        }

        // --- Data Link Layer ---
        let _dll_length = data[2];
        let _dll_control = data[3];
        let destination_address = u16::from_le_bytes([data[4], data[5]]);
        let source_address = u16::from_le_bytes([data[6], data[7]]);
        // bytes [8..10] are the DLL CRC — skip validation for dissection purposes.

        // --- Transport Header ---
        // The transport header is 1 byte immediately after the DLL header.
        if data.len() < DLL_HEADER_SIZE + 1 {
            return Some(ProtocolData::Dnp3(Dnp3Fields {
                source_address,
                destination_address,
                dll_control: data[3],
                transport_seq: 0,
                transport_fir: false,
                transport_fin: false,
                function_code: 0,
                app_control: 0,
                iin: None,
                application_data: Vec::new(),
            }));
        }

        let transport_byte = data[DLL_HEADER_SIZE];
        let transport_fin = (transport_byte & 0x80) != 0;
        let transport_fir = (transport_byte & 0x40) != 0;
        let transport_seq = transport_byte & 0x3F;

        // --- Application Layer ---
        // Application layer starts after DLL header (10) + transport header (1) = offset 11.
        let app_offset = DLL_HEADER_SIZE + 1;
        if data.len() < app_offset + 2 {
            return Some(ProtocolData::Dnp3(Dnp3Fields {
                source_address,
                destination_address,
                dll_control: data[3],
                transport_seq,
                transport_fir,
                transport_fin,
                function_code: 0,
                app_control: 0,
                iin: None,
                application_data: Vec::new(),
            }));
        }

        let app_control = data[app_offset];
        let function_code = data[app_offset + 1];

        // For responses (0x81, 0x82) the next 2 bytes are Internal Indications (IIN).
        let (iin, app_data_start) = if function_code == 0x81 || function_code == 0x82 {
            let iin_val = if data.len() >= app_offset + 4 {
                Some(u16::from_le_bytes([
                    data[app_offset + 2],
                    data[app_offset + 3],
                ]))
            } else {
                None
            };
            (iin_val, app_offset + 4) // control(1) + fc(1) + IIN(2)
        } else {
            (None, app_offset + 2) // control(1) + fc(1)
        };

        let application_data = if app_data_start < data.len() {
            data[app_data_start..].to_vec()
        } else {
            Vec::new()
        };

        Some(ProtocolData::Dnp3(Dnp3Fields {
            source_address,
            destination_address,
            dll_control: data[3],
            transport_seq,
            transport_fir,
            transport_fin,
            function_code,
            app_control,
            iin,
            application_data,
        }))
    }
}

#[derive(Debug, Clone)]
pub struct Dnp3Fields {
    pub source_address: u16,
    pub destination_address: u16,
    /// Raw DLL control byte (DIR/PRM/FCB/FCV/FC bits).
    pub dll_control: u8,
    /// Transport-layer sequence number (6-bit, 0–63).
    pub transport_seq: u8,
    /// Transport FIR bit — first fragment.
    pub transport_fir: bool,
    /// Transport FIN bit — final fragment.
    pub transport_fin: bool,
    /// Application-layer function code.
    pub function_code: u8,
    /// Raw application-layer control byte (FIR/FIN/CON/UNS/SEQ).
    pub app_control: u8,
    /// Internal Indication flags (IIN1 | IIN2 << 8), present on Response (0x81)
    /// and UnsolicitedResponse (0x82) only.
    pub iin: Option<u16>,
    pub application_data: Vec<u8>,
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
            src_port: 49152,
            dst_port: DNP3_PORT,
            src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            dst_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            vlan_id: None,
            timestamp: 0,
        }
    }

    #[test]
    fn can_parse_valid_dnp3() {
        let dissector = Dnp3Dissector;
        // Minimal valid DLL header: start(0x05,0x64) + length + control + dst(2) + src(2) + CRC(2)
        let data = [0x05, 0x64, 0x05, 0xC0, 0x01, 0x00, 0x02, 0x00, 0x00, 0x00];
        assert!(dissector.can_parse(&data, 49152, DNP3_PORT));
    }

    #[test]
    fn can_parse_wrong_port() {
        let dissector = Dnp3Dissector;
        let data = [0x05, 0x64, 0x05, 0xC0, 0x01, 0x00, 0x02, 0x00, 0x00, 0x00];
        assert!(!dissector.can_parse(&data, 1234, 5678));
    }

    #[test]
    fn can_parse_bad_start_bytes() {
        let dissector = Dnp3Dissector;
        let data = [0x00, 0x00, 0x05, 0xC0, 0x01, 0x00, 0x02, 0x00, 0x00, 0x00];
        assert!(!dissector.can_parse(&data, 49152, DNP3_PORT));
    }

    #[test]
    fn parse_read_request() {
        let dissector = Dnp3Dissector;
        // DLL: start(2) + len + ctrl + dst=0x0001 + src=0x0003 + CRC(2)
        // Transport: 0xC0 (FIR=1, FIN=1, seq=0)
        // App: control=0xC0, function=0x01 (Read), object data bytes
        let data: Vec<u8> = vec![
            0x05, 0x64, // start bytes
            0x08, // length
            0xC4, // control (DIR=1, PRM=1, FC=4 unconfirmed)
            0x01, 0x00, // destination = 1
            0x03, 0x00, // source = 3
            0xAA, 0xBB, // CRC (not validated)
            0xC0, // transport: FIR=1, FIN=1, seq=0
            0xC0, // app control
            0x01, // function code = Read
            0x01, 0x02, 0x00, 0x06, // object header: class data
        ];
        let result = dissector.parse(&data, &ctx());
        assert!(result.is_some());
        if let Some(ProtocolData::Dnp3(fields)) = result {
            assert_eq!(fields.destination_address, 1);
            assert_eq!(fields.source_address, 3);
            assert_eq!(fields.function_code, 0x01);
            assert_eq!(function_code_name(fields.function_code), "Read");
            assert_eq!(fields.application_data, vec![0x01, 0x02, 0x00, 0x06]);
        } else {
            panic!("Expected Dnp3 protocol data");
        }
    }

    #[test]
    fn parse_response() {
        let dissector = Dnp3Dissector;
        // Response: function_code 0x81, followed by IIN bytes, then data
        let data: Vec<u8> = vec![
            0x05, 0x64, // start bytes
            0x0A, // length
            0x44, // control
            0x03, 0x00, // destination = 3
            0x01, 0x00, // source = 1
            0xCC, 0xDD, // CRC
            0xC0, // transport: FIR=1, FIN=1, seq=0
            0xC0, // app control
            0x81, // function code = Response
            0x00, 0x00, // IIN bytes (no flags set)
            0xDE, 0xAD, // object data
        ];
        let result = dissector.parse(&data, &ctx());
        assert!(result.is_some());
        if let Some(ProtocolData::Dnp3(fields)) = result {
            assert_eq!(fields.destination_address, 3);
            assert_eq!(fields.source_address, 1);
            assert_eq!(fields.function_code, 0x81);
            assert_eq!(function_code_name(fields.function_code), "Response");
            assert_eq!(fields.application_data, vec![0xDE, 0xAD]);
        } else {
            panic!("Expected Dnp3 protocol data");
        }
    }

    #[test]
    fn parse_unsolicited_response() {
        let dissector = Dnp3Dissector;
        let data: Vec<u8> = vec![
            0x05, 0x64, 0x08, 0x44, 0x03, 0x00, // dst = 3
            0x01, 0x00, // src = 1
            0x00, 0x00, // CRC
            0xC0, // transport
            0xC0, // app control
            0x82, // function code = Unsolicited Response
            0x80, 0x00, // IIN (device restart)
        ];
        let result = dissector.parse(&data, &ctx());
        if let Some(ProtocolData::Dnp3(fields)) = result {
            assert_eq!(fields.function_code, 0x82);
            assert_eq!(
                function_code_name(fields.function_code),
                "UnsolicitedResponse"
            );
            assert!(fields.application_data.is_empty());
        } else {
            panic!("Expected Dnp3 protocol data");
        }
    }

    #[test]
    fn parse_write_request() {
        let dissector = Dnp3Dissector;
        let data: Vec<u8> = vec![
            0x05, 0x64, 0x08, 0xC4, 0x0A, 0x00, // dst = 10
            0x14, 0x00, // src = 20
            0x00, 0x00, // CRC
            0xC0, // transport
            0xD3, // app control (FIR=1, FIN=1, CON=1, UNS=0, seq=19)
            0x02, // function code = Write
            0x50, 0x01, 0x00, 0x07, 0x01, // object data
        ];
        let result = dissector.parse(&data, &ctx());
        if let Some(ProtocolData::Dnp3(fields)) = result {
            assert_eq!(fields.destination_address, 10);
            assert_eq!(fields.source_address, 20);
            assert_eq!(fields.function_code, 0x02);
            assert_eq!(function_code_name(fields.function_code), "Write");
            assert_eq!(fields.application_data, vec![0x50, 0x01, 0x00, 0x07, 0x01]);
        } else {
            panic!("Expected Dnp3 protocol data");
        }
    }

    #[test]
    fn parse_dll_only() {
        let dissector = Dnp3Dissector;
        // Only 10 bytes — DLL header with no transport or app layer
        let data = [0x05, 0x64, 0x05, 0xC0, 0x07, 0x00, 0x08, 0x00, 0x00, 0x00];
        let result = dissector.parse(&data, &ctx());
        if let Some(ProtocolData::Dnp3(fields)) = result {
            assert_eq!(fields.source_address, 8);
            assert_eq!(fields.destination_address, 7);
            assert_eq!(fields.function_code, 0);
        } else {
            panic!("Expected Dnp3 protocol data");
        }
    }
}
