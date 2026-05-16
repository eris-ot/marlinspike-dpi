//! Modbus/TCP dissector.
//!
//! MBAP header (7 bytes): transaction_id (2), protocol_id (2, must be 0),
//! length (2), unit_id (1). Followed by PDU: function_code (1) + data.
//!
//! Supported function codes: 01 Read Coils, 02 Read Discrete Inputs,
//! 03 Read Holding Registers, 04 Read Input Registers, 05 Write Single Coil,
//! 06 Write Single Register, 15 Write Multiple Coils, 16 Write Multiple
//! Registers. Exception responses (FC | 0x80) are always handled. FC 43
//! (Read Device Identification) is parsed for AssetObservation enrichment.

use std::collections::BTreeMap;

use crate::registry::{PacketContext, ProtocolData, ProtocolDissector};

/// Direction of a Modbus PDU relative to the server (unit).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ModbusDirection {
    /// Client → server (master → slave).
    Request,
    /// Server → client (slave → master).
    Response,
}

/// Structured Modbus PDU extracted from a single MBAP frame.
///
/// Carries the full semantic content needed by Silver for register profiling:
/// start address, quantity, values, direction, and exception code.
#[derive(Debug, Clone)]
pub struct ModbusPdu {
    /// Base function code (high-bit stripped).
    pub function_code: u8,
    /// Request or response frame.
    pub direction: ModbusDirection,
    /// Starting register / coil address (0-based). None for response frames
    /// where the server does not echo the address (FC 01/02/03/04 response).
    pub start_addr: Option<u16>,
    /// Quantity of registers or coils. Populated on requests for read FCs and
    /// on both request and response for write-multiple FCs.
    pub qty: Option<u16>,
    /// Register or coil values. Write FCs populate this on the request;
    /// read FCs populate this on the response. Coil bits are packed per the
    /// Modbus spec and stored one-per-u16 (0 or 1) for uniform handling.
    pub values: Vec<u16>,
    /// Exception code present when the frame is an exception response.
    pub exception_code: Option<u8>,
}

#[derive(Debug, Clone)]
pub struct ModbusFields {
    pub transaction_id: u16,
    pub unit_id: u8,
    pub function_code: u8,
    pub is_exception: bool,
    pub exception_code: u8,
    /// Structured PDU — the authoritative source for Silver register profiling.
    pub pdu: Option<ModbusPdu>,
    /// Legacy flat register pairs kept for backward compat with engine helpers.
    pub registers: Vec<(u16, u16)>,
    pub device_identification: BTreeMap<String, String>,
}

#[derive(Default)]
pub struct ModbusDissector;

const MODBUS_PORT: u16 = 502;

impl ProtocolDissector for ModbusDissector {
    fn name(&self) -> &str {
        "modbus"
    }

    fn can_parse(&self, data: &[u8], src_port: u16, dst_port: u16) -> bool {
        if src_port != MODBUS_PORT && dst_port != MODBUS_PORT {
            return false;
        }
        if data.len() < 8 {
            return false;
        }
        let protocol_id = u16::from_be_bytes([data[2], data[3]]);
        if protocol_id != 0 {
            return false;
        }
        let mbap_length = u16::from_be_bytes([data[4], data[5]]) as usize;
        if !(2..=253).contains(&mbap_length) {
            return false;
        }
        let expected = 6 + mbap_length;
        if data.len() < expected || data.len() > expected + 6 {
            return false;
        }
        let fc = data[7];
        let base_fc = fc & 0x7F;
        (1..=127).contains(&base_fc)
    }

    fn parse(&self, data: &[u8], context: &PacketContext) -> Option<ProtocolData> {
        if data.len() < 8 {
            return None;
        }

        let transaction_id = u16::from_be_bytes([data[0], data[1]]);
        let protocol_id = u16::from_be_bytes([data[2], data[3]]);
        if protocol_id != 0 {
            return None;
        }
        let _length = u16::from_be_bytes([data[4], data[5]]);
        let unit_id = data[6];
        let function_code = data[7];

        let is_exception = function_code & 0x80 != 0;
        let base_fc = function_code & 0x7F;

        let mut exception_code = 0u8;
        if is_exception && data.len() >= 9 {
            exception_code = data[8];
        }

        // Determine direction: request is client→server (dst_port == 502).
        let is_request = context.dst_port == MODBUS_PORT && context.src_port != MODBUS_PORT;
        let direction = if is_request {
            ModbusDirection::Request
        } else {
            ModbusDirection::Response
        };

        let pdu = if is_exception {
            Some(ModbusPdu {
                function_code: base_fc,
                direction,
                start_addr: None,
                qty: None,
                values: Vec::new(),
                exception_code: Some(exception_code),
            })
        } else {
            parse_pdu(base_fc, &data[8..], direction)
        };

        let device_identification = if !is_exception {
            parse_device_identification(base_fc, &data[8..])
        } else {
            BTreeMap::new()
        };

        // Build legacy registers for backward compat with engine helper functions.
        let registers = pdu_to_legacy_registers(pdu.as_ref());

        Some(ProtocolData::Modbus(ModbusFields {
            transaction_id,
            unit_id,
            function_code: base_fc,
            is_exception,
            exception_code,
            pdu,
            registers,
            device_identification,
        }))
    }
}

/// Parse a Modbus PDU body (bytes after the function code byte) into a
/// [`ModbusPdu`] for all supported function codes. Returns `None` only if the
/// payload is too short to contain required fields.
fn parse_pdu(function_code: u8, pdu_data: &[u8], direction: ModbusDirection) -> Option<ModbusPdu> {
    match function_code {
        // FC 01 Read Coils, FC 02 Read Discrete Inputs
        1 | 2 => match direction {
            ModbusDirection::Request => {
                if pdu_data.len() < 4 {
                    return None;
                }
                let start_addr = u16::from_be_bytes([pdu_data[0], pdu_data[1]]);
                let qty = u16::from_be_bytes([pdu_data[2], pdu_data[3]]);
                Some(ModbusPdu {
                    function_code,
                    direction,
                    start_addr: Some(start_addr),
                    qty: Some(qty),
                    values: Vec::new(),
                    exception_code: None,
                })
            }
            ModbusDirection::Response => {
                if pdu_data.is_empty() {
                    return None;
                }
                let byte_count = pdu_data[0] as usize;
                let coil_bytes = pdu_data.get(1..1 + byte_count)?;
                // Unpack coil bits: LSB of each byte is the first coil.
                let values: Vec<u16> = coil_bytes
                    .iter()
                    .flat_map(|&b| (0..8).map(move |bit| u16::from((b >> bit) & 1)))
                    .collect();
                Some(ModbusPdu {
                    function_code,
                    direction,
                    start_addr: None,
                    qty: None,
                    values,
                    exception_code: None,
                })
            }
        },

        // FC 03 Read Holding Registers, FC 04 Read Input Registers
        3 | 4 => match direction {
            ModbusDirection::Request => {
                if pdu_data.len() < 4 {
                    return None;
                }
                let start_addr = u16::from_be_bytes([pdu_data[0], pdu_data[1]]);
                let qty = u16::from_be_bytes([pdu_data[2], pdu_data[3]]);
                Some(ModbusPdu {
                    function_code,
                    direction,
                    start_addr: Some(start_addr),
                    qty: Some(qty),
                    values: Vec::new(),
                    exception_code: None,
                })
            }
            ModbusDirection::Response => {
                if pdu_data.is_empty() {
                    return None;
                }
                let byte_count = pdu_data[0] as usize;
                let reg_bytes = pdu_data.get(1..1 + byte_count)?;
                let values: Vec<u16> = reg_bytes
                    .chunks_exact(2)
                    .map(|b| u16::from_be_bytes([b[0], b[1]]))
                    .collect();
                Some(ModbusPdu {
                    function_code,
                    direction,
                    start_addr: None,
                    qty: None,
                    values,
                    exception_code: None,
                })
            }
        },

        // FC 05 Write Single Coil — same layout for request and echo response
        5 => {
            if pdu_data.len() < 4 {
                return None;
            }
            let addr = u16::from_be_bytes([pdu_data[0], pdu_data[1]]);
            let raw = u16::from_be_bytes([pdu_data[2], pdu_data[3]]);
            // Spec: 0xFF00 = ON, 0x0000 = OFF
            let value = if raw == 0xFF00 { 1u16 } else { 0u16 };
            Some(ModbusPdu {
                function_code,
                direction,
                start_addr: Some(addr),
                qty: None,
                values: vec![value],
                exception_code: None,
            })
        }

        // FC 06 Write Single Register — same layout for request and echo response
        6 => {
            if pdu_data.len() < 4 {
                return None;
            }
            let addr = u16::from_be_bytes([pdu_data[0], pdu_data[1]]);
            let value = u16::from_be_bytes([pdu_data[2], pdu_data[3]]);
            Some(ModbusPdu {
                function_code,
                direction,
                start_addr: Some(addr),
                qty: None,
                values: vec![value],
                exception_code: None,
            })
        }

        // FC 15 Write Multiple Coils
        15 => match direction {
            ModbusDirection::Request => {
                if pdu_data.len() < 5 {
                    return None;
                }
                let start_addr = u16::from_be_bytes([pdu_data[0], pdu_data[1]]);
                let qty = u16::from_be_bytes([pdu_data[2], pdu_data[3]]);
                let byte_count = pdu_data[4] as usize;
                let coil_bytes = pdu_data.get(5..5 + byte_count).unwrap_or(&[]);
                let values: Vec<u16> = coil_bytes
                    .iter()
                    .flat_map(|&b| (0..8).map(move |bit| u16::from((b >> bit) & 1)))
                    .take(qty as usize)
                    .collect();
                Some(ModbusPdu {
                    function_code,
                    direction,
                    start_addr: Some(start_addr),
                    qty: Some(qty),
                    values,
                    exception_code: None,
                })
            }
            ModbusDirection::Response => {
                // Echo: start_addr(2) + qty(2)
                if pdu_data.len() < 4 {
                    return None;
                }
                let start_addr = u16::from_be_bytes([pdu_data[0], pdu_data[1]]);
                let qty = u16::from_be_bytes([pdu_data[2], pdu_data[3]]);
                Some(ModbusPdu {
                    function_code,
                    direction,
                    start_addr: Some(start_addr),
                    qty: Some(qty),
                    values: Vec::new(),
                    exception_code: None,
                })
            }
        },

        // FC 16 Write Multiple Registers
        16 => match direction {
            ModbusDirection::Request => {
                if pdu_data.len() < 5 {
                    return None;
                }
                let start_addr = u16::from_be_bytes([pdu_data[0], pdu_data[1]]);
                let qty = u16::from_be_bytes([pdu_data[2], pdu_data[3]]);
                let byte_count = pdu_data[4] as usize;
                let reg_bytes = pdu_data.get(5..5 + byte_count).unwrap_or(&[]);
                let values: Vec<u16> = reg_bytes
                    .chunks_exact(2)
                    .map(|b| u16::from_be_bytes([b[0], b[1]]))
                    .collect();
                Some(ModbusPdu {
                    function_code,
                    direction,
                    start_addr: Some(start_addr),
                    qty: Some(qty),
                    values,
                    exception_code: None,
                })
            }
            ModbusDirection::Response => {
                // Echo: start_addr(2) + qty(2)
                if pdu_data.len() < 4 {
                    return None;
                }
                let start_addr = u16::from_be_bytes([pdu_data[0], pdu_data[1]]);
                let qty = u16::from_be_bytes([pdu_data[2], pdu_data[3]]);
                Some(ModbusPdu {
                    function_code,
                    direction,
                    start_addr: Some(start_addr),
                    qty: Some(qty),
                    values: Vec::new(),
                    exception_code: None,
                })
            }
        },

        // All other FCs (including FC 43 device identification) — no register data
        _ => Some(ModbusPdu {
            function_code,
            direction,
            start_addr: None,
            qty: None,
            values: Vec::new(),
            exception_code: None,
        }),
    }
}

/// Convert structured PDU to legacy `(address, value)` pairs for backward
/// compat with engine helper functions that pre-date `ModbusPdu`.
fn pdu_to_legacy_registers(pdu: Option<&ModbusPdu>) -> Vec<(u16, u16)> {
    let Some(pdu) = pdu else {
        return Vec::new();
    };
    if pdu.exception_code.is_some() {
        return Vec::new();
    }
    match pdu.direction {
        ModbusDirection::Request => match pdu.function_code {
            // Read requests: encode as (start_addr, qty)
            1..=4 => {
                if let (Some(addr), Some(qty)) = (pdu.start_addr, pdu.qty) {
                    vec![(addr, qty)]
                } else {
                    Vec::new()
                }
            }
            // Write single: (addr, value)
            5 | 6 => {
                if let Some(addr) = pdu.start_addr {
                    pdu.values
                        .first()
                        .map(|&v| vec![(addr, v)])
                        .unwrap_or_default()
                } else {
                    Vec::new()
                }
            }
            // Write multiple: (start_addr + i, value[i])
            15 | 16 => {
                let base = pdu.start_addr.unwrap_or(0);
                pdu.values
                    .iter()
                    .enumerate()
                    .map(|(i, &v)| (base + i as u16, v))
                    .collect()
            }
            _ => Vec::new(),
        },
        ModbusDirection::Response => match pdu.function_code {
            // Read responses: (index, value) — address not known without request
            1..=4 => pdu
                .values
                .iter()
                .enumerate()
                .map(|(i, &v)| (i as u16, v))
                .collect(),
            // Write echo: (addr, value)
            5 | 6 => {
                if let Some(addr) = pdu.start_addr {
                    pdu.values
                        .first()
                        .map(|&v| vec![(addr, v)])
                        .unwrap_or_default()
                } else {
                    Vec::new()
                }
            }
            15 | 16 => Vec::new(),
            _ => Vec::new(),
        },
    }
}

fn parse_device_identification(function_code: u8, pdu_data: &[u8]) -> BTreeMap<String, String> {
    if function_code != 43 || pdu_data.len() < 6 || pdu_data[0] != 0x0E {
        return BTreeMap::new();
    }

    let object_count = pdu_data[5] as usize;
    let mut offset = 6;
    let mut out = BTreeMap::new();

    for _ in 0..object_count {
        if offset + 2 > pdu_data.len() {
            break;
        }
        let object_id = pdu_data[offset];
        let len = pdu_data[offset + 1] as usize;
        offset += 2;
        if offset + len > pdu_data.len() {
            break;
        }
        let value = String::from_utf8_lossy(&pdu_data[offset..offset + len]).to_string();
        offset += len;

        let key = match object_id {
            0x00 => "vendor_name",
            0x01 => "product_code",
            0x02 => "revision",
            0x03 => "vendor_url",
            0x04 => "product_name",
            0x05 => "model_name",
            0x06 => "user_application_name",
            _ => continue,
        };
        out.insert(key.to_string(), value);
    }

    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    fn ctx_request() -> PacketContext {
        PacketContext {
            src_mac: [0; 6],
            dst_mac: [0; 6],
            src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            dst_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            src_port: 49152,
            dst_port: 502,
            vlan_id: None,
            timestamp: 0,
        }
    }

    fn ctx_response() -> PacketContext {
        PacketContext {
            src_mac: [0; 6],
            dst_mac: [0; 6],
            src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            dst_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            src_port: 502,
            dst_port: 49152,
            vlan_id: None,
            timestamp: 0,
        }
    }

    // ── FC 01 Read Coils ──────────────────────────────────────────────────────

    #[test]
    fn fc01_read_coils_request() {
        let pkt = [
            0x00, 0x01, 0x00, 0x00, 0x00, 0x06, 0x01, 0x01, // FC 01
            0x00, 0x13, // start addr: 19
            0x00, 0x25, // qty: 37
        ];
        let d = ModbusDissector;
        let result = d.parse(&pkt, &ctx_request()).unwrap();
        match result {
            ProtocolData::Modbus(m) => {
                assert_eq!(m.function_code, 1);
                assert!(!m.is_exception);
                let pdu = m.pdu.unwrap();
                assert_eq!(pdu.direction, ModbusDirection::Request);
                assert_eq!(pdu.start_addr, Some(19));
                assert_eq!(pdu.qty, Some(37));
                assert!(pdu.values.is_empty());
                assert!(pdu.exception_code.is_none());
            }
            _ => panic!("expected Modbus"),
        }
    }

    #[test]
    fn fc01_read_coils_response() {
        // 37 coils → 5 bytes of coil data (0xCD 0x6B 0xB2 0x0E 0x1B)
        let pkt = [
            0x00, 0x01, 0x00, 0x00, 0x00, 0x08, 0x01, 0x01, // FC 01
            0x05, // byte count
            0xCD, 0x6B, 0xB2, 0x0E, 0x1B,
        ];
        let d = ModbusDissector;
        let result = d.parse(&pkt, &ctx_response()).unwrap();
        match result {
            ProtocolData::Modbus(m) => {
                let pdu = m.pdu.unwrap();
                assert_eq!(pdu.direction, ModbusDirection::Response);
                // 5 bytes × 8 bits = 40 coil values
                assert_eq!(pdu.values.len(), 40);
                // First byte 0xCD = 1100_1101 → coils 0..7: 1,0,1,1,0,0,1,1
                assert_eq!(pdu.values[0], 1);
                assert_eq!(pdu.values[1], 0);
                assert_eq!(pdu.values[2], 1);
                assert_eq!(pdu.values[3], 1);
            }
            _ => panic!("expected Modbus"),
        }
    }

    // ── FC 02 Read Discrete Inputs ────────────────────────────────────────────

    #[test]
    fn fc02_read_discrete_inputs_request() {
        let pkt = [
            0x00, 0x02, 0x00, 0x00, 0x00, 0x06, 0x01, 0x02, // FC 02
            0x00, 0xC4, // start addr: 196
            0x00, 0x16, // qty: 22
        ];
        let d = ModbusDissector;
        let result = d.parse(&pkt, &ctx_request()).unwrap();
        match result {
            ProtocolData::Modbus(m) => {
                let pdu = m.pdu.unwrap();
                assert_eq!(pdu.function_code, 2);
                assert_eq!(pdu.start_addr, Some(196));
                assert_eq!(pdu.qty, Some(22));
            }
            _ => panic!("expected Modbus"),
        }
    }

    // ── FC 03 Read Holding Registers ─────────────────────────────────────────

    #[test]
    fn fc03_read_holding_registers_request() {
        let pkt = [
            0x00, 0x01, 0x00, 0x00, 0x00, 0x06, 0x01, 0x03, // FC 03
            0x00, 0x64, // start addr: 100
            0x00, 0x02, // qty: 2
        ];
        let d = ModbusDissector;
        assert!(d.can_parse(&pkt, 49152, 502));
        let result = d.parse(&pkt, &ctx_request()).unwrap();
        match result {
            ProtocolData::Modbus(m) => {
                assert_eq!(m.function_code, 3);
                assert!(!m.is_exception);
                let pdu = m.pdu.unwrap();
                assert_eq!(pdu.direction, ModbusDirection::Request);
                assert_eq!(pdu.start_addr, Some(100));
                assert_eq!(pdu.qty, Some(2));
                assert!(pdu.values.is_empty());
                // Legacy compat
                assert_eq!(m.registers, vec![(100, 2)]);
            }
            _ => panic!("expected Modbus"),
        }
    }

    #[test]
    fn fc03_read_holding_registers_response() {
        let pkt = [
            0x00, 0x01, 0x00, 0x00, 0x00, 0x07, 0x01, 0x03, // FC 03
            0x04, // byte count: 4
            0x00, 0x0A, // reg 0: 10
            0x00, 0x14, // reg 1: 20
        ];
        let d = ModbusDissector;
        let result = d.parse(&pkt, &ctx_response()).unwrap();
        match result {
            ProtocolData::Modbus(m) => {
                assert_eq!(m.function_code, 3);
                let pdu = m.pdu.unwrap();
                assert_eq!(pdu.direction, ModbusDirection::Response);
                assert_eq!(pdu.values, vec![10, 20]);
                // Legacy: (index, value)
                assert_eq!(m.registers, vec![(0, 10), (1, 20)]);
            }
            _ => panic!("expected Modbus"),
        }
    }

    // ── FC 04 Read Input Registers ────────────────────────────────────────────

    #[test]
    fn fc04_read_input_registers_request() {
        let pkt = [
            0x00, 0x03, 0x00, 0x00, 0x00, 0x06, 0x01, 0x04, // FC 04
            0x00, 0x08, // start addr: 8
            0x00, 0x01, // qty: 1
        ];
        let d = ModbusDissector;
        let result = d.parse(&pkt, &ctx_request()).unwrap();
        match result {
            ProtocolData::Modbus(m) => {
                let pdu = m.pdu.unwrap();
                assert_eq!(pdu.function_code, 4);
                assert_eq!(pdu.start_addr, Some(8));
                assert_eq!(pdu.qty, Some(1));
            }
            _ => panic!("expected Modbus"),
        }
    }

    // ── FC 05 Write Single Coil ───────────────────────────────────────────────

    #[test]
    fn fc05_write_single_coil_on() {
        let pkt = [
            0x00, 0x04, 0x00, 0x00, 0x00, 0x06, 0x01, 0x05, // FC 05
            0x00, 0xAC, // addr: 172
            0xFF, 0x00, // value: ON
        ];
        let d = ModbusDissector;
        let result = d.parse(&pkt, &ctx_request()).unwrap();
        match result {
            ProtocolData::Modbus(m) => {
                let pdu = m.pdu.unwrap();
                assert_eq!(pdu.function_code, 5);
                assert_eq!(pdu.start_addr, Some(172));
                assert_eq!(pdu.values, vec![1]);
                assert_eq!(m.registers, vec![(172, 1)]);
            }
            _ => panic!("expected Modbus"),
        }
    }

    #[test]
    fn fc05_write_single_coil_off() {
        let pkt = [
            0x00, 0x04, 0x00, 0x00, 0x00, 0x06, 0x01, 0x05, // FC 05
            0x00, 0xAC, // addr: 172
            0x00, 0x00, // value: OFF
        ];
        let d = ModbusDissector;
        let result = d.parse(&pkt, &ctx_request()).unwrap();
        match result {
            ProtocolData::Modbus(m) => {
                let pdu = m.pdu.unwrap();
                assert_eq!(pdu.values, vec![0]);
            }
            _ => panic!("expected Modbus"),
        }
    }

    // ── FC 06 Write Single Register ──────────────────────────────────────────

    #[test]
    fn fc06_write_single_register() {
        let pkt = [
            0x00, 0x02, 0x00, 0x00, 0x00, 0x06, 0x01, 0x06, // FC 06
            0x00, 0x01, // addr: 1
            0x00, 0xFF, // value: 255
        ];
        let d = ModbusDissector;
        let result = d.parse(&pkt, &ctx_request()).unwrap();
        match result {
            ProtocolData::Modbus(m) => {
                assert_eq!(m.function_code, 6);
                let pdu = m.pdu.unwrap();
                assert_eq!(pdu.start_addr, Some(1));
                assert_eq!(pdu.values, vec![255]);
                assert_eq!(m.registers, vec![(1, 255)]);
            }
            _ => panic!("expected Modbus"),
        }
    }

    // ── FC 15 Write Multiple Coils ────────────────────────────────────────────

    #[test]
    fn fc15_write_multiple_coils_request() {
        // Write 10 coils starting at addr 20: 1010 1100 11 (packed: 0xCD 0x01)
        // 0xCD = 1100_1101 → bits: 1,0,1,1,0,0,1,1
        // 0x01 = 0000_0001 → bits: 1,0 (only 2 more needed for 10 total)
        let pkt = [
            0x00, 0x0F, 0x00, 0x00, 0x00, 0x09, 0x01, 0x0F, // FC 15
            0x00, 0x14, // start addr: 20
            0x00, 0x0A, // qty: 10
            0x02, // byte count: 2
            0xCD, 0x01,
        ];
        let d = ModbusDissector;
        let result = d.parse(&pkt, &ctx_request()).unwrap();
        match result {
            ProtocolData::Modbus(m) => {
                let pdu = m.pdu.unwrap();
                assert_eq!(pdu.function_code, 15);
                assert_eq!(pdu.start_addr, Some(20));
                assert_eq!(pdu.qty, Some(10));
                assert_eq!(pdu.values.len(), 10);
                // First coil (LSB of 0xCD = 1)
                assert_eq!(pdu.values[0], 1);
                // Second coil (bit 1 of 0xCD = 0)
                assert_eq!(pdu.values[1], 0);
            }
            _ => panic!("expected Modbus"),
        }
    }

    // ── FC 16 Write Multiple Registers ───────────────────────────────────────

    #[test]
    fn fc16_write_multiple_registers_request() {
        let pkt = [
            0x00, 0x03, 0x00, 0x00, 0x00, 0x0B, 0x01, 0x10, // FC 16
            0x00, 0x0A, // start addr: 10
            0x00, 0x02, // qty: 2
            0x04, // byte count: 4
            0x00, 0x01, // value 0: 1
            0x00, 0x02, // value 1: 2
        ];
        let d = ModbusDissector;
        let result = d.parse(&pkt, &ctx_request()).unwrap();
        match result {
            ProtocolData::Modbus(m) => {
                assert_eq!(m.function_code, 16);
                let pdu = m.pdu.unwrap();
                assert_eq!(pdu.start_addr, Some(10));
                assert_eq!(pdu.qty, Some(2));
                assert_eq!(pdu.values, vec![1, 2]);
                // Legacy: (start_addr + i, value[i])
                assert_eq!(m.registers, vec![(10, 1), (11, 2)]);
            }
            _ => panic!("expected Modbus"),
        }
    }

    // ── Exception responses ───────────────────────────────────────────────────

    #[test]
    fn exception_response_fc03() {
        let pkt = [
            0x00, 0x01, 0x00, 0x00, 0x00, 0x03, 0x01, 0x83, // FC 03 | 0x80 = exception
            0x02, // exception code: illegal data address
        ];
        let d = ModbusDissector;
        let result = d.parse(&pkt, &ctx_response()).unwrap();
        match result {
            ProtocolData::Modbus(m) => {
                assert!(m.is_exception);
                assert_eq!(m.function_code, 3);
                assert_eq!(m.exception_code, 2);
                let pdu = m.pdu.unwrap();
                assert_eq!(pdu.exception_code, Some(2));
                assert!(m.registers.is_empty());
            }
            _ => panic!("expected Modbus"),
        }
    }

    #[test]
    fn exception_response_fc06() {
        let pkt = [
            0x00, 0x05, 0x00, 0x00, 0x00, 0x03, 0x01, 0x86, // FC 06 | 0x80
            0x04, // exception: server device failure
        ];
        let d = ModbusDissector;
        let result = d.parse(&pkt, &ctx_response()).unwrap();
        match result {
            ProtocolData::Modbus(m) => {
                assert!(m.is_exception);
                assert_eq!(m.function_code, 6);
                assert_eq!(m.exception_code, 4);
            }
            _ => panic!("expected Modbus"),
        }
    }

    // ── FC 43 Device Identification ───────────────────────────────────────────

    #[test]
    fn fc43_device_identification_response() {
        let mut pkt = vec![
            0x00, 0x03, 0x00, 0x00, 0x00, 0x00, 0x01, 0x2B, // FC 43
            0x0E, 0x01, 0x01, 0x00, 0x00, 0x03, // 3 objects
            0x00, 0x09,
        ];
        pkt.extend_from_slice(b"Schneider");
        pkt.extend_from_slice(&[0x05, 0x07]);
        pkt.extend_from_slice(b"M580CPU");
        pkt.extend_from_slice(&[0x02, 0x04]);
        pkt.extend_from_slice(b"2.30");
        let mbap_len = (pkt.len() - 6) as u16;
        pkt[4..6].copy_from_slice(&mbap_len.to_be_bytes());

        let d = ModbusDissector;
        let result = d.parse(&pkt, &ctx_response()).unwrap();
        match result {
            ProtocolData::Modbus(m) => {
                assert_eq!(m.function_code, 43);
                assert_eq!(
                    m.device_identification
                        .get("vendor_name")
                        .map(|s| s.as_str()),
                    Some("Schneider")
                );
                assert_eq!(
                    m.device_identification
                        .get("model_name")
                        .map(|s| s.as_str()),
                    Some("M580CPU")
                );
            }
            _ => panic!("expected Modbus"),
        }
    }

    #[test]
    fn wrong_port_rejected() {
        let pkt = [0x00u8; 12];
        let d = ModbusDissector;
        assert!(!d.can_parse(&pkt, 1234, 5678));
    }
}
