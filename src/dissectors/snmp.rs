//! SNMP dissector with small BER decoder focused on enrichment fields.

use crate::registry::{PacketContext, ProtocolData, ProtocolDissector};

#[derive(Debug, Clone)]
pub struct SnmpFields {
    pub version: String,
    pub community: Option<String>,
    pub pdu_type: String,
    pub request_id: Option<i32>,
    pub var_binds: Vec<SnmpVarBind>,
    pub sys_name: Option<String>,
    pub sys_descr: Option<String>,
    pub sys_object_id: Option<String>,
    pub engine_id: Option<String>,
}

#[derive(Debug, Clone)]
pub struct SnmpVarBind {
    pub oid: String,
    pub value: Option<String>,
}

#[derive(Default)]
pub struct SnmpDissector;

const SNMP_PORT: u16 = 161;
const SNMP_TRAP_PORT: u16 = 162;

impl ProtocolDissector for SnmpDissector {
    fn name(&self) -> &str {
        "snmp"
    }

    fn can_parse(&self, data: &[u8], src_port: u16, dst_port: u16) -> bool {
        if src_port != SNMP_PORT
            && dst_port != SNMP_PORT
            && src_port != SNMP_TRAP_PORT
            && dst_port != SNMP_TRAP_PORT
        {
            return false;
        }

        matches!(data.first(), Some(0x30)) && data.len() >= 8
    }

    fn parse(&self, data: &[u8], _context: &PacketContext) -> Option<ProtocolData> {
        Some(ProtocolData::Snmp(parse_snmp(data)?))
    }
}

fn parse_snmp(data: &[u8]) -> Option<SnmpFields> {
    let mut offset = 0;
    let (tag, outer_len, value_offset) = read_tlv_header(data, &mut offset)?;
    if tag != 0x30 || value_offset + outer_len > data.len() {
        return None;
    }

    let mut seq_offset = value_offset;
    let seq_end = value_offset + outer_len;

    let version = parse_integer(read_tlv(data, &mut seq_offset, seq_end)?.1)?;
    let community = parse_octet_string(read_tlv(data, &mut seq_offset, seq_end)?.1)?;
    let (pdu_tag, pdu_len, pdu_value_offset) = read_tlv_header(data, &mut seq_offset)?;
    if pdu_value_offset + pdu_len > seq_end {
        return None;
    }

    let pdu_type = pdu_type_name(pdu_tag).to_string();

    let mut request_id = None;
    let mut sys_name = None;
    let mut sys_descr = None;
    let mut sys_object_id = None;
    let mut var_binds = Vec::new();

    let mut pdu_cursor = pdu_value_offset;
    let pdu_end = pdu_value_offset + pdu_len;

    if matches!(pdu_tag, 0xA0..=0xA3 | 0xA5 | 0xA6) {
        request_id = Some(parse_integer(read_tlv(data, &mut pdu_cursor, pdu_end)?.1)?);
        let _error_status = read_tlv(data, &mut pdu_cursor, pdu_end)?;
        let _error_index = read_tlv(data, &mut pdu_cursor, pdu_end)?;
        parse_varbinds(
            data,
            &mut pdu_cursor,
            pdu_end,
            &mut var_binds,
            &mut sys_name,
            &mut sys_descr,
            &mut sys_object_id,
        )?;
    } else if pdu_tag == 0xA4 {
        let _enterprise = read_tlv(data, &mut pdu_cursor, pdu_end)?;
        let _agent_addr = read_tlv(data, &mut pdu_cursor, pdu_end)?;
        let _generic_trap = read_tlv(data, &mut pdu_cursor, pdu_end)?;
        let _specific_trap = read_tlv(data, &mut pdu_cursor, pdu_end)?;
        let _time_stamp = read_tlv(data, &mut pdu_cursor, pdu_end)?;
        parse_varbinds(
            data,
            &mut pdu_cursor,
            pdu_end,
            &mut var_binds,
            &mut sys_name,
            &mut sys_descr,
            &mut sys_object_id,
        )?;
    } else if pdu_tag == 0xA7 {
        request_id = Some(parse_integer(read_tlv(data, &mut pdu_cursor, pdu_end)?.1)?);
        let _error_status = read_tlv(data, &mut pdu_cursor, pdu_end)?;
        let _error_index = read_tlv(data, &mut pdu_cursor, pdu_end)?;
        parse_varbinds(
            data,
            &mut pdu_cursor,
            pdu_end,
            &mut var_binds,
            &mut sys_name,
            &mut sys_descr,
            &mut sys_object_id,
        )?;
    } else {
        return None;
    }

    Some(SnmpFields {
        version: snmp_version_name(version).to_string(),
        community: (!community.is_empty()).then_some(community),
        pdu_type,
        request_id: request_id.and_then(|value| i32::try_from(value).ok()),
        var_binds,
        sys_name,
        sys_descr,
        sys_object_id,
        engine_id: None,
    })
}

fn parse_varbinds(
    data: &[u8],
    cursor: &mut usize,
    end: usize,
    out: &mut Vec<SnmpVarBind>,
    sys_name: &mut Option<String>,
    sys_descr: &mut Option<String>,
    sys_object_id: &mut Option<String>,
) -> Option<()> {
    let (vb_tag, vb_len, vb_value_offset) = read_tlv_header(data, cursor)?;
    if vb_tag != 0x30 || vb_value_offset + vb_len > end {
        return None;
    }

    let mut vb_cursor = vb_value_offset;
    let vb_end = vb_value_offset + vb_len;

    while vb_cursor < vb_end {
        let (seq_tag, seq_len, seq_value_offset) = read_tlv_header(data, &mut vb_cursor)?;
        if seq_tag != 0x30 || seq_value_offset + seq_len > vb_end {
            return None;
        }

        let mut item_cursor = seq_value_offset;
        let item_end = seq_value_offset + seq_len;
        let (oid_tag, oid_value_offset, oid_len) = read_tlv_body(data, &mut item_cursor, item_end)?;
        if oid_tag != 0x06 {
            return None;
        }
        let oid = oid_to_string(&data[oid_value_offset..oid_value_offset + oid_len])?;

        let (value_tag, value_offset, value_len) = read_tlv_body(data, &mut item_cursor, item_end)?;
        let value = decode_ber_value(value_tag, &data[value_offset..value_offset + value_len])?;
        out.push(SnmpVarBind {
            oid: oid.clone(),
            value: Some(value.clone()),
        });

        match oid.as_str() {
            "1.3.6.1.2.1.1.5.0" => *sys_name = Some(value),
            "1.3.6.1.2.1.1.1.0" => *sys_descr = Some(value),
            "1.3.6.1.2.1.1.2.0" => *sys_object_id = Some(value),
            _ => {}
        }

        vb_cursor = seq_value_offset + seq_len;
    }

    Some(())
}

fn read_tlv<'a>(data: &'a [u8], cursor: &mut usize, end: usize) -> Option<(u8, &'a [u8])> {
    let (tag, value_offset, len) = read_tlv_body(data, cursor, end)?;
    Some((tag, &data[value_offset..value_offset + len]))
}

fn read_tlv_body(data: &[u8], cursor: &mut usize, end: usize) -> Option<(u8, usize, usize)> {
    let (tag, len, value_offset) = read_tlv_header(data, cursor)?;
    if value_offset + len > end || value_offset + len > data.len() {
        return None;
    }
    *cursor = value_offset + len;
    Some((tag, value_offset, len))
}

fn read_tlv_header(data: &[u8], cursor: &mut usize) -> Option<(u8, usize, usize)> {
    if *cursor + 2 > data.len() {
        return None;
    }
    let tag = data[*cursor];
    *cursor += 1;

    let first_len = data[*cursor];
    *cursor += 1;

    let len = if first_len & 0x80 == 0 {
        first_len as usize
    } else {
        let num_bytes = (first_len & 0x7F) as usize;
        if num_bytes == 0 || num_bytes > 4 || *cursor + num_bytes > data.len() {
            return None;
        }
        let mut len = 0usize;
        for _ in 0..num_bytes {
            len = (len << 8) | data[*cursor] as usize;
            *cursor += 1;
        }
        len
    };

    let value_offset = *cursor;
    Some((tag, len, value_offset))
}

fn parse_integer(bytes: &[u8]) -> Option<i64> {
    if bytes.is_empty() {
        return None;
    }

    let mut value = 0i64;
    for &b in bytes {
        value = (value << 8) | b as i64;
    }

    if bytes[0] & 0x80 != 0 && bytes.len() < 8 {
        let sign_bit = 1i64 << (bytes.len() * 8);
        value -= sign_bit;
    }

    Some(value)
}

fn parse_octet_string(bytes: &[u8]) -> Option<String> {
    Some(String::from_utf8_lossy(bytes).to_string())
}

fn decode_ber_value(tag: u8, bytes: &[u8]) -> Option<String> {
    match tag {
        0x04 => Some(String::from_utf8_lossy(bytes).to_string()),
        0x05 => Some(String::new()),
        0x06 => oid_to_string(bytes),
        0x02 => parse_integer(bytes).map(|v| v.to_string()),
        0x40 => {
            if bytes.len() == 4 {
                Some(format!(
                    "{}.{}.{}.{}",
                    bytes[0], bytes[1], bytes[2], bytes[3]
                ))
            } else {
                None
            }
        }
        _ => Some(
            bytes
                .iter()
                .map(|b| format!("{:02x}", b))
                .collect::<Vec<_>>()
                .join(""),
        ),
    }
}

fn oid_to_string(bytes: &[u8]) -> Option<String> {
    let first = *bytes.first()?;
    let mut arcs = vec![(first / 40) as u32, (first % 40) as u32];
    let mut value = 0u32;

    for &byte in &bytes[1..] {
        value = (value << 7) | u32::from(byte & 0x7F);
        if byte & 0x80 == 0 {
            arcs.push(value);
            value = 0;
        }
    }

    if value != 0 {
        return None;
    }

    Some(
        arcs.into_iter()
            .map(|arc| arc.to_string())
            .collect::<Vec<_>>()
            .join("."),
    )
}

fn pdu_type_name(tag: u8) -> &'static str {
    match tag {
        0xA0 => "get-request",
        0xA1 => "get-next-request",
        0xA2 => "get-response",
        0xA3 => "set-request",
        0xA4 => "trap-v1",
        0xA5 => "get-bulk-request",
        0xA6 => "inform-request",
        0xA7 => "trap-v2",
        0xA8 => "report",
        _ => "unknown",
    }
}

fn snmp_version_name(version: i64) -> &'static str {
    match version {
        0 => "v1",
        1 => "v2c",
        3 => "v3",
        _ => "unknown",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::registry::PacketContext;
    use std::net::{IpAddr, Ipv4Addr};

    fn ctx(src_port: u16, dst_port: u16) -> PacketContext {
        PacketContext {
            src_mac: [0; 6],
            dst_mac: [0; 6],
            src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 20)),
            dst_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 30)),
            src_port,
            dst_port,
            vlan_id: None,
            timestamp: 0,
        }
    }

    fn tlv(tag: u8, value: &[u8]) -> Vec<u8> {
        let mut out = vec![tag];
        if value.len() < 0x80 {
            out.push(value.len() as u8);
        } else {
            let len = value.len();
            let mut len_bytes = Vec::new();
            let mut n = len;
            while n > 0 {
                len_bytes.push((n & 0xFF) as u8);
                n >>= 8;
            }
            len_bytes.reverse();
            out.push(0x80 | len_bytes.len() as u8);
            out.extend_from_slice(&len_bytes);
        }
        out.extend_from_slice(value);
        out
    }

    fn seq(children: Vec<u8>) -> Vec<u8> {
        tlv(0x30, &children)
    }

    fn int(v: i64) -> Vec<u8> {
        let mut bytes = v.to_be_bytes().to_vec();
        while bytes.len() > 1
            && ((bytes[0] == 0x00 && bytes[1] & 0x80 == 0)
                || (bytes[0] == 0xFF && bytes[1] & 0x80 != 0))
        {
            bytes.remove(0);
        }
        tlv(0x02, &bytes)
    }

    fn octets(s: &[u8]) -> Vec<u8> {
        tlv(0x04, s)
    }

    fn oid(arcs: &[u32]) -> Vec<u8> {
        assert!(arcs.len() >= 2);
        let mut out = Vec::new();
        out.push((arcs[0] * 40 + arcs[1]) as u8);
        for &arc in &arcs[2..] {
            let mut stack = vec![(arc & 0x7F) as u8];
            let mut value = arc >> 7;
            while value > 0 {
                stack.push(((value & 0x7F) as u8) | 0x80);
                value >>= 7;
            }
            stack.reverse();
            out.extend_from_slice(&stack);
        }
        tlv(0x06, &out)
    }

    fn varbind(oid_arcs: &[u32], value: Vec<u8>) -> Vec<u8> {
        seq([oid(oid_arcs), value].concat())
    }

    fn get_response_packet() -> Vec<u8> {
        let sys_descr = varbind(
            &[1, 3, 6, 1, 2, 1, 1, 1, 0],
            octets(b"Fathom OT edge appliance"),
        );
        let sys_object_id = varbind(
            &[1, 3, 6, 1, 2, 1, 1, 2, 0],
            oid(&[1, 3, 6, 1, 4, 1, 8072, 3, 2, 10]),
        );
        let sys_name = varbind(&[1, 3, 6, 1, 2, 1, 1, 5, 0], octets(b"zone-17-switch-1"));
        let varbinds = seq([sys_descr, sys_object_id, sys_name].concat());

        let pdu = tlv(0xA2, &[int(0x1234), int(0), int(0), varbinds].concat());

        seq([int(1), octets(b"public"), pdu].concat())
    }

    fn trap_v2_packet() -> Vec<u8> {
        let varbinds = seq(vec![]);
        let pdu = tlv(0xA7, &[int(99), int(0), int(0), varbinds].concat());
        seq([int(1), octets(b"public"), pdu].concat())
    }

    #[test]
    fn can_parse_snmp_ports_and_prefix() {
        let d = SnmpDissector;
        let data = get_response_packet();
        assert!(d.can_parse(&data, 161, 50000));
        assert!(d.can_parse(&data, 50000, 161));
        assert!(!d.can_parse(&data, 1234, 5678));
    }

    #[test]
    fn parse_snmp_response_extracts_system_oids() {
        let fields = parse_snmp(&get_response_packet()).expect("snmp fields");
        assert_eq!(fields.version, "v2c");
        assert_eq!(fields.community.as_deref(), Some("public"));
        assert_eq!(fields.pdu_type, "get-response");
        assert_eq!(fields.request_id, Some(0x1234));
        assert_eq!(
            fields.sys_descr.as_deref(),
            Some("Fathom OT edge appliance")
        );
        assert_eq!(
            fields.sys_object_id.as_deref(),
            Some("1.3.6.1.4.1.8072.3.2.10")
        );
        assert_eq!(fields.sys_name.as_deref(), Some("zone-17-switch-1"));
        assert_eq!(fields.var_binds.len(), 3);
    }

    #[test]
    fn parse_snmp_trap_marks_trap_type() {
        let fields = parse_snmp(&trap_v2_packet()).expect("snmp trap");
        assert_eq!(fields.pdu_type, "trap-v2");
        assert_eq!(fields.request_id, Some(99));
    }

    #[test]
    fn trait_parse_returns_snmp_variant() {
        let d = SnmpDissector;
        assert!(matches!(
            d.parse(&get_response_packet(), &ctx(161, 50000)),
            Some(ProtocolData::Snmp(_))
        ));
    }
}
