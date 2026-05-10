//! BACnet dissector with lightweight BVLC/NPDU/APDU parsing.

use crate::registry::{PacketContext, ProtocolData, ProtocolDissector};

#[derive(Default)]
pub struct BacnetDissector;

const BACNET_IP_PORT: u16 = 47808;

impl ProtocolDissector for BacnetDissector {
    fn name(&self) -> &str {
        "bacnet"
    }

    fn can_parse(&self, data: &[u8], src_port: u16, dst_port: u16) -> bool {
        if (src_port == BACNET_IP_PORT || dst_port == BACNET_IP_PORT)
            && data.len() >= 6
            && data[0] == 0x81
        {
            return true;
        }

        data.len() >= 3 && data[0] == 0x01
    }

    fn parse(&self, data: &[u8], _context: &PacketContext) -> Option<ProtocolData> {
        Some(ProtocolData::Bacnet(parse_bacnet(data)?))
    }
}

fn parse_bacnet(data: &[u8]) -> Option<BacnetFields> {
    let (link_variant, bvlc_function, npdu) = if data.first().copied() == Some(0x81) {
        if data.len() < 4 {
            return None;
        }
        let total_len = u16::from_be_bytes([data[2], data[3]]) as usize;
        if total_len < 4 || total_len > data.len() {
            return None;
        }
        (
            "bacnet_ip".to_string(),
            Some(bvlc_function_name(data[1]).to_string()),
            &data[4..total_len],
        )
    } else if data.first().copied() == Some(0x01) {
        ("bacnet_l2".to_string(), None, data)
    } else {
        return None;
    };

    if npdu.len() < 2 {
        return None;
    }

    let version = npdu[0];
    if version != 0x01 {
        return None;
    }

    let control = npdu[1];
    let mut offset = 2usize;

    if control & 0x20 != 0 {
        if offset + 3 > npdu.len() {
            return None;
        }
        let dlen = npdu[offset + 2] as usize;
        offset += 3;
        if offset + dlen + 1 > npdu.len() {
            return None;
        }
        offset += dlen + 1;
    }

    if control & 0x08 != 0 {
        if offset + 3 > npdu.len() {
            return None;
        }
        let slen = npdu[offset + 2] as usize;
        offset += 3;
        if offset + slen > npdu.len() {
            return None;
        }
        offset += slen;
    }

    if offset >= npdu.len() {
        return None;
    }

    if control & 0x80 != 0 {
        let message_type = npdu[offset];
        let payload = npdu[offset + 1..].to_vec();
        return Some(BacnetFields {
            link_variant,
            bvlc_function,
            npdu_control: control,
            apdu_type: "network".to_string(),
            service: bacnet_network_message_name(message_type).to_string(),
            invoke_id: None,
            device_instance: None,
            vendor_id: None,
            payload,
        });
    }

    let apdu = &npdu[offset..];
    if apdu.is_empty() {
        return None;
    }

    let apdu_type = apdu[0] >> 4;
    let (apdu_type_name, service, invoke_id, payload_offset) = match apdu_type {
        0 => {
            if apdu.len() < 4 {
                return None;
            }
            (
                "confirmed_request",
                bacnet_confirmed_service_name(apdu[3]),
                Some(apdu[2]),
                4,
            )
        }
        1 => {
            if apdu.len() < 2 {
                return None;
            }
            (
                "unconfirmed_request",
                bacnet_unconfirmed_service_name(apdu[1]),
                None,
                2,
            )
        }
        2 => {
            if apdu.len() < 3 {
                return None;
            }
            (
                "simple_ack",
                bacnet_confirmed_service_name(apdu[2]),
                Some(apdu[1]),
                3,
            )
        }
        3 => {
            if apdu.len() < 3 {
                return None;
            }
            let service_index = if apdu[0] & 0x08 != 0 { 3 } else { 2 };
            if apdu.len() <= service_index {
                return None;
            }
            (
                "complex_ack",
                bacnet_confirmed_service_name(apdu[service_index]),
                Some(apdu[1]),
                service_index + 1,
            )
        }
        4 => ("segment_ack", "segment_ack", Some(*apdu.get(1)?), 2),
        5 => ("error", "error", Some(*apdu.get(1)?), 2),
        6 => ("reject", "reject", Some(*apdu.get(1)?), 2),
        7 => ("abort", "abort", Some(*apdu.get(1)?), 2),
        _ => ("unknown", "unknown", None, 1),
    };

    let payload = apdu[payload_offset.min(apdu.len())..].to_vec();
    let (device_instance, vendor_id) = if apdu_type == 1 && apdu.get(1).copied() == Some(0x00) {
        parse_i_am_payload(&payload)
    } else {
        (None, None)
    };

    Some(BacnetFields {
        link_variant,
        bvlc_function,
        npdu_control: control,
        apdu_type: apdu_type_name.to_string(),
        service: service.to_string(),
        invoke_id,
        device_instance,
        vendor_id,
        payload,
    })
}

fn parse_i_am_payload(payload: &[u8]) -> (Option<u32>, Option<u16>) {
    let Some((device_identifier, consumed)) = parse_application_object_identifier(payload) else {
        return (None, None);
    };
    let Some((_, max_apdu_len)) =
        parse_application_unsigned(payload.get(consumed..).unwrap_or(&[]))
    else {
        return (Some(device_identifier & 0x3F_FFFF), None);
    };
    let enum_offset = consumed + max_apdu_len;
    let Some((_, segmentation_len)) =
        parse_application_enumerated(payload.get(enum_offset..).unwrap_or(&[]))
    else {
        return (Some(device_identifier & 0x3F_FFFF), None);
    };
    let vendor_offset = enum_offset + segmentation_len;
    let vendor_id = parse_application_unsigned(payload.get(vendor_offset..).unwrap_or(&[]))
        .and_then(|(value, _)| u16::try_from(value).ok());

    (Some(device_identifier & 0x3F_FFFF), vendor_id)
}

fn parse_application_object_identifier(bytes: &[u8]) -> Option<(u32, usize)> {
    if bytes.len() < 5 || bytes[0] != 0xC4 {
        return None;
    }
    Some((
        u32::from_be_bytes([bytes[1], bytes[2], bytes[3], bytes[4]]),
        5,
    ))
}

fn parse_application_unsigned(bytes: &[u8]) -> Option<(u64, usize)> {
    parse_application_primitive(bytes, 0x2)
}

fn parse_application_enumerated(bytes: &[u8]) -> Option<(u64, usize)> {
    parse_application_primitive(bytes, 0x9)
}

fn parse_application_primitive(bytes: &[u8], tag: u8) -> Option<(u64, usize)> {
    let first = *bytes.first()?;
    let observed_tag = first >> 4;
    let is_context = first & 0x08 != 0;
    let len = (first & 0x07) as usize;
    if observed_tag != tag || is_context || len == 0 || len > 4 || bytes.len() < 1 + len {
        return None;
    }
    let mut value = 0u64;
    for byte in &bytes[1..=len] {
        value = (value << 8) | *byte as u64;
    }
    Some((value, 1 + len))
}

fn bvlc_function_name(code: u8) -> &'static str {
    match code {
        0x00 => "result",
        0x04 => "forwarded_npdu",
        0x09 => "distribute_broadcast_to_network",
        0x0A => "original_unicast_npdu",
        0x0B => "original_broadcast_npdu",
        _ => "bvlc_message",
    }
}

fn bacnet_network_message_name(code: u8) -> &'static str {
    match code {
        0x00 => "who_is_router_to_network",
        0x01 => "i_am_router_to_network",
        0x02 => "i_could_be_router_to_network",
        0x03 => "reject_message_to_network",
        0x04 => "router_busy_to_network",
        0x05 => "router_available_to_network",
        0x06 => "initialize_routing_table",
        0x07 => "initialize_routing_table_ack",
        0x08 => "establish_connection_to_network",
        0x09 => "disconnect_connection_to_network",
        _ => "network_layer_message",
    }
}

fn bacnet_unconfirmed_service_name(code: u8) -> &'static str {
    match code {
        0x00 => "i_am",
        0x01 => "i_have",
        0x02 => "unconfirmed_cov_notification",
        0x07 => "who_has",
        0x08 => "who_is",
        0x09 => "utc_time_synchronization",
        0x0A => "time_synchronization",
        _ => "unconfirmed_service",
    }
}

fn bacnet_confirmed_service_name(code: u8) -> &'static str {
    match code {
        0x00 => "acknowledge_alarm",
        0x05 => "subscribe_cov",
        0x0C => "read_property",
        0x0D => "read_property_conditional",
        0x0E => "read_property_multiple",
        0x0F => "write_property",
        0x10 => "write_property_multiple",
        0x14 => "device_communication_control",
        0x1A => "read_range",
        _ => "confirmed_service",
    }
}

#[derive(Debug, Clone)]
pub struct BacnetFields {
    pub link_variant: String,
    pub bvlc_function: Option<String>,
    pub npdu_control: u8,
    pub apdu_type: String,
    pub service: String,
    pub invoke_id: Option<u8>,
    pub device_instance: Option<u32>,
    pub vendor_id: Option<u16>,
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
            src_port: BACNET_IP_PORT,
            dst_port: BACNET_IP_PORT,
            src_ip: IpAddr::V4(Ipv4Addr::new(192, 168, 0, 13)),
            dst_ip: IpAddr::V4(Ipv4Addr::new(192, 168, 0, 255)),
            vlan_id: None,
            timestamp: 0,
        }
    }

    #[test]
    fn can_parse_bacnet_ip() {
        let dissector = BacnetDissector;
        let data = [0x81, 0x0B, 0x00, 0x04, 0x01, 0x00];
        assert!(dissector.can_parse(&data, BACNET_IP_PORT, BACNET_IP_PORT));
    }

    #[test]
    fn parse_i_am_request() {
        let dissector = BacnetDissector;
        let data = vec![
            0x81, 0x0B, 0x00, 0x13, 0x01, 0x00, 0x10, 0x00, 0xC4, 0x02, 0x00, 0x00, 0x6F, 0x21,
            0x32, 0x91, 0x03, 0x21, 0x2A,
        ];

        let result = dissector.parse(&data, &ctx());
        if let Some(ProtocolData::Bacnet(fields)) = result {
            assert_eq!(fields.link_variant, "bacnet_ip");
            assert_eq!(
                fields.bvlc_function.as_deref(),
                Some("original_broadcast_npdu")
            );
            assert_eq!(fields.apdu_type, "unconfirmed_request");
            assert_eq!(fields.service, "i_am");
            assert_eq!(fields.device_instance, Some(111));
            assert_eq!(fields.vendor_id, Some(42));
        } else {
            panic!("expected bacnet fields");
        }
    }

    #[test]
    fn parse_l2_who_is_request() {
        let dissector = BacnetDissector;
        let data = vec![0x01, 0x00, 0x10, 0x08];

        let result = dissector.parse(&data, &ctx());
        if let Some(ProtocolData::Bacnet(fields)) = result {
            assert_eq!(fields.link_variant, "bacnet_l2");
            assert!(fields.bvlc_function.is_none());
            assert_eq!(fields.apdu_type, "unconfirmed_request");
            assert_eq!(fields.service, "who_is");
        } else {
            panic!("expected bacnet fields");
        }
    }
}
