//! MQTT dissector — extracts connect metadata and publish topics from MQTT 3.1/3.1.1/5.0.

use crate::registry::{PacketContext, ProtocolData, ProtocolDissector};

#[derive(Default)]
pub struct MqttDissector;

fn packet_type_name(ptype: u8) -> &'static str {
    match ptype {
        1 => "CONNECT",
        2 => "CONNACK",
        3 => "PUBLISH",
        4 => "PUBACK",
        5 => "PUBREC",
        6 => "PUBREL",
        7 => "PUBCOMP",
        8 => "SUBSCRIBE",
        9 => "SUBACK",
        10 => "UNSUBSCRIBE",
        11 => "UNSUBACK",
        12 => "PINGREQ",
        13 => "PINGRESP",
        14 => "DISCONNECT",
        15 => "AUTH",
        _ => "UNKNOWN",
    }
}

/// Decode MQTT variable-length remaining length. Returns (value, bytes_consumed).
fn decode_remaining_length(data: &[u8]) -> Option<(usize, usize)> {
    let mut value: usize = 0;
    let mut multiplier: usize = 1;
    for (i, &byte) in data.iter().enumerate().take(4) {
        value += (byte & 0x7F) as usize * multiplier;
        if byte & 0x80 == 0 {
            return Some((value, i + 1));
        }
        multiplier *= 128;
    }
    None
}

/// Read a UTF-8 string prefixed by a 2-byte length.
fn read_mqtt_string(data: &[u8]) -> Option<(String, usize)> {
    if data.len() < 2 {
        return None;
    }
    let len = u16::from_be_bytes([data[0], data[1]]) as usize;
    if data.len() < 2 + len {
        return None;
    }
    let s = String::from_utf8_lossy(&data[2..2 + len]).to_string();
    Some((s, 2 + len))
}

impl MqttDissector {
    pub fn parse_fields(&self, data: &[u8]) -> Option<MqttFields> {
        if data.is_empty() {
            return None;
        }

        let fixed_byte = data[0];
        let packet_type = (fixed_byte >> 4) & 0x0F;
        if !(1..=15).contains(&packet_type) {
            return None;
        }

        let (remaining_length, rl_bytes) = decode_remaining_length(&data[1..])?;
        let header_len = 1 + rl_bytes;
        let payload = if data.len() >= header_len + remaining_length {
            &data[header_len..header_len + remaining_length]
        } else {
            &data[header_len..]
        };

        let mut fields = MqttFields {
            packet_type,
            packet_type_name: packet_type_name(packet_type).to_string(),
            protocol_name: None,
            protocol_version: None,
            client_id: None,
            username: None,
            topic: None,
            qos: None,
            retain: None,
            clean_session: None,
            payload: None,
        };

        match packet_type {
            1 => {
                // CONNECT
                let (proto_name, consumed) = read_mqtt_string(payload)?;
                let rest = payload.get(consumed..)?;
                if rest.is_empty() {
                    return Some(fields);
                }
                let version = rest[0];
                fields.protocol_name = Some(proto_name);
                fields.protocol_version = Some(version);

                if rest.len() < 4 {
                    return Some(fields);
                }
                let connect_flags = rest[1];
                fields.clean_session = Some(connect_flags & 0x02 != 0);
                let has_username = connect_flags & 0x80 != 0;

                // Skip keep_alive (2 bytes) to reach payload.
                let mut offset = 4;

                // MQTT 5.0 has properties length before client_id.
                if version == 5 && rest.len() > offset {
                    let (prop_len, prop_bytes) = decode_remaining_length(&rest[offset..])?;
                    offset += prop_bytes + prop_len;
                }

                if rest.len() > offset
                    && let Some((client_id, cid_len)) = read_mqtt_string(&rest[offset..])
                {
                    fields.client_id = Some(client_id);
                    offset += cid_len;
                }

                // Skip will topic/message if present.
                if connect_flags & 0x04 != 0 && rest.len() > offset {
                    // MQTT 5.0: will properties
                    if version == 5
                        && let Some((plen, pbytes)) = decode_remaining_length(&rest[offset..])
                    {
                        offset += pbytes + plen;
                    }
                    // Will topic
                    if let Some((_, wt_len)) = read_mqtt_string(rest.get(offset..)?) {
                        offset += wt_len;
                    }
                    // Will payload
                    if rest.len() > offset + 2 {
                        let wp_len = u16::from_be_bytes([rest[offset], rest[offset + 1]]) as usize;
                        offset += 2 + wp_len;
                    }
                }

                if has_username
                    && rest.len() > offset
                    && let Some((username, _)) = read_mqtt_string(&rest[offset..])
                {
                    fields.username = Some(username);
                }
            }
            3 => {
                // PUBLISH. MQTT 5.0 PUBLISH properties are not handled — Sparkplug B
                // is virtually always MQTT 3.1.1. TODO: handle MQTT 5 properties when needed.
                let qos = (fixed_byte >> 1) & 0x03;
                fields.retain = Some(fixed_byte & 0x01 != 0);
                fields.qos = Some(qos);
                if let Some((topic, topic_consumed)) = read_mqtt_string(payload) {
                    fields.topic = Some(topic);
                    let mut offset = topic_consumed;
                    // Packet identifier present only for QoS 1 and QoS 2.
                    if qos > 0 {
                        if payload.len() < offset + 2 {
                            // Truncated — leave payload as None; topic still captured.
                            return Some(fields);
                        }
                        offset += 2;
                    }
                    let body = &payload[offset..];
                    fields.payload = Some(body.to_vec());
                }
            }
            8 => {
                // SUBSCRIBE — first topic filter
                if payload.len() >= 4 {
                    // Skip packet identifier (2 bytes).
                    if let Some((topic, _)) = read_mqtt_string(&payload[2..]) {
                        fields.topic = Some(topic);
                    }
                }
            }
            _ => {}
        }

        Some(fields)
    }
}

impl ProtocolDissector for MqttDissector {
    fn name(&self) -> &str {
        "mqtt"
    }

    fn can_parse(&self, data: &[u8], src_port: u16, dst_port: u16) -> bool {
        if !matches!(src_port, 1883 | 8883) && !matches!(dst_port, 1883 | 8883) {
            return false;
        }
        if data.is_empty() {
            return false;
        }
        let ptype = (data[0] >> 4) & 0x0F;
        (1..=15).contains(&ptype)
    }

    fn parse(&self, data: &[u8], _context: &PacketContext) -> Option<ProtocolData> {
        Some(ProtocolData::Mqtt(self.parse_fields(data)?))
    }
}

#[derive(Debug, Clone)]
pub struct MqttFields {
    pub packet_type: u8,
    pub packet_type_name: String,
    pub protocol_name: Option<String>,
    pub protocol_version: Option<u8>,
    pub client_id: Option<String>,
    pub username: Option<String>,
    pub topic: Option<String>,
    pub qos: Option<u8>,
    pub retain: Option<bool>,
    pub clean_session: Option<bool>,
    /// Post-topic publish payload bytes, populated only for PUBLISH (packet_type == 3).
    /// `None` for all other packet types. Empty Vec means "PUBLISH with zero-byte payload".
    pub payload: Option<Vec<u8>>,
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
            src_port: 12345,
            dst_port: 1883,
            vlan_id: None,
            timestamp: 0,
        }
    }

    fn build_connect_packet() -> Vec<u8> {
        let mut pkt = Vec::new();
        // Fixed header: CONNECT (type 1)
        pkt.push(0x10);
        // Variable header + payload (we'll set remaining length at end)
        let mut var = Vec::new();
        // Protocol Name "MQTT"
        var.extend_from_slice(&[0x00, 0x04]);
        var.extend_from_slice(b"MQTT");
        // Protocol Version 4 (3.1.1)
        var.push(0x04);
        // Connect Flags: clean session, username flag
        var.push(0x82);
        // Keep Alive: 60
        var.extend_from_slice(&[0x00, 0x3C]);
        // Client ID "plc-sensor-01"
        let cid = b"plc-sensor-01";
        var.extend_from_slice(&(cid.len() as u16).to_be_bytes());
        var.extend_from_slice(cid);
        // Username "operator"
        let user = b"operator";
        var.extend_from_slice(&(user.len() as u16).to_be_bytes());
        var.extend_from_slice(user);

        pkt.push(var.len() as u8); // remaining length
        pkt.extend_from_slice(&var);
        pkt
    }

    fn build_publish_packet() -> Vec<u8> {
        let mut pkt = Vec::new();
        // Fixed header: PUBLISH, QoS 1, retain
        pkt.push(0x33); // 0011 0011 = PUBLISH, DUP=0, QoS=1, Retain=1
        let mut var = Vec::new();
        let topic = b"factory/line1/temp";
        var.extend_from_slice(&(topic.len() as u16).to_be_bytes());
        var.extend_from_slice(topic);
        // Packet identifier (QoS > 0)
        var.extend_from_slice(&[0x00, 0x01]);
        // Payload
        var.extend_from_slice(b"23.5");

        pkt.push(var.len() as u8);
        pkt.extend_from_slice(&var);
        pkt
    }

    #[test]
    fn parses_connect_fields() {
        let dissector = MqttDissector;
        let pkt = build_connect_packet();
        assert!(dissector.can_parse(&pkt, 12345, 1883));

        let fields = dissector.parse_fields(&pkt).expect("mqtt fields");
        assert_eq!(fields.packet_type, 1);
        assert_eq!(fields.packet_type_name, "CONNECT");
        assert_eq!(fields.protocol_name.as_deref(), Some("MQTT"));
        assert_eq!(fields.protocol_version, Some(4));
        assert_eq!(fields.client_id.as_deref(), Some("plc-sensor-01"));
        assert_eq!(fields.username.as_deref(), Some("operator"));
        assert_eq!(fields.clean_session, Some(true));
    }

    #[test]
    fn parses_publish_topic() {
        let dissector = MqttDissector;
        let pkt = build_publish_packet();
        let fields = dissector.parse_fields(&pkt).expect("mqtt fields");
        assert_eq!(fields.packet_type, 3);
        assert_eq!(fields.packet_type_name, "PUBLISH");
        assert_eq!(fields.topic.as_deref(), Some("factory/line1/temp"));
        assert_eq!(fields.qos, Some(1));
        assert_eq!(fields.retain, Some(true));
        // QoS 1 publish: payload bytes follow topic + 2-byte packet identifier.
        assert_eq!(fields.payload.as_deref(), Some(b"23.5".as_slice()));
    }

    /// Build a QoS-0 PUBLISH (no packet identifier) with a chosen topic + payload.
    fn build_publish_qos0(topic: &[u8], payload_bytes: &[u8]) -> Vec<u8> {
        let mut pkt = Vec::new();
        // Fixed header: PUBLISH, QoS 0, no retain, no DUP.
        pkt.push(0x30);
        let mut var = Vec::new();
        var.extend_from_slice(&(topic.len() as u16).to_be_bytes());
        var.extend_from_slice(topic);
        // No packet identifier for QoS 0.
        var.extend_from_slice(payload_bytes);
        pkt.push(var.len() as u8);
        pkt.extend_from_slice(&var);
        pkt
    }

    #[test]
    fn parses_publish_qos0_payload() {
        let dissector = MqttDissector;
        let pkt = build_publish_qos0(b"sensors/temp", &[0x01, 0x02, 0x03]);
        let fields = dissector.parse_fields(&pkt).expect("mqtt fields");
        assert_eq!(fields.qos, Some(0));
        assert_eq!(fields.topic.as_deref(), Some("sensors/temp"));
        // QoS 0: payload starts immediately after topic — no packet id consumed.
        assert_eq!(
            fields.payload.as_deref(),
            Some([0x01, 0x02, 0x03].as_slice())
        );
    }

    #[test]
    fn parses_publish_empty_payload() {
        let dissector = MqttDissector;
        let pkt = build_publish_qos0(b"x", &[]);
        let fields = dissector.parse_fields(&pkt).expect("mqtt fields");
        assert_eq!(fields.qos, Some(0));
        assert_eq!(fields.topic.as_deref(), Some("x"));
        // Empty Vec, not None — distinguishes "PUBLISH with no body" from "not a PUBLISH".
        assert_eq!(fields.payload.as_deref(), Some([].as_slice()));
    }

    #[test]
    fn connect_has_no_payload() {
        let dissector = MqttDissector;
        let pkt = build_connect_packet();
        let fields = dissector.parse_fields(&pkt).expect("mqtt fields");
        assert_eq!(fields.packet_type, 1);
        assert!(fields.payload.is_none());
    }

    #[test]
    fn subscribe_has_no_payload() {
        let dissector = MqttDissector;
        // Build a minimal SUBSCRIBE: type 8, packet id (2B), topic filter, requested QoS (1B).
        let mut pkt = Vec::new();
        pkt.push(0x82); // SUBSCRIBE with required reserved bits 0010
        let topic = b"foo/bar";
        let mut var = Vec::new();
        var.extend_from_slice(&[0x00, 0x01]); // packet id
        var.extend_from_slice(&(topic.len() as u16).to_be_bytes());
        var.extend_from_slice(topic);
        var.push(0x00); // requested QoS 0
        pkt.push(var.len() as u8);
        pkt.extend_from_slice(&var);

        let fields = dissector.parse_fields(&pkt).expect("mqtt fields");
        assert_eq!(fields.packet_type, 8);
        assert!(fields.payload.is_none());
    }

    #[test]
    fn binary_payload_roundtrip_sparkplug_shaped() {
        let dissector = MqttDissector;
        // Sparkplug-style topic + arbitrary binary bytes (non-UTF-8 sequence).
        let body = vec![
            0x08, 0xCD, 0x9E, 0xC9, 0xC4, 0x84, 0xB1, 0xA8, 0x06, 0x10, 0x07,
        ];
        let pkt = build_publish_qos0(b"spBv1.0/Plant1/NDATA/PLC-A", &body);
        let fields = dissector.parse_fields(&pkt).expect("mqtt fields");
        assert_eq!(fields.payload.as_ref(), Some(&body));
    }

    #[test]
    fn rejects_wrong_port() {
        let dissector = MqttDissector;
        let pkt = build_connect_packet();
        assert!(!dissector.can_parse(&pkt, 80, 80));
    }

    #[test]
    fn trait_parse_returns_mqtt_variant() {
        let dissector = MqttDissector;
        let pkt = build_connect_packet();
        assert!(matches!(
            dissector.parse(&pkt, &ctx()),
            Some(ProtocolData::Mqtt(_))
        ));
    }
}
