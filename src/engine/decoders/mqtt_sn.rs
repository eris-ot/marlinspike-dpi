//! MQTT-SN (Sensor Networks) `SessionDecoder`.
//!
//! MQTT-SN is the constrained-network publish/subscribe protocol for low-power
//! OT field devices: ZigBee/IPv6 bridges, battery sensors, LPWAN nodes. It runs
//! over UDP with much smaller frames than full MQTT.
//!
//! Reference: MQTT-SN Specification Version 1.2 (MQTT.org, 2013-11-14).
//!
//! # Length encoding — the trickiest part of the wire format
//!
//! Every MQTT-SN frame begins with a variable-length header:
//!
//! ```text
//! Short header  (frames ≤ 255 bytes):
//!   byte 0       — total frame length (covers itself + all subsequent bytes)
//!   byte 1       — MsgType
//!   byte 2..     — type-specific payload
//!
//! Extended header (frames > 255 bytes, or forced):
//!   byte 0       — 0x01 (sentinel: "extended length follows")
//!   byte 1..=2   — total frame length as u16 big-endian
//!   byte 3       — MsgType
//!   byte 4..     — type-specific payload
//! ```
//!
//! So: if `data[0] == 0x01` → extended path (4-byte header); otherwise
//! `data[0]` *is* the length and `data[1]` is MsgType (2-byte header).

use std::collections::BTreeMap;
use std::net::IpAddr;

use crate::bronze::{
    AssetObservation, BronzeEvent, BronzeEventFamily, ProtocolTransaction, TransportProtocol,
};
use crate::engine::{
    build_envelope, new_event, parse_anomaly_event, DecoderInterest, SessionDecoder, StreamChunk,
};

// ── Message type constants ────────────────────────────────────────

const MSG_ADVERTISE: u8              = 0x00;
const MSG_SEARCHGW: u8               = 0x01;
const MSG_GWINFO: u8                 = 0x02;
const MSG_CONNECT: u8                = 0x04;
const MSG_CONNACK: u8                = 0x05;
const MSG_WILLTOPICREQ: u8           = 0x06;
const MSG_WILLTOPIC: u8              = 0x07;
const MSG_WILLMSGREQ: u8             = 0x08;
const MSG_WILLMSG: u8                = 0x09;
const MSG_REGISTER: u8               = 0x0A;
const MSG_REGACK: u8                 = 0x0B;
const MSG_PUBLISH: u8                = 0x0C;
const MSG_PUBACK: u8                 = 0x0D;
const MSG_PUBCOMP: u8                = 0x0E;
const MSG_PUBREC: u8                 = 0x0F;
const MSG_PUBREL: u8                 = 0x10;
const MSG_SUBSCRIBE: u8              = 0x12;
const MSG_SUBACK: u8                 = 0x13;
const MSG_UNSUBSCRIBE: u8            = 0x14;
const MSG_UNSUBACK: u8               = 0x15;
const MSG_PINGREQ: u8                = 0x16;
const MSG_PINGRESP: u8               = 0x17;
const MSG_DISCONNECT: u8             = 0x18;
const MSG_WILLTOPICUPD: u8           = 0x1A;
const MSG_WILLTOPICRESP: u8          = 0x1B;
const MSG_WILLMSGUPD: u8             = 0x1C;
const MSG_WILLMSGRESP: u8            = 0x1D;
const MSG_FORWARDER_ENCAPSULATION: u8 = 0xFE;

// ── Header parsing ────────────────────────────────────────────────

struct MqttSnFrame<'a> {
    length:   usize,
    msg_type: u8,
    payload:  &'a [u8],
}

/// Decode the variable-length header. Returns `None` if the datagram is too
/// short. Does not validate `data.len() == length`; the caller handles that.
fn parse_header(data: &[u8]) -> Option<MqttSnFrame<'_>> {
    if data.is_empty() { return None; }
    if data[0] == 0x01 {
        // Extended header: sentinel | u16 BE length | msg_type
        if data.len() < 4 { return None; }
        let length   = u16::from_be_bytes([data[1], data[2]]) as usize;
        let msg_type = data[3];
        let end      = length.min(data.len());
        Some(MqttSnFrame { length, msg_type, payload: if end >= 4 { &data[4..end] } else { &[] } })
    } else {
        // Short header: length | msg_type
        if data.len() < 2 { return None; }
        let length   = data[0] as usize;
        let msg_type = data[1];
        let end      = length.min(data.len());
        Some(MqttSnFrame { length, msg_type, payload: if end >= 2 { &data[2..end] } else { &[] } })
    }
}

fn msg_type_name(t: u8) -> &'static str {
    match t {
        MSG_ADVERTISE              => "mqtt_sn_advertise",
        MSG_SEARCHGW               => "mqtt_sn_searchgw",
        MSG_GWINFO                 => "mqtt_sn_gwinfo",
        MSG_CONNECT                => "mqtt_sn_connect",
        MSG_CONNACK                => "mqtt_sn_connack",
        MSG_WILLTOPICREQ           => "mqtt_sn_willtopicreq",
        MSG_WILLTOPIC              => "mqtt_sn_willtopic",
        MSG_WILLMSGREQ             => "mqtt_sn_willmsgreq",
        MSG_WILLMSG                => "mqtt_sn_willmsg",
        MSG_REGISTER               => "mqtt_sn_register",
        MSG_REGACK                 => "mqtt_sn_regack",
        MSG_PUBLISH                => "mqtt_sn_publish",
        MSG_PUBACK                 => "mqtt_sn_puback",
        MSG_PUBCOMP                => "mqtt_sn_pubcomp",
        MSG_PUBREC                 => "mqtt_sn_pubrec",
        MSG_PUBREL                 => "mqtt_sn_pubrel",
        MSG_SUBSCRIBE              => "mqtt_sn_subscribe",
        MSG_SUBACK                 => "mqtt_sn_suback",
        MSG_UNSUBSCRIBE            => "mqtt_sn_unsubscribe",
        MSG_UNSUBACK               => "mqtt_sn_unsuback",
        MSG_PINGREQ                => "mqtt_sn_pingreq",
        MSG_PINGRESP               => "mqtt_sn_pingresp",
        MSG_DISCONNECT             => "mqtt_sn_disconnect",
        MSG_WILLTOPICUPD           => "mqtt_sn_willtopicupd",
        MSG_WILLTOPICRESP          => "mqtt_sn_willtopicresp",
        MSG_WILLMSGUPD             => "mqtt_sn_willmsgupd",
        MSG_WILLMSGRESP            => "mqtt_sn_willmsgresp",
        MSG_FORWARDER_ENCAPSULATION => "mqtt_sn_forwarder_encapsulation",
        _                          => "",
    }
}

#[inline]
fn operation_string(t: u8) -> String {
    let s = msg_type_name(t);
    if s.is_empty() { format!("mqtt_sn_unknown_0x{t:02x}") } else { s.to_string() }
}

#[inline]
fn status_for_rc(rc: u8) -> String {
    if rc == 0 { "observed".to_string() } else { format!("mqtt_sn_return_code_{rc}") }
}

// ── Decoder ───────────────────────────────────────────────────────

#[derive(Default)]
pub(crate) struct MqttSnDecoder;

impl SessionDecoder for MqttSnDecoder {
    fn name(&self) -> &'static str { "mqtt_sn" }

    fn interest(&self) -> &'static [DecoderInterest] {
        // No IANA-assigned port; 1884 is the de-facto Eclipse Paho gateway port.
        &[DecoderInterest::UdpPort(1884)]
    }

    fn on_datagram(&mut self, chunk: &StreamChunk<'_>, out: &mut Vec<BronzeEvent>) {
        let data = chunk.payload;

        let frame = match parse_header(data) {
            Some(f) => f,
            None => {
                out.push(parse_anomaly_event(
                    chunk.capture_id.to_string(),
                    build_envelope(&chunk.context, chunk.interface_id, chunk.frame_index,
                        chunk.timestamp, chunk.segment_hash, TransportProtocol::Udp,
                        Some("mqtt_sn"), chunk.captured_len, chunk.session_key.clone()),
                    self.name(), "low", "datagram too short for mqtt-sn header", data,
                ));
                return;
            }
        };

        let envelope = build_envelope(
            &chunk.context, chunk.interface_id, chunk.frame_index,
            chunk.timestamp, chunk.segment_hash, TransportProtocol::Udp,
            Some("mqtt_sn"), chunk.captured_len, chunk.session_key.clone(),
        );

        // Declared length must equal the datagram length (it's a UDP datagram, not stream).
        if frame.length != data.len() {
            out.push(parse_anomaly_event(
                chunk.capture_id.to_string(), envelope.clone(), self.name(), "low",
                &format!("mqtt-sn declared length {} does not match datagram length {}",
                    frame.length, data.len()),
                data,
            ));
            // Still attempt to emit a transaction with what we have.
        }

        // Unknown type → anomaly before the transaction.
        if msg_type_name(frame.msg_type).is_empty() {
            out.push(parse_anomaly_event(
                chunk.capture_id.to_string(), envelope.clone(), self.name(), "low",
                &format!("unknown mqtt-sn msg_type 0x{:02x}", frame.msg_type),
                data,
            ));
        }

        let (tx, asset) = decode_message(
            frame.msg_type, frame.length, frame.payload, chunk,
        );

        out.push(new_event(
            chunk.capture_id.to_string(),
            envelope.clone(),
            BronzeEventFamily::ProtocolTransaction(tx),
        ));
        if let Some(a) = asset {
            out.push(new_event(
                chunk.capture_id.to_string(),
                envelope,
                BronzeEventFamily::AssetObservation(a),
            ));
        }
    }
}

/// Decode one MQTT-SN message into a `ProtocolTransaction` and an optional
/// `AssetObservation`. Kept separate from the decoder to isolate wire logic.
fn decode_message(
    msg_type: u8,
    length:   usize,
    payload:  &[u8],
    chunk:    &StreamChunk<'_>,
) -> (ProtocolTransaction, Option<AssetObservation>) {
    let mut attrs: BTreeMap<String, String> = BTreeMap::new();
    attrs.insert("msg_type".to_string(), format!("0x{msg_type:02x}"));
    attrs.insert("length".to_string(), length.to_string());

    let mut status = "observed".to_string();
    let mut asset:  Option<AssetObservation> = None;

    /// Inline helper: u16 from two bytes at offset.
    macro_rules! u16be {
        ($off:expr) => { u16::from_be_bytes([payload[$off], payload[$off + 1]]) };
    }

    match msg_type {
        MSG_ADVERTISE if payload.len() >= 3 => {
            attrs.insert("gateway_id".to_string(), payload[0].to_string());
            attrs.insert("duration".to_string(), u16be!(1).to_string());
        }
        MSG_SEARCHGW if !payload.is_empty() => {
            attrs.insert("radius".to_string(), payload[0].to_string());
        }
        MSG_GWINFO if !payload.is_empty() => {
            let gw = payload[0].to_string();
            attrs.insert("gateway_id".to_string(), gw.clone());
            asset = Some(make_asset(
                &chunk.context.src_ip.to_string(),
                "mqtt_sn_gateway",
                [("gateway_id".into(), gw)].into(),
            ));
        }
        MSG_CONNECT if payload.len() >= 4 => {
            let protocol_id = payload[1];
            let duration    = u16be!(2);
            let client_id   = String::from_utf8_lossy(&payload[4..]).trim().to_string();
            attrs.insert("protocol_id".to_string(), protocol_id.to_string());
            attrs.insert("duration".to_string(), duration.to_string());
            attrs.insert("client_id".to_string(), client_id.clone());
            asset = Some(make_asset(
                &chunk.context.src_ip.to_string(),
                "mqtt_sn_client",
                [("client_id".into(), client_id)].into(),
            ));
        }
        MSG_CONNACK if !payload.is_empty() => {
            let rc = payload[0];
            attrs.insert("return_code".to_string(), rc.to_string());
            status = status_for_rc(rc);
        }
        MSG_WILLTOPIC | MSG_WILLTOPICUPD if payload.len() >= 2 => {
            attrs.insert("will_topic".to_string(),
                String::from_utf8_lossy(&payload[1..]).to_string());
        }
        MSG_WILLMSG | MSG_WILLMSGUPD => {
            attrs.insert("payload_length".to_string(), payload.len().to_string());
        }
        MSG_REGISTER if payload.len() >= 4 => {
            attrs.insert("topic_id".to_string(), u16be!(0).to_string());
            attrs.insert("msg_id".to_string(), u16be!(2).to_string());
            attrs.insert("topic_name".to_string(),
                String::from_utf8_lossy(&payload[4..]).trim().to_string());
        }
        MSG_REGACK if payload.len() >= 5 => {
            attrs.insert("topic_id".to_string(), u16be!(0).to_string());
            attrs.insert("msg_id".to_string(), u16be!(2).to_string());
            let rc = payload[4];
            attrs.insert("return_code".to_string(), rc.to_string());
            status = status_for_rc(rc);
        }
        MSG_PUBLISH if payload.len() >= 5 => {
            // flags(1) + topic_id(2) + msg_id(2) + data(rest)
            attrs.insert("topic_id".to_string(), u16be!(1).to_string());
            attrs.insert("msg_id".to_string(), u16be!(3).to_string());
            attrs.insert("payload_length".to_string(),
                payload.len().saturating_sub(5).to_string());
        }
        MSG_PUBACK if payload.len() >= 5 => {
            attrs.insert("topic_id".to_string(), u16be!(0).to_string());
            attrs.insert("msg_id".to_string(), u16be!(2).to_string());
            let rc = payload[4];
            attrs.insert("return_code".to_string(), rc.to_string());
            status = status_for_rc(rc);
        }
        MSG_PUBCOMP | MSG_PUBREC | MSG_PUBREL | MSG_UNSUBACK if payload.len() >= 2 => {
            attrs.insert("msg_id".to_string(), u16be!(0).to_string());
        }
        MSG_SUBSCRIBE | MSG_UNSUBSCRIBE if payload.len() >= 3 => {
            attrs.insert("msg_id".to_string(), u16be!(1).to_string());
        }
        MSG_SUBACK if payload.len() >= 6 => {
            attrs.insert("topic_id".to_string(), u16be!(1).to_string());
            attrs.insert("msg_id".to_string(), u16be!(3).to_string());
            let rc = payload[5];
            attrs.insert("return_code".to_string(), rc.to_string());
            status = status_for_rc(rc);
        }
        MSG_PINGREQ if !payload.is_empty() => {
            let cid = String::from_utf8_lossy(payload).trim().to_string();
            if !cid.is_empty() { attrs.insert("client_id".to_string(), cid); }
        }
        MSG_DISCONNECT if payload.len() >= 2 => {
            attrs.insert("duration".to_string(), u16be!(0).to_string());
        }
        MSG_WILLTOPICRESP | MSG_WILLMSGRESP if !payload.is_empty() => {
            let rc = payload[0];
            attrs.insert("return_code".to_string(), rc.to_string());
            status = status_for_rc(rc);
        }
        MSG_FORWARDER_ENCAPSULATION if !payload.is_empty() => {
            attrs.insert("ctrl".to_string(), payload[0].to_string());
            attrs.insert("encapsulated_len".to_string(), payload.len().to_string());
        }
        // MSG_WILLTOPICREQ | MSG_WILLMSGREQ | MSG_PINGRESP: empty payload — no-op.
        // Unknown types: no additional attributes; anomaly already emitted.
        _ => {}
    }

    let tx = ProtocolTransaction {
        operation: operation_string(msg_type),
        status,
        request_summary: None,
        response_summary: None,
        object_refs: vec![],
        values: vec![],
        attributes: attrs,
        modbus: None,
        protocol_fields: None,
    };
    (tx, asset)
}

fn make_asset(
    asset_key: &str,
    role: &str,
    identifiers: BTreeMap<String, String>,
) -> AssetObservation {
    AssetObservation {
        asset_key: asset_key.to_string(),
        role: Some(role.to_string()),
        vendor: None,
        model: None,
        firmware: None,
        hostnames: vec![],
        protocols: vec!["mqtt_sn".to_string()],
        identifiers,
    }
}

// ── Self-registration ─────────────────────────────────────────────

inventory::submit!(crate::engine::decoders::DecoderRegistration {
    name: "mqtt_sn",
    factory: || Box::new(MqttSnDecoder::default()),
});

// ── Tests ─────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    use chrono::{TimeZone, Utc};

    use crate::bronze::{BronzeEventFamily, TransportProtocol};
    use crate::engine::{DecoderInterest, StreamChunk};
    use crate::registry::PacketContext;

    fn ctx() -> PacketContext {
        PacketContext {
            src_mac: [0u8; 6],
            dst_mac: [0u8; 6],
            src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            dst_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            src_port: 56000,
            dst_port: 1884,
            vlan_id: None,
            timestamp: 1_700_000_000_000_000,
        }
    }

    fn chunk<'a>(payload: &'a [u8]) -> StreamChunk<'a> {
        StreamChunk {
            capture_id: "cap",
            segment_hash: "seg",
            interface_id: 0,
            frame_index: 1,
            timestamp: Utc.timestamp_opt(1_700_000_000, 0).unwrap(),
            context: ctx(),
            ethertype: 0x0800,
            ip_proto: Some(17),
            llc: None,
            transport: TransportProtocol::Udp,
            payload,
            session_key: "sk".to_string(),
            captured_len: payload.len() as u64,
        }
    }

    fn run(pkt: &[u8]) -> Vec<BronzeEvent> {
        let mut dec = MqttSnDecoder::default();
        let mut out = vec![];
        dec.on_datagram(&chunk(pkt), &mut out);
        out
    }

    fn tx(events: &[BronzeEvent]) -> &ProtocolTransaction {
        events.iter().find_map(|e| {
            if let BronzeEventFamily::ProtocolTransaction(ref t) = e.family { Some(t) } else { None }
        }).expect("no ProtocolTransaction")
    }

    fn asset(events: &[BronzeEvent]) -> &AssetObservation {
        events.iter().find_map(|e| {
            if let BronzeEventFamily::AssetObservation(ref a) = e.family { Some(a) } else { None }
        }).expect("no AssetObservation")
    }

    fn anomaly(events: &[BronzeEvent]) -> &crate::bronze::ParseAnomaly {
        events.iter().find_map(|e| {
            if let BronzeEventFamily::ParseAnomaly(ref a) = e.family { Some(a) } else { None }
        }).expect("no ParseAnomaly")
    }

    // Test 1: CONNECT short-header, client_id="sensor01" → transaction + asset.
    // Layout: len(1) type(1) flags(1) protocol_id(1) duration(2) client_id(8) = 14 bytes.
    #[test]
    fn test_connect_emits_asset() {
        let mut pkt = vec![14u8, 0x04, 0x04, 0x01, 0x00, 0x0F];
        pkt.extend_from_slice(b"sensor01");
        assert_eq!(pkt.len(), 14);

        let evs = run(&pkt);
        let t = tx(&evs);
        assert_eq!(t.operation, "mqtt_sn_connect");
        assert_eq!(t.attributes["client_id"], "sensor01");

        let a = asset(&evs);
        assert_eq!(a.role.as_deref(), Some("mqtt_sn_client"));
        assert_eq!(a.identifiers["client_id"], "sensor01");
    }

    // Test 2: PUBLISH, topic_id=42, msg_id=7, 4-byte data.
    // Layout: len(1) type(1) flags(1) topic_id(2) msg_id(2) data(4) = 11 bytes.
    #[test]
    fn test_publish_fields() {
        let pkt = [11u8, 0x0C, 0x00, 0x00, 42, 0x00, 7, 0xDE, 0xAD, 0xBE, 0xEF];
        let evs = run(&pkt);
        let t = tx(&evs);
        assert_eq!(t.operation, "mqtt_sn_publish");
        assert_eq!(t.attributes["topic_id"], "42");
        assert_eq!(t.attributes["msg_id"], "7");
        assert_eq!(t.attributes["payload_length"], "4");
        assert_eq!(t.status, "observed");
    }

    // Test 3: CONNACK return_code=2 → status=mqtt_sn_return_code_2.
    #[test]
    fn test_connack_nonzero_rc() {
        let pkt = [3u8, 0x05, 0x02];
        let evs = run(&pkt);
        let t = tx(&evs);
        assert_eq!(t.operation, "mqtt_sn_connack");
        assert_eq!(t.status, "mqtt_sn_return_code_2");
        assert_eq!(t.attributes["return_code"], "2");
    }

    // Test 4: GWINFO gateway_id=1 → AssetObservation role=mqtt_sn_gateway.
    #[test]
    fn test_gwinfo_asset() {
        let pkt = [3u8, 0x02, 0x01];
        let evs = run(&pkt);
        let t = tx(&evs);
        assert_eq!(t.operation, "mqtt_sn_gwinfo");
        let a = asset(&evs);
        assert_eq!(a.role.as_deref(), Some("mqtt_sn_gateway"));
        assert_eq!(a.identifiers["gateway_id"], "1");
    }

    // Test 5: Extended-header PUBLISH, 300-byte data payload.
    // Extended header: 0x01 | u16 BE total_len | 0x0C
    // Payload: flags(1) topic_id(2) msg_id(2) data(300) → 305 bytes → total = 309.
    #[test]
    fn test_extended_header_publish() {
        const DATA_LEN: usize = 300;
        let total: u16 = (4 + 1 + 2 + 2 + DATA_LEN) as u16; // 309
        let mut pkt: Vec<u8> = vec![0x01];
        pkt.extend_from_slice(&total.to_be_bytes());
        pkt.push(0x0C); // PUBLISH
        pkt.push(0x00); // flags
        pkt.extend_from_slice(&255u16.to_be_bytes()); // topic_id=255
        pkt.extend_from_slice(&1u16.to_be_bytes());   // msg_id=1
        pkt.extend(std::iter::repeat(0xAAu8).take(DATA_LEN));
        assert_eq!(pkt.len(), total as usize);

        let evs = run(&pkt);
        let t = tx(&evs);
        assert_eq!(t.operation, "mqtt_sn_publish");
        assert_eq!(t.attributes["length"], total.to_string());
        assert_eq!(t.attributes["payload_length"], DATA_LEN.to_string());
        assert_eq!(t.attributes["topic_id"], "255");
    }

    // Test 6: Unknown msg_type 0x99 → operation=mqtt_sn_unknown_0x99 + ParseAnomaly.
    #[test]
    fn test_unknown_msg_type() {
        let pkt = [3u8, 0x99, 0x00];
        let evs = run(&pkt);
        assert_eq!(tx(&evs).operation, "mqtt_sn_unknown_0x99");
        let a = anomaly(&evs);
        assert_eq!(a.severity, "low");
        assert!(a.reason.contains("0x99"));
    }

    // Test 7: UdpPort(1884) registered in interest().
    #[test]
    fn test_interest_port() {
        assert!(MqttSnDecoder::default()
            .interest()
            .contains(&DecoderInterest::UdpPort(1884)));
    }

    // Test 8: Declared length mismatch → ParseAnomaly severity=low.
    #[test]
    fn test_length_mismatch_anomaly() {
        // Declares length=10 but datagram is only 5 bytes.
        let pkt = [10u8, 0x04, 0x04, 0x01, 0x00];
        let evs = run(&pkt);
        let a = anomaly(&evs);
        assert_eq!(a.severity, "low");
        assert!(a.reason.contains("does not match"));
    }
}
