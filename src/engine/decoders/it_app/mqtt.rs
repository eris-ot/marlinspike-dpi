use std::collections::BTreeMap;

use crate::bronze::{
    AssetObservation, BronzeEvent, BronzeEventFamily, MqttBronzeFields, ProtocolFields,
    ProtocolTransaction, TransportProtocol,
};
use crate::dissectors::mqtt::MqttDissector;
use crate::engine::{
    DecoderInterest, SessionDecoder, StreamChunk, build_envelope, new_event, parse_anomaly_event,
};
use crate::registry::{MqttFields, ProtocolData, ProtocolDissector};

// ── MQTT decoder ─────────────────────────────────────────────────

pub(crate) struct MqttDecoder {
    dissector: MqttDissector,
    payload_decoders: Vec<Box<dyn crate::mqtt_payload::MqttPayloadDecoder>>,
}

impl Default for MqttDecoder {
    fn default() -> Self {
        Self {
            dissector: MqttDissector,
            payload_decoders: vec![Box::new(crate::sparkplug::SparkplugBDecoder::new())],
        }
    }
}

impl SessionDecoder for MqttDecoder {
    fn name(&self) -> &'static str {
        "mqtt"
    }

    fn interest(&self) -> &'static [DecoderInterest] {
        &[
            DecoderInterest::TcpPort(1883),
            DecoderInterest::TcpPort(8883),
        ]
    }

    fn on_stream_chunk(&mut self, chunk: &StreamChunk<'_>, out: &mut Vec<BronzeEvent>) {
        match self.dissector.parse(chunk.payload, &chunk.context) {
            Some(ProtocolData::Mqtt(MqttFields {
                packet_type,
                packet_type_name,
                protocol_name,
                protocol_version,
                client_id,
                username,
                topic,
                qos,
                retain,
                payload: mqtt_payload,
                ..
            })) => {
                let envelope = build_envelope(
                    &chunk.context,
                    chunk.interface_id,
                    chunk.frame_index,
                    chunk.timestamp,
                    chunk.segment_hash,
                    TransportProtocol::Tcp,
                    Some("mqtt"),
                    chunk.captured_len,
                    chunk.session_key.clone(),
                );

                let mut attributes = BTreeMap::new();
                if let Some(ref proto) = protocol_name {
                    attributes.insert("protocol_name".to_string(), proto.clone());
                }
                if let Some(ver) = protocol_version {
                    attributes.insert("protocol_version".to_string(), ver.to_string());
                }
                if let Some(ref cid) = client_id {
                    attributes.insert("client_id".to_string(), cid.clone());
                }
                if let Some(ref user) = username {
                    attributes.insert("username".to_string(), user.clone());
                }
                if let Some(q) = qos {
                    attributes.insert("qos".to_string(), q.to_string());
                }

                let operation = packet_type_name.to_lowercase();
                let summary = match packet_type {
                    1 => {
                        let cid_str = client_id.as_deref().unwrap_or("?");
                        format!("CONNECT client_id={cid_str}")
                    }
                    3 => {
                        let t = topic.as_deref().unwrap_or("?");
                        format!("PUBLISH topic={t}")
                    }
                    8 => {
                        let t = topic.as_deref().unwrap_or("?");
                        format!("SUBSCRIBE topic={t}")
                    }
                    _ => packet_type_name.clone(),
                };

                let object_refs = topic.clone().into_iter().collect();

                let mqtt_pf = MqttBronzeFields {
                    packet_type,
                    packet_type_name: packet_type_name.clone(),
                    protocol_name: protocol_name.clone(),
                    protocol_version,
                    client_id: client_id.clone(),
                    username: username.clone(),
                    topic: topic.clone(),
                    qos,
                    retain,
                };
                out.push(new_event(
                    chunk.capture_id.to_string(),
                    envelope.clone(),
                    BronzeEventFamily::ProtocolTransaction(ProtocolTransaction {
                        operation,
                        status: "ok".to_string(),
                        request_summary: Some(summary),
                        response_summary: None,
                        object_refs,
                        values: vec![],
                        attributes,
                        modbus: None,
                        protocol_fields: Some(ProtocolFields::Mqtt(mqtt_pf)),
                    }),
                ));

                // CONNECT packets identify the client device.
                if packet_type == 1 {
                    let mut identifiers =
                        BTreeMap::from([("ip".to_string(), chunk.context.src_ip.to_string())]);
                    if let Some(ref cid) = client_id {
                        identifiers.insert("client_id".to_string(), cid.clone());
                    }
                    out.push(new_event(
                        chunk.capture_id.to_string(),
                        envelope,
                        BronzeEventFamily::AssetObservation(AssetObservation {
                            asset_key: chunk.context.src_ip.to_string(),
                            role: Some("mqtt_client".to_string()),
                            vendor: None,
                            model: None,
                            firmware: None,
                            hostnames: username.into_iter().collect(),
                            protocols: vec!["mqtt".to_string()],
                            identifiers,
                        }),
                    ));
                }

                // PUBLISH payloads fan out to registered MqttPayloadDecoders
                // (Sparkplug B, future UADP / vendor schemas).
                if packet_type == 3
                    && let (Some(topic_str), Some(payload_bytes)) =
                        (topic.as_deref(), mqtt_payload.as_deref())
                {
                    let ctx = build_mqtt_publish_context(
                        chunk,
                        topic_str,
                        payload_bytes,
                        client_id.as_deref(),
                        qos.unwrap_or(0),
                        retain.unwrap_or(false),
                    );
                    for decoder in self.payload_decoders.iter_mut() {
                        let mut events = decoder.try_decode(&ctx);
                        if !events.is_empty() {
                            out.append(&mut events);
                            break; // first decoder that claims the payload wins
                        }
                    }
                }
            }
            _ => out.push(parse_anomaly_event(
                chunk.capture_id.to_string(),
                build_envelope(
                    &chunk.context,
                    chunk.interface_id,
                    chunk.frame_index,
                    chunk.timestamp,
                    chunk.segment_hash,
                    TransportProtocol::Tcp,
                    Some("mqtt"),
                    chunk.captured_len,
                    chunk.session_key.clone(),
                ),
                self.name(),
                "medium",
                "failed to parse mqtt payload",
                chunk.payload,
            )),
        }
    }
}

/// Build an [`MqttPublishContext`] from a [`StreamChunk`] for fanout to
/// registered [`crate::mqtt_payload::MqttPayloadDecoder`] implementations.
///
/// `broker_endpoint` is whichever side of the flow uses port 1883/8883; if
/// neither matches (unusual) we default to the destination side.
fn build_mqtt_publish_context<'a>(
    chunk: &'a StreamChunk<'a>,
    topic: &'a str,
    payload: &'a [u8],
    client_id: Option<&'a str>,
    qos: u8,
    retain: bool,
) -> crate::mqtt_payload::MqttPublishContext<'a> {
    use crate::mqtt_payload::{FlowFiveTuple, MqttPublishContext};
    use std::net::SocketAddr;

    let src = SocketAddr::new(chunk.context.src_ip, chunk.context.src_port);
    let dst = SocketAddr::new(chunk.context.dst_ip, chunk.context.dst_port);
    let broker_endpoint = if matches!(chunk.context.dst_port, 1883 | 8883) {
        dst
    } else if matches!(chunk.context.src_port, 1883 | 8883) {
        src
    } else {
        dst
    };
    let publisher_mac = if broker_endpoint == dst {
        chunk.context.src_mac
    } else {
        chunk.context.dst_mac
    };
    MqttPublishContext {
        broker_endpoint,
        flow_5tuple: FlowFiveTuple {
            src,
            dst,
            transport: 6, // TCP
        },
        client_id,
        topic,
        payload,
        retain,
        qos,
        // chunk.context.timestamp is nanoseconds since epoch; the publish
        // context API uses microseconds.
        packet_ts_us: chunk.context.timestamp / 1_000,
        vlan_id: chunk.context.vlan_id,
        publisher_mac,
    }
}

inventory::submit!(crate::engine::decoders::DecoderRegistration {
    name: "mqtt",
    factory: || Box::new(MqttDecoder::default()),
});
