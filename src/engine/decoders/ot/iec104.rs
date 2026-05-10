use std::collections::BTreeMap;

use crate::bronze::{
    AssetObservation, BronzeEvent, BronzeEventFamily, EventEnvelope, ProtocolTransaction,
    TopologyObservation, TransportProtocol,
};
use crate::dissectors::iec104::parse_iec104_frames;
use crate::engine::{
    artifact_event, build_envelope, new_event, parse_anomaly_event, DecoderInterest, SessionDecoder,
    StreamChunk,
};
use crate::registry::{Iec104Fields, PacketContext};

#[derive(Default)]
pub(crate) struct Iec104DecoderWrapper;

impl SessionDecoder for Iec104DecoderWrapper {
    fn name(&self) -> &'static str {
        "iec104"
    }

    fn interest(&self) -> &'static [DecoderInterest] {
        &[DecoderInterest::TcpPort(2404)]
    }

    fn on_stream_chunk(&mut self, chunk: &StreamChunk<'_>, out: &mut Vec<BronzeEvent>) {
        let frames = parse_iec104_frames(chunk.payload);
        if frames.is_empty() {
            out.push(parse_anomaly_event(
                chunk.capture_id.to_string(),
                build_envelope(
                    &chunk.context,
                    chunk.interface_id,
                    chunk.frame_index,
                    chunk.timestamp,
                    chunk.segment_hash,
                    TransportProtocol::Tcp,
                    Some("iec104"),
                    chunk.captured_len,
                    chunk.session_key.clone(),
                ),
                self.name(),
                "medium",
                "failed to parse iec104 payload",
                chunk.payload,
            ));
            return;
        }

        for fields in frames {
            let Iec104Fields {
                frame_type,
                send_sequence,
                receive_sequence,
                u_format,
                type_id,
                cause_of_transmission,
                common_address,
                information_object_address,
                payload,
            } = fields;

            let envelope = build_envelope(
                &chunk.context,
                chunk.interface_id,
                chunk.frame_index,
                chunk.timestamp,
                chunk.segment_hash,
                TransportProtocol::Tcp,
                Some("iec104"),
                chunk.captured_len,
                chunk.session_key.clone(),
            );
            let mut attributes = BTreeMap::new();
            attributes.insert("frame_type".to_string(), frame_type.clone());
            if let Some(send_sequence) = send_sequence {
                attributes.insert("send_sequence".to_string(), send_sequence.to_string());
            }
            if let Some(receive_sequence) = receive_sequence {
                attributes.insert("receive_sequence".to_string(), receive_sequence.to_string());
            }
            if let Some(type_id) = type_id {
                attributes.insert("type_id".to_string(), type_id.to_string());
                attributes.insert(
                    "type_name".to_string(),
                    iec104_type_name(type_id).to_string(),
                );
            }
            if let Some(cause) = cause_of_transmission {
                attributes.insert("cause".to_string(), cause.to_string());
                attributes.insert(
                    "cause_name".to_string(),
                    iec104_cause_name(cause).to_string(),
                );
            }
            if let Some(common_address) = common_address {
                attributes.insert("common_address".to_string(), common_address.to_string());
            }
            if let Some(ioa) = information_object_address {
                attributes.insert("information_object_address".to_string(), ioa.to_string());
            }
            if let Some(u_format) = &u_format {
                attributes.insert("u_format".to_string(), u_format.clone());
            }

            let operation = iec104_operation_name(&frame_type, type_id, u_format.as_deref());

            out.push(new_event(
                chunk.capture_id.to_string(),
                envelope.clone(),
                BronzeEventFamily::ProtocolTransaction(ProtocolTransaction {
                    operation,
                    status: iec104_status(
                        &frame_type,
                        u_format.as_deref(),
                        cause_of_transmission,
                        &chunk.context,
                    )
                    .to_string(),
                    request_summary: Some(iec104_summary(
                        &frame_type,
                        type_id,
                        cause_of_transmission,
                        common_address,
                    )),
                    response_summary: None,
                    object_refs: iec104_object_refs(
                        type_id,
                        common_address,
                        information_object_address,
                    ),
                    values: Vec::new(),
                    attributes,
                                modbus: None,
                                        protocol_fields: None,
}),
            ));

            for event in iec104_role_observations(
                chunk.capture_id,
                &envelope,
                &chunk.context,
                &frame_type,
                common_address,
            ) {
                out.push(event);
            }

            if !payload.is_empty() {
                out.push(artifact_event(
                    chunk.capture_id.to_string(),
                    envelope,
                    "iec104_asdu",
                    &format!("{}:{}", chunk.session_key, chunk.frame_index),
                    Some("application/octet-stream"),
                    Some("IEC 60870-5-104 ASDU payload"),
                    &payload,
                ));
            }
        }
    }
}


fn iec104_type_name(type_id: u8) -> &'static str {
    match type_id {
        1 => "single_point_information",
        3 => "double_point_information",
        9 => "measured_value_normalized",
        11 => "measured_value_scaled",
        13 => "measured_value_short_float",
        30 => "single_point_with_time",
        45 => "single_command",
        46 => "double_command",
        50 => "set_point_normalized",
        100 => "interrogation_command",
        103 => "clock_sync_command",
        _ => "asdu_type",
    }
}

fn iec104_cause_name(cause: u16) -> &'static str {
    match cause {
        1 => "periodic",
        3 => "spontaneous",
        5 => "request",
        6 => "activation",
        7 => "activation_confirmation",
        10 => "activation_termination",
        20 => "interrogated_by_station",
        _ => "cause",
    }
}

fn iec104_operation_name(frame_type: &str, type_id: Option<u8>, u_format: Option<&str>) -> String {
    match frame_type {
        "u" => u_format.unwrap_or("u_format").to_string(),
        "s" => "supervisory".to_string(),
        _ => type_id
            .map(iec104_type_name)
            .unwrap_or("iec104_asdu")
            .to_string(),
    }
}

fn iec104_status(
    frame_type: &str,
    u_format: Option<&str>,
    cause: Option<u16>,
    context: &PacketContext,
) -> &'static str {
    match frame_type {
        "u" => match u_format {
            Some(value) if value.ends_with("_act") => "request",
            Some(value) if value.ends_with("_con") => "response",
            _ => "observed",
        },
        "s" => "response",
        _ => match cause {
            Some(6) if context.dst_port == 2404 => "request",
            Some(7 | 10) if context.src_port == 2404 => "response",
            _ if context.dst_port == 2404 => "request",
            _ if context.src_port == 2404 => "response",
            _ => "observed",
        },
    }
}

fn iec104_summary(
    frame_type: &str,
    type_id: Option<u8>,
    cause: Option<u16>,
    common_address: Option<u16>,
) -> String {
    match frame_type {
        "u" => "u_format_control".to_string(),
        "s" => "supervisory_ack".to_string(),
        _ => format!(
            "{} cause={} ca={}",
            type_id.map(iec104_type_name).unwrap_or("iec104_asdu"),
            cause
                .map(|value| value.to_string())
                .unwrap_or_else(|| "?".to_string()),
            common_address
                .map(|value| value.to_string())
                .unwrap_or_else(|| "?".to_string())
        ),
    }
}

fn iec104_object_refs(
    type_id: Option<u8>,
    common_address: Option<u16>,
    information_object_address: Option<u32>,
) -> Vec<String> {
    let mut refs = Vec::new();
    if let Some(type_id) = type_id {
        refs.push(format!("iec104_type:{type_id}"));
    }
    if let Some(common_address) = common_address {
        refs.push(format!("iec104_common_address:{common_address}"));
    }
    if let Some(ioa) = information_object_address {
        refs.push(format!("iec104_ioa:{ioa}"));
    }
    refs
}

fn iec104_role_observations(
    capture_id: &str,
    envelope: &EventEnvelope,
    context: &PacketContext,
    frame_type: &str,
    common_address: Option<u16>,
) -> Vec<BronzeEvent> {
    let (src_role, dst_role) = match frame_type {
        "u" | "s" => {
            if context.src_port == 2404 {
                ("outstation", "master")
            } else {
                ("master", "outstation")
            }
        }
        _ if context.dst_port == 2404 => ("master", "outstation"),
        _ if context.src_port == 2404 => ("outstation", "master"),
        _ => ("peer", "peer"),
    };

    let mut src_identifiers = BTreeMap::from([("ip".to_string(), context.src_ip.to_string())]);
    if src_role == "outstation" {
        if let Some(common_address) = common_address {
            src_identifiers.insert(
                "iec104_common_address".to_string(),
                common_address.to_string(),
            );
        }
    }

    let mut dst_identifiers = BTreeMap::from([("ip".to_string(), context.dst_ip.to_string())]);
    if dst_role == "outstation" {
        if let Some(common_address) = common_address {
            dst_identifiers.insert(
                "iec104_common_address".to_string(),
                common_address.to_string(),
            );
        }
    }

    vec![
        new_event(
            capture_id.to_string(),
            envelope.clone(),
            BronzeEventFamily::AssetObservation(AssetObservation {
                asset_key: context.src_ip.to_string(),
                role: Some(src_role.to_string()),
                vendor: None,
                model: None,
                firmware: None,
                hostnames: Vec::new(),
                protocols: vec!["iec104".to_string()],
                identifiers: src_identifiers,
            }),
        ),
        new_event(
            capture_id.to_string(),
            envelope.clone(),
            BronzeEventFamily::AssetObservation(AssetObservation {
                asset_key: context.dst_ip.to_string(),
                role: Some(dst_role.to_string()),
                vendor: None,
                model: None,
                firmware: None,
                hostnames: Vec::new(),
                protocols: vec!["iec104".to_string()],
                identifiers: dst_identifiers,
            }),
        ),
        new_event(
            capture_id.to_string(),
            envelope.clone(),
            BronzeEventFamily::TopologyObservation(TopologyObservation {
                observation_type: "iec104_link".to_string(),
                local_id: context.src_ip.to_string(),
                remote_id: Some(context.dst_ip.to_string()),
                description: Some(frame_type.to_string()),
                capabilities: Vec::new(),
                metadata: common_address
                    .map(|value| {
                        BTreeMap::from([("common_address".to_string(), value.to_string())])
                    })
                    .unwrap_or_default(),
            }),
        ),
    ]
}

inventory::submit!(crate::engine::decoders::DecoderRegistration {
    name: "iec104",
    factory: || Box::new(Iec104DecoderWrapper::default()),
});
