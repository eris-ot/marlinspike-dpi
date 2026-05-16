use std::collections::{BTreeMap, HashMap};

use chrono::{DateTime, Utc};

use crate::bronze::{
    AssetObservation, BronzeEvent, BronzeEventFamily, EventEnvelope, ModbusBronzeFields,
    ObjectValue, ProtocolTransaction, TransportProtocol,
};
use crate::dissectors::modbus::ModbusDissector;
use crate::engine::{
    DecoderInterest, SessionDecoder, StreamChunk, artifact_event, build_envelope, new_event,
    parse_anomaly_event,
};
use crate::registry::{ModbusFields, ModbusPdu, ProtocolData, ProtocolDissector};

#[derive(Clone)]
struct PendingModbus {
    capture_id: String,
    envelope: EventEnvelope,
    #[expect(dead_code, reason = "reserved for future richer response validation")]
    transaction_id: u16,
    #[expect(dead_code, reason = "reserved for future richer response validation")]
    unit_id: u8,
    operation: String,
    request_summary: String,
    object_refs: Vec<String>,
    values: Vec<ObjectValue>,
    attributes: BTreeMap<String, String>,
    raw_payload: Vec<u8>,
    last_seen: DateTime<Utc>,
    /// Structured request PDU; used to build `ModbusBronzeFields` on response.
    request_pdu: Option<ModbusPdu>,
}

#[derive(Default)]
pub(crate) struct ModbusDecoder {
    dissector: ModbusDissector,
    pending: HashMap<String, PendingModbus>,
}

impl SessionDecoder for ModbusDecoder {
    fn name(&self) -> &'static str {
        "modbus"
    }

    fn interest(&self) -> &'static [DecoderInterest] {
        &[DecoderInterest::TcpPort(502)]
    }

    fn on_stream_chunk(&mut self, chunk: &StreamChunk<'_>, out: &mut Vec<BronzeEvent>) {
        match self.dissector.parse(chunk.payload, &chunk.context) {
            Some(ProtocolData::Modbus(fields)) => {
                let operation = modbus_function_name(fields.function_code).to_string();
                let is_request = chunk.context.dst_port == 502 && chunk.context.src_port != 502;
                let envelope = build_envelope(
                    &chunk.context,
                    chunk.interface_id,
                    chunk.frame_index,
                    chunk.timestamp,
                    chunk.segment_hash,
                    TransportProtocol::Tcp,
                    Some("modbus"),
                    chunk.captured_len,
                    chunk.session_key.clone(),
                );
                let key = format!(
                    "{}:{}:{}",
                    chunk.session_key, fields.transaction_id, fields.unit_id
                );
                if is_request {
                    self.pending.insert(
                        key,
                        PendingModbus {
                            capture_id: chunk.capture_id.to_string(),
                            envelope,
                            transaction_id: fields.transaction_id,
                            unit_id: fields.unit_id,
                            operation: operation.clone(),
                            request_summary: modbus_summary(&fields),
                            object_refs: modbus_object_refs(&fields),
                            values: modbus_values(&fields),
                            attributes: modbus_attributes(&fields),
                            raw_payload: chunk.payload.to_vec(),
                            last_seen: chunk.timestamp,
                            request_pdu: fields.pdu.clone(),
                        },
                    );
                } else if let Some(pending) = self.pending.remove(&key) {
                    let mut values = pending.values.clone();
                    values.extend(modbus_values(&fields));
                    let mut attributes = pending.attributes.clone();
                    attributes.extend(modbus_attributes(&fields));
                    let mut merged_envelope = pending.envelope.clone();
                    merged_envelope.bytes_count += envelope.bytes_count;
                    merged_envelope.packet_count += 1;

                    out.push(new_event(
                        pending.capture_id.clone(),
                        merged_envelope.clone(),
                        BronzeEventFamily::ProtocolTransaction(ProtocolTransaction {
                            operation: pending.operation.clone(),
                            status: if fields.is_exception {
                                format!("exception:{}", fields.exception_code)
                            } else {
                                "ok".to_string()
                            },
                            request_summary: Some(pending.request_summary),
                            response_summary: Some(modbus_summary(&fields)),
                            object_refs: pending.object_refs.clone(),
                            values,
                            attributes,
                            modbus: modbus_bronze_fields(
                                pending.request_pdu.as_ref(),
                                fields.pdu.as_ref(),
                                fields.is_exception,
                                fields.exception_code,
                            ),
                            protocol_fields: None,
                        }),
                    ));
                    if !fields.device_identification.is_empty() {
                        out.push(modbus_identity_observation(
                            pending.capture_id.clone(),
                            merged_envelope.clone(),
                            chunk.context.src_ip.to_string(),
                            fields.unit_id,
                            &fields.device_identification,
                        ));
                    }
                    if is_modbus_write(fields.function_code) {
                        out.push(artifact_event(
                            pending.capture_id,
                            merged_envelope,
                            "modbus_write_payload",
                            &format!(
                                "{}:{}:{}",
                                chunk.session_key, fields.transaction_id, fields.unit_id
                            ),
                            Some("application/octet-stream"),
                            Some("Modbus write request payload"),
                            &pending.raw_payload,
                        ));
                    }
                } else {
                    out.push(new_event(
                        chunk.capture_id.to_string(),
                        envelope,
                        BronzeEventFamily::ProtocolTransaction(ProtocolTransaction {
                            operation,
                            status: "response_without_request".to_string(),
                            request_summary: None,
                            response_summary: Some(modbus_summary(&fields)),
                            object_refs: modbus_object_refs(&fields),
                            values: modbus_values(&fields),
                            attributes: modbus_attributes(&fields),
                            modbus: modbus_bronze_fields(
                                None,
                                fields.pdu.as_ref(),
                                fields.is_exception,
                                fields.exception_code,
                            ),
                            protocol_fields: None,
                        }),
                    ));
                    if !fields.device_identification.is_empty() {
                        out.push(modbus_identity_observation(
                            chunk.capture_id.to_string(),
                            build_envelope(
                                &chunk.context,
                                chunk.interface_id,
                                chunk.frame_index,
                                chunk.timestamp,
                                chunk.segment_hash,
                                TransportProtocol::Tcp,
                                Some("modbus"),
                                chunk.captured_len,
                                chunk.session_key.clone(),
                            ),
                            chunk.context.src_ip.to_string(),
                            fields.unit_id,
                            &fields.device_identification,
                        ));
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
                    Some("modbus"),
                    chunk.captured_len,
                    chunk.session_key.clone(),
                ),
                self.name(),
                "medium",
                "failed to parse modbus payload",
                chunk.payload,
            )),
        }
    }

    fn on_idle_flush(&mut self, timestamp: DateTime<Utc>, out: &mut Vec<BronzeEvent>) {
        let expired: Vec<String> = self
            .pending
            .iter()
            .filter_map(|(key, pending)| {
                if (timestamp - pending.last_seen).num_seconds() >= 0 {
                    Some(key.clone())
                } else {
                    None
                }
            })
            .collect();

        for key in expired {
            if let Some(pending) = self.pending.remove(&key) {
                out.push(new_event(
                    pending.capture_id,
                    pending.envelope,
                    BronzeEventFamily::ProtocolTransaction(ProtocolTransaction {
                        operation: pending.operation,
                        status: "partial_request".to_string(),
                        request_summary: Some(pending.request_summary),
                        response_summary: None,
                        object_refs: pending.object_refs,
                        values: pending.values,
                        attributes: pending.attributes,
                        modbus: modbus_bronze_fields(pending.request_pdu.as_ref(), None, false, 0),
                        protocol_fields: None,
                    }),
                ));
            }
        }
    }
}

fn modbus_bronze_fields(
    request_pdu: Option<&ModbusPdu>,
    response_pdu: Option<&ModbusPdu>,
    is_exception: bool,
    exception_code: u8,
) -> Option<ModbusBronzeFields> {
    // Determine which PDU carries the register address (always the request).
    let req = request_pdu;
    let resp = response_pdu;

    let fc = req
        .map(|p| p.function_code)
        .or_else(|| resp.map(|p| p.function_code))?;

    let start_addr = req.and_then(|p| p.start_addr);
    let qty = req.and_then(|p| p.qty);

    // Values come from the response for read FCs, from the request for write FCs.
    let values: Vec<u16> = if let Some(r) = resp {
        if !r.values.is_empty() {
            r.values.clone()
        } else if let Some(req_pdu) = req {
            req_pdu.values.clone()
        } else {
            Vec::new()
        }
    } else if let Some(req_pdu) = req {
        req_pdu.values.clone()
    } else {
        Vec::new()
    };

    let direction = if req.is_some() && resp.is_some() {
        "paired".to_string()
    } else if req.is_some() {
        "request".to_string()
    } else {
        "response".to_string()
    };

    Some(ModbusBronzeFields {
        fc,
        start_addr,
        qty,
        values,
        exception_code: if is_exception {
            Some(exception_code)
        } else {
            None
        },
        direction,
    })
}

fn modbus_function_name(code: u8) -> &'static str {
    match code {
        1 => "read_coils",
        3 => "read_holding_registers",
        5 => "write_single_coil",
        6 => "write_single_register",
        15 => "write_multiple_coils",
        16 => "write_multiple_registers",
        43 => "read_device_identification",
        _ => "modbus_function",
    }
}

fn is_modbus_write(code: u8) -> bool {
    matches!(code, 5 | 6 | 15 | 16)
}

fn modbus_object_refs(fields: &ModbusFields) -> Vec<String> {
    let mut refs: Vec<String> = fields
        .registers
        .iter()
        .map(|(address, _)| format!("register:{address}"))
        .collect();
    if !fields.device_identification.is_empty() {
        refs.push("modbus_device_identification".to_string());
    }
    refs
}

fn modbus_values(fields: &ModbusFields) -> Vec<ObjectValue> {
    fields
        .registers
        .iter()
        .map(|(address, value)| ObjectValue {
            object_ref: format!("register:{address}"),
            value: Some(value.to_string()),
        })
        .collect()
}

fn modbus_attributes(fields: &ModbusFields) -> BTreeMap<String, String> {
    let mut attributes = BTreeMap::new();
    attributes.insert("unit_id".to_string(), fields.unit_id.to_string());
    attributes.insert(
        "transaction_id".to_string(),
        fields.transaction_id.to_string(),
    );
    attributes.insert(
        "function_code".to_string(),
        fields.function_code.to_string(),
    );
    for (key, value) in &fields.device_identification {
        attributes.insert(format!("device_id_{key}"), value.clone());
    }
    attributes
}

fn modbus_summary(fields: &ModbusFields) -> String {
    if fields.is_exception {
        return format!(
            "{} exception {}",
            modbus_function_name(fields.function_code),
            fields.exception_code
        );
    }
    if fields.function_code == 43 && !fields.device_identification.is_empty() {
        return fields
            .device_identification
            .get("model_name")
            .or_else(|| fields.device_identification.get("product_name"))
            .or_else(|| fields.device_identification.get("product_code"))
            .cloned()
            .unwrap_or_else(|| "device_identification".to_string());
    }
    if fields.registers.is_empty() {
        modbus_function_name(fields.function_code).to_string()
    } else {
        format!(
            "{} {}",
            modbus_function_name(fields.function_code),
            fields
                .registers
                .iter()
                .map(|(address, value)| format!("{address}={value}"))
                .collect::<Vec<_>>()
                .join(", ")
        )
    }
}

fn modbus_identity_observation(
    capture_id: String,
    envelope: EventEnvelope,
    asset_ip: String,
    unit_id: u8,
    device_identification: &BTreeMap<String, String>,
) -> BronzeEvent {
    let mut identifiers = BTreeMap::from([
        ("ip".to_string(), asset_ip.clone()),
        ("unit_id".to_string(), unit_id.to_string()),
    ]);
    for (key, value) in device_identification {
        identifiers.insert(format!("modbus_{key}"), value.clone());
    }
    new_event(
        capture_id,
        envelope,
        BronzeEventFamily::AssetObservation(AssetObservation {
            asset_key: asset_ip,
            role: Some("server".to_string()),
            vendor: device_identification.get("vendor_name").cloned(),
            model: device_identification
                .get("model_name")
                .cloned()
                .or_else(|| device_identification.get("product_name").cloned())
                .or_else(|| device_identification.get("product_code").cloned()),
            firmware: device_identification.get("revision").cloned(),
            hostnames: Vec::new(),
            protocols: vec!["modbus".to_string()],
            identifiers,
        }),
    )
}

inventory::submit!(crate::engine::decoders::DecoderRegistration {
    name: "modbus",
    factory: || Box::new(ModbusDecoder::default()),
});
