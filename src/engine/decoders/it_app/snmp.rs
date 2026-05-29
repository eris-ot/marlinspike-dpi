use std::collections::BTreeMap;

use crate::bronze::{
    AssetObservation, BronzeEvent, BronzeEventFamily, ObjectValue, ProtocolFields,
    ProtocolTransaction, SnmpBronzeFields, TransportProtocol,
};
use crate::dissectors::snmp::SnmpDissector;
use crate::engine::decoders::ot::normalize_operation_name;
use crate::engine::{
    DecoderInterest, SessionDecoder, StreamChunk, build_envelope, new_event, parse_anomaly_event,
};
use crate::registry::{ProtocolData, ProtocolDissector, SnmpFields};

#[derive(Default)]
pub(crate) struct SnmpDecoder {
    dissector: SnmpDissector,
}

impl SessionDecoder for SnmpDecoder {
    fn name(&self) -> &'static str {
        "snmp"
    }

    fn interest(&self) -> &'static [DecoderInterest] {
        &[DecoderInterest::UdpPort(161), DecoderInterest::UdpPort(162)]
    }

    fn on_datagram(&mut self, chunk: &StreamChunk<'_>, out: &mut Vec<BronzeEvent>) {
        match self.dissector.parse(chunk.payload, &chunk.context) {
            Some(ProtocolData::Snmp(SnmpFields {
                version,
                pdu_type,
                request_id,
                var_binds,
                sys_name,
                sys_descr,
                sys_object_id,
                engine_id,
                ..
            })) => {
                let envelope = build_envelope(
                    &chunk.context,
                    chunk.interface_id,
                    chunk.frame_index,
                    chunk.timestamp,
                    chunk.segment_hash,
                    TransportProtocol::Udp,
                    Some("snmp"),
                    chunk.captured_len,
                    chunk.session_key.clone(),
                );
                let mut attributes = BTreeMap::from([("version".to_string(), version.clone())]);
                if let Some(id) = request_id {
                    attributes.insert("request_id".to_string(), id.to_string());
                }
                if let Some(engine_id) = engine_id.clone() {
                    attributes.insert("engine_id".to_string(), engine_id);
                }
                let snmp_direction = snmp_status(&pdu_type);
                let snmp_pf = SnmpBronzeFields {
                    version: version.clone(),
                    pdu_type: pdu_type.clone(),
                    request_id,
                    engine_id: engine_id.clone(),
                    oids: var_binds.iter().map(|vb| vb.oid.clone()).collect(),
                    direction: snmp_direction.clone(),
                };
                out.push(new_event(
                    chunk.capture_id.to_string(),
                    envelope.clone(),
                    BronzeEventFamily::ProtocolTransaction(ProtocolTransaction {
                        operation: normalize_operation_name(&pdu_type, "snmp_message"),
                        status: snmp_direction,
                        request_summary: (!var_binds.is_empty()).then(|| {
                            var_binds
                                .iter()
                                .map(|vb| vb.oid.clone())
                                .collect::<Vec<_>>()
                                .join(", ")
                        }),
                        response_summary: sys_name.clone().or(sys_descr.clone()),
                        object_refs: var_binds.iter().map(|vb| vb.oid.clone()).collect(),
                        values: var_binds
                            .iter()
                            .map(|vb| ObjectValue {
                                object_ref: vb.oid.clone(),
                                value: vb.value.clone(),
                            })
                            .collect(),
                        attributes,
                        modbus: None,
                        protocol_fields: Some(ProtocolFields::Snmp(snmp_pf)),
                    }),
                ));

                if sys_name.is_some()
                    || sys_descr.is_some()
                    || sys_object_id.is_some()
                    || engine_id.is_some()
                {
                    let asset_ip = if chunk.context.src_port == 161 || chunk.context.src_port == 162
                    {
                        chunk.context.src_ip.to_string()
                    } else {
                        chunk.context.dst_ip.to_string()
                    };
                    let mut identifiers = BTreeMap::from([("ip".to_string(), asset_ip.clone())]);
                    if let Some(object_id) = sys_object_id.clone() {
                        identifiers.insert("sys_object_id".to_string(), object_id);
                    }
                    if let Some(engine_id) = engine_id {
                        identifiers.insert("engine_id".to_string(), engine_id);
                    }
                    if let Some(sys_descr) = sys_descr.clone() {
                        identifiers.insert("sys_descr".to_string(), sys_descr);
                    }
                    out.push(new_event(
                        chunk.capture_id.to_string(),
                        envelope,
                        BronzeEventFamily::AssetObservation(AssetObservation {
                            asset_key: asset_ip,
                            role: None,
                            vendor: None,
                            model: None,
                            firmware: None,
                            hostnames: sys_name.into_iter().collect(),
                            protocols: vec!["snmp".to_string()],
                            identifiers,
                        }),
                    ));
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
                    TransportProtocol::Udp,
                    Some("snmp"),
                    chunk.captured_len,
                    chunk.session_key.clone(),
                ),
                self.name(),
                "medium",
                "failed to parse snmp payload",
                chunk.payload,
            )),
        }
    }
}

fn snmp_status(pdu_type: &str) -> String {
    if pdu_type.contains("response") {
        "response".to_string()
    } else if pdu_type.contains("trap") || pdu_type.contains("inform") || pdu_type == "report" {
        "observed".to_string()
    } else {
        "request".to_string()
    }
}

inventory::submit!(crate::engine::decoders::DecoderRegistration {
    name: "snmp",
    factory: || Box::new(SnmpDecoder::default()),
});
