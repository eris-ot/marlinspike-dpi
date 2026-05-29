use std::collections::BTreeMap;

use crate::bronze::{
    AssetObservation, BronzeEvent, BronzeEventFamily, ProtocolFields, ProtocolTransaction,
    RadiusBronzeFields, TransportProtocol,
};
use crate::dissectors::radius::RadiusDissector;
use crate::engine::{
    DecoderInterest, SessionDecoder, StreamChunk, build_envelope, new_event, parse_anomaly_event,
};
use crate::registry::{ProtocolData, ProtocolDissector, RadiusFields};

// ── RADIUS decoder ───────────────────────────────────────────────

#[derive(Default)]
pub(crate) struct RadiusDecoder {
    dissector: RadiusDissector,
}

impl SessionDecoder for RadiusDecoder {
    fn name(&self) -> &'static str {
        "radius"
    }

    fn interest(&self) -> &'static [DecoderInterest] {
        &[
            DecoderInterest::UdpPort(1812),
            DecoderInterest::UdpPort(1813),
        ]
    }

    fn on_datagram(&mut self, chunk: &StreamChunk<'_>, out: &mut Vec<BronzeEvent>) {
        match self.dissector.parse(chunk.payload, &chunk.context) {
            Some(ProtocolData::Radius(RadiusFields {
                code,
                code_name,
                identifier,
                username,
                nas_ip_address,
                nas_identifier,
                calling_station_id,
                called_station_id,
                nas_port_type,
                framed_ip_address,
                service_type,
            })) => {
                let envelope = build_envelope(
                    &chunk.context,
                    chunk.interface_id,
                    chunk.frame_index,
                    chunk.timestamp,
                    chunk.segment_hash,
                    TransportProtocol::Udp,
                    Some("radius"),
                    chunk.captured_len,
                    chunk.session_key.clone(),
                );

                let mut attributes = BTreeMap::new();
                attributes.insert("identifier".to_string(), identifier.to_string());
                if let Some(ref user) = username {
                    attributes.insert("username".to_string(), user.clone());
                }
                if let Some(ref nas_ip) = nas_ip_address {
                    attributes.insert("nas_ip_address".to_string(), nas_ip.clone());
                }
                if let Some(ref nas_id) = nas_identifier {
                    attributes.insert("nas_identifier".to_string(), nas_id.clone());
                }
                if let Some(ref csi) = calling_station_id {
                    attributes.insert("calling_station_id".to_string(), csi.clone());
                }
                if let Some(ref csi) = called_station_id {
                    attributes.insert("called_station_id".to_string(), csi.clone());
                }
                if let Some(npt) = nas_port_type {
                    attributes.insert("nas_port_type".to_string(), npt.to_string());
                }
                if let Some(ref fip) = framed_ip_address {
                    attributes.insert("framed_ip_address".to_string(), fip.clone());
                }
                if let Some(st) = service_type {
                    attributes.insert("service_type".to_string(), st.to_string());
                }

                let status = match code {
                    2 | 5 | 41 | 44 => "accept",
                    3 | 42 | 45 => "reject",
                    _ => "request",
                };

                let radius_pf = RadiusBronzeFields {
                    code,
                    code_name: code_name.clone(),
                    identifier,
                    username: username.clone(),
                    nas_ip_address: nas_ip_address.clone(),
                    nas_identifier: nas_identifier.clone(),
                    calling_station_id: calling_station_id.clone(),
                    called_station_id: called_station_id.clone(),
                    nas_port_type,
                    framed_ip_address: framed_ip_address.clone(),
                    service_type,
                    direction: status.to_string(),
                };
                out.push(new_event(
                    chunk.capture_id.to_string(),
                    envelope.clone(),
                    BronzeEventFamily::ProtocolTransaction(ProtocolTransaction {
                        operation: code_name.to_lowercase().replace('-', "_"),
                        status: status.to_string(),
                        request_summary: Some(format!(
                            "{code_name} id={identifier}{}",
                            username
                                .as_ref()
                                .map(|u| format!(" user={u}"))
                                .unwrap_or_default()
                        )),
                        response_summary: None,
                        object_refs: username.clone().into_iter().collect(),
                        values: vec![],
                        attributes,
                        modbus: None,
                        protocol_fields: Some(ProtocolFields::Radius(radius_pf)),
                    }),
                ));

                // NAS identification from Access-Request.
                if code == 1
                    && let Some(nas_ip) = nas_ip_address
                {
                    let hostnames = nas_identifier.clone().into_iter().collect();
                    let mut identifiers = BTreeMap::from([("ip".to_string(), nas_ip.clone())]);
                    if let Some(nas_id) = nas_identifier {
                        identifiers.insert("nas_identifier".to_string(), nas_id.clone());
                    }
                    out.push(new_event(
                        chunk.capture_id.to_string(),
                        envelope,
                        BronzeEventFamily::AssetObservation(AssetObservation {
                            asset_key: nas_ip,
                            role: Some("network_device".to_string()),
                            vendor: None,
                            model: None,
                            firmware: None,
                            hostnames,
                            protocols: vec!["radius".to_string()],
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
                    Some("radius"),
                    chunk.captured_len,
                    chunk.session_key.clone(),
                ),
                self.name(),
                "medium",
                "failed to parse radius payload",
                chunk.payload,
            )),
        }
    }
}

// ── Inventory registration ──────────────────────────────────────
inventory::submit!(crate::engine::decoders::DecoderRegistration {
    name: "radius",
    factory: || Box::new(RadiusDecoder::default()),
});
