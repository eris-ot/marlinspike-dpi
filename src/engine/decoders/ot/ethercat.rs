use std::collections::BTreeMap;

use crate::bronze::{
    AssetObservation, BronzeEvent, BronzeEventFamily, ProtocolTransaction, TopologyObservation,
    TransportProtocol,
};
use crate::dissectors::ethercat::EthercatDissector;
use crate::engine::{
    artifact_event, build_envelope, new_event, parse_anomaly_event, DecoderInterest,
    SessionDecoder, StreamChunk,
};
use crate::registry::{format_mac, ProtocolData, ProtocolDissector};

use super::normalize_operation_name;

#[derive(Default)]
pub(crate) struct EthercatDecoderWrapper {
    dissector: EthercatDissector,
}

impl SessionDecoder for EthercatDecoderWrapper {
    fn name(&self) -> &'static str {
        "ethercat"
    }

    fn interest(&self) -> &'static [DecoderInterest] {
        &[DecoderInterest::EtherType(0x88A4)]
    }

    fn on_datagram(&mut self, chunk: &StreamChunk<'_>, out: &mut Vec<BronzeEvent>) {
        if !self.dissector.can_parse(
            chunk.payload,
            chunk.context.src_port,
            chunk.context.dst_port,
        ) {
            return;
        }

        match self.dissector.parse(chunk.payload, &chunk.context) {
            Some(ProtocolData::Ethercat(fields)) => {
                let envelope = build_envelope(
                    &chunk.context,
                    chunk.interface_id,
                    chunk.frame_index,
                    chunk.timestamp,
                    chunk.segment_hash,
                    TransportProtocol::Ethernet,
                    Some("ethercat"),
                    chunk.captured_len,
                    chunk.session_key.clone(),
                );

                let mut attributes = BTreeMap::new();
                attributes.insert(
                    "datagram_count".to_string(),
                    fields.datagrams.len().to_string(),
                );
                if let Some(first) = fields.datagrams.first() {
                    attributes.insert("first_command".to_string(), first.command.clone());
                    attributes.insert("first_adp".to_string(), first.adp.to_string());
                    attributes.insert("first_ado".to_string(), format!("{:#06x}", first.ado));
                }

                out.push(new_event(
                    chunk.capture_id.to_string(),
                    envelope.clone(),
                    BronzeEventFamily::ProtocolTransaction(ProtocolTransaction {
                        operation: ethercat_operation_name(&fields),
                        status: "observed".to_string(),
                        request_summary: Some(format!("{} datagrams", fields.datagrams.len())),
                        response_summary: None,
                        object_refs: ethercat_object_refs(&fields),
                        values: Vec::new(),
                        attributes,
                                        modbus: None,
                                        protocol_fields: None,
}),
                ));

                out.push(new_event(
                    chunk.capture_id.to_string(),
                    envelope.clone(),
                    BronzeEventFamily::AssetObservation(AssetObservation {
                        asset_key: format_mac(&chunk.context.src_mac),
                        role: Some("master".to_string()),
                        vendor: None,
                        model: None,
                        firmware: None,
                        hostnames: Vec::new(),
                        protocols: vec!["ethercat".to_string()],
                        identifiers: BTreeMap::from([(
                            "mac".to_string(),
                            format_mac(&chunk.context.src_mac),
                        )]),
                    }),
                ));

                for datagram in &fields.datagrams {
                    if let Some(asset_key) =
                        ethercat_slave_asset_key(datagram.adp, datagram.identity.alias_address)
                    {
                        let mut identifiers = BTreeMap::new();
                        identifiers.insert("ethercat_adp".to_string(), datagram.adp.to_string());
                        identifiers
                            .insert("ethercat_ado".to_string(), format!("{:#06x}", datagram.ado));
                        if let Some(alias_address) = datagram.identity.alias_address {
                            identifiers.insert(
                                "ethercat_alias_address".to_string(),
                                alias_address.to_string(),
                            );
                        }
                        if let Some(vendor_id) = datagram.identity.vendor_id {
                            identifiers
                                .insert("ethercat_vendor_id".to_string(), vendor_id.to_string());
                        }
                        if let Some(product_code) = datagram.identity.product_code {
                            identifiers.insert(
                                "ethercat_product_code".to_string(),
                                product_code.to_string(),
                            );
                        }
                        if let Some(revision) = datagram.identity.revision {
                            identifiers
                                .insert("ethercat_revision".to_string(), revision.to_string());
                        }
                        if let Some(serial_number) = datagram.identity.serial_number {
                            identifiers.insert(
                                "ethercat_serial_number".to_string(),
                                serial_number.to_string(),
                            );
                        }
                        out.push(new_event(
                            chunk.capture_id.to_string(),
                            envelope.clone(),
                            BronzeEventFamily::AssetObservation(AssetObservation {
                                asset_key: asset_key.clone(),
                                role: Some("slave".to_string()),
                                vendor: datagram
                                    .identity
                                    .vendor_id
                                    .map(|vendor_id| format!("vendor_{vendor_id}")),
                                model: datagram
                                    .identity
                                    .product_code
                                    .map(|product_code| format!("product_{product_code}")),
                                firmware: datagram
                                    .identity
                                    .revision
                                    .map(|revision| revision.to_string()),
                                hostnames: Vec::new(),
                                protocols: vec!["ethercat".to_string()],
                                identifiers,
                            }),
                        ));
                        out.push(new_event(
                            chunk.capture_id.to_string(),
                            envelope.clone(),
                            BronzeEventFamily::TopologyObservation(TopologyObservation {
                                observation_type: "ethercat_master_slave".to_string(),
                                local_id: format_mac(&chunk.context.src_mac),
                                remote_id: Some(asset_key),
                                description: Some(datagram.command.clone()),
                                capabilities: Vec::new(),
                                metadata: BTreeMap::from([(
                                    "address_mode".to_string(),
                                    datagram.address_mode.clone(),
                                )]),
                            }),
                        ));
                    }
                }

                let mut artifact_payload = Vec::new();
                for datagram in &fields.datagrams {
                    artifact_payload.extend_from_slice(&datagram.payload);
                }
                if !artifact_payload.is_empty() {
                    out.push(artifact_event(
                        chunk.capture_id.to_string(),
                        envelope,
                        "ethercat_payload",
                        &format!("{}:{}", chunk.session_key, chunk.frame_index),
                        Some("application/octet-stream"),
                        Some("EtherCAT datagram payload"),
                        &artifact_payload,
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
                    TransportProtocol::Ethernet,
                    Some("ethercat"),
                    chunk.captured_len,
                    chunk.session_key.clone(),
                ),
                self.name(),
                "medium",
                "failed to parse ethercat payload",
                chunk.payload,
            )),
        }
    }
}

fn ethercat_operation_name(fields: &crate::dissectors::ethercat::EthercatFields) -> String {
    match fields.datagrams.as_slice() {
        [] => "ethercat_frame".to_string(),
        [single] => normalize_operation_name(&single.command, "ethercat_frame"),
        _ => "ethercat_multi_datagram".to_string(),
    }
}

fn ethercat_object_refs(fields: &crate::dissectors::ethercat::EthercatFields) -> Vec<String> {
    let mut refs = Vec::new();
    for datagram in &fields.datagrams {
        refs.push(format!("command:{}", datagram.command));
        refs.push(format!("adp:{}", datagram.adp));
        refs.push(format!("ado:{:#06x}", datagram.ado));
    }
    refs
}

fn ethercat_slave_asset_key(adp: u16, alias_address: Option<u16>) -> Option<String> {
    if let Some(alias_address) = alias_address {
        Some(format!("ethercat_alias:{alias_address}"))
    } else if adp != 0 {
        Some(format!("ethercat_adp:{adp}"))
    } else {
        None
    }
}

inventory::submit!(crate::engine::decoders::DecoderRegistration {
    name: "ethercat",
    factory: || Box::new(EthercatDecoderWrapper::default()),
});
