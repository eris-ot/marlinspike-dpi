use std::collections::BTreeMap;

use crate::bronze::{
    AssetObservation, BronzeEvent, BronzeEventFamily, ProtocolTransaction, TopologyObservation,
    TransportProtocol,
};
use crate::dissectors::iec61850::{
    Iec61850Dissector, Iec61850Fields, Iec61850Profile, IEC61850_GOOSE_ETHERTYPE,
    IEC61850_MMS_PORT, IEC61850_SV_ETHERTYPE,
};
use crate::engine::{
    artifact_event, build_envelope, new_event, parse_anomaly_event, DecoderInterest,
    SessionDecoder, StreamChunk,
};
use super::{context_asset_key, context_remote_asset_key, normalize_operation_name};

#[derive(Default)]
pub(crate) struct Iec61850DecoderWrapper {
    dissector: Iec61850Dissector,
}

impl SessionDecoder for Iec61850DecoderWrapper {
    fn name(&self) -> &'static str {
        "iec61850"
    }

    fn interest(&self) -> &'static [DecoderInterest] {
        static INTERESTS: [DecoderInterest; 3] = [
            DecoderInterest::TcpPort(IEC61850_MMS_PORT),
            DecoderInterest::EtherType(IEC61850_GOOSE_ETHERTYPE),
            DecoderInterest::EtherType(IEC61850_SV_ETHERTYPE),
        ];
        &INTERESTS
    }

    fn on_datagram(&mut self, chunk: &StreamChunk<'_>, out: &mut Vec<BronzeEvent>) {
        let ethertype = chunk.ethertype;
        if !self.dissector.can_parse(
            chunk.payload,
            chunk.context.src_port,
            chunk.context.dst_port,
            Some(ethertype),
        ) {
            return;
        }

        match self.dissector.parse(
            chunk.payload,
            chunk.context.src_port,
            chunk.context.dst_port,
            Some(ethertype),
        ) {
            Some(fields) => self.emit_fields(chunk, TransportProtocol::Ethernet, fields, out),
            None => out.push(parse_anomaly_event(
                chunk.capture_id.to_string(),
                build_envelope(
                    &chunk.context,
                    chunk.interface_id,
                    chunk.frame_index,
                    chunk.timestamp,
                    chunk.segment_hash,
                    TransportProtocol::Ethernet,
                    Some("iec61850"),
                    chunk.captured_len,
                    chunk.session_key.clone(),
                ),
                self.name(),
                "medium",
                "failed to parse iec61850 ethernet payload",
                chunk.payload,
            )),
        }
    }

    fn on_stream_chunk(&mut self, chunk: &StreamChunk<'_>, out: &mut Vec<BronzeEvent>) {
        if !self.dissector.can_parse(
            chunk.payload,
            chunk.context.src_port,
            chunk.context.dst_port,
            None,
        ) {
            return;
        }

        match self.dissector.parse(
            chunk.payload,
            chunk.context.src_port,
            chunk.context.dst_port,
            None,
        ) {
            Some(fields) => self.emit_fields(chunk, TransportProtocol::Tcp, fields, out),
            None => out.push(parse_anomaly_event(
                chunk.capture_id.to_string(),
                build_envelope(
                    &chunk.context,
                    chunk.interface_id,
                    chunk.frame_index,
                    chunk.timestamp,
                    chunk.segment_hash,
                    TransportProtocol::Tcp,
                    Some("iec61850"),
                    chunk.captured_len,
                    chunk.session_key.clone(),
                ),
                self.name(),
                "medium",
                "failed to parse iec61850 tcp payload",
                chunk.payload,
            )),
        }
    }
}

impl Iec61850DecoderWrapper {
    fn emit_fields(
        &self,
        chunk: &StreamChunk<'_>,
        transport: TransportProtocol,
        fields: Iec61850Fields,
        out: &mut Vec<BronzeEvent>,
    ) {
        let envelope = build_envelope(
            &chunk.context,
            chunk.interface_id,
            chunk.frame_index,
            chunk.timestamp,
            chunk.segment_hash,
            transport,
            Some("iec61850"),
            chunk.captured_len,
            chunk.session_key.clone(),
        );

        let mut attributes = BTreeMap::new();
        attributes.insert(
            "profile".to_string(),
            iec61850_profile_name(fields.profile).to_string(),
        );
        attributes.insert("transport".to_string(), fields.transport.clone());
        attributes.insert("message_type".to_string(), fields.message_type.clone());
        if let Some(tpkt_length) = fields.tpkt_length {
            attributes.insert("tpkt_length".to_string(), tpkt_length.to_string());
        }
        if let Some(cotp_pdu_type) = &fields.cotp_pdu_type {
            attributes.insert("cotp_pdu_type".to_string(), cotp_pdu_type.clone());
        }
        if let Some(app_id) = fields.app_id {
            attributes.insert("app_id".to_string(), format!("{app_id:#06x}"));
        }
        if let Some(called_tsap) = &fields.called_tsap {
            attributes.insert("called_tsap".to_string(), called_tsap.clone());
        }
        if let Some(calling_tsap) = &fields.calling_tsap {
            attributes.insert("calling_tsap".to_string(), calling_tsap.clone());
        }
        if let Some(service) = &fields.service {
            attributes.insert("service".to_string(), service.clone());
        }
        if let Some(ied_name) = &fields.ied_name {
            attributes.insert("ied_name".to_string(), ied_name.clone());
        }
        if let Some(logical_device) = &fields.logical_device {
            attributes.insert("logical_device".to_string(), logical_device.clone());
        }
        if let Some(logical_node) = &fields.logical_node {
            attributes.insert("logical_node".to_string(), logical_node.clone());
        }
        if let Some(dataset) = &fields.dataset {
            attributes.insert("dataset".to_string(), dataset.clone());
        }
        attributes.insert(
            "visible_string_count".to_string(),
            fields.visible_strings.len().to_string(),
        );

        out.push(new_event(
            chunk.capture_id.to_string(),
            envelope.clone(),
            BronzeEventFamily::ProtocolTransaction(ProtocolTransaction {
                operation: iec61850_operation_name(&fields),
                status: iec61850_status(&fields).to_string(),
                request_summary: Some(iec61850_summary(&fields)),
                response_summary: None,
                object_refs: fields.object_references.clone(),
                values: Vec::new(),
                attributes,
                        modbus: None,
                                        protocol_fields: None,
}),
        ));

        if fields.ied_name.is_some() || fields.logical_device.is_some() || fields.dataset.is_some()
        {
            let mut identifiers = BTreeMap::new();
            identifiers.insert("endpoint".to_string(), context_asset_key(&chunk.context));
            if let Some(ied_name) = &fields.ied_name {
                identifiers.insert("ied_name".to_string(), ied_name.clone());
            }
            if let Some(logical_device) = &fields.logical_device {
                identifiers.insert("logical_device".to_string(), logical_device.clone());
            }
            if let Some(logical_node) = &fields.logical_node {
                identifiers.insert("logical_node".to_string(), logical_node.clone());
            }
            if let Some(dataset) = &fields.dataset {
                identifiers.insert("dataset".to_string(), dataset.clone());
            }
            if let Some(app_id) = fields.app_id {
                identifiers.insert("app_id".to_string(), app_id.to_string());
            }
            out.push(new_event(
                chunk.capture_id.to_string(),
                envelope.clone(),
                BronzeEventFamily::AssetObservation(AssetObservation {
                    asset_key: context_asset_key(&chunk.context),
                    role: Some("ied".to_string()),
                    vendor: None,
                    model: None,
                    firmware: None,
                    hostnames: fields.ied_name.clone().into_iter().collect(),
                    protocols: vec!["iec61850".to_string()],
                    identifiers,
                }),
            ));
        }

        out.push(new_event(
            chunk.capture_id.to_string(),
            envelope.clone(),
            BronzeEventFamily::TopologyObservation(TopologyObservation {
                observation_type: "iec61850_transaction".to_string(),
                local_id: context_asset_key(&chunk.context),
                remote_id: Some(context_remote_asset_key(&chunk.context)),
                description: fields.service.clone().or(Some(fields.message_type.clone())),
                capabilities: Vec::new(),
                metadata: BTreeMap::from([(
                    "profile".to_string(),
                    iec61850_profile_name(fields.profile).to_string(),
                )]),
            }),
        ));

        if !fields.payload.is_empty() {
            out.push(artifact_event(
                chunk.capture_id.to_string(),
                envelope,
                "iec61850_payload",
                &format!("{}:{}", chunk.session_key, chunk.frame_index),
                Some("application/octet-stream"),
                Some("IEC 61850 payload"),
                &fields.payload,
            ));
        }
    }
}

fn iec61850_profile_name(profile: Iec61850Profile) -> &'static str {
    match profile {
        Iec61850Profile::MmsIsoOnTcp => "mms",
        Iec61850Profile::Goose => "goose",
        Iec61850Profile::SampledValues => "sampled_values",
    }
}

fn iec61850_operation_name(fields: &Iec61850Fields) -> String {
    normalize_operation_name(
        fields
            .service
            .as_deref()
            .unwrap_or(fields.message_type.as_str()),
        "iec61850",
    )
}

fn iec61850_status(fields: &Iec61850Fields) -> &'static str {
    match fields.profile {
        Iec61850Profile::Goose | Iec61850Profile::SampledValues => "publish",
        Iec61850Profile::MmsIsoOnTcp => match fields.service.as_deref() {
            Some(service) if service.contains("response") => "response",
            Some(service) if service.contains("request") => "request",
            _ => "observed",
        },
    }
}

fn iec61850_summary(fields: &Iec61850Fields) -> String {
    let mut summary = fields
        .service
        .clone()
        .unwrap_or_else(|| fields.message_type.clone());
    if let Some(ied_name) = &fields.ied_name {
        summary.push_str(&format!(" {ied_name}"));
    }
    if let Some(dataset) = &fields.dataset {
        summary.push_str(&format!(" dataset={dataset}"));
    }
    summary
}

inventory::submit!(crate::engine::decoders::DecoderRegistration {
    name: "iec61850",
    factory: || Box::new(Iec61850DecoderWrapper::default()),
});
