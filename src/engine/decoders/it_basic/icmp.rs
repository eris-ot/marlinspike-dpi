use std::collections::BTreeMap;

use crate::bronze::{
    BronzeEvent, BronzeEventFamily, IcmpBronzeFields, ProtocolFields, ProtocolTransaction,
    TransportProtocol,
};
use crate::dissectors::icmp::IcmpDissector;
use crate::engine::{DecoderInterest, SessionDecoder, StreamChunk, build_envelope, new_event};
use crate::registry::{ProtocolData, ProtocolDissector};

// ── ICMP Decoder ──────────────────────────────────────────────

#[derive(Default)]
pub(crate) struct IcmpDecoder {
    dissector: IcmpDissector,
}

impl SessionDecoder for IcmpDecoder {
    fn name(&self) -> &'static str {
        "icmp"
    }

    fn interest(&self) -> &'static [DecoderInterest] {
        &[DecoderInterest::IpProto(1)]
    }

    fn on_datagram(&mut self, chunk: &StreamChunk<'_>, out: &mut Vec<BronzeEvent>) {
        let context = &chunk.context;
        if !self.dissector.can_parse(chunk.payload, 0, 0) {
            return;
        }
        let Some(proto_data) = self.dissector.parse(chunk.payload, context) else {
            return;
        };
        let ProtocolData::Icmp(fields) = &proto_data else {
            return;
        };

        let envelope = build_envelope(
            context,
            chunk.interface_id,
            chunk.frame_index,
            chunk.timestamp,
            chunk.segment_hash,
            TransportProtocol::Icmp,
            Some("icmp"),
            chunk.captured_len,
            chunk.session_key.clone(),
        );

        let mut attrs = BTreeMap::new();
        attrs.insert("icmp_type".to_string(), fields.icmp_type.to_string());
        attrs.insert("icmp_code".to_string(), fields.icmp_code.to_string());
        attrs.insert("type_name".to_string(), fields.type_name.clone());
        if !fields.code_name.is_empty() {
            attrs.insert("code_name".to_string(), fields.code_name.clone());
        }
        if let Some(id) = fields.identifier {
            attrs.insert("identifier".to_string(), id.to_string());
        }
        if let Some(seq) = fields.sequence {
            attrs.insert("sequence".to_string(), seq.to_string());
        }
        if let Some(gw) = &fields.gateway_ip {
            attrs.insert("gateway_ip".to_string(), gw.clone());
        }
        attrs.insert("payload_len".to_string(), fields.payload_len.to_string());

        let operation = fields.type_name.clone();
        let status = if fields.icmp_type == 3 {
            fields.code_name.clone()
        } else {
            "ok".to_string()
        };

        let icmp_pf = IcmpBronzeFields {
            icmp_type: fields.icmp_type,
            icmp_code: fields.icmp_code,
            type_name: fields.type_name.clone(),
            code_name: fields.code_name.clone(),
            identifier: fields.identifier,
            sequence: fields.sequence,
            gateway_ip: fields.gateway_ip.clone(),
            payload_len: fields.payload_len as u32,
        };
        out.push(new_event(
            chunk.capture_id.to_string(),
            envelope,
            BronzeEventFamily::ProtocolTransaction(ProtocolTransaction {
                operation,
                status,
                request_summary: Some(format!(
                    "ICMP type {} code {}",
                    fields.icmp_type, fields.icmp_code
                )),
                response_summary: None,
                object_refs: Vec::new(),
                values: Vec::new(),
                attributes: attrs,
                modbus: None,
                protocol_fields: Some(ProtocolFields::Icmp(icmp_pf)),
            }),
        ));
    }
}

// ── Inventory registration ──────────────────────────────────────
inventory::submit!(crate::engine::decoders::DecoderRegistration {
    name: "icmp",
    factory: || Box::new(IcmpDecoder::default()),
});
