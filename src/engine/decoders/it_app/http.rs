use std::collections::BTreeMap;

use crate::bronze::{
    BronzeEvent, BronzeEventFamily, HttpBronzeFields, ProtocolFields, ProtocolTransaction,
    TransportProtocol,
};
use crate::dissectors::http::HttpDissector;
use crate::engine::{DecoderInterest, SessionDecoder, StreamChunk, build_envelope, new_event};
use crate::registry::{HttpFields, ProtocolData, ProtocolDissector};

#[derive(Default)]
pub(crate) struct HttpDecoder {
    dissector: HttpDissector,
}

impl SessionDecoder for HttpDecoder {
    fn name(&self) -> &'static str {
        "http"
    }

    fn interest(&self) -> &'static [DecoderInterest] {
        &[DecoderInterest::TcpPort(80), DecoderInterest::TcpPort(8080)]
    }

    fn on_stream_chunk(&mut self, chunk: &StreamChunk<'_>, out: &mut Vec<BronzeEvent>) {
        if chunk.payload.is_empty() {
            return;
        }
        if let Some(ProtocolData::Http(HttpFields {
            method,
            host,
            uri,
            status_code,
            content_type,
            content_length,
        })) = self.dissector.parse(chunk.payload, &chunk.context)
        {
            let is_request = !method.is_empty();
            let http_pf = HttpBronzeFields {
                method: method.clone(),
                host: host.clone(),
                uri: uri.clone(),
                status_code,
                content_type: content_type.clone(),
                content_length,
                is_request,
                direction: if is_request {
                    "request".to_string()
                } else {
                    status_code.to_string()
                },
            };
            let mut attributes = BTreeMap::new();
            attributes.insert("content_type".to_string(), content_type);
            attributes.insert("content_length".to_string(), content_length.to_string());
            if !host.is_empty() {
                attributes.insert("host".to_string(), host);
            }
            let operation = if is_request {
                method.clone()
            } else {
                "response".to_string()
            };
            out.push(new_event(
                chunk.capture_id.to_string(),
                build_envelope(
                    &chunk.context,
                    chunk.interface_id,
                    chunk.frame_index,
                    chunk.timestamp,
                    chunk.segment_hash,
                    TransportProtocol::Tcp,
                    Some("http"),
                    chunk.captured_len,
                    chunk.session_key.clone(),
                ),
                BronzeEventFamily::ProtocolTransaction(ProtocolTransaction {
                    operation,
                    status: if status_code > 0 {
                        status_code.to_string()
                    } else {
                        "request".to_string()
                    },
                    request_summary: is_request.then_some(uri.clone()),
                    response_summary: (status_code > 0).then_some(status_code.to_string()),
                    object_refs: (!uri.is_empty()).then_some(uri).into_iter().collect(),
                    values: Vec::new(),
                    attributes,
                    modbus: None,
                    protocol_fields: Some(ProtocolFields::Http(http_pf)),
                }),
            ));
        }
    }
}

inventory::submit!(crate::engine::decoders::DecoderRegistration {
    name: "http",
    factory: || Box::new(HttpDecoder::default()),
});
