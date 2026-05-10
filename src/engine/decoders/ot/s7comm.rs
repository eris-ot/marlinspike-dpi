use std::collections::BTreeMap;

use crate::bronze::{BronzeEvent, BronzeEventFamily, ProtocolTransaction, TransportProtocol};
use crate::dissectors::s7comm::S7commDissector;
use crate::engine::{
    artifact_event, build_envelope, new_event, parse_anomaly_event, DecoderInterest,
    SessionDecoder, StreamChunk,
};
use crate::registry::{PacketContext, ProtocolData, ProtocolDissector, S7commFields};

pub(crate) struct S7commDecoderWrapper {
    dissector: S7commDissector,
}

impl Default for S7commDecoderWrapper {
    fn default() -> Self {
        Self {
            dissector: S7commDissector,
        }
    }
}

impl SessionDecoder for S7commDecoderWrapper {
    fn name(&self) -> &'static str {
        "s7comm"
    }

    fn interest(&self) -> &'static [DecoderInterest] {
        &[DecoderInterest::TcpPort(102)]
    }

    fn on_stream_chunk(&mut self, chunk: &StreamChunk<'_>, out: &mut Vec<BronzeEvent>) {
        if !self.dissector.can_parse(
            chunk.payload,
            chunk.context.src_port,
            chunk.context.dst_port,
        ) {
            return;
        }

        match self.dissector.parse(chunk.payload, &chunk.context) {
            Some(ProtocolData::S7comm(S7commFields {
                rosctr,
                function,
                parameter,
                data,
            })) => {
                let operation = s7comm_function_name(function).to_string();
                let mut attributes = BTreeMap::new();
                attributes.insert("rosctr".to_string(), format!("{rosctr:#04x}"));
                attributes.insert(
                    "rosctr_name".to_string(),
                    s7comm_rosctr_name(rosctr).to_string(),
                );
                attributes.insert("function".to_string(), format!("{function:#04x}"));
                attributes.insert("parameter_length".to_string(), parameter.len().to_string());
                attributes.insert("data_length".to_string(), data.len().to_string());

                let envelope = build_envelope(
                    &chunk.context,
                    chunk.interface_id,
                    chunk.frame_index,
                    chunk.timestamp,
                    chunk.segment_hash,
                    TransportProtocol::Tcp,
                    Some("s7comm"),
                    chunk.captured_len,
                    chunk.session_key.clone(),
                );

                out.push(new_event(
                    chunk.capture_id.to_string(),
                    envelope.clone(),
                    BronzeEventFamily::ProtocolTransaction(ProtocolTransaction {
                        operation,
                        status: s7comm_status(rosctr, &chunk.context).to_string(),
                        request_summary: Some(format!(
                            "{} {}",
                            s7comm_rosctr_name(rosctr),
                            s7comm_function_name(function)
                        )),
                        response_summary: None,
                        object_refs: vec![
                            format!("s7_function:{function:#04x}"),
                            format!("s7_rosctr:{rosctr:#04x}"),
                        ],
                        values: Vec::new(),
                        attributes,
                                        modbus: None,
                                        protocol_fields: None,
}),
                ));

                if !data.is_empty() {
                    out.push(artifact_event(
                        chunk.capture_id.to_string(),
                        envelope,
                        "s7comm_data",
                        &format!("{}:{function:#04x}", chunk.session_key),
                        Some("application/octet-stream"),
                        Some("S7comm data payload"),
                        &data,
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
                    TransportProtocol::Tcp,
                    Some("s7comm"),
                    chunk.captured_len,
                    chunk.session_key.clone(),
                ),
                self.name(),
                "medium",
                "failed to parse s7comm payload",
                chunk.payload,
            )),
        }
    }
}

fn s7comm_rosctr_name(code: u8) -> &'static str {
    match code {
        0x01 => "job",
        0x02 => "ack",
        0x03 => "ack_data",
        0x07 => "userdata",
        _ => "unknown",
    }
}

fn s7comm_function_name(code: u8) -> &'static str {
    match code {
        0x00 => "cpu_services",
        0x04 => "read_var",
        0x05 => "write_var",
        0x1A => "request_download",
        0x1B => "download_block",
        0x1C => "download_ended",
        0x1D => "start_upload",
        0x1E => "upload",
        0x1F => "end_upload",
        0x28 => "pi_service",
        0x29 => "plc_stop",
        0xF0 => "setup_communication",
        _ => "s7comm_message",
    }
}

fn s7comm_status(rosctr: u8, context: &PacketContext) -> &'static str {
    match rosctr {
        0x02 | 0x03 => "response",
        0x01 if context.dst_port == 102 => "request",
        0x01 => "observed",
        _ => "observed",
    }
}

inventory::submit!(crate::engine::decoders::DecoderRegistration {
    name: "s7comm",
    factory: || Box::new(S7commDecoderWrapper::default()),
});
