use std::collections::BTreeMap;

use crate::bronze::{
    AssetObservation, BronzeEvent, BronzeEventFamily, FtpBronzeFields, ProtocolFields,
    ProtocolTransaction, TransportProtocol,
};
use crate::dissectors::ftp::FtpDissector;
use crate::engine::{
    DecoderInterest, SessionDecoder, StreamChunk, build_envelope, new_event, parse_anomaly_event,
};
use crate::registry::{FtpFields, ProtocolData, ProtocolDissector};

// ── FTP decoder ──────────────────────────────────────────────────

#[derive(Default)]
pub(crate) struct FtpDecoder {
    dissector: FtpDissector,
}

impl SessionDecoder for FtpDecoder {
    fn name(&self) -> &'static str {
        "ftp"
    }

    fn interest(&self) -> &'static [DecoderInterest] {
        &[DecoderInterest::TcpPort(21)]
    }

    fn on_stream_chunk(&mut self, chunk: &StreamChunk<'_>, out: &mut Vec<BronzeEvent>) {
        match self.dissector.parse(chunk.payload, &chunk.context) {
            Some(ProtocolData::Ftp(FtpFields {
                is_response,
                command,
                argument,
                reply_code,
                reply_text,
                banner,
            })) => {
                let envelope = build_envelope(
                    &chunk.context,
                    chunk.interface_id,
                    chunk.frame_index,
                    chunk.timestamp,
                    chunk.segment_hash,
                    TransportProtocol::Tcp,
                    Some("ftp"),
                    chunk.captured_len,
                    chunk.session_key.clone(),
                );

                let (operation, status, summary) = if is_response {
                    let code = reply_code.unwrap_or(0);
                    let text = reply_text.as_deref().unwrap_or("");
                    (
                        "reply".to_string(),
                        format!("{code}"),
                        format!("{code} {text}"),
                    )
                } else {
                    let cmd = command.as_deref().unwrap_or("?");
                    let arg = argument.as_deref().unwrap_or("");
                    (
                        cmd.to_lowercase(),
                        "request".to_string(),
                        format!("{cmd} {arg}").trim().to_string(),
                    )
                };

                let mut attributes = BTreeMap::new();
                if let Some(ref cmd) = command {
                    attributes.insert("command".to_string(), cmd.clone());
                }
                if let Some(ref arg) = argument {
                    attributes.insert("argument".to_string(), arg.clone());
                }

                let ftp_pf = FtpBronzeFields {
                    is_response,
                    command: command.clone(),
                    argument: argument.clone(),
                    reply_code,
                    reply_text: reply_text.clone(),
                    direction: if is_response { "response" } else { "request" }.to_string(),
                };
                out.push(new_event(
                    chunk.capture_id.to_string(),
                    envelope.clone(),
                    BronzeEventFamily::ProtocolTransaction(ProtocolTransaction {
                        operation,
                        status,
                        request_summary: Some(summary),
                        response_summary: None,
                        object_refs: argument.into_iter().collect(),
                        values: vec![],
                        attributes,
                        modbus: None,
                        protocol_fields: Some(ProtocolFields::Ftp(ftp_pf)),
                    }),
                ));

                // Banner (220) identifies the FTP server.
                if let Some(banner_text) = banner {
                    out.push(new_event(
                        chunk.capture_id.to_string(),
                        envelope,
                        BronzeEventFamily::AssetObservation(AssetObservation {
                            asset_key: chunk.context.src_ip.to_string(),
                            role: Some("ftp_server".to_string()),
                            vendor: None,
                            model: None,
                            firmware: Some(banner_text),
                            hostnames: vec![],
                            protocols: vec!["ftp".to_string()],
                            identifiers: BTreeMap::from([(
                                "ip".to_string(),
                                chunk.context.src_ip.to_string(),
                            )]),
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
                    TransportProtocol::Tcp,
                    Some("ftp"),
                    chunk.captured_len,
                    chunk.session_key.clone(),
                ),
                self.name(),
                "medium",
                "failed to parse ftp payload",
                chunk.payload,
            )),
        }
    }
}

// ── Inventory registration ──────────────────────────────────────
inventory::submit!(crate::engine::decoders::DecoderRegistration {
    name: "ftp",
    factory: || Box::new(FtpDecoder::default()),
});
