use std::collections::BTreeMap;

use crate::bronze::{
    AssetObservation, BronzeEvent, BronzeEventFamily, ProtocolFields, ProtocolTransaction,
    SyslogBronzeFields, TransportProtocol,
};
use crate::dissectors::syslog::SyslogDissector;
use crate::engine::{
    DecoderInterest, SessionDecoder, StreamChunk, build_envelope, new_event, parse_anomaly_event,
};
use crate::registry::{ProtocolData, ProtocolDissector, SyslogFields};

// ── Syslog decoder ───────────────────────────────────────────────

#[derive(Default)]
pub(crate) struct SyslogDecoder {
    dissector: SyslogDissector,
}

impl SessionDecoder for SyslogDecoder {
    fn name(&self) -> &'static str {
        "syslog"
    }

    fn interest(&self) -> &'static [DecoderInterest] {
        &[DecoderInterest::UdpPort(514)]
    }

    fn on_datagram(&mut self, chunk: &StreamChunk<'_>, out: &mut Vec<BronzeEvent>) {
        match self.dissector.parse(chunk.payload, &chunk.context) {
            Some(ProtocolData::Syslog(SyslogFields {
                facility,
                facility_name,
                severity,
                severity_name,
                hostname,
                app_name,
                message,
            })) => {
                let envelope = build_envelope(
                    &chunk.context,
                    chunk.interface_id,
                    chunk.frame_index,
                    chunk.timestamp,
                    chunk.segment_hash,
                    TransportProtocol::Udp,
                    Some("syslog"),
                    chunk.captured_len,
                    chunk.session_key.clone(),
                );

                let mut attributes = BTreeMap::new();
                attributes.insert("facility".to_string(), facility_name.clone());
                attributes.insert("severity".to_string(), severity_name.clone());
                if let Some(ref app) = app_name {
                    attributes.insert("app_name".to_string(), app.clone());
                }

                let syslog_pf = SyslogBronzeFields {
                    facility,
                    facility_name: facility_name.clone(),
                    severity,
                    severity_name: severity_name.clone(),
                    hostname: hostname.clone(),
                    app_name: app_name.clone(),
                };
                out.push(new_event(
                    chunk.capture_id.to_string(),
                    envelope.clone(),
                    BronzeEventFamily::ProtocolTransaction(ProtocolTransaction {
                        operation: "syslog_message".to_string(),
                        status: severity_name,
                        request_summary: message,
                        response_summary: None,
                        object_refs: vec![format!("{facility_name}.{severity}")],
                        values: vec![],
                        attributes,
                        modbus: None,
                        protocol_fields: Some(ProtocolFields::Syslog(syslog_pf)),
                    }),
                ));

                // Hostname in syslog = asset identification.
                if let Some(hostname) = hostname {
                    let mut identifiers =
                        BTreeMap::from([("ip".to_string(), chunk.context.src_ip.to_string())]);
                    identifiers.insert("hostname".to_string(), hostname.clone());
                    let protocols = if let Some(ref app) = app_name {
                        vec!["syslog".to_string(), app.clone()]
                    } else {
                        vec!["syslog".to_string()]
                    };
                    out.push(new_event(
                        chunk.capture_id.to_string(),
                        envelope,
                        BronzeEventFamily::AssetObservation(AssetObservation {
                            asset_key: chunk.context.src_ip.to_string(),
                            role: None,
                            vendor: None,
                            model: None,
                            firmware: None,
                            hostnames: vec![hostname],
                            protocols,
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
                    Some("syslog"),
                    chunk.captured_len,
                    chunk.session_key.clone(),
                ),
                self.name(),
                "low",
                "failed to parse syslog payload",
                chunk.payload,
            )),
        }
    }
}

// ── Inventory registration ──────────────────────────────────────
inventory::submit!(crate::engine::decoders::DecoderRegistration {
    name: "syslog",
    factory: || Box::new(SyslogDecoder::default()),
});
