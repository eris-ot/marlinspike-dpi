use std::collections::BTreeMap;

use crate::bronze::{
    AssetObservation, BronzeEvent, BronzeEventFamily, NtpBronzeFields, ProtocolFields,
    ProtocolTransaction, TransportProtocol,
};
use crate::dissectors::ntp::NtpDissector;
use crate::engine::{
    DecoderInterest, SessionDecoder, StreamChunk, build_envelope, new_event, parse_anomaly_event,
};
use crate::registry::{NtpFields, ProtocolData, ProtocolDissector};

// ── NTP decoder ──────────────────────────────────────────────────

#[derive(Default)]
pub(crate) struct NtpDecoder {
    dissector: NtpDissector,
}

impl SessionDecoder for NtpDecoder {
    fn name(&self) -> &'static str {
        "ntp"
    }

    fn interest(&self) -> &'static [DecoderInterest] {
        &[DecoderInterest::UdpPort(123)]
    }

    fn on_datagram(&mut self, chunk: &StreamChunk<'_>, out: &mut Vec<BronzeEvent>) {
        match self.dissector.parse(chunk.payload, &chunk.context) {
            Some(ProtocolData::Ntp(NtpFields {
                version,
                mode,
                mode_name,
                stratum,
                reference_id,
                ..
            })) => {
                let envelope = build_envelope(
                    &chunk.context,
                    chunk.interface_id,
                    chunk.frame_index,
                    chunk.timestamp,
                    chunk.segment_hash,
                    TransportProtocol::Udp,
                    Some("ntp"),
                    chunk.captured_len,
                    chunk.session_key.clone(),
                );

                let mut attributes = BTreeMap::new();
                attributes.insert("version".to_string(), version.to_string());
                attributes.insert("stratum".to_string(), stratum.to_string());
                attributes.insert("reference_id".to_string(), reference_id.clone());

                let direction = if mode == 4 { "response" } else { "request" };
                out.push(new_event(
                    chunk.capture_id.to_string(),
                    envelope.clone(),
                    BronzeEventFamily::ProtocolTransaction(ProtocolTransaction {
                        operation: mode_name.clone(),
                        status: direction.to_string(),
                        request_summary: Some(format!("NTPv{version} {mode_name}")),
                        response_summary: None,
                        object_refs: vec![],
                        values: vec![],
                        attributes,
                        modbus: None,
                        protocol_fields: Some(ProtocolFields::Ntp(NtpBronzeFields {
                            version,
                            mode,
                            mode_name: mode_name.clone(),
                            stratum,
                            reference_id: reference_id.clone(),
                            direction: direction.to_string(),
                        })),
                    }),
                ));

                // NTP servers (mode 4, stratum 1-15) are worth identifying.
                if mode == 4 && stratum > 0 && stratum < 16 {
                    let mut identifiers =
                        BTreeMap::from([("ip".to_string(), chunk.context.src_ip.to_string())]);
                    identifiers.insert("reference_id".to_string(), reference_id);
                    out.push(new_event(
                        chunk.capture_id.to_string(),
                        envelope,
                        BronzeEventFamily::AssetObservation(AssetObservation {
                            asset_key: chunk.context.src_ip.to_string(),
                            role: Some("ntp_server".to_string()),
                            vendor: None,
                            model: None,
                            firmware: None,
                            hostnames: vec![],
                            protocols: vec!["ntp".to_string()],
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
                    Some("ntp"),
                    chunk.captured_len,
                    chunk.session_key.clone(),
                ),
                self.name(),
                "low",
                "failed to parse ntp payload",
                chunk.payload,
            )),
        }
    }
}

// ── Inventory registration ──────────────────────────────────────
inventory::submit!(crate::engine::decoders::DecoderRegistration {
    name: "ntp",
    factory: || Box::new(NtpDecoder::default()),
});
