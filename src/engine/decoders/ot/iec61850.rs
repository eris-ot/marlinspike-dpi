//! IEC 61850 decoder — MMS (TCP/102), GOOSE (EtherType 0x88B8), and Sampled Values (0x88BA).
//!
//! Dispatches to [`Iec61850Dissector`] which handles all three sub-protocols from a single
//! entry point. Emits [`ProtocolTransaction`], [`AssetObservation`], [`TopologyObservation`],
//! and (when non-empty) [`ExtractedArtifact`] events.
//!
//! Each [`ProtocolTransaction`] carries a typed [`ProtocolFields::Iec61850`] payload alongside
//! the legacy `attributes` map, enabling downstream consumers to pattern-match on structured
//! fields without string-key lookups. The `attributes` map is retained for backward
//! compatibility through the v1.x line and will be removed in v2.0.

use std::collections::BTreeMap;

use super::{context_asset_key, context_remote_asset_key, normalize_operation_name};
use crate::bronze::{
    AssetObservation, BronzeEvent, BronzeEventFamily, Iec61850BronzeFields, ProtocolFields,
    ProtocolTransaction, TopologyObservation, TransportProtocol,
};
use crate::dissectors::iec61850::{
    IEC61850_GOOSE_ETHERTYPE, IEC61850_MMS_PORT, IEC61850_SV_ETHERTYPE, Iec61850Dissector,
    Iec61850Fields, Iec61850Profile,
};
use crate::engine::{
    DecoderInterest, SessionDecoder, StreamChunk, artifact_event, build_envelope, new_event,
    parse_anomaly_event,
};

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

        let protocol_fields = Some(ProtocolFields::Iec61850(iec61850_bronze_fields(&fields)));

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
                protocol_fields,
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

fn iec61850_bronze_fields(fields: &Iec61850Fields) -> Iec61850BronzeFields {
    let sub_protocol = iec61850_profile_name(fields.profile).to_string();

    let direction = match fields.profile {
        Iec61850Profile::Goose | Iec61850Profile::SampledValues => "publish".to_string(),
        Iec61850Profile::MmsIsoOnTcp => match fields.service.as_deref() {
            Some(s) if s.contains("response") => "response".to_string(),
            Some(s) if s.contains("request") => "request".to_string(),
            _ => "observed".to_string(),
        },
    };

    match fields.profile {
        Iec61850Profile::MmsIsoOnTcp => Iec61850BronzeFields {
            sub_protocol,
            mms_service: fields.service.clone(),
            mms_invoke_id: fields.mms_invoke_id,
            mms_visible_string: fields.visible_strings.first().cloned(),
            goose_appid: None,
            goose_dataset_ref: None,
            goose_state_number: None,
            goose_sequence_number: None,
            goose_test: false,
            sv_appid: None,
            sv_smp_cnt: None,
            sv_smp_synch: None,
            direction,
        },
        Iec61850Profile::Goose => Iec61850BronzeFields {
            sub_protocol,
            mms_service: None,
            mms_invoke_id: None,
            mms_visible_string: None,
            goose_appid: fields.app_id,
            goose_dataset_ref: fields
                .dataset
                .clone()
                .or_else(|| fields.object_references.first().cloned()),
            goose_state_number: fields.goose_st_num,
            goose_sequence_number: fields.goose_sq_num,
            goose_test: fields.goose_test,
            sv_appid: None,
            sv_smp_cnt: None,
            sv_smp_synch: None,
            direction,
        },
        Iec61850Profile::SampledValues => Iec61850BronzeFields {
            sub_protocol,
            mms_service: None,
            mms_invoke_id: None,
            mms_visible_string: None,
            goose_appid: None,
            goose_dataset_ref: None,
            goose_state_number: None,
            goose_sequence_number: None,
            goose_test: false,
            sv_appid: fields.app_id,
            sv_smp_cnt: fields.sv_smp_cnt,
            sv_smp_synch: fields.sv_smp_synch,
            direction,
        },
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bronze::{BronzeEventFamily, Iec61850BronzeFields, ProtocolFields};
    use crate::dissectors::iec61850::{
        IEC61850_GOOSE_ETHERTYPE, IEC61850_MMS_PORT, IEC61850_SV_ETHERTYPE,
    };
    use crate::engine::{SessionDecoder, StreamChunk};
    use crate::registry::PacketContext;

    const TPKT_HEADER_SIZE: usize = 4;

    fn build_tpkt_cotp_mms(payload: &[u8]) -> Vec<u8> {
        let cotp_len = 2u8;
        let tpkt_len = (TPKT_HEADER_SIZE + 1 + cotp_len as usize + payload.len()) as u16;
        let mut pkt = Vec::new();
        pkt.push(0x03);
        pkt.push(0x00);
        pkt.extend_from_slice(&tpkt_len.to_be_bytes());
        pkt.push(cotp_len);
        pkt.push(0xF0);
        pkt.push(0x80);
        pkt.extend_from_slice(payload);
        pkt
    }

    fn goose_or_sv_frame(app_id: u16, payload: &[u8]) -> Vec<u8> {
        let len = (8 + payload.len()) as u16;
        let mut pkt = Vec::new();
        pkt.extend_from_slice(&app_id.to_be_bytes());
        pkt.extend_from_slice(&len.to_be_bytes());
        pkt.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);
        pkt.extend_from_slice(payload);
        pkt
    }

    fn make_context(src_port: u16, dst_port: u16) -> PacketContext {
        PacketContext {
            src_mac: [0x02, 0x00, 0x00, 0x00, 0x00, 0x01],
            dst_mac: [0x02, 0x00, 0x00, 0x00, 0x00, 0x02],
            src_ip: std::net::IpAddr::V4(std::net::Ipv4Addr::new(10, 0, 0, 1)),
            dst_ip: std::net::IpAddr::V4(std::net::Ipv4Addr::new(10, 0, 0, 2)),
            src_port,
            dst_port,
            vlan_id: None,
            timestamp: 1_700_000_000_000_000_000,
        }
    }

    fn run_decoder(
        payload: &[u8],
        src_port: u16,
        dst_port: u16,
        ethertype: u16,
    ) -> Vec<BronzeEvent> {
        let context = make_context(src_port, dst_port);
        let chunk = StreamChunk {
            capture_id: "cap1",
            interface_id: 0,
            frame_index: 1,
            timestamp: chrono::DateTime::<chrono::Utc>::from_timestamp(1_700_000_000, 0).unwrap(),
            segment_hash: "seg",
            session_key: "sess".to_string(),
            context,
            payload,
            captured_len: payload.len() as u64,
            ethertype,
            ip_proto: None,
            llc: None,
            transport: TransportProtocol::Ethernet,
        };
        let mut decoder = Iec61850DecoderWrapper::default();
        let mut out = Vec::new();
        if ethertype == IEC61850_GOOSE_ETHERTYPE || ethertype == IEC61850_SV_ETHERTYPE {
            decoder.on_datagram(&chunk, &mut out);
        } else {
            decoder.on_stream_chunk(&chunk, &mut out);
        }
        out
    }

    fn extract_iec61850_fields(events: &[BronzeEvent]) -> &Iec61850BronzeFields {
        for ev in events {
            if let BronzeEventFamily::ProtocolTransaction(tx) = &ev.family
                && let Some(ProtocolFields::Iec61850(ref f)) = tx.protocol_fields
            {
                return f;
            }
        }
        panic!("no Iec61850BronzeFields found in events");
    }

    // -----------------------------------------------------------------------
    // MMS tests
    // -----------------------------------------------------------------------

    #[test]
    fn mms_initiate_request_typed_fields() {
        // MMS initiate-request (tag 0x60) — no visible strings, no invoke-id.
        let payload = &[0x60, 0x04, 0x01, 0x02, 0x03, 0x04];
        let pkt = build_tpkt_cotp_mms(payload);
        let events = run_decoder(&pkt, 50_000, IEC61850_MMS_PORT, 0);

        let f = extract_iec61850_fields(&events);
        assert_eq!(f.sub_protocol, "mms");
        assert_eq!(f.mms_service.as_deref(), Some("initiate_request"));
        assert_eq!(f.direction, "request");
        assert!(f.goose_appid.is_none());
        assert!(f.sv_appid.is_none());
        assert!(!f.goose_test);
    }

    #[test]
    fn mms_read_request_with_visible_string() {
        // confirmed-request (0xA0) with invoke-id=1 followed by a visible string.
        // BER: tag=0xA0, len=0x1E (30), then INTEGER 0x02 0x01 0x01 (invoke-id=1),
        // then readable ASCII reference.
        let inner: &[u8] = b"\x02\x01\x01IED1LD0/MMXU1.A.phsA.cVal.mag.f";
        let mut payload = vec![0xA0u8, inner.len() as u8];
        payload.extend_from_slice(inner);
        let pkt = build_tpkt_cotp_mms(&payload);
        let events = run_decoder(&pkt, 50_000, IEC61850_MMS_PORT, 0);

        let f = extract_iec61850_fields(&events);
        assert_eq!(f.sub_protocol, "mms");
        assert_eq!(f.mms_service.as_deref(), Some("confirmed_request_pdu"));
        assert_eq!(f.mms_invoke_id, Some(1));
        assert!(
            f.mms_visible_string.is_some(),
            "expected at least one visible string"
        );
        assert_eq!(f.direction, "request");
    }

    #[test]
    fn mms_attributes_backward_compat() {
        // Ensure the legacy `attributes` map is still populated alongside typed fields.
        let payload = &[0x60, 0x02, 0x00, 0x00];
        let pkt = build_tpkt_cotp_mms(payload);
        let events = run_decoder(&pkt, 50_000, IEC61850_MMS_PORT, 0);

        let tx = events
            .iter()
            .find_map(|ev| {
                if let BronzeEventFamily::ProtocolTransaction(tx) = &ev.family {
                    Some(tx)
                } else {
                    None
                }
            })
            .expect("expected ProtocolTransaction");

        assert!(
            tx.attributes.contains_key("profile"),
            "attributes must still carry profile"
        );
        assert!(
            tx.attributes.contains_key("message_type"),
            "attributes must carry message_type"
        );
        assert!(
            tx.protocol_fields.is_some(),
            "protocol_fields must be populated"
        );
    }

    // -----------------------------------------------------------------------
    // GOOSE tests
    // -----------------------------------------------------------------------

    #[test]
    fn goose_update_st_num_sq_num() {
        // GOOSE PDU with stNum=5, sqNum=2, test=false.
        // Outer GOOSE-PDU SEQUENCE tag 0x61, then context-primitive TLVs:
        //   [9] stNum=5   → 0x89 0x01 0x05
        //   [10] sqNum=2  → 0x8A 0x01 0x02
        let goose_body: &[u8] = &[
            0x89, 0x01, 0x05, // stNum = 5
            0x8A, 0x01, 0x02, // sqNum = 2
        ];
        let mut goose_pdu = vec![0x61u8, goose_body.len() as u8];
        goose_pdu.extend_from_slice(goose_body);
        // Prefix with dataset ref string so visible-string extraction works.
        let mut inner = b"IED2LD1/LLN0\x24GO\x24gcb1\x00".to_vec();
        inner.extend_from_slice(&goose_pdu);

        let pkt = goose_or_sv_frame(0x1001, &inner);
        let events = run_decoder(&pkt, 0, 0, IEC61850_GOOSE_ETHERTYPE);

        let f = extract_iec61850_fields(&events);
        assert_eq!(f.sub_protocol, "goose");
        assert_eq!(f.goose_appid, Some(0x1001));
        assert_eq!(f.goose_state_number, Some(5));
        assert_eq!(f.goose_sequence_number, Some(2));
        assert!(!f.goose_test);
        assert_eq!(f.direction, "publish");
    }

    #[test]
    fn goose_test_bit_set() {
        // GOOSE PDU with test bit = true (0x86 0x01 0xFF), stNum=1, sqNum=0.
        let goose_body: &[u8] = &[
            0x86, 0x01, 0xFF, // test = true
            0x89, 0x01, 0x01, // stNum = 1
            0x8A, 0x01, 0x00, // sqNum = 0
        ];
        let mut goose_pdu = vec![0x61u8, goose_body.len() as u8];
        goose_pdu.extend_from_slice(goose_body);
        // Pad with some bytes so the frame length is valid.
        let mut inner = b"IED3LD0/LLN0\x24GO\x24testcb\x00".to_vec();
        inner.extend_from_slice(&goose_pdu);

        let pkt = goose_or_sv_frame(0x2000, &inner);
        let events = run_decoder(&pkt, 0, 0, IEC61850_GOOSE_ETHERTYPE);

        let f = extract_iec61850_fields(&events);
        assert_eq!(f.sub_protocol, "goose");
        assert!(
            f.goose_test,
            "test bit must be true for security-relevant test-mode detection"
        );
        assert_eq!(f.goose_state_number, Some(1));
        assert_eq!(f.goose_sequence_number, Some(0));
    }

    // -----------------------------------------------------------------------
    // Sampled Values tests
    // -----------------------------------------------------------------------

    #[test]
    fn sv_asdu_smp_cnt_extracted() {
        // SV PDU: seqOfASDU (0xA2) containing one ASDU (0x30) with:
        //   smpCnt [2] = 0x82 0x02 0x01 0xF4  (smpCnt = 500)
        //   smpSynch [5] = 0x85 0x01 0x02      (smpSynch = 2 = global)
        let asdu_inner: &[u8] = &[
            0x82, 0x02, 0x01, 0xF4, // smpCnt = 500
            0x85, 0x01, 0x02, // smpSynch = 2
        ];
        let mut asdu = vec![0x30u8, asdu_inner.len() as u8];
        asdu.extend_from_slice(asdu_inner);

        let mut seq_of_asdu = vec![0xA2u8, asdu.len() as u8];
        seq_of_asdu.extend_from_slice(&asdu);

        // Prepend a visible string for identity extraction.
        let mut inner = b"IED4LD0/LPHD1\x24SV\x24smvcb\x00".to_vec();
        inner.extend_from_slice(&seq_of_asdu);

        let pkt = goose_or_sv_frame(0x1002, &inner);
        let events = run_decoder(&pkt, 0, 0, IEC61850_SV_ETHERTYPE);

        let f = extract_iec61850_fields(&events);
        assert_eq!(f.sub_protocol, "sampled_values");
        assert_eq!(f.sv_appid, Some(0x1002));
        assert_eq!(f.sv_smp_cnt, Some(500));
        assert_eq!(f.sv_smp_synch, Some(2));
        assert_eq!(f.direction, "publish");
    }
}
