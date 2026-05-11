//! IEC 60870-5-104 session decoder.
//!
//! Emits [`ProtocolTransaction`] events for every APCI frame (I/S/U). The
//! typed [`ProtocolFields::Iec104`] surface is populated on every transaction
//! alongside the legacy `attributes` map, which is retained for backward
//! compatibility through the v1.x line and will be removed in v2.0.

use std::collections::BTreeMap;

use crate::bronze::{
    AssetObservation, BronzeEvent, BronzeEventFamily, EventEnvelope, Iec104BronzeFields,
    ProtocolFields, ProtocolTransaction, TopologyObservation, TransportProtocol,
};
use crate::dissectors::iec104::parse_iec104_frames;
use crate::engine::{
    artifact_event, build_envelope, new_event, parse_anomaly_event, DecoderInterest, SessionDecoder,
    StreamChunk,
};
use crate::registry::{Iec104Fields, PacketContext};

#[derive(Default)]
pub(crate) struct Iec104DecoderWrapper;

impl SessionDecoder for Iec104DecoderWrapper {
    fn name(&self) -> &'static str {
        "iec104"
    }

    fn interest(&self) -> &'static [DecoderInterest] {
        &[DecoderInterest::TcpPort(2404)]
    }

    fn on_stream_chunk(&mut self, chunk: &StreamChunk<'_>, out: &mut Vec<BronzeEvent>) {
        let frames = parse_iec104_frames(chunk.payload);
        if frames.is_empty() {
            out.push(parse_anomaly_event(
                chunk.capture_id.to_string(),
                build_envelope(
                    &chunk.context,
                    chunk.interface_id,
                    chunk.frame_index,
                    chunk.timestamp,
                    chunk.segment_hash,
                    TransportProtocol::Tcp,
                    Some("iec104"),
                    chunk.captured_len,
                    chunk.session_key.clone(),
                ),
                self.name(),
                "medium",
                "failed to parse iec104 payload",
                chunk.payload,
            ));
            return;
        }

        for fields in frames {
            let Iec104Fields {
                frame_type,
                send_sequence,
                receive_sequence,
                u_format,
                type_id,
                cause_of_transmission,
                common_address,
                information_object_address,
                payload,
            } = fields;

            let envelope = build_envelope(
                &chunk.context,
                chunk.interface_id,
                chunk.frame_index,
                chunk.timestamp,
                chunk.segment_hash,
                TransportProtocol::Tcp,
                Some("iec104"),
                chunk.captured_len,
                chunk.session_key.clone(),
            );
            let mut attributes = BTreeMap::new();
            attributes.insert("frame_type".to_string(), frame_type.clone());
            if let Some(send_sequence) = send_sequence {
                attributes.insert("send_sequence".to_string(), send_sequence.to_string());
            }
            if let Some(receive_sequence) = receive_sequence {
                attributes.insert("receive_sequence".to_string(), receive_sequence.to_string());
            }
            if let Some(type_id) = type_id {
                attributes.insert("type_id".to_string(), type_id.to_string());
                attributes.insert(
                    "type_name".to_string(),
                    iec104_type_name(type_id).to_string(),
                );
            }
            if let Some(cause) = cause_of_transmission {
                attributes.insert("cause".to_string(), cause.to_string());
                attributes.insert(
                    "cause_name".to_string(),
                    iec104_cause_name(cause).to_string(),
                );
            }
            if let Some(common_address) = common_address {
                attributes.insert("common_address".to_string(), common_address.to_string());
            }
            if let Some(ioa) = information_object_address {
                attributes.insert("information_object_address".to_string(), ioa.to_string());
            }
            if let Some(u_format) = &u_format {
                attributes.insert("u_format".to_string(), u_format.clone());
            }

            let operation = iec104_operation_name(&frame_type, type_id, u_format.as_deref());

            let status_str = iec104_status(
                &frame_type,
                u_format.as_deref(),
                cause_of_transmission,
                &chunk.context,
            )
            .to_string();

            let typed_fields = iec104_bronze_fields(
                &frame_type,
                send_sequence,
                receive_sequence,
                u_format.as_deref(),
                type_id,
                cause_of_transmission,
                common_address,
                &status_str,
            );

            out.push(new_event(
                chunk.capture_id.to_string(),
                envelope.clone(),
                BronzeEventFamily::ProtocolTransaction(ProtocolTransaction {
                    operation,
                    status: status_str,
                    request_summary: Some(iec104_summary(
                        &frame_type,
                        type_id,
                        cause_of_transmission,
                        common_address,
                    )),
                    response_summary: None,
                    object_refs: iec104_object_refs(
                        type_id,
                        common_address,
                        information_object_address,
                    ),
                    values: Vec::new(),
                    attributes,
                    modbus: None,
                    protocol_fields: Some(ProtocolFields::Iec104(typed_fields)),
                }),
            ));

            for event in iec104_role_observations(
                chunk.capture_id,
                &envelope,
                &chunk.context,
                &frame_type,
                common_address,
            ) {
                out.push(event);
            }

            if !payload.is_empty() {
                out.push(artifact_event(
                    chunk.capture_id.to_string(),
                    envelope,
                    "iec104_asdu",
                    &format!("{}:{}", chunk.session_key, chunk.frame_index),
                    Some("application/octet-stream"),
                    Some("IEC 60870-5-104 ASDU payload"),
                    &payload,
                ));
            }
        }
    }
}


fn iec104_type_name(type_id: u8) -> &'static str {
    match type_id {
        1 => "single_point_information",
        3 => "double_point_information",
        9 => "measured_value_normalized",
        11 => "measured_value_scaled",
        13 => "measured_value_short_float",
        30 => "single_point_with_time",
        45 => "single_command",
        46 => "double_command",
        50 => "set_point_normalized",
        100 => "interrogation_command",
        103 => "clock_sync_command",
        _ => "asdu_type",
    }
}

fn iec104_cause_name(cause: u16) -> &'static str {
    match cause {
        1 => "periodic",
        3 => "spontaneous",
        5 => "request",
        6 => "activation",
        7 => "activation_confirmation",
        10 => "activation_termination",
        20 => "interrogated_by_station",
        _ => "cause",
    }
}

fn iec104_operation_name(frame_type: &str, type_id: Option<u8>, u_format: Option<&str>) -> String {
    match frame_type {
        "u" => u_format.unwrap_or("u_format").to_string(),
        "s" => "supervisory".to_string(),
        _ => type_id
            .map(iec104_type_name)
            .unwrap_or("iec104_asdu")
            .to_string(),
    }
}

fn iec104_status(
    frame_type: &str,
    u_format: Option<&str>,
    cause: Option<u16>,
    context: &PacketContext,
) -> &'static str {
    match frame_type {
        "u" => match u_format {
            Some(value) if value.ends_with("_act") => "request",
            Some(value) if value.ends_with("_con") => "response",
            _ => "observed",
        },
        "s" => "response",
        _ => match cause {
            Some(6) if context.dst_port == 2404 => "request",
            Some(7 | 10) if context.src_port == 2404 => "response",
            _ if context.dst_port == 2404 => "request",
            _ if context.src_port == 2404 => "response",
            _ => "observed",
        },
    }
}

fn iec104_summary(
    frame_type: &str,
    type_id: Option<u8>,
    cause: Option<u16>,
    common_address: Option<u16>,
) -> String {
    match frame_type {
        "u" => "u_format_control".to_string(),
        "s" => "supervisory_ack".to_string(),
        _ => format!(
            "{} cause={} ca={}",
            type_id.map(iec104_type_name).unwrap_or("iec104_asdu"),
            cause
                .map(|value| value.to_string())
                .unwrap_or_else(|| "?".to_string()),
            common_address
                .map(|value| value.to_string())
                .unwrap_or_else(|| "?".to_string())
        ),
    }
}

fn iec104_object_refs(
    type_id: Option<u8>,
    common_address: Option<u16>,
    information_object_address: Option<u32>,
) -> Vec<String> {
    let mut refs = Vec::new();
    if let Some(type_id) = type_id {
        refs.push(format!("iec104_type:{type_id}"));
    }
    if let Some(common_address) = common_address {
        refs.push(format!("iec104_common_address:{common_address}"));
    }
    if let Some(ioa) = information_object_address {
        refs.push(format!("iec104_ioa:{ioa}"));
    }
    refs
}

fn iec104_role_observations(
    capture_id: &str,
    envelope: &EventEnvelope,
    context: &PacketContext,
    frame_type: &str,
    common_address: Option<u16>,
) -> Vec<BronzeEvent> {
    let (src_role, dst_role) = match frame_type {
        "u" | "s" => {
            if context.src_port == 2404 {
                ("outstation", "master")
            } else {
                ("master", "outstation")
            }
        }
        _ if context.dst_port == 2404 => ("master", "outstation"),
        _ if context.src_port == 2404 => ("outstation", "master"),
        _ => ("peer", "peer"),
    };

    let mut src_identifiers = BTreeMap::from([("ip".to_string(), context.src_ip.to_string())]);
    if src_role == "outstation" {
        if let Some(common_address) = common_address {
            src_identifiers.insert(
                "iec104_common_address".to_string(),
                common_address.to_string(),
            );
        }
    }

    let mut dst_identifiers = BTreeMap::from([("ip".to_string(), context.dst_ip.to_string())]);
    if dst_role == "outstation" {
        if let Some(common_address) = common_address {
            dst_identifiers.insert(
                "iec104_common_address".to_string(),
                common_address.to_string(),
            );
        }
    }

    vec![
        new_event(
            capture_id.to_string(),
            envelope.clone(),
            BronzeEventFamily::AssetObservation(AssetObservation {
                asset_key: context.src_ip.to_string(),
                role: Some(src_role.to_string()),
                vendor: None,
                model: None,
                firmware: None,
                hostnames: Vec::new(),
                protocols: vec!["iec104".to_string()],
                identifiers: src_identifiers,
            }),
        ),
        new_event(
            capture_id.to_string(),
            envelope.clone(),
            BronzeEventFamily::AssetObservation(AssetObservation {
                asset_key: context.dst_ip.to_string(),
                role: Some(dst_role.to_string()),
                vendor: None,
                model: None,
                firmware: None,
                hostnames: Vec::new(),
                protocols: vec!["iec104".to_string()],
                identifiers: dst_identifiers,
            }),
        ),
        new_event(
            capture_id.to_string(),
            envelope.clone(),
            BronzeEventFamily::TopologyObservation(TopologyObservation {
                observation_type: "iec104_link".to_string(),
                local_id: context.src_ip.to_string(),
                remote_id: Some(context.dst_ip.to_string()),
                description: Some(frame_type.to_string()),
                capabilities: Vec::new(),
                metadata: common_address
                    .map(|value| {
                        BTreeMap::from([("common_address".to_string(), value.to_string())])
                    })
                    .unwrap_or_default(),
            }),
        ),
    ]
}

/// Build the typed [`Iec104BronzeFields`] for a single APCI frame.
///
/// `status_str` is the already-computed `iec104_status` result reused here so
/// the direction field matches the `ProtocolTransaction::status` exactly.
#[allow(clippy::too_many_arguments)]
fn iec104_bronze_fields(
    frame_type: &str,
    send_sequence: Option<u16>,
    receive_sequence: Option<u16>,
    u_format: Option<&str>,
    type_id: Option<u8>,
    cause_of_transmission: Option<u16>,
    common_address: Option<u16>,
    status_str: &str,
) -> Iec104BronzeFields {
    let apci_type = match frame_type {
        "i" => "i_frame",
        "s" => "s_frame",
        "u" => "u_frame",
        other => other,
    }
    .to_string();

    // COT is a 6-bit field; fits in u8.
    let cot_u8 = cause_of_transmission.map(|c| (c & 0x3F) as u8);
    let cot_name = cot_u8.map(|c| iec104_cause_name(c as u16).to_string());

    let asdu_type_name = type_id.map(|t| iec104_type_name(t).to_string());

    Iec104BronzeFields {
        apci_type,
        send_sequence,
        receive_sequence,
        u_function: u_format.map(str::to_string),
        asdu_type_id: type_id,
        asdu_type_name,
        cause_of_transmission: cot_u8,
        cause_of_transmission_name: cot_name,
        // Flags encoded in upper byte of the raw COT u16 (byte index 3 of ASDU)
        // are not yet extracted by the dissector, so default to false.
        is_negative_confirm: false,
        is_test: false,
        // Originator address byte not yet extracted by the dissector.
        originator_address: None,
        common_address,
        // Variable-structure qualifier not extracted by current dissector.
        num_objects: None,
        is_sequence: false,
        direction: status_str.to_string(),
    }
}

inventory::submit!(crate::engine::decoders::DecoderRegistration {
    name: "iec104",
    factory: || Box::new(Iec104DecoderWrapper::default()),
});

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    use chrono::Utc;

    use crate::bronze::ProtocolFields;
    use crate::engine::StreamChunk;
    use crate::registry::PacketContext;

    /// PacketContext mimicking a master→outstation direction (client→2404).
    fn ctx_master_to_outstation() -> PacketContext {
        PacketContext {
            src_mac: [0; 6],
            dst_mac: [0; 6],
            src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            dst_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            src_port: 50000,
            dst_port: 2404,
            vlan_id: None,
            timestamp: 0,
        }
    }

    /// PacketContext mimicking outstation→master direction (2404→client).
    fn ctx_outstation_to_master() -> PacketContext {
        PacketContext {
            src_mac: [0; 6],
            dst_mac: [0; 6],
            src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            dst_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            src_port: 2404,
            dst_port: 50000,
            vlan_id: None,
            timestamp: 0,
        }
    }

    fn make_chunk<'a>(payload: &'a [u8], context: PacketContext) -> StreamChunk<'a> {
        StreamChunk {
            capture_id: "test",
            segment_hash: "aa",
            interface_id: 0,
            frame_index: 0,
            timestamp: Utc::now(),
            context,
            ethertype: 0x0800,
            ip_proto: Some(6),
            llc: None,
            transport: TransportProtocol::Tcp,
            payload,
            session_key: "sess".to_string(),
            captured_len: payload.len() as u64,
        }
    }

    fn txns(events: &[BronzeEvent]) -> Vec<&ProtocolTransaction> {
        events
            .iter()
            .filter_map(|e| {
                if let BronzeEventFamily::ProtocolTransaction(ref t) = e.family {
                    Some(t)
                } else {
                    None
                }
            })
            .collect()
    }

    fn iec104_fields(tx: &ProtocolTransaction) -> &Iec104BronzeFields {
        match tx.protocol_fields.as_ref().expect("protocol_fields must be Some") {
            ProtocolFields::Iec104(f) => f,
            other => panic!("expected Iec104 variant, got {:?}", other),
        }
    }

    // -----------------------------------------------------------------------
    // I-frame: N(S)=3 N(R)=5, M_SP_NA_1 (type_id=1), cause=spontaneous (3)
    // APDU: 0x68 len ctrl0 ctrl1 ctrl2 ctrl3 type_id vsq cot0 cot1 ca0 ca1 ioa0 ioa1 ioa2 ...
    //   ctrl: I-frame N(S)=3 → bytes [6,0], N(R)=5 → bytes [10,0]
    //   ASDU: type_id=1, vsq=0x01, cot_lo=0x03, cot_hi=0x00, ca=0x0001, ioa=0
    fn i_frame_single_point() -> Vec<u8> {
        vec![
            0x68, 0x0E, // start + apdu_len=14
            0x06, 0x00, // ctrl[0..1]: N(S)=3  (6 >> 1 = 3)
            0x0A, 0x00, // ctrl[2..3]: N(R)=5  (10 >> 1 = 5)
            // ASDU (8 bytes)
            0x01, // type_id = 1 (M_SP_NA_1)
            0x01, // VSQ: SQ=0, num=1
            0x03, 0x00, // COT lo=3 (spontaneous), hi=0
            0x01, 0x00, // CA = 1
            0x00, 0x00, 0x00, // IOA = 0
            0x00, // info object value
        ]
    }

    // S-frame: N(R)=5
    fn s_frame() -> Vec<u8> {
        vec![
            0x68, 0x04, // start + apdu_len=4
            0x01, 0x00, // ctrl[0..1]: S-frame (bit0=1, bit1=0)
            0x0A, 0x00, // ctrl[2..3]: N(R)=5
        ]
    }

    // U-frame: STARTDT_act (0x07)
    fn u_frame_startdt_act() -> Vec<u8> {
        vec![
            0x68, 0x04, // start + apdu_len=4
            0x07, 0x00, 0x00, 0x00, // ctrl: 0x07 = U-frame STARTDT_act
        ]
    }

    // U-frame: TESTFR_act (0x43)
    fn u_frame_testfr_act() -> Vec<u8> {
        vec![
            0x68, 0x04, // start + apdu_len=4
            0x43, 0x00, 0x00, 0x00, // ctrl: 0x43 = U-frame TESTFR_act
        ]
    }

    // C_SC_NA_1 = 45, cot=6 (activation) to outstation port 2404
    fn i_frame_single_command() -> Vec<u8> {
        vec![
            0x68, 0x0E,
            0x00, 0x00, // N(S)=0
            0x00, 0x00, // N(R)=0
            0x2D, // type_id = 45 (C_SC_NA_1)
            0x01, // VSQ
            0x06, 0x00, // COT = 6 (activation)
            0x0A, 0x00, // CA = 10
            0x01, 0x00, 0x00, // IOA = 1
            0x01, // SCO
        ]
    }

    // -----------------------------------------------------------------------

    /// I-frame yields apci_type=i_frame, correct N(S)/N(R), type 1 M_SP_NA_1.
    #[test]
    fn i_frame_typed_fields_send_receive_sequence_and_asdu_type() {
        let payload = i_frame_single_point();
        let mut dec = Iec104DecoderWrapper::default();
        let mut out = Vec::new();
        dec.on_stream_chunk(&make_chunk(&payload, ctx_outstation_to_master()), &mut out);

        let txns = txns(&out);
        assert!(!txns.is_empty(), "expected at least one ProtocolTransaction");
        let f = iec104_fields(txns[0]);

        assert_eq!(f.apci_type, "i_frame");
        assert_eq!(f.send_sequence, Some(3));
        assert_eq!(f.receive_sequence, Some(5));
        assert_eq!(f.u_function, None);
        assert_eq!(f.asdu_type_id, Some(1));
        assert_eq!(f.asdu_type_name.as_deref(), Some("single_point_information"));
    }

    /// S-frame yields apci_type=s_frame, N(R) set, send_sequence None.
    #[test]
    fn s_frame_typed_fields_receive_sequence_only() {
        let payload = s_frame();
        let mut dec = Iec104DecoderWrapper::default();
        let mut out = Vec::new();
        dec.on_stream_chunk(&make_chunk(&payload, ctx_outstation_to_master()), &mut out);

        let txns = txns(&out);
        assert!(!txns.is_empty(), "expected at least one ProtocolTransaction");
        let f = iec104_fields(txns[0]);

        assert_eq!(f.apci_type, "s_frame");
        assert_eq!(f.send_sequence, None);
        assert_eq!(f.receive_sequence, Some(5));
        assert_eq!(f.asdu_type_id, None);
    }

    /// U-frame STARTDT_act yields apci_type=u_frame, u_function=startdt_act.
    #[test]
    fn u_frame_startdt_act_typed_fields() {
        let payload = u_frame_startdt_act();
        let mut dec = Iec104DecoderWrapper::default();
        let mut out = Vec::new();
        dec.on_stream_chunk(&make_chunk(&payload, ctx_master_to_outstation()), &mut out);

        let txns = txns(&out);
        assert!(!txns.is_empty(), "expected at least one ProtocolTransaction");
        let f = iec104_fields(txns[0]);

        assert_eq!(f.apci_type, "u_frame");
        assert_eq!(f.u_function.as_deref(), Some("startdt_act"));
        assert_eq!(f.send_sequence, None);
        assert_eq!(f.receive_sequence, None);
    }

    /// U-frame TESTFR_act yields u_function=testfr_act, direction=request.
    #[test]
    fn u_frame_testfr_act_direction_request() {
        let payload = u_frame_testfr_act();
        let mut dec = Iec104DecoderWrapper::default();
        let mut out = Vec::new();
        dec.on_stream_chunk(&make_chunk(&payload, ctx_master_to_outstation()), &mut out);

        let txns = txns(&out);
        assert!(!txns.is_empty(), "expected at least one ProtocolTransaction");
        let f = iec104_fields(txns[0]);

        assert_eq!(f.u_function.as_deref(), Some("testfr_act"));
        assert_eq!(f.direction, "request");
    }

    /// C_SC_NA_1 (type 45) activation command to port 2404 is typed correctly
    /// and direction=request.
    #[test]
    fn c_sc_na_1_control_direction_and_cot_activation() {
        let payload = i_frame_single_command();
        let mut dec = Iec104DecoderWrapper::default();
        let mut out = Vec::new();
        dec.on_stream_chunk(&make_chunk(&payload, ctx_master_to_outstation()), &mut out);

        let txns = txns(&out);
        assert!(!txns.is_empty(), "expected at least one ProtocolTransaction");
        let f = iec104_fields(txns[0]);

        assert_eq!(f.asdu_type_id, Some(45));
        assert_eq!(f.asdu_type_name.as_deref(), Some("single_command"));
        assert_eq!(f.cause_of_transmission, Some(6));
        assert_eq!(f.cause_of_transmission_name.as_deref(), Some("activation"));
        assert_eq!(f.common_address, Some(10));
        assert_eq!(f.direction, "request");
    }

    /// Typed fields are present AND legacy `attributes` map is still populated.
    #[test]
    fn attributes_map_still_populated_alongside_typed_fields() {
        let payload = i_frame_single_point();
        let mut dec = Iec104DecoderWrapper::default();
        let mut out = Vec::new();
        dec.on_stream_chunk(&make_chunk(&payload, ctx_outstation_to_master()), &mut out);

        let txns = txns(&out);
        assert!(!txns.is_empty());
        let tx = txns[0];

        // Typed surface present.
        assert!(tx.protocol_fields.is_some());
        // Legacy surface still present.
        assert!(tx.attributes.contains_key("frame_type"), "frame_type missing from attributes");
        assert!(tx.attributes.contains_key("type_id"), "type_id missing from attributes");
        assert!(tx.attributes.contains_key("type_name"), "type_name missing from attributes");
        assert!(tx.attributes.contains_key("cause"), "cause missing from attributes");
        assert!(tx.attributes.contains_key("common_address"), "common_address missing from attributes");
        assert_eq!(tx.attributes.get("frame_type").map(String::as_str), Some("i"));
        assert_eq!(tx.attributes.get("type_id").map(String::as_str), Some("1"));
    }

    /// M_SP_NA_1 (type 1) resolves to the correct type name in typed fields.
    #[test]
    fn m_sp_na_1_type_name_in_typed_fields() {
        let payload = i_frame_single_point();
        let mut dec = Iec104DecoderWrapper::default();
        let mut out = Vec::new();
        dec.on_stream_chunk(&make_chunk(&payload, ctx_outstation_to_master()), &mut out);

        let txns = txns(&out);
        let f = iec104_fields(txns[0]);
        assert_eq!(f.asdu_type_id, Some(1));
        assert_eq!(f.asdu_type_name.as_deref(), Some("single_point_information"));
        assert_eq!(f.cause_of_transmission, Some(3));
        assert_eq!(f.cause_of_transmission_name.as_deref(), Some("spontaneous"));
    }
}
