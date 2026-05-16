//! DNP3 session decoder.
//!
//! Decodes DNP3 frames on TCP port 20000. Each well-formed frame produces a
//! `ProtocolTransaction` populated on **two typed surfaces**:
//!
//! * `protocol_fields: Some(ProtocolFields::Dnp3(Dnp3BronzeFields { … }))` — the
//!   typed Bronze v2 surface introduced in v1.13. Downstream consumers should
//!   prefer this for new code.
//! * `attributes: BTreeMap<String, String>` — the legacy flat-map surface retained
//!   for backward compatibility through the v1.x line. Both surfaces carry the
//!   same addressing information. The `attributes` field will be removed in v2.0.

use std::collections::BTreeMap;

use crate::bronze::{
    AssetObservation, BronzeEvent, BronzeEventFamily, Dnp3BronzeFields, ProtocolFields,
    ProtocolTransaction, TopologyObservation, TransportProtocol,
};
use crate::dissectors::dnp3::Dnp3Dissector;
use crate::engine::{
    DecoderInterest, SessionDecoder, StreamChunk, artifact_event, build_envelope, new_event,
    parse_anomaly_event,
};
use crate::registry::{Dnp3Fields, PacketContext, ProtocolData, ProtocolDissector};

use crate::bronze::EventEnvelope;

#[derive(Default)]
pub(crate) struct Dnp3DecoderWrapper {
    dissector: Dnp3Dissector,
}

impl SessionDecoder for Dnp3DecoderWrapper {
    fn name(&self) -> &'static str {
        "dnp3"
    }

    fn interest(&self) -> &'static [DecoderInterest] {
        &[DecoderInterest::TcpPort(20000)]
    }

    fn on_stream_chunk(&mut self, chunk: &StreamChunk<'_>, out: &mut Vec<BronzeEvent>) {
        match self.dissector.parse(chunk.payload, &chunk.context) {
            Some(ProtocolData::Dnp3(ref fields)) => {
                let source_address = fields.source_address;
                let destination_address = fields.destination_address;
                let function_code = fields.function_code;
                let application_data = fields.application_data.clone();

                let operation = dnp3_function_name(function_code);
                let envelope = build_envelope(
                    &chunk.context,
                    chunk.interface_id,
                    chunk.frame_index,
                    chunk.timestamp,
                    chunk.segment_hash,
                    TransportProtocol::Tcp,
                    Some("dnp3"),
                    chunk.captured_len,
                    chunk.session_key.clone(),
                );
                let mut attributes = BTreeMap::new();
                attributes.insert("source_address".to_string(), source_address.to_string());
                attributes.insert(
                    "destination_address".to_string(),
                    destination_address.to_string(),
                );

                let protocol_fields = Some(ProtocolFields::Dnp3(dnp3_bronze_fields(fields)));

                out.push(new_event(
                    chunk.capture_id.to_string(),
                    envelope.clone(),
                    BronzeEventFamily::ProtocolTransaction(ProtocolTransaction {
                        operation: operation.to_string(),
                        status: if function_code >= 0x80 {
                            "response".to_string()
                        } else {
                            "request".to_string()
                        },
                        request_summary: Some(format!(
                            "{operation} {source_address}->{destination_address}"
                        )),
                        response_summary: None,
                        object_refs: vec![format!("dnp3_fc:{function_code:#04x}")],
                        values: Vec::new(),
                        attributes,
                        modbus: None,
                        protocol_fields,
                    }),
                ));
                for event in dnp3_role_observations(
                    chunk.capture_id,
                    &envelope,
                    &chunk.context,
                    source_address,
                    destination_address,
                    function_code,
                ) {
                    out.push(event);
                }
                if is_dnp3_artifact(function_code) && !application_data.is_empty() {
                    out.push(artifact_event(
                        chunk.capture_id.to_string(),
                        envelope,
                        "dnp3_application_data",
                        &format!("{}:{function_code:#04x}", chunk.session_key),
                        Some("application/octet-stream"),
                        Some("DNP3 application payload"),
                        &application_data,
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
                    Some("dnp3"),
                    chunk.captured_len,
                    chunk.session_key.clone(),
                ),
                self.name(),
                "medium",
                "failed to parse dnp3 payload",
                chunk.payload,
            )),
        }
    }
}

fn dnp3_function_name(code: u8) -> &'static str {
    match code {
        0x01 => "read",
        0x02 => "write",
        0x03 => "select",
        0x04 => "operate",
        0x05 => "direct_operate",
        0x06 => "direct_operate_no_ack",
        0x81 => "response",
        0x82 => "unsolicited_response",
        _ => "dnp3_message",
    }
}

fn is_dnp3_artifact(code: u8) -> bool {
    matches!(code, 0x02..=0x06)
}

fn dnp3_role_observations(
    capture_id: &str,
    envelope: &EventEnvelope,
    context: &PacketContext,
    source_address: u16,
    destination_address: u16,
    function_code: u8,
) -> Vec<BronzeEvent> {
    let (src_role, dst_role, observation_type) =
        if function_code >= 0x80 || context.src_port == 20000 {
            ("outstation", "master", "dnp3_response")
        } else {
            ("master", "outstation", "dnp3_request")
        };

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
                protocols: vec!["dnp3".to_string()],
                identifiers: BTreeMap::from([
                    ("ip".to_string(), context.src_ip.to_string()),
                    ("dnp3_address".to_string(), source_address.to_string()),
                ]),
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
                protocols: vec!["dnp3".to_string()],
                identifiers: BTreeMap::from([
                    ("ip".to_string(), context.dst_ip.to_string()),
                    ("dnp3_address".to_string(), destination_address.to_string()),
                ]),
            }),
        ),
        new_event(
            capture_id.to_string(),
            envelope.clone(),
            BronzeEventFamily::TopologyObservation(TopologyObservation {
                observation_type: observation_type.to_string(),
                local_id: source_address.to_string(),
                remote_id: Some(destination_address.to_string()),
                description: Some(dnp3_function_name(function_code).to_string()),
                capabilities: Vec::new(),
                metadata: BTreeMap::from([
                    ("src_ip".to_string(), context.src_ip.to_string()),
                    ("dst_ip".to_string(), context.dst_ip.to_string()),
                ]),
            }),
        ),
    ]
}

/// Returns the canonical human-readable name for a DNP3 application function code.
fn dnp3_application_function_name(fc: u8) -> &'static str {
    match fc {
        0x00 => "Confirm",
        0x01 => "Read",
        0x02 => "Write",
        0x03 => "Select",
        0x04 => "Operate",
        0x05 => "DirectOperate",
        0x06 => "DirectOperateNoAck",
        0x07 => "ImmediateFreeze",
        0x08 => "ImmediateFreezeNoAck",
        0x09 => "FreezeAndClear",
        0x0A => "FreezeAndClearNoAck",
        0x0B => "FreezeAtTime",
        0x0C => "FreezeAtTimeNoAck",
        0x0D => "ColdRestart",
        0x0E => "WarmRestart",
        0x0F => "InitializeData",
        0x10 => "InitializeApplication",
        0x11 => "StartApplication",
        0x12 => "StopApplication",
        0x15 => "EnableUnsolicited",
        0x16 => "DisableUnsolicited",
        0x81 => "Response",
        0x82 => "UnsolicitedResponse",
        _ => "Unknown",
    }
}

/// Extracts the unique object group numbers referenced in a DNP3 application
/// data payload. Scans object headers (group, variation, qualifier, …) to
/// collect group byte values. Returns an empty vec for payloads that carry no
/// object headers (Confirm, restart commands, etc.).
fn extract_object_groups(app_data: &[u8]) -> Vec<u8> {
    let mut groups: Vec<u8> = Vec::new();
    let mut i = 0;
    // Each object header is at minimum 3 bytes: group(1) + variation(1) + qualifier(1).
    while i + 2 < app_data.len() {
        let group = app_data[i];
        let qualifier = app_data[i + 2];
        if !groups.contains(&group) {
            groups.push(group);
        }
        // Advance past this object header. The range/count portion depends on the
        // qualifier code; we move forward by a heuristic minimum to avoid stalling
        // on partial data (full object data parsing is out of scope here).
        let range_bytes: usize = match qualifier & 0x70 {
            0x00 | 0x10 => 2, // 1-octet start/stop or count
            0x20 | 0x30 => 4, // 2-octet start/stop or count
            0x40 | 0x50 => 8, // 4-octet start/stop or count
            _ => 0,           // no range (0x60) or variable/special — stop scanning
        };
        if range_bytes == 0 {
            break;
        }
        i += 3 + range_bytes; // header(3) + range
    }
    groups
}

/// Builds a [`Dnp3BronzeFields`] from parsed dissector output.
fn dnp3_bronze_fields(fields: &Dnp3Fields) -> Dnp3BronzeFields {
    let fc = fields.function_code;
    let direction = if fc == 0x82 {
        "unsolicited".to_string()
    } else if fc >= 0x80 {
        "response".to_string()
    } else {
        "request".to_string()
    };

    Dnp3BronzeFields {
        source_addr: fields.source_address,
        destination_addr: fields.destination_address,
        dll_control: fields.dll_control,
        transport_seq: fields.transport_seq,
        transport_fir: fields.transport_fir,
        transport_fin: fields.transport_fin,
        application_function_code: fc,
        application_function_name: dnp3_application_function_name(fc).to_string(),
        application_seq: fields.app_control & 0x0F,
        iin_flags: fields.iin,
        direction,
        object_groups: extract_object_groups(&fields.application_data),
    }
}

inventory::submit!(crate::engine::decoders::DecoderRegistration {
    name: "dnp3",
    factory: || Box::new(Dnp3DecoderWrapper::default()),
});

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use std::net::{IpAddr, Ipv4Addr};

    use crate::bronze::ProtocolFields;
    use crate::engine::StreamChunk;
    use crate::registry::PacketContext;

    fn ctx(src_port: u16, dst_port: u16) -> PacketContext {
        PacketContext {
            src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            dst_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            src_port,
            dst_port,
            src_mac: [0u8; 6],
            dst_mac: [0u8; 6],
            vlan_id: None,
            timestamp: 0,
        }
    }

    fn feed(
        dec: &mut Dnp3DecoderWrapper,
        payload: &[u8],
        src_port: u16,
        dst_port: u16,
        out: &mut Vec<BronzeEvent>,
    ) {
        let chunk = StreamChunk {
            capture_id: "cap",
            segment_hash: "aa",
            interface_id: 0,
            frame_index: 1,
            timestamp: Utc::now(),
            context: ctx(src_port, dst_port),
            ethertype: 0x0800,
            ip_proto: Some(6),
            llc: None,
            transport: TransportProtocol::Tcp,
            payload,
            session_key: "10.0.0.1-10.0.0.2-49152-20000".to_string(),
            captured_len: payload.len() as u64,
        };
        dec.on_stream_chunk(&chunk, out);
    }

    /// Minimal DNP3 Read request frame: DLL + transport + application.
    fn read_request_bytes() -> Vec<u8> {
        vec![
            0x05, 0x64, // start bytes
            0x08, // length
            0xC4, // DLL control (DIR=1, PRM=1, FC=4)
            0x01, 0x00, // destination = 1
            0x03, 0x00, // source = 3
            0xAA, 0xBB, // CRC (not validated)
            0xC0, // transport: FIR=1, FIN=1, seq=0
            0xC2, // app control: FIR=1, FIN=1, CON=0, UNS=0, seq=2
            0x01, // function code = Read (0x01)
            // Object header: group=60 variation=2 qualifier=0x06 (no range, all)
            0x3C, 0x02, 0x06,
        ]
    }

    /// Minimal DNP3 Response frame (fc=0x81) with IIN bytes.
    fn response_bytes(iin1: u8, iin2: u8) -> Vec<u8> {
        vec![
            0x05, 0x64, 0x0A, 0x44, 0x03, 0x00, // destination = 3
            0x01, 0x00, // source = 1
            0xCC, 0xDD, // CRC
            0xC0, // transport: FIR=1, FIN=1, seq=0
            0xC5, // app control: FIR=1, FIN=1, CON=0, UNS=0, seq=5
            0x81, // function code = Response
            iin1, iin2, // IIN bytes
            // Object header: group=30 variation=1 qualifier=0x01 (1-byte start/stop)
            0x1E, 0x01, 0x01, 0x00, 0x00,
        ]
    }

    /// DNP3 Unsolicited Response frame (fc=0x82), IIN device_restart bit set.
    fn unsolicited_response_bytes() -> Vec<u8> {
        vec![
            0x05, 0x64, 0x08, 0x44, 0x03, 0x00, // destination = 3
            0x01, 0x00, // source = 1
            0x00, 0x00, // CRC
            0xC0, // transport
            0xC0, // app control: seq=0
            0x82, // function code = UnsolicitedResponse
            0x80, 0x00, // IIN: device_restart bit (IIN1 bit 7)
        ]
    }

    fn extract_txn(ev: &BronzeEvent) -> &ProtocolTransaction {
        match &ev.family {
            BronzeEventFamily::ProtocolTransaction(tx) => tx,
            other => panic!("expected ProtocolTransaction, got {other:?}"),
        }
    }

    // --------------------------------------------------------------------------
    // Test 1: Read request → ProtocolFields::Dnp3 populated, direction=request
    // --------------------------------------------------------------------------
    #[test]
    fn read_request_produces_dnp3_bronze_fields() {
        let mut dec = Dnp3DecoderWrapper::default();
        let mut out = Vec::new();
        feed(&mut dec, &read_request_bytes(), 49152, 20000, &mut out);

        // First event is the ProtocolTransaction; remaining are AssetObservations + Topology.
        let txn = extract_txn(&out[0]);

        let Some(ProtocolFields::Dnp3(ref f)) = txn.protocol_fields else {
            panic!(
                "expected ProtocolFields::Dnp3, got {:?}",
                txn.protocol_fields
            );
        };

        assert_eq!(f.source_addr, 3);
        assert_eq!(f.destination_addr, 1);
        assert_eq!(f.application_function_code, 0x01);
        assert_eq!(f.application_function_name, "Read");
        assert_eq!(f.direction, "request");
        assert_eq!(f.application_seq, 2); // low nibble of app_control 0xC2
        assert_eq!(f.transport_fir, true);
        assert_eq!(f.transport_fin, true);
        assert_eq!(f.iin_flags, None); // requests have no IIN
    }

    // --------------------------------------------------------------------------
    // Test 2: Response → direction=response, status="response", IIN extracted
    // --------------------------------------------------------------------------
    #[test]
    fn response_produces_dnp3_bronze_fields_with_iin() {
        let mut dec = Dnp3DecoderWrapper::default();
        let mut out = Vec::new();
        // IIN1=0x80 (device_restart), IIN2=0x00
        feed(
            &mut dec,
            &response_bytes(0x80, 0x00),
            20000,
            49152,
            &mut out,
        );

        let txn = extract_txn(&out[0]);

        assert_eq!(txn.status, "response");

        let Some(ProtocolFields::Dnp3(ref f)) = txn.protocol_fields else {
            panic!("expected ProtocolFields::Dnp3");
        };

        assert_eq!(f.application_function_code, 0x81);
        assert_eq!(f.application_function_name, "Response");
        assert_eq!(f.direction, "response");
        // IIN word = IIN1 | (IIN2 << 8) = 0x0080
        assert_eq!(f.iin_flags, Some(0x0080));
        assert_eq!(f.source_addr, 1);
        assert_eq!(f.destination_addr, 3);
        assert_eq!(f.application_seq, 5); // low nibble of 0xC5
    }

    // --------------------------------------------------------------------------
    // Test 3: IIN flags — no flags set → 0x0000
    // --------------------------------------------------------------------------
    #[test]
    fn response_iin_no_flags() {
        let mut dec = Dnp3DecoderWrapper::default();
        let mut out = Vec::new();
        feed(
            &mut dec,
            &response_bytes(0x00, 0x00),
            20000,
            49152,
            &mut out,
        );

        let txn = extract_txn(&out[0]);
        let Some(ProtocolFields::Dnp3(ref f)) = txn.protocol_fields else {
            panic!("expected ProtocolFields::Dnp3");
        };
        assert_eq!(f.iin_flags, Some(0x0000));
    }

    // --------------------------------------------------------------------------
    // Test 4: Unsolicited response → direction=unsolicited
    // --------------------------------------------------------------------------
    #[test]
    fn unsolicited_response_direction() {
        let mut dec = Dnp3DecoderWrapper::default();
        let mut out = Vec::new();
        feed(
            &mut dec,
            &unsolicited_response_bytes(),
            20000,
            49152,
            &mut out,
        );

        let txn = extract_txn(&out[0]);
        let Some(ProtocolFields::Dnp3(ref f)) = txn.protocol_fields else {
            panic!("expected ProtocolFields::Dnp3");
        };
        assert_eq!(f.application_function_code, 0x82);
        assert_eq!(f.application_function_name, "UnsolicitedResponse");
        assert_eq!(f.direction, "unsolicited");
        assert_eq!(f.iin_flags, Some(0x0080)); // IIN1=0x80 device_restart
    }

    // --------------------------------------------------------------------------
    // Test 5: Object groups extracted from Read request payload (group 60)
    // --------------------------------------------------------------------------
    #[test]
    fn read_request_object_groups_extracted() {
        let mut dec = Dnp3DecoderWrapper::default();
        let mut out = Vec::new();
        feed(&mut dec, &read_request_bytes(), 49152, 20000, &mut out);

        let txn = extract_txn(&out[0]);
        let Some(ProtocolFields::Dnp3(ref f)) = txn.protocol_fields else {
            panic!("expected ProtocolFields::Dnp3");
        };
        // Object header has group=0x3C (60 decimal) with qualifier=0x06 (no range)
        // Our scanner stops at qualifier 0x06 (range_class 0x00 → 0 range bytes, break),
        // so we still capture group 60 before the break.
        assert!(
            f.object_groups.contains(&60),
            "expected group 60 in {:?}",
            f.object_groups
        );
    }

    // --------------------------------------------------------------------------
    // Test 6: Response with group 30 in payload
    // --------------------------------------------------------------------------
    #[test]
    fn response_object_groups_extracted() {
        let mut dec = Dnp3DecoderWrapper::default();
        let mut out = Vec::new();
        feed(
            &mut dec,
            &response_bytes(0x00, 0x00),
            20000,
            49152,
            &mut out,
        );

        let txn = extract_txn(&out[0]);
        let Some(ProtocolFields::Dnp3(ref f)) = txn.protocol_fields else {
            panic!("expected ProtocolFields::Dnp3");
        };
        // Object header group=0x1E (30), variation=0x01, qualifier=0x01 (1-byte start/stop)
        assert!(
            f.object_groups.contains(&30),
            "expected group 30 in {:?}",
            f.object_groups
        );
    }

    // --------------------------------------------------------------------------
    // Test 7: Backward-compat — attributes still populated alongside protocol_fields
    // --------------------------------------------------------------------------
    #[test]
    fn attributes_still_populated_alongside_protocol_fields() {
        let mut dec = Dnp3DecoderWrapper::default();
        let mut out = Vec::new();
        feed(&mut dec, &read_request_bytes(), 49152, 20000, &mut out);

        let txn = extract_txn(&out[0]);

        // Typed surface present
        assert!(
            txn.protocol_fields.is_some(),
            "protocol_fields must be Some"
        );
        // Legacy attributes still present
        assert_eq!(txn.attributes.get("source_address"), Some(&"3".to_string()));
        assert_eq!(
            txn.attributes.get("destination_address"),
            Some(&"1".to_string())
        );
    }

    // --------------------------------------------------------------------------
    // Test 8: Dnp3BronzeFields serialises cleanly to JSON (roundtrip)
    // --------------------------------------------------------------------------
    #[test]
    fn dnp3_bronze_fields_json_roundtrip() {
        let original = Dnp3BronzeFields {
            source_addr: 3,
            destination_addr: 1,
            dll_control: 0xC4,
            transport_seq: 0,
            transport_fir: true,
            transport_fin: true,
            application_function_code: 0x01,
            application_function_name: "Read".to_string(),
            application_seq: 2,
            iin_flags: None,
            direction: "request".to_string(),
            object_groups: vec![60],
        };
        let pf = ProtocolFields::Dnp3(original.clone());
        let json = serde_json::to_string(&pf).expect("serialize");
        let back: ProtocolFields = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(pf, back);
        // iin_flags: None should be omitted from JSON
        assert!(
            !json.contains("iin_flags"),
            "iin_flags:None should be skipped in JSON, got: {json}"
        );
    }
}
