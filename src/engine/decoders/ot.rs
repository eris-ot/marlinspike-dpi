//! OT/ICS protocol `SessionDecoder` impls.
//!
//! Members: BACnet, Modbus, DNP3, IEC 60870-5-104, IEC 61850 (MMS/GOOSE/SV),
//! S7comm, PROFINET, EtherNet/IP (CIP + PCCC dispatch), OPC UA, OMRON FINS,
//! HART-IP, EtherCAT. Each is a stateful or near-stateful decoder; protocol-
//! specific helpers (operation/status/object-ref formatters, role inference,
//! PCCC/CIP path extraction) live alongside their decoder.

use std::collections::{BTreeMap, HashMap};
use std::net::{IpAddr, Ipv4Addr};

use chrono::{DateTime, Utc};

use crate::bronze::{
    AssetObservation, BronzeEvent, BronzeEventFamily, EventEnvelope,
    ModbusBronzeFields, ObjectValue, ProtocolTransaction, TopologyObservation,
    TransportProtocol,
};
use crate::dissectors::bacnet::BacnetDissector;
use crate::dissectors::dnp3::Dnp3Dissector;
use crate::dissectors::ethercat::EthercatDissector;
use crate::dissectors::ethernet_ip::EthernetIpDissector;
use crate::dissectors::fins::OmronFinsDissector;
use crate::dissectors::hart_ip::{parse_hart_ip_frames, HartIpBody, HartIpDissector, HartIpFields};
use crate::dissectors::iec104::parse_iec104_frames;
use crate::dissectors::iec61850::{
    Iec61850Dissector, Iec61850Fields, Iec61850Profile, IEC61850_GOOSE_ETHERTYPE,
    IEC61850_MMS_PORT, IEC61850_SV_ETHERTYPE,
};
use crate::dissectors::modbus::ModbusDissector;
use crate::dissectors::opc_ua::OpcUaDissector;
use crate::dissectors::profinet::ProfinetDissector;
use crate::dissectors::s7comm::S7commDissector;
use crate::engine::{
    artifact_event, build_envelope, new_event, parse_anomaly_event,
    DecoderInterest, SessionDecoder, StreamChunk,
};
use crate::registry::{
    format_mac, BacnetFields, Dnp3Fields, EthernetIpFields, Iec104Fields, ModbusFields,
    ModbusPdu, OmronFinsFields, OpcUaFields, PacketContext, ProfinetFields, ProtocolData,
    ProtocolDissector, S7commFields,
};

#[derive(Default)]
pub(crate) struct BacnetDecoder {
    dissector: BacnetDissector,
}

impl SessionDecoder for BacnetDecoder {
    fn name(&self) -> &'static str {
        "bacnet"
    }

    fn interest(&self) -> &'static [DecoderInterest] {
        static INTERESTS: [DecoderInterest; 2] = [
            DecoderInterest::UdpPort(47808),
            DecoderInterest::Llc {
                dsap: 0x82,
                ssap: 0x82,
            },
        ];
        &INTERESTS
    }

    fn on_datagram(&mut self, chunk: &StreamChunk<'_>, out: &mut Vec<BronzeEvent>) {
        match self.dissector.parse(chunk.payload, &chunk.context) {
            Some(ProtocolData::Bacnet(BacnetFields {
                link_variant,
                bvlc_function,
                npdu_control,
                apdu_type,
                service,
                invoke_id,
                device_instance,
                vendor_id,
                payload,
            })) => {
                let transport = if chunk.transport == TransportProtocol::Udp {
                    TransportProtocol::Udp
                } else {
                    TransportProtocol::Ethernet
                };
                let envelope = build_envelope(
                    &chunk.context,
                    chunk.interface_id,
                    chunk.frame_index,
                    chunk.timestamp,
                    chunk.segment_hash,
                    transport,
                    Some("bacnet"),
                    chunk.captured_len,
                    chunk.session_key.clone(),
                );
                let mut attributes = BTreeMap::new();
                attributes.insert("link_variant".to_string(), link_variant.clone());
                attributes.insert("npdu_control".to_string(), format!("{npdu_control:#04x}"));
                attributes.insert("apdu_type".to_string(), apdu_type.clone());
                if let Some(function) = &bvlc_function {
                    attributes.insert("bvlc_function".to_string(), function.clone());
                }
                if let Some(invoke_id) = invoke_id {
                    attributes.insert("invoke_id".to_string(), invoke_id.to_string());
                }
                if let Some(vendor_id) = vendor_id {
                    attributes.insert("vendor_id".to_string(), vendor_id.to_string());
                }
                if let Some(device_instance) = device_instance {
                    attributes.insert("device_instance".to_string(), device_instance.to_string());
                }

                out.push(new_event(
                    chunk.capture_id.to_string(),
                    envelope.clone(),
                    BronzeEventFamily::ProtocolTransaction(ProtocolTransaction {
                        operation: normalize_operation_name(&service, "bacnet_message"),
                        status: bacnet_status(&apdu_type).to_string(),
                        request_summary: Some(format!("{apdu_type} {service}")),
                        response_summary: None,
                        object_refs: bacnet_object_refs(device_instance, invoke_id),
                        values: Vec::new(),
                        attributes,
                                        modbus: None,
                                        protocol_fields: None,
}),
                ));

                if let Some(device_instance) = device_instance {
                    let mut identifiers = BTreeMap::from([
                        ("ip".to_string(), chunk.context.src_ip.to_string()),
                        (
                            "bacnet_device_instance".to_string(),
                            device_instance.to_string(),
                        ),
                    ]);
                    if let Some(vendor_id) = vendor_id {
                        identifiers.insert("bacnet_vendor_id".to_string(), vendor_id.to_string());
                    }
                    out.push(new_event(
                        chunk.capture_id.to_string(),
                        envelope.clone(),
                        BronzeEventFamily::AssetObservation(AssetObservation {
                            asset_key: chunk.context.src_ip.to_string(),
                            role: Some("device".to_string()),
                            vendor: None,
                            model: None,
                            firmware: None,
                            hostnames: Vec::new(),
                            protocols: vec!["bacnet".to_string()],
                            identifiers,
                        }),
                    ));
                }

                out.push(new_event(
                    chunk.capture_id.to_string(),
                    envelope.clone(),
                    BronzeEventFamily::TopologyObservation(TopologyObservation {
                        observation_type: "bacnet_transaction".to_string(),
                        local_id: chunk.context.src_ip.to_string(),
                        remote_id: Some(chunk.context.dst_ip.to_string()),
                        description: Some(service.clone()),
                        capabilities: Vec::new(),
                        metadata: BTreeMap::from([
                            ("link_variant".to_string(), link_variant),
                            ("apdu_type".to_string(), apdu_type.clone()),
                        ]),
                    }),
                ));

                if !payload.is_empty() {
                    out.push(artifact_event(
                        chunk.capture_id.to_string(),
                        envelope,
                        "bacnet_apdu",
                        &format!("{}:{}", service, chunk.frame_index),
                        Some("application/octet-stream"),
                        Some("BACnet APDU payload"),
                        &payload,
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
                    chunk.transport,
                    Some("bacnet"),
                    chunk.captured_len,
                    chunk.session_key.clone(),
                ),
                self.name(),
                "medium",
                "failed to parse bacnet payload",
                chunk.payload,
            )),
        }
    }
}

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
            Some(ProtocolData::Dnp3(Dnp3Fields {
                source_address,
                destination_address,
                function_code,
                application_data,
            })) => {
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
                                        protocol_fields: None,
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

            out.push(new_event(
                chunk.capture_id.to_string(),
                envelope.clone(),
                BronzeEventFamily::ProtocolTransaction(ProtocolTransaction {
                    operation,
                    status: iec104_status(
                        &frame_type,
                        u_format.as_deref(),
                        cause_of_transmission,
                        &chunk.context,
                    )
                    .to_string(),
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
                                        protocol_fields: None,
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

#[derive(Default)]
pub(crate) struct OmronFinsDecoder {
    dissector: OmronFinsDissector,
}

impl SessionDecoder for OmronFinsDecoder {
    fn name(&self) -> &'static str {
        "omron_fins"
    }

    fn interest(&self) -> &'static [DecoderInterest] {
        static INTERESTS: [DecoderInterest; 2] = [
            DecoderInterest::UdpPort(9600),
            DecoderInterest::TcpPort(9600),
        ];
        &INTERESTS
    }

    fn on_datagram(&mut self, chunk: &StreamChunk<'_>, out: &mut Vec<BronzeEvent>) {
        self.handle(chunk, TransportProtocol::Udp, out);
    }

    fn on_stream_chunk(&mut self, chunk: &StreamChunk<'_>, out: &mut Vec<BronzeEvent>) {
        self.handle(chunk, TransportProtocol::Tcp, out);
    }
}

impl OmronFinsDecoder {
    fn handle(
        &mut self,
        chunk: &StreamChunk<'_>,
        transport: TransportProtocol,
        out: &mut Vec<BronzeEvent>,
    ) {
        if !self.dissector.can_parse(
            chunk.payload,
            chunk.context.src_port,
            chunk.context.dst_port,
        ) {
            return;
        }

        match self.dissector.parse(chunk.payload, &chunk.context) {
            Some(ProtocolData::OmronFins(fields)) => {
                self.emit_fields(chunk, transport, fields, out)
            }
            _ => out.push(parse_anomaly_event(
                chunk.capture_id.to_string(),
                build_envelope(
                    &chunk.context,
                    chunk.interface_id,
                    chunk.frame_index,
                    chunk.timestamp,
                    chunk.segment_hash,
                    transport,
                    Some("omron_fins"),
                    chunk.captured_len,
                    chunk.session_key.clone(),
                ),
                self.name(),
                "medium",
                "failed to parse omron fins payload",
                chunk.payload,
            )),
        }
    }

    fn emit_fields(
        &self,
        chunk: &StreamChunk<'_>,
        transport: TransportProtocol,
        fields: OmronFinsFields,
        out: &mut Vec<BronzeEvent>,
    ) {
        let OmronFinsFields {
            frame_variant,
            tcp_command,
            tcp_error_code,
            icf,
            rsv,
            gateway_count,
            destination_network,
            destination_node,
            destination_unit,
            source_network,
            source_node,
            source_unit,
            service_id,
            command_code,
            command_name,
            memory_area,
            memory_word,
            memory_bit,
            item_count,
            payload,
        } = fields;

        let envelope = build_envelope(
            &chunk.context,
            chunk.interface_id,
            chunk.frame_index,
            chunk.timestamp,
            chunk.segment_hash,
            transport,
            Some("omron_fins"),
            chunk.captured_len,
            chunk.session_key.clone(),
        );

        let mut attributes = BTreeMap::new();
        attributes.insert("frame_variant".to_string(), frame_variant.clone());
        if let Some(tcp_command) = tcp_command {
            attributes.insert("tcp_command".to_string(), format!("{tcp_command:#010x}"));
        }
        if let Some(tcp_error_code) = tcp_error_code {
            attributes.insert(
                "tcp_error_code".to_string(),
                format!("{tcp_error_code:#010x}"),
            );
        }
        if let Some(icf) = icf {
            attributes.insert("icf".to_string(), format!("{icf:#04x}"));
        }
        if let Some(rsv) = rsv {
            attributes.insert("rsv".to_string(), format!("{rsv:#04x}"));
        }
        if let Some(gateway_count) = gateway_count {
            attributes.insert("gateway_count".to_string(), gateway_count.to_string());
        }
        if let Some(service_id) = service_id {
            attributes.insert("service_id".to_string(), format!("{service_id:#04x}"));
        }
        if let Some(command_code) = command_code {
            attributes.insert("command_code".to_string(), format!("{command_code:#06x}"));
        }
        if let Some(command_name) = &command_name {
            attributes.insert("command_name".to_string(), command_name.clone());
        }
        if let Some(memory_area) = memory_area {
            attributes.insert("memory_area".to_string(), format!("{memory_area:#04x}"));
        }
        if let Some(memory_word) = memory_word {
            attributes.insert("memory_word".to_string(), memory_word.to_string());
        }
        if let Some(memory_bit) = memory_bit {
            attributes.insert("memory_bit".to_string(), memory_bit.to_string());
        }
        if let Some(item_count) = item_count {
            attributes.insert("item_count".to_string(), item_count.to_string());
        }
        if let Some(destination_network) = destination_network {
            attributes.insert(
                "destination_network".to_string(),
                destination_network.to_string(),
            );
        }
        if let Some(destination_node) = destination_node {
            attributes.insert("destination_node".to_string(), destination_node.to_string());
        }
        if let Some(destination_unit) = destination_unit {
            attributes.insert("destination_unit".to_string(), destination_unit.to_string());
        }
        if let Some(source_network) = source_network {
            attributes.insert("source_network".to_string(), source_network.to_string());
        }
        if let Some(source_node) = source_node {
            attributes.insert("source_node".to_string(), source_node.to_string());
        }
        if let Some(source_unit) = source_unit {
            attributes.insert("source_unit".to_string(), source_unit.to_string());
        }

        let operation = omron_fins_operation_name(command_name.as_deref(), command_code);
        out.push(new_event(
            chunk.capture_id.to_string(),
            envelope.clone(),
            BronzeEventFamily::ProtocolTransaction(ProtocolTransaction {
                operation,
                status: omron_fins_status(&chunk.context).to_string(),
                request_summary: Some(omron_fins_summary(
                    command_name.as_deref(),
                    source_node,
                    destination_node,
                )),
                response_summary: None,
                object_refs: omron_fins_object_refs(
                    memory_area,
                    memory_word,
                    memory_bit,
                    item_count,
                ),
                values: Vec::new(),
                attributes,
                        modbus: None,
                                        protocol_fields: None,
}),
        ));

        if source_node.is_some() || source_network.is_some() || source_unit.is_some() {
            let mut identifiers = BTreeMap::new();
            identifiers.insert("ip".to_string(), chunk.context.src_ip.to_string());
            if let Some(network) = source_network {
                identifiers.insert("fins_network".to_string(), network.to_string());
            }
            if let Some(node) = source_node {
                identifiers.insert("fins_node".to_string(), node.to_string());
            }
            if let Some(unit) = source_unit {
                identifiers.insert("fins_unit".to_string(), unit.to_string());
            }
            out.push(new_event(
                chunk.capture_id.to_string(),
                envelope.clone(),
                BronzeEventFamily::AssetObservation(AssetObservation {
                    asset_key: chunk.context.src_ip.to_string(),
                    role: omron_fins_source_role(&chunk.context).map(str::to_string),
                    vendor: Some("OMRON".to_string()),
                    model: None,
                    firmware: None,
                    hostnames: Vec::new(),
                    protocols: vec!["omron_fins".to_string()],
                    identifiers,
                }),
            ));
        }

        if destination_node.is_some() || destination_network.is_some() || destination_unit.is_some()
        {
            let mut identifiers = BTreeMap::new();
            identifiers.insert("ip".to_string(), chunk.context.dst_ip.to_string());
            if let Some(network) = destination_network {
                identifiers.insert("fins_network".to_string(), network.to_string());
            }
            if let Some(node) = destination_node {
                identifiers.insert("fins_node".to_string(), node.to_string());
            }
            if let Some(unit) = destination_unit {
                identifiers.insert("fins_unit".to_string(), unit.to_string());
            }
            out.push(new_event(
                chunk.capture_id.to_string(),
                envelope.clone(),
                BronzeEventFamily::AssetObservation(AssetObservation {
                    asset_key: chunk.context.dst_ip.to_string(),
                    role: omron_fins_destination_role(&chunk.context).map(str::to_string),
                    vendor: Some("OMRON".to_string()),
                    model: None,
                    firmware: None,
                    hostnames: Vec::new(),
                    protocols: vec!["omron_fins".to_string()],
                    identifiers,
                }),
            ));
        }

        out.push(new_event(
            chunk.capture_id.to_string(),
            envelope.clone(),
            BronzeEventFamily::TopologyObservation(TopologyObservation {
                observation_type: "omron_fins_transaction".to_string(),
                local_id: chunk.context.src_ip.to_string(),
                remote_id: Some(chunk.context.dst_ip.to_string()),
                description: command_name.clone(),
                capabilities: Vec::new(),
                metadata: BTreeMap::from([("frame_variant".to_string(), frame_variant)]),
            }),
        ));

        if !payload.is_empty() {
            out.push(artifact_event(
                chunk.capture_id.to_string(),
                envelope,
                "omron_fins_payload",
                &format!("{}:{}", chunk.session_key, chunk.frame_index),
                Some("application/octet-stream"),
                Some("OMRON FINS command payload"),
                &payload,
            ));
        }
    }
}

#[derive(Default)]
pub(crate) struct HartIpDecoderWrapper {
    dissector: HartIpDissector,
}

impl SessionDecoder for HartIpDecoderWrapper {
    fn name(&self) -> &'static str {
        "hart_ip"
    }

    fn interest(&self) -> &'static [DecoderInterest] {
        static INTERESTS: [DecoderInterest; 2] = [
            DecoderInterest::TcpPort(5094),
            DecoderInterest::UdpPort(5094),
        ];
        &INTERESTS
    }

    fn on_datagram(&mut self, chunk: &StreamChunk<'_>, out: &mut Vec<BronzeEvent>) {
        if !self.dissector.can_parse(
            chunk.payload,
            chunk.context.src_port,
            chunk.context.dst_port,
        ) {
            return;
        }

        match self.dissector.parse(chunk.payload, &chunk.context) {
            Some(ProtocolData::HartIp(fields)) => {
                self.emit_frame(chunk, TransportProtocol::Udp, fields, out)
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
                    Some("hart_ip"),
                    chunk.captured_len,
                    chunk.session_key.clone(),
                ),
                self.name(),
                "medium",
                "failed to parse hart ip payload",
                chunk.payload,
            )),
        }
    }

    fn on_stream_chunk(&mut self, chunk: &StreamChunk<'_>, out: &mut Vec<BronzeEvent>) {
        if !self.dissector.can_parse(
            chunk.payload,
            chunk.context.src_port,
            chunk.context.dst_port,
        ) {
            return;
        }

        let frames = parse_hart_ip_frames(chunk.payload);
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
                    Some("hart_ip"),
                    chunk.captured_len,
                    chunk.session_key.clone(),
                ),
                self.name(),
                "medium",
                "failed to parse hart ip payload",
                chunk.payload,
            ));
            return;
        }

        for fields in frames {
            self.emit_frame(chunk, TransportProtocol::Tcp, fields, out);
        }
    }
}

impl HartIpDecoderWrapper {
    fn emit_frame(
        &self,
        chunk: &StreamChunk<'_>,
        transport: TransportProtocol,
        fields: HartIpFields,
        out: &mut Vec<BronzeEvent>,
    ) {
        let envelope = build_envelope(
            &chunk.context,
            chunk.interface_id,
            chunk.frame_index,
            chunk.timestamp,
            chunk.segment_hash,
            transport,
            Some("hart_ip"),
            chunk.captured_len,
            chunk.session_key.clone(),
        );

        let mut attributes = BTreeMap::new();
        attributes.insert("version".to_string(), fields.version.to_string());
        attributes.insert("message_type".to_string(), fields.message_type.clone());
        attributes.insert("message_id".to_string(), fields.message_id.clone());
        attributes.insert("status".to_string(), format!("{:#04x}", fields.status));
        attributes.insert(
            "transaction_id".to_string(),
            fields.transaction_id.to_string(),
        );
        attributes.insert(
            "message_length".to_string(),
            fields.message_length.to_string(),
        );

        let mut object_refs = Vec::new();
        let mut device_identity = None;
        let mut device_tag = None;
        let body_summary = match &fields.body {
            HartIpBody::SessionInitiate {
                master_type,
                inactivity_close_timer,
            } => {
                attributes.insert("master_type".to_string(), master_type.clone());
                attributes.insert(
                    "inactivity_close_timer".to_string(),
                    inactivity_close_timer.to_string(),
                );
                Some(format!("session_initiate {master_type}"))
            }
            HartIpBody::SessionClose => Some("session_close".to_string()),
            HartIpBody::KeepAlive => Some("keep_alive".to_string()),
            HartIpBody::Error { error_code, .. } => {
                if let Some(error_code) = error_code {
                    attributes.insert("error_code".to_string(), format!("{error_code:#04x}"));
                }
                Some("error".to_string())
            }
            HartIpBody::PassThrough(pass) => {
                attributes.insert("frame_type".to_string(), pass.frame_type.clone());
                attributes.insert(
                    "physical_layer_type".to_string(),
                    pass.physical_layer_type.clone(),
                );
                attributes.insert("address_type".to_string(), pass.address_type.clone());
                attributes.insert("command".to_string(), pass.command.to_string());
                attributes.insert("payload_length".to_string(), pass.payload.len().to_string());
                object_refs.push(format!("hart_command:{}", pass.command));
                if let Some(identity) = &pass.identity {
                    if let Some(manufacturer_id) = identity.manufacturer_id {
                        object_refs.push(format!("hart_manufacturer:{manufacturer_id}"));
                    }
                    if let Some(device_type) = identity.device_type {
                        object_refs.push(format!("hart_device_type:{device_type}"));
                    }
                    device_tag = identity.tag.clone();
                    device_identity = Some(identity.clone());
                }
                Some(format!(
                    "{} {}",
                    pass.frame_type,
                    hart_passthrough_command_name(pass.command)
                ))
            }
            HartIpBody::Raw(body) => Some(format!("raw {} bytes", body.len())),
        };

        out.push(new_event(
            chunk.capture_id.to_string(),
            envelope.clone(),
            BronzeEventFamily::ProtocolTransaction(ProtocolTransaction {
                operation: hart_ip_operation_name(&fields),
                status: hart_ip_status(&fields).to_string(),
                request_summary: body_summary,
                response_summary: None,
                object_refs,
                values: Vec::new(),
                attributes,
                        modbus: None,
                                        protocol_fields: None,
}),
        ));

        if let Some(identity) = device_identity {
            let mut identifiers = BTreeMap::new();
            identifiers.insert(
                "ip".to_string(),
                hart_ip_device_asset_key(&chunk.context, &fields).to_string(),
            );
            if let Some(manufacturer_id) = identity.manufacturer_id {
                identifiers.insert(
                    "hart_manufacturer_id".to_string(),
                    manufacturer_id.to_string(),
                );
            }
            if let Some(device_type) = identity.device_type {
                identifiers.insert("hart_device_type".to_string(), device_type.to_string());
            }
            if let Some(tag) = &identity.tag {
                identifiers.insert("hart_tag".to_string(), tag.clone());
            }
            if let Some(revision) = identity.hart_universal_revision {
                identifiers.insert("hart_universal_revision".to_string(), revision.to_string());
            }
            if let Some(revision) = identity.device_revision {
                identifiers.insert("hart_device_revision".to_string(), revision.to_string());
            }
            if let Some(revision) = identity.software_revision {
                identifiers.insert("hart_software_revision".to_string(), revision.to_string());
            }
            if let Some(revision) = identity.hardware_revision {
                identifiers.insert("hart_hardware_revision".to_string(), revision.to_string());
            }
            if let Some(counter) = identity.configuration_change_counter {
                identifiers.insert(
                    "hart_configuration_change_counter".to_string(),
                    counter.to_string(),
                );
            }
            if let Some(status) = identity.extended_device_status {
                identifiers.insert(
                    "hart_extended_device_status".to_string(),
                    status.to_string(),
                );
            }
            if let Some(device_id) = identity.device_id {
                identifiers.insert("hart_device_id".to_string(), hex::encode(device_id));
            }
            out.push(new_event(
                chunk.capture_id.to_string(),
                envelope.clone(),
                BronzeEventFamily::AssetObservation(AssetObservation {
                    asset_key: hart_ip_device_asset_key(&chunk.context, &fields),
                    role: Some("field_device".to_string()),
                    vendor: None,
                    model: identity
                        .device_type
                        .map(|device_type| format!("device_type_{device_type}")),
                    firmware: identity
                        .software_revision
                        .map(|revision| revision.to_string()),
                    hostnames: device_tag.into_iter().collect(),
                    protocols: vec!["hart_ip".to_string()],
                    identifiers,
                }),
            ));
        }

        if matches!(fields.body, HartIpBody::SessionInitiate { .. }) {
            out.push(new_event(
                chunk.capture_id.to_string(),
                envelope.clone(),
                BronzeEventFamily::AssetObservation(AssetObservation {
                    asset_key: context_asset_key(&chunk.context),
                    role: Some("host".to_string()),
                    vendor: None,
                    model: None,
                    firmware: None,
                    hostnames: Vec::new(),
                    protocols: vec!["hart_ip".to_string()],
                    identifiers: BTreeMap::from([(
                        "ip".to_string(),
                        chunk.context.src_ip.to_string(),
                    )]),
                }),
            ));
        }

        out.push(new_event(
            chunk.capture_id.to_string(),
            envelope.clone(),
            BronzeEventFamily::TopologyObservation(TopologyObservation {
                observation_type: "hart_ip_transaction".to_string(),
                local_id: context_asset_key(&chunk.context),
                remote_id: Some(context_remote_asset_key(&chunk.context)),
                description: Some(fields.message_id.clone()),
                capabilities: Vec::new(),
                metadata: BTreeMap::from([(
                    "message_type".to_string(),
                    fields.message_type.clone(),
                )]),
            }),
        ));

        if !fields.payload.is_empty() {
            out.push(artifact_event(
                chunk.capture_id.to_string(),
                envelope,
                "hart_ip_payload",
                &format!("{}:{}", chunk.session_key, fields.transaction_id),
                Some("application/octet-stream"),
                Some("HART-IP message payload"),
                &fields.payload,
            ));
        }
    }
}

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

#[derive(Default)]
pub(crate) struct EthercatDecoderWrapper {
    dissector: EthercatDissector,
}

impl SessionDecoder for EthercatDecoderWrapper {
    fn name(&self) -> &'static str {
        "ethercat"
    }

    fn interest(&self) -> &'static [DecoderInterest] {
        &[DecoderInterest::EtherType(0x88A4)]
    }

    fn on_datagram(&mut self, chunk: &StreamChunk<'_>, out: &mut Vec<BronzeEvent>) {
        if !self.dissector.can_parse(
            chunk.payload,
            chunk.context.src_port,
            chunk.context.dst_port,
        ) {
            return;
        }

        match self.dissector.parse(chunk.payload, &chunk.context) {
            Some(ProtocolData::Ethercat(fields)) => {
                let envelope = build_envelope(
                    &chunk.context,
                    chunk.interface_id,
                    chunk.frame_index,
                    chunk.timestamp,
                    chunk.segment_hash,
                    TransportProtocol::Ethernet,
                    Some("ethercat"),
                    chunk.captured_len,
                    chunk.session_key.clone(),
                );

                let mut attributes = BTreeMap::new();
                attributes.insert(
                    "datagram_count".to_string(),
                    fields.datagrams.len().to_string(),
                );
                if let Some(first) = fields.datagrams.first() {
                    attributes.insert("first_command".to_string(), first.command.clone());
                    attributes.insert("first_adp".to_string(), first.adp.to_string());
                    attributes.insert("first_ado".to_string(), format!("{:#06x}", first.ado));
                }

                out.push(new_event(
                    chunk.capture_id.to_string(),
                    envelope.clone(),
                    BronzeEventFamily::ProtocolTransaction(ProtocolTransaction {
                        operation: ethercat_operation_name(&fields),
                        status: "observed".to_string(),
                        request_summary: Some(format!("{} datagrams", fields.datagrams.len())),
                        response_summary: None,
                        object_refs: ethercat_object_refs(&fields),
                        values: Vec::new(),
                        attributes,
                                        modbus: None,
                                        protocol_fields: None,
}),
                ));

                out.push(new_event(
                    chunk.capture_id.to_string(),
                    envelope.clone(),
                    BronzeEventFamily::AssetObservation(AssetObservation {
                        asset_key: format_mac(&chunk.context.src_mac),
                        role: Some("master".to_string()),
                        vendor: None,
                        model: None,
                        firmware: None,
                        hostnames: Vec::new(),
                        protocols: vec!["ethercat".to_string()],
                        identifiers: BTreeMap::from([(
                            "mac".to_string(),
                            format_mac(&chunk.context.src_mac),
                        )]),
                    }),
                ));

                for datagram in &fields.datagrams {
                    if let Some(asset_key) =
                        ethercat_slave_asset_key(datagram.adp, datagram.identity.alias_address)
                    {
                        let mut identifiers = BTreeMap::new();
                        identifiers.insert("ethercat_adp".to_string(), datagram.adp.to_string());
                        identifiers
                            .insert("ethercat_ado".to_string(), format!("{:#06x}", datagram.ado));
                        if let Some(alias_address) = datagram.identity.alias_address {
                            identifiers.insert(
                                "ethercat_alias_address".to_string(),
                                alias_address.to_string(),
                            );
                        }
                        if let Some(vendor_id) = datagram.identity.vendor_id {
                            identifiers
                                .insert("ethercat_vendor_id".to_string(), vendor_id.to_string());
                        }
                        if let Some(product_code) = datagram.identity.product_code {
                            identifiers.insert(
                                "ethercat_product_code".to_string(),
                                product_code.to_string(),
                            );
                        }
                        if let Some(revision) = datagram.identity.revision {
                            identifiers
                                .insert("ethercat_revision".to_string(), revision.to_string());
                        }
                        if let Some(serial_number) = datagram.identity.serial_number {
                            identifiers.insert(
                                "ethercat_serial_number".to_string(),
                                serial_number.to_string(),
                            );
                        }
                        out.push(new_event(
                            chunk.capture_id.to_string(),
                            envelope.clone(),
                            BronzeEventFamily::AssetObservation(AssetObservation {
                                asset_key: asset_key.clone(),
                                role: Some("slave".to_string()),
                                vendor: datagram
                                    .identity
                                    .vendor_id
                                    .map(|vendor_id| format!("vendor_{vendor_id}")),
                                model: datagram
                                    .identity
                                    .product_code
                                    .map(|product_code| format!("product_{product_code}")),
                                firmware: datagram
                                    .identity
                                    .revision
                                    .map(|revision| revision.to_string()),
                                hostnames: Vec::new(),
                                protocols: vec!["ethercat".to_string()],
                                identifiers,
                            }),
                        ));
                        out.push(new_event(
                            chunk.capture_id.to_string(),
                            envelope.clone(),
                            BronzeEventFamily::TopologyObservation(TopologyObservation {
                                observation_type: "ethercat_master_slave".to_string(),
                                local_id: format_mac(&chunk.context.src_mac),
                                remote_id: Some(asset_key),
                                description: Some(datagram.command.clone()),
                                capabilities: Vec::new(),
                                metadata: BTreeMap::from([(
                                    "address_mode".to_string(),
                                    datagram.address_mode.clone(),
                                )]),
                            }),
                        ));
                    }
                }

                let mut artifact_payload = Vec::new();
                for datagram in &fields.datagrams {
                    artifact_payload.extend_from_slice(&datagram.payload);
                }
                if !artifact_payload.is_empty() {
                    out.push(artifact_event(
                        chunk.capture_id.to_string(),
                        envelope,
                        "ethercat_payload",
                        &format!("{}:{}", chunk.session_key, chunk.frame_index),
                        Some("application/octet-stream"),
                        Some("EtherCAT datagram payload"),
                        &artifact_payload,
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
                    TransportProtocol::Ethernet,
                    Some("ethercat"),
                    chunk.captured_len,
                    chunk.session_key.clone(),
                ),
                self.name(),
                "medium",
                "failed to parse ethercat payload",
                chunk.payload,
            )),
        }
    }
}

#[derive(Default)]
pub(crate) struct EthernetIpDecoderWrapper {
    dissector: EthernetIpDissector,
    pccc_decoder: crate::pccc::PcccDecoder,
}

impl SessionDecoder for EthernetIpDecoderWrapper {
    fn name(&self) -> &'static str {
        "ethernet_ip"
    }

    fn interest(&self) -> &'static [DecoderInterest] {
        &[DecoderInterest::TcpPort(44818)]
    }

    fn on_stream_chunk(&mut self, chunk: &StreamChunk<'_>, out: &mut Vec<BronzeEvent>) {
        match self.dissector.parse(chunk.payload, &chunk.context) {
            Some(ProtocolData::EthernetIp(EthernetIpFields {
                command,
                session_handle,
                cip_data,
            })) => {
                let command_name = ethernet_ip_command_name(command);
                let mut attributes = BTreeMap::new();
                attributes.insert("session_handle".to_string(), session_handle.to_string());
                attributes.insert(
                    "encapsulation_command".to_string(),
                    format!("{command:#06x}"),
                );
                if let Some(service) = cip_service_name(&cip_data) {
                    attributes.insert("cip_service".to_string(), service.to_string());
                }
                if let Some(identity) = parse_cip_identity_claim(command, &cip_data) {
                    attributes.insert("cip_vendor_id".to_string(), identity.vendor_id.to_string());
                    attributes.insert(
                        "cip_product_code".to_string(),
                        identity.product_code.to_string(),
                    );
                    attributes.insert(
                        "cip_serial_number".to_string(),
                        identity.serial_number.to_string(),
                    );
                    attributes.insert("cip_revision".to_string(), identity.revision.clone());
                }
                let envelope = build_envelope(
                    &chunk.context,
                    chunk.interface_id,
                    chunk.frame_index,
                    chunk.timestamp,
                    chunk.segment_hash,
                    TransportProtocol::Tcp,
                    Some("ethernet_ip"),
                    chunk.captured_len,
                    chunk.session_key.clone(),
                );
                out.push(new_event(
                    chunk.capture_id.to_string(),
                    envelope.clone(),
                    BronzeEventFamily::ProtocolTransaction(ProtocolTransaction {
                        operation: command_name.to_string(),
                        status: if chunk.context.dst_port == 44818 {
                            "request".to_string()
                        } else {
                            "response".to_string()
                        },
                        request_summary: Some(format!("{command_name} session={session_handle}")),
                        response_summary: None,
                        object_refs: cip_object_refs(&cip_data),
                        values: Vec::new(),
                        attributes,
                                        modbus: None,
                                        protocol_fields: None,
}),
                ));
                for identity in parse_cip_identity_claims(command, &cip_data) {
                    let asset_key = identity
                        .ip_address
                        .clone()
                        .unwrap_or_else(|| chunk.context.src_ip.to_string());
                    let mut identifiers = BTreeMap::from([
                        ("ip".to_string(), asset_key.clone()),
                        ("cip_vendor_id".to_string(), identity.vendor_id.to_string()),
                        (
                            "cip_device_type".to_string(),
                            identity.device_type.to_string(),
                        ),
                        (
                            "cip_product_code".to_string(),
                            identity.product_code.to_string(),
                        ),
                        (
                            "cip_serial_number".to_string(),
                            identity.serial_number.to_string(),
                        ),
                    ]);
                    identifiers.insert("cip_revision".to_string(), identity.revision.clone());
                    identifiers.insert("cip_status".to_string(), identity.status.to_string());
                    if let Some(state) = identity.state {
                        identifiers.insert("cip_state".to_string(), state.to_string());
                    }
                    out.push(new_event(
                        chunk.capture_id.to_string(),
                        envelope.clone(),
                        BronzeEventFamily::AssetObservation(AssetObservation {
                            asset_key,
                            role: cip_role_from_device_type(identity.device_type)
                                .map(str::to_string),
                            vendor: cip_vendor_name(identity.vendor_id).map(str::to_string),
                            model: Some(identity.product_name.clone()),
                            firmware: Some(identity.revision.clone()),
                            hostnames: Vec::new(),
                            protocols: vec!["ethernet_ip".to_string(), "cip".to_string()],
                            identifiers,
                        }),
                    ));
                }
                if matches!(command, 0x006F | 0x0070) && !cip_data.is_empty() {
                    // PCCC dispatch: if the CIP service is Execute PCCC
                    // (request 0x4B / response 0xCB), pull the embedded PCCC
                    // PDU and let the PcccDecoder produce ProcessReadings.
                    if let Some(message) = cip_explicit_message(&cip_data) {
                        if let Some((is_request, pccc_pdu)) =
                            extract_pccc_pdu(message)
                        {
                            let mut events = self.pccc_decoder.handle_pdu(
                                pccc_pdu,
                                is_request,
                                chunk.context.src_ip,
                                &envelope,
                                chunk.capture_id,
                            );
                            out.append(&mut events);
                        }
                    }
                    out.push(artifact_event(
                        chunk.capture_id.to_string(),
                        envelope,
                        "cip_payload",
                        &format!("{session_handle}:{}", chunk.frame_index),
                        Some("application/octet-stream"),
                        Some("EtherNet/IP CIP payload"),
                        &cip_data,
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
                    Some("ethernet_ip"),
                    chunk.captured_len,
                    chunk.session_key.clone(),
                ),
                self.name(),
                "medium",
                "failed to parse ethernet/ip payload",
                chunk.payload,
            )),
        }
    }
}

pub(crate) struct OpcUaDecoderWrapper {
    dissector: OpcUaDissector,
    service_decoder: crate::opc_ua::OpcUaServiceDecoder,
    event_id_counter: u64,
}

impl Default for OpcUaDecoderWrapper {
    fn default() -> Self {
        Self {
            dissector: OpcUaDissector,
            service_decoder: crate::opc_ua::OpcUaServiceDecoder::new(),
            event_id_counter: 0,
        }
    }
}

impl SessionDecoder for OpcUaDecoderWrapper {
    fn name(&self) -> &'static str {
        "opc_ua"
    }

    fn interest(&self) -> &'static [DecoderInterest] {
        &[
            DecoderInterest::TcpPort(4840),
            DecoderInterest::TcpPort(12001),
        ]
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
            Some(ProtocolData::OpcUa(OpcUaFields {
                message_type,
                request_id,
                service_type,
            })) => {
                let mut attributes = BTreeMap::new();
                attributes.insert("message_type".to_string(), message_type.clone());
                attributes.insert("service_type".to_string(), service_type.clone());
                if request_id != 0 {
                    attributes.insert("request_id".to_string(), request_id.to_string());
                }

                let envelope = build_envelope(
                    &chunk.context,
                    chunk.interface_id,
                    chunk.frame_index,
                    chunk.timestamp,
                    chunk.segment_hash,
                    TransportProtocol::Tcp,
                    Some("opc_ua"),
                    chunk.captured_len,
                    chunk.session_key.clone(),
                );

                out.push(new_event(
                    chunk.capture_id.to_string(),
                    envelope.clone(),
                    BronzeEventFamily::ProtocolTransaction(ProtocolTransaction {
                        operation: opc_ua_operation_name(&service_type),
                        status: if service_type.starts_with("Error") {
                            "error".to_string()
                        } else if matches!(chunk.context.dst_port, 4840 | 12001) {
                            "request".to_string()
                        } else {
                            "response".to_string()
                        },
                        request_summary: Some(format!("{message_type} {service_type}")),
                        response_summary: None,
                        object_refs: if request_id == 0 {
                            vec![format!("opcua_message:{message_type}")]
                        } else {
                            vec![format!("opcua_request:{request_id}")]
                        },
                        values: Vec::new(),
                        attributes,
                                        modbus: None,
                                        protocol_fields: None,
}),
                ));

                // For MSG chunks with the full 24-byte secure header, hand
                // the body to the OPC UA service decoder. Read* services
                // produce ProcessReading events; others are ignored.
                if message_type == "MSG" && chunk.payload.len() >= 24 {
                    let secure_channel_id = u32::from_le_bytes([
                        chunk.payload[8],
                        chunk.payload[9],
                        chunk.payload[10],
                        chunk.payload[11],
                    ]);
                    let body = &chunk.payload[24..];
                    let now_us = chunk.context.timestamp / 1_000;
                    let counter = &mut self.event_id_counter;
                    let mut next_id = || {
                        *counter = counter.wrapping_add(1);
                        format!("opcua-{}", *counter)
                    };
                    let mut events = self.service_decoder.handle_msg_body(
                        body,
                        secure_channel_id,
                        request_id,
                        &envelope,
                        now_us,
                        &mut next_id,
                        chunk.capture_id,
                    );
                    out.append(&mut events);
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
                    Some("opc_ua"),
                    chunk.captured_len,
                    chunk.session_key.clone(),
                ),
                self.name(),
                "medium",
                "failed to parse opc ua payload",
                chunk.payload,
            )),
        }
    }
}

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

pub(crate) struct ProfinetDecoderWrapper {
    dissector: ProfinetDissector,
}

impl Default for ProfinetDecoderWrapper {
    fn default() -> Self {
        Self {
            dissector: ProfinetDissector,
        }
    }
}

impl SessionDecoder for ProfinetDecoderWrapper {
    fn name(&self) -> &'static str {
        "profinet"
    }

    fn interest(&self) -> &'static [DecoderInterest] {
        &[
            DecoderInterest::UdpPort(34964),
            DecoderInterest::EtherType(0x8892),
        ]
    }

    fn on_datagram(&mut self, chunk: &StreamChunk<'_>, out: &mut Vec<BronzeEvent>) {
        if !self.dissector.can_parse(
            chunk.payload,
            chunk.context.src_port,
            chunk.context.dst_port,
        ) {
            return;
        }

        match self.dissector.parse(chunk.payload, &chunk.context) {
            Some(ProtocolData::Profinet(ProfinetFields {
                frame_id,
                service_type,
                payload,
            })) => {
                let transport = chunk.transport;
                let mut attributes = BTreeMap::new();
                attributes.insert("frame_id".to_string(), format!("{frame_id:#06x}"));
                attributes.insert("service_type".to_string(), service_type.clone());
                attributes.insert("payload_length".to_string(), payload.len().to_string());

                let envelope = build_envelope(
                    &chunk.context,
                    chunk.interface_id,
                    chunk.frame_index,
                    chunk.timestamp,
                    chunk.segment_hash,
                    transport,
                    Some("profinet"),
                    chunk.captured_len,
                    chunk.session_key.clone(),
                );

                out.push(new_event(
                    chunk.capture_id.to_string(),
                    envelope.clone(),
                    BronzeEventFamily::ProtocolTransaction(ProtocolTransaction {
                        operation: profinet_operation_name(&service_type),
                        status: if service_type.contains("Response") {
                            "response".to_string()
                        } else if service_type.contains("Request")
                            || chunk.context.dst_port == 34964
                        {
                            "request".to_string()
                        } else {
                            "observed".to_string()
                        },
                        request_summary: Some(format!("{service_type} frame={frame_id:#06x}")),
                        response_summary: None,
                        object_refs: vec![format!("profinet_frame:{frame_id:#06x}")],
                        values: Vec::new(),
                        attributes,
                                        modbus: None,
                                        protocol_fields: None,
}),
                ));

                if !payload.is_empty() {
                    out.push(artifact_event(
                        chunk.capture_id.to_string(),
                        envelope,
                        "profinet_payload",
                        &format!("{frame_id:#06x}:{}", chunk.frame_index),
                        Some("application/octet-stream"),
                        Some("PROFINET payload"),
                        &payload,
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
                    chunk.transport,
                    Some("profinet"),
                    chunk.captured_len,
                    chunk.session_key.clone(),
                ),
                self.name(),
                "medium",
                "failed to parse profinet payload",
                chunk.payload,
            )),
        }
    }
}

#[derive(Clone)]
struct PendingModbus {
    capture_id: String,
    envelope: EventEnvelope,
    transaction_id: u16,
    unit_id: u8,
    operation: String,
    request_summary: String,
    object_refs: Vec<String>,
    values: Vec<ObjectValue>,
    attributes: BTreeMap<String, String>,
    raw_payload: Vec<u8>,
    last_seen: DateTime<Utc>,
    /// Structured request PDU; used to build `ModbusBronzeFields` on response.
    request_pdu: Option<ModbusPdu>,
}

#[derive(Debug, Clone)]
struct CipIdentityClaim {
    vendor_id: u16,
    device_type: u16,
    product_code: u16,
    revision: String,
    serial_number: u32,
    product_name: String,
    status: u16,
    state: Option<u8>,
    ip_address: Option<String>,
}

#[derive(Default)]
pub(crate) struct ModbusDecoder {
    dissector: ModbusDissector,
    pending: HashMap<String, PendingModbus>,
}

impl SessionDecoder for ModbusDecoder {
    fn name(&self) -> &'static str {
        "modbus"
    }

    fn interest(&self) -> &'static [DecoderInterest] {
        &[DecoderInterest::TcpPort(502)]
    }

    fn on_stream_chunk(&mut self, chunk: &StreamChunk<'_>, out: &mut Vec<BronzeEvent>) {
        match self.dissector.parse(chunk.payload, &chunk.context) {
            Some(ProtocolData::Modbus(fields)) => {
                let operation = modbus_function_name(fields.function_code).to_string();
                let is_request = chunk.context.dst_port == 502 && chunk.context.src_port != 502;
                let envelope = build_envelope(
                    &chunk.context,
                    chunk.interface_id,
                    chunk.frame_index,
                    chunk.timestamp,
                    chunk.segment_hash,
                    TransportProtocol::Tcp,
                    Some("modbus"),
                    chunk.captured_len,
                    chunk.session_key.clone(),
                );
                let key = format!(
                    "{}:{}:{}",
                    chunk.session_key, fields.transaction_id, fields.unit_id
                );
                if is_request {
                    self.pending.insert(
                        key,
                        PendingModbus {
                            capture_id: chunk.capture_id.to_string(),
                            envelope,
                            transaction_id: fields.transaction_id,
                            unit_id: fields.unit_id,
                            operation: operation.clone(),
                            request_summary: modbus_summary(&fields),
                            object_refs: modbus_object_refs(&fields),
                            values: modbus_values(&fields),
                            attributes: modbus_attributes(&fields),
                            raw_payload: chunk.payload.to_vec(),
                            last_seen: chunk.timestamp,
                            request_pdu: fields.pdu.clone(),
                        },
                    );
                } else if let Some(pending) = self.pending.remove(&key) {
                    let mut values = pending.values.clone();
                    values.extend(modbus_values(&fields));
                    let mut attributes = pending.attributes.clone();
                    attributes.extend(modbus_attributes(&fields));
                    let mut merged_envelope = pending.envelope.clone();
                    merged_envelope.bytes_count += envelope.bytes_count;
                    merged_envelope.packet_count += 1;

                    out.push(new_event(
                        pending.capture_id.clone(),
                        merged_envelope.clone(),
                        BronzeEventFamily::ProtocolTransaction(ProtocolTransaction {
                            operation: pending.operation.clone(),
                            status: if fields.is_exception {
                                format!("exception:{}", fields.exception_code)
                            } else {
                                "ok".to_string()
                            },
                            request_summary: Some(pending.request_summary),
                            response_summary: Some(modbus_summary(&fields)),
                            object_refs: pending.object_refs.clone(),
                            values,
                            attributes,
                            modbus: modbus_bronze_fields(
                                pending.request_pdu.as_ref(),
                                fields.pdu.as_ref(),
                                fields.is_exception,
                                fields.exception_code,
                            ),
                            protocol_fields: None,
                        }),
                    ));
                    if !fields.device_identification.is_empty() {
                        out.push(modbus_identity_observation(
                            pending.capture_id.clone(),
                            merged_envelope.clone(),
                            chunk.context.src_ip.to_string(),
                            fields.unit_id,
                            &fields.device_identification,
                        ));
                    }
                    if is_modbus_write(fields.function_code) {
                        out.push(artifact_event(
                            pending.capture_id,
                            merged_envelope,
                            "modbus_write_payload",
                            &format!(
                                "{}:{}:{}",
                                chunk.session_key, fields.transaction_id, fields.unit_id
                            ),
                            Some("application/octet-stream"),
                            Some("Modbus write request payload"),
                            &pending.raw_payload,
                        ));
                    }
                } else {
                    out.push(new_event(
                        chunk.capture_id.to_string(),
                        envelope,
                        BronzeEventFamily::ProtocolTransaction(ProtocolTransaction {
                            operation,
                            status: "response_without_request".to_string(),
                            request_summary: None,
                            response_summary: Some(modbus_summary(&fields)),
                            object_refs: modbus_object_refs(&fields),
                            values: modbus_values(&fields),
                            attributes: modbus_attributes(&fields),
                            modbus: modbus_bronze_fields(
                                None,
                                fields.pdu.as_ref(),
                                fields.is_exception,
                                fields.exception_code,
                            ),
                            protocol_fields: None,
                        }),
                    ));
                    if !fields.device_identification.is_empty() {
                        out.push(modbus_identity_observation(
                            chunk.capture_id.to_string(),
                            build_envelope(
                                &chunk.context,
                                chunk.interface_id,
                                chunk.frame_index,
                                chunk.timestamp,
                                chunk.segment_hash,
                                TransportProtocol::Tcp,
                                Some("modbus"),
                                chunk.captured_len,
                                chunk.session_key.clone(),
                            ),
                            chunk.context.src_ip.to_string(),
                            fields.unit_id,
                            &fields.device_identification,
                        ));
                    }
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
                    Some("modbus"),
                    chunk.captured_len,
                    chunk.session_key.clone(),
                ),
                self.name(),
                "medium",
                "failed to parse modbus payload",
                chunk.payload,
            )),
        }
    }

    fn on_idle_flush(&mut self, timestamp: DateTime<Utc>, out: &mut Vec<BronzeEvent>) {
        let expired: Vec<String> = self
            .pending
            .iter()
            .filter_map(|(key, pending)| {
                if (timestamp - pending.last_seen).num_seconds() >= 0 {
                    Some(key.clone())
                } else {
                    None
                }
            })
            .collect();

        for key in expired {
            if let Some(pending) = self.pending.remove(&key) {
                out.push(new_event(
                    pending.capture_id,
                    pending.envelope,
                    BronzeEventFamily::ProtocolTransaction(ProtocolTransaction {
                        operation: pending.operation,
                        status: "partial_request".to_string(),
                        request_summary: Some(pending.request_summary),
                        response_summary: None,
                        object_refs: pending.object_refs,
                        values: pending.values,
                        attributes: pending.attributes,
                        modbus: modbus_bronze_fields(
                            pending.request_pdu.as_ref(),
                            None,
                            false,
                            0,
                        ),
                        protocol_fields: None,
                    }),
                ));
            }
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
    matches!(code, 0x02 | 0x03 | 0x04 | 0x05 | 0x06)
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

fn bacnet_status(apdu_type: &str) -> &'static str {
    match apdu_type {
        "confirmed_request" | "unconfirmed_request" => "request",
        "simple_ack" | "complex_ack" => "response",
        "error" | "reject" | "abort" => "error",
        _ => "observed",
    }
}

fn bacnet_object_refs(device_instance: Option<u32>, invoke_id: Option<u8>) -> Vec<String> {
    let mut refs = Vec::new();
    if let Some(device_instance) = device_instance {
        refs.push(format!("bacnet_device:{device_instance}"));
    }
    if let Some(invoke_id) = invoke_id {
        refs.push(format!("bacnet_invoke:{invoke_id}"));
    }
    refs
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

fn opc_ua_operation_name(service_type: &str) -> String {
    normalize_operation_name(service_type, "opc_ua_message")
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

fn profinet_operation_name(service_type: &str) -> String {
    normalize_operation_name(service_type, "profinet_frame")
}

fn context_asset_key(context: &PacketContext) -> String {
    match context.src_ip {
        IpAddr::V4(ip) if ip != Ipv4Addr::UNSPECIFIED => ip.to_string(),
        _ => format_mac(&context.src_mac),
    }
}

fn context_remote_asset_key(context: &PacketContext) -> String {
    match context.dst_ip {
        IpAddr::V4(ip) if ip != Ipv4Addr::UNSPECIFIED => ip.to_string(),
        _ => format_mac(&context.dst_mac),
    }
}

fn omron_fins_operation_name(command_name: Option<&str>, command_code: Option<u16>) -> String {
    command_name
        .map(|name| normalize_operation_name(name, "omron_fins"))
        .or_else(|| command_code.map(|code| format!("command_{code:04x}")))
        .unwrap_or_else(|| "omron_fins".to_string())
}

fn omron_fins_status(context: &PacketContext) -> &'static str {
    if context.dst_port == 9600 && context.src_port != 9600 {
        "request"
    } else if context.src_port == 9600 && context.dst_port != 9600 {
        "response"
    } else {
        "observed"
    }
}

fn omron_fins_summary(
    command_name: Option<&str>,
    source_node: Option<u8>,
    destination_node: Option<u8>,
) -> String {
    let mut summary = command_name.unwrap_or("fins_command").to_string();
    if let (Some(source_node), Some(destination_node)) = (source_node, destination_node) {
        summary.push_str(&format!(" {source_node}->{destination_node}"));
    }
    summary
}

fn omron_fins_object_refs(
    memory_area: Option<u8>,
    memory_word: Option<u16>,
    memory_bit: Option<u8>,
    item_count: Option<u16>,
) -> Vec<String> {
    let mut refs = Vec::new();
    if let Some(memory_area) = memory_area {
        refs.push(format!("memory_area:{memory_area:#04x}"));
    }
    if let Some(memory_word) = memory_word {
        refs.push(format!("memory_word:{memory_word}"));
    }
    if let Some(memory_bit) = memory_bit {
        refs.push(format!("memory_bit:{memory_bit}"));
    }
    if let Some(item_count) = item_count {
        refs.push(format!("item_count:{item_count}"));
    }
    refs
}

fn omron_fins_source_role(context: &PacketContext) -> Option<&'static str> {
    if context.dst_port == 9600 && context.src_port != 9600 {
        Some("controller")
    } else if context.src_port == 9600 && context.dst_port != 9600 {
        Some("plc")
    } else {
        None
    }
}

fn omron_fins_destination_role(context: &PacketContext) -> Option<&'static str> {
    if context.dst_port == 9600 && context.src_port != 9600 {
        Some("plc")
    } else if context.src_port == 9600 && context.dst_port != 9600 {
        Some("controller")
    } else {
        None
    }
}

fn hart_ip_operation_name(fields: &HartIpFields) -> String {
    match &fields.body {
        HartIpBody::PassThrough(pass) => normalize_operation_name(
            hart_passthrough_command_name(pass.command),
            "hart_pass_through",
        ),
        _ => normalize_operation_name(&fields.message_id, "hart_ip"),
    }
}

fn hart_ip_status(fields: &HartIpFields) -> &'static str {
    match fields.message_type.as_str() {
        "request" => "request",
        "response" => "response",
        "publish" => "publish",
        "error" | "nak" => "error",
        _ => "observed",
    }
}

fn hart_passthrough_command_name(command: u8) -> &'static str {
    match command {
        0 => "read_unique_identifier",
        11 => "read_device_identity",
        20 => "read_long_tag",
        21 => "read_tag_descriptor",
        22 => "read_message",
        _ => "pass_through_command",
    }
}

fn hart_ip_device_asset_key(context: &PacketContext, fields: &HartIpFields) -> String {
    if hart_ip_status(fields) == "response" {
        context_asset_key(context)
    } else {
        context_remote_asset_key(context)
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

fn ethercat_operation_name(fields: &crate::dissectors::ethercat::EthercatFields) -> String {
    match fields.datagrams.as_slice() {
        [] => "ethercat_frame".to_string(),
        [single] => normalize_operation_name(&single.command, "ethercat_frame"),
        _ => "ethercat_multi_datagram".to_string(),
    }
}

fn ethercat_object_refs(fields: &crate::dissectors::ethercat::EthercatFields) -> Vec<String> {
    let mut refs = Vec::new();
    for datagram in &fields.datagrams {
        refs.push(format!("command:{}", datagram.command));
        refs.push(format!("adp:{}", datagram.adp));
        refs.push(format!("ado:{:#06x}", datagram.ado));
    }
    refs
}

fn ethercat_slave_asset_key(adp: u16, alias_address: Option<u16>) -> Option<String> {
    if let Some(alias_address) = alias_address {
        Some(format!("ethercat_alias:{alias_address}"))
    } else if adp != 0 {
        Some(format!("ethercat_adp:{adp}"))
    } else {
        None
    }
}

pub(crate) fn normalize_operation_name(label: &str, fallback: &str) -> String {
    let mut normalized = String::new();
    let mut last_was_separator = true;

    for ch in label.chars() {
        if ch.is_ascii_alphanumeric() {
            normalized.push(ch.to_ascii_lowercase());
            last_was_separator = false;
        } else if !last_was_separator {
            normalized.push('_');
            last_was_separator = true;
        }
    }

    while normalized.ends_with('_') {
        normalized.pop();
    }

    if normalized.is_empty() {
        fallback.to_string()
    } else {
        normalized
    }
}

fn ethernet_ip_command_name(command: u16) -> &'static str {
    match command {
        0x0001 => "nop",
        0x0004 => "list_services",
        0x0063 => "list_identity",
        0x0064 => "list_interfaces",
        0x0065 => "register_session",
        0x0066 => "unregister_session",
        0x006F => "send_rr_data",
        0x0070 => "send_unit_data",
        _ => "encapsulation_command",
    }
}

fn cip_service_name(cip_data: &[u8]) -> Option<&'static str> {
    let service = cip_explicit_message(cip_data)
        .and_then(|message| message.first().copied())
        .or_else(|| cip_data.iter().find(|byte| **byte != 0).copied())?;
    match service & 0x7F {
        0x01 => Some("get_attributes_all"),
        0x4C => Some("read_tag_service"),
        0x4D => Some("write_tag_service"),
        0x0E => Some("get_attribute_single"),
        0x10 => Some("set_attribute_single"),
        0x54 => Some("forward_open"),
        0x52 => Some("unconnected_send"),
        _ => None,
    }
}

fn cip_object_refs(cip_data: &[u8]) -> Vec<String> {
    let mut refs = Vec::new();
    if let Some(service) = cip_service_name(cip_data) {
        refs.push(format!("cip_service:{service}"));
    }
    if parse_cip_identity_response(cip_data).is_some() {
        refs.push("cip_object:identity".to_string());
    }
    refs
}

fn parse_cip_identity_claim(command: u16, cip_data: &[u8]) -> Option<CipIdentityClaim> {
    parse_cip_identity_claims(command, cip_data)
        .into_iter()
        .next()
}

fn parse_cip_identity_claims(command: u16, cip_data: &[u8]) -> Vec<CipIdentityClaim> {
    match command {
        0x0063 => parse_enip_list_identity(cip_data),
        0x006F | 0x0070 => parse_cip_identity_response(cip_data).into_iter().collect(),
        _ => Vec::new(),
    }
}

fn parse_enip_list_identity(data: &[u8]) -> Vec<CipIdentityClaim> {
    if data.len() < 2 {
        return Vec::new();
    }
    let item_count = u16::from_le_bytes([data[0], data[1]]) as usize;
    let mut offset = 2;
    let mut claims = Vec::new();
    for _ in 0..item_count {
        if offset + 4 > data.len() {
            break;
        }
        let item_type = u16::from_le_bytes([data[offset], data[offset + 1]]);
        let item_len = u16::from_le_bytes([data[offset + 2], data[offset + 3]]) as usize;
        offset += 4;
        if offset + item_len > data.len() {
            break;
        }
        let item = &data[offset..offset + item_len];
        if item_type == 0x000C {
            if let Some(claim) = parse_list_identity_item(item) {
                claims.push(claim);
            }
        }
        offset += item_len;
    }
    claims
}

fn parse_list_identity_item(item: &[u8]) -> Option<CipIdentityClaim> {
    if item.len() < 34 {
        return None;
    }
    let vendor_id = u16::from_le_bytes([item[18], item[19]]);
    let device_type = u16::from_le_bytes([item[20], item[21]]);
    let product_code = u16::from_le_bytes([item[22], item[23]]);
    let revision = format!("{}.{}", item[24], item[25]);
    let status = u16::from_le_bytes([item[26], item[27]]);
    let serial_number = u32::from_le_bytes([item[28], item[29], item[30], item[31]]);
    let name_len = item[32] as usize;
    if 33 + name_len > item.len() {
        return None;
    }
    let product_name = String::from_utf8_lossy(&item[33..33 + name_len]).to_string();
    let state = item.get(33 + name_len).copied();
    let ip_address = if item.len() >= 10 {
        Some(format!("{}.{}.{}.{}", item[6], item[7], item[8], item[9]))
    } else {
        None
    };
    Some(CipIdentityClaim {
        vendor_id,
        device_type,
        product_code,
        revision,
        serial_number,
        product_name,
        status,
        state,
        ip_address,
    })
}

fn parse_cip_identity_response(cip_data: &[u8]) -> Option<CipIdentityClaim> {
    let message = cip_explicit_message(cip_data)?;
    if message.len() < 4 || message[0] != 0x81 || message[2] != 0 {
        return None;
    }
    let additional_status_words = message[3] as usize;
    let data_offset = 4 + additional_status_words * 2;
    if data_offset + 15 > message.len() {
        return None;
    }
    let body = &message[data_offset..];
    let vendor_id = u16::from_le_bytes([body[0], body[1]]);
    let device_type = u16::from_le_bytes([body[2], body[3]]);
    let product_code = u16::from_le_bytes([body[4], body[5]]);
    let revision = format!("{}.{}", body[6], body[7]);
    let status = u16::from_le_bytes([body[8], body[9]]);
    let serial_number = u32::from_le_bytes([body[10], body[11], body[12], body[13]]);
    let name_len = body[14] as usize;
    if 15 + name_len > body.len() {
        return None;
    }
    let product_name = String::from_utf8_lossy(&body[15..15 + name_len]).to_string();
    let state = body.get(15 + name_len).copied();
    Some(CipIdentityClaim {
        vendor_id,
        device_type,
        product_code,
        revision,
        serial_number,
        product_name,
        status,
        state,
        ip_address: None,
    })
}

/// Detect CIP service 0x4B (Execute PCCC) inside an explicit CIP message and
/// return `(is_request, pccc_pdu_bytes)`. Returns None for any other service
/// or for malformed messages.
fn extract_pccc_pdu(message: &[u8]) -> Option<(bool, &[u8])> {
    if message.is_empty() {
        return None;
    }
    let service = message[0];
    let is_request = service & 0x80 == 0;
    if service & 0x7F != 0x4B {
        return None;
    }
    if is_request {
        if message.len() < 2 {
            return None;
        }
        let path_size_words = message[1] as usize;
        let header_len = 2 + path_size_words * 2;
        if message.len() < header_len {
            return None;
        }
        Some((true, &message[header_len..]))
    } else {
        // Response: service (1) + reserved (1) + general_status (1)
        // + ext_status_size (1) + ext status words
        if message.len() < 4 {
            return None;
        }
        let ext_status_words = message[3] as usize;
        let header_len = 4 + ext_status_words * 2;
        if message.len() < header_len {
            return None;
        }
        Some((false, &message[header_len..]))
    }
}

fn cip_explicit_message(cip_data: &[u8]) -> Option<&[u8]> {
    if cip_data.len() < 8 {
        return None;
    }
    let item_count = u16::from_le_bytes([cip_data[6], cip_data[7]]) as usize;
    let mut offset = 8;
    for _ in 0..item_count {
        if offset + 4 > cip_data.len() {
            return None;
        }
        let item_type = u16::from_le_bytes([cip_data[offset], cip_data[offset + 1]]);
        let item_len = u16::from_le_bytes([cip_data[offset + 2], cip_data[offset + 3]]) as usize;
        offset += 4;
        if offset + item_len > cip_data.len() {
            return None;
        }
        let item = &cip_data[offset..offset + item_len];
        if matches!(item_type, 0x00B1 | 0x00B2) {
            return Some(item);
        }
        offset += item_len;
    }
    None
}

fn cip_vendor_name(vendor_id: u16) -> Option<&'static str> {
    match vendor_id {
        1 => Some("Rockwell Automation/Allen-Bradley"),
        _ => None,
    }
}

fn cip_role_from_device_type(device_type: u16) -> Option<&'static str> {
    match device_type {
        0x000E => Some("plc"),
        0x000C => Some("adapter"),
        _ => None,
    }
}

/// Build a [`ModbusBronzeFields`] from the request and response PDUs.
///
/// `request_pdu` is `None` for unpaired response-only events. `response_pdu`
/// is `None` for partial-request (idle-flushed) events.
fn modbus_bronze_fields(
    request_pdu: Option<&ModbusPdu>,
    response_pdu: Option<&ModbusPdu>,
    is_exception: bool,
    exception_code: u8,
) -> Option<ModbusBronzeFields> {
    // Determine which PDU carries the register address (always the request).
    let req = request_pdu;
    let resp = response_pdu;

    let fc = req
        .map(|p| p.function_code)
        .or_else(|| resp.map(|p| p.function_code))?;

    let start_addr = req.and_then(|p| p.start_addr);
    let qty = req.and_then(|p| p.qty);

    // Values come from the response for read FCs, from the request for write FCs.
    let values: Vec<u16> = if let Some(r) = resp {
        if !r.values.is_empty() {
            r.values.clone()
        } else if let Some(req_pdu) = req {
            req_pdu.values.clone()
        } else {
            Vec::new()
        }
    } else if let Some(req_pdu) = req {
        req_pdu.values.clone()
    } else {
        Vec::new()
    };

    let direction = if req.is_some() && resp.is_some() {
        "paired".to_string()
    } else if req.is_some() {
        "request".to_string()
    } else {
        "response".to_string()
    };

    Some(ModbusBronzeFields {
        fc,
        start_addr,
        qty,
        values,
        exception_code: if is_exception { Some(exception_code) } else { None },
        direction,
    })
}

fn modbus_function_name(code: u8) -> &'static str {
    match code {
        1 => "read_coils",
        3 => "read_holding_registers",
        5 => "write_single_coil",
        6 => "write_single_register",
        15 => "write_multiple_coils",
        16 => "write_multiple_registers",
        43 => "read_device_identification",
        _ => "modbus_function",
    }
}

fn is_modbus_write(code: u8) -> bool {
    matches!(code, 5 | 6 | 15 | 16)
}

fn modbus_object_refs(fields: &ModbusFields) -> Vec<String> {
    let mut refs: Vec<String> = fields
        .registers
        .iter()
        .map(|(address, _)| format!("register:{address}"))
        .collect();
    if !fields.device_identification.is_empty() {
        refs.push("modbus_device_identification".to_string());
    }
    refs
}

fn modbus_values(fields: &ModbusFields) -> Vec<ObjectValue> {
    fields
        .registers
        .iter()
        .map(|(address, value)| ObjectValue {
            object_ref: format!("register:{address}"),
            value: Some(value.to_string()),
        })
        .collect()
}

fn modbus_attributes(fields: &ModbusFields) -> BTreeMap<String, String> {
    let mut attributes = BTreeMap::new();
    attributes.insert("unit_id".to_string(), fields.unit_id.to_string());
    attributes.insert(
        "transaction_id".to_string(),
        fields.transaction_id.to_string(),
    );
    attributes.insert(
        "function_code".to_string(),
        fields.function_code.to_string(),
    );
    for (key, value) in &fields.device_identification {
        attributes.insert(format!("device_id_{key}"), value.clone());
    }
    attributes
}

fn modbus_summary(fields: &ModbusFields) -> String {
    if fields.is_exception {
        return format!(
            "{} exception {}",
            modbus_function_name(fields.function_code),
            fields.exception_code
        );
    }
    if fields.function_code == 43 && !fields.device_identification.is_empty() {
        return fields
            .device_identification
            .get("model_name")
            .or_else(|| fields.device_identification.get("product_name"))
            .or_else(|| fields.device_identification.get("product_code"))
            .cloned()
            .unwrap_or_else(|| "device_identification".to_string());
    }
    if fields.registers.is_empty() {
        modbus_function_name(fields.function_code).to_string()
    } else {
        format!(
            "{} {}",
            modbus_function_name(fields.function_code),
            fields
                .registers
                .iter()
                .map(|(address, value)| format!("{address}={value}"))
                .collect::<Vec<_>>()
                .join(", ")
        )
    }
}

fn modbus_identity_observation(
    capture_id: String,
    envelope: EventEnvelope,
    asset_ip: String,
    unit_id: u8,
    device_identification: &BTreeMap<String, String>,
) -> BronzeEvent {
    let mut identifiers = BTreeMap::from([
        ("ip".to_string(), asset_ip.clone()),
        ("unit_id".to_string(), unit_id.to_string()),
    ]);
    for (key, value) in device_identification {
        identifiers.insert(format!("modbus_{key}"), value.clone());
    }
    new_event(
        capture_id,
        envelope,
        BronzeEventFamily::AssetObservation(AssetObservation {
            asset_key: asset_ip,
            role: Some("server".to_string()),
            vendor: device_identification.get("vendor_name").cloned(),
            model: device_identification
                .get("model_name")
                .cloned()
                .or_else(|| device_identification.get("product_name").cloned())
                .or_else(|| device_identification.get("product_code").cloned()),
            firmware: device_identification.get("revision").cloned(),
            hostnames: Vec::new(),
            protocols: vec!["modbus".to_string()],
            identifiers,
        }),
    )
}

// ── Inventory registration ──────────────────────────────────────
inventory::submit!(crate::engine::decoders::DecoderRegistration {
    name: "bacnet",
    factory: || Box::new(BacnetDecoder::default()),
});
inventory::submit!(crate::engine::decoders::DecoderRegistration {
    name: "dnp3",
    factory: || Box::new(Dnp3DecoderWrapper::default()),
});
inventory::submit!(crate::engine::decoders::DecoderRegistration {
    name: "iec104",
    factory: || Box::new(Iec104DecoderWrapper::default()),
});
inventory::submit!(crate::engine::decoders::DecoderRegistration {
    name: "omron_fins",
    factory: || Box::new(OmronFinsDecoder::default()),
});
inventory::submit!(crate::engine::decoders::DecoderRegistration {
    name: "hart_ip",
    factory: || Box::new(HartIpDecoderWrapper::default()),
});
inventory::submit!(crate::engine::decoders::DecoderRegistration {
    name: "iec61850",
    factory: || Box::new(Iec61850DecoderWrapper::default()),
});
inventory::submit!(crate::engine::decoders::DecoderRegistration {
    name: "ethercat",
    factory: || Box::new(EthercatDecoderWrapper::default()),
});
inventory::submit!(crate::engine::decoders::DecoderRegistration {
    name: "ethernet_ip",
    factory: || Box::new(EthernetIpDecoderWrapper::default()),
});
inventory::submit!(crate::engine::decoders::DecoderRegistration {
    name: "opc_ua",
    factory: || Box::new(OpcUaDecoderWrapper::default()),
});
inventory::submit!(crate::engine::decoders::DecoderRegistration {
    name: "s7comm",
    factory: || Box::new(S7commDecoderWrapper::default()),
});
inventory::submit!(crate::engine::decoders::DecoderRegistration {
    name: "profinet",
    factory: || Box::new(ProfinetDecoderWrapper::default()),
});
inventory::submit!(crate::engine::decoders::DecoderRegistration {
    name: "modbus",
    factory: || Box::new(ModbusDecoder::default()),
});
