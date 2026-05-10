use std::collections::BTreeMap;

use crate::bronze::{
    AssetObservation, BronzeEvent, BronzeEventFamily, ProtocolTransaction, TopologyObservation,
    TransportProtocol,
};
use crate::dissectors::fins::OmronFinsDissector;
use crate::engine::{
    artifact_event, build_envelope, new_event, parse_anomaly_event, DecoderInterest,
    SessionDecoder, StreamChunk,
};
use crate::registry::{OmronFinsFields, PacketContext, ProtocolData, ProtocolDissector};

use super::normalize_operation_name;

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

inventory::submit!(crate::engine::decoders::DecoderRegistration {
    name: "omron_fins",
    factory: || Box::new(OmronFinsDecoder::default()),
});
