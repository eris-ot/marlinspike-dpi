use std::collections::BTreeMap;

use crate::bronze::{
    AssetObservation, BronzeEvent, BronzeEventFamily, DhcpBronzeFields, ProtocolFields,
    ProtocolTransaction, TopologyObservation, TransportProtocol,
};
use crate::dissectors::dhcp::DhcpDissector;
use crate::engine::{
    DecoderInterest, SessionDecoder, StreamChunk, build_envelope, new_event, parse_anomaly_event,
};
use crate::registry::{DhcpFields, PacketContext, ProtocolData, ProtocolDissector, format_mac};

#[derive(Default)]
pub(crate) struct DhcpDecoder {
    dissector: DhcpDissector,
}

impl SessionDecoder for DhcpDecoder {
    fn name(&self) -> &'static str {
        "dhcp"
    }

    fn interest(&self) -> &'static [DecoderInterest] {
        &[DecoderInterest::UdpPort(67), DecoderInterest::UdpPort(68)]
    }

    fn on_datagram(&mut self, chunk: &StreamChunk<'_>, out: &mut Vec<BronzeEvent>) {
        match self.dissector.parse(chunk.payload, &chunk.context) {
            Some(ProtocolData::Dhcp(DhcpFields {
                op,
                xid,
                client_mac,
                ciaddr,
                yiaddr,
                siaddr,
                giaddr,
                message_type,
                hostname,
                client_id,
                vendor_class,
                requested_ip,
                server_id,
            })) => {
                let envelope = build_envelope(
                    &chunk.context,
                    chunk.interface_id,
                    chunk.frame_index,
                    chunk.timestamp,
                    chunk.segment_hash,
                    TransportProtocol::Udp,
                    Some("dhcp"),
                    chunk.captured_len,
                    chunk.session_key.clone(),
                );
                let operation = dhcp_message_type_name(message_type);
                let mut attributes = BTreeMap::new();
                attributes.insert("xid".to_string(), format!("{xid:#010x}"));
                attributes.insert("bootp_op".to_string(), op.to_string());
                if let Some(ip) = requested_ip.clone() {
                    attributes.insert("requested_ip".to_string(), ip);
                }
                if let Some(ip) = yiaddr.clone() {
                    attributes.insert("your_ip".to_string(), ip);
                }
                if let Some(ip) = server_id.clone() {
                    attributes.insert("server_id".to_string(), ip);
                }
                if let Some(ip) = giaddr.clone() {
                    attributes.insert("relay_ip".to_string(), ip);
                }
                if let Some(vendor_class) = vendor_class.clone() {
                    attributes.insert("vendor_class".to_string(), vendor_class);
                }
                let dhcp_direction = dhcp_status(&chunk.context);
                let dhcp_pf = DhcpBronzeFields {
                    op,
                    xid,
                    message_type,
                    message_type_name: operation.to_string(),
                    client_mac: format_mac(&client_mac),
                    requested_ip: requested_ip.clone(),
                    your_ip: yiaddr.clone(),
                    server_id: server_id.clone(),
                    relay_ip: giaddr.clone(),
                    hostname: hostname.clone(),
                    client_id: client_id.clone(),
                    vendor_class: vendor_class.clone(),
                    direction: dhcp_direction.to_string(),
                };
                out.push(new_event(
                    chunk.capture_id.to_string(),
                    envelope.clone(),
                    BronzeEventFamily::ProtocolTransaction(ProtocolTransaction {
                        operation: operation.to_string(),
                        status: dhcp_direction.to_string(),
                        request_summary: hostname.as_ref().map(|name| format!("{name} via DHCP")),
                        response_summary: yiaddr.clone(),
                        object_refs: requested_ip
                            .clone()
                            .or_else(|| yiaddr.clone())
                            .into_iter()
                            .collect(),
                        values: Vec::new(),
                        attributes,
                        modbus: None,
                        protocol_fields: Some(ProtocolFields::Dhcp(dhcp_pf)),
                    }),
                ));

                let mut identifiers =
                    BTreeMap::from([("mac".to_string(), format_mac(&client_mac))]);
                if let Some(ip) = yiaddr.clone().or(ciaddr.clone()).or(requested_ip.clone()) {
                    identifiers.insert("ip".to_string(), ip);
                }
                if let Some(client_id) = client_id.clone() {
                    identifiers.insert("client_id".to_string(), client_id);
                }
                if let Some(vendor_class) = vendor_class.clone() {
                    identifiers.insert("vendor_class".to_string(), vendor_class);
                }
                let hostnames = hostname.clone().into_iter().collect();
                out.push(new_event(
                    chunk.capture_id.to_string(),
                    envelope.clone(),
                    BronzeEventFamily::AssetObservation(AssetObservation {
                        asset_key: format_mac(&client_mac),
                        role: None,
                        vendor: None,
                        model: None,
                        firmware: None,
                        hostnames,
                        protocols: vec!["dhcp".to_string()],
                        identifiers,
                    }),
                ));

                if let Some(server_ip) = server_id.clone().or(siaddr.clone()) {
                    out.push(new_event(
                        chunk.capture_id.to_string(),
                        envelope.clone(),
                        BronzeEventFamily::AssetObservation(AssetObservation {
                            asset_key: server_ip.clone(),
                            role: Some("server".to_string()),
                            vendor: None,
                            model: None,
                            firmware: None,
                            hostnames: Vec::new(),
                            protocols: vec!["dhcp".to_string()],
                            identifiers: BTreeMap::from([("ip".to_string(), server_ip)]),
                        }),
                    ));
                }

                if server_id.is_some() || giaddr.is_some() {
                    let mut metadata = BTreeMap::new();
                    if let Some(ip) = yiaddr.or(requested_ip) {
                        metadata.insert("lease_ip".to_string(), ip);
                    }
                    if let Some(ip) = giaddr.clone() {
                        metadata.insert("relay_ip".to_string(), ip);
                    }
                    out.push(new_event(
                        chunk.capture_id.to_string(),
                        envelope,
                        BronzeEventFamily::TopologyObservation(TopologyObservation {
                            observation_type: "dhcp_lease".to_string(),
                            local_id: format_mac(&client_mac),
                            remote_id: server_id.or(giaddr),
                            description: Some(operation.to_string()),
                            capabilities: Vec::new(),
                            metadata,
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
                    Some("dhcp"),
                    chunk.captured_len,
                    chunk.session_key.clone(),
                ),
                self.name(),
                "medium",
                "failed to parse dhcp payload",
                chunk.payload,
            )),
        }
    }
}

fn dhcp_message_type_name(message_type: Option<u8>) -> &'static str {
    match message_type {
        Some(1) => "discover",
        Some(2) => "offer",
        Some(3) => "request",
        Some(4) => "decline",
        Some(5) => "ack",
        Some(6) => "nak",
        Some(7) => "release",
        Some(8) => "inform",
        _ => "bootp",
    }
}

fn dhcp_status(context: &PacketContext) -> &'static str {
    if context.dst_port == 67 {
        "request"
    } else if context.src_port == 67 {
        "response"
    } else {
        "observed"
    }
}

inventory::submit!(crate::engine::decoders::DecoderRegistration {
    name: "dhcp",
    factory: || Box::new(DhcpDecoder::default()),
});
