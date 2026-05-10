//! IT application-protocol `SessionDecoder` impls — DNS, DHCP, SNMP, HTTP,
//! TLS, MQTT. Includes per-protocol helpers (DNS payload extraction, DHCP
//! status mapping, SNMP status mapping, TLS Client Hello parser) and the
//! MQTT-payload-decoder fanout context builder used to dispatch Sparkplug B
//! and other future MQTT-payload protocols.

use std::collections::BTreeMap;
use std::net::IpAddr;

use crate::bronze::{
    AssetObservation, BronzeEvent, BronzeEventFamily, ObjectValue, ProtocolTransaction,
    TopologyObservation, TransportProtocol,
};
use crate::dissectors::dhcp::DhcpDissector;
use crate::dissectors::dns::DnsDissector;
use crate::dissectors::http::HttpDissector;
use crate::dissectors::mqtt::MqttDissector;
use crate::dissectors::snmp::SnmpDissector;
use crate::engine::decoders::ot::normalize_operation_name;
use crate::engine::{
    build_envelope, new_event, parse_anomaly_event, DecoderInterest,
    SessionDecoder, StreamChunk,
};
use crate::registry::{
    format_mac, DhcpFields, DnsFields, HttpFields, MqttFields, PacketContext, ProtocolData,
    ProtocolDissector, SnmpFields,
};

#[derive(Default)]
pub(crate) struct DnsDecoder {
    dissector: DnsDissector,
}

impl SessionDecoder for DnsDecoder {
    fn name(&self) -> &'static str {
        "dns"
    }

    fn interest(&self) -> &'static [DecoderInterest] {
        &[
            DecoderInterest::UdpPort(53),
            DecoderInterest::TcpPort(53),
            DecoderInterest::UdpPort(5353), // mDNS — same wire format, local hostnames
        ]
    }

    fn on_datagram(&mut self, chunk: &StreamChunk<'_>, out: &mut Vec<BronzeEvent>) {
        let payload = dns_payload(chunk);
        match self.dissector.parse(payload, &chunk.context) {
            Some(ProtocolData::Dns(DnsFields {
                is_response,
                transaction_id,
                queries,
                answers,
                records,
            })) => {
                let mut attributes = BTreeMap::new();
                attributes.insert("transaction_id".to_string(), transaction_id.to_string());
                let envelope = build_envelope(
                    &chunk.context,
                    chunk.interface_id,
                    chunk.frame_index,
                    chunk.timestamp,
                    chunk.segment_hash,
                    chunk.transport,
                    Some("dns"),
                    chunk.captured_len,
                    chunk.session_key.clone(),
                );
                out.push(new_event(
                    chunk.capture_id.to_string(),
                    envelope.clone(),
                    BronzeEventFamily::ProtocolTransaction(ProtocolTransaction {
                        operation: if is_response {
                            "response".to_string()
                        } else {
                            "query".to_string()
                        },
                        status: if is_response {
                            "response".to_string()
                        } else {
                            "request".to_string()
                        },
                        request_summary: (!queries.is_empty()).then_some(queries.join(", ")),
                        response_summary: (!answers.is_empty()).then_some(answers.join(", ")),
                        object_refs: queries.clone(),
                        values: answers
                            .iter()
                            .map(|answer| ObjectValue {
                                object_ref: "answer".to_string(),
                                value: Some(answer.clone()),
                            })
                            .collect(),
                        attributes,
                                        modbus: None,
                                        protocol_fields: None,
}),
                ));
                if is_response {
                    use crate::registry::{DnsRecordData, DnsRecordType};

                    let is_mdns = chunk.context.dst_port == 5353 || chunk.context.src_port == 5353;

                    // ── Standard DNS: pair queries with answers ──
                    if !is_mdns {
                        for (query, answer) in queries.iter().zip(answers.iter()) {
                            let hostname = dns_hostname_from_query(query);
                            if let Some(ip) = dns_ip_from_answer(answer) {
                                out.push(new_event(
                                    chunk.capture_id.to_string(),
                                    envelope.clone(),
                                    BronzeEventFamily::AssetObservation(AssetObservation {
                                        asset_key: ip.clone(),
                                        role: None,
                                        vendor: None,
                                        model: None,
                                        firmware: None,
                                        hostnames: vec![hostname],
                                        protocols: vec!["dns".to_string()],
                                        identifiers: BTreeMap::from([("ip".to_string(), ip)]),
                                    }),
                                ));
                            }
                        }
                    }

                    // ── mDNS: use structured records for rich extraction ──
                    if is_mdns {
                        let src_ip = chunk.context.src_ip.to_string();

                        // Collect A record bindings: hostname.local → IP
                        let mut hostname_ips: Vec<(String, String)> = Vec::new();
                        for rec in &records {
                            if let DnsRecordData::A(ip) = &rec.data {
                                if rec.name.ends_with(".local") {
                                    hostname_ips.push((rec.name.clone(), ip.clone()));
                                }
                            }
                        }

                        // Emit hostname observations from A records
                        for (hostname, ip) in &hostname_ips {
                            // Skip service discovery names
                            if hostname.contains("._tcp.") || hostname.contains("._udp.") {
                                continue;
                            }
                            out.push(new_event(
                                chunk.capture_id.to_string(),
                                envelope.clone(),
                                BronzeEventFamily::AssetObservation(AssetObservation {
                                    asset_key: ip.clone(),
                                    role: None,
                                    vendor: None,
                                    model: None,
                                    firmware: None,
                                    hostnames: vec![hostname.clone()],
                                    protocols: vec!["mdns".to_string()],
                                    identifiers: BTreeMap::from([("ip".to_string(), ip.clone())]),
                                }),
                            ));
                        }

                        // If no A records matched, enrich src_ip with the
                        // first clean .local PTR name
                        if hostname_ips.is_empty() {
                            for rec in &records {
                                if let DnsRecordData::Ptr(name) = &rec.data {
                                    if name.ends_with(".local")
                                        && !name.contains("._tcp.")
                                        && !name.contains("._udp.")
                                        && !rec.name.contains(".ip6.arpa")
                                    {
                                        out.push(new_event(
                                            chunk.capture_id.to_string(),
                                            envelope.clone(),
                                            BronzeEventFamily::AssetObservation(AssetObservation {
                                                asset_key: src_ip.clone(),
                                                role: None,
                                                vendor: None,
                                                model: None,
                                                firmware: None,
                                                hostnames: vec![name.clone()],
                                                protocols: vec!["mdns".to_string()],
                                                identifiers: BTreeMap::from([(
                                                    "ip".to_string(),
                                                    src_ip.clone(),
                                                )]),
                                            }),
                                        ));
                                        break;
                                    }
                                }
                            }
                        }

                        // Extract device metadata from TXT records.
                        // Covers: AirPlay, RAOP, Google Cast, Roku, printers (IPP),
                        // HomeKit (HAP), Sonos, Hue, ESPHome, Samsung, Home Assistant.
                        let mut mdns_vendor: Option<String> = None;
                        let mut mdns_model: Option<String> = None;
                        let mut mdns_firmware: Option<String> = None;
                        let mut mdns_device_name: Option<String> = None;
                        let mut service_types: Vec<String> = Vec::new();

                        for rec in &records {
                            // Track which service types are advertised
                            if rec.rtype == DnsRecordType::PTR {
                                if let DnsRecordData::Ptr(instance) = &rec.data {
                                    if rec.name.contains("._tcp.") || rec.name.contains("._udp.") {
                                        service_types.push(rec.name.clone());
                                    }
                                    // Extract friendly name from service instance
                                    // e.g. "Bathroom TV._airplay._tcp.local" → "Bathroom TV"
                                    if let Some(name) = instance.split("._").next().filter(|n| {
                                        !n.is_empty()
                                            && n.len() > 2
                                            && (n.contains(' ') || n.len() > 6)
                                    }) {
                                        // Skip UUID-style names
                                        if !name.chars().all(|c| c.is_ascii_hexdigit() || c == '-')
                                        {
                                            if mdns_device_name.is_none() {
                                                mdns_device_name = Some(name.to_string());
                                            }
                                        }
                                    }
                                }
                            }

                            if let DnsRecordData::Txt(entries) = &rec.data {
                                for entry in entries {
                                    let Some((key, val)) = entry.split_once('=') else {
                                        continue;
                                    };
                                    if val.is_empty() {
                                        continue;
                                    }
                                    match key {
                                        // Vendor / manufacturer
                                        "manufacturer" | "usb_MFG" | "integrator" => {
                                            if mdns_vendor.is_none() {
                                                mdns_vendor = Some(val.to_string());
                                            }
                                        }
                                        // Model (priority order handled by first-wins)
                                        "md" | "model" | "am" | "mdl" | "modelid" | "usb_MDL"
                                        | "mn" => {
                                            if mdns_model.is_none() {
                                                mdns_model = Some(val.to_string());
                                            }
                                        }
                                        // Printer type string (very descriptive)
                                        "ty" | "product" => {
                                            if mdns_model.is_none() {
                                                let cleaned =
                                                    val.trim_matches(|c| c == '(' || c == ')');
                                                mdns_model = Some(cleaned.to_string());
                                            }
                                        }
                                        // Friendly name
                                        "fn" | "n" | "friendly_name" | "name" => {
                                            mdns_device_name = Some(val.to_string());
                                        }
                                        // Firmware / software version
                                        "fv" | "srcvers" | "vs" | "vers" | "swversion"
                                        | "version" => {
                                            if mdns_firmware.is_none() {
                                                mdns_firmware = Some(val.to_string());
                                            }
                                        }
                                        _ => {}
                                    }
                                }
                            }
                        }

                        // Infer vendor from service type when TXT doesn't have it
                        if mdns_vendor.is_none() {
                            for svc in &service_types {
                                if svc.contains("_googlecast.") {
                                    mdns_vendor = Some("Google".into());
                                    break;
                                }
                                if svc.contains("_sonos.") {
                                    mdns_vendor = Some("Sonos".into());
                                    break;
                                }
                                if svc.contains("_hue.") {
                                    mdns_vendor = Some("Philips".into());
                                    break;
                                }
                                if svc.contains("_samsungtv.") {
                                    mdns_vendor = Some("Samsung".into());
                                    break;
                                }
                                if svc.contains("_amzn-wplay.") {
                                    mdns_vendor = Some("Amazon".into());
                                    break;
                                }
                            }
                        }

                        // Emit enriched observation with vendor/model/firmware if found
                        if mdns_vendor.is_some()
                            || mdns_model.is_some()
                            || mdns_device_name.is_some()
                            || mdns_firmware.is_some()
                        {
                            let mut identifiers = BTreeMap::new();
                            identifiers.insert("ip".to_string(), src_ip.clone());
                            if let Some(ref name) = mdns_device_name {
                                identifiers.insert("device_name".to_string(), name.clone());
                            }
                            // Use device name as hostname if we have one
                            let hostnames = mdns_device_name
                                .as_ref()
                                .map(|n| vec![n.clone()])
                                .unwrap_or_default();
                            out.push(new_event(
                                chunk.capture_id.to_string(),
                                envelope.clone(),
                                BronzeEventFamily::AssetObservation(AssetObservation {
                                    asset_key: src_ip.clone(),
                                    role: None,
                                    vendor: mdns_vendor,
                                    model: mdns_model,
                                    firmware: mdns_firmware,
                                    hostnames,
                                    protocols: vec!["mdns".to_string()],
                                    identifiers,
                                }),
                            ));
                        }

                        // Reverse PTR records (in-addr.arpa)
                        for rec in &records {
                            if rec.name.ends_with(".in-addr.arpa") {
                                if let DnsRecordData::Ptr(ptr_name) = &rec.data {
                                    let octets: Vec<&str> = rec
                                        .name
                                        .trim_end_matches(".in-addr.arpa")
                                        .split('.')
                                        .collect();
                                    if octets.len() == 4 {
                                        let reversed_ip = format!(
                                            "{}.{}.{}.{}",
                                            octets[3], octets[2], octets[1], octets[0]
                                        );
                                        out.push(new_event(
                                            chunk.capture_id.to_string(),
                                            envelope.clone(),
                                            BronzeEventFamily::AssetObservation(AssetObservation {
                                                asset_key: reversed_ip.clone(),
                                                role: None,
                                                vendor: None,
                                                model: None,
                                                firmware: None,
                                                hostnames: vec![ptr_name.clone()],
                                                protocols: vec!["mdns".to_string()],
                                                identifiers: BTreeMap::from([(
                                                    "ip".to_string(),
                                                    reversed_ip,
                                                )]),
                                            }),
                                        ));
                                    }
                                }
                            }
                        }
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
                    chunk.transport,
                    Some("dns"),
                    chunk.captured_len,
                    chunk.session_key.clone(),
                ),
                self.name(),
                "medium",
                "failed to parse dns payload",
                payload,
            )),
        }
    }
}

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
                out.push(new_event(
                    chunk.capture_id.to_string(),
                    envelope.clone(),
                    BronzeEventFamily::ProtocolTransaction(ProtocolTransaction {
                        operation: operation.to_string(),
                        status: dhcp_status(&chunk.context).to_string(),
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
                                        protocol_fields: None,
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

#[derive(Default)]
pub(crate) struct SnmpDecoder {
    dissector: SnmpDissector,
}

impl SessionDecoder for SnmpDecoder {
    fn name(&self) -> &'static str {
        "snmp"
    }

    fn interest(&self) -> &'static [DecoderInterest] {
        &[DecoderInterest::UdpPort(161), DecoderInterest::UdpPort(162)]
    }

    fn on_datagram(&mut self, chunk: &StreamChunk<'_>, out: &mut Vec<BronzeEvent>) {
        match self.dissector.parse(chunk.payload, &chunk.context) {
            Some(ProtocolData::Snmp(SnmpFields {
                version,
                pdu_type,
                request_id,
                var_binds,
                sys_name,
                sys_descr,
                sys_object_id,
                engine_id,
                ..
            })) => {
                let envelope = build_envelope(
                    &chunk.context,
                    chunk.interface_id,
                    chunk.frame_index,
                    chunk.timestamp,
                    chunk.segment_hash,
                    TransportProtocol::Udp,
                    Some("snmp"),
                    chunk.captured_len,
                    chunk.session_key.clone(),
                );
                let mut attributes = BTreeMap::from([("version".to_string(), version.clone())]);
                if let Some(id) = request_id {
                    attributes.insert("request_id".to_string(), id.to_string());
                }
                if let Some(engine_id) = engine_id.clone() {
                    attributes.insert("engine_id".to_string(), engine_id);
                }
                out.push(new_event(
                    chunk.capture_id.to_string(),
                    envelope.clone(),
                    BronzeEventFamily::ProtocolTransaction(ProtocolTransaction {
                        operation: normalize_operation_name(&pdu_type, "snmp_message"),
                        status: snmp_status(&pdu_type),
                        request_summary: (!var_binds.is_empty()).then(|| {
                            var_binds
                                .iter()
                                .map(|vb| vb.oid.clone())
                                .collect::<Vec<_>>()
                                .join(", ")
                        }),
                        response_summary: sys_name.clone().or(sys_descr.clone()),
                        object_refs: var_binds.iter().map(|vb| vb.oid.clone()).collect(),
                        values: var_binds
                            .iter()
                            .map(|vb| ObjectValue {
                                object_ref: vb.oid.clone(),
                                value: vb.value.clone(),
                            })
                            .collect(),
                        attributes,
                                        modbus: None,
                                        protocol_fields: None,
}),
                ));

                if sys_name.is_some()
                    || sys_descr.is_some()
                    || sys_object_id.is_some()
                    || engine_id.is_some()
                {
                    let asset_ip = if chunk.context.src_port == 161 || chunk.context.src_port == 162
                    {
                        chunk.context.src_ip.to_string()
                    } else {
                        chunk.context.dst_ip.to_string()
                    };
                    let mut identifiers = BTreeMap::from([("ip".to_string(), asset_ip.clone())]);
                    if let Some(object_id) = sys_object_id.clone() {
                        identifiers.insert("sys_object_id".to_string(), object_id);
                    }
                    if let Some(engine_id) = engine_id {
                        identifiers.insert("engine_id".to_string(), engine_id);
                    }
                    if let Some(sys_descr) = sys_descr.clone() {
                        identifiers.insert("sys_descr".to_string(), sys_descr);
                    }
                    out.push(new_event(
                        chunk.capture_id.to_string(),
                        envelope,
                        BronzeEventFamily::AssetObservation(AssetObservation {
                            asset_key: asset_ip,
                            role: None,
                            vendor: None,
                            model: None,
                            firmware: None,
                            hostnames: sys_name.into_iter().collect(),
                            protocols: vec!["snmp".to_string()],
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
                    Some("snmp"),
                    chunk.captured_len,
                    chunk.session_key.clone(),
                ),
                self.name(),
                "medium",
                "failed to parse snmp payload",
                chunk.payload,
            )),
        }
    }
}

#[derive(Default)]
pub(crate) struct HttpDecoder {
    dissector: HttpDissector,
}

impl SessionDecoder for HttpDecoder {
    fn name(&self) -> &'static str {
        "http"
    }

    fn interest(&self) -> &'static [DecoderInterest] {
        &[DecoderInterest::TcpPort(80), DecoderInterest::TcpPort(8080)]
    }

    fn on_stream_chunk(&mut self, chunk: &StreamChunk<'_>, out: &mut Vec<BronzeEvent>) {
        if chunk.payload.is_empty() {
            return;
        }
        match self.dissector.parse(chunk.payload, &chunk.context) {
            Some(ProtocolData::Http(HttpFields {
                method,
                host,
                uri,
                status_code,
                content_type,
                content_length,
            })) => {
                let mut attributes = BTreeMap::new();
                attributes.insert("content_type".to_string(), content_type);
                attributes.insert("content_length".to_string(), content_length.to_string());
                if !host.is_empty() {
                    attributes.insert("host".to_string(), host);
                }
                let is_request = !method.is_empty();
                let operation = if is_request {
                    method.clone()
                } else {
                    "response".to_string()
                };
                out.push(new_event(
                    chunk.capture_id.to_string(),
                    build_envelope(
                        &chunk.context,
                        chunk.interface_id,
                        chunk.frame_index,
                        chunk.timestamp,
                        chunk.segment_hash,
                        TransportProtocol::Tcp,
                        Some("http"),
                        chunk.captured_len,
                        chunk.session_key.clone(),
                    ),
                    BronzeEventFamily::ProtocolTransaction(ProtocolTransaction {
                        operation,
                        status: if status_code > 0 {
                            status_code.to_string()
                        } else {
                            "request".to_string()
                        },
                        request_summary: is_request.then_some(uri.clone()),
                        response_summary: (status_code > 0).then_some(status_code.to_string()),
                        object_refs: (!uri.is_empty()).then_some(uri).into_iter().collect(),
                        values: Vec::new(),
                        attributes,
                                        modbus: None,
                                        protocol_fields: None,
}),
                ));
            }
            _ => {}
        }
    }
}

pub(crate) struct TlsDecoder;

impl SessionDecoder for TlsDecoder {
    fn name(&self) -> &'static str {
        "tls"
    }

    fn interest(&self) -> &'static [DecoderInterest] {
        &[
            DecoderInterest::TcpPort(443),
            DecoderInterest::TcpPort(4840),
        ]
    }

    fn on_stream_chunk(&mut self, chunk: &StreamChunk<'_>, out: &mut Vec<BronzeEvent>) {
        let Some(tls) = parse_tls_client_hello(chunk.payload) else {
            return;
        };
        let mut attributes = BTreeMap::new();
        attributes.insert("version".to_string(), tls.version.clone());
        if let Some(ref cipher) = tls.cipher_suite {
            attributes.insert("cipher_suite".to_string(), cipher.clone());
        }
        let envelope = build_envelope(
            &chunk.context,
            chunk.interface_id,
            chunk.frame_index,
            chunk.timestamp,
            chunk.segment_hash,
            TransportProtocol::Tcp,
            Some("tls"),
            chunk.captured_len,
            chunk.session_key.clone(),
        );
        out.push(new_event(
            chunk.capture_id.to_string(),
            envelope.clone(),
            BronzeEventFamily::ProtocolTransaction(ProtocolTransaction {
                operation: "client_hello".to_string(),
                status: "observed".to_string(),
                request_summary: tls.sni.clone(),
                response_summary: None,
                object_refs: tls.sni.clone().into_iter().collect(),
                values: Vec::new(),
                attributes,
                        modbus: None,
                                        protocol_fields: None,
}),
        ));
        if let Some(sni) = tls.sni {
            out.push(new_event(
                chunk.capture_id.to_string(),
                envelope,
                BronzeEventFamily::AssetObservation(AssetObservation {
                    asset_key: chunk.context.dst_ip.to_string(),
                    role: None,
                    vendor: None,
                    model: None,
                    firmware: None,
                    hostnames: vec![sni],
                    protocols: vec!["tls".to_string()],
                    identifiers: BTreeMap::from([(
                        "ip".to_string(),
                        chunk.context.dst_ip.to_string(),
                    )]),
                }),
            ));
        }
    }
}

fn dns_payload<'a>(chunk: &'a StreamChunk<'_>) -> &'a [u8] {
    if chunk.transport == TransportProtocol::Tcp && chunk.payload.len() > 2 {
        let advertised = u16::from_be_bytes([chunk.payload[0], chunk.payload[1]]) as usize;
        if advertised + 2 <= chunk.payload.len() {
            return &chunk.payload[2..2 + advertised];
        }
    }
    chunk.payload
}

fn dns_hostname_from_query(query: &str) -> String {
    query.split_whitespace().next().unwrap_or(query).to_string()
}

fn dns_ip_from_answer(answer: &str) -> Option<String> {
    let candidate = answer.split_whitespace().last()?;
    candidate
        .parse::<IpAddr>()
        .ok()
        .map(|_| candidate.to_string())
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

fn snmp_status(pdu_type: &str) -> String {
    if pdu_type.contains("response") {
        "response".to_string()
    } else if pdu_type.contains("trap") || pdu_type.contains("inform") || pdu_type == "report" {
        "observed".to_string()
    } else {
        "request".to_string()
    }
}

#[derive(Debug)]
struct ParsedTls {
    version: String,
    sni: Option<String>,
    cipher_suite: Option<String>,
}

fn parse_tls_client_hello(payload: &[u8]) -> Option<ParsedTls> {
    if payload.len() < 9 {
        return None;
    }
    let content_type = payload[0];
    if content_type != 22 {
        return None;
    }
    let version = format!("TLS {:02x}{:02x}", payload[1], payload[2]);
    let record_len = u16::from_be_bytes([payload[3], payload[4]]) as usize;
    if payload.len() < 5 + record_len || payload[5] != 1 {
        return None;
    }

    let mut offset = 9; // record header + handshake header
    if payload.len() < offset + 34 {
        return None;
    }
    offset += 2; // client version
    offset += 32; // random
    let session_id_len = *payload.get(offset)? as usize;
    offset += 1 + session_id_len;
    let cipher_len =
        u16::from_be_bytes([*payload.get(offset)?, *payload.get(offset + 1)?]) as usize;
    offset += 2;
    let cipher_suite = if cipher_len >= 2 && offset + 2 <= payload.len() {
        Some(format!(
            "0x{:02x}{:02x}",
            payload[offset],
            payload[offset + 1]
        ))
    } else {
        None
    };
    offset += cipher_len;
    let compression_len = *payload.get(offset)? as usize;
    offset += 1 + compression_len;
    let ext_len = u16::from_be_bytes([*payload.get(offset)?, *payload.get(offset + 1)?]) as usize;
    offset += 2;
    let ext_end = offset.checked_add(ext_len)?.min(payload.len());

    let mut sni = None;
    while offset + 4 <= ext_end {
        let ext_type = u16::from_be_bytes([payload[offset], payload[offset + 1]]);
        let item_len = u16::from_be_bytes([payload[offset + 2], payload[offset + 3]]) as usize;
        offset += 4;
        if offset + item_len > ext_end {
            break;
        }
        if ext_type == 0x0000 && item_len >= 5 {
            let list_len = u16::from_be_bytes([payload[offset], payload[offset + 1]]) as usize;
            if list_len + 2 <= item_len && payload[offset + 2] == 0 {
                let name_len =
                    u16::from_be_bytes([payload[offset + 3], payload[offset + 4]]) as usize;
                if offset + 5 + name_len <= ext_end {
                    sni = std::str::from_utf8(&payload[offset + 5..offset + 5 + name_len])
                        .ok()
                        .map(str::to_string);
                }
            }
        }
        offset += item_len;
    }

    Some(ParsedTls {
        version,
        sni,
        cipher_suite,
    })
}

// ── MQTT decoder ─────────────────────────────────────────────────

pub(crate) struct MqttDecoder {
    dissector: MqttDissector,
    payload_decoders: Vec<Box<dyn crate::mqtt_payload::MqttPayloadDecoder>>,
}

impl Default for MqttDecoder {
    fn default() -> Self {
        Self {
            dissector: MqttDissector,
            payload_decoders: vec![Box::new(crate::sparkplug::SparkplugBDecoder::new())],
        }
    }
}

impl SessionDecoder for MqttDecoder {
    fn name(&self) -> &'static str {
        "mqtt"
    }

    fn interest(&self) -> &'static [DecoderInterest] {
        &[
            DecoderInterest::TcpPort(1883),
            DecoderInterest::TcpPort(8883),
        ]
    }

    fn on_stream_chunk(&mut self, chunk: &StreamChunk<'_>, out: &mut Vec<BronzeEvent>) {
        match self.dissector.parse(chunk.payload, &chunk.context) {
            Some(ProtocolData::Mqtt(MqttFields {
                packet_type,
                packet_type_name,
                protocol_name,
                protocol_version,
                client_id,
                username,
                topic,
                qos,
                retain,
                payload: mqtt_payload,
                ..
            })) => {
                let envelope = build_envelope(
                    &chunk.context,
                    chunk.interface_id,
                    chunk.frame_index,
                    chunk.timestamp,
                    chunk.segment_hash,
                    TransportProtocol::Tcp,
                    Some("mqtt"),
                    chunk.captured_len,
                    chunk.session_key.clone(),
                );

                let mut attributes = BTreeMap::new();
                if let Some(ref proto) = protocol_name {
                    attributes.insert("protocol_name".to_string(), proto.clone());
                }
                if let Some(ver) = protocol_version {
                    attributes.insert("protocol_version".to_string(), ver.to_string());
                }
                if let Some(ref cid) = client_id {
                    attributes.insert("client_id".to_string(), cid.clone());
                }
                if let Some(ref user) = username {
                    attributes.insert("username".to_string(), user.clone());
                }
                if let Some(q) = qos {
                    attributes.insert("qos".to_string(), q.to_string());
                }

                let operation = packet_type_name.to_lowercase();
                let summary = match packet_type {
                    1 => {
                        let cid_str = client_id.as_deref().unwrap_or("?");
                        format!("CONNECT client_id={cid_str}")
                    }
                    3 => {
                        let t = topic.as_deref().unwrap_or("?");
                        format!("PUBLISH topic={t}")
                    }
                    8 => {
                        let t = topic.as_deref().unwrap_or("?");
                        format!("SUBSCRIBE topic={t}")
                    }
                    _ => packet_type_name.clone(),
                };

                let object_refs = topic.clone().into_iter().collect();

                out.push(new_event(
                    chunk.capture_id.to_string(),
                    envelope.clone(),
                    BronzeEventFamily::ProtocolTransaction(ProtocolTransaction {
                        operation,
                        status: "ok".to_string(),
                        request_summary: Some(summary),
                        response_summary: None,
                        object_refs,
                        values: vec![],
                        attributes,
                                        modbus: None,
                                        protocol_fields: None,
}),
                ));

                // CONNECT packets identify the client device.
                if packet_type == 1 {
                    let mut identifiers = BTreeMap::from([(
                        "ip".to_string(),
                        chunk.context.src_ip.to_string(),
                    )]);
                    if let Some(ref cid) = client_id {
                        identifiers.insert("client_id".to_string(), cid.clone());
                    }
                    out.push(new_event(
                        chunk.capture_id.to_string(),
                        envelope,
                        BronzeEventFamily::AssetObservation(AssetObservation {
                            asset_key: chunk.context.src_ip.to_string(),
                            role: Some("mqtt_client".to_string()),
                            vendor: None,
                            model: None,
                            firmware: None,
                            hostnames: username.into_iter().collect(),
                            protocols: vec!["mqtt".to_string()],
                            identifiers,
                        }),
                    ));
                }

                // PUBLISH payloads fan out to registered MqttPayloadDecoders
                // (Sparkplug B, future UADP / vendor schemas).
                if packet_type == 3 {
                    if let (Some(topic_str), Some(payload_bytes)) =
                        (topic.as_deref(), mqtt_payload.as_deref())
                    {
                        let ctx = build_mqtt_publish_context(
                            chunk,
                            topic_str,
                            payload_bytes,
                            client_id.as_deref(),
                            qos.unwrap_or(0),
                            retain.unwrap_or(false),
                        );
                        for decoder in self.payload_decoders.iter_mut() {
                            let mut events = decoder.try_decode(&ctx);
                            if !events.is_empty() {
                                out.append(&mut events);
                                break; // first decoder that claims the payload wins
                            }
                        }
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
                    Some("mqtt"),
                    chunk.captured_len,
                    chunk.session_key.clone(),
                ),
                self.name(),
                "medium",
                "failed to parse mqtt payload",
                chunk.payload,
            )),
        }
    }
}

/// Build an [`MqttPublishContext`] from a [`StreamChunk`] for fanout to
/// registered [`crate::mqtt_payload::MqttPayloadDecoder`] implementations.
///
/// `broker_endpoint` is whichever side of the flow uses port 1883/8883; if
/// neither matches (unusual) we default to the destination side.
fn build_mqtt_publish_context<'a>(
    chunk: &'a StreamChunk<'a>,
    topic: &'a str,
    payload: &'a [u8],
    client_id: Option<&'a str>,
    qos: u8,
    retain: bool,
) -> crate::mqtt_payload::MqttPublishContext<'a> {
    use crate::mqtt_payload::{FlowFiveTuple, MqttPublishContext};
    use std::net::SocketAddr;

    let src = SocketAddr::new(chunk.context.src_ip, chunk.context.src_port);
    let dst = SocketAddr::new(chunk.context.dst_ip, chunk.context.dst_port);
    let broker_endpoint = if matches!(chunk.context.dst_port, 1883 | 8883) {
        dst
    } else if matches!(chunk.context.src_port, 1883 | 8883) {
        src
    } else {
        dst
    };
    let publisher_mac = if broker_endpoint == dst {
        chunk.context.src_mac
    } else {
        chunk.context.dst_mac
    };
    MqttPublishContext {
        broker_endpoint,
        flow_5tuple: FlowFiveTuple {
            src,
            dst,
            transport: 6, // TCP
        },
        client_id,
        topic,
        payload,
        retain,
        qos,
        // chunk.context.timestamp is nanoseconds since epoch; the publish
        // context API uses microseconds.
        packet_ts_us: chunk.context.timestamp / 1_000,
        vlan_id: chunk.context.vlan_id,
        publisher_mac,
    }
}



// ── Inventory registration ──────────────────────────────────────
inventory::submit!(crate::engine::decoders::DecoderRegistration {
    name: "dns",
    factory: || Box::new(DnsDecoder::default()),
});
inventory::submit!(crate::engine::decoders::DecoderRegistration {
    name: "dhcp",
    factory: || Box::new(DhcpDecoder::default()),
});
inventory::submit!(crate::engine::decoders::DecoderRegistration {
    name: "snmp",
    factory: || Box::new(SnmpDecoder::default()),
});
inventory::submit!(crate::engine::decoders::DecoderRegistration {
    name: "http",
    factory: || Box::new(HttpDecoder::default()),
});
inventory::submit!(crate::engine::decoders::DecoderRegistration {
    name: "tls",
    factory: || Box::new(TlsDecoder),
});
inventory::submit!(crate::engine::decoders::DecoderRegistration {
    name: "mqtt",
    factory: || Box::new(MqttDecoder::default()),
});
