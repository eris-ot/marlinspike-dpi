use std::collections::BTreeMap;
use std::net::IpAddr;

use crate::bronze::{
    AssetObservation, BronzeEvent, BronzeEventFamily, DnsBronzeFields, ObjectValue, ProtocolFields,
    ProtocolTransaction, TransportProtocol,
};
use crate::dissectors::dns::DnsDissector;
use crate::engine::{
    DecoderInterest, SessionDecoder, StreamChunk, build_envelope, new_event, parse_anomaly_event,
};
use crate::registry::{DnsFields, ProtocolData, ProtocolDissector};

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
                let dns_pf = DnsBronzeFields {
                    transaction_id,
                    is_response,
                    queries: queries.clone(),
                    answers: answers.clone(),
                    direction: if is_response { "response" } else { "request" }.to_string(),
                };
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
                        protocol_fields: Some(ProtocolFields::Dns(dns_pf)),
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
                            if let DnsRecordData::A(ip) = &rec.data
                                && rec.name.ends_with(".local")
                            {
                                hostname_ips.push((rec.name.clone(), ip.clone()));
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
                                if let DnsRecordData::Ptr(name) = &rec.data
                                    && name.ends_with(".local")
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
                            if rec.rtype == DnsRecordType::PTR
                                && let DnsRecordData::Ptr(instance) = &rec.data
                            {
                                if rec.name.contains("._tcp.") || rec.name.contains("._udp.") {
                                    service_types.push(rec.name.clone());
                                }
                                // Extract friendly name from service instance
                                // e.g. "Bathroom TV._airplay._tcp.local" → "Bathroom TV"
                                if let Some(name) = instance.split("._").next().filter(|n| {
                                    !n.is_empty() && n.len() > 2 && (n.contains(' ') || n.len() > 6)
                                }) {
                                    // Skip UUID-style names
                                    if !name.chars().all(|c| c.is_ascii_hexdigit() || c == '-')
                                        && mdns_device_name.is_none()
                                    {
                                        mdns_device_name = Some(name.to_string());
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
                            if rec.name.ends_with(".in-addr.arpa")
                                && let DnsRecordData::Ptr(ptr_name) = &rec.data
                            {
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

inventory::submit!(crate::engine::decoders::DecoderRegistration {
    name: "dns",
    factory: || Box::new(DnsDecoder::default()),
});
