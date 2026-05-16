//! Simple IT-protocol `SessionDecoder` impls — port-based decoders that
//! emit one ProtocolTransaction (and sometimes an AssetObservation) per
//! parsed packet. Members: NTP, Syslog, FTP, SSH, RADIUS, ICMP.

use std::collections::BTreeMap;

use crate::bronze::{
    AssetObservation, BronzeEvent, BronzeEventFamily, FtpBronzeFields, IcmpBronzeFields,
    NtpBronzeFields, ProtocolFields, ProtocolTransaction, RadiusBronzeFields, SshBronzeFields,
    SyslogBronzeFields, TransportProtocol,
};
use crate::dissectors::ftp::FtpDissector;
use crate::dissectors::icmp::IcmpDissector;
use crate::dissectors::ntp::NtpDissector;
use crate::dissectors::radius::RadiusDissector;
use crate::dissectors::ssh::SshDissector;
use crate::dissectors::syslog::SyslogDissector;
use crate::engine::{
    DecoderInterest, SessionDecoder, StreamChunk, build_envelope, new_event, parse_anomaly_event,
};
use crate::registry::{
    FtpFields, NtpFields, ProtocolData, ProtocolDissector, RadiusFields, SshFields, SyslogFields,
};

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

// ── FTP decoder ──────────────────────────────────────────────────

#[derive(Default)]
pub(crate) struct FtpDecoder {
    dissector: FtpDissector,
}

impl SessionDecoder for FtpDecoder {
    fn name(&self) -> &'static str {
        "ftp"
    }

    fn interest(&self) -> &'static [DecoderInterest] {
        &[DecoderInterest::TcpPort(21)]
    }

    fn on_stream_chunk(&mut self, chunk: &StreamChunk<'_>, out: &mut Vec<BronzeEvent>) {
        match self.dissector.parse(chunk.payload, &chunk.context) {
            Some(ProtocolData::Ftp(FtpFields {
                is_response,
                command,
                argument,
                reply_code,
                reply_text,
                banner,
            })) => {
                let envelope = build_envelope(
                    &chunk.context,
                    chunk.interface_id,
                    chunk.frame_index,
                    chunk.timestamp,
                    chunk.segment_hash,
                    TransportProtocol::Tcp,
                    Some("ftp"),
                    chunk.captured_len,
                    chunk.session_key.clone(),
                );

                let (operation, status, summary) = if is_response {
                    let code = reply_code.unwrap_or(0);
                    let text = reply_text.as_deref().unwrap_or("");
                    (
                        "reply".to_string(),
                        format!("{code}"),
                        format!("{code} {text}"),
                    )
                } else {
                    let cmd = command.as_deref().unwrap_or("?");
                    let arg = argument.as_deref().unwrap_or("");
                    (
                        cmd.to_lowercase(),
                        "request".to_string(),
                        format!("{cmd} {arg}").trim().to_string(),
                    )
                };

                let mut attributes = BTreeMap::new();
                if let Some(ref cmd) = command {
                    attributes.insert("command".to_string(), cmd.clone());
                }
                if let Some(ref arg) = argument {
                    attributes.insert("argument".to_string(), arg.clone());
                }

                let ftp_pf = FtpBronzeFields {
                    is_response,
                    command: command.clone(),
                    argument: argument.clone(),
                    reply_code,
                    reply_text: reply_text.clone(),
                    direction: if is_response { "response" } else { "request" }.to_string(),
                };
                out.push(new_event(
                    chunk.capture_id.to_string(),
                    envelope.clone(),
                    BronzeEventFamily::ProtocolTransaction(ProtocolTransaction {
                        operation,
                        status,
                        request_summary: Some(summary),
                        response_summary: None,
                        object_refs: argument.into_iter().collect(),
                        values: vec![],
                        attributes,
                        modbus: None,
                        protocol_fields: Some(ProtocolFields::Ftp(ftp_pf)),
                    }),
                ));

                // Banner (220) identifies the FTP server.
                if let Some(banner_text) = banner {
                    out.push(new_event(
                        chunk.capture_id.to_string(),
                        envelope,
                        BronzeEventFamily::AssetObservation(AssetObservation {
                            asset_key: chunk.context.src_ip.to_string(),
                            role: Some("ftp_server".to_string()),
                            vendor: None,
                            model: None,
                            firmware: Some(banner_text),
                            hostnames: vec![],
                            protocols: vec!["ftp".to_string()],
                            identifiers: BTreeMap::from([(
                                "ip".to_string(),
                                chunk.context.src_ip.to_string(),
                            )]),
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
                    TransportProtocol::Tcp,
                    Some("ftp"),
                    chunk.captured_len,
                    chunk.session_key.clone(),
                ),
                self.name(),
                "medium",
                "failed to parse ftp payload",
                chunk.payload,
            )),
        }
    }
}

// ── SSH decoder ──────────────────────────────────────────────────

#[derive(Default)]
pub(crate) struct SshDecoder {
    dissector: SshDissector,
}

impl SessionDecoder for SshDecoder {
    fn name(&self) -> &'static str {
        "ssh"
    }

    fn interest(&self) -> &'static [DecoderInterest] {
        &[DecoderInterest::TcpPort(22)]
    }

    fn on_stream_chunk(&mut self, chunk: &StreamChunk<'_>, out: &mut Vec<BronzeEvent>) {
        // Only parse banner packets (contain "SSH-").
        if !chunk.payload.windows(4).any(|w| w == b"SSH-") {
            return;
        }
        if let Some(ProtocolData::Ssh(SshFields {
            protocol_version,
            software_version,
            comments,
            banner,
        })) = self.dissector.parse(chunk.payload, &chunk.context)
        {
            let envelope = build_envelope(
                &chunk.context,
                chunk.interface_id,
                chunk.frame_index,
                chunk.timestamp,
                chunk.segment_hash,
                TransportProtocol::Tcp,
                Some("ssh"),
                chunk.captured_len,
                chunk.session_key.clone(),
            );

            let mut attributes = BTreeMap::new();
            attributes.insert("protocol_version".to_string(), protocol_version.clone());
            attributes.insert("software_version".to_string(), software_version.clone());
            if let Some(ref c) = comments {
                attributes.insert("comments".to_string(), c.clone());
            }

            let ssh_pf = SshBronzeFields {
                protocol_version: protocol_version.clone(),
                software_version: software_version.clone(),
                comments: comments.clone(),
            };
            out.push(new_event(
                chunk.capture_id.to_string(),
                envelope.clone(),
                BronzeEventFamily::ProtocolTransaction(ProtocolTransaction {
                    operation: "banner".to_string(),
                    status: "ok".to_string(),
                    request_summary: Some(banner),
                    response_summary: None,
                    object_refs: vec![],
                    values: vec![],
                    attributes,
                    modbus: None,
                    protocol_fields: Some(ProtocolFields::Ssh(ssh_pf)),
                }),
            ));

            // The banner sender is the SSH server — identify it.
            let is_server = chunk.context.src_port == 22;
            let firmware = Some(software_version.clone());
            let role = if is_server {
                "ssh_server"
            } else {
                "ssh_client"
            };
            let ip = if is_server {
                chunk.context.src_ip.to_string()
            } else {
                chunk.context.dst_ip.to_string()
            };
            let mut identifiers = BTreeMap::from([("ip".to_string(), ip.clone())]);
            identifiers.insert("software_version".to_string(), software_version);
            if let Some(c) = comments {
                identifiers.insert("os_hint".to_string(), c);
            }

            out.push(new_event(
                chunk.capture_id.to_string(),
                envelope,
                BronzeEventFamily::AssetObservation(AssetObservation {
                    asset_key: ip,
                    role: Some(role.to_string()),
                    vendor: None,
                    model: None,
                    firmware,
                    hostnames: vec![],
                    protocols: vec!["ssh".to_string()],
                    identifiers,
                }),
            ));
        }
    }
}

// ── RADIUS decoder ───────────────────────────────────────────────

#[derive(Default)]
pub(crate) struct RadiusDecoder {
    dissector: RadiusDissector,
}

impl SessionDecoder for RadiusDecoder {
    fn name(&self) -> &'static str {
        "radius"
    }

    fn interest(&self) -> &'static [DecoderInterest] {
        &[
            DecoderInterest::UdpPort(1812),
            DecoderInterest::UdpPort(1813),
        ]
    }

    fn on_datagram(&mut self, chunk: &StreamChunk<'_>, out: &mut Vec<BronzeEvent>) {
        match self.dissector.parse(chunk.payload, &chunk.context) {
            Some(ProtocolData::Radius(RadiusFields {
                code,
                code_name,
                identifier,
                username,
                nas_ip_address,
                nas_identifier,
                calling_station_id,
                called_station_id,
                nas_port_type,
                framed_ip_address,
                service_type,
            })) => {
                let envelope = build_envelope(
                    &chunk.context,
                    chunk.interface_id,
                    chunk.frame_index,
                    chunk.timestamp,
                    chunk.segment_hash,
                    TransportProtocol::Udp,
                    Some("radius"),
                    chunk.captured_len,
                    chunk.session_key.clone(),
                );

                let mut attributes = BTreeMap::new();
                attributes.insert("identifier".to_string(), identifier.to_string());
                if let Some(ref user) = username {
                    attributes.insert("username".to_string(), user.clone());
                }
                if let Some(ref nas_ip) = nas_ip_address {
                    attributes.insert("nas_ip_address".to_string(), nas_ip.clone());
                }
                if let Some(ref nas_id) = nas_identifier {
                    attributes.insert("nas_identifier".to_string(), nas_id.clone());
                }
                if let Some(ref csi) = calling_station_id {
                    attributes.insert("calling_station_id".to_string(), csi.clone());
                }
                if let Some(ref csi) = called_station_id {
                    attributes.insert("called_station_id".to_string(), csi.clone());
                }
                if let Some(npt) = nas_port_type {
                    attributes.insert("nas_port_type".to_string(), npt.to_string());
                }
                if let Some(ref fip) = framed_ip_address {
                    attributes.insert("framed_ip_address".to_string(), fip.clone());
                }
                if let Some(st) = service_type {
                    attributes.insert("service_type".to_string(), st.to_string());
                }

                let status = match code {
                    2 | 5 | 41 | 44 => "accept",
                    3 | 42 | 45 => "reject",
                    _ => "request",
                };

                let radius_pf = RadiusBronzeFields {
                    code,
                    code_name: code_name.clone(),
                    identifier,
                    username: username.clone(),
                    nas_ip_address: nas_ip_address.clone(),
                    nas_identifier: nas_identifier.clone(),
                    calling_station_id: calling_station_id.clone(),
                    called_station_id: called_station_id.clone(),
                    nas_port_type,
                    framed_ip_address: framed_ip_address.clone(),
                    service_type,
                    direction: status.to_string(),
                };
                out.push(new_event(
                    chunk.capture_id.to_string(),
                    envelope.clone(),
                    BronzeEventFamily::ProtocolTransaction(ProtocolTransaction {
                        operation: code_name.to_lowercase().replace('-', "_"),
                        status: status.to_string(),
                        request_summary: Some(format!(
                            "{code_name} id={identifier}{}",
                            username
                                .as_ref()
                                .map(|u| format!(" user={u}"))
                                .unwrap_or_default()
                        )),
                        response_summary: None,
                        object_refs: username.clone().into_iter().collect(),
                        values: vec![],
                        attributes,
                        modbus: None,
                        protocol_fields: Some(ProtocolFields::Radius(radius_pf)),
                    }),
                ));

                // NAS identification from Access-Request.
                if code == 1
                    && let Some(nas_ip) = nas_ip_address
                {
                    let hostnames = nas_identifier.clone().into_iter().collect();
                    let mut identifiers = BTreeMap::from([("ip".to_string(), nas_ip.clone())]);
                    if let Some(nas_id) = nas_identifier {
                        identifiers.insert("nas_identifier".to_string(), nas_id.clone());
                    }
                    out.push(new_event(
                        chunk.capture_id.to_string(),
                        envelope,
                        BronzeEventFamily::AssetObservation(AssetObservation {
                            asset_key: nas_ip,
                            role: Some("network_device".to_string()),
                            vendor: None,
                            model: None,
                            firmware: None,
                            hostnames,
                            protocols: vec!["radius".to_string()],
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
                    Some("radius"),
                    chunk.captured_len,
                    chunk.session_key.clone(),
                ),
                self.name(),
                "medium",
                "failed to parse radius payload",
                chunk.payload,
            )),
        }
    }
}

// ── ICMP Decoder ──────────────────────────────────────────────

#[derive(Default)]
pub(crate) struct IcmpDecoder {
    dissector: IcmpDissector,
}

impl SessionDecoder for IcmpDecoder {
    fn name(&self) -> &'static str {
        "icmp"
    }

    fn interest(&self) -> &'static [DecoderInterest] {
        &[DecoderInterest::IpProto(1)]
    }

    fn on_datagram(&mut self, chunk: &StreamChunk<'_>, out: &mut Vec<BronzeEvent>) {
        let context = &chunk.context;
        if !self.dissector.can_parse(chunk.payload, 0, 0) {
            return;
        }
        let Some(proto_data) = self.dissector.parse(chunk.payload, context) else {
            return;
        };
        let ProtocolData::Icmp(fields) = &proto_data else {
            return;
        };

        let envelope = build_envelope(
            context,
            chunk.interface_id,
            chunk.frame_index,
            chunk.timestamp,
            chunk.segment_hash,
            TransportProtocol::Icmp,
            Some("icmp"),
            chunk.captured_len,
            chunk.session_key.clone(),
        );

        let mut attrs = BTreeMap::new();
        attrs.insert("icmp_type".to_string(), fields.icmp_type.to_string());
        attrs.insert("icmp_code".to_string(), fields.icmp_code.to_string());
        attrs.insert("type_name".to_string(), fields.type_name.clone());
        if !fields.code_name.is_empty() {
            attrs.insert("code_name".to_string(), fields.code_name.clone());
        }
        if let Some(id) = fields.identifier {
            attrs.insert("identifier".to_string(), id.to_string());
        }
        if let Some(seq) = fields.sequence {
            attrs.insert("sequence".to_string(), seq.to_string());
        }
        if let Some(gw) = &fields.gateway_ip {
            attrs.insert("gateway_ip".to_string(), gw.clone());
        }
        attrs.insert("payload_len".to_string(), fields.payload_len.to_string());

        let operation = fields.type_name.clone();
        let status = if fields.icmp_type == 3 {
            fields.code_name.clone()
        } else {
            "ok".to_string()
        };

        let icmp_pf = IcmpBronzeFields {
            icmp_type: fields.icmp_type,
            icmp_code: fields.icmp_code,
            type_name: fields.type_name.clone(),
            code_name: fields.code_name.clone(),
            identifier: fields.identifier,
            sequence: fields.sequence,
            gateway_ip: fields.gateway_ip.clone(),
            payload_len: fields.payload_len as u32,
        };
        out.push(new_event(
            chunk.capture_id.to_string(),
            envelope,
            BronzeEventFamily::ProtocolTransaction(ProtocolTransaction {
                operation,
                status,
                request_summary: Some(format!(
                    "ICMP type {} code {}",
                    fields.icmp_type, fields.icmp_code
                )),
                response_summary: None,
                object_refs: Vec::new(),
                values: Vec::new(),
                attributes: attrs,
                modbus: None,
                protocol_fields: Some(ProtocolFields::Icmp(icmp_pf)),
            }),
        ));
    }
}

// ── Stovetop finding → BronzeEvent helpers ────────────────────

// ── Inventory registration ──────────────────────────────────────
inventory::submit!(crate::engine::decoders::DecoderRegistration {
    name: "ntp",
    factory: || Box::new(NtpDecoder::default()),
});
inventory::submit!(crate::engine::decoders::DecoderRegistration {
    name: "syslog",
    factory: || Box::new(SyslogDecoder::default()),
});
inventory::submit!(crate::engine::decoders::DecoderRegistration {
    name: "ftp",
    factory: || Box::new(FtpDecoder::default()),
});
inventory::submit!(crate::engine::decoders::DecoderRegistration {
    name: "ssh",
    factory: || Box::new(SshDecoder::default()),
});
inventory::submit!(crate::engine::decoders::DecoderRegistration {
    name: "radius",
    factory: || Box::new(RadiusDecoder::default()),
});
inventory::submit!(crate::engine::decoders::DecoderRegistration {
    name: "icmp",
    factory: || Box::new(IcmpDecoder::default()),
});
