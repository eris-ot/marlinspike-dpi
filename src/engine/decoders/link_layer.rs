//! Layer-2 / link-layer `SessionDecoder` impls.
//!
//! Members: ARP, LLDP, CDP, STP, RSTP, MSTP, PVST+, LACP, PRP, MRP, VTP.
//! Each is a small, mostly-self-contained decoder; they're grouped here
//! because they share the L2 frame surface and have minimal interaction
//! beyond emitting AssetObservation + TopologyObservation events.

use std::collections::BTreeMap;

use crate::bronze::{
    AssetObservation, BronzeEvent, BronzeEventFamily, ProtocolTransaction,
    TopologyObservation, TransportProtocol,
};
use crate::dissectors::arp::ArpDissector;
use crate::dissectors::cdp::CdpDissector;
use crate::dissectors::lacp::LacpDissector;
use crate::dissectors::lldp::LldpDissector;
use crate::dissectors::mrp::MrpDissector;
use crate::dissectors::mstp::MstpDissector;
use crate::dissectors::prp::PrpDissector;
use crate::dissectors::pvst::PvstDissector;
use crate::dissectors::stp::StpDissector;
use crate::dissectors::vtp::VtpDissector;
use crate::engine::{
    build_envelope, new_event, parse_anomaly_event, DecoderInterest, SessionDecoder, StreamChunk,
};
use crate::registry::{
    format_mac, ArpFields, CdpFields, LacpFields, LldpFields, MrpFields,
    PrpFields, ProtocolData, ProtocolDissector, PvstFields, StpFields, VtpFields,
};

#[derive(Default)]
pub(crate) struct ArpDecoder {
    dissector: ArpDissector,
}

impl SessionDecoder for ArpDecoder {
    fn name(&self) -> &'static str {
        "arp"
    }

    fn interest(&self) -> &'static [DecoderInterest] {
        &[DecoderInterest::EtherType(0x0806)]
    }

    fn on_datagram(&mut self, chunk: &StreamChunk<'_>, out: &mut Vec<BronzeEvent>) {
        match self.dissector.parse(chunk.payload, &chunk.context) {
            Some(ProtocolData::Arp(ArpFields {
                sender_mac,
                sender_ip,
                target_mac,
                target_ip,
                operation,
            })) => {
                let envelope = build_envelope(
                    &chunk.context,
                    chunk.interface_id,
                    chunk.frame_index,
                    chunk.timestamp,
                    chunk.segment_hash,
                    TransportProtocol::Arp,
                    Some("arp"),
                    chunk.captured_len,
                    chunk.session_key.clone(),
                );
                let sender_ip = format!(
                    "{}.{}.{}.{}",
                    sender_ip[0], sender_ip[1], sender_ip[2], sender_ip[3]
                );
                let target_ip = format!(
                    "{}.{}.{}.{}",
                    target_ip[0], target_ip[1], target_ip[2], target_ip[3]
                );
                out.push(new_event(
                    chunk.capture_id.to_string(),
                    envelope.clone(),
                    BronzeEventFamily::AssetObservation(AssetObservation {
                        asset_key: format_mac(&sender_mac),
                        role: None,
                        vendor: None,
                        model: None,
                        firmware: None,
                        hostnames: Vec::new(),
                        protocols: vec!["arp".to_string()],
                        identifiers: BTreeMap::from([
                            ("mac".to_string(), format_mac(&sender_mac)),
                            ("ip".to_string(), sender_ip.clone()),
                        ]),
                    }),
                ));
                out.push(new_event(
                    chunk.capture_id.to_string(),
                    envelope,
                    BronzeEventFamily::TopologyObservation(TopologyObservation {
                        observation_type: if operation == 2 {
                            "arp_reply".to_string()
                        } else {
                            "arp_request".to_string()
                        },
                        local_id: sender_ip,
                        remote_id: Some(target_ip),
                        description: Some(format!(
                            "ARP op={operation} {} -> {}",
                            format_mac(&sender_mac),
                            format_mac(&target_mac)
                        )),
                        capabilities: Vec::new(),
                        metadata: BTreeMap::new(),
                    }),
                ));
            }
            _ => out.push(parse_anomaly_event(
                chunk.capture_id.to_string(),
                build_envelope(
                    &chunk.context,
                    chunk.interface_id,
                    chunk.frame_index,
                    chunk.timestamp,
                    chunk.segment_hash,
                    TransportProtocol::Arp,
                    Some("arp"),
                    chunk.captured_len,
                    chunk.session_key.clone(),
                ),
                self.name(),
                "medium",
                "failed to parse arp payload",
                chunk.payload,
            )),
        }
    }
}

#[derive(Default)]
pub(crate) struct LldpDecoder {
    dissector: LldpDissector,
}

impl SessionDecoder for LldpDecoder {
    fn name(&self) -> &'static str {
        "lldp"
    }

    fn interest(&self) -> &'static [DecoderInterest] {
        &[DecoderInterest::EtherType(0x88CC)]
    }

    fn on_datagram(&mut self, chunk: &StreamChunk<'_>, out: &mut Vec<BronzeEvent>) {
        match self.dissector.parse(chunk.payload, &chunk.context) {
            Some(ProtocolData::Lldp(LldpFields {
                chassis_id,
                port_id,
                system_name,
                system_description,
                capabilities,
                ..
            })) => {
                let envelope = build_envelope(
                    &chunk.context,
                    chunk.interface_id,
                    chunk.frame_index,
                    chunk.timestamp,
                    chunk.segment_hash,
                    TransportProtocol::Ethernet,
                    Some("lldp"),
                    chunk.captured_len,
                    chunk.session_key.clone(),
                );
                out.push(new_event(
                    chunk.capture_id.to_string(),
                    envelope.clone(),
                    BronzeEventFamily::AssetObservation(AssetObservation {
                        asset_key: chassis_id.clone(),
                        role: Some("switch".to_string()),
                        vendor: (!system_name.is_empty()).then_some(system_name.clone()),
                        model: (!system_description.is_empty())
                            .then_some(system_description.clone()),
                        firmware: None,
                        hostnames: Vec::new(),
                        protocols: vec!["lldp".to_string()],
                        identifiers: BTreeMap::from([
                            ("chassis_id".to_string(), chassis_id.clone()),
                            ("port_id".to_string(), port_id.clone()),
                        ]),
                    }),
                ));
                out.push(new_event(
                    chunk.capture_id.to_string(),
                    envelope,
                    BronzeEventFamily::TopologyObservation(TopologyObservation {
                        observation_type: "lldp_neighbor".to_string(),
                        local_id: format_mac(&chunk.context.src_mac),
                        remote_id: Some(chassis_id),
                        description: Some(port_id),
                        capabilities,
                        metadata: BTreeMap::new(),
                    }),
                ));
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
                    Some("lldp"),
                    chunk.captured_len,
                    chunk.session_key.clone(),
                ),
                self.name(),
                "medium",
                "failed to parse lldp payload",
                chunk.payload,
            )),
        }
    }
}

#[derive(Default)]
pub(crate) struct CdpDecoder {
    dissector: CdpDissector,
}

impl SessionDecoder for CdpDecoder {
    fn name(&self) -> &'static str {
        "cdp"
    }

    fn interest(&self) -> &'static [DecoderInterest] {
        &[DecoderInterest::Snap {
            oui: [0x00, 0x00, 0x0C],
            pid: 0x2000,
        }]
    }

    fn on_datagram(&mut self, chunk: &StreamChunk<'_>, out: &mut Vec<BronzeEvent>) {
        match self.dissector.parse(chunk.payload, &chunk.context) {
            Some(ProtocolData::Cdp(CdpFields {
                device_id,
                port_id,
                platform,
                software_version,
                capabilities,
                native_vlan,
                duplex,
                ..
            })) => {
                let envelope = build_envelope(
                    &chunk.context,
                    chunk.interface_id,
                    chunk.frame_index,
                    chunk.timestamp,
                    chunk.segment_hash,
                    TransportProtocol::Ethernet,
                    Some("cdp"),
                    chunk.captured_len,
                    chunk.session_key.clone(),
                );
                let role = if capabilities.iter().any(|c| c == "switch") {
                    Some("switch".to_string())
                } else if capabilities.iter().any(|c| c == "router") {
                    Some("router".to_string())
                } else {
                    None
                };
                let mut identifiers = BTreeMap::from([
                    ("mac".to_string(), format_mac(&chunk.context.src_mac)),
                    ("device_id".to_string(), device_id.clone()),
                ]);
                if !port_id.is_empty() {
                    identifiers.insert("port_id".to_string(), port_id.clone());
                }
                if let Some(vlan) = native_vlan {
                    identifiers.insert("native_vlan".to_string(), vlan.to_string());
                }
                out.push(new_event(
                    chunk.capture_id.to_string(),
                    envelope.clone(),
                    BronzeEventFamily::AssetObservation(AssetObservation {
                        asset_key: device_id.clone(),
                        role,
                        vendor: Some("Cisco".to_string()),
                        model: platform,
                        firmware: software_version,
                        hostnames: vec![device_id.clone()],
                        protocols: vec!["cdp".to_string()],
                        identifiers,
                    }),
                ));

                let mut metadata = BTreeMap::new();
                if let Some(vlan) = native_vlan {
                    metadata.insert("native_vlan".to_string(), vlan.to_string());
                }
                if let Some(duplex) = duplex {
                    metadata.insert("duplex".to_string(), duplex);
                }
                out.push(new_event(
                    chunk.capture_id.to_string(),
                    envelope,
                    BronzeEventFamily::TopologyObservation(TopologyObservation {
                        observation_type: "cdp_neighbor".to_string(),
                        local_id: format_mac(&chunk.context.src_mac),
                        remote_id: Some(device_id),
                        description: (!port_id.is_empty()).then_some(port_id),
                        capabilities,
                        metadata,
                    }),
                ));
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
                    Some("cdp"),
                    chunk.captured_len,
                    chunk.session_key.clone(),
                ),
                self.name(),
                "medium",
                "failed to parse cdp payload",
                chunk.payload,
            )),
        }
    }
}

#[derive(Default)]
pub(crate) struct StpDecoder {
    dissector: StpDissector,
}

impl SessionDecoder for StpDecoder {
    fn name(&self) -> &'static str {
        "stp"
    }

    fn interest(&self) -> &'static [DecoderInterest] {
        &[DecoderInterest::Llc {
            dsap: 0x42,
            ssap: 0x42,
        }]
    }

    fn on_datagram(&mut self, chunk: &StreamChunk<'_>, out: &mut Vec<BronzeEvent>) {
        match self.dissector.parse(chunk.payload, &chunk.context) {
            Some(ProtocolData::Stp(StpFields {
                protocol_version,
                bpdu_type,
                flags,
                root_id,
                root_path_cost,
                bridge_id,
                port_id,
                ..
            })) => {
                let envelope = build_envelope(
                    &chunk.context,
                    chunk.interface_id,
                    chunk.frame_index,
                    chunk.timestamp,
                    chunk.segment_hash,
                    TransportProtocol::Ethernet,
                    Some("stp"),
                    chunk.captured_len,
                    chunk.session_key.clone(),
                );
                let mut identifiers = BTreeMap::from([
                    ("mac".to_string(), format_mac(&chunk.context.src_mac)),
                    ("bridge_id".to_string(), bridge_id.clone()),
                    ("root_id".to_string(), root_id.clone()),
                    ("port_id".to_string(), format!("{port_id:#06x}")),
                ]);
                identifiers.insert("root_path_cost".to_string(), root_path_cost.to_string());
                out.push(new_event(
                    chunk.capture_id.to_string(),
                    envelope.clone(),
                    BronzeEventFamily::AssetObservation(AssetObservation {
                        asset_key: bridge_id.clone(),
                        role: Some("switch".to_string()),
                        vendor: None,
                        model: None,
                        firmware: None,
                        hostnames: Vec::new(),
                        protocols: vec!["stp".to_string()],
                        identifiers,
                    }),
                ));

                let mut metadata = BTreeMap::new();
                metadata.insert("protocol_version".to_string(), protocol_version.to_string());
                metadata.insert("bpdu_type".to_string(), format!("{bpdu_type:#04x}"));
                metadata.insert("flags".to_string(), format!("{flags:#04x}"));
                metadata.insert("root_path_cost".to_string(), root_path_cost.to_string());
                metadata.insert("port_id".to_string(), format!("{port_id:#06x}"));
                out.push(new_event(
                    chunk.capture_id.to_string(),
                    envelope,
                    BronzeEventFamily::TopologyObservation(TopologyObservation {
                        observation_type: "stp_topology".to_string(),
                        local_id: bridge_id,
                        remote_id: Some(root_id),
                        description: Some("spanning_tree_bpdu".to_string()),
                        capabilities: Vec::new(),
                        metadata,
                    }),
                ));
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
                    Some("stp"),
                    chunk.captured_len,
                    chunk.session_key.clone(),
                ),
                self.name(),
                "medium",
                "failed to parse stp payload",
                chunk.payload,
            )),
        }
    }
}
// ── VTP decoder ──────────────────────────────────────────────────

#[derive(Default)]
pub(crate) struct VtpDecoder {
    dissector: VtpDissector,
}

impl SessionDecoder for VtpDecoder {
    fn name(&self) -> &'static str {
        "vtp"
    }

    fn interest(&self) -> &'static [DecoderInterest] {
        &[DecoderInterest::Snap {
            oui: [0x00, 0x00, 0x0C],
            pid: 0x2003,
        }]
    }

    fn on_datagram(&mut self, chunk: &StreamChunk<'_>, out: &mut Vec<BronzeEvent>) {
        match self.dissector.parse(chunk.payload, &chunk.context) {
            Some(ProtocolData::Vtp(VtpFields {
                version,
                message_type: _,
                message_type_name,
                domain_name,
                revision,
                vlans,
            })) => {
                let envelope = build_envelope(
                    &chunk.context,
                    chunk.interface_id,
                    chunk.frame_index,
                    chunk.timestamp,
                    chunk.segment_hash,
                    TransportProtocol::Ethernet,
                    Some("vtp"),
                    chunk.captured_len,
                    chunk.session_key.clone(),
                );

                let mut attributes = BTreeMap::new();
                attributes.insert("version".to_string(), version.to_string());
                attributes.insert("domain_name".to_string(), domain_name.clone());
                if let Some(rev) = revision {
                    attributes.insert("revision".to_string(), rev.to_string());
                }
                if !vlans.is_empty() {
                    attributes.insert(
                        "vlans".to_string(),
                        vlans.iter().map(|v| v.to_string()).collect::<Vec<_>>().join(","),
                    );
                }

                out.push(new_event(
                    chunk.capture_id.to_string(),
                    envelope.clone(),
                    BronzeEventFamily::ProtocolTransaction(ProtocolTransaction {
                        operation: message_type_name,
                        status: "ok".to_string(),
                        request_summary: Some(format!("VTP domain={domain_name}")),
                        response_summary: None,
                        object_refs: vec![domain_name.clone()],
                        values: vec![],
                        attributes,
                                        modbus: None,
                                        protocol_fields: None,
}),
                ));

                out.push(new_event(
                    chunk.capture_id.to_string(),
                    envelope,
                    BronzeEventFamily::AssetObservation(AssetObservation {
                        asset_key: format_mac(&chunk.context.src_mac),
                        role: Some("switch".to_string()),
                        vendor: Some("Cisco".to_string()),
                        model: None,
                        firmware: None,
                        hostnames: vec![],
                        protocols: vec!["vtp".to_string()],
                        identifiers: BTreeMap::from([
                            ("mac".to_string(), format_mac(&chunk.context.src_mac)),
                            ("vtp_domain".to_string(), domain_name),
                        ]),
                    }),
                ));
            }
            _ => {}
        }
    }
}

// ── MRP decoder ──────────────────────────────────────────────────

#[derive(Default)]
pub(crate) struct MrpDecoder {
    dissector: MrpDissector,
}

impl SessionDecoder for MrpDecoder {
    fn name(&self) -> &'static str {
        "mrp"
    }

    fn interest(&self) -> &'static [DecoderInterest] {
        &[DecoderInterest::EtherType(0x88E3)]
    }

    fn on_datagram(&mut self, chunk: &StreamChunk<'_>, out: &mut Vec<BronzeEvent>) {
        match self.dissector.parse(chunk.payload, &chunk.context) {
            Some(ProtocolData::Mrp(MrpFields {
                version: _,
                frame_type: _,
                frame_type_name,
                domain_uuid,
                ring_state,
                priority,
                source_mac,
            })) => {
                let envelope = build_envelope(
                    &chunk.context,
                    chunk.interface_id,
                    chunk.frame_index,
                    chunk.timestamp,
                    chunk.segment_hash,
                    TransportProtocol::Ethernet,
                    Some("mrp"),
                    chunk.captured_len,
                    chunk.session_key.clone(),
                );

                let mut metadata = BTreeMap::new();
                if let Some(ref uuid) = domain_uuid {
                    metadata.insert("domain_uuid".to_string(), uuid.clone());
                }
                if let Some(ref state) = ring_state {
                    metadata.insert("ring_state".to_string(), state.clone());
                }
                if let Some(prio) = priority {
                    metadata.insert("priority".to_string(), prio.to_string());
                }

                let local_id = source_mac
                    .clone()
                    .unwrap_or_else(|| format_mac(&chunk.context.src_mac));

                out.push(new_event(
                    chunk.capture_id.to_string(),
                    envelope.clone(),
                    BronzeEventFamily::TopologyObservation(TopologyObservation {
                        observation_type: format!("mrp_{}", frame_type_name.to_lowercase()),
                        local_id: local_id.clone(),
                        remote_id: domain_uuid,
                        description: ring_state.clone(),
                        capabilities: vec!["mrp".to_string()],
                        metadata,
                    }),
                ));

                out.push(new_event(
                    chunk.capture_id.to_string(),
                    envelope,
                    BronzeEventFamily::AssetObservation(AssetObservation {
                        asset_key: local_id,
                        role: Some("switch".to_string()),
                        vendor: None,
                        model: None,
                        firmware: None,
                        hostnames: vec![],
                        protocols: vec!["mrp".to_string()],
                        identifiers: BTreeMap::from([(
                            "mac".to_string(),
                            format_mac(&chunk.context.src_mac),
                        )]),
                    }),
                ));
            }
            _ => {}
        }
    }
}

// ── MSTP decoder ─────────────────────────────────────────────────

#[derive(Default)]
pub(crate) struct MstpDecoder {
    dissector: MstpDissector,
}

impl SessionDecoder for MstpDecoder {
    fn name(&self) -> &'static str {
        "mstp"
    }

    fn interest(&self) -> &'static [DecoderInterest] {
        &[DecoderInterest::Llc {
            dsap: 0x42,
            ssap: 0x42,
        }]
    }

    fn on_datagram(&mut self, chunk: &StreamChunk<'_>, out: &mut Vec<BronzeEvent>) {
        // Only handle version >= 3; regular STP/RSTP falls through to StpDecoder.
        let fields = match self.dissector.parse(chunk.payload, &chunk.context) {
            Some(ProtocolData::Mstp(f)) => f,
            _ => return,
        };

        let envelope = build_envelope(
            &chunk.context,
            chunk.interface_id,
            chunk.frame_index,
            chunk.timestamp,
            chunk.segment_hash,
            TransportProtocol::Ethernet,
            Some("mstp"),
            chunk.captured_len,
            chunk.session_key.clone(),
        );

        let mut metadata = BTreeMap::new();
        metadata.insert("protocol_version".to_string(), fields.protocol_version.to_string());
        if let Some(ref name) = fields.config_name {
            metadata.insert("config_name".to_string(), name.clone());
        }
        if let Some(rev) = fields.revision_level {
            metadata.insert("revision_level".to_string(), rev.to_string());
        }
        metadata.insert("msti_count".to_string(), fields.msti_records.len().to_string());

        out.push(new_event(
            chunk.capture_id.to_string(),
            envelope.clone(),
            BronzeEventFamily::TopologyObservation(TopologyObservation {
                observation_type: "mstp_bpdu".to_string(),
                local_id: fields.bridge_id.clone(),
                remote_id: Some(fields.root_id.clone()),
                description: fields.config_name.clone(),
                capabilities: vec!["mstp".to_string()],
                metadata,
            }),
        ));

        out.push(new_event(
            chunk.capture_id.to_string(),
            envelope,
            BronzeEventFamily::AssetObservation(AssetObservation {
                asset_key: fields.bridge_id.clone(),
                role: Some("switch".to_string()),
                vendor: None,
                model: None,
                firmware: None,
                hostnames: vec![],
                protocols: vec!["mstp".to_string()],
                identifiers: BTreeMap::from([
                    ("mac".to_string(), format_mac(&chunk.context.src_mac)),
                    ("bridge_id".to_string(), fields.bridge_id),
                ]),
            }),
        ));
    }
}

// ── PVST+ decoder ────────────────────────────────────────────────

#[derive(Default)]
pub(crate) struct PvstDecoder {
    dissector: PvstDissector,
}

impl SessionDecoder for PvstDecoder {
    fn name(&self) -> &'static str {
        "pvst"
    }

    fn interest(&self) -> &'static [DecoderInterest] {
        &[DecoderInterest::Snap {
            oui: [0x00, 0x00, 0x0C],
            pid: 0x010B,
        }]
    }

    fn on_datagram(&mut self, chunk: &StreamChunk<'_>, out: &mut Vec<BronzeEvent>) {
        match self.dissector.parse(chunk.payload, &chunk.context) {
            Some(ProtocolData::Pvst(PvstFields {
                protocol_version,
                bpdu_type: _,
                flags: _,
                root_id,
                root_path_cost,
                bridge_id,
                port_id,
                originating_vlan,
            })) => {
                let envelope = build_envelope(
                    &chunk.context,
                    chunk.interface_id,
                    chunk.frame_index,
                    chunk.timestamp,
                    chunk.segment_hash,
                    TransportProtocol::Ethernet,
                    Some("pvst"),
                    chunk.captured_len,
                    chunk.session_key.clone(),
                );

                let mut metadata = BTreeMap::new();
                metadata.insert("protocol_version".to_string(), protocol_version.to_string());
                metadata.insert("root_path_cost".to_string(), root_path_cost.to_string());
                metadata.insert("port_id".to_string(), format!("{port_id:#06x}"));
                if let Some(vlan) = originating_vlan {
                    metadata.insert("originating_vlan".to_string(), vlan.to_string());
                }

                out.push(new_event(
                    chunk.capture_id.to_string(),
                    envelope.clone(),
                    BronzeEventFamily::TopologyObservation(TopologyObservation {
                        observation_type: "pvst_bpdu".to_string(),
                        local_id: bridge_id.clone(),
                        remote_id: Some(root_id),
                        description: originating_vlan.map(|v| format!("VLAN {v}")),
                        capabilities: vec!["pvst".to_string()],
                        metadata,
                    }),
                ));

                let mut identifiers = BTreeMap::from([
                    ("mac".to_string(), format_mac(&chunk.context.src_mac)),
                    ("bridge_id".to_string(), bridge_id.clone()),
                ]);
                if let Some(vlan) = originating_vlan {
                    identifiers.insert("originating_vlan".to_string(), vlan.to_string());
                }

                out.push(new_event(
                    chunk.capture_id.to_string(),
                    envelope,
                    BronzeEventFamily::AssetObservation(AssetObservation {
                        asset_key: bridge_id,
                        role: Some("switch".to_string()),
                        vendor: Some("Cisco".to_string()),
                        model: None,
                        firmware: None,
                        hostnames: vec![],
                        protocols: vec!["pvst".to_string()],
                        identifiers,
                    }),
                ));
            }
            _ => {}
        }
    }
}

// ── PRP decoder ──────────────────────────────────────────────────

#[derive(Default)]
pub(crate) struct PrpDecoder {
    dissector: PrpDissector,
}

impl SessionDecoder for PrpDecoder {
    fn name(&self) -> &'static str {
        "prp"
    }

    fn interest(&self) -> &'static [DecoderInterest] {
        &[DecoderInterest::EtherType(0x88FB)]
    }

    fn on_datagram(&mut self, chunk: &StreamChunk<'_>, out: &mut Vec<BronzeEvent>) {
        match self.dissector.parse(chunk.payload, &chunk.context) {
            Some(ProtocolData::Prp(PrpFields {
                supervision_type_name,
                source_mac,
                red_box_mac,
                sequence_nr,
                ..
            })) => {
                let envelope = build_envelope(
                    &chunk.context,
                    chunk.interface_id,
                    chunk.frame_index,
                    chunk.timestamp,
                    chunk.segment_hash,
                    TransportProtocol::Ethernet,
                    Some("prp"),
                    chunk.captured_len,
                    chunk.session_key.clone(),
                );

                let local_id = source_mac
                    .clone()
                    .unwrap_or_else(|| format_mac(&chunk.context.src_mac));

                let mut metadata = BTreeMap::new();
                if let Some(seq) = sequence_nr {
                    metadata.insert("sequence_nr".to_string(), seq.to_string());
                }
                if let Some(ref rb) = red_box_mac {
                    metadata.insert("red_box_mac".to_string(), rb.clone());
                }

                out.push(new_event(
                    chunk.capture_id.to_string(),
                    envelope.clone(),
                    BronzeEventFamily::TopologyObservation(TopologyObservation {
                        observation_type: format!(
                            "prp_{}",
                            supervision_type_name.to_lowercase()
                        ),
                        local_id: local_id.clone(),
                        remote_id: red_box_mac,
                        description: Some("PRP supervision".to_string()),
                        capabilities: vec!["prp".to_string()],
                        metadata,
                    }),
                ));

                out.push(new_event(
                    chunk.capture_id.to_string(),
                    envelope,
                    BronzeEventFamily::AssetObservation(AssetObservation {
                        asset_key: local_id,
                        role: Some("prp_node".to_string()),
                        vendor: None,
                        model: None,
                        firmware: None,
                        hostnames: vec![],
                        protocols: vec!["prp".to_string()],
                        identifiers: BTreeMap::from([(
                            "mac".to_string(),
                            format_mac(&chunk.context.src_mac),
                        )]),
                    }),
                ));
            }
            _ => {}
        }
    }
}

// ── LACP decoder ─────────────────────────────────────────────────

#[derive(Default)]
pub(crate) struct LacpDecoder {
    dissector: LacpDissector,
}

impl SessionDecoder for LacpDecoder {
    fn name(&self) -> &'static str {
        "lacp"
    }

    fn interest(&self) -> &'static [DecoderInterest] {
        &[DecoderInterest::EtherType(0x8809)]
    }

    fn on_datagram(&mut self, chunk: &StreamChunk<'_>, out: &mut Vec<BronzeEvent>) {
        match self.dissector.parse(chunk.payload, &chunk.context) {
            Some(ProtocolData::Lacp(LacpFields {
                version: _,
                ref actor,
                ref partner,
                max_delay,
            })) => {
                let envelope = build_envelope(
                    &chunk.context,
                    chunk.interface_id,
                    chunk.frame_index,
                    chunk.timestamp,
                    chunk.segment_hash,
                    TransportProtocol::Ethernet,
                    Some("lacp"),
                    chunk.captured_len,
                    chunk.session_key.clone(),
                );

                let mut metadata = BTreeMap::new();
                metadata.insert("actor_system".to_string(), actor.system.clone());
                metadata.insert("actor_key".to_string(), actor.key.to_string());
                metadata.insert("actor_port".to_string(), actor.port.to_string());
                metadata.insert("partner_system".to_string(), partner.system.clone());
                metadata.insert("partner_key".to_string(), partner.key.to_string());
                metadata.insert("partner_port".to_string(), partner.port.to_string());
                if let Some(delay) = max_delay {
                    metadata.insert("max_delay".to_string(), delay.to_string());
                }

                out.push(new_event(
                    chunk.capture_id.to_string(),
                    envelope.clone(),
                    BronzeEventFamily::TopologyObservation(TopologyObservation {
                        observation_type: "lacp_bond".to_string(),
                        local_id: actor.system.clone(),
                        remote_id: Some(partner.system.clone()),
                        description: Some(format!(
                            "key={} port={} <-> key={} port={}",
                            actor.key, actor.port, partner.key, partner.port
                        )),
                        capabilities: actor.state_flags.clone(),
                        metadata,
                    }),
                ));

                // Identify both actor and partner as switches.
                for (sys_mac, role_prefix) in
                    [(&actor.system, "actor"), (&partner.system, "partner")]
                {
                    out.push(new_event(
                        chunk.capture_id.to_string(),
                        envelope.clone(),
                        BronzeEventFamily::AssetObservation(AssetObservation {
                            asset_key: sys_mac.clone(),
                            role: Some("switch".to_string()),
                            vendor: None,
                            model: None,
                            firmware: None,
                            hostnames: vec![],
                            protocols: vec!["lacp".to_string()],
                            identifiers: BTreeMap::from([
                                ("system".to_string(), sys_mac.clone()),
                                ("lacp_role".to_string(), role_prefix.to_string()),
                            ]),
                        }),
                    ));
                }
            }
            _ => {}
        }
    }
}


// ── Inventory registration ──────────────────────────────────────
inventory::submit!(crate::engine::decoders::DecoderRegistration {
    name: "arp",
    factory: || Box::new(ArpDecoder::default()),
});
inventory::submit!(crate::engine::decoders::DecoderRegistration {
    name: "lldp",
    factory: || Box::new(LldpDecoder::default()),
});
inventory::submit!(crate::engine::decoders::DecoderRegistration {
    name: "cdp",
    factory: || Box::new(CdpDecoder::default()),
});
inventory::submit!(crate::engine::decoders::DecoderRegistration {
    name: "stp",
    factory: || Box::new(StpDecoder::default()),
});
inventory::submit!(crate::engine::decoders::DecoderRegistration {
    name: "vtp",
    factory: || Box::new(VtpDecoder::default()),
});
inventory::submit!(crate::engine::decoders::DecoderRegistration {
    name: "mrp",
    factory: || Box::new(MrpDecoder::default()),
});
inventory::submit!(crate::engine::decoders::DecoderRegistration {
    name: "mstp",
    factory: || Box::new(MstpDecoder::default()),
});
inventory::submit!(crate::engine::decoders::DecoderRegistration {
    name: "pvst",
    factory: || Box::new(PvstDecoder::default()),
});
inventory::submit!(crate::engine::decoders::DecoderRegistration {
    name: "prp",
    factory: || Box::new(PrpDecoder::default()),
});
inventory::submit!(crate::engine::decoders::DecoderRegistration {
    name: "lacp",
    factory: || Box::new(LacpDecoder::default()),
});
