//! Ethernet POWERLINK decoder (EPSG DS 301 V1.5).
//!
//! POWERLINK is a real-time Ethernet motion-control protocol used in European
//! machine-automation builds (B&R Automation, Bachmann, Lenze, Hilscher).
//! It runs directly over Ethernet — EtherType 0x88AB — with no IP layer.
//!
//! # Frame layout (after Ethernet header is stripped)
//!
//! ```text
//! byte 0  : MessageType
//! byte 1  : Destination node ID
//! byte 2  : Source node ID
//! bytes 3+: type-specific payload
//! ```
//!
//! # Node-ID role convention (EPSG DS 301 §7.3.1)
//!
//! | ID range | Role |
//! |----------|------|
//! | 1..=239  | Controlled Node (CN) |
//! | 240 (0xF0) | Managing Node (MN) — the network master |
//! | 241..=254 | Reserved |
//! | 255 (0xFF) | Broadcast — addressed to all nodes |
//!
//! A POWERLINK network has exactly one MN and up to 239 CNs. The MN
//! orchestrates the cyclic schedule (SoC/PReq/PRes/SoA) and handles NMT.

use std::collections::BTreeMap;

use crate::bronze::{
    AssetObservation, BronzeEvent, BronzeEventFamily, ProtocolTransaction, TransportProtocol,
};
use crate::engine::{
    build_envelope, new_event, parse_anomaly_event, DecoderInterest, SessionDecoder, StreamChunk,
};
use crate::registry::format_mac;

// ── Message type constants (EPSG DS 301 Table 1) ──────────────────────────────

const MSGTYPE_SOC: u8 = 0x01; // Start of Cyclic — MN broadcast
const MSGTYPE_PREQ: u8 = 0x03; // Poll Request     — MN → CN unicast
const MSGTYPE_PRES: u8 = 0x04; // Poll Response    — CN → ALL multicast
const MSGTYPE_SOA: u8 = 0x05; // Start of Async   — MN broadcast
const MSGTYPE_ASND: u8 = 0x06; // Async Send       — node sends async data
const MSGTYPE_AINV: u8 = 0x0D; // Async Invite     — newer variant
const MSGTYPE_AMNI: u8 = 0x0E; // Active MN Indication

// ── ASnd ServiceID values (byte 3 of ASnd frames) ────────────────────────────

const SVC_IDENT_RESPONSE: u8 = 0x01;
const SVC_STATUS_RESPONSE: u8 = 0x02;
const SVC_NMT_REQUEST: u8 = 0x03;
const SVC_NMT_COMMAND: u8 = 0x04;
const SVC_SDO: u8 = 0x05;

// ── Node role helpers ─────────────────────────────────────────────────────────

const NODE_MANAGING: u8 = 0xF0; // 240 — the Managing Node
const NODE_BROADCAST: u8 = 0xFF; // 255 — all nodes

/// Returns a human-readable label for a node ID.
fn node_label(id: u8) -> String {
    match id {
        NODE_MANAGING => format!("{id} (managing_node)"),
        NODE_BROADCAST => format!("{id} (broadcast)"),
        1..=239 => format!("{id} (controlled_node)"),
        other => format!("{other} (reserved)"),
    }
}

/// Role string for an `AssetObservation`.
fn node_role(id: u8) -> &'static str {
    match id {
        NODE_MANAGING => "powerlink_managing_node",
        _ => "powerlink_controlled_node",
    }
}

// ── IdentResponse field offsets (relative to byte after ServiceID) ────────────
//
// Offsets match EPSG DS 301 V1.5 Table 3 (IdentResponse payload).

fn read_u16_le(buf: &[u8], off: usize) -> Option<u16> {
    buf.get(off..off + 2)
        .map(|b| u16::from_le_bytes([b[0], b[1]]))
}

fn read_u32_le(buf: &[u8], off: usize) -> Option<u32> {
    buf.get(off..off + 4)
        .map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
}

// ── Decoder ───────────────────────────────────────────────────────────────────

#[derive(Default)]
pub(crate) struct PowerlinkDecoder;

impl SessionDecoder for PowerlinkDecoder {
    fn name(&self) -> &'static str {
        "powerlink"
    }

    fn interest(&self) -> &'static [DecoderInterest] {
        &[DecoderInterest::EtherType(0x88AB)]
    }

    fn on_datagram(&mut self, chunk: &StreamChunk<'_>, out: &mut Vec<BronzeEvent>) {
        let payload = chunk.payload;

        if payload.len() < 3 {
            out.push(parse_anomaly_event(
                chunk.capture_id.to_string(),
                build_envelope(
                    &chunk.context,
                    chunk.interface_id,
                    chunk.frame_index,
                    chunk.timestamp,
                    chunk.segment_hash,
                    TransportProtocol::Ethernet,
                    Some("powerlink"),
                    chunk.captured_len,
                    chunk.session_key.clone(),
                ),
                self.name(),
                "medium",
                "powerlink frame shorter than 3-byte header",
                payload,
            ));
            return;
        }

        let msg_type = payload[0];
        let dst_node = payload[1];
        let src_node = payload[2];
        let type_payload = &payload[3..];

        let envelope = build_envelope(
            &chunk.context,
            chunk.interface_id,
            chunk.frame_index,
            chunk.timestamp,
            chunk.segment_hash,
            TransportProtocol::Ethernet,
            Some("powerlink"),
            chunk.captured_len,
            chunk.session_key.clone(),
        );

        let mut attributes = BTreeMap::new();
        attributes.insert("message_type".to_string(), format!("{msg_type:#04x}"));
        attributes.insert("destination_node".to_string(), node_label(dst_node));
        attributes.insert("source_node".to_string(), node_label(src_node));

        match msg_type {
            MSGTYPE_SOC => {
                out.push(new_event(
                    chunk.capture_id.to_string(),
                    envelope,
                    BronzeEventFamily::ProtocolTransaction(ProtocolTransaction {
                        operation: "powerlink_soc".to_string(),
                        status: "observed".to_string(),
                        request_summary: None,
                        response_summary: None,
                        object_refs: Vec::new(),
                        values: Vec::new(),
                        attributes,
                        modbus: None,
                        protocol_fields: None,
                    }),
                ));
            }

            MSGTYPE_PREQ => {
                out.push(new_event(
                    chunk.capture_id.to_string(),
                    envelope,
                    BronzeEventFamily::ProtocolTransaction(ProtocolTransaction {
                        operation: "powerlink_preq".to_string(),
                        status: "observed".to_string(),
                        request_summary: Some(format!(
                            "MN→CN{dst_node} poll request ({} bytes)",
                            type_payload.len()
                        )),
                        response_summary: None,
                        object_refs: Vec::new(),
                        values: Vec::new(),
                        attributes,
                        modbus: None,
                        protocol_fields: None,
                    }),
                ));
            }

            MSGTYPE_PRES => {
                out.push(new_event(
                    chunk.capture_id.to_string(),
                    envelope,
                    BronzeEventFamily::ProtocolTransaction(ProtocolTransaction {
                        operation: "powerlink_pres".to_string(),
                        status: "observed".to_string(),
                        request_summary: None,
                        response_summary: Some(format!(
                            "CN{src_node} poll response ({} bytes)",
                            type_payload.len()
                        )),
                        object_refs: Vec::new(),
                        values: Vec::new(),
                        attributes,
                        modbus: None,
                        protocol_fields: None,
                    }),
                ));
            }

            MSGTYPE_SOA => {
                out.push(new_event(
                    chunk.capture_id.to_string(),
                    envelope,
                    BronzeEventFamily::ProtocolTransaction(ProtocolTransaction {
                        operation: "powerlink_soa".to_string(),
                        status: "observed".to_string(),
                        request_summary: None,
                        response_summary: None,
                        object_refs: Vec::new(),
                        values: Vec::new(),
                        attributes,
                        modbus: None,
                        protocol_fields: None,
                    }),
                ));
            }

            MSGTYPE_ASND => {
                decode_asnd(chunk, envelope, src_node, type_payload, attributes, out);
            }

            MSGTYPE_AINV => {
                out.push(new_event(
                    chunk.capture_id.to_string(),
                    envelope,
                    BronzeEventFamily::ProtocolTransaction(ProtocolTransaction {
                        operation: "powerlink_ainv".to_string(),
                        status: "observed".to_string(),
                        request_summary: None,
                        response_summary: None,
                        object_refs: Vec::new(),
                        values: Vec::new(),
                        attributes,
                        modbus: None,
                        protocol_fields: None,
                    }),
                ));
            }

            MSGTYPE_AMNI => {
                out.push(new_event(
                    chunk.capture_id.to_string(),
                    envelope,
                    BronzeEventFamily::ProtocolTransaction(ProtocolTransaction {
                        operation: "powerlink_amni".to_string(),
                        status: "observed".to_string(),
                        request_summary: None,
                        response_summary: None,
                        object_refs: Vec::new(),
                        values: Vec::new(),
                        attributes,
                        modbus: None,
                        protocol_fields: None,
                    }),
                ));
            }

            unknown => {
                let operation = format!("powerlink_unknown_msgtype_{unknown:#04x}");
                out.push(new_event(
                    chunk.capture_id.to_string(),
                    envelope.clone(),
                    BronzeEventFamily::ProtocolTransaction(ProtocolTransaction {
                        operation,
                        status: "observed".to_string(),
                        request_summary: None,
                        response_summary: None,
                        object_refs: Vec::new(),
                        values: Vec::new(),
                        attributes,
                        modbus: None,
                        protocol_fields: None,
                    }),
                ));
                out.push(parse_anomaly_event(
                    chunk.capture_id.to_string(),
                    envelope,
                    "powerlink",
                    "low",
                    &format!("unknown POWERLINK MessageType {unknown:#04x}"),
                    payload,
                ));
            }
        }
    }
}

// ── ASnd dispatch ─────────────────────────────────────────────────────────────

fn decode_asnd(
    chunk: &StreamChunk<'_>,
    envelope: crate::bronze::EventEnvelope,
    src_node: u8,
    type_payload: &[u8], // bytes after the 3-byte header
    mut attributes: BTreeMap<String, String>,
    out: &mut Vec<BronzeEvent>,
) {
    // type_payload[0] is the ServiceID byte.
    let service_id = match type_payload.first() {
        Some(&id) => id,
        None => {
            // ASnd with no ServiceID byte — treat as unknown.
            out.push(new_event(
                chunk.capture_id.to_string(),
                envelope,
                BronzeEventFamily::ProtocolTransaction(ProtocolTransaction {
                    operation: "powerlink_asnd_sdo".to_string(),
                    status: "observed".to_string(),
                    request_summary: None,
                    response_summary: None,
                    object_refs: Vec::new(),
                    values: Vec::new(),
                    attributes,
                    modbus: None,
                    protocol_fields: None,
                }),
            ));
            return;
        }
    };

    attributes.insert("asnd_service_id".to_string(), format!("{service_id:#04x}"));
    let svc_payload = &type_payload[1..]; // bytes after ServiceID

    let operation = match service_id {
        SVC_IDENT_RESPONSE => "powerlink_asnd_ident_response",
        SVC_STATUS_RESPONSE => "powerlink_asnd_status_response",
        SVC_NMT_REQUEST => "powerlink_asnd_nmt_request",
        SVC_NMT_COMMAND => "powerlink_asnd_nmt_command",
        SVC_SDO => "powerlink_asnd_sdo",
        _ => "powerlink_asnd_sdo", // fallback for unrecognised service IDs
    };

    out.push(new_event(
        chunk.capture_id.to_string(),
        envelope.clone(),
        BronzeEventFamily::ProtocolTransaction(ProtocolTransaction {
            operation: operation.to_string(),
            status: "observed".to_string(),
            request_summary: None,
            response_summary: None,
            object_refs: Vec::new(),
            values: Vec::new(),
            attributes,
            modbus: None,
            protocol_fields: None,
        }),
    ));

    // Parse IdentResponse for AssetObservation.
    if service_id == SVC_IDENT_RESPONSE {
        if let Some(asset) = parse_ident_response(src_node, svc_payload, chunk) {
            out.push(new_event(
                chunk.capture_id.to_string(),
                envelope,
                BronzeEventFamily::AssetObservation(asset),
            ));
        }
    }
}

// ── IdentResponse parser ──────────────────────────────────────────────────────
//
// svc_payload starts immediately after the ServiceID byte (0x01).
// Field layout follows EPSG DS 301 V1.5 Table 3.
//
// Offset | Size | Field
// -------|------|-------
//      0 |    1 | NMTStatus
//      1 |    1 | IdentResponseFlags
//      2 |    1 | NMTState
//      3 |    1 | (reserved)
//      4 |    4 | EPLProfileVersion
//      8 |    4 | FeatureFlags
//     12 |    2 | MTU (u16 LE)
//     14 |    2 | PollInSize (u16 LE)
//     16 |    2 | PollOutSize (u16 LE)
//     18 |    4 | ResponseTime (u32 LE)
//     22 |    4 | DeviceType (u32 LE)
//     26 |    4 | VendorId (u32 LE)
//     30 |    4 | ProductCode (u32 LE)
//     34 |    4 | RevisionNumber (u32 LE)
//     38 |    4 | SerialNumber (u32 LE)
//     42 |    8 | VendorSpecificExtension
//     50 |   32 | HostName (null-terminated ASCII)

fn parse_ident_response(
    src_node: u8,
    svc_payload: &[u8],
    chunk: &StreamChunk<'_>,
) -> Option<AssetObservation> {
    // Minimum: we need at least up to SerialNumber (42 bytes) for a useful
    // AssetObservation. Anything shorter we still try but gracefully skip
    // missing fields.
    let vendor_id = read_u32_le(svc_payload, 26).unwrap_or(0);
    let product_code = read_u32_le(svc_payload, 30).unwrap_or(0);
    let revision_number = read_u32_le(svc_payload, 34).unwrap_or(0);
    let serial_number = read_u32_le(svc_payload, 38).unwrap_or(0);

    // HostName: 32 bytes at offset 50, null-terminated ASCII.
    let hostname: Option<String> = svc_payload.get(50..82).and_then(|raw| {
        let nul_pos = raw.iter().position(|&b| b == 0).unwrap_or(raw.len());
        let trimmed = &raw[..nul_pos];
        if trimmed.is_empty() {
            None
        } else {
            Some(String::from_utf8_lossy(trimmed).into_owned())
        }
    });

    let asset_key = format!(
        "powerlink_node:{}:{}",
        format_mac(&chunk.context.src_mac),
        src_node
    );

    let mut identifiers = BTreeMap::new();
    identifiers.insert("powerlink_node_id".to_string(), src_node.to_string());
    identifiers.insert("vendor_id".to_string(), format!("{vendor_id:#010x}"));
    identifiers.insert("product_code".to_string(), format!("{product_code:#010x}"));
    identifiers.insert("serial_number".to_string(), format!("{serial_number:#010x}"));

    Some(AssetObservation {
        asset_key,
        role: Some(node_role(src_node).to_string()),
        vendor: Some(format!("VendorID {vendor_id:#010x}")),
        model: Some(format!("ProductCode {product_code:#010x}")),
        firmware: Some(format!("Rev {revision_number:#010x}")),
        hostnames: hostname.into_iter().collect(),
        protocols: vec!["powerlink".to_string()],
        identifiers,
    })
}

// ── Self-registration ─────────────────────────────────────────────────────────

inventory::submit!(crate::engine::decoders::DecoderRegistration {
    name: "powerlink",
    factory: || Box::new(PowerlinkDecoder::default()),
});

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    use chrono::Utc;

    use crate::bronze::{BronzeEventFamily, ParseAnomaly, ProtocolTransaction};
    use crate::engine::{DecoderInterest, SessionDecoder, StreamChunk};
    use crate::registry::PacketContext;

    // ── Helpers ───────────────────────────────────────────────────────────────

    fn make_context() -> PacketContext {
        PacketContext {
            src_mac: [0x00, 0x11, 0x22, 0x33, 0x44, 0x55],
            dst_mac: [0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF],
            src_ip: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            dst_ip: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            src_port: 0,
            dst_port: 0,
            vlan_id: None,
            timestamp: 0,
        }
    }

    fn make_chunk<'a>(payload: &'a [u8], ctx: &'a PacketContext) -> StreamChunk<'a> {
        StreamChunk {
            capture_id: "test_cap",
            segment_hash: "deadbeef",
            interface_id: 0,
            frame_index: 1,
            timestamp: Utc::now(),
            context: ctx.clone(),
            ethertype: 0x88AB,
            ip_proto: None,
            llc: None,
            transport: TransportProtocol::Ethernet,
            payload,
            session_key: "pl-sess-1".to_string(),
            captured_len: payload.len() as u64,
        }
    }

    fn tx(ev: &BronzeEvent) -> &ProtocolTransaction {
        match &ev.family {
            BronzeEventFamily::ProtocolTransaction(t) => t,
            other => panic!("expected ProtocolTransaction, got {other:?}"),
        }
    }

    fn asset(ev: &BronzeEvent) -> &AssetObservation {
        match &ev.family {
            BronzeEventFamily::AssetObservation(a) => a,
            other => panic!("expected AssetObservation, got {other:?}"),
        }
    }

    fn anomaly(ev: &BronzeEvent) -> &ParseAnomaly {
        match &ev.family {
            BronzeEventFamily::ParseAnomaly(a) => a,
            other => panic!("expected ParseAnomaly, got {other:?}"),
        }
    }

    // ── Test 1: SoC from MN (240) to broadcast (255) ──────────────────────────

    #[test]
    fn soc_from_mn_to_broadcast() {
        let mut dec = PowerlinkDecoder::default();
        let mut out = Vec::new();

        // byte 0: SoC (0x01), dst: 0xFF (broadcast), src: 0xF0 (MN)
        let payload = [MSGTYPE_SOC, NODE_BROADCAST, NODE_MANAGING, 0x00, 0x00];
        let ctx = make_context();
        dec.on_datagram(&make_chunk(&payload, &ctx), &mut out);

        assert_eq!(out.len(), 1, "SoC should produce exactly one event");
        let t = tx(&out[0]);
        assert_eq!(t.operation, "powerlink_soc");
        assert_eq!(t.status, "observed");
        assert!(
            t.attributes["source_node"].contains("managing_node"),
            "source should be labelled managing_node"
        );
        assert!(
            t.attributes["destination_node"].contains("broadcast"),
            "destination should be labelled broadcast"
        );
    }

    // ── Test 2: PReq from MN (240) to CN (5) ─────────────────────────────────

    #[test]
    fn preq_from_mn_to_cn5() {
        let mut dec = PowerlinkDecoder::default();
        let mut out = Vec::new();

        // byte 0: PReq (0x03), dst: 5 (CN), src: 0xF0 (MN)
        let payload = [MSGTYPE_PREQ, 5u8, NODE_MANAGING, 0xAB, 0xCD];
        let ctx = make_context();
        dec.on_datagram(&make_chunk(&payload, &ctx), &mut out);

        assert_eq!(out.len(), 1);
        let t = tx(&out[0]);
        assert_eq!(t.operation, "powerlink_preq");
        assert_eq!(t.status, "observed");
        assert!(
            t.attributes["destination_node"].contains("controlled_node"),
            "destination CN should be labelled controlled_node"
        );
        assert!(
            t.attributes["source_node"].contains("managing_node"),
            "source MN should be labelled managing_node"
        );
    }

    // ── Test 3: ASnd IdentResponse with vendor/product/hostname ──────────────

    #[test]
    fn asnd_ident_response_asset_observation() {
        let mut dec = PowerlinkDecoder::default();
        let mut out = Vec::new();

        // Build an ASnd IdentResponse frame.
        // Header: [ASnd, dst=0xFF, src=7]
        // ServiceID: 0x01 (IdentResponse)
        // svc_payload: 82-byte body per spec table
        //   offsets 0..26: placeholders
        //   offset 26..30: VendorId = 0x00000001 (LE)
        //   offset 30..34: ProductCode = 0x00001234 (LE)
        //   offset 34..38: RevisionNumber = 0x00000002 (LE)
        //   offset 38..42: SerialNumber = 0x0000ABCD (LE)
        //   offset 42..50: VendorSpecificExtension (8 bytes, zero)
        //   offset 50..82: HostName "DRIVE01\0" padded to 32 bytes

        let mut svc = [0u8; 82];
        // VendorId at offset 26
        svc[26] = 0x01;
        svc[27] = 0x00;
        svc[28] = 0x00;
        svc[29] = 0x00;
        // ProductCode at offset 30
        svc[30] = 0x34;
        svc[31] = 0x12;
        svc[32] = 0x00;
        svc[33] = 0x00;
        // RevisionNumber at offset 34
        svc[34] = 0x02;
        // SerialNumber at offset 38
        svc[38] = 0xCD;
        svc[39] = 0xAB;
        // HostName at offset 50
        let hostname = b"DRIVE01";
        svc[50..50 + hostname.len()].copy_from_slice(hostname);
        // null terminator at [57] is already 0

        // Full frame: [msgtype, dst, src, service_id, svc_payload...]
        let mut frame = Vec::new();
        frame.push(MSGTYPE_ASND);
        frame.push(NODE_BROADCAST); // dst
        frame.push(7u8); // src = CN 7
        frame.push(SVC_IDENT_RESPONSE);
        frame.extend_from_slice(&svc);

        let ctx = make_context();
        dec.on_datagram(&make_chunk(&frame, &ctx), &mut out);

        // Expect: one ProtocolTransaction + one AssetObservation
        assert_eq!(out.len(), 2, "IdentResponse should emit tx + asset");

        let t = tx(&out[0]);
        assert_eq!(t.operation, "powerlink_asnd_ident_response");
        assert_eq!(t.status, "observed");

        let a = asset(&out[1]);
        assert_eq!(
            a.role.as_deref(),
            Some("powerlink_controlled_node"),
            "CN 7 should have role powerlink_controlled_node"
        );
        assert!(
            a.vendor.as_deref().unwrap_or("").contains("0x00000001"),
            "vendor should embed vendor_id 0x00000001"
        );
        assert!(
            a.model.as_deref().unwrap_or("").contains("0x00001234"),
            "model should embed product_code 0x00001234"
        );
        assert_eq!(
            a.hostnames,
            vec!["DRIVE01".to_string()],
            "hostname should be DRIVE01"
        );
        assert_eq!(
            a.identifiers.get("powerlink_node_id").map(String::as_str),
            Some("7")
        );
    }

    // ── Test 4: Unknown MessageType 0xFF → tx + ParseAnomaly(low) ────────────

    #[test]
    fn unknown_msgtype_emits_anomaly_low() {
        let mut dec = PowerlinkDecoder::default();
        let mut out = Vec::new();

        let payload = [0xFFu8, NODE_BROADCAST, NODE_MANAGING, 0x00];
        let ctx = make_context();
        dec.on_datagram(&make_chunk(&payload, &ctx), &mut out);

        assert_eq!(out.len(), 2, "unknown msgtype should emit tx + anomaly");

        let t = tx(&out[0]);
        assert_eq!(t.operation, "powerlink_unknown_msgtype_0xff");

        let a = anomaly(&out[1]);
        assert_eq!(a.severity, "low");
        assert!(a.reason.contains("0xff"), "anomaly reason should name the unknown type");
    }

    // ── Test 5: Truncated 2-byte frame → ParseAnomaly(medium) ────────────────

    #[test]
    fn truncated_frame_emits_anomaly_medium() {
        let mut dec = PowerlinkDecoder::default();
        let mut out = Vec::new();

        // Only 2 bytes — no source node field, cannot form a valid header.
        let payload = [MSGTYPE_SOC, NODE_BROADCAST];
        let ctx = make_context();
        dec.on_datagram(&make_chunk(&payload, &ctx), &mut out);

        assert_eq!(out.len(), 1, "truncated frame should emit exactly one anomaly");
        let a = anomaly(&out[0]);
        assert_eq!(a.severity, "medium");
        assert!(a.reason.contains("3-byte header"));
    }

    // ── Test 6: interest() advertises EtherType 0x88AB ───────────────────────

    #[test]
    fn decoder_interest_is_ethertype_88ab() {
        let dec = PowerlinkDecoder::default();
        assert!(
            dec.interest()
                .contains(&DecoderInterest::EtherType(0x88AB)),
            "decoder must declare interest in EtherType 0x88AB"
        );
    }
}
