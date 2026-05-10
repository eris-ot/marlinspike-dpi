//! OPC UA PubSub (UADP over UDP) decoder — Phase 6 DPI.
//!
//! Decodes UADP NetworkMessage headers (Part 14 §7.2) arriving on UDP 4840.
//! Emits one `ProtocolTransaction` per datagram and a `TopologyObservation`
//! per unique publisher_id seen on the session. Dataset payload decoding
//! (DataSetMessages) is deferred to a future phase.

use std::collections::{BTreeMap, HashSet};

use crate::bronze::{
    BronzeEvent, BronzeEventFamily, ProtocolTransaction, TopologyObservation, TransportProtocol,
};
use crate::engine::{
    build_envelope, new_event, parse_anomaly_event, DecoderInterest, SessionDecoder, StreamChunk,
};

// ── Publisher ID type codes (ExtendedFlags1 bits 0..2) ──────────────────────

const PID_TYPE_BYTE: u8 = 0;
const PID_TYPE_UINT16: u8 = 1;
const PID_TYPE_UINT32: u8 = 2;
const PID_TYPE_UINT64: u8 = 3;
const PID_TYPE_STRING: u8 = 4;

// ── Decoder state ────────────────────────────────────────────────────────────

pub(crate) struct OpcUaPubSubDecoder {
    /// Publisher IDs already emitted as TopologyObservations this session.
    seen_publishers: HashSet<String>,
}

impl Default for OpcUaPubSubDecoder {
    fn default() -> Self {
        Self {
            seen_publishers: HashSet::new(),
        }
    }
}

// ── Wire parsing ─────────────────────────────────────────────────────────────

/// Parsed UADP NetworkMessage header fields.
struct NetworkMessageHeader {
    ua_version: u8,
    publisher_id: Option<String>,
    publisher_id_type: Option<&'static str>,
    dataset_class_id: Option<String>,
    writer_group_id: Option<u16>,
    group_version: Option<u32>,
    network_message_number: Option<u16>,
    sequence_number: Option<u16>,
    dataset_writer_ids: Vec<u16>,
}

/// Attempt to parse a UADP NetworkMessage from `buf`.
///
/// Returns `Ok(header)` on success, `Err(reason)` on truncation or structural
/// error (the caller emits a `ParseAnomaly`).
fn parse_network_message(buf: &[u8]) -> Result<NetworkMessageHeader, &'static str> {
    if buf.is_empty() {
        return Err("empty datagram");
    }

    let flags1 = buf[0];
    let ua_version = flags1 & 0x0F;
    let publisher_id_enabled = (flags1 >> 4) & 1 == 1;
    let group_header_enabled = (flags1 >> 5) & 1 == 1;
    let payload_header_enabled = (flags1 >> 6) & 1 == 1;
    let extended_flags1_enabled = (flags1 >> 7) & 1 == 1;

    let mut cursor = 1usize;

    // — ExtendedFlags1 ————————————————————————————————————————————
    let (pid_type, dataset_class_id_enabled, extended_flags2_enabled) =
        if extended_flags1_enabled {
            if buf.len() < cursor + 1 {
                return Err("truncated: missing ExtendedFlags1");
            }
            let f2 = buf[cursor];
            cursor += 1;
            let pid_type = f2 & 0x07;
            let dataset_class_id_enabled = (f2 >> 3) & 1 == 1;
            let extended_flags2_enabled = (f2 >> 7) & 1 == 1;
            (pid_type, dataset_class_id_enabled, extended_flags2_enabled)
        } else {
            (PID_TYPE_BYTE, false, false)
        };

    // — ExtendedFlags2 ————————————————————————————————————————————
    if extended_flags2_enabled {
        if buf.len() < cursor + 1 {
            return Err("truncated: missing ExtendedFlags2");
        }
        cursor += 1; // consume flags3; fields within are not decoded in v1
    }

    // — PublisherId ———————————————————————————————————————————————
    let (publisher_id, publisher_id_type) = if publisher_id_enabled {
        match pid_type {
            PID_TYPE_BYTE => {
                if buf.len() < cursor + 1 {
                    return Err("truncated: missing PublisherId (Byte)");
                }
                let v = buf[cursor];
                cursor += 1;
                (Some(v.to_string()), Some("byte"))
            }
            PID_TYPE_UINT16 => {
                if buf.len() < cursor + 2 {
                    return Err("truncated: missing PublisherId (UInt16)");
                }
                let v = u16::from_le_bytes([buf[cursor], buf[cursor + 1]]);
                cursor += 2;
                (Some(v.to_string()), Some("uint16"))
            }
            PID_TYPE_UINT32 => {
                if buf.len() < cursor + 4 {
                    return Err("truncated: missing PublisherId (UInt32)");
                }
                let v = u32::from_le_bytes([
                    buf[cursor],
                    buf[cursor + 1],
                    buf[cursor + 2],
                    buf[cursor + 3],
                ]);
                cursor += 4;
                (Some(v.to_string()), Some("uint32"))
            }
            PID_TYPE_UINT64 => {
                if buf.len() < cursor + 8 {
                    return Err("truncated: missing PublisherId (UInt64)");
                }
                let v = u64::from_le_bytes([
                    buf[cursor],
                    buf[cursor + 1],
                    buf[cursor + 2],
                    buf[cursor + 3],
                    buf[cursor + 4],
                    buf[cursor + 5],
                    buf[cursor + 6],
                    buf[cursor + 7],
                ]);
                cursor += 8;
                (Some(v.to_string()), Some("uint64"))
            }
            PID_TYPE_STRING => {
                if buf.len() < cursor + 4 {
                    return Err("truncated: missing PublisherId string length");
                }
                let len = i32::from_le_bytes([
                    buf[cursor],
                    buf[cursor + 1],
                    buf[cursor + 2],
                    buf[cursor + 3],
                ]);
                cursor += 4;
                if len < 0 {
                    // Null string — treat as empty publisher id
                    (Some(String::new()), Some("string"))
                } else {
                    let len = len as usize;
                    if buf.len() < cursor + len {
                        return Err("truncated: missing PublisherId string bytes");
                    }
                    let s = String::from_utf8_lossy(&buf[cursor..cursor + len]).into_owned();
                    cursor += len;
                    (Some(s), Some("string"))
                }
            }
            _ => {
                // Unknown type — skip publisher_id, note unknown type
                (None, Some("unknown"))
            }
        }
    } else {
        (None, None)
    };

    // — DataSetClassId (16-byte GUID) —————————————————————————————
    let dataset_class_id = if dataset_class_id_enabled {
        if buf.len() < cursor + 16 {
            return Err("truncated: missing DataSetClassId");
        }
        let guid_bytes = &buf[cursor..cursor + 16];
        cursor += 16;
        // Format as uppercase hex groups: {XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX}
        let hex = hex_guid(guid_bytes);
        Some(hex)
    } else {
        None
    };

    // — GroupHeader ———————————————————————————————————————————————
    let (writer_group_id, group_version, network_message_number, sequence_number) =
        if group_header_enabled {
            if buf.len() < cursor + 1 {
                return Err("truncated: missing GroupHeader flags");
            }
            let gh_flags = buf[cursor];
            cursor += 1;
            let has_writer_group_id = gh_flags & 0x01 != 0;
            let has_group_version = (gh_flags >> 1) & 1 != 0;
            let has_network_msg_number = (gh_flags >> 2) & 1 != 0;
            let has_sequence_number = (gh_flags >> 3) & 1 != 0;

            let writer_group_id = if has_writer_group_id {
                if buf.len() < cursor + 2 {
                    return Err("truncated: missing WriterGroupId");
                }
                let v = u16::from_le_bytes([buf[cursor], buf[cursor + 1]]);
                cursor += 2;
                Some(v)
            } else {
                None
            };

            let group_version = if has_group_version {
                if buf.len() < cursor + 4 {
                    return Err("truncated: missing GroupVersion");
                }
                let v = u32::from_le_bytes([
                    buf[cursor],
                    buf[cursor + 1],
                    buf[cursor + 2],
                    buf[cursor + 3],
                ]);
                cursor += 4;
                Some(v)
            } else {
                None
            };

            let network_message_number = if has_network_msg_number {
                if buf.len() < cursor + 2 {
                    return Err("truncated: missing NetworkMessageNumber");
                }
                let v = u16::from_le_bytes([buf[cursor], buf[cursor + 1]]);
                cursor += 2;
                Some(v)
            } else {
                None
            };

            let sequence_number = if has_sequence_number {
                if buf.len() < cursor + 2 {
                    return Err("truncated: missing SequenceNumber");
                }
                let v = u16::from_le_bytes([buf[cursor], buf[cursor + 1]]);
                cursor += 2;
                Some(v)
            } else {
                None
            };

            (
                writer_group_id,
                group_version,
                network_message_number,
                sequence_number,
            )
        } else {
            (None, None, None, None)
        };

    // — PayloadHeader ————————————————————————————————————————————
    let dataset_writer_ids = if payload_header_enabled {
        if buf.len() < cursor + 1 {
            return Err("truncated: missing PayloadHeader count");
        }
        let count = buf[cursor] as usize;
        cursor += 1;
        if buf.len() < cursor + count * 2 {
            return Err("truncated: missing DataSetWriterIds");
        }
        let mut ids = Vec::with_capacity(count);
        for i in 0..count {
            let off = cursor + i * 2;
            ids.push(u16::from_le_bytes([buf[off], buf[off + 1]]));
        }
        // cursor advances past the DataSetWriterIds; DataSetMessages are not decoded
        ids
    } else {
        Vec::new()
    };

    Ok(NetworkMessageHeader {
        ua_version,
        publisher_id,
        publisher_id_type,
        dataset_class_id,
        writer_group_id,
        group_version,
        network_message_number,
        sequence_number,
        dataset_writer_ids,
    })
}

/// Format 16 raw GUID bytes as uppercase `{XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX}`.
fn hex_guid(b: &[u8]) -> String {
    // OPC UA GUID wire order: Data1 (4B LE), Data2 (2B LE), Data3 (2B LE),
    // Data4[0..8] (8B big-endian).
    let d1 = u32::from_le_bytes([b[0], b[1], b[2], b[3]]);
    let d2 = u16::from_le_bytes([b[4], b[5]]);
    let d3 = u16::from_le_bytes([b[6], b[7]]);
    format!(
        "{{{:08X}-{:04X}-{:04X}-{:02X}{:02X}-{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}}}",
        d1, d2, d3, b[8], b[9], b[10], b[11], b[12], b[13], b[14], b[15]
    )
}

// ── SessionDecoder impl ──────────────────────────────────────────────────────

impl SessionDecoder for OpcUaPubSubDecoder {
    fn name(&self) -> &'static str {
        "opc_ua_pubsub"
    }

    fn interest(&self) -> &'static [DecoderInterest] {
        &[DecoderInterest::UdpPort(4840)]
    }

    fn on_datagram(&mut self, chunk: &StreamChunk<'_>, out: &mut Vec<BronzeEvent>) {
        let envelope = build_envelope(
            &chunk.context,
            chunk.interface_id,
            chunk.frame_index,
            chunk.timestamp,
            chunk.segment_hash,
            TransportProtocol::Udp,
            Some("opc_ua_pubsub"),
            chunk.captured_len,
            chunk.session_key.clone(),
        );

        let hdr = match parse_network_message(chunk.payload) {
            Ok(h) => h,
            Err(reason) => {
                out.push(parse_anomaly_event(
                    chunk.capture_id.to_string(),
                    envelope,
                    self.name(),
                    "low",
                    reason,
                    chunk.payload,
                ));
                return;
            }
        };

        // Version anomaly — still emit the transaction, then append anomaly.
        let version_anomaly = hdr.ua_version != 1;

        // Build attributes map.
        let mut attributes = BTreeMap::new();
        attributes.insert("ua_version".to_string(), hdr.ua_version.to_string());

        if let Some(ref pid) = hdr.publisher_id {
            attributes.insert("publisher_id".to_string(), pid.clone());
        }
        if let Some(pid_type) = hdr.publisher_id_type {
            attributes.insert("publisher_id_type".to_string(), pid_type.to_string());
        }
        if let Some(wgid) = hdr.writer_group_id {
            attributes.insert("writer_group_id".to_string(), wgid.to_string());
        }
        if let Some(gv) = hdr.group_version {
            attributes.insert("group_version".to_string(), gv.to_string());
        }
        if let Some(nmn) = hdr.network_message_number {
            attributes.insert("network_message_number".to_string(), nmn.to_string());
        }
        if let Some(sn) = hdr.sequence_number {
            attributes.insert("sequence_number".to_string(), sn.to_string());
        }
        if let Some(ref guid) = hdr.dataset_class_id {
            attributes.insert("dataset_class_id".to_string(), guid.clone());
        }

        attributes.insert(
            "dataset_writer_count".to_string(),
            hdr.dataset_writer_ids.len().to_string(),
        );
        if !hdr.dataset_writer_ids.is_empty() {
            attributes.insert(
                "dataset_writer_ids".to_string(),
                hdr.dataset_writer_ids
                    .iter()
                    .map(|id| id.to_string())
                    .collect::<Vec<_>>()
                    .join(","),
            );
        }

        out.push(new_event(
            chunk.capture_id.to_string(),
            envelope.clone(),
            BronzeEventFamily::ProtocolTransaction(ProtocolTransaction {
                operation: "opc_ua_pubsub_publish".to_string(),
                status: "observed".to_string(),
                request_summary: Some(format!(
                    "UADP NetworkMessage v{} publisher={}",
                    hdr.ua_version,
                    hdr.publisher_id.as_deref().unwrap_or("<none>")
                )),
                response_summary: None,
                object_refs: vec![],
                values: vec![],
                attributes,
                modbus: None,
                protocol_fields: None,
            }),
        ));

        if version_anomaly {
            out.push(parse_anomaly_event(
                chunk.capture_id.to_string(),
                envelope.clone(),
                self.name(),
                "medium",
                "unexpected UADP ua_version (expected 1)",
                chunk.payload,
            ));
        }

        // TopologyObservation — once per unique publisher_id per session.
        if let Some(ref pid_str) = hdr.publisher_id {
            if self.seen_publishers.insert(pid_str.clone()) {
                let mut metadata = BTreeMap::new();
                if !hdr.dataset_writer_ids.is_empty() {
                    metadata.insert(
                        "dataset_writer_ids".to_string(),
                        hdr.dataset_writer_ids
                            .iter()
                            .map(|id| id.to_string())
                            .collect::<Vec<_>>()
                            .join(","),
                    );
                }
                if let Some(wgid) = hdr.writer_group_id {
                    metadata.insert("writer_group_id".to_string(), wgid.to_string());
                }

                out.push(new_event(
                    chunk.capture_id.to_string(),
                    envelope,
                    BronzeEventFamily::TopologyObservation(TopologyObservation {
                        observation_type: "opc_ua_pubsub_publisher".to_string(),
                        local_id: pid_str.clone(),
                        remote_id: None,
                        description: Some("OPC UA PubSub publisher".to_string()),
                        capabilities: vec![],
                        metadata,
                    }),
                ));
            }
        }
    }
}

// ── Inventory registration ───────────────────────────────────────────────────

inventory::submit!(crate::engine::decoders::DecoderRegistration {
    name: "opc_ua_pubsub",
    factory: || Box::new(OpcUaPubSubDecoder::default()),
});

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bronze::BronzeEventFamily;
    use crate::engine::StreamChunk;
    use crate::engine::TransportProtocol;
    use crate::registry::PacketContext;
    use chrono::Utc;
    use std::net::{IpAddr, Ipv4Addr};

    // ── Helpers ───────────────────────────────────────────────────────────────

    fn dummy_context() -> PacketContext {
        PacketContext {
            src_ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10)),
            dst_ip: IpAddr::V4(Ipv4Addr::new(224, 0, 2, 14)),
            src_port: 54321,
            dst_port: 4840,
            src_mac: [0x00, 0x1A, 0x2B, 0x3C, 0x4D, 0x5E],
            dst_mac: [0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF],
            vlan_id: None,
            timestamp: 0,
        }
    }

    fn make_chunk<'a>(payload: &'a [u8], context: &'a PacketContext) -> StreamChunk<'a> {
        StreamChunk {
            capture_id: "test-cap",
            segment_hash: "seg",
            interface_id: 0,
            frame_index: 0,
            timestamp: Utc::now(),
            context: context.clone(),
            ethertype: 0x0800,
            ip_proto: Some(17),
            llc: None,
            transport: TransportProtocol::Udp,
            payload,
            session_key: "session-key".to_string(),
            captured_len: payload.len() as u64,
        }
    }

    fn run_decoder(payload: &[u8]) -> Vec<BronzeEvent> {
        let mut decoder = OpcUaPubSubDecoder::default();
        let ctx = dummy_context();
        let chunk = make_chunk(payload, &ctx);
        let mut out = Vec::new();
        decoder.on_datagram(&chunk, &mut out);
        out
    }

    fn get_transaction(events: &[BronzeEvent]) -> Option<&ProtocolTransaction> {
        events.iter().find_map(|e| {
            if let BronzeEventFamily::ProtocolTransaction(tx) = &e.family {
                Some(tx)
            } else {
                None
            }
        })
    }

    fn get_anomalies(events: &[BronzeEvent]) -> Vec<&crate::bronze::ParseAnomaly> {
        events
            .iter()
            .filter_map(|e| {
                if let BronzeEventFamily::ParseAnomaly(a) = &e.family {
                    Some(a)
                } else {
                    None
                }
            })
            .collect()
    }

    fn get_topology(events: &[BronzeEvent]) -> Vec<&TopologyObservation> {
        events
            .iter()
            .filter_map(|e| {
                if let BronzeEventFamily::TopologyObservation(t) = &e.family {
                    Some(t)
                } else {
                    None
                }
            })
            .collect()
    }

    // ── Test 1: minimal NetworkMessage — no optional flags ────────────────────

    #[test]
    fn minimal_no_flags() {
        // flags1 = 0x01 — ua_version=1, all optional fields disabled.
        let payload = &[0x01u8];
        let events = run_decoder(payload);

        let tx = get_transaction(&events).expect("should emit ProtocolTransaction");
        assert_eq!(tx.operation, "opc_ua_pubsub_publish");
        assert_eq!(tx.status, "observed");
        assert_eq!(tx.attributes["ua_version"], "1");

        let anomalies = get_anomalies(&events);
        assert!(anomalies.is_empty(), "no anomalies expected for valid v1");
    }

    // ── Test 2: publisher_id_enabled, UInt16 type ─────────────────────────────

    #[test]
    fn publisher_id_uint16() {
        // flags1 = 0x91:
        //   bits 0..3 = 1 (ua_version)
        //   bit 4 = 1 (publisher_id_enabled)
        //   bit 7 = 1 (extended_flags1_enabled)
        // flags2 = 0x01: publisher_id_type = 1 (UInt16)
        // publisher_id bytes: 0x39 0x05 → 1337 LE
        let payload = &[
            0b1001_0001u8, // flags1: version=1, pid_enabled, ext1_enabled
            0b0000_0001u8, // flags2: pid_type=UInt16
            0x39, 0x05,    // publisher_id = 1337 LE
        ];
        let events = run_decoder(payload);

        let tx = get_transaction(&events).expect("ProtocolTransaction");
        assert_eq!(tx.attributes.get("publisher_id").map(String::as_str), Some("1337"));
        assert_eq!(
            tx.attributes.get("publisher_id_type").map(String::as_str),
            Some("uint16")
        );

        let topology = get_topology(&events);
        assert_eq!(topology.len(), 1);
        assert_eq!(topology[0].local_id, "1337");
        assert_eq!(
            topology[0].observation_type,
            "opc_ua_pubsub_publisher"
        );
    }

    // ── Test 3: publisher_id of String type ───────────────────────────────────

    #[test]
    fn publisher_id_string() {
        // flags1: version=1, pid_enabled, ext1_enabled
        // flags2: pid_type=4 (String)
        // string: length=5 (i32 LE), then b"Plant"
        let label = b"Plant";
        let mut payload = vec![
            0b1001_0001u8, // flags1
            0b0000_0100u8, // flags2: pid_type=String (4)
            5, 0, 0, 0,    // i32 LE length = 5
        ];
        payload.extend_from_slice(label);

        let events = run_decoder(&payload);
        let tx = get_transaction(&events).expect("ProtocolTransaction");
        assert_eq!(
            tx.attributes.get("publisher_id").map(String::as_str),
            Some("Plant")
        );
        assert_eq!(
            tx.attributes.get("publisher_id_type").map(String::as_str),
            Some("string")
        );

        let topology = get_topology(&events);
        assert_eq!(topology.len(), 1);
        assert_eq!(topology[0].local_id, "Plant");
    }

    // ── Test 4: payload_header present — dataset_writer_ids extracted ─────────

    #[test]
    fn payload_header_dataset_writer_ids() {
        // flags1: version=1, payload_header_enabled (bit 6)
        // 0b0100_0001 = 0x41
        // PayloadHeader: count=2, then two u16 LE writer ids: 10, 20
        let payload = &[
            0x41u8,        // flags1: version=1, payload_header_enabled
            2u8,           // count = 2
            10, 0,         // writer id 10
            20, 0,         // writer id 20
        ];
        let events = run_decoder(payload);

        let tx = get_transaction(&events).expect("ProtocolTransaction");
        assert_eq!(
            tx.attributes.get("dataset_writer_count").map(String::as_str),
            Some("2")
        );
        let ids_str = tx.attributes.get("dataset_writer_ids").expect("dataset_writer_ids");
        assert!(ids_str.contains("10"), "must contain writer id 10");
        assert!(ids_str.contains("20"), "must contain writer id 20");
    }

    // ── Test 5: wrong ua_version → ParseAnomaly severity=medium ──────────────

    #[test]
    fn wrong_ua_version_emits_medium_anomaly() {
        // flags1 lower nibble = 2 → ua_version = 2 (invalid; spec says 1)
        let payload = &[0x02u8]; // version=2, no other flags
        let events = run_decoder(payload);

        // ProtocolTransaction still emitted
        let tx = get_transaction(&events).expect("ProtocolTransaction even on bad version");
        assert_eq!(tx.attributes["ua_version"], "2");

        let anomalies = get_anomalies(&events);
        assert!(!anomalies.is_empty(), "must emit at least one ParseAnomaly");
        let medium = anomalies.iter().find(|a| a.severity == "medium");
        assert!(
            medium.is_some(),
            "expected severity=medium anomaly, got: {:?}",
            anomalies.iter().map(|a| &a.severity).collect::<Vec<_>>()
        );
    }

    // ── Test 6: two distinct publishers → two TopologyObservations ───────────

    #[test]
    fn two_distinct_publishers_two_topology_observations() {
        // Build two messages with different UInt16 publisher_ids.
        // flags1: version=1, pid_enabled, ext1_enabled = 0x91
        // flags2: pid_type=UInt16 = 0x01
        let msg_a = [0x91u8, 0x01, 0x01, 0x00]; // publisher_id = 1
        let msg_b = [0x91u8, 0x01, 0x02, 0x00]; // publisher_id = 2

        let mut decoder = OpcUaPubSubDecoder::default();
        let ctx = dummy_context();
        let mut out = Vec::new();

        let chunk_a = make_chunk(&msg_a, &ctx);
        decoder.on_datagram(&chunk_a, &mut out);

        let chunk_b = make_chunk(&msg_b, &ctx);
        decoder.on_datagram(&chunk_b, &mut out);

        let topology: Vec<_> = out
            .iter()
            .filter_map(|e| {
                if let BronzeEventFamily::TopologyObservation(t) = &e.family {
                    Some(t)
                } else {
                    None
                }
            })
            .collect();

        assert_eq!(
            topology.len(),
            2,
            "expected 2 TopologyObservations, got {}: {:?}",
            topology.len(),
            topology.iter().map(|t| &t.local_id).collect::<Vec<_>>()
        );

        let ids: HashSet<&str> = topology.iter().map(|t| t.local_id.as_str()).collect();
        assert!(ids.contains("1"), "publisher 1 should be observed");
        assert!(ids.contains("2"), "publisher 2 should be observed");
    }
}
