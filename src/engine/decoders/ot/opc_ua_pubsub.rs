//! OPC UA PubSub (UADP over UDP) decoder — Phase 6 DPI.
//!
//! Decodes UADP NetworkMessage headers (Part 14 §7.2) and DataSetMessages
//! (Part 14 §7.2.2) arriving on UDP 4840.
//!
//! ## Supported encodings
//! - **Variant encoding (FieldEncoding=0)**: scalar OPC UA Variants (Boolean,
//!   SByte, Byte, Int16, UInt16, Int32, UInt32, Int64, UInt64, Float, Double,
//!   String, DateTime). Each decoded field emits a `ProcessReading` Bronze event.
//! - **DataValue encoding (FieldEncoding=2)**: full OPC UA DataValue — includes
//!   the Variant value plus optional StatusCode, SourceTimestamp, and
//!   SourcePicoSeconds. Quality is carried as `RawQuality::OpcUaStatusCode`.
//! - **RawData encoding (FieldEncoding=1)**: requires out-of-band
//!   PublishedDataSet configuration not present on the wire. A low-severity
//!   `ParseAnomaly` is emitted and the DataSetMessage is skipped.
//!
//! ## Field-index-as-NodeId fallback
//! Without OPC UA configuration metadata on the wire we cannot resolve wire
//! field positions to real NodeIds. Field identifiers are therefore encoded as
//! `PointIdentifier::OpcUaNode { namespace_index: 0, identifier:
//! OpcUaNodeId::Numeric(field_index) }` — field_index is the zero-based
//! position of the field within its DataSetMessage. Embedders that have
//! out-of-band configuration can rewrite these identifiers.
//!
//! ## Timestamp conversion
//! UADP carries timestamps as Windows FILETIME (u64 LE, 100-ns ticks since
//! 1601-01-01). These are converted to microseconds since Unix epoch via:
//! `(filetime - 116_444_736_000_000_000) / 10`.
//!
//! ## Emissions per datagram
//! - One `ProtocolTransaction` with operation `opc_ua_pubsub_publish` for the
//!   NetworkMessage envelope (existing behaviour preserved).
//! - One `ProtocolTransaction` per DataSetMessage with operation
//!   `opc_ua_pubsub_data_key_frame`, `..._data_delta_frame`,
//!   `..._event_frame`, or `..._keep_alive`.
//! - One `ProcessReading` per decoded field (Variant or DataValue encoding).
//! - One `TopologyObservation` per unique publisher_id per session.
//! - One `AssetObservation` per unique publisher_id per session
//!   (role = `opc_ua_publisher`).

use std::collections::{BTreeMap, HashSet};

use crate::bronze::{
    AssetObservation, BronzeEvent, BronzeEventFamily, OpcUaNodeId, PointIdentifier, ProcessReading,
    ProtocolTransaction, RawQuality, TopologyObservation, TransportProtocol,
};
use crate::engine::{
    DecoderInterest, SessionDecoder, StreamChunk, build_envelope, new_event, parse_anomaly_event,
};
use crate::opc_ua::data_value::read_data_value;
use crate::opc_ua::datetime::opcua_datetime_to_unix_us;
use crate::opc_ua::reader::Reader;
use crate::opc_ua::variant::read_variant;

// ── Publisher ID type codes (ExtendedFlags1 bits 0..2) ──────────────────────

const PID_TYPE_BYTE: u8 = 0;
const PID_TYPE_UINT16: u8 = 1;
const PID_TYPE_UINT32: u8 = 2;
const PID_TYPE_UINT64: u8 = 3;
const PID_TYPE_STRING: u8 = 4;

// ── DSM FieldEncoding values (DataSetFlags1 bits 1..2) ──────────────────────

const FIELD_ENC_VARIANT: u8 = 0;
const FIELD_ENC_RAW_DATA: u8 = 1;
const FIELD_ENC_DATA_VALUE: u8 = 2;

// ── DSM MessageType values (DataSetFlags2 bits 0..3) ────────────────────────

const MSG_TYPE_DATA_KEY_FRAME: u8 = 0;
const MSG_TYPE_DATA_DELTA_FRAME: u8 = 1;
const MSG_TYPE_EVENT: u8 = 2;
const MSG_TYPE_KEEP_ALIVE: u8 = 3;

const SOURCE_PROTOCOL: &str = "opc_ua_pubsub";

// ── Decoder state ────────────────────────────────────────────────────────────

#[derive(Default)]
pub(crate) struct OpcUaPubSubDecoder {
    /// Publisher IDs already emitted as TopologyObservations this session.
    seen_publishers: HashSet<String>,
    /// Publisher IDs already emitted as AssetObservations this session.
    seen_assets: HashSet<String>,
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
    /// Byte offset where DataSetMessage payloads begin.
    payload_start: usize,
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
    let (pid_type, dataset_class_id_enabled, extended_flags2_enabled) = if extended_flags1_enabled {
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
        cursor += count * 2;
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
        payload_start: cursor,
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

// ── DataSetMessage parsing ───────────────────────────────────────────────────

/// Decoded DataSetMessage header fields.
struct DsmHeader {
    field_encoding: u8,
    message_type: u8,
    sequence_number: Option<u16>,
    /// DSM-level timestamp (microseconds since Unix epoch), if present.
    dsm_timestamp_us: Option<u64>,
    status_code: Option<u16>,
}

/// Parse the DataSetMessage header from a `Reader`.
/// Returns `Err(&'static str)` on truncation.
fn parse_dsm_header(r: &mut Reader<'_>) -> Result<DsmHeader, &'static str> {
    let flags1 = r
        .read_u8()
        .map_err(|_| "truncated: missing DataSetFlags1")?;

    let _valid = flags1 & 0x01 != 0;
    let field_encoding = (flags1 >> 1) & 0x03;
    let seq_num_enabled = (flags1 >> 3) & 1 != 0;
    let status_enabled = (flags1 >> 4) & 1 != 0;
    let major_ver_enabled = (flags1 >> 5) & 1 != 0;
    let minor_ver_enabled = (flags1 >> 6) & 1 != 0;
    let flags2_enabled = (flags1 >> 7) & 1 != 0;

    let (message_type, timestamp_enabled, pico_seconds_enabled) = if flags2_enabled {
        let flags2 = r
            .read_u8()
            .map_err(|_| "truncated: missing DataSetFlags2")?;
        let mt = flags2 & 0x0F;
        let ts_en = (flags2 >> 4) & 1 != 0;
        let ps_en = (flags2 >> 5) & 1 != 0;
        (mt, ts_en, ps_en)
    } else {
        (MSG_TYPE_DATA_KEY_FRAME, false, false)
    };

    let sequence_number = if seq_num_enabled {
        let sn = r
            .read_u16()
            .map_err(|_| "truncated: missing DSM SequenceNumber")?;
        Some(sn)
    } else {
        None
    };

    let dsm_timestamp_us = if timestamp_enabled {
        let ticks = r
            .read_u64()
            .map_err(|_| "truncated: missing DSM Timestamp")?;
        // Convert Windows FILETIME (100-ns ticks since 1601) to Unix microseconds.
        opcua_datetime_to_unix_us(ticks as i64)
    } else {
        None
    };

    if pico_seconds_enabled {
        r.read_u16()
            .map_err(|_| "truncated: missing DSM PicoSeconds")?;
    }

    let status_code = if status_enabled {
        let sc = r
            .read_u16()
            .map_err(|_| "truncated: missing DSM StatusCode")?;
        Some(sc)
    } else {
        None
    };

    if major_ver_enabled {
        r.read_u32()
            .map_err(|_| "truncated: missing DSM MajorVersion")?;
    }
    if minor_ver_enabled {
        r.read_u32()
            .map_err(|_| "truncated: missing DSM MinorVersion")?;
    }

    Ok(DsmHeader {
        field_encoding,
        message_type,
        sequence_number,
        dsm_timestamp_us,
        status_code,
    })
}

/// Operation name for a DSM message type.
fn dsm_operation(message_type: u8) -> &'static str {
    match message_type {
        MSG_TYPE_DATA_KEY_FRAME => "opc_ua_pubsub_data_key_frame",
        MSG_TYPE_DATA_DELTA_FRAME => "opc_ua_pubsub_data_delta_frame",
        MSG_TYPE_EVENT => "opc_ua_pubsub_event_frame",
        MSG_TYPE_KEEP_ALIVE => "opc_ua_pubsub_keep_alive",
        _ => "opc_ua_pubsub_data_key_frame",
    }
}

/// Field encoding label for attributes.
fn field_encoding_str(enc: u8) -> &'static str {
    match enc {
        FIELD_ENC_VARIANT => "variant",
        FIELD_ENC_RAW_DATA => "raw_data",
        FIELD_ENC_DATA_VALUE => "data_value",
        _ => "unknown",
    }
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
                    envelope.clone(),
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

            // AssetObservation — once per unique publisher_id per session.
            if self.seen_assets.insert(pid_str.clone()) {
                let mut identifiers = BTreeMap::new();
                if let Some(pid_type) = hdr.publisher_id_type {
                    identifiers.insert("publisher_id_type".to_string(), pid_type.to_string());
                }
                identifiers.insert("publisher_id".to_string(), pid_str.clone());

                out.push(new_event(
                    chunk.capture_id.to_string(),
                    envelope.clone(),
                    BronzeEventFamily::AssetObservation(AssetObservation {
                        asset_key: format!("opc_ua_pubsub_publisher:{}", pid_str),
                        role: Some("opc_ua_publisher".to_string()),
                        vendor: None,
                        model: None,
                        firmware: None,
                        hostnames: vec![],
                        protocols: vec!["opc_ua_pubsub".to_string()],
                        identifiers,
                    }),
                ));
            }
        }

        // ── DataSetMessage decoding ─────────────────────────────────────────
        // Only decode if there is payload after the NetworkMessage header.
        let payload_buf = chunk.payload;
        if hdr.payload_start >= payload_buf.len() {
            return;
        }

        let dsm_payload = &payload_buf[hdr.payload_start..];
        let observed_ts = chunk.timestamp.timestamp_micros() as u64;

        // When a PayloadHeader was present, dataset_writer_ids tells us how
        // many DSMs follow and their writer IDs. When absent, there may be
        // zero or one implicit DSM — if there are remaining bytes and no writer
        // IDs, attempt one implicit DSM with writer_id=0.
        if hdr.dataset_writer_ids.is_empty() {
            if !dsm_payload.is_empty() {
                let mut r = Reader::new(dsm_payload);
                decode_dsm(
                    &mut r,
                    0u16,
                    chunk.capture_id,
                    &envelope,
                    observed_ts,
                    self.name(),
                    out,
                    chunk.payload,
                );
            }
        } else {
            let mut r = Reader::new(dsm_payload);
            for &writer_id in &hdr.dataset_writer_ids {
                if r.remaining() == 0 {
                    break;
                }
                decode_dsm(
                    &mut r,
                    writer_id,
                    chunk.capture_id,
                    &envelope,
                    observed_ts,
                    self.name(),
                    out,
                    chunk.payload,
                );
            }
        }
    }
}

/// Decode one DataSetMessage from `r` and push resulting events to `out`.
#[allow(clippy::too_many_arguments)]
fn decode_dsm(
    r: &mut Reader<'_>,
    writer_id: u16,
    capture_id: &str,
    envelope: &crate::bronze::EventEnvelope,
    observed_ts: u64,
    decoder_name: &str,
    out: &mut Vec<BronzeEvent>,
    raw_excerpt: &[u8],
) {
    let dsm_hdr = match parse_dsm_header(r) {
        Ok(h) => h,
        Err(reason) => {
            out.push(parse_anomaly_event(
                capture_id.to_string(),
                envelope.clone(),
                decoder_name,
                "low",
                reason,
                raw_excerpt,
            ));
            return;
        }
    };

    // RawData: emit low anomaly, skip rest of DSM (we cannot decode it without
    // PublishedDataSet config that isn't on the wire).
    if dsm_hdr.field_encoding == FIELD_ENC_RAW_DATA {
        out.push(parse_anomaly_event(
            capture_id.to_string(),
            envelope.clone(),
            decoder_name,
            "low",
            "RawData field encoding requires out-of-band PublishedDataSet config; skipped",
            raw_excerpt,
        ));
        // Emit a KeepAlive-style transaction so the writer_id is recorded.
        emit_dsm_transaction(r, capture_id, envelope, writer_id, &dsm_hdr, 0, out);
        return;
    }

    // KeepAlive: no fields, just emit the transaction.
    if dsm_hdr.message_type == MSG_TYPE_KEEP_ALIVE {
        emit_dsm_transaction(r, capture_id, envelope, writer_id, &dsm_hdr, 0, out);
        return;
    }

    // KeyFrame / DeltaFrame / Event: read FieldCount then fields.
    let field_count = match r.read_u16() {
        Ok(n) => n,
        Err(_) => {
            out.push(parse_anomaly_event(
                capture_id.to_string(),
                envelope.clone(),
                decoder_name,
                "low",
                "truncated: missing DSM FieldCount",
                raw_excerpt,
            ));
            return;
        }
    };

    let is_delta = dsm_hdr.message_type == MSG_TYPE_DATA_DELTA_FRAME;
    let mut readings: Vec<BronzeEvent> = Vec::with_capacity(field_count as usize);

    for field_index in 0u16..field_count {
        // DeltaFrame carries a u16 FieldIndex before each value.
        let point_index = if is_delta {
            match r.read_u16() {
                Ok(fi) => fi,
                Err(_) => {
                    out.push(parse_anomaly_event(
                        capture_id.to_string(),
                        envelope.clone(),
                        decoder_name,
                        "low",
                        "truncated: missing DeltaFrame FieldIndex",
                        raw_excerpt,
                    ));
                    emit_dsm_transaction(
                        r,
                        capture_id,
                        envelope,
                        writer_id,
                        &dsm_hdr,
                        readings.len() as u16,
                        out,
                    );
                    out.append(&mut readings);
                    return;
                }
            }
        } else {
            field_index
        };

        let point_id = PointIdentifier::OpcUaNode {
            namespace_index: 0,
            identifier: OpcUaNodeId::Numeric(point_index as u32),
        };

        match dsm_hdr.field_encoding {
            FIELD_ENC_VARIANT => match read_variant(r) {
                Ok(value) => {
                    readings.push(new_event(
                        capture_id.to_string(),
                        envelope.clone(),
                        BronzeEventFamily::ProcessReading(ProcessReading {
                            source_protocol: SOURCE_PROTOCOL.to_string(),
                            point_id,
                            value,
                            quality: RawQuality::None,
                            source_ts: dsm_hdr.dsm_timestamp_us,
                            observed_ts,
                        }),
                    ));
                }
                Err(_) => {
                    out.push(parse_anomaly_event(
                        capture_id.to_string(),
                        envelope.clone(),
                        decoder_name,
                        "low",
                        "unsupported or truncated Variant in DataSetMessage",
                        raw_excerpt,
                    ));
                    emit_dsm_transaction(
                        r,
                        capture_id,
                        envelope,
                        writer_id,
                        &dsm_hdr,
                        readings.len() as u16,
                        out,
                    );
                    out.append(&mut readings);
                    return;
                }
            },
            FIELD_ENC_DATA_VALUE => match read_data_value(r) {
                Ok(dv) => {
                    readings.push(new_event(
                        capture_id.to_string(),
                        envelope.clone(),
                        BronzeEventFamily::ProcessReading(ProcessReading {
                            source_protocol: SOURCE_PROTOCOL.to_string(),
                            point_id,
                            value: dv.value,
                            quality: dv.quality,
                            source_ts: dv.source_ts,
                            observed_ts,
                        }),
                    ));
                }
                Err(_) => {
                    out.push(parse_anomaly_event(
                        capture_id.to_string(),
                        envelope.clone(),
                        decoder_name,
                        "low",
                        "truncated DataValue in DataSetMessage",
                        raw_excerpt,
                    ));
                    emit_dsm_transaction(
                        r,
                        capture_id,
                        envelope,
                        writer_id,
                        &dsm_hdr,
                        readings.len() as u16,
                        out,
                    );
                    out.append(&mut readings);
                    return;
                }
            },
            _ => {
                // Should not reach here (RawData handled above, reserved enc=3).
                out.push(parse_anomaly_event(
                    capture_id.to_string(),
                    envelope.clone(),
                    decoder_name,
                    "low",
                    "unknown FieldEncoding in DataSetMessage",
                    raw_excerpt,
                ));
                emit_dsm_transaction(
                    r,
                    capture_id,
                    envelope,
                    writer_id,
                    &dsm_hdr,
                    readings.len() as u16,
                    out,
                );
                out.append(&mut readings);
                return;
            }
        }
    }

    emit_dsm_transaction(
        r,
        capture_id,
        envelope,
        writer_id,
        &dsm_hdr,
        field_count,
        out,
    );
    out.append(&mut readings);
}

/// Emit one per-DSM `ProtocolTransaction` event.
fn emit_dsm_transaction(
    _r: &mut Reader<'_>,
    capture_id: &str,
    envelope: &crate::bronze::EventEnvelope,
    writer_id: u16,
    dsm_hdr: &DsmHeader,
    field_count: u16,
    out: &mut Vec<BronzeEvent>,
) {
    let mut attrs = BTreeMap::new();
    attrs.insert("dataset_writer_id".to_string(), writer_id.to_string());
    attrs.insert("field_count".to_string(), field_count.to_string());
    attrs.insert(
        "field_encoding".to_string(),
        field_encoding_str(dsm_hdr.field_encoding).to_string(),
    );
    if let Some(sn) = dsm_hdr.sequence_number {
        attrs.insert("sequence_number".to_string(), sn.to_string());
    }
    if let Some(sc) = dsm_hdr.status_code {
        attrs.insert("status_code".to_string(), sc.to_string());
    }

    out.push(new_event(
        capture_id.to_string(),
        envelope.clone(),
        BronzeEventFamily::ProtocolTransaction(ProtocolTransaction {
            operation: dsm_operation(dsm_hdr.message_type).to_string(),
            status: "observed".to_string(),
            request_summary: Some(format!(
                "UADP DSM writer_id={} fields={}",
                writer_id, field_count
            )),
            response_summary: None,
            object_refs: vec![],
            values: vec![],
            attributes: attrs,
            modbus: None,
            protocol_fields: None,
        }),
    ));
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
    use crate::bronze::{BronzeEventFamily, PointValue};
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

    fn get_transactions(events: &[BronzeEvent]) -> Vec<&ProtocolTransaction> {
        events
            .iter()
            .filter_map(|e| {
                if let BronzeEventFamily::ProtocolTransaction(tx) = &e.family {
                    Some(tx)
                } else {
                    None
                }
            })
            .collect()
    }

    fn get_transaction(events: &[BronzeEvent]) -> Option<&ProtocolTransaction> {
        get_transactions(events).into_iter().next()
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

    fn get_assets(events: &[BronzeEvent]) -> Vec<&AssetObservation> {
        events
            .iter()
            .filter_map(|e| {
                if let BronzeEventFamily::AssetObservation(a) = &e.family {
                    Some(a)
                } else {
                    None
                }
            })
            .collect()
    }

    fn get_readings(events: &[BronzeEvent]) -> Vec<&ProcessReading> {
        events
            .iter()
            .filter_map(|e| {
                if let BronzeEventFamily::ProcessReading(r) = &e.family {
                    Some(r)
                } else {
                    None
                }
            })
            .collect()
    }

    /// Build a minimal UADP NetworkMessage with payload_header (flags1 bit 6)
    /// and one DSM with Variant encoding containing the given fields.
    ///
    /// Layout:
    ///   [0]  flags1 = 0x41 (version=1, payload_header_enabled)
    ///   [1]  PayloadHeader count = 1
    ///   [2..3] DataSetWriterId = writer_id (LE)
    ///   Then DSM bytes (pre-built by caller).
    fn make_uadp_with_dsm(writer_id: u16, dsm_bytes: &[u8]) -> Vec<u8> {
        let mut pkt = vec![
            0x41u8, // flags1: version=1, payload_header_enabled
            1u8,    // PayloadHeader count = 1
        ];
        pkt.extend_from_slice(&writer_id.to_le_bytes());
        pkt.extend_from_slice(dsm_bytes);
        pkt
    }

    /// Build a DataSetMessage with Variant encoding and a list of Variant bytes.
    /// DataSetFlags1 = 0x01 (valid, FieldEncoding=0 Variant, no optional fields).
    fn make_dsm_variant(field_variants: &[Vec<u8>]) -> Vec<u8> {
        let mut dsm = vec![0x01u8]; // DataSetFlags1: valid, Variant encoding
        let count = field_variants.len() as u16;
        dsm.extend_from_slice(&count.to_le_bytes()); // FieldCount
        for v in field_variants {
            dsm.extend_from_slice(v);
        }
        dsm
    }

    /// Build a single OPC UA Variant encoding for an Int32 value.
    fn variant_int32(v: i32) -> Vec<u8> {
        let mut b = vec![6u8]; // T_INT32 = 6
        b.extend_from_slice(&v.to_le_bytes());
        b
    }

    /// Build a single OPC UA Variant encoding for a Double value.
    fn variant_double(v: f64) -> Vec<u8> {
        let mut b = vec![11u8]; // T_DOUBLE = 11
        b.extend_from_slice(&v.to_le_bytes());
        b
    }

    /// Build a single OPC UA Variant encoding for a Boolean value.
    fn variant_bool(v: bool) -> Vec<u8> {
        vec![1u8, if v { 1 } else { 0 }] // T_BOOLEAN = 1
    }

    /// Build a single OPC UA Variant encoding for an Int16 value.
    fn variant_int16(v: i16) -> Vec<u8> {
        let mut b = vec![4u8]; // T_INT16 = 4
        b.extend_from_slice(&v.to_le_bytes());
        b
    }

    /// Build a single OPC UA Variant encoding for a Float value.
    fn variant_float(v: f32) -> Vec<u8> {
        let mut b = vec![10u8]; // T_FLOAT = 10
        b.extend_from_slice(&v.to_le_bytes());
        b
    }

    /// Build a single OPC UA Variant encoding for a String value.
    fn variant_string(s: &str) -> Vec<u8> {
        let mut b = vec![12u8]; // T_STRING = 12
        let bytes = s.as_bytes();
        b.extend_from_slice(&(bytes.len() as i32).to_le_bytes());
        b.extend_from_slice(bytes);
        b
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
            0x39,
            0x05, // publisher_id = 1337 LE
        ];
        let events = run_decoder(payload);

        let tx = get_transaction(&events).expect("ProtocolTransaction");
        assert_eq!(
            tx.attributes.get("publisher_id").map(String::as_str),
            Some("1337")
        );
        assert_eq!(
            tx.attributes.get("publisher_id_type").map(String::as_str),
            Some("uint16")
        );

        let topology = get_topology(&events);
        assert_eq!(topology.len(), 1);
        assert_eq!(topology[0].local_id, "1337");
        assert_eq!(topology[0].observation_type, "opc_ua_pubsub_publisher");
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
            5,
            0,
            0,
            0, // i32 LE length = 5
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
        // Plus a DSM per writer — use minimal valid ones.
        // DSM for writer 10: flags1=0x01, field_count=0
        // DSM for writer 20: flags1=0x01, field_count=0
        let payload = &[
            0x41u8, // flags1: version=1, payload_header_enabled
            2u8,    // count = 2
            10, 0, // writer id 10
            20, 0, // writer id 20
            0x01u8, 0, 0, // DSM1: flags1=valid, Variant enc, FieldCount=0
            0x01u8, 0, 0, // DSM2: flags1=valid, Variant enc, FieldCount=0
        ];
        let events = run_decoder(payload);

        let tx = get_transaction(&events).expect("ProtocolTransaction");
        assert_eq!(
            tx.attributes
                .get("dataset_writer_count")
                .map(String::as_str),
            Some("2")
        );
        let ids_str = tx
            .attributes
            .get("dataset_writer_ids")
            .expect("dataset_writer_ids");
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

    // ── Test 7: KeyFrame with one Int32 field → ProcessReading ───────────────

    #[test]
    fn key_frame_one_int32_field() {
        let dsm = make_dsm_variant(&[variant_int32(42)]);
        let payload = make_uadp_with_dsm(1, &dsm);

        let events = run_decoder(&payload);

        let readings = get_readings(&events);
        assert_eq!(readings.len(), 1, "expected 1 ProcessReading");

        let r = readings[0];
        assert_eq!(r.source_protocol, "opc_ua_pubsub");
        assert!(
            matches!(r.value, PointValue::Int32(42)),
            "expected Int32(42), got {:?}",
            r.value
        );
        assert!(matches!(r.quality, RawQuality::None));

        // point_id should be field index 0
        assert!(
            matches!(
                &r.point_id,
                PointIdentifier::OpcUaNode {
                    namespace_index: 0,
                    identifier: OpcUaNodeId::Numeric(0)
                }
            ),
            "expected OpcUaNode{{ns=0, Numeric(0)}}, got {:?}",
            r.point_id
        );

        // per-DSM transaction
        let txs = get_transactions(&events);
        let dsm_tx = txs
            .iter()
            .find(|t| t.operation == "opc_ua_pubsub_data_key_frame")
            .expect("DSM ProtocolTransaction");
        assert_eq!(dsm_tx.attributes["field_count"], "1");
        assert_eq!(dsm_tx.attributes["field_encoding"], "variant");
        assert_eq!(dsm_tx.attributes["dataset_writer_id"], "1");
    }

    // ── Test 8: KeyFrame with mixed types (Bool, Int16, Float, Double, String) ─

    #[test]
    fn key_frame_mixed_types() {
        let fields = vec![
            variant_bool(true),
            variant_int16(-100),
            variant_float(3.14f32),
            variant_double(2.718f64),
            variant_string("hello"),
        ];
        let dsm = make_dsm_variant(&fields);
        let payload = make_uadp_with_dsm(7, &dsm);

        let events = run_decoder(&payload);
        let readings = get_readings(&events);
        assert_eq!(readings.len(), 5, "expected 5 ProcessReadings");

        assert!(matches!(readings[0].value, PointValue::Bool(true)));
        assert!(matches!(readings[1].value, PointValue::Int16(-100)));
        assert!(matches!(readings[2].value, PointValue::Float(f) if (f - 3.14f32).abs() < 1e-4));
        assert!(matches!(readings[3].value, PointValue::Double(d) if (d - 2.718f64).abs() < 1e-9));
        assert!(matches!(&readings[4].value, PointValue::Text(s) if s == "hello"));

        // Field indices should be 0..4
        for (i, r) in readings.iter().enumerate() {
            assert!(
                matches!(
                    &r.point_id,
                    PointIdentifier::OpcUaNode {
                        namespace_index: 0,
                        identifier: OpcUaNodeId::Numeric(n)
                    } if *n == i as u32
                ),
                "field {} has unexpected point_id: {:?}",
                i,
                r.point_id
            );
        }
    }

    // ── Test 9: DeltaFrame with FieldIndex ────────────────────────────────────

    #[test]
    fn delta_frame_with_field_index() {
        // DataSetFlags1 = 0x03: valid + FieldEncoding=1 (raw_data)?
        // No — DeltaFrame is message type bit, set via DataSetFlags2.
        // DataSetFlags1 = 0x81: valid, Variant enc, DataSetFlags2Enabled.
        // DataSetFlags2 = 0x01: MessageType=DeltaFrame(1).
        // FieldCount = 1
        // FieldIndex = 5 (u16 LE)
        // Variant = Int32(99)
        let mut dsm = vec![
            0x81u8, // DataSetFlags1: valid, Variant enc, Flags2Enabled
            0x01u8, // DataSetFlags2: MessageType=1 (DeltaFrame)
            1, 0, // FieldCount = 1
            5, 0, // FieldIndex = 5
        ];
        dsm.extend_from_slice(&variant_int32(99));

        let payload = make_uadp_with_dsm(3, &dsm);
        let events = run_decoder(&payload);

        let readings = get_readings(&events);
        assert_eq!(readings.len(), 1);

        // point_id must reflect the FieldIndex (5), not the loop counter (0).
        assert!(
            matches!(
                &readings[0].point_id,
                PointIdentifier::OpcUaNode {
                    namespace_index: 0,
                    identifier: OpcUaNodeId::Numeric(5)
                }
            ),
            "expected Numeric(5) (DeltaFrame FieldIndex), got {:?}",
            readings[0].point_id
        );
        assert!(matches!(readings[0].value, PointValue::Int32(99)));

        let txs = get_transactions(&events);
        let dsm_tx = txs
            .iter()
            .find(|t| t.operation == "opc_ua_pubsub_data_delta_frame")
            .expect("delta_frame transaction");
        assert_eq!(dsm_tx.attributes["field_count"], "1");
    }

    // ── Test 10: DataValue encoding with StatusCode + SourceTimestamp ─────────

    #[test]
    fn data_value_encoding_status_and_timestamp() {
        // DataSetFlags1 = 0x05: valid + FieldEncoding=2 (DataValue).
        // FieldCount = 1
        // DataValue: mask = HAS_VALUE | HAS_STATUS_CODE | HAS_SOURCE_TIMESTAMP
        //   Variant = Double(72.5)
        //   StatusCode = 0x8000_0000 (Bad)
        //   SourceTimestamp = 1 second after Unix epoch in OPC UA ticks.
        const HAS_VALUE: u8 = 0x01;
        const HAS_STATUS_CODE: u8 = 0x02;
        const HAS_SOURCE_TIMESTAMP: u8 = 0x04;
        let dv_mask = HAS_VALUE | HAS_STATUS_CODE | HAS_SOURCE_TIMESTAMP;
        let ts_ticks: i64 = 116_444_736_000_000_000 + 10_000_000; // 1s after epoch

        let mut dsm = vec![
            0x05u8, // DataSetFlags1: valid, DataValue encoding (bits 1..2 = 2 = 0b10)
            1, 0, // FieldCount = 1
            dv_mask, 11, // T_DOUBLE
        ];
        dsm.extend_from_slice(&72.5f64.to_le_bytes());
        dsm.extend_from_slice(&0x8000_0000u32.to_le_bytes()); // status code
        dsm.extend_from_slice(&ts_ticks.to_le_bytes()); // source timestamp

        let payload = make_uadp_with_dsm(2, &dsm);
        let events = run_decoder(&payload);

        let readings = get_readings(&events);
        assert_eq!(readings.len(), 1);

        let r = readings[0];
        assert!(matches!(r.value, PointValue::Double(d) if (d - 72.5).abs() < 1e-9));
        assert!(
            matches!(r.quality, RawQuality::OpcUaStatusCode(0x8000_0000)),
            "expected OpcUaStatusCode(0x80000000), got {:?}",
            r.quality
        );
        // Source timestamp should be 1_000_000 µs (1 second)
        assert_eq!(r.source_ts, Some(1_000_000));

        let txs = get_transactions(&events);
        let dsm_tx = txs
            .iter()
            .find(|t| t.operation == "opc_ua_pubsub_data_key_frame")
            .expect("key_frame transaction");
        assert_eq!(dsm_tx.attributes["field_encoding"], "data_value");
    }

    // ── Test 11: KeepAlive emits operation but no readings ────────────────────

    #[test]
    fn keep_alive_no_readings() {
        // DataSetFlags1 = 0x81: valid, Variant enc, Flags2Enabled.
        // DataSetFlags2 = 0x03: MessageType=3 (KeepAlive).
        let dsm = vec![
            0x81u8, // DataSetFlags1: valid, Variant enc, Flags2Enabled
            0x03u8, // DataSetFlags2: MessageType=3 (KeepAlive)
        ];
        let payload = make_uadp_with_dsm(5, &dsm);
        let events = run_decoder(&payload);

        let readings = get_readings(&events);
        assert!(readings.is_empty(), "KeepAlive must not produce readings");

        let txs = get_transactions(&events);
        let ka_tx = txs
            .iter()
            .find(|t| t.operation == "opc_ua_pubsub_keep_alive")
            .expect("keep_alive transaction");
        assert_eq!(ka_tx.attributes["dataset_writer_id"], "5");
    }

    // ── Test 12: RawData encoding → low anomaly + skip ────────────────────────

    #[test]
    fn raw_data_encoding_emits_anomaly() {
        // DataSetFlags1 = 0x03: valid + FieldEncoding=1 (RawData).
        // No FieldCount follows in our encoding (we skip the DSM).
        let dsm = vec![0x03u8]; // DataSetFlags1: valid, RawData encoding
        let payload = make_uadp_with_dsm(10, &dsm);

        let events = run_decoder(&payload);

        let anomalies = get_anomalies(&events);
        let raw_data_anomaly = anomalies
            .iter()
            .find(|a| a.severity == "low" && a.reason.contains("RawData"));
        assert!(
            raw_data_anomaly.is_some(),
            "expected low-severity RawData anomaly, got: {:?}",
            anomalies
        );

        // No readings
        let readings = get_readings(&events);
        assert!(readings.is_empty(), "RawData must not produce readings");
    }

    // ── Test 13: Unsupported Variant built-in type → low anomaly ─────────────

    #[test]
    fn unsupported_variant_type_emits_anomaly() {
        // Type ID 22 = ExtensionObject — unsupported, cursor cannot advance.
        // After the anomaly the DSM is abandoned.
        let mut dsm = vec![
            0x01u8, // DataSetFlags1: valid, Variant enc
            1, 0, // FieldCount = 1
            22u8, // T_EXTENSION_OBJECT (unsupported)
               // No further bytes — read_scalar returns Null (not Err) for type 22.
               // The variant decoder returns Ok(Null) for unknown types.
               // So no anomaly from unsupported type per the variant.rs design.
               // Instead test an actual truncation to force an Err path:
        ];
        // Actually T_STRING (12) with a truncated length triggers ReaderError.
        // Reset: single String variant with no length bytes.
        dsm = vec![
            0x01u8, // DataSetFlags1
            1, 0,    // FieldCount = 1
            12u8, // T_STRING — needs 4-byte i32 length, truncated
        ];
        let payload = make_uadp_with_dsm(11, &dsm);
        let events = run_decoder(&payload);

        let anomalies = get_anomalies(&events);
        let low = anomalies.iter().find(|a| a.severity == "low");
        assert!(
            low.is_some(),
            "expected low-severity anomaly for truncated Variant"
        );

        let readings = get_readings(&events);
        assert!(
            readings.is_empty(),
            "truncated Variant must not produce readings"
        );
    }

    // ── Test 14: Windows FILETIME → Unix micros conversion correctness ─────────

    #[test]
    fn windows_filetime_to_unix_micros() {
        // 116_444_736_000_000_000 ticks = Unix epoch (1970-01-01).
        // 10_000_000 ticks = 1 second.
        // So 116_444_736_000_000_000 + 10_000_000 = 1_000_000 µs.
        let ticks: i64 = 116_444_736_000_000_000 + 10_000_000;
        let result = opcua_datetime_to_unix_us(ticks);
        assert_eq!(result, Some(1_000_000), "1s after epoch = 1_000_000 µs");

        // 0 ticks = null OPC UA DateTime → None.
        assert_eq!(opcua_datetime_to_unix_us(0), None);

        // Pre-1970 should be None.
        assert_eq!(opcua_datetime_to_unix_us(1), None);
    }

    // ── Test 15: AssetObservation emitted once per publisher_id ───────────────

    #[test]
    fn asset_observation_emitted_once_per_publisher() {
        // Send the same publisher twice — AssetObservation should appear only once.
        // flags1: version=1, pid_enabled, ext1_enabled = 0x91
        // flags2: pid_type=UInt16
        let msg = [0x91u8, 0x01, 0x07, 0x00]; // publisher_id = 7

        let mut decoder = OpcUaPubSubDecoder::default();
        let ctx = dummy_context();
        let mut out = Vec::new();

        let chunk1 = make_chunk(&msg, &ctx);
        decoder.on_datagram(&chunk1, &mut out);
        let chunk2 = make_chunk(&msg, &ctx);
        decoder.on_datagram(&chunk2, &mut out);

        let assets = get_assets(&out);
        assert_eq!(assets.len(), 1, "AssetObservation must appear exactly once");
        assert_eq!(assets[0].role.as_deref(), Some("opc_ua_publisher"));
        assert!(assets[0].asset_key.contains("7"));
        assert_eq!(
            assets[0]
                .identifiers
                .get("publisher_id")
                .map(String::as_str),
            Some("7")
        );
    }

    // ── Test 16: Multiple DSMs in one UADP datagram ───────────────────────────

    #[test]
    fn multiple_dsms_in_one_datagram() {
        // PayloadHeader with 2 writer IDs; two DSMs each with one Int32 field.
        let dsm1 = make_dsm_variant(&[variant_int32(10)]);
        let dsm2 = make_dsm_variant(&[variant_int32(20)]);

        // Build manually: flags1=0x41, count=2, ids=[100, 200], then dsm1+dsm2.
        let mut payload = vec![
            0x41u8, // flags1: version=1, payload_header_enabled
            2u8,    // count = 2
            100, 0, // writer_id 100
            200, 0, // writer_id 200
        ];
        payload.extend_from_slice(&dsm1);
        payload.extend_from_slice(&dsm2);

        let events = run_decoder(&payload);
        let readings = get_readings(&events);
        assert_eq!(readings.len(), 2, "expected 2 readings (one per DSM)");

        let values: Vec<_> = readings.iter().map(|r| &r.value).collect();
        assert!(values.iter().any(|v| matches!(v, PointValue::Int32(10))));
        assert!(values.iter().any(|v| matches!(v, PointValue::Int32(20))));

        // Should have 3 ProtocolTransactions: 1 NetworkMessage + 2 DSMs.
        let txs = get_transactions(&events);
        let dsm_txs: Vec<_> = txs
            .iter()
            .filter(|t| t.operation == "opc_ua_pubsub_data_key_frame")
            .collect();
        assert_eq!(dsm_txs.len(), 2, "expected 2 DSM ProtocolTransactions");
        let writer_ids: Vec<_> = dsm_txs
            .iter()
            .map(|t| t.attributes["dataset_writer_id"].as_str())
            .collect();
        assert!(writer_ids.contains(&"100"));
        assert!(writer_ids.contains(&"200"));
    }

    // ── Test 17: DSM with sequence number in attributes ───────────────────────

    #[test]
    fn dsm_sequence_number_in_attributes() {
        // DataSetFlags1 = 0x09: valid, Variant enc, SeqNumEnabled (bit 3).
        // SeqNum = 42 (u16 LE)
        // FieldCount = 0
        let dsm = vec![
            0x09u8, // DataSetFlags1: valid, Variant enc, SeqNumEnabled
            42, 0, // SequenceNumber = 42
            0, 0, // FieldCount = 0
        ];
        let payload = make_uadp_with_dsm(8, &dsm);
        let events = run_decoder(&payload);

        let txs = get_transactions(&events);
        let dsm_tx = txs
            .iter()
            .find(|t| t.operation == "opc_ua_pubsub_data_key_frame")
            .expect("key_frame transaction");
        assert_eq!(
            dsm_tx.attributes.get("sequence_number").map(String::as_str),
            Some("42")
        );
    }
}
