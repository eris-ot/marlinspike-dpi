//! Stateful OPC UA decoder for `MSG`-chunk service messages. Tracks
//! ReadRequest NodeIds keyed by `(secure_channel_id, request_id)` and pairs
//! them with the corresponding ReadResponse's `DataValue[]` results to emit
//! `BronzeEventFamily::ProcessReading` events.

use crate::bronze::{
    BronzeEvent, BronzeEventFamily, EventEnvelope, PointIdentifier, ProcessReading,
};
use crate::opc_ua::reader::Reader;
use crate::opc_ua::services::{
    READ_REQUEST_TYPE_ID, READ_RESPONSE_TYPE_ID, parse_read_request_body, parse_read_response_body,
    read_service_type_id,
};
use crate::opc_ua::state::{PendingConfig, PendingKey, PendingReads};

const SOURCE_PROTOCOL: &str = "opc_ua";

/// Stateful OPC UA decoder. Maintains a `PendingReads` table to correlate
/// ReadRequest → ReadResponse pairs by `(secure_channel_id, request_id)`.
#[derive(Default)]
pub struct OpcUaServiceDecoder {
    pending: PendingReads,
}

impl OpcUaServiceDecoder {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_config(config: PendingConfig) -> Self {
        Self {
            pending: PendingReads::with_config(config),
        }
    }

    pub fn pending_count(&self) -> usize {
        self.pending.len()
    }

    pub fn evict_expired(&mut self, now_us: u64) -> usize {
        self.pending.evict_expired(now_us)
    }

    /// Process one MSG-chunk body (the bytes after the 24-byte secure header).
    /// `secure_channel_id` and `request_id` come from the secure header,
    /// extracted by the caller. `now_us` is the packet timestamp in
    /// microseconds since Unix epoch.
    ///
    /// Returns any [`BronzeEvent`]s derived from this chunk (process readings
    /// for ReadResponse). Non-Read services are ignored quietly.
    #[allow(clippy::too_many_arguments)]
    pub fn handle_msg_body(
        &mut self,
        body: &[u8],
        secure_channel_id: u32,
        request_id: u32,
        envelope: &EventEnvelope,
        now_us: u64,
        next_event_id: &mut dyn FnMut() -> String,
        capture_id: &str,
    ) -> Vec<BronzeEvent> {
        let mut r = Reader::new(body);
        let Ok(type_id) = read_service_type_id(&mut r) else {
            return Vec::new();
        };
        match type_id {
            READ_REQUEST_TYPE_ID => {
                if let Ok(nodes) = parse_read_request_body(&mut r) {
                    self.pending.insert(
                        PendingKey {
                            secure_channel_id,
                            request_id,
                        },
                        nodes,
                        now_us,
                    );
                }
                Vec::new()
            }
            READ_RESPONSE_TYPE_ID => {
                let Ok(response) = parse_read_response_body(&mut r) else {
                    return Vec::new();
                };
                let nodes = self
                    .pending
                    .take(&PendingKey {
                        secure_channel_id,
                        request_id,
                    })
                    .unwrap_or_default();
                let mut out = Vec::with_capacity(response.results.len());
                for (i, dv) in response.results.into_iter().enumerate() {
                    let point_id = match nodes.get(i) {
                        Some(decoded) => PointIdentifier::OpcUaNode {
                            namespace_index: decoded.namespace_index,
                            identifier: decoded.identifier.clone(),
                        },
                        None => PointIdentifier::OpcUaNode {
                            namespace_index: 0,
                            identifier: crate::bronze::OpcUaNodeId::Numeric(i as u32),
                        },
                    };
                    let reading = ProcessReading {
                        source_protocol: SOURCE_PROTOCOL.into(),
                        point_id,
                        value: dv.value,
                        quality: dv.quality,
                        source_ts: dv.source_ts,
                        observed_ts: now_us,
                    };
                    out.push(BronzeEvent {
                        event_id: next_event_id(),
                        capture_id: capture_id.to_string(),
                        schema_version: crate::bronze::BRONZE_SCHEMA_VERSION.into(),
                        envelope: envelope.clone(),
                        family: BronzeEventFamily::ProcessReading(reading),
                    });
                }
                out
            }
            _ => Vec::new(), // not Read* — skip silently
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bronze::{
        BRONZE_SCHEMA_VERSION, EventEnvelope, OpcUaNodeId, PointValue, RawQuality,
        TransportProtocol,
    };
    use chrono::{DateTime, Utc};

    fn null_node_id() -> Vec<u8> {
        vec![0x00, 0x00]
    }

    fn build_request_header(request_handle: u32) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&null_node_id());
        bytes.extend_from_slice(&0i64.to_le_bytes());
        bytes.extend_from_slice(&request_handle.to_le_bytes());
        bytes.extend_from_slice(&0u32.to_le_bytes());
        bytes.extend_from_slice(&(-1i32).to_le_bytes());
        bytes.extend_from_slice(&0u32.to_le_bytes());
        bytes.extend_from_slice(&null_node_id());
        bytes.push(0x00);
        bytes
    }

    fn build_response_header(request_handle: u32, service_result: u32) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&0i64.to_le_bytes());
        bytes.extend_from_slice(&request_handle.to_le_bytes());
        bytes.extend_from_slice(&service_result.to_le_bytes());
        bytes.push(0x00);
        bytes.extend_from_slice(&(-1i32).to_le_bytes());
        bytes.extend_from_slice(&null_node_id());
        bytes.push(0x00);
        bytes
    }

    /// Build the body of a ReadRequest MSG: TypeId NodeId + RequestHeader +
    /// maxAge + timestampsToReturn + nodesToRead.
    fn build_read_request_msg_body(node_ids: &[u32]) -> Vec<u8> {
        let mut bytes = Vec::new();
        // TypeId: ReadRequest_Encoding_DefaultBinary (numeric, ns=0, id=631).
        // FourByte encoding fits.
        bytes.push(0x01);
        bytes.push(0x00); // ns
        bytes.extend_from_slice(&(READ_REQUEST_TYPE_ID as u16).to_le_bytes());
        bytes.extend_from_slice(&build_request_header(1));
        bytes.extend_from_slice(&0.0f64.to_le_bytes());
        bytes.extend_from_slice(&0u32.to_le_bytes());
        bytes.extend_from_slice(&(node_ids.len() as i32).to_le_bytes());
        for id in node_ids {
            // FourByte enc, ns=2.
            bytes.push(0x01);
            bytes.push(0x02);
            bytes.extend_from_slice(&(*id as u16).to_le_bytes());
            bytes.extend_from_slice(&13u32.to_le_bytes());
            bytes.extend_from_slice(&(-1i32).to_le_bytes());
            bytes.extend_from_slice(&0u16.to_le_bytes());
            bytes.extend_from_slice(&(-1i32).to_le_bytes());
        }
        bytes
    }

    fn build_read_response_msg_body(values: &[f64]) -> Vec<u8> {
        let mut bytes = Vec::new();
        // TypeId: ReadResponse_Encoding_DefaultBinary (634, ns=0).
        bytes.push(0x01);
        bytes.push(0x00);
        bytes.extend_from_slice(&(READ_RESPONSE_TYPE_ID as u16).to_le_bytes());
        bytes.extend_from_slice(&build_response_header(1, 0));
        bytes.extend_from_slice(&(values.len() as i32).to_le_bytes());
        for v in values {
            bytes.push(0x01); // HAS_VALUE
            bytes.push(11); // T_DOUBLE
            bytes.extend_from_slice(&v.to_le_bytes());
        }
        bytes
    }

    fn envelope() -> EventEnvelope {
        EventEnvelope {
            timestamp: DateTime::<Utc>::from_timestamp(1_700_000_000, 0).unwrap(),
            interface_id: 0,
            segment_hash: "seg".into(),
            frame_index: 0,
            session_key: "k".into(),
            src_mac: None,
            dst_mac: None,
            src_ip: None,
            dst_ip: None,
            src_port: None,
            dst_port: None,
            vlan_id: None,
            transport: TransportProtocol::Tcp,
            protocol: Some("opc_ua".into()),
            bytes_count: 0,
            packet_count: 1,
        }
    }

    #[test]
    fn read_request_alone_emits_no_events_but_stores_pending() {
        let mut d = OpcUaServiceDecoder::new();
        let body = build_read_request_msg_body(&[1234, 5678]);
        let env = envelope();
        let mut counter = 0u64;
        let mut next_id = || {
            counter += 1;
            format!("e{counter}")
        };
        let events = d.handle_msg_body(&body, 1, 7, &env, 100, &mut next_id, "cap");
        assert!(events.is_empty());
        assert_eq!(d.pending_count(), 1);
    }

    #[test]
    fn read_response_with_matching_request_pairs_node_ids() {
        let mut d = OpcUaServiceDecoder::new();
        let req_body = build_read_request_msg_body(&[1234, 5678]);
        let resp_body = build_read_response_msg_body(&[50.0, 51.5]);
        let env = envelope();
        let mut counter = 0u64;
        let mut next_id = || {
            counter += 1;
            format!("e{counter}")
        };
        let _ = d.handle_msg_body(&req_body, 1, 7, &env, 100, &mut next_id, "cap");
        let events = d.handle_msg_body(&resp_body, 1, 7, &env, 200, &mut next_id, "cap");
        assert_eq!(events.len(), 2);
        let r0 = match &events[0].family {
            BronzeEventFamily::ProcessReading(r) => r,
            _ => panic!(),
        };
        match &r0.point_id {
            PointIdentifier::OpcUaNode {
                namespace_index,
                identifier,
            } => {
                assert_eq!(*namespace_index, 2);
                assert_eq!(*identifier, OpcUaNodeId::Numeric(1234));
            }
            _ => panic!(),
        }
        assert_eq!(r0.value, PointValue::Double(50.0));
        assert!(matches!(r0.quality, RawQuality::OpcUaStatusCode(0)));
        assert_eq!(r0.observed_ts, 200);
        // Pending entry consumed.
        assert_eq!(d.pending_count(), 0);
    }

    #[test]
    fn read_response_without_request_uses_index_placeholder() {
        let mut d = OpcUaServiceDecoder::new();
        let resp_body = build_read_response_msg_body(&[42.0]);
        let env = envelope();
        let mut counter = 0u64;
        let mut next_id = || {
            counter += 1;
            format!("e{counter}")
        };
        let events = d.handle_msg_body(&resp_body, 1, 7, &env, 200, &mut next_id, "cap");
        assert_eq!(events.len(), 1);
        let r = match &events[0].family {
            BronzeEventFamily::ProcessReading(r) => r,
            _ => panic!(),
        };
        // Placeholder NodeId: namespace 0, numeric = array index.
        match &r.point_id {
            PointIdentifier::OpcUaNode {
                namespace_index,
                identifier,
            } => {
                assert_eq!(*namespace_index, 0);
                assert_eq!(*identifier, OpcUaNodeId::Numeric(0));
            }
            _ => panic!(),
        }
        // Suppress unused warning on BRONZE_SCHEMA_VERSION import.
        let _ = BRONZE_SCHEMA_VERSION;
    }

    #[test]
    fn unrelated_service_type_id_is_ignored() {
        let mut d = OpcUaServiceDecoder::new();
        // TypeId = some other service (e.g. WriteRequest 671).
        let mut bytes = vec![0x01, 0x00];
        bytes.extend_from_slice(&671u16.to_le_bytes());
        bytes.extend_from_slice(&[0u8; 50]);
        let env = envelope();
        let mut counter = 0u64;
        let mut next_id = || {
            counter += 1;
            format!("e{counter}")
        };
        let events = d.handle_msg_body(&bytes, 1, 1, &env, 100, &mut next_id, "cap");
        assert!(events.is_empty());
        assert_eq!(d.pending_count(), 0);
    }
}
