//! EtherNet/IP Class 1 cyclic I/O decoder — UDP/2222 implicit messaging.
//!
//! ## Why this decoder exists
//!
//! The sibling `ethernet_ip` decoder (TCP/44818) handles explicit messaging.
//! Class 1 implicit (cyclic) I/O connections carry servo positions, drive
//! commands, and safety I/O at 1–10 ms scan rates over UDP/2222 with no EIP
//! encapsulation header — just a raw CPF packet on the wire.
//!
//! ## Periodic sampling rationale
//!
//! A single servo axis produces 1000–5000 datagrams/sec. Emitting one event per
//! datagram floods downstream consumers and buries real anomalies. Strategy:
//!   - **First** datagram per connection: emit baseline open event.
//!   - Every **1000th** datagram: emit a sampled heartbeat.
//!   - **Sequence gap**: emit immediately — the only per-datagram signal worth
//!     surfacing (packet loss, replay, or controller restart).
//!
//! ## Wire format (CIP Vol 2, §3-2.2)
//!
//! ```text
//! [item_count u16 LE] [item: type u16 LE + length u16 LE + data ...]
//! Sequenced Address Item (0x8002): connection_id u32 LE + seq_number u32 LE
//! Connected Address Item  (0x00A1): connection_id u32 LE
//! Connected Data Item     (0x00B1): cip_seq_count u16 LE + I/O bytes
//! ```
//! Rockwell run/idle header: bit 0 of first I/O byte (1=Run, 0=Idle).

use std::collections::{BTreeMap, HashMap};

use crate::bronze::{
    AssetObservation, BronzeEvent, BronzeEventFamily, ProtocolTransaction, TransportProtocol,
};
use crate::engine::{
    build_envelope, new_event, parse_anomaly_event, DecoderInterest, SessionDecoder, StreamChunk,
};

const ITEM_SEQUENCED_ADDR: u16 = 0x8002;
const ITEM_CONNECTED_ADDR: u16 = 0x00A1;
const ITEM_CONNECTED_DATA: u16 = 0x00B1;

/// Emit a sampled heartbeat every N datagrams per connection.
const PERIODIC_INTERVAL: u64 = 1000;

// ── State ─────────────────────────────────────────────────────────────────────

#[derive(Debug)]
struct ConnectionState {
    seq_last: u32,
    packet_count: u64,
}

// ── Parser output ─────────────────────────────────────────────────────────────

struct ParsedCpf<'a> {
    item_count: u16,
    connection_id: u32,
    sequence_number: u32,
    /// Payload bytes after the 2-byte CIP sequence count.
    io_data: &'a [u8],
}

// ── Decoder ───────────────────────────────────────────────────────────────────

#[derive(Default)]
pub(crate) struct EipIoDecoder {
    /// Keyed by (session_key, connection_id).
    connections: HashMap<(String, u32), ConnectionState>,
}

impl SessionDecoder for EipIoDecoder {
    fn name(&self) -> &'static str { "eip_io" }

    fn interest(&self) -> &'static [DecoderInterest] {
        &[DecoderInterest::UdpPort(2222)]
    }

    fn on_datagram(&mut self, chunk: &StreamChunk<'_>, out: &mut Vec<BronzeEvent>) {
        let envelope = build_envelope(
            &chunk.context, chunk.interface_id, chunk.frame_index,
            chunk.timestamp, chunk.segment_hash, TransportProtocol::Udp,
            Some("eip_io"), chunk.captured_len, chunk.session_key.clone(),
        );

        let cpf = match parse_cpf(chunk.payload) {
            Ok(c) => c,
            Err(reason) => {
                out.push(parse_anomaly_event(
                    chunk.capture_id.to_string(), envelope, self.name(),
                    "medium", reason, chunk.payload,
                ));
                return;
            }
        };

        let key = (chunk.session_key.clone(), cpf.connection_id);
        let conn_id_hex = format!("{:#010x}", cpf.connection_id);

        if let Some(state) = self.connections.get_mut(&key) {
            let expected = state.seq_last.wrapping_add(1);
            let gap = cpf.sequence_number != expected;
            state.packet_count += 1;
            let count = state.packet_count;
            state.seq_last = cpf.sequence_number;

            if gap {
                let mut attrs = BTreeMap::new();
                attrs.insert("connection_id".to_string(), conn_id_hex.clone());
                attrs.insert("packet_count_observed".to_string(), count.to_string());
                out.push(new_event(
                    chunk.capture_id.to_string(), envelope.clone(),
                    BronzeEventFamily::ProtocolTransaction(ProtocolTransaction {
                        operation: "eip_io_class1_sequence_gap".to_string(),
                        status: "observed".to_string(),
                        request_summary: Some(format!(
                            "EIP Class 1 seq gap conn={conn_id_hex} \
                             expected={expected} got={}", cpf.sequence_number
                        )),
                        response_summary: None, object_refs: vec![],
                        values: vec![], attributes: attrs,
                        modbus: None, protocol_fields: None,
                    }),
                ));
                out.push(parse_anomaly_event(
                    chunk.capture_id.to_string(), envelope, self.name(),
                    "low", "EIP Class 1 sequence number gap", chunk.payload,
                ));
                return;
            }

            if count % PERIODIC_INTERVAL == 0 {
                let mut attrs = BTreeMap::new();
                attrs.insert("connection_id".to_string(), conn_id_hex);
                attrs.insert("packet_count_observed".to_string(), count.to_string());
                out.push(new_event(
                    chunk.capture_id.to_string(), envelope,
                    BronzeEventFamily::ProtocolTransaction(ProtocolTransaction {
                        operation: "eip_io_class1_periodic".to_string(),
                        status: "observed".to_string(),
                        request_summary: Some(format!(
                            "EIP Class 1 periodic sample: {count} packets"
                        )),
                        response_summary: None, object_refs: vec![],
                        values: vec![], attributes: attrs,
                        modbus: None, protocol_fields: None,
                    }),
                ));
            }
        } else {
            // First datagram — baseline open + asset identification.
            let run_idle = decode_run_idle(cpf.io_data);

            let mut attrs = BTreeMap::new();
            attrs.insert("connection_id".to_string(), conn_id_hex.clone());
            attrs.insert("payload_length".to_string(), cpf.io_data.len().to_string());
            attrs.insert("cpf_item_count".to_string(), cpf.item_count.to_string());
            attrs.insert("sequence_number_initial".to_string(), cpf.sequence_number.to_string());
            attrs.insert("run_idle".to_string(), run_idle.to_string());

            out.push(new_event(
                chunk.capture_id.to_string(), envelope.clone(),
                BronzeEventFamily::ProtocolTransaction(ProtocolTransaction {
                    operation: "eip_io_class1_open".to_string(),
                    status: "observed".to_string(),
                    request_summary: Some(format!(
                        "EIP Class 1 connection opened conn={conn_id_hex}"
                    )),
                    response_summary: None, object_refs: vec![],
                    values: vec![], attributes: attrs,
                    modbus: None, protocol_fields: None,
                }),
            ));

            for ip_str in [
                chunk.context.src_ip.to_string(),
                chunk.context.dst_ip.to_string(),
            ] {
                let mut ids = BTreeMap::new();
                ids.insert("ip".to_string(), ip_str.clone());
                ids.insert("connection_id".to_string(), conn_id_hex.clone());
                out.push(new_event(
                    chunk.capture_id.to_string(), envelope.clone(),
                    BronzeEventFamily::AssetObservation(AssetObservation {
                        asset_key: ip_str,
                        role: Some("eip_io_endpoint".to_string()),
                        vendor: None, model: None, firmware: None,
                        hostnames: vec![],
                        protocols: vec!["ethernet_ip".to_string(), "cip".to_string()],
                        identifiers: ids,
                    }),
                ));
            }

            self.connections.insert(key, ConnectionState {
                seq_last: cpf.sequence_number,
                packet_count: 1,
            });
        }
    }
}

// ── CPF parser ────────────────────────────────────────────────────────────────

fn parse_cpf(data: &[u8]) -> Result<ParsedCpf<'_>, &'static str> {
    if data.len() < 2 {
        return Err("CPF datagram too short for item_count");
    }
    let item_count = u16::from_le_bytes([data[0], data[1]]);
    let remaining = data.len().saturating_sub(2);
    if item_count as usize > remaining / 4 {
        return Err("CPF item_count exceeds available datagram space");
    }

    let mut offset = 2usize;
    let mut connection_id: Option<u32> = None;
    let mut sequence_number: Option<u32> = None;
    let mut io_data: Option<&[u8]> = None;

    for _ in 0..item_count {
        if offset + 4 > data.len() {
            return Err("CPF item header truncated");
        }
        let item_type = u16::from_le_bytes([data[offset], data[offset + 1]]);
        let item_len = u16::from_le_bytes([data[offset + 2], data[offset + 3]]) as usize;
        offset += 4;
        if offset + item_len > data.len() {
            return Err("CPF item data truncated");
        }
        let item_data = &data[offset..offset + item_len];

        match item_type {
            ITEM_SEQUENCED_ADDR => {
                if item_len < 8 { return Err("Sequenced Address Item too short"); }
                connection_id = Some(u32::from_le_bytes(item_data[..4].try_into().unwrap()));
                sequence_number = Some(u32::from_le_bytes(item_data[4..8].try_into().unwrap()));
            }
            ITEM_CONNECTED_ADDR => {
                if item_len < 4 { return Err("Connected Address Item too short"); }
                connection_id.get_or_insert_with(|| {
                    u32::from_le_bytes(item_data[..4].try_into().unwrap())
                });
            }
            ITEM_CONNECTED_DATA => {
                if item_len < 2 { return Err("Connected Data Item too short for CIP seq count"); }
                // If no Sequenced Address Item was present, use the 16-bit CIP
                // sequence count (widened to u32) as the tracked sequence value.
                sequence_number.get_or_insert_with(|| {
                    u16::from_le_bytes([item_data[0], item_data[1]]) as u32
                });
                io_data = Some(&item_data[2..]);
            }
            _ => { /* unknown item type — skip */ }
        }
        offset += item_len;
    }

    Ok(ParsedCpf {
        item_count,
        connection_id: connection_id.ok_or("CPF: no Address Item found")?,
        sequence_number: sequence_number.ok_or("CPF: no sequence number found")?,
        io_data: io_data.unwrap_or(&[]),
    })
}

// ── Run/Idle helper ───────────────────────────────────────────────────────────

/// Bit 0 of the first I/O byte: 1 = controller Run, 0 = Idle (Rockwell convention).
fn decode_run_idle(io_data: &[u8]) -> &'static str {
    match io_data.first() {
        Some(&b) if b & 0x01 != 0 => "run",
        Some(_) => "idle",
        None => "unknown",
    }
}

// ── Registration ──────────────────────────────────────────────────────────────

inventory::submit!(crate::engine::decoders::DecoderRegistration {
    name: "eip_io",
    factory: || Box::new(EipIoDecoder::default()),
});

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};
    use chrono::{TimeZone, Utc};
    use super::*;
    use crate::bronze::{AssetObservation, BronzeEventFamily, ProtocolTransaction};
    use crate::engine::{DecoderInterest, StreamChunk};
    use crate::registry::PacketContext;

    fn ctx(src: [u8; 4], dst: [u8; 4]) -> PacketContext {
        PacketContext {
            src_mac: [0u8; 6], dst_mac: [0u8; 6],
            src_ip: IpAddr::V4(Ipv4Addr::from(src)),
            dst_ip: IpAddr::V4(Ipv4Addr::from(dst)),
            src_port: 2222, dst_port: 2222,
            vlan_id: None, timestamp: 1_700_000_000_000_000,
        }
    }

    fn chunk<'a>(payload: &'a [u8], context: PacketContext, sk: &str) -> StreamChunk<'a> {
        StreamChunk {
            capture_id: "test", segment_hash: "seg", interface_id: 0, frame_index: 1,
            timestamp: Utc.timestamp_opt(1_700_000_000, 0).unwrap(),
            context, ethertype: 0x0800, ip_proto: Some(17), llc: None,
            transport: TransportProtocol::Udp, payload,
            session_key: sk.to_string(), captured_len: payload.len() as u64,
        }
    }

    /// CPF with Sequenced Address Item + Connected Data Item.
    fn cpf_seq(connection_id: u32, seq: u32, io: &[u8]) -> Vec<u8> {
        let mut b = Vec::new();
        b.extend_from_slice(&2u16.to_le_bytes());
        b.extend_from_slice(&ITEM_SEQUENCED_ADDR.to_le_bytes());
        b.extend_from_slice(&8u16.to_le_bytes());
        b.extend_from_slice(&connection_id.to_le_bytes());
        b.extend_from_slice(&seq.to_le_bytes());
        let data_len = (2 + io.len()) as u16;
        b.extend_from_slice(&ITEM_CONNECTED_DATA.to_le_bytes());
        b.extend_from_slice(&data_len.to_le_bytes());
        b.extend_from_slice(&(seq as u16).to_le_bytes()); // CIP seq count
        b.extend_from_slice(io);
        b
    }

    fn txns(events: &[BronzeEvent]) -> Vec<&ProtocolTransaction> {
        events.iter().filter_map(|e| {
            if let BronzeEventFamily::ProtocolTransaction(ref tx) = e.family { Some(tx) } else { None }
        }).collect()
    }

    fn assets(events: &[BronzeEvent]) -> Vec<&AssetObservation> {
        events.iter().filter_map(|e| {
            if let BronzeEventFamily::AssetObservation(ref a) = e.family { Some(a) } else { None }
        }).collect()
    }

    fn anomalies(events: &[BronzeEvent]) -> Vec<&crate::bronze::ParseAnomaly> {
        events.iter().filter_map(|e| {
            if let BronzeEventFamily::ParseAnomaly(ref a) = e.family { Some(a) } else { None }
        }).collect()
    }

    // 1. First datagram → open event + two AssetObservations.
    #[test]
    fn test_first_datagram_open_and_assets() {
        let p = cpf_seq(0x1234_5678, 0, &[0x01, 0xAB]);
        let mut dec = EipIoDecoder::default();
        let mut ev = Vec::new();
        dec.on_datagram(&chunk(&p, ctx([10,0,0,1], [10,0,0,2]), "sk1"), &mut ev);

        let tx = txns(&ev);
        assert_eq!(tx.len(), 1);
        assert_eq!(tx[0].operation, "eip_io_class1_open");
        assert_eq!(tx[0].status, "observed");
        assert_eq!(tx[0].attributes.get("connection_id").map(String::as_str), Some("0x12345678"));
        assert_eq!(tx[0].attributes.get("sequence_number_initial").map(String::as_str), Some("0"));
        assert_eq!(tx[0].attributes.get("run_idle").map(String::as_str), Some("run"));

        let a = assets(&ev);
        assert_eq!(a.len(), 2);
        for obs in &a {
            assert_eq!(obs.role.as_deref(), Some("eip_io_endpoint"));
            assert_eq!(obs.identifiers.get("connection_id").map(String::as_str), Some("0x12345678"));
        }
    }

    // 2. Normal sequential datagrams → no events.
    #[test]
    fn test_sequential_datagrams_silent() {
        let conn_id = 0xDEAD_BEEF;
        let mut dec = EipIoDecoder::default();
        let mut ev = Vec::new();
        dec.on_datagram(&chunk(&cpf_seq(conn_id, 0, &[0x00]), ctx([10,0,1,1],[10,0,1,2]), "sk2"), &mut ev);
        ev.clear();
        dec.on_datagram(&chunk(&cpf_seq(conn_id, 1, &[0x00]), ctx([10,0,1,1],[10,0,1,2]), "sk2"), &mut ev);
        assert!(ev.is_empty(), "sequential datagram must emit no events");
    }

    // 3. Sequence gap → gap transaction + low ParseAnomaly.
    #[test]
    fn test_sequence_gap() {
        let conn_id = 0xCAFE_BABE;
        let mut dec = EipIoDecoder::default();
        let mut ev = Vec::new();
        dec.on_datagram(&chunk(&cpf_seq(conn_id, 10, &[0x00]), ctx([10,0,2,1],[10,0,2,2]), "sk3"), &mut ev);
        ev.clear();
        dec.on_datagram(&chunk(&cpf_seq(conn_id, 99, &[0x00]), ctx([10,0,2,1],[10,0,2,2]), "sk3"), &mut ev);

        let tx = txns(&ev);
        assert_eq!(tx.len(), 1);
        assert_eq!(tx[0].operation, "eip_io_class1_sequence_gap");
        assert_eq!(tx[0].status, "observed");

        let an = anomalies(&ev);
        assert_eq!(an.len(), 1);
        assert_eq!(an[0].severity, "low");
        assert!(an[0].reason.contains("sequence number gap"));
    }

    // 4. Two distinct connection_ids → two open events, four AssetObservations.
    #[test]
    fn test_two_connections_independent() {
        let mut dec = EipIoDecoder::default();
        let mut ev = Vec::new();
        dec.on_datagram(&chunk(&cpf_seq(0xAAAA_0001, 0, &[0x00]), ctx([10,0,3,1],[10,0,3,2]), "sk4"), &mut ev);
        dec.on_datagram(&chunk(&cpf_seq(0xBBBB_0002, 0, &[0x00]), ctx([10,0,3,1],[10,0,3,2]), "sk4"), &mut ev);

        let opens: Vec<_> = txns(&ev).into_iter().filter(|t| t.operation == "eip_io_class1_open").collect();
        assert_eq!(opens.len(), 2);
        assert_eq!(assets(&ev).len(), 4);

        let ids: Vec<_> = opens.iter()
            .map(|t| t.attributes.get("connection_id").map(String::as_str).unwrap_or(""))
            .collect();
        assert!(ids.contains(&"0xaaaa0001"));
        assert!(ids.contains(&"0xbbbb0002"));
    }

    // 5. Malformed CPF (item_count implies more data than available) → medium anomaly.
    #[test]
    fn test_malformed_cpf_medium_anomaly() {
        // item_count=10, but datagram is only 8 bytes total.
        let bad: Vec<u8> = vec![0x0A, 0x00, 0xAB, 0xCD, 0xEF, 0x01, 0x02, 0x03];
        let mut dec = EipIoDecoder::default();
        let mut ev = Vec::new();
        dec.on_datagram(&chunk(&bad, ctx([10,0,4,1],[10,0,4,2]), "sk5"), &mut ev);

        let an = anomalies(&ev);
        assert_eq!(an.len(), 1);
        assert_eq!(an[0].severity, "medium");
        assert!(txns(&ev).is_empty(), "no transaction for malformed datagram");
    }

    // 6. Run/Idle bit: set→"run", clear→"idle", empty payload→"unknown".
    #[test]
    fn test_run_idle_variants() {
        let mut dec = EipIoDecoder::default();

        // run
        let mut ev = Vec::new();
        dec.on_datagram(&chunk(&cpf_seq(0x01, 0, &[0x01]), ctx([10,0,5,1],[10,0,5,2]), "sk6a"), &mut ev);
        assert_eq!(txns(&ev)[0].attributes.get("run_idle").map(String::as_str), Some("run"));

        // idle
        ev.clear();
        dec.on_datagram(&chunk(&cpf_seq(0x02, 0, &[0x00]), ctx([10,0,5,1],[10,0,5,2]), "sk6b"), &mut ev);
        assert_eq!(txns(&ev)[0].attributes.get("run_idle").map(String::as_str), Some("idle"));

        // unknown — Connected Data Item with only the 2-byte CIP seq count, no I/O.
        ev.clear();
        let mut no_io: Vec<u8> = Vec::new();
        no_io.extend_from_slice(&2u16.to_le_bytes());
        no_io.extend_from_slice(&ITEM_SEQUENCED_ADDR.to_le_bytes());
        no_io.extend_from_slice(&8u16.to_le_bytes());
        no_io.extend_from_slice(&0x03u32.to_le_bytes());
        no_io.extend_from_slice(&0u32.to_le_bytes());
        no_io.extend_from_slice(&ITEM_CONNECTED_DATA.to_le_bytes());
        no_io.extend_from_slice(&2u16.to_le_bytes()); // only CIP seq count, no I/O
        no_io.extend_from_slice(&0u16.to_le_bytes());
        dec.on_datagram(&chunk(&no_io, ctx([10,0,5,1],[10,0,5,2]), "sk6c"), &mut ev);
        assert_eq!(txns(&ev)[0].attributes.get("run_idle").map(String::as_str), Some("unknown"));
    }
}
