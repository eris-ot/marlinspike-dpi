//! SERCOS III (IEC 61491 / IEC 61784-2 CPF 3) session decoder. EtherType 0x88CD.
//!
//! Spec is partial-public; this decoder does recognition + telegram-type
//! identification + slot index. Deep Service Channel (SVC) parsing is future work.
//!
//! Wire format (payload after Ethernet header):
//!   [0] bits 0..6 = MST Cycle Count, bit 7 = Sync Flag
//!   [1] bits 0..2 = Telegram Type (MST/MDT/AT/NRT/HotPlug/reserved)
//!   [2..4] Slot Index u16 LE  [4..6] Data Length u16 LE  [6..] payload
//!
//! Sampling: first per (session, type) → _first event; every 1000th → _periodic;
//! sync-flag set→clear → sercos_sync_lost. Reference: packet-sercosiii.c.

use std::collections::{BTreeMap, HashMap, HashSet};

use crate::bronze::{
    AssetObservation, BronzeEvent, BronzeEventFamily, ProtocolTransaction, TransportProtocol,
};
use crate::engine::{
    DecoderInterest, SessionDecoder, StreamChunk, build_envelope, new_event, parse_anomaly_event,
};
use crate::registry::format_mac;

const TTYPE_MST: u8 = 0;
const TTYPE_MDT: u8 = 1;
const TTYPE_AT: u8 = 2;
const TTYPE_NRT: u8 = 3;
const TTYPE_HOTPLUG: u8 = 4;
const PERIODIC_INTERVAL: u64 = 1000;

fn telegram_type_name(t: u8) -> &'static str {
    match t {
        TTYPE_MST => "mst",
        TTYPE_MDT => "mdt",
        TTYPE_AT => "at",
        TTYPE_NRT => "nrt",
        TTYPE_HOTPLUG => "hotplug",
        _ => "reserved",
    }
}

/// Per-(session, telegram_type) counters.
#[derive(Default)]
struct TelegramTypeState {
    count: u64,
    first_emitted: bool,
}

#[derive(Default)]
struct SessionState {
    by_type: HashMap<u8, TelegramTypeState>,
    last_sync_flag: Option<bool>,
    master_observed: bool,
    slave_macs_observed: HashSet<[u8; 6]>,
}

#[derive(Default)]
pub(crate) struct SercosDecoder {
    sessions: HashMap<String, SessionState>,
}

impl SessionDecoder for SercosDecoder {
    fn name(&self) -> &'static str {
        "sercos"
    }

    fn interest(&self) -> &'static [DecoderInterest] {
        &[DecoderInterest::EtherType(0x88CD)]
    }

    fn on_datagram(&mut self, chunk: &StreamChunk<'_>, out: &mut Vec<BronzeEvent>) {
        let payload = chunk.payload;

        // Minimum viable frame: 6 bytes for header + slot_index + data_length.
        if payload.len() < 6 {
            out.push(parse_anomaly_event(
                chunk.capture_id.to_string(),
                build_envelope(
                    &chunk.context,
                    chunk.interface_id,
                    chunk.frame_index,
                    chunk.timestamp,
                    chunk.segment_hash,
                    TransportProtocol::Ethernet,
                    Some("sercos"),
                    chunk.captured_len,
                    chunk.session_key.clone(),
                ),
                self.name(),
                "medium",
                "sercos frame shorter than 6 bytes",
                payload,
            ));
            return;
        }

        let mst_cycle_count = payload[0] & 0x7F;
        let sync_flag = (payload[0] & 0x80) != 0;
        let telegram_type = payload[1] & 0x07;
        let slot_index = u16::from_le_bytes([payload[2], payload[3]]);
        let data_length = u16::from_le_bytes([payload[4], payload[5]]);
        let type_name = telegram_type_name(telegram_type);

        let envelope = build_envelope(
            &chunk.context,
            chunk.interface_id,
            chunk.frame_index,
            chunk.timestamp,
            chunk.segment_hash,
            TransportProtocol::Ethernet,
            Some("sercos"),
            chunk.captured_len,
            chunk.session_key.clone(),
        );

        let mut attributes = BTreeMap::new();
        attributes.insert("telegram_type".to_string(), telegram_type.to_string());
        attributes.insert("telegram_type_name".to_string(), type_name.to_string());
        attributes.insert("slot_index".to_string(), slot_index.to_string());
        attributes.insert("data_length".to_string(), data_length.to_string());
        attributes.insert("mst_cycle_count".to_string(), mst_cycle_count.to_string());
        attributes.insert("sync_flag".to_string(), sync_flag.to_string());

        // Reserved types 5..7 → anomaly (low severity).
        if telegram_type > TTYPE_HOTPLUG {
            out.push(parse_anomaly_event(
                chunk.capture_id.to_string(),
                envelope.clone(),
                self.name(),
                "low",
                &format!("unknown sercos telegram type {telegram_type}"),
                payload,
            ));
        }

        let session = self.sessions.entry(chunk.session_key.clone()).or_default();

        // Sync-flag set → clear transition.
        let sync_lost = matches!(session.last_sync_flag, Some(true)) && !sync_flag;
        session.last_sync_flag = Some(sync_flag);

        if sync_lost {
            let mut sync_attrs = attributes.clone();
            sync_attrs.insert("packet_count_observed".to_string(), {
                session
                    .by_type
                    .get(&telegram_type)
                    .map(|s| s.count)
                    .unwrap_or(0)
                    .to_string()
            });
            out.push(new_event(
                chunk.capture_id.to_string(),
                envelope.clone(),
                BronzeEventFamily::ProtocolTransaction(ProtocolTransaction {
                    operation: "sercos_sync_lost".to_string(),
                    status: "observed".to_string(),
                    request_summary: Some("sync flag cleared".to_string()),
                    response_summary: None,
                    object_refs: Vec::new(),
                    values: Vec::new(),
                    attributes: sync_attrs,
                    modbus: None,
                    protocol_fields: None,
                }),
            ));
        }

        // Per-type counters: first / periodic emission.
        let type_state = session.by_type.entry(telegram_type).or_default();
        type_state.count += 1;
        let count = type_state.count;
        let first_emitted = type_state.first_emitted;

        let operation: Option<String> = if !first_emitted {
            type_state.first_emitted = true;
            let op = if telegram_type > TTYPE_HOTPLUG {
                format!("sercos_unknown_type_{telegram_type}_first")
            } else {
                format!("sercos_{type_name}_first")
            };
            Some(op)
        } else if count.is_multiple_of(PERIODIC_INTERVAL) {
            let op = if telegram_type > TTYPE_HOTPLUG {
                format!("sercos_unknown_type_{telegram_type}_periodic")
            } else {
                format!("sercos_{type_name}_periodic")
            };
            Some(op)
        } else {
            None
        };

        if let Some(op) = operation {
            let mut tx_attrs = attributes.clone();
            if count.is_multiple_of(PERIODIC_INTERVAL) {
                tx_attrs.insert("packet_count_observed".to_string(), count.to_string());
            }
            out.push(new_event(
                chunk.capture_id.to_string(),
                envelope.clone(),
                BronzeEventFamily::ProtocolTransaction(ProtocolTransaction {
                    operation: op,
                    status: "observed".to_string(),
                    request_summary: Some(format!(
                        "sercos {type_name} slot={slot_index} len={data_length}"
                    )),
                    response_summary: None,
                    object_refs: vec![
                        format!("telegram_type:{telegram_type}"),
                        format!("slot_index:{slot_index}"),
                    ],
                    values: Vec::new(),
                    attributes: tx_attrs,
                    modbus: None,
                    protocol_fields: None,
                }),
            ));
        }

        // MST sender → master asset (once per session).
        if telegram_type == TTYPE_MST && !session.master_observed {
            session.master_observed = true;
            out.push(new_event(
                chunk.capture_id.to_string(),
                envelope.clone(),
                BronzeEventFamily::AssetObservation(AssetObservation {
                    asset_key: format_mac(&chunk.context.src_mac),
                    role: Some("sercos_master_node".to_string()),
                    vendor: None,
                    model: None,
                    firmware: None,
                    hostnames: Vec::new(),
                    protocols: vec!["sercos".to_string()],
                    identifiers: BTreeMap::from([(
                        "mac".to_string(),
                        format_mac(&chunk.context.src_mac),
                    )]),
                }),
            ));
        }

        // AT sender → slave asset (once per unique source MAC).
        if telegram_type == TTYPE_AT
            && !session.slave_macs_observed.contains(&chunk.context.src_mac)
        {
            session.slave_macs_observed.insert(chunk.context.src_mac);
            out.push(new_event(
                chunk.capture_id.to_string(),
                envelope,
                BronzeEventFamily::AssetObservation(AssetObservation {
                    asset_key: format_mac(&chunk.context.src_mac),
                    role: Some("sercos_drive_slave".to_string()),
                    vendor: None,
                    model: None,
                    firmware: None,
                    hostnames: Vec::new(),
                    protocols: vec!["sercos".to_string()],
                    identifiers: BTreeMap::from([(
                        "mac".to_string(),
                        format_mac(&chunk.context.src_mac),
                    )]),
                }),
            ));
        }
    }
}

inventory::submit!(crate::engine::decoders::DecoderRegistration {
    name: "sercos",
    factory: || Box::new(SercosDecoder::default()),
});

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bronze::BronzeEventFamily;
    use crate::engine::StreamChunk;
    use crate::registry::PacketContext;
    use chrono::Utc;
    use std::net::{IpAddr, Ipv4Addr};

    fn ctx(src_mac: [u8; 6]) -> PacketContext {
        PacketContext {
            src_mac,
            dst_mac: [0xFF; 6],
            src_ip: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            dst_ip: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            src_port: 0,
            dst_port: 0,
            vlan_id: None,
            timestamp: 0,
        }
    }

    fn make_chunk<'a>(payload: &'a [u8], src_mac: [u8; 6], session: &str) -> StreamChunk<'a> {
        StreamChunk {
            capture_id: "test",
            segment_hash: "aa",
            interface_id: 0,
            frame_index: 1,
            timestamp: Utc::now(),
            context: ctx(src_mac),
            ethertype: 0x88CD,
            ip_proto: None,
            llc: None,
            transport: TransportProtocol::Ethernet,
            payload,
            session_key: session.to_string(),
            captured_len: payload.len() as u64,
        }
    }

    /// byte0 = (sync_flag<<7)|(cycle_count&0x7F), byte1 = telegram_type&0x07.
    fn build_frame(ttype: u8, sync: bool, cycle: u8, slot: u16, dlen: u16) -> Vec<u8> {
        let b0 = if sync { 0x80u8 } else { 0 } | (cycle & 0x7F);
        let mut f = vec![b0, ttype & 0x07];
        f.extend_from_slice(&slot.to_le_bytes());
        f.extend_from_slice(&dlen.to_le_bytes());
        f
    }

    fn txns(events: &[BronzeEvent]) -> Vec<&ProtocolTransaction> {
        events
            .iter()
            .filter_map(|e| {
                if let BronzeEventFamily::ProtocolTransaction(ref t) = e.family {
                    Some(t)
                } else {
                    None
                }
            })
            .collect()
    }

    fn assets(events: &[BronzeEvent]) -> Vec<&AssetObservation> {
        events
            .iter()
            .filter_map(|e| {
                if let BronzeEventFamily::AssetObservation(ref a) = e.family {
                    Some(a)
                } else {
                    None
                }
            })
            .collect()
    }

    fn anomalies(events: &[BronzeEvent]) -> Vec<&crate::bronze::ParseAnomaly> {
        events
            .iter()
            .filter_map(|e| {
                if let BronzeEventFamily::ParseAnomaly(ref a) = e.family {
                    Some(a)
                } else {
                    None
                }
            })
            .collect()
    }

    // 1. MST — first sight: correct operation, mst_cycle_count, master AssetObservation.
    #[test]
    fn mst_first_emits_transaction_and_master_asset() {
        let mut dec = SercosDecoder::default();
        let mut out = Vec::new();
        let mac = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55];
        // type=0 (MST), sync_flag=true, cycle_count=42, slot=0, data_len=0
        let frame = build_frame(TTYPE_MST, true, 42, 0, 0);
        dec.on_datagram(&make_chunk(&frame, mac, "s1"), &mut out);

        let tx = txns(&out);
        assert_eq!(tx.len(), 1, "expect exactly one ProtocolTransaction");
        assert_eq!(tx[0].operation, "sercos_mst_first");
        assert_eq!(tx[0].attributes["mst_cycle_count"], "42");
        assert_eq!(tx[0].attributes["sync_flag"], "true");
        assert_eq!(tx[0].attributes["telegram_type_name"], "mst");

        let obs = assets(&out);
        assert_eq!(obs.len(), 1, "expect master AssetObservation");
        assert_eq!(obs[0].role.as_deref(), Some("sercos_master_node"));
    }

    // 2. MDT — first sight.
    #[test]
    fn mdt_first_emits_transaction() {
        let mut dec = SercosDecoder::default();
        let mut out = Vec::new();
        let mac = [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF];
        let frame = build_frame(TTYPE_MDT, false, 0, 1, 8);
        dec.on_datagram(&make_chunk(&frame, mac, "s2"), &mut out);

        let tx = txns(&out);
        assert_eq!(tx.len(), 1);
        assert_eq!(tx[0].operation, "sercos_mdt_first");
        assert_eq!(tx[0].attributes["telegram_type_name"], "mdt");
        assert!(anomalies(&out).is_empty(), "no anomalies for known type");
    }

    // 3. AT — first sight + slave AssetObservation.
    #[test]
    fn at_first_emits_transaction_and_slave_asset() {
        let mut dec = SercosDecoder::default();
        let mut out = Vec::new();
        let mac = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06];
        let frame = build_frame(TTYPE_AT, true, 5, 2, 16);
        dec.on_datagram(&make_chunk(&frame, mac, "s3"), &mut out);

        let tx = txns(&out);
        assert_eq!(tx.len(), 1);
        assert_eq!(tx[0].operation, "sercos_at_first");

        let obs = assets(&out);
        assert_eq!(obs.len(), 1, "expect slave AssetObservation");
        assert_eq!(obs[0].role.as_deref(), Some("sercos_drive_slave"));
    }

    // 4. NRT — first sight.
    #[test]
    fn nrt_first_emits_transaction() {
        let mut dec = SercosDecoder::default();
        let mut out = Vec::new();
        let mac = [0x10, 0x20, 0x30, 0x40, 0x50, 0x60];
        let frame = build_frame(TTYPE_NRT, false, 0, 0, 64);
        dec.on_datagram(&make_chunk(&frame, mac, "s4"), &mut out);

        let tx = txns(&out);
        assert_eq!(tx.len(), 1);
        assert_eq!(tx[0].operation, "sercos_nrt_first");
        assert_eq!(tx[0].attributes["telegram_type_name"], "nrt");
    }

    // 5. Reserved type 7 — _first transaction + ParseAnomaly severity=low.
    #[test]
    fn reserved_type7_first_and_anomaly() {
        let mut dec = SercosDecoder::default();
        let mut out = Vec::new();
        let mac = [0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x01];
        let frame = build_frame(7, false, 0, 0, 0);
        dec.on_datagram(&make_chunk(&frame, mac, "s5"), &mut out);

        let tx = txns(&out);
        assert_eq!(tx.len(), 1);
        assert_eq!(tx[0].operation, "sercos_unknown_type_7_first");

        let anom = anomalies(&out);
        assert_eq!(anom.len(), 1, "expect one ParseAnomaly");
        assert_eq!(anom[0].severity, "low");
        assert!(anom[0].reason.contains('7'));
    }

    // 6. Truncated 4-byte frame — ParseAnomaly severity=medium, no transaction.
    #[test]
    fn truncated_frame_anomaly_medium() {
        let mut dec = SercosDecoder::default();
        let mut out = Vec::new();
        let mac = [0x00, 0x00, 0x00, 0x00, 0x00, 0x01];
        let frame: Vec<u8> = vec![0x82, 0x00, 0x00, 0x00]; // only 4 bytes
        dec.on_datagram(&make_chunk(&frame, mac, "s6"), &mut out);

        let anom = anomalies(&out);
        assert_eq!(anom.len(), 1, "expect exactly one ParseAnomaly");
        assert_eq!(anom[0].severity, "medium");
        // No ProtocolTransaction on truncated frames.
        assert!(txns(&out).is_empty());
    }

    // 7. Periodic emission at frame 1000.
    #[test]
    fn periodic_emission_at_1000th_frame() {
        let mut dec = SercosDecoder::default();
        let mac = [0x00, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE];
        let frame = build_frame(TTYPE_MDT, false, 0, 0, 4);

        let mut first_out = Vec::new();
        dec.on_datagram(&make_chunk(&frame, mac, "s7"), &mut first_out);
        // First frame: one _first transaction.
        assert_eq!(txns(&first_out)[0].operation, "sercos_mdt_first");

        // Frames 2..999 — no transactions.
        for _ in 2..1000 {
            let mut out = Vec::new();
            dec.on_datagram(&make_chunk(&frame, mac, "s7"), &mut out);
            assert!(
                txns(&out).is_empty(),
                "no emission between first and 1000th"
            );
        }

        // Frame 1000 — periodic.
        let mut periodic_out = Vec::new();
        dec.on_datagram(&make_chunk(&frame, mac, "s7"), &mut periodic_out);
        let tx = txns(&periodic_out);
        assert_eq!(tx.len(), 1);
        assert_eq!(tx[0].operation, "sercos_mdt_periodic");
        assert_eq!(tx[0].attributes["packet_count_observed"], "1000");
    }

    // 8. Sync-flag set→clear emits sercos_sync_lost.
    #[test]
    fn sync_lost_emitted_on_flag_clear() {
        let mut dec = SercosDecoder::default();
        let mac = [0x00, 0x11, 0x22, 0x33, 0x44, 0x66];

        // Frame with sync_flag=true.
        let synced = build_frame(TTYPE_MST, true, 10, 0, 0);
        let mut out1 = Vec::new();
        dec.on_datagram(&make_chunk(&synced, mac, "s8"), &mut out1);
        // No sync_lost yet.
        assert!(
            !txns(&out1)
                .iter()
                .any(|t| t.operation == "sercos_sync_lost")
        );

        // Frame with sync_flag=false — transition triggers sync_lost.
        let unsynced = build_frame(TTYPE_MST, false, 11, 0, 0);
        let mut out2 = Vec::new();
        dec.on_datagram(&make_chunk(&unsynced, mac, "s8"), &mut out2);
        let tx = txns(&out2);
        assert!(
            tx.iter().any(|t| t.operation == "sercos_sync_lost"),
            "sercos_sync_lost should be emitted on sync flag clear"
        );
    }
}
