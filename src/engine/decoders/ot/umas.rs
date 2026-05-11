//! Modicon UMAS (Unified Messaging Application Services) decoder.
//!
//! UMAS is Schneider Electric's proprietary management protocol encapsulated
//! inside Modbus/TCP function code 0x5A (90). Used for engineering operations on
//! Modicon M340, M580, and Quantum PLCs. Involved in the 2022 Industroyer2
//! attacks against Ukrainian power infrastructure.
//!
//! Protocol is partially reverse-engineered. Public sources: NCC Group (2021),
//! Claroty (2021), Forescout Research Labs (2022), Nozomi Networks (2023).
//! No official Schneider specification is publicly available.
//!
//! Wire format:
//!   MBAP header (7 B, BE): [txn_id:u16][proto_id:u16=0][length:u16][unit_id:u8]
//!   Modbus PDU:             [FC:u8=0x5A][pair_id:u8][umas_subfn:u8][payload...]
//!   Exception responses use FC = 0xDA (0x5A | 0x80).

use std::collections::{BTreeMap, HashMap};

use chrono::{DateTime, Utc};

use crate::bronze::{
    AssetObservation, BronzeEvent, BronzeEventFamily, EventEnvelope, ProtocolTransaction,
    TransportProtocol,
};
use crate::engine::{
    build_envelope, new_event, parse_anomaly_event, DecoderInterest, SessionDecoder, StreamChunk,
};

// ── Constants ─────────────────────────────────────────────────────────────────

const FC_UMAS: u8 = 0x5A;
const FC_UMAS_EXC: u8 = 0xDA;

// UMAS sub-function codes (byte 1 of the UMAS PDU, after pair_id).
const SF_INIT_COMM: u8 = 0x01;
const SF_READ_ID: u8 = 0x02;
const SF_READ_PROJECT_INFO: u8 = 0x03;
const SF_READ_PLC_INFO: u8 = 0x04;
const SF_READ_CARD_INFO: u8 = 0x06;
const SF_REPEAT: u8 = 0x10;
const SF_TAKE_RESERVATION: u8 = 0x11;
const SF_RELEASE_RESERVATION: u8 = 0x12;
const SF_KEEP_ALIVE: u8 = 0x13;
const SF_READ_MEM: u8 = 0x20;
const SF_WRITE_MEM: u8 = 0x21;
const SF_READ_VARS: u8 = 0x22;
const SF_WRITE_VARS: u8 = 0x23;
const SF_READ_COILS: u8 = 0x24;
const SF_WRITE_COILS: u8 = 0x25;
const SF_INIT_UPLOAD: u8 = 0x26;
const SF_UPLOAD_BLOCK: u8 = 0x27;
const SF_END_UPLOAD: u8 = 0x28;
const SF_INIT_DOWNLOAD: u8 = 0x29;
const SF_DOWNLOAD_BLOCK: u8 = 0x2A;
const SF_END_DOWNLOAD: u8 = 0x2B;
const SF_START_PLC: u8 = 0x40;
const SF_STOP_PLC: u8 = 0x41;
const SF_MONITOR_PLC: u8 = 0x50;
const SF_CHECK_PLC: u8 = 0x58;
const SF_READ_IO: u8 = 0x70;
const SF_WRITE_IO: u8 = 0x71;
const SF_GET_STATUS: u8 = 0x73;
const SF_AUTH_REQUEST: u8 = 0xFD;
const SF_AUTH_REPLY: u8 = 0xFE;

// ── Helpers ───────────────────────────────────────────────────────────────────

fn umas_operation(sf: u8) -> String {
    match sf {
        SF_INIT_COMM => "umas_init_comm",
        SF_READ_ID => "umas_read_id",
        SF_READ_PROJECT_INFO => "umas_read_project_info",
        SF_READ_PLC_INFO => "umas_read_plc_info",
        SF_READ_CARD_INFO => "umas_read_card_info",
        SF_REPEAT => "umas_repeat",
        SF_TAKE_RESERVATION => "umas_take_plc_reservation",
        SF_RELEASE_RESERVATION => "umas_release_plc_reservation",
        SF_KEEP_ALIVE => "umas_keep_alive",
        SF_READ_MEM => "umas_read_memory_block",
        SF_WRITE_MEM => "umas_write_memory_block",
        SF_READ_VARS => "umas_read_variables",
        SF_WRITE_VARS => "umas_write_variables",
        SF_READ_COILS => "umas_read_coils_registers",
        SF_WRITE_COILS => "umas_write_coils_registers",
        SF_INIT_UPLOAD => "umas_initialize_upload",
        SF_UPLOAD_BLOCK => "umas_upload_block",
        SF_END_UPLOAD => "umas_end_strategy_upload",
        SF_INIT_DOWNLOAD => "umas_initialize_download",
        SF_DOWNLOAD_BLOCK => "umas_download_block",
        SF_END_DOWNLOAD => "umas_end_strategy_download",
        SF_START_PLC => "umas_start_plc",
        SF_STOP_PLC => "umas_stop_plc",
        SF_MONITOR_PLC => "umas_monitor_plc",
        SF_CHECK_PLC => "umas_check_plc",
        SF_READ_IO => "umas_read_io_object",
        SF_WRITE_IO => "umas_write_io_object",
        SF_GET_STATUS => "umas_get_status_module",
        SF_AUTH_REQUEST => "umas_auth_request",
        SF_AUTH_REPLY => "umas_auth_reply",
        _ => return format!("umas_unknown_subfn_0x{sf:02x}"),
    }
    .to_string()
}

fn umas_attrs(sf: u8, pair_id: u8, txn: u16, unit: u8, req_len: u16, exc: bool)
    -> BTreeMap<String, String>
{
    BTreeMap::from([
        ("umas_subfunction".into(), format!("0x{sf:02x}")),
        ("pair_id".into(), pair_id.to_string()),
        ("transaction_id".into(), txn.to_string()),
        ("unit_id".into(), unit.to_string()),
        ("request_length".into(), req_len.to_string()),
        ("is_exception".into(), if exc { "true" } else { "false" }.into()),
    ])
}

fn build_env(chunk: &StreamChunk<'_>) -> EventEnvelope {
    build_envelope(
        &chunk.context,
        chunk.interface_id,
        chunk.frame_index,
        chunk.timestamp,
        chunk.segment_hash,
        TransportProtocol::Tcp,
        Some("umas"),
        chunk.captured_len,
        chunk.session_key.clone(),
    )
}

fn anomaly(chunk: &StreamChunk<'_>, severity: &str, reason: &str) -> BronzeEvent {
    parse_anomaly_event(
        chunk.capture_id.to_string(),
        build_env(chunk),
        "umas",
        severity,
        reason,
        chunk.payload,
    )
}

fn asset_obs(
    chunk: &StreamChunk<'_>,
    env: EventEnvelope,
    ip: String,
    role: &str,
    vendor: Option<&str>,
) -> BronzeEvent {
    new_event(
        chunk.capture_id.to_string(),
        env,
        BronzeEventFamily::AssetObservation(AssetObservation {
            asset_key: ip.clone(),
            role: Some(role.into()),
            vendor: vendor.map(Into::into),
            model: None,
            firmware: None,
            hostnames: vec![],
            protocols: vec!["umas".into(), "modbus".into()],
            identifiers: BTreeMap::from([("ip".into(), ip)]),
        }),
    )
}

fn emit_tx(
    capture_id: String,
    env: EventEnvelope,
    operation: String,
    status: String,
    sf: u8,
    pair_id: u8,
    txn: u16,
    unit: u8,
    req_len: u16,
    is_exc: bool,
) -> BronzeEvent {
    new_event(
        capture_id,
        env,
        BronzeEventFamily::ProtocolTransaction(ProtocolTransaction {
            operation,
            status,
            request_summary: None,
            response_summary: None,
            object_refs: vec![],
            values: vec![],
            attributes: umas_attrs(sf, pair_id, txn, unit, req_len, is_exc),
            modbus: None,
            protocol_fields: None,
        }),
    )
}

// ── State ─────────────────────────────────────────────────────────────────────

#[derive(Clone)]
struct PendingUmas {
    capture_id: String,
    envelope: EventEnvelope,
    transaction_id: u16,
    unit_id: u8,
    pair_id: u8,
    subfn: u8,
    operation: String,
    request_len: u16,
}

// ── Decoder ───────────────────────────────────────────────────────────────────

#[derive(Default)]
pub(crate) struct UmasDecoder {
    /// Key: `"{session_key}:{pair_id}"`.
    pending: HashMap<String, PendingUmas>,
}

impl SessionDecoder for UmasDecoder {
    fn name(&self) -> &'static str { "umas" }

    fn interest(&self) -> &'static [DecoderInterest] {
        &[DecoderInterest::TcpPort(502)]
    }

    fn on_stream_chunk(&mut self, chunk: &StreamChunk<'_>, out: &mut Vec<BronzeEvent>) {
        let p = chunk.payload;
        // Minimum: 7 B MBAP + FC + pair_id + subfn = 10 B
        if p.len() < 10 { return; }

        let txn_id = u16::from_be_bytes([p[0], p[1]]);
        if u16::from_be_bytes([p[2], p[3]]) != 0 { return; } // protocol_id must be 0
        let mbap_len = u16::from_be_bytes([p[4], p[5]]);
        let unit_id = p[6];
        let fc = p[7];

        if fc != FC_UMAS && fc != FC_UMAS_EXC { return; }

        let pair_id = p[8];
        let subfn   = p[9];
        let is_exc  = fc == FC_UMAS_EXC;
        let exc_code = if is_exc && p.len() > 10 { Some(p[10]) } else { None };

        let is_request = chunk.context.dst_port == 502 && chunk.context.src_port != 502;
        let key = format!("{}:{}", chunk.session_key, pair_id);
        let src_ip = chunk.context.src_ip.to_string();
        let dst_ip = chunk.context.dst_ip.to_string();

        if is_request && !is_exc {
            // Emit security anomalies before parking the request.
            match subfn {
                SF_STOP_PLC => out.push(anomaly(chunk, "high",
                    "UMAS STOP_PLC — control-disruption capable command observed")),
                SF_START_PLC => out.push(anomaly(chunk, "high",
                    "UMAS START_PLC — control-disruption capable command observed")),
                SF_DOWNLOAD_BLOCK => out.push(anomaly(chunk, "high",
                    "UMAS DOWNLOAD_BLOCK — program-modification capable command observed")),
                SF_INIT_DOWNLOAD => out.push(anomaly(chunk, "high",
                    "UMAS INITIALIZE_DOWNLOAD — program-modification capable command observed")),
                SF_END_DOWNLOAD => out.push(anomaly(chunk, "high",
                    "UMAS END_STRATEGY_DOWNLOAD — program-modification capable command observed")),
                SF_AUTH_REQUEST => out.push(anomaly(chunk, "medium",
                    "UMAS AUTH_REQUEST — authentication flow visible on wire")),
                sf if !is_known_subfn(sf) => out.push(anomaly(chunk, "low",
                    &format!("UMAS unknown sub-function 0x{sf:02x} observed"))),
                _ => {}
            }

            // Emit asset observations for TAKE_PLC_RESERVATION.
            if subfn == SF_TAKE_RESERVATION {
                let env = build_env(chunk);
                out.push(asset_obs(chunk, env.clone(), src_ip, "schneider_engineering_workstation", None));
                out.push(asset_obs(chunk, env, dst_ip, "schneider_modicon_plc", Some("Schneider Electric")));
            }

            self.pending.insert(key, PendingUmas {
                capture_id: chunk.capture_id.to_string(),
                envelope: build_env(chunk),
                transaction_id: txn_id,
                unit_id,
                pair_id,
                subfn,
                operation: umas_operation(subfn),
                request_len: mbap_len,
            });
        } else {
            // Response path — normal or exception.
            let status = if is_exc {
                format!("umas_exception_0x{:02x}", exc_code.unwrap_or(0))
            } else {
                "ok".into()
            };

            if let Some(req) = self.pending.remove(&key) {
                let mut env = req.envelope.clone();
                env.bytes_count += chunk.captured_len;
                env.packet_count += 1;
                out.push(emit_tx(req.capture_id, env, req.operation, status,
                    req.subfn, req.pair_id, req.transaction_id, req.unit_id, req.request_len, is_exc));
            } else {
                // Unpaired response.
                out.push(emit_tx(chunk.capture_id.to_string(), build_env(chunk),
                    umas_operation(subfn), status, subfn, pair_id, txn_id, unit_id, 0, is_exc));
            }
        }
    }

    fn on_idle_flush(&mut self, _ts: DateTime<Utc>, out: &mut Vec<BronzeEvent>) {
        for (_, req) in self.pending.drain() {
            out.push(emit_tx(req.capture_id, req.envelope, req.operation,
                "request_only".into(), req.subfn, req.pair_id,
                req.transaction_id, req.unit_id, req.request_len, false));
        }
    }
}

fn is_known_subfn(sf: u8) -> bool {
    matches!(sf,
        SF_INIT_COMM | SF_READ_ID | SF_READ_PROJECT_INFO | SF_READ_PLC_INFO |
        SF_READ_CARD_INFO | SF_REPEAT | SF_TAKE_RESERVATION | SF_RELEASE_RESERVATION |
        SF_KEEP_ALIVE | SF_READ_MEM | SF_WRITE_MEM | SF_READ_VARS | SF_WRITE_VARS |
        SF_READ_COILS | SF_WRITE_COILS | SF_INIT_UPLOAD | SF_UPLOAD_BLOCK | SF_END_UPLOAD |
        SF_INIT_DOWNLOAD | SF_DOWNLOAD_BLOCK | SF_END_DOWNLOAD | SF_START_PLC | SF_STOP_PLC |
        SF_MONITOR_PLC | SF_CHECK_PLC | SF_READ_IO | SF_WRITE_IO | SF_GET_STATUS |
        SF_AUTH_REQUEST | SF_AUTH_REPLY
    )
}

// ── Self-registration ─────────────────────────────────────────────────────────

inventory::submit!(crate::engine::decoders::DecoderRegistration {
    name: "umas",
    factory: || Box::new(UmasDecoder::default()),
});

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use std::net::IpAddr;

    use chrono::Utc;

    use crate::bronze::{BronzeEventFamily, TransportProtocol};
    use crate::engine::{DecoderInterest, SessionDecoder, StreamChunk};
    use crate::registry::PacketContext;

    use super::UmasDecoder;

    // ── Frame builders ────────────────────────────────────────────────────────

    /// MBAP (7 B) + FC=0x5A + pair_id + subfn + extra.
    fn req_frame(txn: u16, unit: u8, pair: u8, sf: u8, extra: &[u8]) -> Vec<u8> {
        let mbap_len = (2 + extra.len()) as u16 + 2; // unit + FC + pair + sf + extra
        let mut f = txn.to_be_bytes().to_vec();
        f.extend_from_slice(&0u16.to_be_bytes());
        f.extend_from_slice(&mbap_len.to_be_bytes());
        f.extend_from_slice(&[unit, 0x5A, pair, sf]);
        f.extend_from_slice(extra);
        f
    }

    fn resp_frame(txn: u16, unit: u8, pair: u8, sf: u8) -> Vec<u8> {
        req_frame(txn, unit, pair, sf, &[])
    }

    fn exc_frame(txn: u16, unit: u8, pair: u8, sf: u8, exc: u8) -> Vec<u8> {
        let mbap_len: u16 = 5;
        let mut f = txn.to_be_bytes().to_vec();
        f.extend_from_slice(&0u16.to_be_bytes());
        f.extend_from_slice(&mbap_len.to_be_bytes());
        f.extend_from_slice(&[unit, 0xDA, pair, sf, exc]);
        f
    }

    fn ctx_client(src: &str, dst: &str) -> PacketContext {
        PacketContext {
            src_mac: [0x00, 0x11, 0x22, 0x33, 0x44, 0x55],
            dst_mac: [0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb],
            src_ip: src.parse::<IpAddr>().unwrap(),
            dst_ip: dst.parse::<IpAddr>().unwrap(),
            src_port: 50000,
            dst_port: 502,
            vlan_id: None,
            timestamp: 0,
        }
    }

    fn ctx_server(src: &str, dst: &str) -> PacketContext {
        PacketContext {
            src_mac: [0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb],
            dst_mac: [0x00, 0x11, 0x22, 0x33, 0x44, 0x55],
            src_ip: src.parse::<IpAddr>().unwrap(),
            dst_ip: dst.parse::<IpAddr>().unwrap(),
            src_port: 502,
            dst_port: 50000,
            vlan_id: None,
            timestamp: 0,
        }
    }

    fn chunk<'a>(payload: &'a [u8], ctx: &'a PacketContext) -> StreamChunk<'a> {
        StreamChunk {
            capture_id: "test",
            segment_hash: "hash",
            interface_id: 0,
            frame_index: 1,
            timestamp: Utc::now(),
            context: ctx.clone(),
            ethertype: 0x0800,
            ip_proto: Some(6),
            llc: None,
            transport: TransportProtocol::Tcp,
            payload,
            session_key: "tcp:10.0.0.10:50000:10.0.0.20:502".into(),
            captured_len: payload.len() as u64,
        }
    }

    // ── Test 1: READ_ID request alone → no event ──────────────────────────────

    #[test]
    fn read_id_request_alone_emits_nothing() {
        let mut d = UmasDecoder::default();
        let p = req_frame(1, 1, 1, 0x02, &[]);
        let ctx = ctx_client("10.0.0.10", "10.0.0.20");
        let mut out = vec![];
        d.on_stream_chunk(&chunk(&p, &ctx), &mut out);
        assert!(out.is_empty(), "unpaired request must not emit; got {out:?}");
    }

    // ── Test 2: READ_ID request + response → paired transaction, status=ok ────

    #[test]
    fn read_id_paired_emits_ok_transaction() {
        let mut d = UmasDecoder::default();
        let req = req_frame(1, 1, 1, 0x02, &[]);
        let c_req = ctx_client("10.0.0.10", "10.0.0.20");
        let mut out = vec![];
        d.on_stream_chunk(&chunk(&req, &c_req), &mut out);

        let resp = resp_frame(1, 1, 1, 0x02);
        let c_resp = ctx_server("10.0.0.20", "10.0.0.10");
        d.on_stream_chunk(&chunk(&resp, &c_resp), &mut out);

        assert_eq!(out.len(), 1);
        match &out[0].family {
            BronzeEventFamily::ProtocolTransaction(tx) => {
                assert_eq!(tx.operation, "umas_read_id");
                assert_eq!(tx.status, "ok");
                assert_eq!(tx.attributes["pair_id"], "1");
                assert_eq!(tx.attributes["umas_subfunction"], "0x02");
                assert_eq!(tx.attributes["is_exception"], "false");
            }
            other => panic!("expected ProtocolTransaction, got {other:?}"),
        }
    }

    // ── Test 3: STOP_PLC → high ParseAnomaly; flush → request_only ───────────

    #[test]
    fn stop_plc_emits_high_anomaly_and_parks_request() {
        let mut d = UmasDecoder::default();
        let p = req_frame(2, 1, 2, 0x41, &[]);
        let ctx = ctx_client("10.0.0.10", "10.0.0.20");
        let mut out = vec![];
        d.on_stream_chunk(&chunk(&p, &ctx), &mut out);

        assert_eq!(out.len(), 1, "expect exactly one ParseAnomaly on request");
        match &out[0].family {
            BronzeEventFamily::ParseAnomaly(a) => {
                assert_eq!(a.severity, "high");
                assert!(a.reason.contains("STOP_PLC"), "bad reason: {}", a.reason);
            }
            other => panic!("expected ParseAnomaly, got {other:?}"),
        }

        let mut flush = vec![];
        d.on_idle_flush(Utc::now(), &mut flush);
        assert_eq!(flush.len(), 1);
        match &flush[0].family {
            BronzeEventFamily::ProtocolTransaction(tx) => {
                assert_eq!(tx.operation, "umas_stop_plc");
                assert_eq!(tx.status, "request_only");
            }
            other => panic!("expected ProtocolTransaction on flush, got {other:?}"),
        }
    }

    // ── Test 4: DOWNLOAD_BLOCK → high ParseAnomaly ────────────────────────────

    #[test]
    fn download_block_emits_high_anomaly() {
        let mut d = UmasDecoder::default();
        let p = req_frame(3, 1, 3, 0x2A, &[0x00, 0x01]);
        let ctx = ctx_client("10.0.0.10", "10.0.0.20");
        let mut out = vec![];
        d.on_stream_chunk(&chunk(&p, &ctx), &mut out);

        let a = out.iter().find_map(|e| {
            if let BronzeEventFamily::ParseAnomaly(a) = &e.family { Some(a) } else { None }
        }).expect("DOWNLOAD_BLOCK must emit a ParseAnomaly");
        assert_eq!(a.severity, "high");
        assert!(a.reason.contains("DOWNLOAD_BLOCK"), "bad reason: {}", a.reason);
    }

    // ── Test 5: Exception response (FC=0xDA, exc=0x83) → umas_exception_0x83 ──

    #[test]
    fn exception_response_correct_status() {
        let mut d = UmasDecoder::default();
        let req = req_frame(4, 1, 4, 0x02, &[]);
        let c_req = ctx_client("10.0.0.10", "10.0.0.20");
        let mut out = vec![];
        d.on_stream_chunk(&chunk(&req, &c_req), &mut out);

        let exc = exc_frame(4, 1, 4, 0x02, 0x83);
        let c_exc = ctx_server("10.0.0.20", "10.0.0.10");
        d.on_stream_chunk(&chunk(&exc, &c_exc), &mut out);

        assert_eq!(out.len(), 1);
        match &out[0].family {
            BronzeEventFamily::ProtocolTransaction(tx) => {
                assert_eq!(tx.status, "umas_exception_0x83");
                assert_eq!(tx.attributes["is_exception"], "true");
            }
            other => panic!("expected ProtocolTransaction, got {other:?}"),
        }
    }

    // ── Test 6: Unknown sub-function 0xAA → low anomaly + umas_unknown_subfn ──

    #[test]
    fn unknown_subfn_emits_low_anomaly_and_unknown_operation() {
        let mut d = UmasDecoder::default();
        let p = req_frame(5, 1, 5, 0xAA, &[]);
        let ctx = ctx_client("10.0.0.10", "10.0.0.20");
        let mut out = vec![];
        d.on_stream_chunk(&chunk(&p, &ctx), &mut out);

        let a = out.iter().find_map(|e| {
            if let BronzeEventFamily::ParseAnomaly(a) = &e.family { Some(a) } else { None }
        }).expect("unknown subfn must emit a ParseAnomaly");
        assert_eq!(a.severity, "low");

        let mut flush = vec![];
        d.on_idle_flush(Utc::now(), &mut flush);
        assert_eq!(flush.len(), 1);
        match &flush[0].family {
            BronzeEventFamily::ProtocolTransaction(tx) =>
                assert_eq!(tx.operation, "umas_unknown_subfn_0xaa"),
            other => panic!("expected ProtocolTransaction, got {other:?}"),
        }
    }

    // ── Test 7: TAKE_PLC_RESERVATION → two AssetObservations ─────────────────

    #[test]
    fn take_reservation_emits_asset_observations() {
        let mut d = UmasDecoder::default();
        let p = req_frame(6, 1, 6, 0x11, &[]);
        let ctx = ctx_client("10.0.0.10", "10.0.0.20");
        let mut out = vec![];
        d.on_stream_chunk(&chunk(&p, &ctx), &mut out);

        let assets: Vec<_> = out.iter().filter_map(|e| {
            if let BronzeEventFamily::AssetObservation(a) = &e.family { Some(a) } else { None }
        }).collect();
        assert_eq!(assets.len(), 2, "expect EWS + PLC asset observations");

        let ews = assets.iter().find(|a| a.asset_key == "10.0.0.10").unwrap();
        assert_eq!(ews.role.as_deref(), Some("schneider_engineering_workstation"));

        let plc = assets.iter().find(|a| a.asset_key == "10.0.0.20").unwrap();
        assert_eq!(plc.role.as_deref(), Some("schneider_modicon_plc"));
        assert_eq!(plc.vendor.as_deref(), Some("Schneider Electric"));
    }

    // ── Test 8: Decoder interest covers TCP/502 ───────────────────────────────

    #[test]
    fn decoder_interest_is_tcp_502() {
        let d = UmasDecoder::default();
        assert!(d.interest().contains(&DecoderInterest::TcpPort(502)));
    }
}
