//! Modbus-over-UDP decoder — sibling to the TCP variant in `modbus.rs`.
//!
//! Modbus/UDP carries one Modbus/TCP-style MBAP+PDU frame per datagram (no
//! stream reassembly). Found on legacy RTUs and resource-constrained embedded
//! controllers. Wire port is UDP/502.
//!
//! MBAP (7 B BE): [txn_id:u16][proto_id:u16=0][length:u16][unit_id:u8]
//! PDU:            [fc:u8][function-specific bytes…]
//!
//! FC 0x5A (UMAS) is intentionally skipped — handled by umas.rs on TCP.
//!
//! Pairing is keyed by (src_ip, dst_ip, transaction_id) with a 256-entry LRU
//! pending map; UDP loss is common so unpaired halves emit request_only /
//! response_only on flush.

use std::collections::{BTreeMap, VecDeque};
use std::net::IpAddr;

use chrono::{DateTime, Utc};

use crate::bronze::{
    BronzeEvent, BronzeEventFamily, EventEnvelope, ModbusBronzeFields, ModbusRegKind,
    PointIdentifier, PointValue, ProcessReading, ProtocolTransaction, RawQuality,
    TransportProtocol,
};
use crate::engine::{
    build_envelope, new_event, parse_anomaly_event, DecoderInterest, SessionDecoder, StreamChunk,
};

const FC_UMAS: u8 = 0x5A;
const MBAP_LEN: usize = 7;
const MAX_PENDING: usize = 256;

// ── Pending state ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct PKey {
    src_ip: IpAddr,
    dst_ip: IpAddr,
    txn_id: u16,
}

#[derive(Clone)]
struct PReq {
    key: PKey,
    capture_id: String,
    envelope: EventEnvelope,
    unit_id: u8,
    fc: u8,
    operation: String,
    start_addr: Option<u16>,
    qty: Option<u16>,
}

// ── Decoder ───────────────────────────────────────────────────────────────────

#[derive(Default)]
pub(crate) struct ModbusUdpDecoder {
    order: VecDeque<PKey>,
    pending: std::collections::HashMap<PKey, PReq>,
}

impl ModbusUdpDecoder {
    fn park(&mut self, req: PReq) {
        if self.pending.len() >= MAX_PENDING {
            if let Some(k) = self.order.pop_front() {
                self.pending.remove(&k);
            }
        }
        if self.pending.contains_key(&req.key) {
            self.order.retain(|k| k != &req.key);
        }
        self.order.push_back(req.key.clone());
        self.pending.insert(req.key.clone(), req);
    }

    fn pop(&mut self, key: &PKey) -> Option<PReq> {
        self.pending.remove(key).inspect(|_| {
            self.order.retain(|k| k != key);
        })
    }
}

impl SessionDecoder for ModbusUdpDecoder {
    fn name(&self) -> &'static str { "modbus_udp" }

    fn interest(&self) -> &'static [DecoderInterest] {
        &[DecoderInterest::UdpPort(502)]
    }

    fn on_datagram(&mut self, chunk: &StreamChunk<'_>, out: &mut Vec<BronzeEvent>) {
        let p = chunk.payload;
        if p.len() < MBAP_LEN + 1 {
            out.push(anomaly(chunk, "medium", "modbus/udp datagram shorter than minimum MBAP+FC"));
            return;
        }

        let txn_id   = u16::from_be_bytes([p[0], p[1]]);
        let proto_id = u16::from_be_bytes([p[2], p[3]]);
        let mbap_len = u16::from_be_bytes([p[4], p[5]]) as usize;
        let unit_id  = p[6];
        let fc       = p[7];
        let pdu      = &p[MBAP_LEN..]; // [fc, payload…]

        if proto_id != 0 {
            out.push(anomaly(chunk, "medium",
                &format!("modbus/udp non-zero protocol_id={proto_id:#06x}")));
            return;
        }
        // MBAP length = unit_id(1) + PDU bytes; total datagram = 6 + mbap_len.
        if 6 + mbap_len != p.len() {
            out.push(anomaly(chunk, "medium",
                &format!("modbus/udp MBAP length={mbap_len} disagrees with datagram length={}",
                    p.len() - 6)));
            // Continue — anomaly noted but data may still parse.
        }

        // Skip UMAS (and its exception variant 0xDA).
        if fc == FC_UMAS || fc == (FC_UMAS | 0x80) {
            return;
        }

        let is_exception = (fc & 0x80) != 0;
        let base_fc = fc & 0x7F;
        let is_request = chunk.context.dst_port == 502 && chunk.context.src_port != 502;
        let env = udp_env(chunk);

        if is_exception {
            let exc_code = pdu.get(1).copied().unwrap_or(0);
            let req_key = PKey {
                src_ip: chunk.context.dst_ip,
                dst_ip: chunk.context.src_ip,
                txn_id,
            };
            let (operation, start_addr, qty, direction) =
                if let Some(req) = self.pop(&req_key) {
                    let op = req.operation.clone();
                    let sa = req.start_addr;
                    let q  = req.qty;
                    let merged = merge(&req.envelope, &env);
                    out.push(tx_event(req.capture_id, merged, op.clone(),
                        format!("exception_0x{exc_code:02x}"),
                        unit_id, txn_id, base_fc, sa, q, vec![], Some(exc_code), "paired"));
                    return;
                } else {
                    (fc_name(base_fc), None, None, "response")
                };
            out.push(tx_event(chunk.capture_id.to_string(), env, operation,
                format!("exception_0x{exc_code:02x}"),
                unit_id, txn_id, base_fc, start_addr, qty, vec![], Some(exc_code), direction));
            return;
        }

        // Emit ParseAnomaly for unrecognised FCs (0x5A already skipped above).
        if !is_known_fc(fc) {
            out.push(anomaly(chunk, "low",
                &format!("modbus/udp unknown function code 0x{fc:02x}")));
        }

        let operation = fc_name(fc);

        if is_request {
            let (start_addr, qty) = req_addr_qty(fc, pdu);
            self.park(PReq {
                key: PKey { src_ip: chunk.context.src_ip, dst_ip: chunk.context.dst_ip, txn_id },
                capture_id: chunk.capture_id.to_string(),
                envelope: env,
                unit_id, fc, operation, start_addr, qty,
            });
        } else {
            let values = resp_values(fc, pdu);
            let obs_ts = chunk.timestamp.timestamp_micros() as u64;
            let req_key = PKey {
                src_ip: chunk.context.dst_ip,
                dst_ip: chunk.context.src_ip,
                txn_id,
            };
            if let Some(req) = self.pop(&req_key) {
                let merged = merge(&req.envelope, &env);
                emit_readings(fc, req.start_addr, req.unit_id, &values,
                    chunk.capture_id, merged.clone(), obs_ts, out);
                out.push(tx_event(req.capture_id, merged, req.operation, "ok".into(),
                    unit_id, txn_id, fc, req.start_addr, req.qty, values, None, "paired"));
            } else {
                emit_readings(fc, None, unit_id, &values,
                    chunk.capture_id, env.clone(), obs_ts, out);
                out.push(tx_event(chunk.capture_id.to_string(), env, operation, "response_only".into(),
                    unit_id, txn_id, fc, None, None, values, None, "response"));
            }
        }
    }

    fn on_idle_flush(&mut self, _ts: DateTime<Utc>, out: &mut Vec<BronzeEvent>) {
        let drained: Vec<PReq> = self.pending.drain().map(|(_, v)| v).collect();
        self.order.clear();
        for req in drained {
            out.push(tx_event(req.capture_id, req.envelope, req.operation,
                "request_only".into(), req.unit_id, req.key.txn_id,
                req.fc, req.start_addr, req.qty, vec![], None, "request"));
        }
    }
}

// ── Parse helpers ─────────────────────────────────────────────────────────────

fn req_addr_qty(fc: u8, pdu: &[u8]) -> (Option<u16>, Option<u16>) {
    match fc {
        0x01 | 0x02 | 0x03 | 0x04 if pdu.len() >= 5 => (
            Some(u16::from_be_bytes([pdu[1], pdu[2]])),
            Some(u16::from_be_bytes([pdu[3], pdu[4]])),
        ),
        0x05 | 0x06 if pdu.len() >= 5 => (
            Some(u16::from_be_bytes([pdu[1], pdu[2]])),
            None,
        ),
        0x0F | 0x10 if pdu.len() >= 5 => (
            Some(u16::from_be_bytes([pdu[1], pdu[2]])),
            Some(u16::from_be_bytes([pdu[3], pdu[4]])),
        ),
        0x16 if pdu.len() >= 3 => (Some(u16::from_be_bytes([pdu[1], pdu[2]])), None),
        0x17 if pdu.len() >= 5 => (
            Some(u16::from_be_bytes([pdu[1], pdu[2]])),
            Some(u16::from_be_bytes([pdu[3], pdu[4]])),
        ),
        _ => (None, None),
    }
}

fn resp_values(fc: u8, pdu: &[u8]) -> Vec<u16> {
    match fc {
        0x03 | 0x04 | 0x17 if pdu.len() >= 2 => {
            let byte_count = pdu[1] as usize;
            let data = &pdu[2..];
            if data.len() < byte_count || byte_count % 2 != 0 {
                return vec![];
            }
            data[..byte_count].chunks_exact(2)
                .map(|c| u16::from_be_bytes([c[0], c[1]]))
                .collect()
        }
        _ => vec![],
    }
}

// ── Emission helpers ──────────────────────────────────────────────────────────

#[allow(clippy::too_many_arguments)]
fn emit_readings(
    fc: u8, start_addr: Option<u16>, unit_id: u8, values: &[u16],
    capture_id: &str, envelope: EventEnvelope, observed_ts: u64,
    out: &mut Vec<BronzeEvent>,
) {
    let register_type = match fc {
        0x03 | 0x17 => ModbusRegKind::HoldingRegister,
        0x04 => ModbusRegKind::InputRegister,
        _ => return,
    };
    let base = start_addr.unwrap_or(0);
    for (i, &val) in values.iter().enumerate() {
        out.push(new_event(
            capture_id.to_string(),
            envelope.clone(),
            BronzeEventFamily::ProcessReading(ProcessReading {
                source_protocol: "modbus_udp".into(),
                point_id: PointIdentifier::ModbusRegister {
                    unit_id,
                    addr: base.saturating_add(i as u16),
                    register_type,
                },
                value: PointValue::UInt16(val),
                quality: RawQuality::None,
                source_ts: None,
                observed_ts,
            }),
        ));
    }
}

#[allow(clippy::too_many_arguments)]
fn tx_event(
    capture_id: String, envelope: EventEnvelope,
    operation: String, status: String,
    unit_id: u8, txn_id: u16, fc: u8,
    start_addr: Option<u16>, qty: Option<u16>,
    values: Vec<u16>, exception_code: Option<u8>,
    direction: &str,
) -> BronzeEvent {
    let mut attrs = BTreeMap::new();
    attrs.insert("unit_id".into(), unit_id.to_string());
    attrs.insert("transaction_id".into(), txn_id.to_string());
    attrs.insert("function_code".into(), format!("0x{fc:02x}"));
    attrs.insert("transport".into(), "udp".into());

    new_event(capture_id, envelope, BronzeEventFamily::ProtocolTransaction(ProtocolTransaction {
        operation, status,
        request_summary: None, response_summary: None,
        object_refs: vec![], values: vec![],
        attributes: attrs,
        modbus: Some(ModbusBronzeFields {
            fc: fc & 0x7F, start_addr, qty, values,
            exception_code, direction: direction.into(),
        }),
        protocol_fields: None,
    }))
}

fn udp_env(chunk: &StreamChunk<'_>) -> EventEnvelope {
    build_envelope(&chunk.context, chunk.interface_id, chunk.frame_index,
        chunk.timestamp, chunk.segment_hash, TransportProtocol::Udp,
        Some("modbus_udp"), chunk.captured_len, chunk.session_key.clone())
}

fn merge(req: &EventEnvelope, resp: &EventEnvelope) -> EventEnvelope {
    let mut m = req.clone();
    m.bytes_count += resp.bytes_count;
    m.packet_count += 1;
    m
}

fn anomaly(chunk: &StreamChunk<'_>, severity: &str, reason: &str) -> BronzeEvent {
    parse_anomaly_event(chunk.capture_id.to_string(), udp_env(chunk),
        "modbus_udp", severity, reason, chunk.payload)
}

fn fc_name(fc: u8) -> String {
    match fc {
        0x01 => "read_coils",
        0x02 => "read_discrete_inputs",
        0x03 => "read_holding_registers",
        0x04 => "read_input_registers",
        0x05 => "write_single_coil",
        0x06 => "write_single_register",
        0x0F => "write_multiple_coils",
        0x10 => "write_multiple_registers",
        0x16 => "mask_write_register",
        0x17 => "read_write_multiple_registers",
        0x2B => "encapsulated_interface_transport",
        n    => return format!("modbus_unknown_fc_{n}"),
    }.into()
}

fn is_known_fc(fc: u8) -> bool {
    matches!(fc, 0x01 | 0x02 | 0x03 | 0x04 | 0x05 | 0x06
               | 0x0F | 0x10 | 0x16 | 0x17 | 0x2B)
}

// ── Self-registration ─────────────────────────────────────────────────────────

inventory::submit!(crate::engine::decoders::DecoderRegistration {
    name: "modbus_udp",
    factory: || Box::new(ModbusUdpDecoder::default()),
});

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use std::net::IpAddr;
    use chrono::Utc;
    use crate::bronze::{BronzeEventFamily, ModbusRegKind, PointIdentifier, TransportProtocol};
    use crate::engine::{DecoderInterest, SessionDecoder, StreamChunk};
    use crate::registry::PacketContext;
    use super::ModbusUdpDecoder;

    // ── Frame / context builders ──────────────────────────────────────────────

    fn frame(txn: u16, unit: u8, pdu: &[u8]) -> Vec<u8> {
        let mbap_len = (1 + pdu.len()) as u16;
        let mut f = txn.to_be_bytes().to_vec();
        f.extend_from_slice(&0u16.to_be_bytes());
        f.extend_from_slice(&mbap_len.to_be_bytes());
        f.push(unit);
        f.extend_from_slice(pdu);
        f
    }

    fn pdu_rhr_req(addr: u16, qty: u16) -> Vec<u8> {
        let mut p = vec![0x03];
        p.extend_from_slice(&addr.to_be_bytes());
        p.extend_from_slice(&qty.to_be_bytes());
        p
    }

    fn pdu_rhr_resp(vals: &[u16]) -> Vec<u8> {
        let mut p = vec![0x03, (vals.len() * 2) as u8];
        for &v in vals { p.extend_from_slice(&v.to_be_bytes()); }
        p
    }

    fn ctx_c(src: &str, dst: &str) -> PacketContext {
        PacketContext {
            src_mac: [0x00, 0x11, 0x22, 0x33, 0x44, 0x55],
            dst_mac: [0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb],
            src_ip: src.parse::<IpAddr>().unwrap(),
            dst_ip: dst.parse::<IpAddr>().unwrap(),
            src_port: 49152, dst_port: 502,
            vlan_id: None, timestamp: 0,
        }
    }

    fn ctx_s(src: &str, dst: &str) -> PacketContext {
        PacketContext {
            src_mac: [0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb],
            dst_mac: [0x00, 0x11, 0x22, 0x33, 0x44, 0x55],
            src_ip: src.parse::<IpAddr>().unwrap(),
            dst_ip: dst.parse::<IpAddr>().unwrap(),
            src_port: 502, dst_port: 49152,
            vlan_id: None, timestamp: 0,
        }
    }

    fn dgram<'a>(payload: &'a [u8], ctx: &'a PacketContext) -> StreamChunk<'a> {
        StreamChunk {
            capture_id: "test", segment_hash: "hash",
            interface_id: 0, frame_index: 1,
            timestamp: Utc::now(),
            context: ctx.clone(),
            ethertype: 0x0800, ip_proto: Some(17), llc: None,
            transport: TransportProtocol::Udp,
            payload,
            session_key: "udp:10.0.0.10:49152:10.0.0.20:502".into(),
            captured_len: payload.len() as u64,
        }
    }

    // ── Test 1: FC=03 request → parks; + response → paired ProtocolTransaction

    #[test]
    fn read_holding_registers_paired() {
        let mut d = ModbusUdpDecoder::default();
        let req_f = frame(1, 1, &pdu_rhr_req(100, 10));
        let mut out = vec![];
        d.on_datagram(&dgram(&req_f, &ctx_c("10.0.0.10", "10.0.0.20")), &mut out);
        assert!(out.is_empty(), "lone request must not emit");

        let resp_f = frame(1, 1, &pdu_rhr_resp(&[1,2,3,4,5,6,7,8,9,10]));
        d.on_datagram(&dgram(&resp_f, &ctx_s("10.0.0.20", "10.0.0.10")), &mut out);

        let tx = out.iter().find_map(|e| {
            if let BronzeEventFamily::ProtocolTransaction(t) = &e.family { Some(t) } else { None }
        }).expect("ProtocolTransaction required");

        assert_eq!(tx.operation, "read_holding_registers");
        assert_eq!(tx.status, "ok");
        assert_eq!(tx.attributes["transport"], "udp");
        assert_eq!(tx.attributes["transaction_id"], "1");
        assert_eq!(tx.attributes["function_code"], "0x03");
    }

    // ── Test 2: FC=03 response with 5 values → 5 ProcessReadings ─────────────

    #[test]
    fn read_holding_registers_process_readings() {
        let mut d = ModbusUdpDecoder::default();
        let req_f  = frame(2, 1, &pdu_rhr_req(40, 5));
        let mut out = vec![];
        d.on_datagram(&dgram(&req_f, &ctx_c("10.0.0.10", "10.0.0.20")), &mut out);

        let resp_f = frame(2, 1, &pdu_rhr_resp(&[100, 200, 300, 400, 500]));
        d.on_datagram(&dgram(&resp_f, &ctx_s("10.0.0.20", "10.0.0.10")), &mut out);

        let readings: Vec<_> = out.iter().filter_map(|e| {
            if let BronzeEventFamily::ProcessReading(r) = &e.family { Some(r) } else { None }
        }).collect();
        assert_eq!(readings.len(), 5);

        for (i, r) in readings.iter().enumerate() {
            assert_eq!(r.source_protocol, "modbus_udp");
            match &r.point_id {
                PointIdentifier::ModbusRegister { unit_id, addr, register_type } => {
                    assert_eq!(*unit_id, 1);
                    assert_eq!(*addr, 40 + i as u16);
                    assert_eq!(*register_type, ModbusRegKind::HoldingRegister);
                }
                other => panic!("expected ModbusRegister, got {other:?}"),
            }
        }
    }

    // ── Test 3: FC=06 Write Single Register → write_single_register ──────────

    #[test]
    fn write_single_register_operation() {
        let mut d = ModbusUdpDecoder::default();
        let mut pdu = vec![0x06];
        pdu.extend_from_slice(&200u16.to_be_bytes());
        pdu.extend_from_slice(&0xBEEFu16.to_be_bytes());
        let req_f = frame(3, 1, &pdu);
        let mut out = vec![];
        d.on_datagram(&dgram(&req_f, &ctx_c("10.0.0.10", "10.0.0.20")), &mut out);
        // Modbus FC06 response echoes the request.
        d.on_datagram(&dgram(&req_f, &ctx_s("10.0.0.20", "10.0.0.10")), &mut out);

        let tx = out.iter().find_map(|e| {
            if let BronzeEventFamily::ProtocolTransaction(t) = &e.family { Some(t) } else { None }
        }).expect("ProtocolTransaction required");
        assert_eq!(tx.operation, "write_single_register");
        assert_eq!(tx.status, "ok");
    }

    // ── Test 4: Exception FC=0x83, exc=0x02 → status=exception_0x02 ──────────

    #[test]
    fn exception_response_status() {
        let mut d = ModbusUdpDecoder::default();
        let req_f = frame(4, 1, &pdu_rhr_req(0, 1));
        let mut out = vec![];
        d.on_datagram(&dgram(&req_f, &ctx_c("10.0.0.10", "10.0.0.20")), &mut out);

        let exc_f = frame(4, 1, &[0x83, 0x02]);
        d.on_datagram(&dgram(&exc_f, &ctx_s("10.0.0.20", "10.0.0.10")), &mut out);

        let tx = out.iter().find_map(|e| {
            if let BronzeEventFamily::ProtocolTransaction(t) = &e.family { Some(t) } else { None }
        }).expect("ProtocolTransaction required");
        assert_eq!(tx.status, "exception_0x02");
        assert_eq!(tx.operation, "read_holding_registers");
        let mb = tx.modbus.as_ref().unwrap();
        assert_eq!(mb.exception_code, Some(0x02));
    }

    // ── Test 5: FC=0x5A (UMAS) → no event ────────────────────────────────────

    #[test]
    fn umas_fc_skipped() {
        let mut d = ModbusUdpDecoder::default();
        let f = frame(5, 1, &[0x5A, 0x01, 0x02]);
        let mut out = vec![];
        d.on_datagram(&dgram(&f, &ctx_c("10.0.0.10", "10.0.0.20")), &mut out);
        assert!(out.is_empty(), "UMAS FC must be silently skipped; got {out:?}");
    }

    // ── Test 6: Unknown FC=0x42 → ParseAnomaly low + modbus_unknown_fc_66 ─────

    #[test]
    fn unknown_fc_anomaly_and_operation() {
        let mut d = ModbusUdpDecoder::default();
        let f = frame(6, 1, &[0x42, 0xDE, 0xAD]);
        let mut out = vec![];
        d.on_datagram(&dgram(&f, &ctx_c("10.0.0.10", "10.0.0.20")), &mut out);

        let a = out.iter().find_map(|e| {
            if let BronzeEventFamily::ParseAnomaly(a) = &e.family { Some(a) } else { None }
        }).expect("ParseAnomaly required");
        assert_eq!(a.severity, "low");
        assert!(a.reason.contains("0x42"), "reason: {}", a.reason);

        let mut flush = vec![];
        d.on_idle_flush(Utc::now(), &mut flush);
        let tx = flush.iter().find_map(|e| {
            if let BronzeEventFamily::ProtocolTransaction(t) = &e.family { Some(t) } else { None }
        }).expect("ProtocolTransaction on flush");
        assert_eq!(tx.operation, "modbus_unknown_fc_66");
        assert_eq!(tx.status, "request_only");
    }

    // ── Test 7: Decoder declares UdpPort(502) interest ───────────────────────

    #[test]
    fn interest_is_udp_502() {
        assert!(ModbusUdpDecoder::default().interest()
            .contains(&DecoderInterest::UdpPort(502)));
    }

    // ── Test 8: MBAP length mismatch → medium ParseAnomaly ───────────────────

    #[test]
    fn mbap_length_mismatch_medium_anomaly() {
        let mut d = ModbusUdpDecoder::default();
        let mut f = frame(7, 1, &pdu_rhr_req(0, 1));
        // Inflate the claimed MBAP length (bytes 4..6).
        f[4] = 0x00;
        f[5] = 0xFF;
        let mut out = vec![];
        d.on_datagram(&dgram(&f, &ctx_c("10.0.0.10", "10.0.0.20")), &mut out);

        let a = out.iter().find_map(|e| {
            if let BronzeEventFamily::ParseAnomaly(a) = &e.family { Some(a) } else { None }
        }).expect("ParseAnomaly required for MBAP length mismatch");
        assert_eq!(a.severity, "medium");
    }
}
