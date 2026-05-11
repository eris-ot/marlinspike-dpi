//! PTPv2 / gPTP (IEEE 1588-2008 / IEEE 802.1AS) session decoder.
//!
//! # Wire format — PTP common header (34 bytes, big-endian)
//! ```text
//! Byte 0 : [7:4] transportSpecific | [3:0] messageType
//!            transportSpecific 0 = standard PTP ("ptp")
//!            transportSpecific 1 = IEEE 802.1AS gPTP ("gptp")
//!            messageType: 0=Sync 1=Delay_Req 2=Pdelay_Req 3=Pdelay_Resp
//!                         8=Follow_Up 9=Delay_Resp A=Pdelay_Resp_Follow_Up
//!                         B=Announce C=Signaling D=Management
//! Byte 1 : [3:0] versionPTP (must be 2)
//! Bytes 2-3 : messageLength u16 BE
//! Byte 4    : domainNumber
//! Bytes 20-27: sourcePortIdentity.clockIdentity (EUI-64)
//! Bytes 28-29: sourcePortIdentity.portNumber u16 BE
//! Bytes 30-31: sequenceId u16 BE
//! ```
//! Announce body at byte 34 (total ≥ 64):
//!   [13]=grandmasterPriority1 [14]=clockClass [15]=clockAccuracy
//!   [16-17]=offsetScaledLogVariance [18]=grandmasterPriority2
//!   [19-26]=grandmasterIdentity [27-28]=stepsRemoved [29]=timeSource

use std::collections::{BTreeMap, HashMap, HashSet};

use crate::bronze::{
    AssetObservation, BronzeEvent, BronzeEventFamily, ProtocolTransaction, TransportProtocol,
};
use crate::engine::{
    build_envelope, new_event, parse_anomaly_event, DecoderInterest, SessionDecoder, StreamChunk,
};

const MSG_SYNC: u8 = 0x0;
const MSG_DELAY_REQ: u8 = 0x1;
const MSG_PDELAY_REQ: u8 = 0x2;
const MSG_PDELAY_RESP: u8 = 0x3;
const MSG_FOLLOW_UP: u8 = 0x8;
const MSG_DELAY_RESP: u8 = 0x9;
const MSG_PDELAY_RESP_FOLLOW_UP: u8 = 0xA;
const MSG_ANNOUNCE: u8 = 0xB;
const MSG_SIGNALING: u8 = 0xC;
const MSG_MANAGEMENT: u8 = 0xD;

fn msg_type_operation(t: u8) -> String {
    match t {
        MSG_SYNC => "ptp_sync_first",
        MSG_DELAY_REQ => "ptp_delay_req_first",
        MSG_PDELAY_REQ => "ptp_pdelay_req_first",
        MSG_PDELAY_RESP => "ptp_pdelay_resp_first",
        MSG_FOLLOW_UP => "ptp_follow_up_first",
        MSG_DELAY_RESP => "ptp_delay_resp_first",
        MSG_PDELAY_RESP_FOLLOW_UP => "ptp_pdelay_resp_follow_up_first",
        MSG_ANNOUNCE => "ptp_announce",
        MSG_SIGNALING => "ptp_signaling_first",
        MSG_MANAGEMENT => "ptp_management_first",
        other => return format!("ptp_unknown_type_{other:#x}_first"),
    }
    .to_string()
}

fn is_known_type(t: u8) -> bool {
    matches!(
        t,
        MSG_SYNC | MSG_DELAY_REQ | MSG_PDELAY_REQ | MSG_PDELAY_RESP | MSG_FOLLOW_UP
            | MSG_DELAY_RESP | MSG_PDELAY_RESP_FOLLOW_UP | MSG_SIGNALING | MSG_MANAGEMENT
    )
}

struct PtpHdr {
    transport_specific: u8,
    msg_type: u8,
    version: u8,
    message_length: u16,
    domain_number: u8,
    clock_id: [u8; 8],
    port_number: u16,
    sequence_id: u16,
}

fn parse_hdr(buf: &[u8]) -> Option<PtpHdr> {
    if buf.len() < 34 { return None; }
    let mut clock_id = [0u8; 8];
    clock_id.copy_from_slice(&buf[20..28]);
    Some(PtpHdr {
        transport_specific: (buf[0] >> 4) & 0x0F,
        msg_type: buf[0] & 0x0F,
        version: buf[1] & 0x0F,
        message_length: u16::from_be_bytes([buf[2], buf[3]]),
        domain_number: buf[4],
        clock_id,
        port_number: u16::from_be_bytes([buf[28], buf[29]]),
        sequence_id: u16::from_be_bytes([buf[30], buf[31]]),
    })
}

struct AnnounceBody {
    gm_priority1: u8,
    gm_priority2: u8,
    clock_class: u8,
    clock_accuracy: u8,
    gm_identity: [u8; 8],
    steps_removed: u16,
    time_source: u8,
}

fn parse_announce(buf: &[u8]) -> Option<AnnounceBody> {
    if buf.len() < 64 { return None; }
    let b = &buf[34..]; // body slice; b[0] = originTimestamp[0]
    let mut gm_identity = [0u8; 8];
    gm_identity.copy_from_slice(&b[19..27]);
    Some(AnnounceBody {
        gm_priority1: b[13],
        clock_class: b[14],
        clock_accuracy: b[15],
        gm_priority2: b[18],
        gm_identity,
        steps_removed: u16::from_be_bytes([b[27], b[28]]),
        time_source: b[29],
    })
}

/// Per-session PTP decoder state.
#[derive(Default)]
pub(crate) struct PtpDecoder {
    /// clockIdentities for which we have emitted `ptp_clock_observed`.
    seen_clocks: HashSet<[u8; 8]>,
    /// (clockId, msgType) → total seen count, for 1000th-packet sampling.
    msg_counts: HashMap<([u8; 8], u8), u64>,
    /// (clockId, msgType) pairs for which the *_first event has been emitted.
    first_seen: HashSet<([u8; 8], u8)>,
    /// (domain, clockId) → last seen grandmaster identity; detects GM changes.
    domain_gm: HashMap<(u8, [u8; 8]), [u8; 8]>,
}

impl SessionDecoder for PtpDecoder {
    fn name(&self) -> &'static str { "ptp" }

    fn interest(&self) -> &'static [DecoderInterest] {
        &[
            DecoderInterest::EtherType(0x88F7),
            DecoderInterest::UdpPort(319),
            DecoderInterest::UdpPort(320),
        ]
    }

    fn on_datagram(&mut self, chunk: &StreamChunk<'_>, out: &mut Vec<BronzeEvent>) {
        let transport = if chunk.ethertype == 0x88F7 {
            TransportProtocol::Ethernet
        } else {
            TransportProtocol::Udp
        };

        let envelope = || build_envelope(
            &chunk.context,
            chunk.interface_id,
            chunk.frame_index,
            chunk.timestamp,
            chunk.segment_hash,
            transport,
            Some("ptp"),
            chunk.captured_len,
            chunk.session_key.clone(),
        );

        let hdr = match parse_hdr(chunk.payload) {
            Some(h) => h,
            None => {
                out.push(parse_anomaly_event(
                    chunk.capture_id.to_string(), envelope(), self.name(), "medium",
                    "PTP packet too short for 34-byte common header", chunk.payload,
                ));
                return;
            }
        };

        if hdr.version != 2 {
            out.push(parse_anomaly_event(
                chunk.capture_id.to_string(), envelope(), self.name(), "low",
                &format!("PTP versionPTP={} expected 2", hdr.version), chunk.payload,
            ));
        }

        if hdr.message_length != chunk.payload.len() as u16 {
            out.push(parse_anomaly_event(
                chunk.capture_id.to_string(), envelope(), self.name(), "medium",
                &format!(
                    "PTP messageLength={} disagrees with packet length={}",
                    hdr.message_length, chunk.payload.len()
                ),
                chunk.payload,
            ));
        }

        let clock_hex = hex::encode(hdr.clock_id);
        let ts_name = if hdr.transport_specific == 1 { "gptp" } else { "ptp" };

        // Emit ptp_clock_observed on first sight of each clockIdentity.
        if self.seen_clocks.insert(hdr.clock_id) {
            let mut attrs = BTreeMap::new();
            attrs.insert("clock_identity_hex".to_string(), clock_hex.clone());
            attrs.insert("port_number".to_string(), hdr.port_number.to_string());
            attrs.insert("domain_number".to_string(), hdr.domain_number.to_string());
            attrs.insert("transport_specific".to_string(), ts_name.to_string());
            attrs.insert("version".to_string(), hdr.version.to_string());
            out.push(new_event(
                chunk.capture_id.to_string(), envelope(),
                BronzeEventFamily::ProtocolTransaction(ProtocolTransaction {
                    operation: "ptp_clock_observed".to_string(),
                    status: "observed".to_string(),
                    request_summary: Some(format!(
                        "PTP clock {clock_hex} domain={} port={}",
                        hdr.domain_number, hdr.port_number
                    )),
                    response_summary: None, object_refs: vec![], values: vec![],
                    attributes: attrs, modbus: None, protocol_fields: None,
                }),
            ));
        }

        if hdr.msg_type == MSG_ANNOUNCE {
            self.handle_announce(chunk, &hdr, ts_name, &clock_hex, envelope, out);
        } else {
            self.handle_sampled(chunk, &hdr, ts_name, &clock_hex, envelope, out);
        }
    }
}

impl PtpDecoder {
    fn handle_announce<F>(
        &mut self,
        chunk: &StreamChunk<'_>,
        hdr: &PtpHdr,
        ts_name: &str,
        clock_hex: &str,
        envelope: F,
        out: &mut Vec<BronzeEvent>,
    ) where F: Fn() -> crate::bronze::EventEnvelope {
        let ann = match parse_announce(chunk.payload) {
            Some(a) => a,
            None => {
                out.push(parse_anomaly_event(
                    chunk.capture_id.to_string(), envelope(), "ptp", "medium",
                    "PTP Announce body too short (need 64 bytes total)", chunk.payload,
                ));
                return;
            }
        };

        let gm_hex = hex::encode(ann.gm_identity);
        let dk = (hdr.domain_number, hdr.clock_id);

        // Grandmaster change detection per (domain, sourceClockIdentity).
        if let Some(prev) = self.domain_gm.get(&dk) {
            if *prev != ann.gm_identity {
                out.push(parse_anomaly_event(
                    chunk.capture_id.to_string(), envelope(), "ptp", "medium",
                    &format!(
                        "PTP grandmaster changed in domain {} — verify legitimate failover",
                        hdr.domain_number
                    ),
                    chunk.payload,
                ));
            }
        }
        self.domain_gm.insert(dk, ann.gm_identity);

        let mut attrs = BTreeMap::new();
        attrs.insert("clock_identity_hex".to_string(), clock_hex.to_string());
        attrs.insert("port_number".to_string(), hdr.port_number.to_string());
        attrs.insert("domain_number".to_string(), hdr.domain_number.to_string());
        attrs.insert("transport_specific".to_string(), ts_name.to_string());
        attrs.insert("version".to_string(), hdr.version.to_string());
        attrs.insert("grandmaster_identity_hex".to_string(), gm_hex.clone());
        attrs.insert("grandmaster_priority1".to_string(), ann.gm_priority1.to_string());
        attrs.insert("grandmaster_priority2".to_string(), ann.gm_priority2.to_string());
        attrs.insert("clock_class".to_string(), ann.clock_class.to_string());
        attrs.insert("clock_accuracy".to_string(), ann.clock_accuracy.to_string());
        attrs.insert("steps_removed".to_string(), ann.steps_removed.to_string());
        attrs.insert("time_source".to_string(), ann.time_source.to_string());

        out.push(new_event(
            chunk.capture_id.to_string(), envelope(),
            BronzeEventFamily::ProtocolTransaction(ProtocolTransaction {
                operation: "ptp_announce".to_string(),
                status: "observed".to_string(),
                request_summary: Some(format!(
                    "Announce gm={gm_hex} priority1={} class={}",
                    ann.gm_priority1, ann.clock_class
                )),
                response_summary: None, object_refs: vec![], values: vec![],
                attributes: attrs, modbus: None, protocol_fields: None,
            }),
        ));

        // AssetObservation — once per (clockId, Announce).
        if self.first_seen.insert((hdr.clock_id, MSG_ANNOUNCE)) {
            let is_gm = hdr.clock_id == ann.gm_identity;
            let mut ids = BTreeMap::new();
            ids.insert("ptp_clock_identity".to_string(), clock_hex.to_string());
            ids.insert("ptp_domain".to_string(), hdr.domain_number.to_string());
            ids.insert("ptp_grandmaster_identity".to_string(), gm_hex);
            out.push(new_event(
                chunk.capture_id.to_string(), envelope(),
                BronzeEventFamily::AssetObservation(AssetObservation {
                    asset_key: clock_hex.to_string(),
                    role: Some(if is_gm { "ptp_grandmaster" } else { "ptp_clock" }.to_string()),
                    vendor: None, model: None, firmware: None, hostnames: vec![],
                    protocols: vec!["ptp".to_string()],
                    identifiers: ids,
                }),
            ));
        }
    }

    fn handle_sampled<F>(
        &mut self,
        chunk: &StreamChunk<'_>,
        hdr: &PtpHdr,
        ts_name: &str,
        clock_hex: &str,
        envelope: F,
        out: &mut Vec<BronzeEvent>,
    ) where F: Fn() -> crate::bronze::EventEnvelope {
        let key = (hdr.clock_id, hdr.msg_type);
        let count = self.msg_counts.entry(key).or_insert(0);
        *count += 1;

        let is_first = !self.first_seen.contains(&key);
        if !is_first && *count % 1000 != 0 {
            return;
        }
        if is_first {
            self.first_seen.insert(key);
        }

        if !is_known_type(hdr.msg_type) {
            out.push(parse_anomaly_event(
                chunk.capture_id.to_string(), envelope(), "ptp", "low",
                &format!("PTP unknown messageType {:#x}", hdr.msg_type),
                chunk.payload,
            ));
        }

        let mut attrs = BTreeMap::new();
        attrs.insert("clock_identity_hex".to_string(), clock_hex.to_string());
        attrs.insert("port_number".to_string(), hdr.port_number.to_string());
        attrs.insert("domain_number".to_string(), hdr.domain_number.to_string());
        attrs.insert("transport_specific".to_string(), ts_name.to_string());
        attrs.insert("version".to_string(), hdr.version.to_string());
        attrs.insert("sequence_id".to_string(), hdr.sequence_id.to_string());

        out.push(new_event(
            chunk.capture_id.to_string(), envelope(),
            BronzeEventFamily::ProtocolTransaction(ProtocolTransaction {
                operation: msg_type_operation(hdr.msg_type),
                status: "observed".to_string(),
                request_summary: Some(format!(
                    "PTP msg={:#x} clock={clock_hex} seq={}", hdr.msg_type, hdr.sequence_id
                )),
                response_summary: None, object_refs: vec![], values: vec![],
                attributes: attrs, modbus: None, protocol_fields: None,
            }),
        ));
    }
}

inventory::submit!(crate::engine::decoders::DecoderRegistration {
    name: "ptp",
    factory: || Box::new(PtpDecoder::default()),
});

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};
    use chrono::Utc;
    use super::*;
    use crate::bronze::BronzeEventFamily;
    use crate::engine::StreamChunk;
    use crate::registry::PacketContext;

    // ── Frame builders ────────────────────────────────────────────────────────

    /// Build a minimal PTP packet of `total_len` bytes with a complete header.
    fn ptp_pkt(ts: u8, msg: u8, version: u8, domain: u8, clock: [u8; 8], port: u16, total_len: usize) -> Vec<u8> {
        let mut b = vec![0u8; total_len];
        b[0] = ((ts & 0xF) << 4) | (msg & 0xF);
        b[1] = version & 0xF;
        let len = (total_len as u16).to_be_bytes();
        b[2] = len[0]; b[3] = len[1];
        b[4] = domain;
        b[20..28].copy_from_slice(&clock);
        let pn = port.to_be_bytes();
        b[28] = pn[0]; b[29] = pn[1];
        b
    }

    /// Build a 64-byte Announce packet.
    fn announce_pkt(
        ts: u8, domain: u8, clock: [u8; 8], port: u16,
        pri1: u8, pri2: u8, cls: u8, acc: u8,
        gm: [u8; 8], steps: u16, time_src: u8,
    ) -> Vec<u8> {
        let mut b = ptp_pkt(ts, MSG_ANNOUNCE, 2, domain, clock, port, 64);
        b[34 + 13] = pri1;
        b[34 + 14] = cls;
        b[34 + 15] = acc;
        b[34 + 18] = pri2;
        b[34 + 19..34 + 27].copy_from_slice(&gm);
        let s = steps.to_be_bytes();
        b[34 + 27] = s[0]; b[34 + 28] = s[1];
        b[34 + 29] = time_src;
        b
    }

    // ── Chunk helpers ─────────────────────────────────────────────────────────

    fn ctx_l2() -> PacketContext {
        PacketContext {
            src_ip: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            dst_ip: IpAddr::V4(Ipv4Addr::new(1, 0, 94, 0)),
            src_port: 0, dst_port: 0,
            src_mac: [0x00, 0x1B, 0x21, 0xAA, 0xBB, 0xCC],
            dst_mac: [0x01, 0x1B, 0x19, 0x00, 0x00, 0x00],
            vlan_id: None, timestamp: 0,
        }
    }

    fn ctx_udp(src: u16, dst: u16) -> PacketContext {
        PacketContext {
            src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            dst_ip: IpAddr::V4(Ipv4Addr::new(224, 0, 1, 129)),
            src_port: src, dst_port: dst,
            src_mac: [0x00, 0x1B, 0x21, 0x11, 0x22, 0x33],
            dst_mac: [0x01, 0x00, 0x5E, 0x00, 0x01, 0x81],
            vlan_id: None, timestamp: 0,
        }
    }

    fn feed_l2(dec: &mut PtpDecoder, payload: &[u8], out: &mut Vec<BronzeEvent>) {
        dec.on_datagram(&StreamChunk {
            capture_id: "cap", segment_hash: "seg", interface_id: 0, frame_index: 1,
            timestamp: Utc::now(), context: ctx_l2(), ethertype: 0x88F7,
            ip_proto: None, llc: None, transport: TransportProtocol::Ethernet,
            payload, session_key: "l2".to_string(), captured_len: payload.len() as u64,
        }, out);
    }

    fn feed_udp(dec: &mut PtpDecoder, payload: &[u8], dst_port: u16, out: &mut Vec<BronzeEvent>) {
        dec.on_datagram(&StreamChunk {
            capture_id: "cap", segment_hash: "seg", interface_id: 0, frame_index: 1,
            timestamp: Utc::now(), context: ctx_udp(12345, dst_port), ethertype: 0x0800,
            ip_proto: Some(17), llc: None, transport: TransportProtocol::Udp,
            payload, session_key: "udp".to_string(), captured_len: payload.len() as u64,
        }, out);
    }

    fn find_txn<'a>(out: &'a [BronzeEvent], op: &str) -> Option<&'a crate::bronze::ProtocolTransaction> {
        out.iter().find_map(|e| match &e.family {
            BronzeEventFamily::ProtocolTransaction(t) if t.operation == op => Some(t),
            _ => None,
        })
    }

    fn find_anomaly<'a>(out: &'a [BronzeEvent], sev: &str, substr: &str) -> Option<&'a crate::bronze::ParseAnomaly> {
        out.iter().find_map(|e| match &e.family {
            BronzeEventFamily::ParseAnomaly(a) if a.severity == sev && a.reason.contains(substr) => Some(a),
            _ => None,
        })
    }

    // ── Test 1: Sync gPTP over EtherType 0x88F7 ──────────────────────────────

    #[test]
    fn test_sync_gptp_ethertype() {
        let clock = [0x00, 0x1B, 0x21, 0xFF, 0xFE, 0xAA, 0xBB, 0xCC];
        let pkt = ptp_pkt(1 /* gPTP */, MSG_SYNC, 2, 0, clock, 1, 34);
        let mut dec = PtpDecoder::default();
        let mut out = Vec::new();
        feed_l2(&mut dec, &pkt, &mut out);

        let txn = find_txn(&out, "ptp_sync_first").expect("missing ptp_sync_first");
        assert_eq!(txn.attributes["transport_specific"], "gptp");
        assert_eq!(txn.attributes["domain_number"], "0");
    }

    // ── Test 2: Announce self-as-grandmaster → ptp_grandmaster role ───────────

    #[test]
    fn test_announce_grandmaster_self() {
        let clock = [0x00, 0x1B, 0x21, 0xFF, 0xFE, 0x01, 0x02, 0x03];
        let pkt = announce_pkt(1, 0, clock, 1, 128, 128, 6, 0x20, clock /* gm = self */, 0, 0x20);
        let mut dec = PtpDecoder::default();
        let mut out = Vec::new();
        feed_l2(&mut dec, &pkt, &mut out);

        let txn = find_txn(&out, "ptp_announce").expect("missing ptp_announce");
        assert_eq!(txn.attributes["grandmaster_priority1"], "128");
        assert_eq!(txn.attributes["clock_class"], "6");

        let asset = out.iter().find_map(|e| match &e.family {
            BronzeEventFamily::AssetObservation(a) if a.role.as_deref() == Some("ptp_grandmaster") => Some(a),
            _ => None,
        });
        assert!(asset.is_some(), "missing ptp_grandmaster AssetObservation");
    }

    // ── Test 3: Sync over UDP 319, transportSpecific=0 → transport_specific="ptp" ──

    #[test]
    fn test_sync_ptp_udp319() {
        let clock = [0x00, 0xAA, 0xBB, 0xFF, 0xFE, 0x11, 0x22, 0x33];
        let pkt = ptp_pkt(0 /* PTP */, MSG_SYNC, 2, 5, clock, 2, 34);
        let mut dec = PtpDecoder::default();
        let mut out = Vec::new();
        feed_udp(&mut dec, &pkt, 319, &mut out);

        let txn = find_txn(&out, "ptp_sync_first").expect("missing ptp_sync_first over UDP");
        assert_eq!(txn.attributes["transport_specific"], "ptp");
    }

    // ── Test 4: Delay_Req → ptp_delay_req_first ──────────────────────────────

    #[test]
    fn test_delay_req() {
        let clock = [0x00, 0xCC, 0xDD, 0xFF, 0xFE, 0x44, 0x55, 0x66];
        let pkt = ptp_pkt(0, MSG_DELAY_REQ, 2, 0, clock, 1, 34);
        let mut dec = PtpDecoder::default();
        let mut out = Vec::new();
        feed_udp(&mut dec, &pkt, 319, &mut out);
        assert!(find_txn(&out, "ptp_delay_req_first").is_some(), "missing ptp_delay_req_first");
    }

    // ── Test 5: Unknown messageType 0xF → unknown operation + low ParseAnomaly ─

    #[test]
    fn test_unknown_message_type() {
        let clock = [0x00, 0xEE, 0xFF, 0xFF, 0xFE, 0x77, 0x88, 0x99];
        let pkt = ptp_pkt(0, 0xF, 2, 0, clock, 1, 34);
        let mut dec = PtpDecoder::default();
        let mut out = Vec::new();
        feed_l2(&mut dec, &pkt, &mut out);

        assert!(find_txn(&out, "ptp_unknown_type_0xf_first").is_some(), "missing unknown-type txn");
        assert!(find_anomaly(&out, "low", "unknown messageType").is_some(), "missing low ParseAnomaly");
    }

    // ── Test 6: Two Announces, different GM in same domain → medium ParseAnomaly ─

    #[test]
    fn test_grandmaster_change_anomaly() {
        let clock = [0x00, 0x11, 0x22, 0xFF, 0xFE, 0x33, 0x44, 0x55];
        let pkt_a = announce_pkt(0, 0, clock, 1, 128, 128, 135, 0x21, [0xAA; 8], 1, 0xA0);
        let pkt_b = announce_pkt(0, 0, clock, 1, 128, 128, 135, 0x21, [0xBB; 8], 1, 0xA0);
        let mut dec = PtpDecoder::default();
        let mut out = Vec::new();

        feed_l2(&mut dec, &pkt_a, &mut out);
        // No grandmaster-change anomaly after first Announce.
        assert!(
            find_anomaly(&out, "medium", "grandmaster changed").is_none(),
            "spurious grandmaster-change anomaly on first Announce"
        );

        feed_l2(&mut dec, &pkt_b, &mut out);
        let anomaly = find_anomaly(&out, "medium", "grandmaster changed")
            .expect("missing grandmaster-change ParseAnomaly on second Announce");
        assert!(anomaly.reason.contains("domain 0"), "reason should mention domain: {}", anomaly.reason);
    }
}
