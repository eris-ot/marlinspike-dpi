use std::collections::{BTreeMap, HashMap, HashSet};

use chrono::{DateTime, Utc};

use crate::bronze::{
    AssetObservation, BronzeEvent, BronzeEventFamily, ProtocolTransaction, TransportProtocol,
};
use crate::engine::{
    DecoderInterest, SessionDecoder, StreamChunk, build_envelope, new_event, parse_anomaly_event,
};

const ADS_MAX_DATA_LEN: u32 = 16 * 1024 * 1024;
const ADS_PENDING_CAP: usize = 1024;
const AMS_TCP_HDR: usize = 6;
const AMS_PKT_HDR: usize = 32;
const ADS_MIN_FRAME: usize = AMS_TCP_HDR + AMS_PKT_HDR;
const FLAG_RESPONSE: u16 = 0x0001;

#[derive(Clone)]
struct Pending {
    capture_id: String,
    envelope: crate::bronze::EventEnvelope,
    operation: String,
    attributes: BTreeMap<String, String>,
}

#[derive(Default)]
pub(crate) struct AdsDecoder {
    buf: Vec<u8>,
    pending: HashMap<String, Pending>,
    seen_netids: HashSet<String>,
}

impl SessionDecoder for AdsDecoder {
    fn name(&self) -> &'static str {
        "ads"
    }

    fn interest(&self) -> &'static [DecoderInterest] {
        &[DecoderInterest::TcpPort(48898)]
    }

    fn on_stream_chunk(&mut self, chunk: &StreamChunk<'_>, out: &mut Vec<BronzeEvent>) {
        self.buf.extend_from_slice(chunk.payload);
        self.drain(chunk, out);
    }

    fn on_idle_flush(&mut self, _timestamp: DateTime<Utc>, out: &mut Vec<BronzeEvent>) {
        for (_, p) in self.pending.drain() {
            out.push(unpaired_tx(
                p.capture_id,
                p.envelope,
                p.operation,
                p.attributes,
                "request_only",
            ));
        }
    }
}

impl AdsDecoder {
    fn drain(&mut self, chunk: &StreamChunk<'_>, out: &mut Vec<BronzeEvent>) {
        loop {
            if self.buf.len() < ADS_MIN_FRAME {
                break;
            }

            let reserved = u16::from_le_bytes([self.buf[0], self.buf[1]]);
            let ams_len =
                u32::from_le_bytes([self.buf[2], self.buf[3], self.buf[4], self.buf[5]]) as usize;
            let total = AMS_TCP_HDR + ams_len;
            if self.buf.len() < total {
                break;
            }

            let frame: Vec<u8> = self.buf[..total].to_vec();
            self.buf.drain(..total);
            self.process(&frame, reserved, chunk, out);
        }
    }

    fn process(
        &mut self,
        frame: &[u8],
        reserved: u16,
        chunk: &StreamChunk<'_>,
        out: &mut Vec<BronzeEvent>,
    ) {
        let env = build_envelope(
            &chunk.context,
            chunk.interface_id,
            chunk.frame_index,
            chunk.timestamp,
            chunk.segment_hash,
            TransportProtocol::Tcp,
            Some("ads"),
            chunk.captured_len,
            chunk.session_key.clone(),
        );

        if reserved != 0 {
            out.push(parse_anomaly_event(
                chunk.capture_id.to_string(),
                env.clone(),
                self.name(),
                "medium",
                "AMS/TCP reserved field non-zero",
                frame,
            ));
        }

        let h = &frame[AMS_TCP_HDR..];
        if h.len() < AMS_PKT_HDR {
            out.push(parse_anomaly_event(
                chunk.capture_id.to_string(),
                env,
                self.name(),
                "medium",
                "AMS packet header truncated",
                frame,
            ));
            return;
        }

        let tgt_netid = fmt_netid(&h[0..6]);
        let tgt_port = u16::from_le_bytes([h[6], h[7]]);
        let src_netid = fmt_netid(&h[8..14]);
        let src_port = u16::from_le_bytes([h[14], h[15]]);
        let cmd_id = u16::from_le_bytes([h[16], h[17]]);
        let state_flags = u16::from_le_bytes([h[18], h[19]]);
        let data_len = u32::from_le_bytes([h[20], h[21], h[22], h[23]]);
        let error_code = u32::from_le_bytes([h[24], h[25], h[26], h[27]]);
        let invoke_id = u32::from_le_bytes([h[28], h[29], h[30], h[31]]);

        if data_len > ADS_MAX_DATA_LEN {
            out.push(parse_anomaly_event(
                chunk.capture_id.to_string(),
                env,
                self.name(),
                "high",
                "AMS data_len exceeds 16 MiB — likely malformed",
                frame,
            ));
            return;
        }

        let operation = cmd_operation(cmd_id);
        if !matches!(cmd_id, 1..=9) {
            out.push(parse_anomaly_event(
                chunk.capture_id.to_string(),
                env.clone(),
                self.name(),
                "low",
                &format!("unknown ADS command ID 0x{cmd_id:04x}"),
                frame,
            ));
        }

        let mut attrs = BTreeMap::new();
        attrs.insert("target_netid".into(), tgt_netid.clone());
        attrs.insert("target_port".into(), tgt_port.to_string());
        attrs.insert("source_netid".into(), src_netid.clone());
        attrs.insert("source_port".into(), src_port.to_string());
        attrs.insert("invoke_id".into(), invoke_id.to_string());
        attrs.insert("error_code".into(), error_code.to_string());
        attrs.insert("state_flags_hex".into(), format!("{state_flags:#06x}"));

        if self.seen_netids.insert(src_netid.clone()) {
            let mut ids = BTreeMap::new();
            ids.insert("ams_netid".into(), src_netid.clone());
            out.push(new_event(
                chunk.capture_id.to_string(),
                env.clone(),
                BronzeEventFamily::AssetObservation(AssetObservation {
                    asset_key: src_netid.clone(),
                    role: Some("beckhoff_runtime".into()),
                    vendor: None,
                    model: None,
                    firmware: None,
                    hostnames: Vec::new(),
                    protocols: vec!["ads".into()],
                    identifiers: ids,
                }),
            ));
        }

        if state_flags & FLAG_RESPONSE != 0 {
            let status = if error_code == 0 {
                "ok".into()
            } else {
                format!("ads_error_0x{error_code:08x}")
            };
            // Response target_netid is the original requester's source NetID.
            let req_key = format!("{}|{}|{}", chunk.session_key, tgt_netid, invoke_id);
            if let Some(p) = self.pending.remove(&req_key) {
                out.push(unpaired_tx(
                    p.capture_id,
                    p.envelope,
                    p.operation,
                    p.attributes,
                    &status,
                ));
            } else {
                out.push(unpaired_tx(
                    chunk.capture_id.to_string(),
                    env,
                    operation,
                    attrs,
                    "response_only",
                ));
            }
        } else {
            // Key on the requester's source NetID so the response lookup can find it.
            let key = format!("{}|{}|{}", chunk.session_key, src_netid, invoke_id);
            if self.pending.len() >= ADS_PENDING_CAP {
                // Evict oldest to bound memory on captures with no responses.
                if let Some(k) = self.pending.keys().next().cloned() {
                    self.pending.remove(&k);
                }
            }
            self.pending.insert(
                key,
                Pending {
                    capture_id: chunk.capture_id.to_string(),
                    envelope: env,
                    operation,
                    attributes: attrs,
                },
            );
        }
    }
}

fn fmt_netid(b: &[u8]) -> String {
    format!("{}.{}.{}.{}.{}.{}", b[0], b[1], b[2], b[3], b[4], b[5])
}

fn cmd_operation(id: u16) -> String {
    match id {
        1 => "ads_read_device_info",
        2 => "ads_read",
        3 => "ads_write",
        4 => "ads_read_state",
        5 => "ads_write_control",
        6 => "ads_add_device_notification",
        7 => "ads_delete_device_notification",
        8 => "ads_device_notification",
        9 => "ads_read_write",
        _ => return format!("ads_unknown_{id}"),
    }
    .into()
}

fn unpaired_tx(
    capture_id: String,
    envelope: crate::bronze::EventEnvelope,
    operation: String,
    attributes: BTreeMap<String, String>,
    status: &str,
) -> BronzeEvent {
    new_event(
        capture_id,
        envelope,
        BronzeEventFamily::ProtocolTransaction(ProtocolTransaction {
            operation,
            status: status.into(),
            request_summary: None,
            response_summary: None,
            object_refs: Vec::new(),
            values: Vec::new(),
            attributes,
            modbus: None,
            protocol_fields: None,
        }),
    )
}

inventory::submit!(crate::engine::decoders::DecoderRegistration {
    name: "ads",
    factory: || Box::new(AdsDecoder::default()),
});

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::StreamChunk;
    use crate::registry::PacketContext;
    use std::net::{IpAddr, Ipv4Addr};

    fn ctx(src_port: u16, dst_port: u16) -> PacketContext {
        PacketContext {
            src_mac: [0; 6],
            dst_mac: [0; 6],
            src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            dst_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            src_port,
            dst_port,
            vlan_id: None,
            timestamp: 0,
        }
    }

    fn chunk<'a>(payload: &'a [u8], context: PacketContext, session: &str) -> StreamChunk<'a> {
        StreamChunk {
            capture_id: "test",
            segment_hash: "aa",
            interface_id: 0,
            frame_index: 0,
            timestamp: Utc::now(),
            context,
            ethertype: 0x0800,
            ip_proto: Some(6),
            llc: None,
            transport: TransportProtocol::Tcp,
            payload,
            session_key: session.to_string(),
            captured_len: payload.len() as u64,
        }
    }

    /// Minimal AMS/TCP frame (no payload after AMS header).
    #[allow(clippy::too_many_arguments)]
    fn frame(
        src_n: [u8; 6],
        src_p: u16,
        dst_n: [u8; 6],
        dst_p: u16,
        cmd: u16,
        flags: u16,
        err: u32,
        invoke: u32,
        reserved: u16,
    ) -> Vec<u8> {
        let mut f = Vec::new();
        f.extend_from_slice(&reserved.to_le_bytes());
        f.extend_from_slice(&(AMS_PKT_HDR as u32).to_le_bytes());
        f.extend_from_slice(&dst_n);
        f.extend_from_slice(&dst_p.to_le_bytes());
        f.extend_from_slice(&src_n);
        f.extend_from_slice(&src_p.to_le_bytes());
        f.extend_from_slice(&cmd.to_le_bytes());
        f.extend_from_slice(&flags.to_le_bytes());
        f.extend_from_slice(&0u32.to_le_bytes()); // data_len = 0
        f.extend_from_slice(&err.to_le_bytes());
        f.extend_from_slice(&invoke.to_le_bytes());
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

    // 1. Request alone — no ProtocolTransaction emitted.
    #[test]
    fn request_alone_no_transaction() {
        let mut dec = AdsDecoder::default();
        let mut out = Vec::new();
        let f = frame(
            [10, 0, 0, 1, 1, 1],
            1000,
            [10, 0, 0, 2, 1, 1],
            851,
            2,
            0x04,
            0,
            42,
            0,
        );
        dec.on_stream_chunk(&chunk(&f, ctx(1000, 48898), "s1"), &mut out);
        assert!(txns(&out).is_empty());
        assert_eq!(dec.pending.len(), 1);
    }

    // 2. Request + matching response → ProtocolTransaction status="ok", correct operation.
    #[test]
    fn request_response_pair_ok() {
        let mut dec = AdsDecoder::default();
        let mut out = Vec::new();
        let sn = [10, 0, 0, 1, 1, 1];
        let dn = [10, 0, 0, 2, 1, 1];
        let req = frame(sn, 1000, dn, 851, 2, 0x04, 0, 7, 0);
        let resp = frame(dn, 851, sn, 1000, 2, 0x05, 0, 7, 0); // bit 0 set = response
        dec.on_stream_chunk(&chunk(&req, ctx(1000, 48898), "s2"), &mut out);
        dec.on_stream_chunk(&chunk(&resp, ctx(48898, 1000), "s2"), &mut out);
        let tx = txns(&out);
        assert_eq!(tx.len(), 1);
        assert_eq!(tx[0].operation, "ads_read");
        assert_eq!(tx[0].status, "ok");
    }

    // 3. Response with error_code 0x710 → status "ads_error_0x00000710".
    #[test]
    fn response_nonzero_error_code() {
        let mut dec = AdsDecoder::default();
        let mut out = Vec::new();
        let sn = [10, 0, 0, 3, 1, 1];
        let dn = [10, 0, 0, 4, 1, 1];
        dec.on_stream_chunk(
            &chunk(
                &frame(sn, 2000, dn, 851, 4, 0x04, 0, 99, 0),
                ctx(2000, 48898),
                "s3",
            ),
            &mut out,
        );
        dec.on_stream_chunk(
            &chunk(
                &frame(dn, 851, sn, 2000, 4, 0x05, 0x710, 99, 0),
                ctx(48898, 2000),
                "s3",
            ),
            &mut out,
        );
        assert_eq!(txns(&out)[0].status, "ads_error_0x00000710");
    }

    // 4. Reserved != 0 → ParseAnomaly severity "medium".
    #[test]
    fn reserved_nonzero_anomaly_medium() {
        let mut dec = AdsDecoder::default();
        let mut out = Vec::new();
        let f = frame(
            [1, 2, 3, 4, 5, 6],
            3000,
            [6, 5, 4, 3, 2, 1],
            851,
            2,
            0x04,
            0,
            1,
            1,
        );
        dec.on_stream_chunk(&chunk(&f, ctx(3000, 48898), "s4"), &mut out);
        let a = anomalies(&out);
        assert!(!a.is_empty());
        assert_eq!(a[0].severity, "medium");
    }

    // 5. Unknown command ID → anomaly severity "low" + operation contains "unknown".
    #[test]
    fn unknown_command_id_anomaly_and_operation() {
        let mut dec = AdsDecoder::default();
        let mut out = Vec::new();
        let f = frame(
            [10, 1, 1, 1, 1, 1],
            4000,
            [10, 1, 1, 2, 1, 1],
            851,
            0xFF,
            0x04,
            0,
            5,
            0,
        );
        dec.on_stream_chunk(&chunk(&f, ctx(4000, 48898), "s5"), &mut out);
        assert_eq!(anomalies(&out)[0].severity, "low");
        dec.on_idle_flush(Utc::now(), &mut out);
        assert!(txns(&out).iter().any(|t| t.operation.contains("unknown")));
    }

    // 6. Two distinct source NetIDs → two AssetObservations.
    #[test]
    fn two_netids_two_asset_observations() {
        let mut dec = AdsDecoder::default();
        let mut out = Vec::new();
        let fa = frame(
            [10, 0, 0, 1, 1, 1],
            5001,
            [10, 0, 0, 10, 1, 1],
            851,
            2,
            0x04,
            0,
            1,
            0,
        );
        let fb = frame(
            [172, 16, 0, 5, 1, 1],
            5002,
            [10, 0, 0, 10, 1, 1],
            851,
            2,
            0x04,
            0,
            2,
            0,
        );
        dec.on_stream_chunk(&chunk(&fa, ctx(5001, 48898), "s6"), &mut out);
        dec.on_stream_chunk(&chunk(&fb, ctx(5002, 48898), "s6"), &mut out);
        let obs: Vec<_> = out
            .iter()
            .filter(|e| matches!(e.family, BronzeEventFamily::AssetObservation(_)))
            .collect();
        assert_eq!(obs.len(), 2);
    }

    // 7. Same NetID seen twice → only one AssetObservation.
    #[test]
    fn same_netid_one_observation() {
        let mut dec = AdsDecoder::default();
        let mut out = Vec::new();
        let netid = [10, 0, 0, 1, 1, 1];
        for iv in [10u32, 11u32] {
            let f = frame(netid, 6000, [10, 0, 0, 2, 1, 1], 851, 2, 0x04, 0, iv, 0);
            dec.on_stream_chunk(&chunk(&f, ctx(6000, 48898), "s7"), &mut out);
        }
        let count = out
            .iter()
            .filter(|e| matches!(e.family, BronzeEventFamily::AssetObservation(_)))
            .count();
        assert_eq!(count, 1);
    }

    // 8. Frame split across two TCP chunks — reassembly must work.
    #[test]
    fn fragmented_reassembly() {
        let mut dec = AdsDecoder::default();
        let mut out = Vec::new();
        let f = frame(
            [10, 0, 0, 1, 1, 1],
            7000,
            [10, 0, 0, 2, 1, 1],
            851,
            3,
            0x04,
            0,
            55,
            0,
        );
        let mid = f.len() / 2;
        dec.on_stream_chunk(&chunk(&f[..mid], ctx(7000, 48898), "s8"), &mut out);
        assert!(txns(&out).is_empty(), "no events before frame complete");
        dec.on_stream_chunk(&chunk(&f[mid..], ctx(7000, 48898), "s8"), &mut out);
        assert_eq!(dec.pending.len(), 1); // request buffered, awaiting response
    }
}
