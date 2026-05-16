//! RadSec (RADIUS over TLS) session decoder — RFC 6614.
//!
//! RadSec is RADIUS-over-TLS. Payload is encrypted; this decoder is recognition +
//! TLS-handshake-byte fingerprinting + AssetObservation only.
//!
//! Without TLS session keys a passive sensor cannot read RADIUS attributes.
//! The decoder fingerprints the TLS record type from the first byte of each new
//! session on TCP port 2083 and records the server endpoint as an asset.
//! The STARTTLS upgrade variant (RFC 6614 §2.2) is out of scope.

use std::collections::{BTreeMap, HashSet};
use std::net::IpAddr;

use crate::bronze::{
    AssetObservation, BronzeEvent, BronzeEventFamily, ProtocolTransaction, TransportProtocol,
};
use crate::engine::{
    DecoderInterest, SessionDecoder, StreamChunk, build_envelope, new_event, parse_anomaly_event,
};

const TLS_CHANGE_CIPHER_SPEC: u8 = 0x14;
const TLS_ALERT: u8 = 0x15;
const TLS_HANDSHAKE: u8 = 0x16;
const TLS_APPLICATION_DATA: u8 = 0x17;

// ── Decoder ────────────────────────────────────────────────────────────────────

#[derive(Default)]
pub(crate) struct RadSecDecoder {
    seen_sessions: HashSet<String>,
}

impl SessionDecoder for RadSecDecoder {
    fn name(&self) -> &'static str {
        "radsec"
    }

    fn interest(&self) -> &'static [DecoderInterest] {
        static INTERESTS: [DecoderInterest; 1] = [DecoderInterest::TcpPort(2083)];
        &INTERESTS
    }

    fn on_stream_chunk(&mut self, chunk: &StreamChunk<'_>, out: &mut Vec<BronzeEvent>) {
        let payload = chunk.payload;
        if payload.is_empty() || !self.seen_sessions.insert(chunk.session_key.clone()) {
            return;
        }

        let make_env = || {
            build_envelope(
                &chunk.context,
                chunk.interface_id,
                chunk.frame_index,
                chunk.timestamp,
                chunk.segment_hash,
                TransportProtocol::Tcp,
                Some("radsec"),
                chunk.captured_len,
                chunk.session_key.clone(),
            )
        };

        let first = payload[0];
        if !matches!(
            first,
            TLS_CHANGE_CIPHER_SPEC | TLS_ALERT | TLS_HANDSHAKE | TLS_APPLICATION_DATA
        ) {
            out.push(parse_anomaly_event(
                chunk.capture_id.to_string(),
                make_env(),
                self.name(),
                "low",
                "port 2083 traffic does not start with a TLS record byte",
                payload,
            ));
            return;
        }

        // TLS record header: [content_type(1), version(2), length(2)]
        let tls_version_hex = if payload.len() >= 3 {
            format!("{:02x}{:02x}", payload[1], payload[2])
        } else {
            "unknown".to_string()
        };
        let record_length = if payload.len() >= 5 {
            u16::from_be_bytes([payload[3], payload[4]]).to_string()
        } else {
            "unknown".to_string()
        };

        let mut attrs = BTreeMap::new();
        attrs.insert("tls_record_type".to_string(), (first as u32).to_string());
        attrs.insert("tls_version_hex".to_string(), tls_version_hex);
        attrs.insert("record_length".to_string(), record_length);

        let env = make_env();
        out.push(new_event(
            chunk.capture_id.to_string(),
            env.clone(),
            BronzeEventFamily::ProtocolTransaction(ProtocolTransaction {
                operation: "radsec_tls_session".to_string(),
                status: "observed".to_string(),
                request_summary: None,
                response_summary: None,
                object_refs: Vec::new(),
                values: Vec::new(),
                attributes: attrs,
                modbus: None,
                protocol_fields: None,
            }),
        ));

        let mut identifiers = BTreeMap::new();
        identifiers.insert("port".to_string(), "2083".to_string());
        out.push(new_event(
            chunk.capture_id.to_string(),
            env,
            BronzeEventFamily::AssetObservation(AssetObservation {
                asset_key: dst_asset_key(&chunk.context),
                role: Some("radsec_server".to_string()),
                vendor: None,
                model: None,
                firmware: None,
                hostnames: Vec::new(),
                protocols: vec!["radsec".to_string()],
                identifiers,
            }),
        ));
    }
}

fn dst_asset_key(ctx: &crate::registry::PacketContext) -> String {
    match ctx.dst_ip {
        IpAddr::V4(ip) if ip != std::net::Ipv4Addr::UNSPECIFIED => ip.to_string(),
        IpAddr::V6(ip) if ip != std::net::Ipv6Addr::UNSPECIFIED => ip.to_string(),
        _ => crate::registry::format_mac(&ctx.dst_mac),
    }
}

// ── Self-registration ──────────────────────────────────────────────────────────

inventory::submit!(crate::engine::decoders::DecoderRegistration {
    name: "radsec",
    factory: || Box::new(RadSecDecoder::default()),
});

// ── Tests ──────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    use chrono::Utc;

    use crate::bronze::BronzeEventFamily;
    use crate::engine::{DecoderInterest, SessionDecoder, StreamChunk};
    use crate::registry::PacketContext;

    fn make_context() -> PacketContext {
        PacketContext {
            src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            dst_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            src_port: 54321,
            dst_port: 2083,
            src_mac: [0x00, 0x11, 0x22, 0x33, 0x44, 0x55],
            dst_mac: [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF],
            vlan_id: None,
            timestamp: 0,
        }
    }

    fn make_chunk<'a>(
        payload: &'a [u8],
        ctx: &'a PacketContext,
        session_key: &'a str,
    ) -> StreamChunk<'a> {
        StreamChunk {
            capture_id: "test_cap",
            segment_hash: "deadbeef",
            interface_id: 0,
            frame_index: 1,
            timestamp: Utc::now(),
            context: ctx.clone(),
            ethertype: 0x0800,
            ip_proto: Some(6),
            llc: None,
            transport: TransportProtocol::Tcp,
            payload,
            session_key: session_key.to_string(),
            captured_len: payload.len() as u64,
        }
    }

    fn as_transaction(ev: &BronzeEvent) -> &ProtocolTransaction {
        match &ev.family {
            BronzeEventFamily::ProtocolTransaction(tx) => tx,
            other => panic!("expected ProtocolTransaction, got {other:?}"),
        }
    }

    fn as_asset(ev: &BronzeEvent) -> &AssetObservation {
        match &ev.family {
            BronzeEventFamily::AssetObservation(a) => a,
            other => panic!("expected AssetObservation, got {other:?}"),
        }
    }

    fn as_anomaly(ev: &BronzeEvent) -> &crate::bronze::ParseAnomaly {
        match &ev.family {
            BronzeEventFamily::ParseAnomaly(a) => a,
            other => panic!("expected ParseAnomaly, got {other:?}"),
        }
    }

    // Test 1: 0x16 (TLS Handshake) + TLS 1.2 version → correct ProtocolTransaction fields.
    #[test]
    fn tls_handshake_byte_emits_session_transaction() {
        let mut dec = RadSecDecoder::default();
        let mut out = Vec::new();
        // content_type=0x16, version=0x03 0x03 (TLS 1.2), length=0x00 0x28 (40)
        let payload = [0x16u8, 0x03, 0x03, 0x00, 0x28, 0xAB, 0xCD];
        let ctx = make_context();
        dec.on_stream_chunk(&make_chunk(&payload, &ctx, "sess-1"), &mut out);

        assert_eq!(
            out.len(),
            2,
            "expected ProtocolTransaction + AssetObservation"
        );
        let tx = as_transaction(&out[0]);
        assert_eq!(tx.operation, "radsec_tls_session");
        assert_eq!(tx.status, "observed");
        assert_eq!(tx.attributes["tls_record_type"], "22", "0x16 = 22 decimal");
        assert_eq!(tx.attributes["tls_version_hex"], "0303", "TLS 1.2");
        assert_eq!(tx.attributes["record_length"], "40", "0x0028 = 40");
    }

    // Test 2: AssetObservation carries role=radsec_server and port=2083.
    #[test]
    fn asset_observation_has_radsec_server_role() {
        let mut dec = RadSecDecoder::default();
        let mut out = Vec::new();
        let payload = [0x16u8, 0x03, 0x03, 0x00, 0x10];
        let ctx = make_context();
        dec.on_stream_chunk(&make_chunk(&payload, &ctx, "sess-2"), &mut out);

        assert_eq!(out.len(), 2);
        let asset = as_asset(&out[1]);
        assert_eq!(asset.role.as_deref(), Some("radsec_server"));
        assert_eq!(
            asset.identifiers.get("port").map(String::as_str),
            Some("2083")
        );
        assert_eq!(asset.asset_key, "10.0.0.2");
    }

    // Test 3: Second chunk on same session_key → no additional events.
    #[test]
    fn second_chunk_on_same_session_is_silent() {
        let mut dec = RadSecDecoder::default();
        let mut out = Vec::new();
        let p1 = [0x16u8, 0x03, 0x03, 0x00, 0x05];
        let p2 = [0x17u8, 0x03, 0x03, 0x01, 0x00];
        let ctx = make_context();
        dec.on_stream_chunk(&make_chunk(&p1, &ctx, "sess-3"), &mut out);
        assert_eq!(out.len(), 2);
        dec.on_stream_chunk(&make_chunk(&p2, &ctx, "sess-3"), &mut out);
        assert_eq!(out.len(), 2, "second chunk must not add events");
    }

    // Test 4: Non-TLS first byte → ParseAnomaly severity=low.
    #[test]
    fn non_tls_first_byte_emits_low_severity_anomaly() {
        let mut dec = RadSecDecoder::default();
        let mut out = Vec::new();
        let payload = [0xABu8, 0x00, 0x01, 0x02, 0x03];
        let ctx = make_context();
        dec.on_stream_chunk(&make_chunk(&payload, &ctx, "sess-4"), &mut out);

        assert_eq!(out.len(), 1);
        let anomaly = as_anomaly(&out[0]);
        assert_eq!(anomaly.severity, "low");
        assert!(
            anomaly.reason.contains("TLS record byte"),
            "got: {}",
            anomaly.reason
        );
    }

    // Test 5: Interest list is exactly TCP/2083.
    #[test]
    fn interest_is_tcp_2083_only() {
        let dec = RadSecDecoder::default();
        let interests = dec.interest();
        assert_eq!(interests, &[DecoderInterest::TcpPort(2083)]);
    }
}
