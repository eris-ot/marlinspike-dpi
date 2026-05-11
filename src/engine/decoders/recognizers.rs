//! Recognition-only `SessionDecoder` impls — port + light signature check,
//! emit a `ProtocolTransaction` for traffic classification. No deep PDU
//! parsing.
//!
//! Members: SMB, CC-Link IE, CODESYS, IO-Link Wireless.
//! Kerberos has been promoted to a full ASN.1 decoder in `kerberos.rs`.
//! LDAP has been promoted to a full BER operation parser in `ldap.rs`.
//! IGMP has been promoted to a full deep decoder in `igmp.rs`.

use std::collections::BTreeMap;

use crate::bronze::{BronzeEvent, BronzeEventFamily, ProtocolTransaction};
use crate::engine::{
    build_envelope, new_event, DecoderInterest, SessionDecoder, StreamChunk,
};

/// Helper to emit a single ProtocolTransaction recognition event.
fn emit_recognition(
    chunk: &StreamChunk<'_>,
    out: &mut Vec<BronzeEvent>,
    protocol: &'static str,
    operation: &'static str,
    summary: &str,
) {
    let envelope = build_envelope(
        &chunk.context,
        chunk.interface_id,
        chunk.frame_index,
        chunk.timestamp,
        chunk.segment_hash,
        chunk.transport,
        Some(protocol),
        chunk.captured_len,
        chunk.session_key.clone(),
    );
    let mut attributes = BTreeMap::new();
    attributes.insert("protocol".to_string(), protocol.to_string());
    out.push(new_event(
        chunk.capture_id.to_string(),
        envelope,
        BronzeEventFamily::ProtocolTransaction(ProtocolTransaction {
            operation: operation.to_string(),
            status: "ok".to_string(),
            request_summary: Some(summary.to_string()),
            response_summary: None,
            object_refs: Vec::new(),
            values: Vec::new(),
            attributes,
            modbus: None,
                                        protocol_fields: None,
        }),
    ));
}

pub(crate) struct SmbRecognizer;

impl SessionDecoder for SmbRecognizer {
    fn name(&self) -> &'static str {
        "smb"
    }

    fn interest(&self) -> &'static [DecoderInterest] {
        &[DecoderInterest::TcpPort(445), DecoderInterest::TcpPort(139)]
    }

    fn on_stream_chunk(&mut self, chunk: &StreamChunk<'_>, out: &mut Vec<BronzeEvent>) {
        let p = chunk.payload;
        // SMB direct (port 445): the SMB header may start at offset 4 if a
        // 4-byte NetBIOS-style length prefix is present (always for 139,
        // sometimes for 445), or at offset 0.
        let candidates: [usize; 2] = [4, 0];
        for &off in &candidates {
            if off + 4 > p.len() {
                continue;
            }
            let sig = &p[off..off + 4];
            if sig == [0xFF, b'S', b'M', b'B'] {
                emit_recognition(chunk, out, "smb", "smb1_message", "SMB1 traffic");
                return;
            }
            if sig == [0xFE, b'S', b'M', b'B'] {
                emit_recognition(chunk, out, "smb", "smb2_message", "SMB2 traffic");
                return;
            }
        }
    }
}


// CC-Link IE Field — UDP 61450, often multicast (239.192.0.0/16).
pub(crate) struct CcLinkRecognizer;

impl SessionDecoder for CcLinkRecognizer {
    fn name(&self) -> &'static str {
        "cclink"
    }

    fn interest(&self) -> &'static [DecoderInterest] {
        &[DecoderInterest::UdpPort(61450)]
    }

    fn on_datagram(&mut self, chunk: &StreamChunk<'_>, out: &mut Vec<BronzeEvent>) {
        emit_recognition(chunk, out, "cclink", "cclink_ie_traffic", "CC-Link IE Field traffic");
    }
}

// CODESYS — TCP 1217 (V3 Gateway), 1740 (V2), 2455 (V3 alt), 11740 (V3 Runtime).
pub(crate) struct CodesysRecognizer;

impl SessionDecoder for CodesysRecognizer {
    fn name(&self) -> &'static str {
        "codesys"
    }

    fn interest(&self) -> &'static [DecoderInterest] {
        &[
            DecoderInterest::TcpPort(1217),
            DecoderInterest::TcpPort(1740),
            DecoderInterest::TcpPort(2455),
            DecoderInterest::TcpPort(11740),
        ]
    }

    fn on_stream_chunk(&mut self, chunk: &StreamChunk<'_>, out: &mut Vec<BronzeEvent>) {
        let summary = match chunk.context.dst_port.max(chunk.context.src_port) {
            1217 => "CODESYS V3 Gateway traffic",
            1740 => "CODESYS V2 traffic",
            2455 => "CODESYS V3 (alternate) traffic",
            11740 => "CODESYS V3 Runtime traffic",
            _ => "CODESYS traffic",
        };
        emit_recognition(chunk, out, "codesys", "codesys_traffic", summary);
    }
}

// IO-Link Wireless — UDP 59152.
pub(crate) struct IoLinkRecognizer;

impl SessionDecoder for IoLinkRecognizer {
    fn name(&self) -> &'static str {
        "iolink"
    }

    fn interest(&self) -> &'static [DecoderInterest] {
        &[DecoderInterest::UdpPort(59152)]
    }

    fn on_datagram(&mut self, chunk: &StreamChunk<'_>, out: &mut Vec<BronzeEvent>) {
        emit_recognition(chunk, out, "iolink", "iolink_traffic", "IO-Link Wireless traffic");
    }
}

// ── Inventory registration ──────────────────────────────────────
inventory::submit!(crate::engine::decoders::DecoderRegistration {
    name: "smb",
    factory: || Box::new(SmbRecognizer),
});
inventory::submit!(crate::engine::decoders::DecoderRegistration {
    name: "cclink",
    factory: || Box::new(CcLinkRecognizer),
});
inventory::submit!(crate::engine::decoders::DecoderRegistration {
    name: "codesys",
    factory: || Box::new(CodesysRecognizer),
});
inventory::submit!(crate::engine::decoders::DecoderRegistration {
    name: "iolink",
    factory: || Box::new(IoLinkRecognizer),
});
