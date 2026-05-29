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
use crate::engine::{StreamChunk, build_envelope, new_event};

/// Helper to emit a single ProtocolTransaction recognition event.
#[allow(dead_code)]
pub(super) fn emit_recognition(
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

#[cfg(feature = "cclink")]
pub(crate) mod cclink;
#[cfg(feature = "codesys")]
pub(crate) mod codesys;
#[cfg(feature = "iolink")]
pub(crate) mod iolink;
#[cfg(feature = "smb")]
pub(crate) mod smb;
