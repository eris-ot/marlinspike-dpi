use std::collections::BTreeMap;

use crate::bronze::{
    AssetObservation, BronzeEvent, BronzeEventFamily, ProtocolFields, ProtocolTransaction,
    TlsBronzeFields, TransportProtocol,
};
use crate::engine::{DecoderInterest, SessionDecoder, StreamChunk, build_envelope, new_event};

pub(crate) struct TlsDecoder;

impl SessionDecoder for TlsDecoder {
    fn name(&self) -> &'static str {
        "tls"
    }

    fn interest(&self) -> &'static [DecoderInterest] {
        &[
            DecoderInterest::TcpPort(443),
            DecoderInterest::TcpPort(4840),
        ]
    }

    fn on_stream_chunk(&mut self, chunk: &StreamChunk<'_>, out: &mut Vec<BronzeEvent>) {
        let Some(tls) = parse_tls_client_hello(chunk.payload) else {
            return;
        };
        let mut attributes = BTreeMap::new();
        attributes.insert("version".to_string(), tls.version.clone());
        if let Some(ref cipher) = tls.cipher_suite {
            attributes.insert("cipher_suite".to_string(), cipher.clone());
        }
        let envelope = build_envelope(
            &chunk.context,
            chunk.interface_id,
            chunk.frame_index,
            chunk.timestamp,
            chunk.segment_hash,
            TransportProtocol::Tcp,
            Some("tls"),
            chunk.captured_len,
            chunk.session_key.clone(),
        );
        let tls_pf = TlsBronzeFields {
            version: tls.version.clone(),
            cipher_suite: tls.cipher_suite.clone(),
            sni: tls.sni.clone(),
        };
        out.push(new_event(
            chunk.capture_id.to_string(),
            envelope.clone(),
            BronzeEventFamily::ProtocolTransaction(ProtocolTransaction {
                operation: "client_hello".to_string(),
                status: "observed".to_string(),
                request_summary: tls.sni.clone(),
                response_summary: None,
                object_refs: tls.sni.clone().into_iter().collect(),
                values: Vec::new(),
                attributes,
                modbus: None,
                protocol_fields: Some(ProtocolFields::Tls(tls_pf)),
            }),
        ));
        if let Some(sni) = tls.sni {
            out.push(new_event(
                chunk.capture_id.to_string(),
                envelope,
                BronzeEventFamily::AssetObservation(AssetObservation {
                    asset_key: chunk.context.dst_ip.to_string(),
                    role: None,
                    vendor: None,
                    model: None,
                    firmware: None,
                    hostnames: vec![sni],
                    protocols: vec!["tls".to_string()],
                    identifiers: BTreeMap::from([(
                        "ip".to_string(),
                        chunk.context.dst_ip.to_string(),
                    )]),
                }),
            ));
        }
    }
}

#[derive(Debug)]
struct ParsedTls {
    version: String,
    sni: Option<String>,
    cipher_suite: Option<String>,
}

fn parse_tls_client_hello(payload: &[u8]) -> Option<ParsedTls> {
    if payload.len() < 9 {
        return None;
    }
    let content_type = payload[0];
    if content_type != 22 {
        return None;
    }
    let version = format!("TLS {:02x}{:02x}", payload[1], payload[2]);
    let record_len = u16::from_be_bytes([payload[3], payload[4]]) as usize;
    if payload.len() < 5 + record_len || payload[5] != 1 {
        return None;
    }

    let mut offset = 9; // record header + handshake header
    if payload.len() < offset + 34 {
        return None;
    }
    offset += 2; // client version
    offset += 32; // random
    let session_id_len = *payload.get(offset)? as usize;
    offset += 1 + session_id_len;
    let cipher_len =
        u16::from_be_bytes([*payload.get(offset)?, *payload.get(offset + 1)?]) as usize;
    offset += 2;
    let cipher_suite = if cipher_len >= 2 && offset + 2 <= payload.len() {
        Some(format!(
            "0x{:02x}{:02x}",
            payload[offset],
            payload[offset + 1]
        ))
    } else {
        None
    };
    offset += cipher_len;
    let compression_len = *payload.get(offset)? as usize;
    offset += 1 + compression_len;
    let ext_len = u16::from_be_bytes([*payload.get(offset)?, *payload.get(offset + 1)?]) as usize;
    offset += 2;
    let ext_end = offset.checked_add(ext_len)?.min(payload.len());

    let mut sni = None;
    while offset + 4 <= ext_end {
        let ext_type = u16::from_be_bytes([payload[offset], payload[offset + 1]]);
        let item_len = u16::from_be_bytes([payload[offset + 2], payload[offset + 3]]) as usize;
        offset += 4;
        if offset + item_len > ext_end {
            break;
        }
        if ext_type == 0x0000 && item_len >= 5 {
            let list_len = u16::from_be_bytes([payload[offset], payload[offset + 1]]) as usize;
            if list_len + 2 <= item_len && payload[offset + 2] == 0 {
                let name_len =
                    u16::from_be_bytes([payload[offset + 3], payload[offset + 4]]) as usize;
                if offset + 5 + name_len <= ext_end {
                    sni = std::str::from_utf8(&payload[offset + 5..offset + 5 + name_len])
                        .ok()
                        .map(str::to_string);
                }
            }
        }
        offset += item_len;
    }

    Some(ParsedTls {
        version,
        sni,
        cipher_suite,
    })
}

inventory::submit!(crate::engine::decoders::DecoderRegistration {
    name: "tls",
    factory: || Box::new(TlsDecoder),
});

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a TLS 1.2 record-layer ClientHello carrying one cipher suite
    /// (0x1301) and an SNI extension for `host`.
    fn client_hello(host: &[u8]) -> Vec<u8> {
        // Handshake body (everything after the 4-byte handshake header).
        let mut body = Vec::new();
        body.extend_from_slice(&[0x03, 0x03]); // client_version TLS 1.2
        body.extend_from_slice(&[0u8; 32]); // random
        body.push(0); // session_id length = 0
        body.extend_from_slice(&[0x00, 0x02, 0x13, 0x01]); // cipher suites: len=2, TLS_AES_128_GCM_SHA256
        body.extend_from_slice(&[0x01, 0x00]); // compression: len=1, null

        // SNI extension data: server_name_list.
        let mut sni_data = Vec::new();
        let list_len = (1 + 2 + host.len()) as u16; // name_type + name_len + name
        sni_data.extend_from_slice(&list_len.to_be_bytes());
        sni_data.push(0); // name_type = host_name
        sni_data.extend_from_slice(&(host.len() as u16).to_be_bytes());
        sni_data.extend_from_slice(host);

        let mut exts = Vec::new();
        exts.extend_from_slice(&0x0000u16.to_be_bytes()); // ext_type = server_name
        exts.extend_from_slice(&(sni_data.len() as u16).to_be_bytes());
        exts.extend_from_slice(&sni_data);

        body.extend_from_slice(&(exts.len() as u16).to_be_bytes()); // extensions length
        body.extend_from_slice(&exts);

        // Handshake header: type=1 (ClientHello) + 3-byte length.
        let blen = body.len();
        let mut hs = vec![1, (blen >> 16) as u8, (blen >> 8) as u8, blen as u8];
        hs.extend_from_slice(&body);

        // Record header: content_type=22 (handshake), version 0x0301, length.
        let mut rec = vec![22, 0x03, 0x01];
        rec.extend_from_slice(&(hs.len() as u16).to_be_bytes());
        rec.extend_from_slice(&hs);
        rec
    }

    #[test]
    fn parses_version_cipher_and_sni() {
        let parsed = parse_tls_client_hello(&client_hello(b"example.com"))
            .expect("valid ClientHello must parse");
        assert_eq!(parsed.version, "TLS 0301");
        assert_eq!(parsed.cipher_suite.as_deref(), Some("0x1301"));
        assert_eq!(parsed.sni.as_deref(), Some("example.com"));
    }

    #[test]
    fn rejects_non_handshake_record() {
        // content_type 23 = application_data, not a handshake.
        let mut not_tls = client_hello(b"example.com");
        not_tls[0] = 23;
        assert!(parse_tls_client_hello(&not_tls).is_none());
    }

    #[test]
    fn rejects_truncated_payload() {
        assert!(parse_tls_client_hello(&[22, 0x03, 0x01]).is_none());
    }
}
