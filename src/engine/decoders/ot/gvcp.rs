//! GVCP (GigE Vision Control Protocol) session decoder — UDP 3956.
//!
//! GigE Vision Standard 2.x §14–16. Command packets begin with key_code 0x42;
//! acknowledge packets begin with a status u16 BE (0x0000 = success).

use std::collections::BTreeMap;

use crate::bronze::{
    AssetObservation, BronzeEvent, BronzeEventFamily, ProtocolTransaction, TransportProtocol,
};
use crate::engine::{
    build_envelope, new_event, parse_anomaly_event, DecoderInterest, SessionDecoder, StreamChunk,
};

// GVCP command codes (GigE Vision Standard 2.x §14)

const CMD_DISCOVERY:     u16 = 0x0002;
const ACK_DISCOVERY:     u16 = 0x0003;
const CMD_FORCEIP:       u16 = 0x0004;
const ACK_FORCEIP:       u16 = 0x0005;
const CMD_PACKETRESEND:  u16 = 0x0040;
const CMD_READREG:       u16 = 0x0080;
const ACK_READREG:       u16 = 0x0081;
const CMD_WRITEREG:      u16 = 0x0082;
const ACK_WRITEREG:      u16 = 0x0083;
const CMD_READMEM:       u16 = 0x0084;
const ACK_READMEM:       u16 = 0x0085;
const CMD_WRITEMEM:      u16 = 0x0086;
const ACK_WRITEMEM:      u16 = 0x0087;
const CMD_EVENT:         u16 = 0x0090;
const CMD_ACTION:        u16 = 0x00C0;

const GVCP_KEY_CODE: u8 = 0x42; // sentinel: byte 0 of every command packet
const HEADER_LEN:    usize = 8; // minimum wire size

// DISCOVERY_ACK payload (§16.2): 56-byte network/device state block precedes the string fields.
const DISC_STR_OFFSET:       usize = 56;
const DISC_MANUFACTURER_OFF: usize = DISC_STR_OFFSET;        // 32 bytes
const DISC_MODEL_OFF:        usize = DISC_STR_OFFSET + 32;   // 32 bytes
const DISC_VERSION_OFF:      usize = DISC_STR_OFFSET + 64;   // 32 bytes
const DISC_MFR_INFO_OFF:     usize = DISC_STR_OFFSET + 96;   // 48 bytes
const DISC_SERIAL_OFF:       usize = DISC_STR_OFFSET + 144;  // 16 bytes
const DISC_USERNAME_OFF:     usize = DISC_STR_OFFSET + 160;  // 16 bytes

const DISC_ACK_PAYLOAD_FULL: usize = DISC_USERNAME_OFF + 16; // 176 bytes total


#[derive(Debug)]
struct GvcpCommand {
    flags:      u8,
    command:    u16,
    length:     u16,
    request_id: u16,
}

#[derive(Debug)]
struct GvcpAck {
    status:      u16,
    acknowledge: u16,
    length:      u16,
    ack_id:      u16,
}


fn parse_command(buf: &[u8]) -> Option<GvcpCommand> {
    if buf.len() < HEADER_LEN || buf[0] != GVCP_KEY_CODE {
        return None;
    }
    Some(GvcpCommand {
        flags:      buf[1],
        command:    u16::from_be_bytes([buf[2], buf[3]]),
        length:     u16::from_be_bytes([buf[4], buf[5]]),
        request_id: u16::from_be_bytes([buf[6], buf[7]]),
    })
}

fn parse_ack(buf: &[u8]) -> Option<GvcpAck> {
    if buf.len() < HEADER_LEN {
        return None;
    }
    Some(GvcpAck {
        status:      u16::from_be_bytes([buf[0], buf[1]]),
        acknowledge: u16::from_be_bytes([buf[2], buf[3]]),
        length:      u16::from_be_bytes([buf[4], buf[5]]),
        ack_id:      u16::from_be_bytes([buf[6], buf[7]]),
    })
}

/// Map a GVCP command/ack code to an operation slug.
fn command_to_operation(code: u16) -> String {
    match code {
        CMD_DISCOVERY    => "gvcp_discovery".to_string(),
        ACK_DISCOVERY    => "gvcp_discovery_ack".to_string(),
        CMD_FORCEIP      => "gvcp_forceip".to_string(),
        ACK_FORCEIP      => "gvcp_forceip_ack".to_string(),
        CMD_PACKETRESEND => "gvcp_packetresend".to_string(),
        CMD_READREG      => "gvcp_readreg".to_string(),
        ACK_READREG      => "gvcp_readreg_ack".to_string(),
        CMD_WRITEREG     => "gvcp_writereg".to_string(),
        ACK_WRITEREG     => "gvcp_writereg_ack".to_string(),
        CMD_READMEM      => "gvcp_readmem".to_string(),
        ACK_READMEM      => "gvcp_readmem_ack".to_string(),
        CMD_WRITEMEM     => "gvcp_writemem".to_string(),
        ACK_WRITEMEM     => "gvcp_writemem_ack".to_string(),
        CMD_EVENT        => "gvcp_event".to_string(),
        CMD_ACTION       => "gvcp_action".to_string(),
        other            => format!("gvcp_unknown_0x{other:04x}"),
    }
}

/// Read a null-terminated ASCII string from a fixed-width byte slice.
///
/// Convention: GVCP strings are padded with NUL bytes to their fixed field
/// width. We trim at the first NUL so callers receive only the printable
/// content. Non-UTF-8 bytes are replaced with U+FFFD (lossy) — cameras in
/// the field sometimes ship stale firmware that doesn't sanitise these.
fn trim_nul(bytes: &[u8]) -> String {
    let end = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
    String::from_utf8_lossy(&bytes[..end]).trim().to_string()
}


#[derive(Default)]
pub(crate) struct GvcpDecoder;

impl SessionDecoder for GvcpDecoder {
    fn name(&self) -> &'static str {
        "gvcp"
    }

    fn interest(&self) -> &'static [DecoderInterest] {
        &[DecoderInterest::UdpPort(3956)]
    }

    fn on_datagram(&mut self, chunk: &StreamChunk<'_>, out: &mut Vec<BronzeEvent>) {
        let buf = chunk.payload;

        // Minimum frame guard.
        if buf.len() < HEADER_LEN {
            out.push(parse_anomaly_event(
                chunk.capture_id.to_string(),
                build_envelope(
                    &chunk.context,
                    chunk.interface_id,
                    chunk.frame_index,
                    chunk.timestamp,
                    chunk.segment_hash,
                    TransportProtocol::Udp,
                    Some("gvcp"),
                    chunk.captured_len,
                    chunk.session_key.clone(),
                ),
                self.name(),
                "medium",
                "gvcp frame shorter than 8-byte header",
                buf,
            ));
            return;
        }

        let is_command = buf[0] == GVCP_KEY_CODE;

        if is_command {
            self.handle_command(chunk, buf, out);
        } else {
            self.handle_ack(chunk, buf, out);
        }
    }
}

impl GvcpDecoder {
    fn handle_command(
        &mut self,
        chunk: &StreamChunk<'_>,
        buf: &[u8],
        out: &mut Vec<BronzeEvent>,
    ) {
        let cmd = match parse_command(buf) {
            Some(c) => c,
            None => return,
        };

        let envelope = build_envelope(
            &chunk.context,
            chunk.interface_id,
            chunk.frame_index,
            chunk.timestamp,
            chunk.segment_hash,
            TransportProtocol::Udp,
            Some("gvcp"),
            chunk.captured_len,
            chunk.session_key.clone(),
        );

        let operation = command_to_operation(cmd.command);
        let is_unknown = operation.starts_with("gvcp_unknown_");

        // Emit ParseAnomaly for unknown commands (low severity).
        if is_unknown {
            out.push(parse_anomaly_event(
                chunk.capture_id.to_string(),
                envelope.clone(),
                self.name(),
                "low",
                &format!("unknown gvcp command code 0x{:04x}", cmd.command),
                buf,
            ));
        }

        let mut attributes = BTreeMap::new();
        attributes.insert("command".to_string(), format!("0x{:04x}", cmd.command));
        attributes.insert("request_id".to_string(), cmd.request_id.to_string());
        attributes.insert("payload_length".to_string(), cmd.length.to_string());
        attributes.insert("flags_hex".to_string(), format!("0x{:02x}", cmd.flags));

        out.push(new_event(
            chunk.capture_id.to_string(),
            envelope,
            BronzeEventFamily::ProtocolTransaction(ProtocolTransaction {
                operation,
                status: "observed".to_string(),
                request_summary: Some(format!(
                    "GVCP cmd=0x{:04x} rid={}",
                    cmd.command, cmd.request_id
                )),
                response_summary: None,
                object_refs: vec![],
                values: vec![],
                attributes,
                modbus: None,
                protocol_fields: None,
            }),
        ));
    }

    fn handle_ack(
        &mut self,
        chunk: &StreamChunk<'_>,
        buf: &[u8],
        out: &mut Vec<BronzeEvent>,
    ) {
        // If byte 0 is not 0x42 but this doesn't look like a valid ack either,
        // emit a medium-severity anomaly (likely key_code corruption or wrong
        // protocol speaking on port 3956).
        let ack = match parse_ack(buf) {
            Some(a) => a,
            None => {
                out.push(parse_anomaly_event(
                    chunk.capture_id.to_string(),
                    build_envelope(
                        &chunk.context,
                        chunk.interface_id,
                        chunk.frame_index,
                        chunk.timestamp,
                        chunk.segment_hash,
                        TransportProtocol::Udp,
                        Some("gvcp"),
                        chunk.captured_len,
                        chunk.session_key.clone(),
                    ),
                    self.name(),
                    "medium",
                    "gvcp frame: key_code != 0x42 and insufficient bytes for ack",
                    buf,
                ));
                return;
            }
        };

        let envelope = build_envelope(
            &chunk.context,
            chunk.interface_id,
            chunk.frame_index,
            chunk.timestamp,
            chunk.segment_hash,
            TransportProtocol::Udp,
            Some("gvcp"),
            chunk.captured_len,
            chunk.session_key.clone(),
        );

        let operation = command_to_operation(ack.acknowledge);

        let status = if ack.status == 0x0000 {
            "ok".to_string()
        } else {
            format!("gvcp_status_0x{:04x}", ack.status)
        };

        let is_unknown_ack = operation.starts_with("gvcp_unknown_");
        if is_unknown_ack {
            out.push(parse_anomaly_event(
                chunk.capture_id.to_string(),
                envelope.clone(),
                self.name(),
                "low",
                &format!("unknown gvcp acknowledge code 0x{:04x}", ack.acknowledge),
                buf,
            ));
        }

        let mut attributes = BTreeMap::new();
        attributes.insert("command".to_string(), format!("0x{:04x}", ack.acknowledge));
        attributes.insert("request_id".to_string(), ack.ack_id.to_string());
        attributes.insert("payload_length".to_string(), ack.length.to_string());
        attributes.insert("flags_hex".to_string(), "0x00".to_string());

        out.push(new_event(
            chunk.capture_id.to_string(),
            envelope.clone(),
            BronzeEventFamily::ProtocolTransaction(ProtocolTransaction {
                operation: operation.clone(),
                status,
                request_summary: Some(format!(
                    "GVCP ack=0x{:04x} id={}",
                    ack.acknowledge, ack.ack_id
                )),
                response_summary: None,
                object_refs: vec![],
                values: vec![],
                attributes,
                modbus: None,
                protocol_fields: None,
            }),
        ));

        // DISCOVERY_ACK carries the camera identity — parse it for AssetObservation.
        if ack.acknowledge == ACK_DISCOVERY {
            self.emit_discovery_asset(chunk, buf, envelope, out);
        }
    }

    /// Parse the DISCOVERY_ACK string block and emit an AssetObservation.
    fn emit_discovery_asset(
        &self,
        chunk: &StreamChunk<'_>,
        buf: &[u8],
        envelope: crate::bronze::EventEnvelope,
        out: &mut Vec<BronzeEvent>,
    ) {
        let payload = &buf[HEADER_LEN..];
        if payload.len() < DISC_ACK_PAYLOAD_FULL {
            // Undersized DISCOVERY_ACK — skip asset extraction silently.
            return;
        }

        // NUL-trim convention: each string field is padded to its fixed byte
        // width with NUL bytes. `trim_nul` slices at the first 0x00 so the
        // resulting String contains only the printable device-supplied text.
        let manufacturer = trim_nul(&payload[DISC_MANUFACTURER_OFF..DISC_MANUFACTURER_OFF + 32]);
        let model        = trim_nul(&payload[DISC_MODEL_OFF..DISC_MODEL_OFF + 32]);
        let version      = trim_nul(&payload[DISC_VERSION_OFF..DISC_VERSION_OFF + 32]);
        let mfr_info     = trim_nul(&payload[DISC_MFR_INFO_OFF..DISC_MFR_INFO_OFF + 48]);
        let serial       = trim_nul(&payload[DISC_SERIAL_OFF..DISC_SERIAL_OFF + 16]);
        let username     = trim_nul(&payload[DISC_USERNAME_OFF..DISC_USERNAME_OFF + 16]);

        let asset_key = chunk.context.src_ip.to_string();

        let mut identifiers = BTreeMap::new();
        identifiers.insert("ip".to_string(), asset_key.clone());
        if !serial.is_empty() {
            identifiers.insert("serial_number".to_string(), serial);
        }
        if !mfr_info.is_empty() {
            identifiers.insert("manufacturer_info".to_string(), mfr_info);
        }

        let hostnames = if username.is_empty() {
            vec![]
        } else {
            vec![username]
        };

        out.push(new_event(
            chunk.capture_id.to_string(),
            envelope,
            BronzeEventFamily::AssetObservation(AssetObservation {
                asset_key,
                role: Some("gige_vision_camera".to_string()),
                vendor: if manufacturer.is_empty() { None } else { Some(manufacturer) },
                model: if model.is_empty() { None } else { Some(model) },
                firmware: if version.is_empty() { None } else { Some(version) },
                hostnames,
                protocols: vec!["gvcp".to_string()],
                identifiers,
            }),
        ));
    }
}


inventory::submit!(crate::engine::decoders::DecoderRegistration {
    name: "gvcp",
    factory: || Box::new(GvcpDecoder::default()),
});


#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};

    use chrono::Utc;

    use super::*;
    use crate::bronze::BronzeEventFamily;
    use crate::engine::StreamChunk;
    use crate::registry::PacketContext;

    fn make_context() -> PacketContext {
        PacketContext {
            src_ip:  IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10)),
            dst_ip:  IpAddr::V4(Ipv4Addr::new(255, 255, 255, 255)),
            src_port: 49152,
            dst_port: 3956,
            src_mac: [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF],
            dst_mac: [0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF],
            vlan_id: None,
            timestamp: 0,
        }
    }

    fn feed(dec: &mut GvcpDecoder, payload: &[u8], out: &mut Vec<BronzeEvent>) {
        let context = make_context();
        let chunk = StreamChunk {
            capture_id:   "cap-test",
            segment_hash: "seg",
            interface_id: 0,
            frame_index:  1,
            timestamp:    Utc::now(),
            context,
            ethertype:    0x0800,
            ip_proto:     Some(17),
            llc:          None,
            transport:    TransportProtocol::Udp,
            payload,
            session_key:  "192.168.1.10:49152-255.255.255.255:3956".to_string(),
            captured_len: payload.len() as u64,
        };
        dec.on_datagram(&chunk, out);
    }

    /// Build an 8-byte GVCP command header.
    fn cmd_header(flags: u8, command: u16, length: u16, request_id: u16) -> Vec<u8> {
        let mut buf = vec![GVCP_KEY_CODE, flags];
        buf.extend_from_slice(&command.to_be_bytes());
        buf.extend_from_slice(&length.to_be_bytes());
        buf.extend_from_slice(&request_id.to_be_bytes());
        buf
    }

    /// Build an 8-byte GVCP ack header.
    fn ack_header(status: u16, acknowledge: u16, length: u16, ack_id: u16) -> Vec<u8> {
        let mut buf = vec![];
        buf.extend_from_slice(&status.to_be_bytes());
        buf.extend_from_slice(&acknowledge.to_be_bytes());
        buf.extend_from_slice(&length.to_be_bytes());
        buf.extend_from_slice(&ack_id.to_be_bytes());
        buf
    }

    /// Pad an ASCII string to `width` bytes, NUL-filling the tail.
    fn padded(s: &str, width: usize) -> Vec<u8> {
        let mut v = s.as_bytes().to_vec();
        v.resize(width, 0);
        v
    }

    // 1. DISCOVERY_CMD → operation = gvcp_discovery, request_id matches
    #[test]
    fn test_discovery_cmd() {
        let mut dec = GvcpDecoder::default();
        let mut out = Vec::new();
        let pkt = cmd_header(0x01, CMD_DISCOVERY, 0, 42);
        feed(&mut dec, &pkt, &mut out);

        assert_eq!(out.len(), 1, "expected exactly one event");
        let BronzeEventFamily::ProtocolTransaction(ref txn) = out[0].family else {
            panic!("expected ProtocolTransaction");
        };
        assert_eq!(txn.operation, "gvcp_discovery");
        assert_eq!(txn.status, "observed");
        assert_eq!(txn.attributes["request_id"], "42");
        assert_eq!(txn.attributes["command"], "0x0002");
    }

    // 2. DISCOVERY_ACK with full payload → AssetObservation vendor/model parsed
    #[test]
    fn test_discovery_ack_asset_observation() {
        let mut dec = GvcpDecoder::default();
        let mut out = Vec::new();

        // Build a 176-byte payload (the minimum spec-defined block).
        // Byte layout: 56-byte device/network block + 176-56 = 120 bytes of strings.
        // We zero-fill the 56-byte header block and fill the strings.
        let mut payload = vec![0u8; 56]; // network/device state block
        payload.extend_from_slice(&padded("ACME Vision", 32)); // manufacturer_name
        payload.extend_from_slice(&padded("C1500", 32));       // model_name
        payload.extend_from_slice(&padded("2.3.1", 32));       // device_version
        payload.extend_from_slice(&padded("Industrial", 48));  // manufacturer_info
        payload.extend_from_slice(&padded("SN-0042", 16));     // serial_number
        payload.extend_from_slice(&padded("LineScan01", 16));  // user_defined_name

        assert_eq!(payload.len(), DISC_ACK_PAYLOAD_FULL, "payload must be exactly {DISC_ACK_PAYLOAD_FULL} bytes");

        let mut pkt = ack_header(0x0000, ACK_DISCOVERY, payload.len() as u16, 7);
        pkt.extend_from_slice(&payload);
        feed(&mut dec, &pkt, &mut out);

        // Expect: ProtocolTransaction + AssetObservation.
        assert_eq!(out.len(), 2, "expected ProtocolTransaction + AssetObservation");

        let txn_ev = out.iter().find(|e| matches!(e.family, BronzeEventFamily::ProtocolTransaction(_)))
            .expect("missing ProtocolTransaction");
        let BronzeEventFamily::ProtocolTransaction(ref txn) = txn_ev.family else { unreachable!() };
        assert_eq!(txn.operation, "gvcp_discovery_ack");
        assert_eq!(txn.status, "ok");

        let asset_ev = out.iter().find(|e| matches!(e.family, BronzeEventFamily::AssetObservation(_)))
            .expect("missing AssetObservation");
        let BronzeEventFamily::AssetObservation(ref asset) = asset_ev.family else { unreachable!() };
        assert_eq!(asset.role.as_deref(), Some("gige_vision_camera"));
        assert_eq!(asset.vendor.as_deref(), Some("ACME Vision"));
        assert_eq!(asset.model.as_deref(), Some("C1500"));
        assert_eq!(asset.firmware.as_deref(), Some("2.3.1"));
        assert_eq!(asset.hostnames, vec!["LineScan01".to_string()]);
        assert_eq!(asset.identifiers["serial_number"], "SN-0042");
        assert_eq!(asset.identifiers["manufacturer_info"], "Industrial");
    }

    // 3. READREG_CMD → operation = gvcp_readreg
    #[test]
    fn test_readreg_cmd() {
        let mut dec = GvcpDecoder::default();
        let mut out = Vec::new();
        // READREG payload: list of register addresses (u32 each); 4 bytes = 1 register.
        let mut pkt = cmd_header(0x01, CMD_READREG, 4, 99);
        pkt.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // register address 0
        feed(&mut dec, &pkt, &mut out);

        assert_eq!(out.len(), 1);
        let BronzeEventFamily::ProtocolTransaction(ref txn) = out[0].family else {
            panic!("expected ProtocolTransaction");
        };
        assert_eq!(txn.operation, "gvcp_readreg");
        assert_eq!(txn.status, "observed");
        assert_eq!(txn.attributes["request_id"], "99");
    }

    // 4. WRITEREG_ACK status=0x8002 → status = "gvcp_status_0x8002"
    #[test]
    fn test_writereg_ack_error_status() {
        let mut dec = GvcpDecoder::default();
        let mut out = Vec::new();
        let pkt = ack_header(0x8002, ACK_WRITEREG, 0, 55);
        feed(&mut dec, &pkt, &mut out);

        assert_eq!(out.len(), 1);
        let BronzeEventFamily::ProtocolTransaction(ref txn) = out[0].family else {
            panic!("expected ProtocolTransaction");
        };
        assert_eq!(txn.operation, "gvcp_writereg_ack");
        assert_eq!(txn.status, "gvcp_status_0x8002");
    }

    // 5. Unknown command 0xFFFF → gvcp_unknown_0xffff + ParseAnomaly severity=low
    #[test]
    fn test_unknown_command_anomaly() {
        let mut dec = GvcpDecoder::default();
        let mut out = Vec::new();
        let pkt = cmd_header(0x00, 0xFFFF, 0, 1);
        feed(&mut dec, &pkt, &mut out);

        // Expect: ParseAnomaly then ProtocolTransaction (order from handle_command).
        assert_eq!(out.len(), 2, "expected ParseAnomaly + ProtocolTransaction");

        let anomaly_ev = out.iter().find(|e| matches!(e.family, BronzeEventFamily::ParseAnomaly(_)))
            .expect("missing ParseAnomaly");
        let BronzeEventFamily::ParseAnomaly(ref anomaly) = anomaly_ev.family else { unreachable!() };
        assert_eq!(anomaly.severity, "low");
        assert!(anomaly.reason.contains("0xffff"), "reason: {}", anomaly.reason);

        let txn_ev = out.iter().find(|e| matches!(e.family, BronzeEventFamily::ProtocolTransaction(_)))
            .expect("missing ProtocolTransaction");
        let BronzeEventFamily::ProtocolTransaction(ref txn) = txn_ev.family else { unreachable!() };
        assert_eq!(txn.operation, "gvcp_unknown_0xffff");
    }

    // 6. Frame < 8 bytes → medium ParseAnomaly, no transaction
    #[test]
    fn test_truncated_frame_anomaly() {
        let mut dec = GvcpDecoder::default();
        let mut out = Vec::new();
        let pkt = vec![0x42, 0x01, 0x00]; // only 3 bytes
        feed(&mut dec, &pkt, &mut out);

        assert_eq!(out.len(), 1);
        let BronzeEventFamily::ParseAnomaly(ref a) = out[0].family else {
            panic!("expected ParseAnomaly");
        };
        assert_eq!(a.severity, "medium");
    }
}
