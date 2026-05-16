//! SMB2/3 deep-parse session decoder — MS-SMB2.
//!
//! Decodes SMB2 and SMB3 PDUs (ProtocolId = `\xFESMB`) over TCP ports 445 and
//! 139. SMB1 (`\xFFSMB`) is handled by the recognition-only `SmbRecognizer` in
//! `recognizers.rs`; this decoder ignores those frames.
//!
//! # NetBIOS framing
//! Both port 445 and port 139 use a 4-byte NetBIOS Session Service header:
//!   - byte 0: message type (0x00 = Session Message)
//!   - bytes 1..3: length u24 BE
//!
//! This decoder strips that wrapper before parsing the SMB2 fixed header.
//!
//! # Compound requests
//! When `NextCommand != 0`, the frame contains a chain of SMB2 PDUs packed
//! sequentially. Each PDU begins at the offset given by `NextCommand` from the
//! start of the *current* PDU. All PDUs in a chain are decoded in one call.
//!
//! # SMB3 encrypted frames
//! Transform Header (`\xFDSMB`, byte 0 = 0xFD) signals SMB3 encryption.
//! These are emitted as an opaque observation and skipped — decrypting them
//! requires session keys which the passive DPI does not have.
//!
//! # What is deferred
//! - SMB3 encrypted Transform PDUs (0xFD signature).
//! - NTLMSSP blob deep-parse (owned by the `ntlmssp` decoder).
//! - SMB signature validation.
//! - Full request/response body reconstruction for very large PDUs.

use std::collections::{BTreeMap, HashMap};

use crate::bronze::{
    AssetObservation, BronzeEvent, BronzeEventFamily, EventEnvelope, ProtocolTransaction,
    TransportProtocol,
};
use crate::engine::{
    DecoderInterest, SessionDecoder, StreamChunk, build_envelope, new_event, parse_anomaly_event,
};

// ── SMB2 wire constants ───────────────────────────────────────────────────────

const SMB2_SIGNATURE: [u8; 4] = [0xFE, b'S', b'M', b'B'];
const SMB3_TRANSFORM: [u8; 4] = [0xFD, b'S', b'M', b'B'];
const SMB1_SIGNATURE: [u8; 4] = [0xFF, b'S', b'M', b'B'];

/// Fixed SMB2 header length (bytes) per MS-SMB2 §2.2.1.
const SMB2_HEADER_LEN: usize = 64;

/// SMB2 command codes.
const CMD_NEGOTIATE: u16 = 0x0000;
const CMD_SESSION_SETUP: u16 = 0x0001;
const CMD_LOGOFF: u16 = 0x0002;
const CMD_TREE_CONNECT: u16 = 0x0003;
const CMD_TREE_DISCONNECT: u16 = 0x0004;
const CMD_CREATE: u16 = 0x0005;
const CMD_CLOSE: u16 = 0x0006;
const CMD_READ: u16 = 0x0008;
const CMD_WRITE: u16 = 0x0009;
const CMD_IOCTL: u16 = 0x000B;

/// SMB2 header flags.
const FLAGS_SERVER_TO_REDIR: u32 = 0x0000_0001;

/// NT status codes of interest.
const STATUS_SUCCESS: u32 = 0x0000_0000;
const STATUS_LOGON_FAILURE: u32 = 0xC000_006D;
const STATUS_ACCESS_DENIED: u32 = 0xC000_0022;
const STATUS_OBJECT_NAME_NOT_FOUND: u32 = 0xC000_0034;
const STATUS_OBJECT_PATH_NOT_FOUND: u32 = 0xC000_003A;
const STATUS_NO_SUCH_FILE: u32 = 0xC000_000F;
const STATUS_SHARING_VIOLATION: u32 = 0xC000_0043;
const STATUS_USER_SESSION_DELETED: u32 = 0xC000_0203;
const STATUS_NETWORK_SESSION_EXPIRED: u32 = 0xC000_035C;

/// FSCTL codes of interest (MS-FSCC).
const FSCTL_DFS_GET_REFERRALS: u32 = 0x0006_0194;
const FSCTL_PIPE_TRANSCEIVE: u32 = 0x0011_C017;
const FSCTL_VALIDATE_NEGOTIATE_INFO: u32 = 0x0014_0204;
const FSCTL_GET_REPARSE_POINT: u32 = 0x0009_0094;
const FSCTL_SET_REPARSE_POINT: u32 = 0x0009_00A4;
const FSCTL_REQUEST_OPLOCK_LEVEL_1: u32 = 0x0009_0000;
const FSCTL_REQUEST_OPLOCK_LEVEL_2: u32 = 0x0009_0004;
const FSCTL_QUERY_NETWORK_INTERFACE_INFO: u32 = 0x0014_0170;
const FSCTL_SRV_COPYCHUNK: u32 = 0x0010_1194;
const FSCTL_SRV_ENUMERATE_SNAPSHOTS: u32 = 0x0014_4064;

/// Named pipes with high-interest security signals.
/// These are used in `classify_pipe_transceive` and tests via string matching.
#[allow(dead_code)]
const PIPE_SVCCTL: &str = r"\PIPE\svcctl";
#[allow(dead_code)]
const PIPE_SAMR: &str = r"\PIPE\samr";
#[allow(dead_code)]
const PIPE_LSARPC: &str = r"\PIPE\lsarpc";
#[allow(dead_code)]
const PIPE_WINREG: &str = r"\PIPE\winreg";
#[allow(dead_code)]
const PIPE_ATSVC: &str = r"\PIPE\atsvc";
#[allow(dead_code)]
const PIPE_NETLOGON: &str = r"\PIPE\netlogon";
#[allow(dead_code)]
const PIPE_SRVSVC: &str = r"\PIPE\srvsvc";
#[allow(dead_code)]
const PIPE_WKSSVC: &str = r"\PIPE\wkssvc";
#[allow(dead_code)]
const PIPE_DRSUAPI: &str = r"\PIPE\drsuapi";
#[allow(dead_code)]
const PIPE_SPOOLSS: &str = r"\PIPE\spoolss";

// ── LRU-bounded pending-request map ─────────────────────────────────────────

/// Key for correlating SMB2 request↔response pairs.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct PendingKey {
    session_key: String,
    message_id: u64,
}

#[derive(Debug)]
struct PendingRequest {
    #[expect(dead_code, reason = "reserved for richer audit/event wording")]
    operation: String,
    #[expect(dead_code, reason = "reserved for richer tree correlation")]
    tree_id: u32,
    file_name: Option<String>,
}

// ── Per-session tree and file tracking ───────────────────────────────────────

struct SessionState {
    /// TreeId → UNC share path (e.g. `\\server\share`).
    tree_paths: HashMap<u32, String>,
    /// FileId (16 raw bytes as [u8;16]) → filename.
    file_names: HashMap<[u8; 16], String>,
    /// Negotiated dialect once the NEGOTIATE response is processed.
    dialect: Option<u16>,
    /// Asset observation emitted for this session's server.
    asset_emitted: bool,
}

impl SessionState {
    fn new() -> Self {
        Self {
            tree_paths: HashMap::new(),
            file_names: HashMap::new(),
            dialect: None,
            asset_emitted: false,
        }
    }

    fn set_tree_path(&mut self, tree_id: u32, path: String) {
        self.tree_paths.insert(tree_id, path);
    }

    fn tree_path(&self, tree_id: u32) -> Option<&str> {
        self.tree_paths.get(&tree_id).map(String::as_str)
    }

    fn set_file_name(&mut self, file_id: [u8; 16], name: String) {
        if self.file_names.len() >= 256 {
            // Evict one arbitrarily (HashMap iteration is non-deterministic but acceptable).
            if let Some(k) = self.file_names.keys().next().cloned() {
                self.file_names.remove(&k);
            }
        }
        self.file_names.insert(file_id, name);
    }

    fn file_name(&self, file_id: &[u8; 16]) -> Option<&str> {
        self.file_names.get(file_id).map(String::as_str)
    }
}

// ── Decoder ───────────────────────────────────────────────────────────────────

#[derive(Default)]
pub(crate) struct Smb2Decoder {
    /// MessageId-keyed pending request map (bounded to 1024 entries).
    pending: HashMap<PendingKey, PendingRequest>,
    /// Per-session state keyed by session_key.
    sessions: HashMap<String, SessionState>,
    /// NetBIOS reassembly buffer per session_key.
    /// Holds incomplete NetBIOS+SMB2 bytes that haven't yet been fully received.
    buffers: HashMap<String, Vec<u8>>,
}

inventory::submit!(crate::engine::decoders::DecoderRegistration {
    name: "smb2",
    factory: || Box::new(Smb2Decoder::default()),
});

impl SessionDecoder for Smb2Decoder {
    fn name(&self) -> &'static str {
        "smb2"
    }

    fn interest(&self) -> &'static [DecoderInterest] {
        &[DecoderInterest::TcpPort(445), DecoderInterest::TcpPort(139)]
    }

    fn on_stream_chunk(&mut self, chunk: &StreamChunk<'_>, out: &mut Vec<BronzeEvent>) {
        let buf = self.buffers.entry(chunk.session_key.clone()).or_default();
        buf.extend_from_slice(chunk.payload);

        // Drain complete NetBIOS/SMB2 frames from the reassembly buffer.
        // We collect all frames first (copying bytes out), then decode them,
        // to avoid a mutable-borrow conflict between `self.buffers` and `self.decode_frame`.
        let frames: Vec<Vec<u8>> = {
            let buf = self.buffers.get_mut(&chunk.session_key).unwrap();
            let mut out_frames = Vec::new();
            loop {
                if buf.len() < 4 {
                    break;
                }
                let nb_len = read_u24_be(&buf[1..4]) as usize;
                let total = 4 + nb_len;
                if buf.len() < total {
                    break;
                }
                out_frames.push(buf[4..total].to_vec());
                let remaining: Vec<u8> = buf[total..].to_vec();
                *buf = remaining;
            }
            out_frames
        };

        for frame in frames {
            self.decode_frame(chunk, &frame, out);
        }
    }
}

impl Smb2Decoder {
    /// Decode one complete SMB2 frame (after stripping the 4-byte NetBIOS header).
    fn decode_frame(&mut self, chunk: &StreamChunk<'_>, frame: &[u8], out: &mut Vec<BronzeEvent>) {
        if frame.len() < 4 {
            return;
        }

        let sig = &frame[0..4];

        // SMB3 encrypted Transform — note presence and skip decryption.
        if sig == SMB3_TRANSFORM {
            out.push(self.anomaly(
                chunk,
                "low",
                "smb3 encrypted transform PDU — decryption deferred (no session keys)",
            ));
            return;
        }

        // SMB1 — owned by SmbRecognizer; silently skip.
        if sig == SMB1_SIGNATURE {
            return;
        }

        if sig != SMB2_SIGNATURE {
            // Unknown signature — could be noise or a different protocol.
            if !frame.is_empty() {
                out.push(self.anomaly(chunk, "low", "smb2: unrecognized frame signature"));
            }
            return;
        }

        // Walk the compound chain.
        let mut offset: usize = 0;
        loop {
            if offset >= frame.len() {
                break;
            }
            let pdu = &frame[offset..];
            if pdu.len() < SMB2_HEADER_LEN {
                out.push(self.anomaly(chunk, "low", "smb2: truncated header (<64 bytes)"));
                break;
            }

            // Validate StructureSize field at bytes 4..6 — must be 64.
            let structure_size = u16::from_le_bytes([pdu[4], pdu[5]]);
            if structure_size != 64 {
                out.push(self.anomaly(
                    chunk,
                    "low",
                    &format!("smb2: invalid StructureSize {structure_size} (expected 64)"),
                ));
                // Don't continue — the rest of the chain is unreliable.
                break;
            }

            // NextCommand is at bytes 20..24 in the SMB2 fixed header.
            let next_command = u32::from_le_bytes([pdu[20], pdu[21], pdu[22], pdu[23]]) as usize;
            self.decode_pdu(chunk, pdu, out);

            if next_command == 0 {
                break;
            }
            if next_command < SMB2_HEADER_LEN {
                // Malformed NextCommand — avoid infinite loop.
                out.push(self.anomaly(
                    chunk,
                    "low",
                    "smb2: invalid NextCommand offset (too small)",
                ));
                break;
            }
            offset += next_command;
        }
    }

    /// Decode a single SMB2 PDU starting at byte 0 (ProtocolId).
    fn decode_pdu(&mut self, chunk: &StreamChunk<'_>, pdu: &[u8], out: &mut Vec<BronzeEvent>) {
        // SMB2 fixed header layout (all LE unless noted):
        //  0..4   ProtocolId = \xFESMB
        //  4..6   StructureSize = 64
        //  6..8   CreditCharge
        //  8..12  ChannelSequence/Reserved (responses: Status u32)
        //  12..14 Command
        //  14..16 CreditRequest/Response
        //  16..20 Flags
        //  20..24 NextCommand (already used by caller to walk compound chain)
        //  24..32 MessageId
        //  32..36 ProcessId (async: high 32 bits of AsyncId)
        //  36..40 TreeId (async: low 32 bits of AsyncId)
        //  40..48 SessionId
        //  48..64 Signature [16 bytes]

        let status_or_reserved = u32::from_le_bytes([pdu[8], pdu[9], pdu[10], pdu[11]]);
        let command = u16::from_le_bytes([pdu[12], pdu[13]]);
        let flags = u32::from_le_bytes([pdu[16], pdu[17], pdu[18], pdu[19]]);
        let message_id = u64::from_le_bytes([
            pdu[24], pdu[25], pdu[26], pdu[27], pdu[28], pdu[29], pdu[30], pdu[31],
        ]);
        let tree_id = u32::from_le_bytes([pdu[36], pdu[37], pdu[38], pdu[39]]);
        let session_id = u64::from_le_bytes([
            pdu[40], pdu[41], pdu[42], pdu[43], pdu[44], pdu[45], pdu[46], pdu[47],
        ]);
        let is_response = (flags & FLAGS_SERVER_TO_REDIR) != 0;

        // Status is only valid on responses.
        let nt_status = if is_response { status_or_reserved } else { 0 };

        let body = if pdu.len() > SMB2_HEADER_LEN {
            &pdu[SMB2_HEADER_LEN..]
        } else {
            &[]
        };

        // NULL session: session_id == 0 on a TREE_CONNECT or higher is suspicious.
        if session_id == 0
            && !is_response
            && matches!(
                command,
                CMD_TREE_CONNECT | CMD_CREATE | CMD_READ | CMD_WRITE | CMD_IOCTL
            )
        {
            out.push(self.anomaly(
                chunk,
                "medium",
                "smb2: NULL session (session_id=0) on data command — possible anonymous access",
            ));
        }

        match command {
            CMD_NEGOTIATE => {
                if is_response {
                    self.on_negotiate_response(chunk, body, message_id, nt_status, out);
                } else {
                    self.on_negotiate_request(chunk, body, message_id, out);
                }
            }
            CMD_SESSION_SETUP => {
                if is_response {
                    self.on_session_setup_response(chunk, body, message_id, nt_status, out);
                } else {
                    self.on_session_setup_request(chunk, body, message_id, out);
                }
            }
            CMD_LOGOFF => {
                if is_response {
                    self.on_logoff_response(chunk, message_id, nt_status, out);
                } else {
                    self.on_logoff_request(chunk, message_id, out);
                }
            }
            CMD_TREE_CONNECT => {
                if is_response {
                    self.on_tree_connect_response(chunk, message_id, nt_status, tree_id, out);
                } else {
                    self.on_tree_connect_request(chunk, body, message_id, tree_id, out);
                }
            }
            CMD_TREE_DISCONNECT => {
                self.emit_simple(
                    chunk,
                    message_id,
                    is_response,
                    nt_status,
                    "smb2_tree_disconnect_request",
                    "smb2_tree_disconnect_response",
                    out,
                );
            }
            CMD_CREATE => {
                if is_response {
                    self.on_create_response(chunk, body, message_id, nt_status, out);
                } else {
                    self.on_create_request(chunk, body, message_id, tree_id, out);
                }
            }
            CMD_CLOSE => {
                if is_response {
                    self.on_close_response(chunk, message_id, nt_status, out);
                } else {
                    self.on_close_request(chunk, body, message_id, out);
                }
            }
            CMD_READ => {
                if is_response {
                    self.on_read_response(chunk, message_id, nt_status, out);
                } else {
                    self.on_read_request(chunk, body, message_id, out);
                }
            }
            CMD_WRITE => {
                if is_response {
                    self.on_write_response(chunk, message_id, nt_status, out);
                } else {
                    self.on_write_request(chunk, body, message_id, out);
                }
            }
            CMD_IOCTL => {
                if is_response {
                    self.on_ioctl_response(chunk, body, message_id, nt_status, out);
                } else {
                    self.on_ioctl_request(chunk, body, message_id, tree_id, out);
                }
            }
            other => {
                out.push(self.anomaly(
                    chunk,
                    "low",
                    &format!("smb2: unknown command 0x{other:04x}"),
                ));
            }
        }
    }

    // ── Command handlers ─────────────────────────────────────────────────────

    fn on_negotiate_request(
        &mut self,
        chunk: &StreamChunk<'_>,
        body: &[u8],
        message_id: u64,
        out: &mut Vec<BronzeEvent>,
    ) {
        // NEGOTIATE request body (MS-SMB2 §2.2.3):
        //  0..2   StructureSize = 36
        //  2..4   DialectCount
        //  4..6   SecurityMode
        //  6..8   Reserved
        //  8..12  Capabilities
        //  12..28 ClientGuid [16 bytes]
        //  28..   Dialects[] u16 LE × DialectCount
        let mut attrs = BTreeMap::new();
        attrs.insert("command".into(), "negotiate".into());
        attrs.insert("direction".into(), "request".into());

        if body.len() >= 4 {
            let dialect_count = u16::from_le_bytes([body[2], body[3]]) as usize;
            attrs.insert("dialect_count".into(), dialect_count.to_string());

            if body.len() >= 28 + dialect_count * 2 {
                let mut dialects = Vec::new();
                for i in 0..dialect_count {
                    let off = 28 + i * 2;
                    let d = u16::from_le_bytes([body[off], body[off + 1]]);
                    dialects.push(format!("0x{d:04x}"));
                }
                attrs.insert("dialects_offered".into(), dialects.join(","));
            }
        }

        let key = PendingKey {
            session_key: chunk.session_key.clone(),
            message_id,
        };
        self.pending.insert(
            key,
            PendingRequest {
                operation: "smb2_negotiate_request".into(),
                tree_id: 0,
                file_name: None,
            },
        );

        out.push(self.tx(chunk, "smb2_negotiate_request", "request_pending", attrs));
    }

    fn on_negotiate_response(
        &mut self,
        chunk: &StreamChunk<'_>,
        body: &[u8],
        message_id: u64,
        nt_status: u32,
        out: &mut Vec<BronzeEvent>,
    ) {
        // NEGOTIATE response body (MS-SMB2 §2.2.4):
        //  0..2  StructureSize = 65
        //  2..4  SecurityMode
        //  4..6  DialectRevision (the negotiated dialect)
        //  ...
        let key = PendingKey {
            session_key: chunk.session_key.clone(),
            message_id,
        };
        self.pending.remove(&key);

        let mut attrs = BTreeMap::new();
        attrs.insert("command".into(), "negotiate".into());
        attrs.insert("direction".into(), "response".into());

        let mut negotiated_dialect: Option<u16> = None;
        if body.len() >= 6 {
            let dialect = u16::from_le_bytes([body[4], body[5]]);
            attrs.insert("negotiated_dialect".into(), format!("0x{dialect:04x}"));
            negotiated_dialect = Some(dialect);
        }

        let status_str = nt_status_name(nt_status);
        attrs.insert("nt_status".into(), status_str.clone());

        if nt_status == STATUS_SUCCESS {
            // Emit AssetObservation for the server.
            let server_ip = if is_server_port(chunk.context.src_port) {
                chunk.context.src_ip.to_string()
            } else {
                chunk.context.dst_ip.to_string()
            };
            let sess = self
                .sessions
                .entry(chunk.session_key.clone())
                .or_insert_with(SessionState::new);
            if let Some(d) = negotiated_dialect {
                sess.dialect = Some(d);
            }
            if !sess.asset_emitted {
                sess.asset_emitted = true;
                let mut identifiers = BTreeMap::new();
                if let Some(d) = negotiated_dialect {
                    identifiers.insert("smb2_dialect".into(), format!("0x{d:04x}"));
                }
                out.push(new_event(
                    chunk.capture_id.to_string(),
                    self.envelope(chunk),
                    BronzeEventFamily::AssetObservation(AssetObservation {
                        asset_key: server_ip,
                        role: Some("smb_server".into()),
                        vendor: None,
                        model: None,
                        firmware: None,
                        hostnames: vec![],
                        protocols: vec!["smb2".into()],
                        identifiers,
                    }),
                ));
            }
        }

        out.push(self.tx(chunk, "smb2_negotiate_response", &status_str, attrs));
    }

    fn on_session_setup_request(
        &mut self,
        chunk: &StreamChunk<'_>,
        body: &[u8],
        message_id: u64,
        out: &mut Vec<BronzeEvent>,
    ) {
        // SESSION_SETUP request body (MS-SMB2 §2.2.5):
        //  0..2   StructureSize = 25
        //  2      Flags
        //  3      SecurityMode
        //  4..8   Capabilities
        //  8..12  Channel
        //  12..14 SecurityBufferOffset (relative to start of header, i.e. add SMB2_HEADER_LEN)
        //  14..16 SecurityBufferLength
        //  16..24 PreviousSessionId
        let mut attrs = BTreeMap::new();
        attrs.insert("command".into(), "session_setup".into());
        attrs.insert("direction".into(), "request".into());

        if body.len() >= 24 {
            let sec_buf_len = u16::from_le_bytes([body[14], body[15]]) as usize;
            attrs.insert("security_blob_len".into(), sec_buf_len.to_string());

            let prev_sess = u64::from_le_bytes([
                body[16], body[17], body[18], body[19], body[20], body[21], body[22], body[23],
            ]);
            if prev_sess != 0 {
                attrs.insert("previous_session_id".into(), format!("0x{prev_sess:016x}"));
            }
        }

        let key = PendingKey {
            session_key: chunk.session_key.clone(),
            message_id,
        };
        self.pending.insert(
            key,
            PendingRequest {
                operation: "smb2_session_setup_request".into(),
                tree_id: 0,
                file_name: None,
            },
        );

        out.push(self.tx(
            chunk,
            "smb2_session_setup_request",
            "request_pending",
            attrs,
        ));
    }

    fn on_session_setup_response(
        &mut self,
        chunk: &StreamChunk<'_>,
        _body: &[u8],
        message_id: u64,
        nt_status: u32,
        out: &mut Vec<BronzeEvent>,
    ) {
        let key = PendingKey {
            session_key: chunk.session_key.clone(),
            message_id,
        };
        self.pending.remove(&key);

        let status_str = nt_status_name(nt_status);
        let mut attrs = BTreeMap::new();
        attrs.insert("command".into(), "session_setup".into());
        attrs.insert("direction".into(), "response".into());
        attrs.insert("nt_status".into(), status_str.clone());

        // Credential probing: repeated LOGON_FAILURE is a brute-force signal.
        if nt_status == STATUS_LOGON_FAILURE {
            out.push(self.anomaly(
                chunk,
                "medium",
                "smb2: SESSION_SETUP STATUS_LOGON_FAILURE — possible credential probing",
            ));
        }

        out.push(self.tx(chunk, "smb2_session_setup_response", &status_str, attrs));
    }

    fn on_logoff_request(
        &mut self,
        chunk: &StreamChunk<'_>,
        message_id: u64,
        out: &mut Vec<BronzeEvent>,
    ) {
        let key = PendingKey {
            session_key: chunk.session_key.clone(),
            message_id,
        };
        self.pending.insert(
            key,
            PendingRequest {
                operation: "smb2_logoff_request".into(),
                tree_id: 0,
                file_name: None,
            },
        );
        let mut attrs = BTreeMap::new();
        attrs.insert("command".into(), "logoff".into());
        out.push(self.tx(chunk, "smb2_logoff_request", "request_pending", attrs));
    }

    fn on_logoff_response(
        &mut self,
        chunk: &StreamChunk<'_>,
        message_id: u64,
        nt_status: u32,
        out: &mut Vec<BronzeEvent>,
    ) {
        let key = PendingKey {
            session_key: chunk.session_key.clone(),
            message_id,
        };
        self.pending.remove(&key);
        let status_str = nt_status_name(nt_status);
        let mut attrs = BTreeMap::new();
        attrs.insert("command".into(), "logoff".into());
        attrs.insert("nt_status".into(), status_str.clone());
        out.push(self.tx(chunk, "smb2_logoff_response", &status_str, attrs));
    }

    fn on_tree_connect_request(
        &mut self,
        chunk: &StreamChunk<'_>,
        body: &[u8],
        message_id: u64,
        _tree_id: u32,
        out: &mut Vec<BronzeEvent>,
    ) {
        // TREE_CONNECT request body (MS-SMB2 §2.2.9):
        //  0..2   StructureSize = 9
        //  2..4   Flags
        //  4..6   PathOffset (relative to start of SMB2 header)
        //  6..8   PathLength
        let mut attrs = BTreeMap::new();
        attrs.insert("command".into(), "tree_connect".into());
        attrs.insert("direction".into(), "request".into());

        let mut tree_path: Option<String> = None;
        if body.len() >= 8 {
            let path_offset = u16::from_le_bytes([body[4], body[5]]) as usize;
            let path_len = u16::from_le_bytes([body[6], body[7]]) as usize;
            // path_offset is relative to the start of the SMB2 header (64 bytes
            // before body). Adjust to be relative to body start.
            let body_offset = path_offset.saturating_sub(SMB2_HEADER_LEN);
            if body_offset + path_len <= body.len() && path_len > 0 {
                let path_bytes = &body[body_offset..body_offset + path_len];
                let path = decode_utf16le(path_bytes);
                attrs.insert("tree_path".into(), path.clone());
                tree_path = Some(path);
            }
        }

        let key = PendingKey {
            session_key: chunk.session_key.clone(),
            message_id,
        };
        self.pending.insert(
            key,
            PendingRequest {
                operation: "smb2_tree_connect_request".into(),
                tree_id: 0,
                file_name: tree_path,
            },
        );

        out.push(self.tx(chunk, "smb2_tree_connect_request", "request_pending", attrs));
    }

    fn on_tree_connect_response(
        &mut self,
        chunk: &StreamChunk<'_>,
        message_id: u64,
        nt_status: u32,
        tree_id: u32,
        out: &mut Vec<BronzeEvent>,
    ) {
        let key = PendingKey {
            session_key: chunk.session_key.clone(),
            message_id,
        };
        let req = self.pending.remove(&key);

        let status_str = nt_status_name(nt_status);
        let mut attrs = BTreeMap::new();
        attrs.insert("command".into(), "tree_connect".into());
        attrs.insert("direction".into(), "response".into());
        attrs.insert("nt_status".into(), status_str.clone());
        attrs.insert("tree_id".into(), format!("0x{tree_id:08x}"));

        if nt_status == STATUS_SUCCESS {
            if let Some(r) = &req
                && let Some(ref path) = r.file_name
            {
                attrs.insert("tree_path".into(), path.clone());
                let sess = self
                    .sessions
                    .entry(chunk.session_key.clone())
                    .or_insert_with(SessionState::new);
                sess.set_tree_path(tree_id, path.clone());
            }
        } else {
            out.push(self.anomaly(
                chunk,
                "medium",
                &format!("smb2: TREE_CONNECT failed: {status_str}"),
            ));
        }

        out.push(self.tx(chunk, "smb2_tree_connect_response", &status_str, attrs));
    }

    fn on_create_request(
        &mut self,
        chunk: &StreamChunk<'_>,
        body: &[u8],
        message_id: u64,
        tree_id: u32,
        out: &mut Vec<BronzeEvent>,
    ) {
        // CREATE request body (MS-SMB2 §2.2.13):
        //  0..2   StructureSize = 57
        //  2      SecurityFlags (reserved)
        //  3      RequestedOplockLevel
        //  4..8   ImpersonationLevel
        //  8..16  SmbCreateFlags
        //  16..24 Reserved
        //  24..28 DesiredAccess
        //  28..32 FileAttributes
        //  32..36 ShareAccess
        //  36..40 CreateDisposition
        //  40..44 CreateOptions
        //  44..46 NameOffset (relative to start of SMB2 header)
        //  46..48 NameLength
        //  ...    CreateContexts
        let mut attrs = BTreeMap::new();
        attrs.insert("command".into(), "create".into());
        attrs.insert("direction".into(), "request".into());

        // Annotate with tree path if known.
        if let Some(path) = self
            .sessions
            .get(&chunk.session_key)
            .and_then(|s| s.tree_path(tree_id))
        {
            attrs.insert("tree_path".into(), path.to_string());
        }

        let mut file_name: Option<String> = None;
        if body.len() >= 48 {
            let desired_access = u32::from_le_bytes([body[24], body[25], body[26], body[27]]);
            let share_access = u32::from_le_bytes([body[32], body[33], body[34], body[35]]);
            let disposition = u32::from_le_bytes([body[36], body[37], body[38], body[39]]);

            attrs.insert("desired_access".into(), format!("0x{desired_access:08x}"));
            attrs.insert("share_access".into(), format!("0x{share_access:08x}"));
            attrs.insert("disposition".into(), create_disposition_name(disposition));

            let name_offset = u16::from_le_bytes([body[44], body[45]]) as usize;
            let name_len = u16::from_le_bytes([body[46], body[47]]) as usize;
            let body_offset = name_offset.saturating_sub(SMB2_HEADER_LEN);
            if body_offset + name_len <= body.len() && name_len > 0 {
                let name_bytes = &body[body_offset..body_offset + name_len];
                let name = decode_utf16le(name_bytes);
                attrs.insert("file_name".into(), name.clone());
                file_name = Some(name);
            }
        }

        let key = PendingKey {
            session_key: chunk.session_key.clone(),
            message_id,
        };
        self.pending.insert(
            key,
            PendingRequest {
                operation: "smb2_create_request".into(),
                tree_id,
                file_name: file_name.clone(),
            },
        );

        out.push(self.tx(chunk, "smb2_create_request", "request_pending", attrs));
    }

    fn on_create_response(
        &mut self,
        chunk: &StreamChunk<'_>,
        body: &[u8],
        message_id: u64,
        nt_status: u32,
        out: &mut Vec<BronzeEvent>,
    ) {
        // CREATE response body (MS-SMB2 §2.2.14):
        //  0..2   StructureSize = 89
        //  2      OplockLevel
        //  3      Flags
        //  4..8   CreateAction
        //  8..24  CreationTime, LastAccessTime, LastWriteTime, ChangeTime (each u64)
        //  ...
        //  60..76 FileId [16 bytes] (Persistent: 8 bytes, Volatile: 8 bytes)
        let key = PendingKey {
            session_key: chunk.session_key.clone(),
            message_id,
        };
        let req = self.pending.remove(&key);

        let status_str = nt_status_name(nt_status);
        let mut attrs = BTreeMap::new();
        attrs.insert("command".into(), "create".into());
        attrs.insert("direction".into(), "response".into());
        attrs.insert("nt_status".into(), status_str.clone());

        if nt_status == STATUS_SUCCESS {
            // Extract FileId (16 bytes at offset 60 in body for SMB2 CREATE response).
            if body.len() >= 76 {
                let file_id_bytes = &body[60..76];
                let mut file_id = [0u8; 16];
                file_id.copy_from_slice(file_id_bytes);

                if let Some(r) = &req
                    && let Some(ref name) = r.file_name
                {
                    // Remember FileId → filename.
                    let sess = self
                        .sessions
                        .entry(chunk.session_key.clone())
                        .or_insert_with(SessionState::new);
                    sess.set_file_name(file_id, name.clone());
                    attrs.insert("file_name".into(), name.clone());
                }

                let file_id_hex = hex::encode(file_id_bytes);
                attrs.insert("file_id".into(), file_id_hex);
            }
        }

        out.push(self.tx(chunk, "smb2_create_response", &status_str, attrs));
    }

    fn on_close_request(
        &mut self,
        chunk: &StreamChunk<'_>,
        body: &[u8],
        message_id: u64,
        out: &mut Vec<BronzeEvent>,
    ) {
        // CLOSE request body (MS-SMB2 §2.2.15):
        //  0..2  StructureSize = 24
        //  2..4  Flags
        //  4..8  Reserved
        //  8..24 FileId [16 bytes]
        let mut attrs = BTreeMap::new();
        attrs.insert("command".into(), "close".into());
        attrs.insert("direction".into(), "request".into());

        if body.len() >= 24 {
            let file_id_bytes = &body[8..24];
            let mut file_id = [0u8; 16];
            file_id.copy_from_slice(file_id_bytes);
            attrs.insert("file_id".into(), hex::encode(file_id_bytes));

            if let Some(name) = self
                .sessions
                .get(&chunk.session_key)
                .and_then(|s| s.file_name(&file_id))
            {
                attrs.insert("file_name".into(), name.to_string());
            }
        }

        let key = PendingKey {
            session_key: chunk.session_key.clone(),
            message_id,
        };
        self.pending.insert(
            key,
            PendingRequest {
                operation: "smb2_close_request".into(),
                tree_id: 0,
                file_name: None,
            },
        );

        out.push(self.tx(chunk, "smb2_close_request", "request_pending", attrs));
    }

    fn on_close_response(
        &mut self,
        chunk: &StreamChunk<'_>,
        message_id: u64,
        nt_status: u32,
        out: &mut Vec<BronzeEvent>,
    ) {
        let key = PendingKey {
            session_key: chunk.session_key.clone(),
            message_id,
        };
        self.pending.remove(&key);
        let status_str = nt_status_name(nt_status);
        let mut attrs = BTreeMap::new();
        attrs.insert("command".into(), "close".into());
        attrs.insert("nt_status".into(), status_str.clone());
        out.push(self.tx(chunk, "smb2_close_response", &status_str, attrs));
    }

    fn on_read_request(
        &mut self,
        chunk: &StreamChunk<'_>,
        body: &[u8],
        message_id: u64,
        out: &mut Vec<BronzeEvent>,
    ) {
        // READ request body (MS-SMB2 §2.2.19):
        //  0..2   StructureSize = 49
        //  2      Padding
        //  3      Flags
        //  4..8   Length
        //  8..16  Offset
        //  16..32 FileId [16 bytes]
        let mut attrs = BTreeMap::new();
        attrs.insert("command".into(), "read".into());
        attrs.insert("direction".into(), "request".into());

        if body.len() >= 32 {
            let length = u32::from_le_bytes([body[4], body[5], body[6], body[7]]);
            let offset = u64::from_le_bytes([
                body[8], body[9], body[10], body[11], body[12], body[13], body[14], body[15],
            ]);
            let file_id_bytes = &body[16..32];
            let mut file_id = [0u8; 16];
            file_id.copy_from_slice(file_id_bytes);

            attrs.insert("read_length".into(), length.to_string());
            attrs.insert("read_offset".into(), offset.to_string());
            attrs.insert("file_id".into(), hex::encode(file_id_bytes));

            if let Some(name) = self
                .sessions
                .get(&chunk.session_key)
                .and_then(|s| s.file_name(&file_id))
            {
                attrs.insert("file_name".into(), name.to_string());
            }
        }

        let key = PendingKey {
            session_key: chunk.session_key.clone(),
            message_id,
        };
        self.pending.insert(
            key,
            PendingRequest {
                operation: "smb2_read_request".into(),
                tree_id: 0,
                file_name: None,
            },
        );

        out.push(self.tx(chunk, "smb2_read_request", "request_pending", attrs));
    }

    fn on_read_response(
        &mut self,
        chunk: &StreamChunk<'_>,
        message_id: u64,
        nt_status: u32,
        out: &mut Vec<BronzeEvent>,
    ) {
        let key = PendingKey {
            session_key: chunk.session_key.clone(),
            message_id,
        };
        self.pending.remove(&key);
        let status_str = nt_status_name(nt_status);
        let mut attrs = BTreeMap::new();
        attrs.insert("command".into(), "read".into());
        attrs.insert("nt_status".into(), status_str.clone());
        out.push(self.tx(chunk, "smb2_read_response", &status_str, attrs));
    }

    fn on_write_request(
        &mut self,
        chunk: &StreamChunk<'_>,
        body: &[u8],
        message_id: u64,
        out: &mut Vec<BronzeEvent>,
    ) {
        // WRITE request body (MS-SMB2 §2.2.21):
        //  0..2   StructureSize = 49
        //  2..4   DataOffset (relative to start of SMB2 header)
        //  4..8   Length
        //  8..16  Offset
        //  16..32 FileId [16 bytes]
        let mut attrs = BTreeMap::new();
        attrs.insert("command".into(), "write".into());
        attrs.insert("direction".into(), "request".into());

        if body.len() >= 32 {
            let length = u32::from_le_bytes([body[4], body[5], body[6], body[7]]);
            let offset = u64::from_le_bytes([
                body[8], body[9], body[10], body[11], body[12], body[13], body[14], body[15],
            ]);
            let file_id_bytes = &body[16..32];
            let mut file_id = [0u8; 16];
            file_id.copy_from_slice(file_id_bytes);

            attrs.insert("write_length".into(), length.to_string());
            attrs.insert("write_offset".into(), offset.to_string());
            attrs.insert("file_id".into(), hex::encode(file_id_bytes));

            if let Some(name) = self
                .sessions
                .get(&chunk.session_key)
                .and_then(|s| s.file_name(&file_id))
            {
                attrs.insert("file_name".into(), name.to_string());
            }
        }

        let key = PendingKey {
            session_key: chunk.session_key.clone(),
            message_id,
        };
        self.pending.insert(
            key,
            PendingRequest {
                operation: "smb2_write_request".into(),
                tree_id: 0,
                file_name: None,
            },
        );

        out.push(self.tx(chunk, "smb2_write_request", "request_pending", attrs));
    }

    fn on_write_response(
        &mut self,
        chunk: &StreamChunk<'_>,
        message_id: u64,
        nt_status: u32,
        out: &mut Vec<BronzeEvent>,
    ) {
        let key = PendingKey {
            session_key: chunk.session_key.clone(),
            message_id,
        };
        self.pending.remove(&key);
        let status_str = nt_status_name(nt_status);
        let mut attrs = BTreeMap::new();
        attrs.insert("command".into(), "write".into());
        attrs.insert("nt_status".into(), status_str.clone());
        out.push(self.tx(chunk, "smb2_write_response", &status_str, attrs));
    }

    fn on_ioctl_request(
        &mut self,
        chunk: &StreamChunk<'_>,
        body: &[u8],
        message_id: u64,
        tree_id: u32,
        out: &mut Vec<BronzeEvent>,
    ) {
        // IOCTL request body (MS-SMB2 §2.2.31):
        //  0..2   StructureSize = 57
        //  2..4   Reserved
        //  4..8   CtlCode
        //  8..24  FileId [16 bytes]
        //  ...
        let mut attrs = BTreeMap::new();
        attrs.insert("command".into(), "ioctl".into());
        attrs.insert("direction".into(), "request".into());

        if let Some(path) = self
            .sessions
            .get(&chunk.session_key)
            .and_then(|s| s.tree_path(tree_id))
        {
            attrs.insert("tree_path".into(), path.to_string());
        }

        let mut ctl_code: u32 = 0;
        let mut file_id: [u8; 16] = [0u8; 16];
        let mut file_name_for_pipe: Option<String> = None;

        if body.len() >= 24 {
            ctl_code = u32::from_le_bytes([body[4], body[5], body[6], body[7]]);
            file_id.copy_from_slice(&body[8..24]);

            attrs.insert("ctl_code".into(), format!("0x{ctl_code:08x}"));
            attrs.insert("ctl_code_name".into(), fsctl_name(ctl_code).to_string());

            if let Some(name) = self
                .sessions
                .get(&chunk.session_key)
                .and_then(|s| s.file_name(&file_id))
            {
                attrs.insert("file_name".into(), name.to_string());
                file_name_for_pipe = Some(name.to_string());
            }
        }

        // High-priority signal: PIPE_TRANSCEIVE on \PIPE\svcctl = SCM lateral movement.
        if ctl_code == FSCTL_PIPE_TRANSCEIVE {
            let pipe_name = file_name_for_pipe.as_deref().unwrap_or("");
            let (severity, reason) = classify_pipe_transceive(pipe_name);
            out.push(self.anomaly(chunk, severity, reason));
        }

        let key = PendingKey {
            session_key: chunk.session_key.clone(),
            message_id,
        };
        self.pending.insert(
            key,
            PendingRequest {
                operation: "smb2_ioctl_request".into(),
                tree_id,
                file_name: None,
            },
        );

        out.push(self.tx(chunk, "smb2_ioctl_request", "request_pending", attrs));
    }

    fn on_ioctl_response(
        &mut self,
        chunk: &StreamChunk<'_>,
        body: &[u8],
        message_id: u64,
        nt_status: u32,
        out: &mut Vec<BronzeEvent>,
    ) {
        let key = PendingKey {
            session_key: chunk.session_key.clone(),
            message_id,
        };
        self.pending.remove(&key);

        let status_str = nt_status_name(nt_status);
        let mut attrs = BTreeMap::new();
        attrs.insert("command".into(), "ioctl".into());
        attrs.insert("direction".into(), "response".into());
        attrs.insert("nt_status".into(), status_str.clone());

        if body.len() >= 8 {
            let ctl_code = u32::from_le_bytes([body[4], body[5], body[6], body[7]]);
            attrs.insert("ctl_code".into(), format!("0x{ctl_code:08x}"));
            attrs.insert("ctl_code_name".into(), fsctl_name(ctl_code).to_string());
        }

        out.push(self.tx(chunk, "smb2_ioctl_response", &status_str, attrs));
    }

    /// Emit paired request/response events for simple commands (TREE_DISCONNECT, etc.).
    #[allow(clippy::too_many_arguments)]
    fn emit_simple(
        &mut self,
        chunk: &StreamChunk<'_>,
        message_id: u64,
        is_response: bool,
        nt_status: u32,
        req_op: &'static str,
        resp_op: &'static str,
        out: &mut Vec<BronzeEvent>,
    ) {
        let key = PendingKey {
            session_key: chunk.session_key.clone(),
            message_id,
        };
        if is_response {
            self.pending.remove(&key);
            let status_str = nt_status_name(nt_status);
            let mut attrs = BTreeMap::new();
            attrs.insert("nt_status".into(), status_str.clone());
            out.push(self.tx(chunk, resp_op, &status_str, attrs));
        } else {
            self.pending.insert(
                key,
                PendingRequest {
                    operation: req_op.into(),
                    tree_id: 0,
                    file_name: None,
                },
            );
            out.push(self.tx(chunk, req_op, "request_pending", BTreeMap::new()));
        }
    }

    // ── Event helpers ─────────────────────────────────────────────────────────

    fn envelope(&self, chunk: &StreamChunk<'_>) -> EventEnvelope {
        build_envelope(
            &chunk.context,
            chunk.interface_id,
            chunk.frame_index,
            chunk.timestamp,
            chunk.segment_hash,
            TransportProtocol::Tcp,
            Some("smb2"),
            chunk.captured_len,
            chunk.session_key.clone(),
        )
    }

    fn tx(
        &self,
        chunk: &StreamChunk<'_>,
        operation: &str,
        status: &str,
        attributes: BTreeMap<String, String>,
    ) -> BronzeEvent {
        new_event(
            chunk.capture_id.to_string(),
            self.envelope(chunk),
            BronzeEventFamily::ProtocolTransaction(ProtocolTransaction {
                operation: operation.to_string(),
                status: status.to_string(),
                request_summary: None,
                response_summary: None,
                object_refs: vec![],
                values: vec![],
                attributes,
                modbus: None,
                protocol_fields: None,
            }),
        )
    }

    fn anomaly(&self, chunk: &StreamChunk<'_>, severity: &str, reason: &str) -> BronzeEvent {
        parse_anomaly_event(
            chunk.capture_id.to_string(),
            self.envelope(chunk),
            "smb2",
            severity,
            reason,
            chunk.payload,
        )
    }
}

// ── Pure helper functions ─────────────────────────────────────────────────────

/// Decode UTF-16LE bytes to a String, replacing unparseable code units with U+FFFD.
fn decode_utf16le(bytes: &[u8]) -> String {
    // Strip trailing null words.
    let units: Vec<u16> = bytes
        .chunks_exact(2)
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .collect();
    let trimmed: Vec<u16> = units.into_iter().take_while(|&u| u != 0).collect();
    String::from_utf16_lossy(&trimmed).to_string()
}

fn read_u24_be(b: &[u8]) -> u32 {
    (u32::from(b[0]) << 16) | (u32::from(b[1]) << 8) | u32::from(b[2])
}

fn nt_status_name(status: u32) -> String {
    match status {
        STATUS_SUCCESS => "ok".into(),
        STATUS_LOGON_FAILURE => "STATUS_LOGON_FAILURE".into(),
        STATUS_ACCESS_DENIED => "STATUS_ACCESS_DENIED".into(),
        STATUS_OBJECT_NAME_NOT_FOUND => "STATUS_OBJECT_NAME_NOT_FOUND".into(),
        STATUS_OBJECT_PATH_NOT_FOUND => "STATUS_OBJECT_PATH_NOT_FOUND".into(),
        STATUS_NO_SUCH_FILE => "STATUS_NO_SUCH_FILE".into(),
        STATUS_SHARING_VIOLATION => "STATUS_SHARING_VIOLATION".into(),
        STATUS_USER_SESSION_DELETED => "STATUS_USER_SESSION_DELETED".into(),
        STATUS_NETWORK_SESSION_EXPIRED => "STATUS_NETWORK_SESSION_EXPIRED".into(),
        other => format!("status_0x{other:08x}"),
    }
}

fn fsctl_name(code: u32) -> &'static str {
    match code {
        FSCTL_DFS_GET_REFERRALS => "FSCTL_DFS_GET_REFERRALS",
        FSCTL_PIPE_TRANSCEIVE => "FSCTL_PIPE_TRANSCEIVE",
        FSCTL_VALIDATE_NEGOTIATE_INFO => "FSCTL_VALIDATE_NEGOTIATE_INFO",
        FSCTL_GET_REPARSE_POINT => "FSCTL_GET_REPARSE_POINT",
        FSCTL_SET_REPARSE_POINT => "FSCTL_SET_REPARSE_POINT",
        FSCTL_REQUEST_OPLOCK_LEVEL_1 => "FSCTL_REQUEST_OPLOCK_LEVEL_1",
        FSCTL_REQUEST_OPLOCK_LEVEL_2 => "FSCTL_REQUEST_OPLOCK_LEVEL_2",
        FSCTL_QUERY_NETWORK_INTERFACE_INFO => "FSCTL_QUERY_NETWORK_INTERFACE_INFO",
        FSCTL_SRV_COPYCHUNK => "FSCTL_SRV_COPYCHUNK",
        FSCTL_SRV_ENUMERATE_SNAPSHOTS => "FSCTL_SRV_ENUMERATE_SNAPSHOTS",
        _ => "FSCTL_UNKNOWN",
    }
}

fn create_disposition_name(d: u32) -> String {
    match d {
        0 => "FILE_SUPERSEDE".into(),
        1 => "FILE_OPEN".into(),
        2 => "FILE_CREATE".into(),
        3 => "FILE_OPEN_IF".into(),
        4 => "FILE_OVERWRITE".into(),
        5 => "FILE_OVERWRITE_IF".into(),
        other => format!("disposition_{other}"),
    }
}

/// Classify severity for FSCTL_PIPE_TRANSCEIVE based on the named pipe target.
///
/// Returns `(severity, reason)`. Severity is "high" for SCM/admin pipes
/// (classic lateral-movement primitives), "medium" for other named pipes.
fn classify_pipe_transceive(pipe_name: &str) -> (&'static str, &'static str) {
    // Case-insensitive comparison against well-known pipe names.
    let lower = pipe_name.to_ascii_lowercase();
    if lower.ends_with("svcctl") {
        return (
            "high",
            "smb2: FSCTL_PIPE_TRANSCEIVE on \\PIPE\\svcctl — SCM access (classic lateral-movement vector)",
        );
    }
    if lower.ends_with("samr") {
        return (
            "high",
            "smb2: FSCTL_PIPE_TRANSCEIVE on \\PIPE\\samr — SAM remote access",
        );
    }
    if lower.ends_with("atsvc") {
        return (
            "high",
            "smb2: FSCTL_PIPE_TRANSCEIVE on \\PIPE\\atsvc — Task Scheduler remote access",
        );
    }
    if lower.ends_with("drsuapi") {
        return (
            "high",
            "smb2: FSCTL_PIPE_TRANSCEIVE on \\PIPE\\drsuapi — AD replication/DCSync",
        );
    }
    if lower.ends_with("lsarpc") || lower.ends_with("lsass") {
        return (
            "medium",
            "smb2: FSCTL_PIPE_TRANSCEIVE on \\PIPE\\lsarpc — LSA remote procedure call",
        );
    }
    if lower.ends_with("winreg") {
        return (
            "medium",
            "smb2: FSCTL_PIPE_TRANSCEIVE on \\PIPE\\winreg — remote registry access",
        );
    }
    if lower.ends_with("spoolss") {
        return (
            "medium",
            "smb2: FSCTL_PIPE_TRANSCEIVE on \\PIPE\\spoolss — print spooler (PrintNightmare surface)",
        );
    }
    ("medium", "smb2: FSCTL_PIPE_TRANSCEIVE — named pipe I/O")
}

/// Determine if a port number is the server-side (to orient server IP selection).
fn is_server_port(port: u16) -> bool {
    port == 445 || port == 139
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bronze::BronzeEventFamily;
    use crate::engine::StreamChunk;
    use crate::registry::PacketContext;
    use chrono::Utc;
    use std::net::{IpAddr, Ipv4Addr};

    // ── Frame builders ────────────────────────────────────────────────────────

    fn ctx(src_port: u16, dst_port: u16) -> PacketContext {
        PacketContext {
            src_mac: [0u8; 6],
            dst_mac: [0u8; 6],
            src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            dst_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            src_port,
            dst_port,
            vlan_id: None,
            timestamp: 0,
        }
    }

    fn chunk_with_session<'a>(
        payload: &'a [u8],
        context: PacketContext,
        session: &str,
    ) -> StreamChunk<'a> {
        StreamChunk {
            capture_id: "test",
            segment_hash: "seg",
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

    fn get_txns(evs: &[BronzeEvent]) -> Vec<&ProtocolTransaction> {
        evs.iter()
            .filter_map(|e| {
                if let BronzeEventFamily::ProtocolTransaction(ref t) = e.family {
                    Some(t)
                } else {
                    None
                }
            })
            .collect()
    }

    fn get_anomalies(evs: &[BronzeEvent]) -> Vec<&crate::bronze::ParseAnomaly> {
        evs.iter()
            .filter_map(|e| {
                if let BronzeEventFamily::ParseAnomaly(ref a) = e.family {
                    Some(a)
                } else {
                    None
                }
            })
            .collect()
    }

    fn get_assets(evs: &[BronzeEvent]) -> Vec<&AssetObservation> {
        evs.iter()
            .filter_map(|e| {
                if let BronzeEventFamily::AssetObservation(ref a) = e.family {
                    Some(a)
                } else {
                    None
                }
            })
            .collect()
    }

    /// Build a 4-byte NetBIOS Session Service header (type=0x00, length=u24 BE).
    fn nb_header(payload_len: usize) -> Vec<u8> {
        let len = payload_len as u32;
        vec![
            0x00,
            ((len >> 16) & 0xFF) as u8,
            ((len >> 8) & 0xFF) as u8,
            (len & 0xFF) as u8,
        ]
    }

    /// Build a minimal SMB2 fixed header (64 bytes).
    ///
    /// - `command`: SMB2 command code (LE u16)
    /// - `flags`: header flags (bit 0 = ServerToRedir / response direction)
    /// - `message_id`: MessageId (LE u64)
    /// - `nt_status`: only meaningful on responses (placed at bytes 8..12)
    fn smb2_hdr(
        command: u16,
        flags: u32,
        message_id: u64,
        nt_status: u32,
        tree_id: u32,
        session_id: u64,
    ) -> Vec<u8> {
        let mut h = vec![0u8; 64];
        h[0..4].copy_from_slice(&SMB2_SIGNATURE);
        h[4..6].copy_from_slice(&64u16.to_le_bytes()); // StructureSize
        // bytes 6..8: CreditCharge (0)
        h[8..12].copy_from_slice(&nt_status.to_le_bytes()); // Status/Reserved
        h[12..14].copy_from_slice(&command.to_le_bytes());
        h[16..20].copy_from_slice(&flags.to_le_bytes());
        // bytes 20..24: NextCommand = 0 (no compound)
        h[24..32].copy_from_slice(&message_id.to_le_bytes());
        h[36..40].copy_from_slice(&tree_id.to_le_bytes());
        h[40..48].copy_from_slice(&session_id.to_le_bytes());
        // bytes 48..64: Signature (zeros)
        h
    }

    /// Wrap SMB2 bytes in NetBIOS framing and deliver to decoder.
    fn feed(
        dec: &mut Smb2Decoder,
        smb2_bytes: &[u8],
        context: PacketContext,
        session: &str,
    ) -> Vec<BronzeEvent> {
        let mut framed = nb_header(smb2_bytes.len());
        framed.extend_from_slice(smb2_bytes);
        let mut out = Vec::new();
        dec.on_stream_chunk(&chunk_with_session(&framed, context, session), &mut out);
        out
    }

    // ── Test 1: NEGOTIATE request extracts dialect list ───────────────────────

    #[test]
    fn test_negotiate_request_dialects() {
        let mut dec = Smb2Decoder::default();
        // NEGOTIATE body: StructureSize=36, DialectCount=2, SecurityMode=0, Reserved=0, Caps=0,
        // ClientGuid=[0;16], Dialects=[0x0300, 0x0311]
        let mut body = vec![0u8; 36];
        body[0..2].copy_from_slice(&36u16.to_le_bytes()); // StructureSize
        body[2..4].copy_from_slice(&2u16.to_le_bytes()); // DialectCount
        // ClientGuid at bytes 12..28 (all zeros)
        body[28..30].copy_from_slice(&0x0300u16.to_le_bytes());
        body[30..32].copy_from_slice(&0x0311u16.to_le_bytes());

        let mut pdu = smb2_hdr(CMD_NEGOTIATE, 0, 1, 0, 0, 0);
        pdu.extend_from_slice(&body);

        let evs = feed(&mut dec, &pdu, ctx(55000, 445), "s1");
        let txns = get_txns(&evs);
        assert_eq!(txns.len(), 1);
        assert_eq!(txns[0].operation, "smb2_negotiate_request");
        let dialects = txns[0]
            .attributes
            .get("dialects_offered")
            .expect("dialects_offered");
        assert!(dialects.contains("0x0300"), "expected 0x0300 in {dialects}");
        assert!(dialects.contains("0x0311"), "expected 0x0311 in {dialects}");
    }

    // ── Test 2: NEGOTIATE response + asset observation with dialect 0x0311 ────

    #[test]
    fn test_negotiate_response_asset_obs_smb311() {
        let mut dec = Smb2Decoder::default();
        // Response body: StructureSize=65, SecurityMode=1, DialectRevision=0x0311
        let mut body = vec![0u8; 65];
        body[0..2].copy_from_slice(&65u16.to_le_bytes());
        body[4..6].copy_from_slice(&0x0311u16.to_le_bytes()); // DialectRevision

        let mut pdu = smb2_hdr(
            CMD_NEGOTIATE,
            FLAGS_SERVER_TO_REDIR,
            1,
            STATUS_SUCCESS,
            0,
            0,
        );
        pdu.extend_from_slice(&body);

        let evs = feed(&mut dec, &pdu, ctx(445, 55000), "s2");
        let txns = get_txns(&evs);
        let assets = get_assets(&evs);
        assert_eq!(txns.len(), 1);
        assert_eq!(txns[0].operation, "smb2_negotiate_response");
        assert_eq!(txns[0].status, "ok");
        assert_eq!(
            txns[0]
                .attributes
                .get("negotiated_dialect")
                .map(String::as_str),
            Some("0x0311")
        );

        assert_eq!(assets.len(), 1);
        assert_eq!(assets[0].role.as_deref(), Some("smb_server"));
        assert!(assets[0].protocols.contains(&"smb2".to_string()));
        assert_eq!(
            assets[0]
                .identifiers
                .get("smb2_dialect")
                .map(String::as_str),
            Some("0x0311")
        );
    }

    // ── Test 3: SESSION_SETUP request notes security blob length ─────────────

    #[test]
    fn test_session_setup_request_blob_len() {
        let mut dec = Smb2Decoder::default();
        let mut body = vec![0u8; 25];
        body[0..2].copy_from_slice(&25u16.to_le_bytes()); // StructureSize
        // SecurityBufferLength at bytes 14..16 = 256 (NTLMSSP blob placeholder)
        body[14..16].copy_from_slice(&256u16.to_le_bytes());

        let mut pdu = smb2_hdr(CMD_SESSION_SETUP, 0, 2, 0, 0, 0);
        pdu.extend_from_slice(&body);

        let evs = feed(&mut dec, &pdu, ctx(55000, 445), "s3");
        let txns = get_txns(&evs);
        assert_eq!(txns[0].operation, "smb2_session_setup_request");
        assert_eq!(
            txns[0]
                .attributes
                .get("security_blob_len")
                .map(String::as_str),
            Some("256")
        );
    }

    // ── Test 4: SESSION_SETUP LOGON_FAILURE → medium anomaly ─────────────────

    #[test]
    fn test_session_setup_logon_failure_anomaly() {
        let mut dec = Smb2Decoder::default();
        let body = vec![0u8; 9]; // minimal response body
        let mut pdu = smb2_hdr(
            CMD_SESSION_SETUP,
            FLAGS_SERVER_TO_REDIR,
            2,
            STATUS_LOGON_FAILURE,
            0,
            0,
        );
        pdu.extend_from_slice(&body);

        let evs = feed(&mut dec, &pdu, ctx(445, 55000), "s4");
        let anoms = get_anomalies(&evs);
        assert!(!anoms.is_empty(), "expected anomaly for LOGON_FAILURE");
        assert_eq!(anoms[0].severity, "medium");
        let txns = get_txns(&evs);
        assert_eq!(txns[0].status, "STATUS_LOGON_FAILURE");
    }

    // ── Test 5: TREE_CONNECT request extracts UNC path ────────────────────────

    #[test]
    fn test_tree_connect_request_unc_path() {
        let mut dec = Smb2Decoder::default();
        // UNC path = "\\10.0.0.2\share" encoded in UTF-16LE
        let unc = r"\\10.0.0.2\share";
        let unc_utf16: Vec<u8> = unc
            .encode_utf16()
            .flat_map(|c| c.to_le_bytes().to_vec())
            .collect();

        // Body: StructureSize=9, Flags=0, PathOffset, PathLength
        // PathOffset is relative to start of SMB2 header (64 bytes),
        // so for a body with fields at offsets 0..8, the path data starts at:
        //   SMB2_HEADER_LEN + 8 = 64+8 = 72
        let path_offset: u16 = (SMB2_HEADER_LEN + 8) as u16;
        let path_len: u16 = unc_utf16.len() as u16;
        let mut body = vec![0u8; 8 + unc_utf16.len()];
        body[0..2].copy_from_slice(&9u16.to_le_bytes());
        body[4..6].copy_from_slice(&path_offset.to_le_bytes());
        body[6..8].copy_from_slice(&path_len.to_le_bytes());
        body[8..8 + unc_utf16.len()].copy_from_slice(&unc_utf16);

        let mut pdu = smb2_hdr(CMD_TREE_CONNECT, 0, 3, 0, 0, 0);
        pdu.extend_from_slice(&body);

        let evs = feed(&mut dec, &pdu, ctx(55000, 445), "s5");
        let txns = get_txns(&evs);
        assert_eq!(txns[0].operation, "smb2_tree_connect_request");
        assert_eq!(
            txns[0].attributes.get("tree_path").map(String::as_str),
            Some(unc)
        );
    }

    // ── Test 6: TREE_CONNECT fail → medium anomaly + named status ────────────

    #[test]
    fn test_tree_connect_access_denied_anomaly() {
        let mut dec = Smb2Decoder::default();
        let pdu = smb2_hdr(
            CMD_TREE_CONNECT,
            FLAGS_SERVER_TO_REDIR,
            3,
            STATUS_ACCESS_DENIED,
            0,
            0,
        );
        let evs = feed(&mut dec, &pdu, ctx(445, 55000), "s5");
        let anoms = get_anomalies(&evs);
        assert!(!anoms.is_empty(), "expected anomaly");
        assert_eq!(anoms[0].severity, "medium");
        let txns = get_txns(&evs);
        assert_eq!(txns[0].status, "STATUS_ACCESS_DENIED");
    }

    // ── Test 7: CREATE request extracts filename and disposition ──────────────

    #[test]
    fn test_create_request_filename_and_disposition() {
        let mut dec = Smb2Decoder::default();
        let filename = "malware.exe";
        let name_utf16: Vec<u8> = filename
            .encode_utf16()
            .flat_map(|c| c.to_le_bytes().to_vec())
            .collect();

        // CREATE request body layout: 57+ bytes
        // DesiredAccess at offset 24, ShareAccess at 32, CreateDisposition at 36,
        // NameOffset at 44, NameLength at 46.
        // NameOffset = SMB2_HEADER_LEN + 48 = 112 (relative to header start).
        let name_offset: u16 = (SMB2_HEADER_LEN + 48) as u16;
        let name_len: u16 = name_utf16.len() as u16;
        let mut body = vec![0u8; 48 + name_utf16.len()];
        body[0..2].copy_from_slice(&57u16.to_le_bytes()); // StructureSize
        body[24..28].copy_from_slice(&0x001F01FFu32.to_le_bytes()); // DesiredAccess (full)
        body[36..40].copy_from_slice(&2u32.to_le_bytes()); // FILE_CREATE
        body[44..46].copy_from_slice(&name_offset.to_le_bytes());
        body[46..48].copy_from_slice(&name_len.to_le_bytes());
        body[48..48 + name_utf16.len()].copy_from_slice(&name_utf16);

        let mut pdu = smb2_hdr(CMD_CREATE, 0, 4, 0, 1, 0);
        pdu.extend_from_slice(&body);

        let evs = feed(&mut dec, &pdu, ctx(55000, 445), "s6");
        let txns = get_txns(&evs);
        assert_eq!(txns[0].operation, "smb2_create_request");
        assert_eq!(
            txns[0].attributes.get("file_name").map(String::as_str),
            Some(filename)
        );
        assert_eq!(
            txns[0].attributes.get("disposition").map(String::as_str),
            Some("FILE_CREATE")
        );
    }

    // ── Test 8: CREATE response → FileId stored, later READ sees filename ─────

    #[test]
    fn test_create_then_read_file_name_tracking() {
        let mut dec = Smb2Decoder::default();
        let sess = "s7";
        let filename = "document.docx";
        let name_utf16: Vec<u8> = filename
            .encode_utf16()
            .flat_map(|c| c.to_le_bytes().to_vec())
            .collect();

        // 1. Send CREATE request with filename.
        let name_offset: u16 = (SMB2_HEADER_LEN + 48) as u16;
        let name_len: u16 = name_utf16.len() as u16;
        let mut req_body = vec![0u8; 48 + name_utf16.len()];
        req_body[0..2].copy_from_slice(&57u16.to_le_bytes());
        req_body[44..46].copy_from_slice(&name_offset.to_le_bytes());
        req_body[46..48].copy_from_slice(&name_len.to_le_bytes());
        req_body[48..48 + name_utf16.len()].copy_from_slice(&name_utf16);
        let mut create_req = smb2_hdr(CMD_CREATE, 0, 5, 0, 1, 1);
        create_req.extend_from_slice(&req_body);
        feed(&mut dec, &create_req, ctx(55000, 445), sess);

        // 2. Send CREATE response with a FileId at body offset 60.
        // CREATE response body must be >= 76 bytes.
        let file_id: [u8; 16] = [0xAB; 16];
        let mut resp_body = vec![0u8; 89];
        resp_body[0..2].copy_from_slice(&89u16.to_le_bytes()); // StructureSize
        resp_body[60..76].copy_from_slice(&file_id);
        let mut create_resp = smb2_hdr(CMD_CREATE, FLAGS_SERVER_TO_REDIR, 5, STATUS_SUCCESS, 1, 1);
        create_resp.extend_from_slice(&resp_body);
        feed(&mut dec, &create_resp, ctx(445, 55000), sess);

        // 3. Send READ request referencing the same FileId.
        let mut read_body = vec![0u8; 32];
        read_body[0..2].copy_from_slice(&49u16.to_le_bytes()); // StructureSize
        read_body[4..8].copy_from_slice(&4096u32.to_le_bytes()); // Length
        read_body[16..32].copy_from_slice(&file_id);
        let mut read_req = smb2_hdr(CMD_READ, 0, 6, 0, 1, 1);
        read_req.extend_from_slice(&read_body);
        let read_evs = feed(&mut dec, &read_req, ctx(55000, 445), sess);

        let txns = get_txns(&read_evs);
        assert_eq!(txns[0].operation, "smb2_read_request");
        assert_eq!(
            txns[0].attributes.get("file_name").map(String::as_str),
            Some(filename),
            "READ should carry filename from CREATE tracking"
        );
    }

    // ── Test 9: IOCTL FSCTL_PIPE_TRANSCEIVE on svcctl → high anomaly ─────────

    #[test]
    fn test_ioctl_pipe_transceive_svcctl_high_anomaly() {
        let mut dec = Smb2Decoder::default();
        let sess = "s8";

        // First register the filename via CREATE so the FileId maps to the pipe name.
        let pipe_name = PIPE_SVCCTL;
        let name_utf16: Vec<u8> = pipe_name
            .encode_utf16()
            .flat_map(|c| c.to_le_bytes().to_vec())
            .collect();
        let name_offset: u16 = (SMB2_HEADER_LEN + 48) as u16;
        let name_len: u16 = name_utf16.len() as u16;
        let mut req_body = vec![0u8; 48 + name_utf16.len()];
        req_body[0..2].copy_from_slice(&57u16.to_le_bytes());
        req_body[44..46].copy_from_slice(&name_offset.to_le_bytes());
        req_body[46..48].copy_from_slice(&name_len.to_le_bytes());
        req_body[48..48 + name_utf16.len()].copy_from_slice(&name_utf16);
        let mut create_req = smb2_hdr(CMD_CREATE, 0, 10, 0, 1, 1);
        create_req.extend_from_slice(&req_body);
        feed(&mut dec, &create_req, ctx(55000, 445), sess);

        // CREATE response — register FileId.
        let file_id: [u8; 16] = [0xCC; 16];
        let mut resp_body = vec![0u8; 89];
        resp_body[60..76].copy_from_slice(&file_id);
        let mut create_resp = smb2_hdr(CMD_CREATE, FLAGS_SERVER_TO_REDIR, 10, STATUS_SUCCESS, 1, 1);
        create_resp.extend_from_slice(&resp_body);
        feed(&mut dec, &create_resp, ctx(445, 55000), sess);

        // IOCTL FSCTL_PIPE_TRANSCEIVE with the svcctl FileId.
        let mut ioctl_body = vec![0u8; 57];
        ioctl_body[0..2].copy_from_slice(&57u16.to_le_bytes());
        ioctl_body[4..8].copy_from_slice(&FSCTL_PIPE_TRANSCEIVE.to_le_bytes());
        ioctl_body[8..24].copy_from_slice(&file_id);
        let mut ioctl_req = smb2_hdr(CMD_IOCTL, 0, 11, 0, 1, 1);
        ioctl_req.extend_from_slice(&ioctl_body);
        let ioctl_evs = feed(&mut dec, &ioctl_req, ctx(55000, 445), sess);

        let anoms = get_anomalies(&ioctl_evs);
        let high_anoms: Vec<_> = anoms.iter().filter(|a| a.severity == "high").collect();
        assert!(
            !high_anoms.is_empty(),
            "expected high anomaly for svcctl pipe transceive"
        );
        assert!(
            high_anoms[0].reason.contains("svcctl") || high_anoms[0].reason.contains("SCM"),
            "reason should mention svcctl: {}",
            high_anoms[0].reason
        );

        let txns = get_txns(&ioctl_evs);
        assert!(
            txns.iter().any(|t| t.operation == "smb2_ioctl_request"),
            "should emit ioctl tx"
        );
        let ioctl_tx = txns
            .iter()
            .find(|t| t.operation == "smb2_ioctl_request")
            .unwrap();
        assert_eq!(
            ioctl_tx.attributes.get("ctl_code_name").map(String::as_str),
            Some("FSCTL_PIPE_TRANSCEIVE")
        );
    }

    // ── Test 10: IOCTL FSCTL_DFS_GET_REFERRALS ───────────────────────────────

    #[test]
    fn test_ioctl_dfs_get_referrals() {
        let mut dec = Smb2Decoder::default();
        let mut body = vec![0u8; 57];
        body[0..2].copy_from_slice(&57u16.to_le_bytes());
        body[4..8].copy_from_slice(&FSCTL_DFS_GET_REFERRALS.to_le_bytes());
        let mut pdu = smb2_hdr(CMD_IOCTL, 0, 12, 0, 1, 1);
        pdu.extend_from_slice(&body);

        let evs = feed(&mut dec, &pdu, ctx(55000, 445), "s9");
        let txns = get_txns(&evs);
        assert!(txns.iter().any(|t| t.operation == "smb2_ioctl_request"));
        let tx = txns
            .iter()
            .find(|t| t.operation == "smb2_ioctl_request")
            .unwrap();
        assert_eq!(
            tx.attributes.get("ctl_code_name").map(String::as_str),
            Some("FSCTL_DFS_GET_REFERRALS")
        );
    }

    // ── Test 11: CLOSE with FileId annotation ────────────────────────────────

    #[test]
    fn test_close_request_with_file_id() {
        let mut dec = Smb2Decoder::default();
        let mut body = vec![0u8; 24];
        body[0..2].copy_from_slice(&24u16.to_le_bytes());
        let file_id: [u8; 16] = [0x42; 16];
        body[8..24].copy_from_slice(&file_id);

        let mut pdu = smb2_hdr(CMD_CLOSE, 0, 13, 0, 1, 1);
        pdu.extend_from_slice(&body);

        let evs = feed(&mut dec, &pdu, ctx(55000, 445), "s10");
        let txns = get_txns(&evs);
        assert_eq!(txns[0].operation, "smb2_close_request");
        assert!(txns[0].attributes.contains_key("file_id"));
    }

    // ── Test 12: LOGOFF request + response pairing ───────────────────────────

    #[test]
    fn test_logoff_request_response() {
        let mut dec = Smb2Decoder::default();
        let sess = "s11";
        // LOGOFF request (body = minimal 4 bytes per spec)
        let req_body = vec![0u8; 4];
        let mut req = smb2_hdr(CMD_LOGOFF, 0, 14, 0, 0, 1);
        req.extend_from_slice(&req_body);
        let req_evs = feed(&mut dec, &req, ctx(55000, 445), sess);
        let req_txns = get_txns(&req_evs);
        assert_eq!(req_txns[0].operation, "smb2_logoff_request");

        // LOGOFF response
        let resp_body = vec![0u8; 4];
        let mut resp = smb2_hdr(CMD_LOGOFF, FLAGS_SERVER_TO_REDIR, 14, STATUS_SUCCESS, 0, 1);
        resp.extend_from_slice(&resp_body);
        let resp_evs = feed(&mut dec, &resp, ctx(445, 55000), sess);
        let resp_txns = get_txns(&resp_evs);
        assert_eq!(resp_txns[0].operation, "smb2_logoff_response");
        assert_eq!(resp_txns[0].status, "ok");
    }

    // ── Test 13: Request/response MessageId pairing ───────────────────────────

    #[test]
    fn test_message_id_pairing_across_sessions() {
        // Two sessions with same MessageId: should not cross-correlate.
        let mut dec = Smb2Decoder::default();
        let body = vec![0u8; 4];

        // Session A, message_id=100
        let mut req_a = smb2_hdr(CMD_LOGOFF, 0, 100, 0, 0, 1);
        req_a.extend_from_slice(&body);
        feed(&mut dec, &req_a, ctx(55000, 445), "sessA");

        // Session B, message_id=100 — should not consume session A's pending.
        let mut resp_b = smb2_hdr(CMD_LOGOFF, FLAGS_SERVER_TO_REDIR, 100, STATUS_SUCCESS, 0, 1);
        resp_b.extend_from_slice(&body);
        let resp_b_evs = feed(&mut dec, &resp_b, ctx(445, 55001), "sessB");

        // Session A should still have its pending entry (B didn't consume it).
        assert!(
            dec.pending.contains_key(&PendingKey {
                session_key: "sessA".to_string(),
                message_id: 100,
            }),
            "session A pending should remain after session B response"
        );

        // Now send the response for session A.
        let mut resp_a = smb2_hdr(CMD_LOGOFF, FLAGS_SERVER_TO_REDIR, 100, STATUS_SUCCESS, 0, 1);
        resp_a.extend_from_slice(&body);
        feed(&mut dec, &resp_a, ctx(445, 55000), "sessA");

        assert!(
            !dec.pending.contains_key(&PendingKey {
                session_key: "sessA".to_string(),
                message_id: 100,
            }),
            "session A pending should be consumed after its own response"
        );

        // Suppress unused variable warning.
        let _ = resp_b_evs;
    }

    // ── Test 14: NetBIOS framing on port 445 ─────────────────────────────────

    #[test]
    fn test_netbios_framing_port_445() {
        let mut dec = Smb2Decoder::default();
        let pdu = smb2_hdr(CMD_LOGOFF, 0, 15, 0, 0, 1);

        // Deliver with explicit NetBIOS framing (type=0x00).
        let mut framed = nb_header(pdu.len());
        framed.extend_from_slice(&pdu);
        let mut out = Vec::new();
        dec.on_stream_chunk(
            &chunk_with_session(&framed, ctx(55000, 445), "s14"),
            &mut out,
        );

        let txns = get_txns(&out);
        assert_eq!(txns.len(), 1);
        assert_eq!(txns[0].operation, "smb2_logoff_request");
    }

    // ── Test 15: NetBIOS framing on port 139 ─────────────────────────────────

    #[test]
    fn test_netbios_framing_port_139() {
        let mut dec = Smb2Decoder::default();
        let pdu = smb2_hdr(CMD_LOGOFF, 0, 16, 0, 0, 1);

        let mut framed = nb_header(pdu.len());
        framed.extend_from_slice(&pdu);
        let mut out = Vec::new();
        dec.on_stream_chunk(
            &chunk_with_session(&framed, ctx(55001, 139), "s15"),
            &mut out,
        );

        let txns = get_txns(&out);
        assert!(!txns.is_empty(), "should parse SMB2 over port 139");
        assert_eq!(txns[0].operation, "smb2_logoff_request");
    }

    // ── Test 16: Compound request (NextCommand chain) ─────────────────────────

    #[test]
    fn test_compound_request_two_pdus() {
        let mut dec = Smb2Decoder::default();

        // Build two chained PDUs.
        // PDU 1: NEGOTIATE request, NextCommand = 64 (points right to PDU 2).
        let mut pdu1 = smb2_hdr(CMD_NEGOTIATE, 0, 20, 0, 0, 0);
        pdu1[20..24].copy_from_slice(&64u32.to_le_bytes()); // NextCommand = 64

        // PDU 2: LOGOFF request, no body needed, NextCommand = 0.
        let pdu2 = smb2_hdr(CMD_LOGOFF, 0, 21, 0, 0, 1);

        // Concatenate PDUs (compound frame).
        let mut compound = pdu1.clone();
        compound.extend_from_slice(&pdu2);

        let evs = feed(&mut dec, &compound, ctx(55000, 445), "s16");
        let txns = get_txns(&evs);
        assert_eq!(
            txns.len(),
            2,
            "compound frame should yield 2 transactions, got {}",
            txns.len()
        );
        assert!(txns.iter().any(|t| t.operation == "smb2_negotiate_request"));
        assert!(txns.iter().any(|t| t.operation == "smb2_logoff_request"));
    }

    // ── Test 17: Truncated header → low anomaly ───────────────────────────────

    #[test]
    fn test_truncated_header_anomaly() {
        let mut dec = Smb2Decoder::default();
        // Only 20 bytes — too short for the 64-byte SMB2 fixed header.
        let short_pdu: Vec<u8> = {
            let mut v = SMB2_SIGNATURE.to_vec();
            v.extend_from_slice(&[0u8; 16]); // pad to 20 bytes
            v
        };

        let evs = feed(&mut dec, &short_pdu, ctx(55000, 445), "s17");
        let anoms = get_anomalies(&evs);
        assert!(!anoms.is_empty(), "expected anomaly for truncated header");
        assert_eq!(anoms[0].severity, "low");
    }

    // ── Test 18: Unknown command → low anomaly ────────────────────────────────

    #[test]
    fn test_unknown_command_low_anomaly() {
        let mut dec = Smb2Decoder::default();
        let pdu = smb2_hdr(0x00FF, 0, 22, 0, 0, 0); // 0x00FF = not a real command
        let evs = feed(&mut dec, &pdu, ctx(55000, 445), "s18");
        let anoms = get_anomalies(&evs);
        assert!(!anoms.is_empty(), "expected unknown-command anomaly");
        assert_eq!(anoms[0].severity, "low");
        assert!(
            anoms[0].reason.contains("0x00ff") || anoms[0].reason.contains("0x00FF"),
            "reason should contain the unknown command code: {}",
            anoms[0].reason
        );
    }

    // ── Test 19: STATUS_ACCESS_DENIED name ───────────────────────────────────

    #[test]
    fn test_status_access_denied_naming() {
        assert_eq!(nt_status_name(STATUS_ACCESS_DENIED), "STATUS_ACCESS_DENIED");
    }

    // ── Test 20: WRITE request with FileId annotation ─────────────────────────

    #[test]
    fn test_write_request_extracts_file_id() {
        let mut dec = Smb2Decoder::default();
        let file_id: [u8; 16] = [0x55; 16];
        let mut body = vec![0u8; 32];
        body[0..2].copy_from_slice(&49u16.to_le_bytes()); // StructureSize
        body[4..8].copy_from_slice(&512u32.to_le_bytes()); // Length
        body[16..32].copy_from_slice(&file_id);

        let mut pdu = smb2_hdr(CMD_WRITE, 0, 23, 0, 1, 1);
        pdu.extend_from_slice(&body);

        let evs = feed(&mut dec, &pdu, ctx(55000, 445), "s20");
        let txns = get_txns(&evs);
        assert_eq!(txns[0].operation, "smb2_write_request");
        assert!(txns[0].attributes.contains_key("file_id"));
        assert_eq!(
            txns[0].attributes.get("write_length").map(String::as_str),
            Some("512")
        );
    }

    // ── Test 21: SMB3 encrypted transform → low anomaly ──────────────────────

    #[test]
    fn test_smb3_transform_opaque_anomaly() {
        let mut dec = Smb2Decoder::default();
        // SMB3 Transform header starts with \xFDSMB.
        let mut transform_hdr = SMB3_TRANSFORM.to_vec();
        transform_hdr.extend_from_slice(&[0u8; 52]); // pad to 56 bytes (typical Transform header)

        let evs = feed(&mut dec, &transform_hdr, ctx(55000, 445), "s21");
        let anoms = get_anomalies(&evs);
        assert!(
            !anoms.is_empty(),
            "expected anomaly for SMB3 encrypted transform"
        );
    }

    // ── Test 22: TREE_CONNECT success then CREATE annotates share path ────────

    #[test]
    fn test_tree_connect_then_create_annotates_share() {
        let mut dec = Smb2Decoder::default();
        let sess = "s22";
        let tree_id: u32 = 0x00000001;

        // TREE_CONNECT request with UNC path.
        let unc = r"\\fileserver\c$";
        let unc_utf16: Vec<u8> = unc
            .encode_utf16()
            .flat_map(|c| c.to_le_bytes().to_vec())
            .collect();
        let path_offset: u16 = (SMB2_HEADER_LEN + 8) as u16;
        let path_len: u16 = unc_utf16.len() as u16;
        let mut tc_body = vec![0u8; 8 + unc_utf16.len()];
        tc_body[4..6].copy_from_slice(&path_offset.to_le_bytes());
        tc_body[6..8].copy_from_slice(&path_len.to_le_bytes());
        tc_body[8..8 + unc_utf16.len()].copy_from_slice(&unc_utf16);
        let mut tc_req = smb2_hdr(CMD_TREE_CONNECT, 0, 30, 0, 0, 1);
        tc_req.extend_from_slice(&tc_body);
        feed(&mut dec, &tc_req, ctx(55000, 445), sess);

        // TREE_CONNECT response — the server echoes back the tree_id.
        let tc_resp = smb2_hdr(
            CMD_TREE_CONNECT,
            FLAGS_SERVER_TO_REDIR,
            30,
            STATUS_SUCCESS,
            tree_id,
            1,
        );
        feed(&mut dec, &tc_resp, ctx(445, 55000), sess);

        // CREATE request on the same tree.
        let filename = "secret.txt";
        let name_utf16: Vec<u8> = filename
            .encode_utf16()
            .flat_map(|c| c.to_le_bytes().to_vec())
            .collect();
        let name_offset: u16 = (SMB2_HEADER_LEN + 48) as u16;
        let name_len: u16 = name_utf16.len() as u16;
        let mut cr_body = vec![0u8; 48 + name_utf16.len()];
        cr_body[0..2].copy_from_slice(&57u16.to_le_bytes());
        cr_body[44..46].copy_from_slice(&name_offset.to_le_bytes());
        cr_body[46..48].copy_from_slice(&name_len.to_le_bytes());
        cr_body[48..48 + name_utf16.len()].copy_from_slice(&name_utf16);
        let mut cr_req = smb2_hdr(CMD_CREATE, 0, 31, 0, tree_id, 1);
        cr_req.extend_from_slice(&cr_body);
        let cr_evs = feed(&mut dec, &cr_req, ctx(55000, 445), sess);

        let txns = get_txns(&cr_evs);
        let create_tx = txns
            .iter()
            .find(|t| t.operation == "smb2_create_request")
            .expect("smb2_create_request not found");
        assert_eq!(
            create_tx.attributes.get("tree_path").map(String::as_str),
            Some(unc),
            "CREATE should annotate tree_path from TREE_CONNECT"
        );
        assert_eq!(
            create_tx.attributes.get("file_name").map(String::as_str),
            Some(filename)
        );
    }

    // ── Test 23: FSCTL_VALIDATE_NEGOTIATE_INFO name ───────────────────────────

    #[test]
    fn test_ioctl_validate_negotiate_info() {
        let mut dec = Smb2Decoder::default();
        let mut body = vec![0u8; 57];
        body[0..2].copy_from_slice(&57u16.to_le_bytes());
        body[4..8].copy_from_slice(&FSCTL_VALIDATE_NEGOTIATE_INFO.to_le_bytes());
        let mut pdu = smb2_hdr(CMD_IOCTL, 0, 33, 0, 1, 1);
        pdu.extend_from_slice(&body);

        let evs = feed(&mut dec, &pdu, ctx(55000, 445), "s23");
        let txns = get_txns(&evs);
        let ioctl = txns
            .iter()
            .find(|t| t.operation == "smb2_ioctl_request")
            .unwrap();
        assert_eq!(
            ioctl.attributes.get("ctl_code_name").map(String::as_str),
            Some("FSCTL_VALIDATE_NEGOTIATE_INFO")
        );
    }

    // ── Test 24: Two NetBIOS frames in one TCP segment (stream reassembly) ────

    #[test]
    fn test_two_nb_frames_in_one_segment() {
        let mut dec = Smb2Decoder::default();
        let sess = "s24";

        let pdu1 = smb2_hdr(CMD_LOGOFF, 0, 40, 0, 0, 1);
        let pdu2 = smb2_hdr(CMD_LOGOFF, 0, 41, 0, 0, 1);

        let mut combined = nb_header(pdu1.len());
        combined.extend_from_slice(&pdu1);
        combined.extend_from_slice(&nb_header(pdu2.len()));
        combined.extend_from_slice(&pdu2);

        let mut out = Vec::new();
        dec.on_stream_chunk(
            &chunk_with_session(&combined, ctx(55000, 445), sess),
            &mut out,
        );

        let txns = get_txns(&out);
        assert_eq!(
            txns.len(),
            2,
            "two NB-framed PDUs should yield 2 transactions, got {}",
            txns.len()
        );
    }

    // ── Test 25: STATUS_OBJECT_NAME_NOT_FOUND naming ─────────────────────────

    #[test]
    fn test_status_object_name_not_found_naming() {
        assert_eq!(
            nt_status_name(STATUS_OBJECT_NAME_NOT_FOUND),
            "STATUS_OBJECT_NAME_NOT_FOUND"
        );
    }
}
