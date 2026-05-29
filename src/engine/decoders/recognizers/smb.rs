use super::emit_recognition;
use crate::bronze::BronzeEvent;
use crate::engine::{DecoderInterest, SessionDecoder, StreamChunk};

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
                // SMB2 is now owned by the `smb2` deep decoder — skip silently.
                return;
            }
        }
    }
}

// ── Inventory registration ──────────────────────────────────────
inventory::submit!(crate::engine::decoders::DecoderRegistration {
    name: "smb",
    factory: || Box::new(SmbRecognizer),
});
