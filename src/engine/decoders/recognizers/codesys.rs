use super::emit_recognition;
use crate::bronze::BronzeEvent;
use crate::engine::{DecoderInterest, SessionDecoder, StreamChunk};

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

// ── Inventory registration ──────────────────────────────────────
inventory::submit!(crate::engine::decoders::DecoderRegistration {
    name: "codesys",
    factory: || Box::new(CodesysRecognizer),
});
