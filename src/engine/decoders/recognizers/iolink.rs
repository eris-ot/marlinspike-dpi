use super::emit_recognition;
use crate::bronze::BronzeEvent;
use crate::engine::{DecoderInterest, SessionDecoder, StreamChunk};

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
        emit_recognition(
            chunk,
            out,
            "iolink",
            "iolink_traffic",
            "IO-Link Wireless traffic",
        );
    }
}

// ── Inventory registration ──────────────────────────────────────
inventory::submit!(crate::engine::decoders::DecoderRegistration {
    name: "iolink",
    factory: || Box::new(IoLinkRecognizer),
});
