use super::emit_recognition;
use crate::bronze::BronzeEvent;
use crate::engine::{DecoderInterest, SessionDecoder, StreamChunk};

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
        emit_recognition(
            chunk,
            out,
            "cclink",
            "cclink_ie_traffic",
            "CC-Link IE Field traffic",
        );
    }
}

// ── Inventory registration ──────────────────────────────────────
inventory::submit!(crate::engine::decoders::DecoderRegistration {
    name: "cclink",
    factory: || Box::new(CcLinkRecognizer),
});
