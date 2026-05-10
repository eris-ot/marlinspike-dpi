//! Synchrophasor (IEEE C37.118) `SessionDecoder` wrapper. The wire-format
//! parsing and stateful CFG/data-frame logic live in `crate::synchrophasor`;
//! this module just bridges that to the engine's dispatch surface.

use crate::bronze::BronzeEvent;
use crate::engine::{
    build_envelope, DecoderInterest, SessionDecoder, StreamChunk,
};

#[derive(Default)]
pub(crate) struct SynchrophasorDecoderWrapper {
    decoder: crate::synchrophasor::SynchrophasorDecoder,
}

impl SessionDecoder for SynchrophasorDecoderWrapper {
    fn name(&self) -> &'static str {
        "synchrophasor"
    }

    fn interest(&self) -> &'static [DecoderInterest] {
        &[
            DecoderInterest::TcpPort(4712),
            DecoderInterest::TcpPort(4713),
            DecoderInterest::UdpPort(4712),
            DecoderInterest::UdpPort(4713),
        ]
    }

    fn on_stream_chunk(&mut self, chunk: &StreamChunk<'_>, out: &mut Vec<BronzeEvent>) {
        self.handle(chunk, out);
    }

    fn on_datagram(&mut self, chunk: &StreamChunk<'_>, out: &mut Vec<BronzeEvent>) {
        self.handle(chunk, out);
    }
}

impl SynchrophasorDecoderWrapper {
    fn handle(&mut self, chunk: &StreamChunk<'_>, out: &mut Vec<BronzeEvent>) {
        if !crate::synchrophasor::looks_like_synchrophasor(chunk.payload) {
            return;
        }
        let envelope = build_envelope(
            &chunk.context,
            chunk.interface_id,
            chunk.frame_index,
            chunk.timestamp,
            chunk.segment_hash,
            chunk.transport,
            Some("synchrophasor"),
            chunk.captured_len,
            chunk.session_key.clone(),
        );
        let mut events = self.decoder.handle_frame(
            chunk.payload,
            chunk.context.src_ip,
            &envelope,
            chunk.capture_id,
        );
        out.append(&mut events);
    }
}
