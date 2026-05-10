//! Per-protocol session decoders. Each submodule owns one decoder
//! implementation (or a tightly-related family) plus its private state.
//!
//! Decoders are registered in `DpiEngine::new()` and dispatched by the
//! engine pipeline based on `DecoderInterest`.

pub(crate) mod it_app;
pub(crate) mod it_basic;
pub(crate) mod link_layer;
pub(crate) mod ot;
pub(crate) mod recognizers;
pub(crate) mod synchrophasor;
