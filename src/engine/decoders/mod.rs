//! Per-protocol session decoders. Each submodule owns one decoder
//! implementation (or a tightly-related family) plus its private state.
//!
//! Decoders self-register via `inventory::submit!(DecoderRegistration { ... })`
//! at the bottom of their file. `DpiEngine::new()` collects every registration
//! at startup, sorts by name for determinism, and instantiates each decoder
//! through its factory closure. Adding a new protocol is a single new file +
//! one `submit!` block — no central registration list to edit.

use crate::engine::SessionDecoder;

/// One self-registered decoder. `name` is the diagnostic protocol slug
/// (`"modbus"`, `"sparkplug_b"`, etc.); `factory` constructs a fresh decoder
/// instance each time `DpiEngine::new()` is called.
pub(crate) struct DecoderRegistration {
    pub(crate) name: &'static str,
    pub(crate) factory: fn() -> Box<dyn SessionDecoder>,
}

inventory::collect!(DecoderRegistration);

pub(crate) mod dcerpc;
pub(crate) mod discovery;
pub(crate) mod ike;
pub(crate) mod it_app;
pub(crate) mod it_basic;
pub(crate) mod link_layer;
pub(crate) mod netbios;
pub(crate) mod netflow;
pub(crate) mod openvpn;
pub(crate) mod ot;
pub(crate) mod quic;
pub(crate) mod rdp;
pub(crate) mod recognizers;
pub(crate) mod smtp;
pub(crate) mod synchrophasor;
pub(crate) mod tacacs;
pub(crate) mod tftp;
pub(crate) mod vnc;
pub(crate) mod winrm;
pub(crate) mod wireguard;
