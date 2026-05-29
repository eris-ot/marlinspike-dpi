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

#[cfg(feature = "amqp")]
pub(crate) mod amqp;
#[cfg(feature = "coap")]
pub(crate) mod coap;
#[cfg(feature = "dcerpc")]
pub(crate) mod dcerpc;
#[cfg(feature = "diameter")]
pub(crate) mod diameter;
#[cfg(feature = "discovery")]
pub(crate) mod discovery;
#[cfg(feature = "igmp")]
pub(crate) mod igmp;
#[cfg(feature = "ike")]
pub(crate) mod ike;
// Multi-protocol families — directory modules whose submodules are gated
// individually inside their own `mod.rs`. An all-disabled family compiles
// to an empty module.
pub(crate) mod it_app;
pub(crate) mod it_basic;
#[cfg(feature = "kerberos")]
pub(crate) mod kerberos;
#[cfg(feature = "ldap")]
pub(crate) mod ldap;
pub(crate) mod link_layer;
#[cfg(feature = "mqtt_sn")]
pub(crate) mod mqtt_sn;
#[cfg(feature = "netbios")]
pub(crate) mod netbios;
#[cfg(feature = "netflow")]
pub(crate) mod netflow;
#[cfg(feature = "ntlmssp")]
pub(crate) mod ntlmssp;
#[cfg(feature = "openvpn")]
pub(crate) mod openvpn;
pub(crate) mod ot;
#[cfg(feature = "quic")]
pub(crate) mod quic;
#[cfg(feature = "radsec")]
pub(crate) mod radsec;
#[cfg(feature = "rdp")]
pub(crate) mod rdp;
pub(crate) mod recognizers;
#[cfg(feature = "sip_rtp")]
pub(crate) mod sip_rtp;
#[cfg(feature = "smb2")]
pub(crate) mod smb2;
#[cfg(feature = "smtp")]
pub(crate) mod smtp;
#[cfg(feature = "synchrophasor")]
pub(crate) mod synchrophasor;
#[cfg(feature = "tacacs")]
pub(crate) mod tacacs;
#[cfg(feature = "tftp")]
pub(crate) mod tftp;
#[cfg(feature = "vnc")]
pub(crate) mod vnc;
#[cfg(feature = "winrm")]
pub(crate) mod winrm;
#[cfg(feature = "wireguard")]
pub(crate) mod wireguard;
