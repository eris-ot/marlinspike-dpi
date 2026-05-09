//! IEEE C37.118 (synchrophasor) protocol — frame parsers, configuration state,
//! and stateful decoder.
//!
//! [`reader`]   — big-endian cursor (network byte order)
//! [`frame`]    — common 14-byte header + frame-type discrimination
//! [`config`]   — CFG-2 frame parser + per-PMU layout descriptor
//! [`data`]     — data frame decoder (uses CFG-2 layout)
//! [`decoder`]  — orchestrating [`SynchrophasorDecoder`] with per-source CFG state

pub mod config;
pub mod data;
pub mod decoder;
pub mod frame;
pub mod reader;

pub use decoder::SynchrophasorDecoder;
pub use frame::looks_like_synchrophasor;
