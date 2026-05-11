//! Output renderers — convert canonical `BronzeEvent`s into external formats.
//!
//! Bronze remains the source of truth; renderers here are pure transforms
//! and have no dependency on engine internals. New formats add a sibling
//! module without touching anything else.

pub mod influx_line;
pub mod ocsf;
pub mod zeek;
