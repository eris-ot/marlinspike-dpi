//! Shared contracts between Fathom appliance, collectors, and pluggable engines
//! (marlinspike-dpi, marlinspike-malware, future engines).
//!
//! Per `docs/repo-modularization-and-contracts-spec.md` in the appliance repo,
//! this crate owns vocabulary that crosses repo boundaries: protocol identifiers,
//! engine manifest schema, artifact bundle contracts.
//!
//! Phase 0 surface: `ProtocolId` only. Engine manifests and bundle schemas
//! land in subsequent phases.

pub mod classifier;
pub mod protocol;

pub use classifier::Classifier;
pub use protocol::ProtocolId;
