//! marlinspike-dpi — pure-Rust DPI engine with anomaly detection for OT/ICS
//! and IT network monitoring.
//!
//! Transforms Iron captures (`pcap` or `pcapng`) into Bronze v2 events:
//! protocol transactions, asset observations, topology, parse anomalies,
//! and extracted artifacts.
//!
//! 34 protocol dissectors, plus three detection subsystems:
//! - **[`stovetop`]** — frame-level integrity (padding, CRC, runt/oversized)
//! - **[`icmpeeker`]** — ICMP threat detection (redirects, tunnels, recon)
//! - **[`bilgepump`]** — stateful L2 monitoring (ARP spoofing, VLAN hopping,
//!   STP hijacking, rogue DHCP, identity conflicts)
//!
//! ```no_run
//! use fm_dpi::DpiEngine;
//!
//! let bytes = std::fs::read("capture.pcap")?;
//! let mut engine = DpiEngine::new();
//! let bronze = engine.process_capture("capture-1", std::io::Cursor::new(bytes))?;
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```
//!
//! For non-Rust consumers, enable the `ffi` feature and build
//! `marlinspike-dpi` as a `cdylib` or `staticlib`. The exported C ABI accepts
//! capture bytes and returns a JSON payload containing the Bronze checkpoint
//! plus Bronze events. The legacy `fm_dpi_process_pcapng_json` symbol name is
//! preserved for compatibility even though the implementation now accepts both
//! classic PCAP and PCAPNG input.

pub mod bronze;
pub mod classify;
pub mod corpus;
pub mod dedup;
pub mod dissectors;
pub mod bilgepump;
pub mod engine;
pub mod icmpeeker;
pub mod mqtt_payload;
pub mod opc_ua;
pub mod output;
pub mod pccc;
pub mod registry;
pub mod sparkplug;
pub mod stovetop;
pub mod synchrophasor;

#[cfg(feature = "ffi")]
pub mod ffi;

pub use crate::bronze::{
    BRONZE_SCHEMA_VERSION, BronzeBatch, BronzeEvent, BronzeEventFamily, EventEnvelope,
    ModbusRegKind, OpcUaNodeId, PointIdentifier, PointValue, ProcessReading, RawQuality,
    SegmentCheckpoint, activity_records,
};
pub use crate::corpus::{
    CorpusDirectory, CorpusManifest, CorpusManifestSummary, CorpusRoadmapPhase,
    CorpusValidationOptions, CorpusValidationSummary, FixtureResult, FixtureResultStatus,
    FixtureSpec, FixtureValidationObservation, ImplementationStatus, validate_corpus_manifest,
};
pub use crate::classify::{RegistryClassifier, name_to_protocol_id};
pub use crate::engine::{BronzeSink, DpiEngine, DpiError, DpiSegmentOutput, SegmentMeta};
pub use fathom_contracts::{Classifier, ProtocolId};
