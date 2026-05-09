//! Sparkplug B types and session decoder.
//!
//! [`proto`] exposes the `prost`-generated protobuf message types. [`decoder`]
//! holds the stateful [`SparkplugBDecoder`] that consumes MQTT publish payloads
//! (via the [`crate::mqtt_payload::MqttPayloadDecoder`] trait), resolves
//! alias→metric_name from BIRTH messages, and emits
//! [`crate::bronze::BronzeEventFamily::ProcessReading`].
//!
//! Submodules:
//! - [`topic`] — Sparkplug B topic parser
//! - [`state`] — per-session alias table with bdSeq supersession
//! - [`value`] — Sparkplug Metric → typed `PointValue` / `RawQuality`
//! - [`decoder`] — main `SparkplugBDecoder` glue

pub mod decoder;
pub mod proto;
pub mod state;
pub mod topic;
pub mod value;

pub use decoder::SparkplugBDecoder;
