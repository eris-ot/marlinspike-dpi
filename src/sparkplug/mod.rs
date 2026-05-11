//! Sparkplug B types and session decoder.
//!
//! [`proto`] exposes the `prost`-generated protobuf message types. [`decoder`]
//! holds the stateful [`SparkplugBDecoder`] that consumes MQTT publish payloads
//! (via the [`crate::mqtt_payload::MqttPayloadDecoder`] trait), resolves
//! alias→metric_name from BIRTH messages, and emits two event families:
//!
//! - **[`crate::bronze::BronzeEventFamily::ProcessReading`]** — one per metric
//!   in metric-bearing messages (NBIRTH, DBIRTH, NDATA, DDATA). Point identity
//!   is typed via [`crate::bronze::PointIdentifier::SparkplugMetric`]; quality
//!   via [`crate::bronze::RawQuality::SparkplugQuality`].
//!
//! - **[`crate::bronze::BronzeEventFamily::ProtocolTransaction`]** — one per
//!   Sparkplug message, covering the session-management envelope (NBIRTH,
//!   NDEATH, DBIRTH, DDEATH, NDATA, DDATA, NCMD, DCMD, STATE). The typed
//!   surface is [`crate::bronze::ProtocolFields::Sparkplug`] carrying a
//!   [`crate::bronze::SparkplugBronzeFields`] struct. The legacy
//!   `attributes: BTreeMap<String, String>` field is also populated for
//!   backward compatibility through v1.x; it will be removed in v2.0.
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
