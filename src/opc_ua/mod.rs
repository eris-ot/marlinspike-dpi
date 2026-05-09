//! OPC UA Binary protocol — wire-format decoders and stateful service correlation.
//!
//! [`reader`] — little-endian cursor over OPC UA binary bytes
//! [`datetime`] — Windows FILETIME → microseconds-since-epoch conversion
//! [`node_id`] — NodeId / ExpandedNodeId decoding into [`crate::bronze::OpcUaNodeId`]
//! [`variant`] — Variant decoding into [`crate::bronze::PointValue`]
//! [`data_value`] — DataValue decoding (value + status + timestamps)
//! [`services`] — ReadRequest / ReadResponse body parsers
//! [`state`] — pending-read correlation table (`secure_channel_id`, `request_id`) → NodeIds
//! [`decoder`] — orchestrating [`OpcUaServiceDecoder`]

pub mod data_value;
pub mod datetime;
pub mod decoder;
pub mod node_id;
pub mod reader;
pub mod services;
pub mod state;
pub mod variant;

pub use decoder::OpcUaServiceDecoder;
