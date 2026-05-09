//! Generic fanout point for MQTT PUBLISH payload decoders.
//!
//! The MQTT decoder in the engine extracts topic + payload bytes for every
//! PUBLISH frame. Sub-protocols layered on MQTT (Sparkplug B, OPC UA over MQTT
//! UADP, vendor JSON schemas) are dispatched through implementations of
//! [`MqttPayloadDecoder`] in priority order. The first decoder whose
//! [`MqttPayloadDecoder::try_decode`] returns a non-empty event vector wins;
//! subsequent decoders are skipped for that frame.
//!
//! Priority slots (lower runs first):
//! - `100` — Sparkplug B (`spBv1.0/...`)
//! - `200` — reserved for OPC UA UADP
//! - `300` — reserved for known vendor schemas (HiveMQ Edge, Cirrus Link Modules)
//! - `1000` — last-resort generic JSON

use std::net::SocketAddr;

use crate::bronze::BronzeEvent;

/// Context handed to an [`MqttPayloadDecoder`] for a single MQTT PUBLISH frame.
#[derive(Debug, Clone)]
pub struct MqttPublishContext<'a> {
    /// The 5-tuple side identified as the broker by port heuristic
    /// (the side whose port is 1883 or 8883). Used as a stable key when keeping
    /// per-session state across many MQTT clients connected to one broker.
    pub broker_endpoint: SocketAddr,
    /// Full 5-tuple as observed.
    pub flow_5tuple: FlowFiveTuple,
    /// MQTT client_id from the prior CONNECT on this flow, when known.
    /// Decoders should not require this — it may be absent if capture began
    /// mid-session.
    pub client_id: Option<&'a str>,
    pub topic: &'a str,
    pub payload: &'a [u8],
    pub retain: bool,
    pub qos: u8,
    /// Microseconds since Unix epoch when the capture observed the frame.
    /// Decoders that emit `ProcessReading` should carry this as `observed_ts`.
    pub packet_ts_us: u64,
    /// VLAN id from the packet, when tagged.
    pub vlan_id: Option<u16>,
    /// Source MAC of the publishing side of the flow (the non-broker side).
    pub publisher_mac: [u8; 6],
}

/// Five-tuple identifying a flow.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct FlowFiveTuple {
    pub src: SocketAddr,
    pub dst: SocketAddr,
    /// Transport protocol number (6 = TCP).
    pub transport: u8,
}

/// A pluggable decoder for MQTT PUBLISH payloads. Implementations are stateful;
/// the engine instantiates one per `DpiEngine` and feeds it every PUBLISH frame
/// matching its priority.
pub trait MqttPayloadDecoder: Send {
    /// Diagnostic name (e.g. `"sparkplug_b"`).
    fn name(&self) -> &'static str;

    /// Inspect the publish and return any Bronze events derived from it.
    /// Returning an empty vec means "I looked but this isn't for me" — the
    /// dispatcher will continue to the next registered decoder.
    fn try_decode(&mut self, ctx: &MqttPublishContext<'_>) -> Vec<BronzeEvent>;
}
