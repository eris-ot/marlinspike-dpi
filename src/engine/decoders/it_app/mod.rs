//! IT application-protocol `SessionDecoder` impls — DNS, DHCP, SNMP, HTTP,
//! TLS, MQTT. Includes per-protocol helpers (DNS payload extraction, DHCP
//! status mapping, SNMP status mapping, TLS Client Hello parser) and the
//! MQTT-payload-decoder fanout context builder used to dispatch Sparkplug B
//! and other future MQTT-payload protocols.

#[cfg(feature = "dhcp")]
pub(crate) mod dhcp;
#[cfg(feature = "dns")]
pub(crate) mod dns;
#[cfg(feature = "http")]
pub(crate) mod http;
#[cfg(feature = "mqtt")]
pub(crate) mod mqtt;
#[cfg(feature = "snmp")]
pub(crate) mod snmp;
#[cfg(feature = "tls")]
pub(crate) mod tls;

#[cfg(feature = "mqtt")]
#[allow(unused_imports)] // consumed by a #[cfg(test)] block in engine/mod.rs
pub(crate) use mqtt::MqttDecoder;
