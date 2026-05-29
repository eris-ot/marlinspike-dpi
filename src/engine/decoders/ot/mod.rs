//! OT/ICS protocol `SessionDecoder` impls.
//!
//! Members: BACnet, Modbus, DNP3, IEC 60870-5-104, IEC 61850 (MMS/GOOSE/SV),
//! S7comm, PROFINET, EtherNet/IP (CIP + PCCC dispatch), OPC UA, OMRON FINS,
//! HART-IP, EtherCAT. Each protocol lives in its own sub-module.

use std::net::{IpAddr, Ipv4Addr};

use crate::registry::{PacketContext, format_mac};

#[cfg(feature = "ab_csp")]
pub(crate) mod ab_csp;
#[cfg(feature = "ads")]
pub(crate) mod ads;
#[cfg(feature = "avtp")]
pub(crate) mod avtp;
#[cfg(feature = "bacnet")]
pub(crate) mod bacnet;
#[cfg(feature = "bacnet_sc")]
pub(crate) mod bacnet_sc;
#[cfg(feature = "cip_safety")]
pub(crate) mod cip_safety;
#[cfg(feature = "dnp3")]
pub(crate) mod dnp3;
#[cfg(feature = "dnp3_sav5")]
pub(crate) mod dnp3_sav5;
#[cfg(feature = "eip_io")]
pub(crate) mod eip_io;
#[cfg(feature = "ethercat")]
pub(crate) mod ethercat;
#[cfg(feature = "ethernet_ip")]
pub(crate) mod ethernet_ip;
#[cfg(feature = "ff_hse")]
pub(crate) mod ff_hse;
#[cfg(feature = "ge_srtp")]
pub(crate) mod ge_srtp;
#[cfg(feature = "gvcp")]
pub(crate) mod gvcp;
#[cfg(feature = "hart_ip")]
pub(crate) mod hart_ip;
#[cfg(feature = "iec104")]
pub(crate) mod iec104;
#[cfg(feature = "iec61850")]
pub(crate) mod iec61850;
#[cfg(feature = "melsec")]
pub(crate) mod melsec;
#[cfg(feature = "modbus")]
pub(crate) mod modbus;
#[cfg(feature = "modbus_udp")]
pub(crate) mod modbus_udp;
#[cfg(feature = "fins")]
pub(crate) mod omron_fins;
#[cfg(feature = "opc_classic")]
pub(crate) mod opc_classic;
#[cfg(feature = "opc_ua")]
pub(crate) mod opc_ua;
#[cfg(feature = "opc_ua_pubsub")]
pub(crate) mod opc_ua_pubsub;
#[cfg(feature = "osi_pi")]
pub(crate) mod osi_pi;
#[cfg(feature = "powerlink")]
pub(crate) mod powerlink;
#[cfg(feature = "profinet")]
pub(crate) mod profinet;
#[cfg(feature = "ptp")]
pub(crate) mod ptp;
#[cfg(feature = "roc_plus")]
pub(crate) mod roc_plus;
#[cfg(feature = "s7comm")]
pub(crate) mod s7comm;
#[cfg(feature = "sercos")]
pub(crate) mod sercos;
#[cfg(feature = "tristation")]
pub(crate) mod tristation;
#[cfg(feature = "umas")]
pub(crate) mod umas;
#[cfg(feature = "vnet_ip")]
pub(crate) mod vnet_ip;

/// Normalise an operation label to `snake_case`, falling back to `fallback`
/// if the result would be empty.  Used by IT and OT decoders alike.
#[allow(dead_code)] // used by a subset of OT decoders; may be gated out
pub(crate) fn normalize_operation_name(label: &str, fallback: &str) -> String {
    let mut normalized = String::new();
    let mut last_was_separator = true;

    for ch in label.chars() {
        if ch.is_ascii_alphanumeric() {
            normalized.push(ch.to_ascii_lowercase());
            last_was_separator = false;
        } else if !last_was_separator {
            normalized.push('_');
            last_was_separator = true;
        }
    }

    while normalized.ends_with('_') {
        normalized.pop();
    }

    if normalized.is_empty() {
        fallback.to_string()
    } else {
        normalized
    }
}

/// Asset key derived from source IP; falls back to MAC when IP is unspecified.
#[allow(dead_code)] // used by a subset of OT decoders; may be gated out
pub(super) fn context_asset_key(context: &PacketContext) -> String {
    match context.src_ip {
        IpAddr::V4(ip) if ip != Ipv4Addr::UNSPECIFIED => ip.to_string(),
        _ => format_mac(&context.src_mac),
    }
}

/// Asset key derived from destination IP; falls back to MAC when IP is unspecified.
#[allow(dead_code)] // used by a subset of OT decoders; may be gated out
pub(super) fn context_remote_asset_key(context: &PacketContext) -> String {
    match context.dst_ip {
        IpAddr::V4(ip) if ip != Ipv4Addr::UNSPECIFIED => ip.to_string(),
        _ => format_mac(&context.dst_mac),
    }
}
