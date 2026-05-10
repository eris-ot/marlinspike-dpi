//! OT/ICS protocol `SessionDecoder` impls.
//!
//! Members: BACnet, Modbus, DNP3, IEC 60870-5-104, IEC 61850 (MMS/GOOSE/SV),
//! S7comm, PROFINET, EtherNet/IP (CIP + PCCC dispatch), OPC UA, OMRON FINS,
//! HART-IP, EtherCAT. Each protocol lives in its own sub-module.

use std::net::{IpAddr, Ipv4Addr};

use crate::registry::{format_mac, PacketContext};

pub(crate) mod ab_csp;
pub(crate) mod ads;
pub(crate) mod bacnet;
pub(crate) mod bacnet_sc;
pub(crate) mod cip_safety;
pub(crate) mod dnp3;
pub(crate) mod dnp3_sav5;
pub(crate) mod ethercat;
pub(crate) mod ethernet_ip;
pub(crate) mod ge_srtp;
pub(crate) mod gvcp;
pub(crate) mod hart_ip;
pub(crate) mod iec104;
pub(crate) mod iec61850;
pub(crate) mod melsec;
pub(crate) mod modbus;
pub(crate) mod opc_classic;
pub(crate) mod opc_ua;
pub(crate) mod opc_ua_pubsub;
pub(crate) mod omron_fins;
pub(crate) mod osi_pi;
pub(crate) mod profinet;
pub(crate) mod s7comm;
pub(crate) mod tristation;
pub(crate) mod vnet_ip;

/// Normalise an operation label to `snake_case`, falling back to `fallback`
/// if the result would be empty.  Used by IT and OT decoders alike.
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
pub(super) fn context_asset_key(context: &PacketContext) -> String {
    match context.src_ip {
        IpAddr::V4(ip) if ip != Ipv4Addr::UNSPECIFIED => ip.to_string(),
        _ => format_mac(&context.src_mac),
    }
}

/// Asset key derived from destination IP; falls back to MAC when IP is unspecified.
pub(super) fn context_remote_asset_key(context: &PacketContext) -> String {
    match context.dst_ip {
        IpAddr::V4(ip) if ip != Ipv4Addr::UNSPECIFIED => ip.to_string(),
        _ => format_mac(&context.dst_mac),
    }
}
