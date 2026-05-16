//! OCSF (Open Cybersecurity Schema Framework) renderer.
//!
//! Maps `BronzeEvent`s to OCSF records. Each event becomes one OCSF JSON object.
//!
//! Class dispatch:
//! - `ProtocolTransaction`:
//!   - `dns` → DNS Activity (4003)
//!   - `http` → HTTP Activity (4002)
//!   - `ssh` → SSH Activity (4007)
//!   - `smb*` → SMB Activity (4006)
//!   - `kerberos*`, `ldap*` → Authentication (3002)
//!   - everything else → Network Activity (4001)
//! - `AssetObservation` → Device Inventory Info (5001)
//! - `ParseAnomaly` → Detection Finding (2004)
//! - `ProcessReading`, `ExtractedArtifact`, `TopologyObservation` → not mapped
//!   (return `None`); OCSF has no natural class for OT process telemetry or
//!   generic wire artifacts. Use Bronze JSON or `output::influx_line` for those.
//!
//! Protocol-specific richness that has no first-class OCSF field is preserved
//! in `unmapped` so consumers can recover it without losing information.
//!
//! OCSF reference: <https://schema.ocsf.io/>
//!
//! Targeted schema version: see [`OCSF_SCHEMA_VERSION`].

use serde_json::{Map, Value, json};

use crate::bronze::{
    AssetObservation, BronzeEvent, BronzeEventFamily, EventEnvelope, ParseAnomaly,
    ProtocolTransaction, TransportProtocol,
};

/// OCSF schema version this renderer targets.
pub const OCSF_SCHEMA_VERSION: &str = "1.4.0";

const PRODUCT_NAME: &str = "marlinspike-dpi";
const VENDOR_NAME: &str = "Marlinspike";

/// Render a `BronzeEvent` to an OCSF record. Returns `None` for event families
/// without an OCSF mapping (`ProcessReading`, `ExtractedArtifact`,
/// `TopologyObservation`).
pub fn render_event(event: &BronzeEvent) -> Option<Value> {
    match &event.family {
        BronzeEventFamily::ProtocolTransaction(tx) => Some(render_protocol_transaction(event, tx)),
        BronzeEventFamily::AssetObservation(obs) => Some(render_asset_observation(event, obs)),
        BronzeEventFamily::ParseAnomaly(an) => Some(render_parse_anomaly(event, an)),
        BronzeEventFamily::ProcessReading(_)
        | BronzeEventFamily::ExtractedArtifact(_)
        | BronzeEventFamily::TopologyObservation(_) => None,
    }
}

/// Render one event to a single-line JSON string. `None` for unmapped families.
pub fn render_event_string(event: &BronzeEvent) -> Option<String> {
    render_event(event).and_then(|v| serde_json::to_string(&v).ok())
}

/// Render many events as newline-delimited JSON (NDJSON). Events without an
/// OCSF mapping are skipped.
pub fn render_ndjson(events: &[BronzeEvent]) -> String {
    let mut out = String::new();
    for ev in events {
        if let Some(s) = render_event_string(ev) {
            if !out.is_empty() {
                out.push('\n');
            }
            out.push_str(&s);
        }
    }
    out
}

// ─── Class dispatch ────────────────────────────────────────────────────────

#[derive(Clone, Copy)]
struct OcsfClass {
    class_uid: u32,
    class_name: &'static str,
    category_uid: u32,
    category_name: &'static str,
}

const NETWORK_ACTIVITY: OcsfClass = OcsfClass {
    class_uid: 4001,
    class_name: "Network Activity",
    category_uid: 4,
    category_name: "Network Activity",
};
const HTTP_ACTIVITY: OcsfClass = OcsfClass {
    class_uid: 4002,
    class_name: "HTTP Activity",
    category_uid: 4,
    category_name: "Network Activity",
};
const DNS_ACTIVITY: OcsfClass = OcsfClass {
    class_uid: 4003,
    class_name: "DNS Activity",
    category_uid: 4,
    category_name: "Network Activity",
};
const SMB_ACTIVITY: OcsfClass = OcsfClass {
    class_uid: 4006,
    class_name: "SMB Activity",
    category_uid: 4,
    category_name: "Network Activity",
};
const SSH_ACTIVITY: OcsfClass = OcsfClass {
    class_uid: 4007,
    class_name: "SSH Activity",
    category_uid: 4,
    category_name: "Network Activity",
};
const AUTHENTICATION: OcsfClass = OcsfClass {
    class_uid: 3002,
    class_name: "Authentication",
    category_uid: 3,
    category_name: "Identity & Access Management",
};
const DEVICE_INVENTORY: OcsfClass = OcsfClass {
    class_uid: 5001,
    class_name: "Device Inventory Info",
    category_uid: 5,
    category_name: "Discovery",
};
const DETECTION_FINDING: OcsfClass = OcsfClass {
    class_uid: 2004,
    class_name: "Detection Finding",
    category_uid: 2,
    category_name: "Findings",
};

fn classify_protocol(proto: &str) -> OcsfClass {
    match proto {
        "dns" => DNS_ACTIVITY,
        "http" => HTTP_ACTIVITY,
        "ssh" => SSH_ACTIVITY,
        p if p.starts_with("smb") => SMB_ACTIVITY,
        p if p.starts_with("kerberos") || p.starts_with("ldap") => AUTHENTICATION,
        _ => NETWORK_ACTIVITY,
    }
}

// ─── Common base record ────────────────────────────────────────────────────

fn base_record(event: &BronzeEvent, class: &OcsfClass) -> Map<String, Value> {
    let time_ms = event.envelope.timestamp.timestamp_millis();
    let mut m = Map::new();
    m.insert("class_uid".into(), json!(class.class_uid));
    m.insert("class_name".into(), json!(class.class_name));
    m.insert("category_uid".into(), json!(class.category_uid));
    m.insert("category_name".into(), json!(class.category_name));
    m.insert("time".into(), json!(time_ms));
    m.insert("metadata".into(), metadata(event));
    m.insert("severity_id".into(), json!(1));
    m.insert("severity".into(), json!("Informational"));
    m
}

fn metadata(event: &BronzeEvent) -> Value {
    json!({
        "version": OCSF_SCHEMA_VERSION,
        "product": {
            "name": PRODUCT_NAME,
            "vendor_name": VENDOR_NAME,
        },
        "uid": event.event_id,
        "correlation_uid": event.capture_id,
        "log_name": "bronze",
        "log_version": event.schema_version,
        "logged_time": event.envelope.timestamp.timestamp_millis(),
    })
}

// ─── ProtocolTransaction → Network/HTTP/DNS/SMB/SSH/Authentication ─────────

fn render_protocol_transaction(event: &BronzeEvent, tx: &ProtocolTransaction) -> Value {
    let proto = event.protocol().unwrap_or("");
    let class = classify_protocol(proto);
    let mut r = base_record(event, &class);

    let (activity_id, activity_name) = activity_for(&class, proto, tx);
    let type_uid = class.class_uid * 100 + activity_id;
    r.insert("activity_id".into(), json!(activity_id));
    r.insert("activity_name".into(), json!(activity_name));
    r.insert("type_uid".into(), json!(type_uid));
    r.insert(
        "type_name".into(),
        json!(format!("{}: {}", class.class_name, activity_name)),
    );

    let (status_id, status_name) = status_for(&tx.status);
    r.insert("status_id".into(), json!(status_id));
    r.insert("status".into(), json!(status_name));
    if status_name != tx.status && !tx.status.is_empty() {
        r.insert("status_detail".into(), json!(&tx.status));
    }

    r.insert("connection_info".into(), connection_info(&event.envelope));
    r.insert("src_endpoint".into(), endpoint(&event.envelope, Side::Src));
    r.insert("dst_endpoint".into(), endpoint(&event.envelope, Side::Dst));

    r.insert(
        "traffic".into(),
        json!({
            "bytes": event.envelope.bytes_count,
            "packets": event.envelope.packet_count,
        }),
    );

    if let Some(msg) = summary_message(tx) {
        r.insert("message".into(), json!(msg));
    }

    if let Some(extra) = class_specific(&class, proto, tx) {
        for (k, v) in extra {
            r.insert(k, v);
        }
    }

    r.insert("unmapped".into(), unmapped_for_tx(proto, tx));

    Value::Object(r)
}

fn activity_for(class: &OcsfClass, proto: &str, tx: &ProtocolTransaction) -> (u32, &'static str) {
    match class.class_uid {
        // HTTP Activity: map by method.
        4002 => match tx.operation.to_ascii_uppercase().as_str() {
            "CONNECT" => (1, "Connect"),
            "DELETE" => (2, "Delete"),
            "GET" => (3, "Get"),
            "HEAD" => (4, "Head"),
            "OPTIONS" => (5, "Options"),
            "POST" => (6, "Post"),
            "PUT" => (7, "Put"),
            "TRACE" => (8, "Trace"),
            _ => (99, "Other"),
        },
        // DNS Activity: query/response/traffic.
        4003 => match tx.status.as_str() {
            "request" | "query" => (1, "Query"),
            "response" => (2, "Response"),
            _ => (3, "Traffic"),
        },
        // Authentication: try to detect logon vs ticket vs other.
        3002 => {
            let op = tx.operation.to_ascii_lowercase();
            if op.contains("as_req") || op.contains("as-req") {
                (3, "Authentication Ticket")
            } else if op.contains("tgs_req") || op.contains("tgs-req") {
                (4, "Service Ticket Request")
            } else if op.contains("logoff") || op.contains("unbind") {
                (2, "Logoff")
            } else if op.contains("bind") || op.contains("logon") || proto.starts_with("kerberos") {
                (1, "Logon")
            } else {
                (99, "Other")
            }
        }
        // Network/SMB/SSH: Traffic by default; failures map to Fail.
        _ => {
            let (sid, _) = status_for(&tx.status);
            if sid == 2 {
                (4, "Fail")
            } else {
                (6, "Traffic")
            }
        }
    }
}

fn class_specific(
    class: &OcsfClass,
    proto: &str,
    tx: &ProtocolTransaction,
) -> Option<Vec<(String, Value)>> {
    match class.class_uid {
        4002 => Some(vec![(
            "http_request".into(),
            json!({
                "http_method": tx.operation,
                "url": tx
                    .object_refs
                    .first()
                    .cloned()
                    .or_else(|| tx.attributes.get("url").cloned()),
                "user_agent": tx.attributes.get("user_agent"),
                "version": tx.attributes.get("http_version"),
            }),
        )]),
        4003 => {
            let qname = tx
                .object_refs
                .first()
                .cloned()
                .or_else(|| tx.attributes.get("query_name").cloned());
            let qtype = tx.attributes.get("query_type").cloned();
            Some(vec![(
                "query".into(),
                json!({
                    "hostname": qname,
                    "type": qtype,
                }),
            )])
        }
        4006 | 4007 => Some(vec![(
            "protocol_ver".into(),
            json!(tx.attributes.get("version")),
        )]),
        3002 => {
            let user = tx
                .attributes
                .get("principal")
                .or_else(|| tx.attributes.get("username"))
                .or_else(|| tx.attributes.get("user_name"))
                .cloned();
            Some(vec![
                ("user".into(), json!({ "name": user })),
                ("auth_protocol".into(), json!(proto)),
            ])
        }
        _ => None,
    }
}

fn unmapped_for_tx(proto: &str, tx: &ProtocolTransaction) -> Value {
    let mut m = Map::new();
    m.insert("protocol".into(), json!(proto));
    m.insert("operation".into(), json!(tx.operation));
    if !tx.object_refs.is_empty() {
        m.insert("object_refs".into(), json!(tx.object_refs));
    }
    if !tx.values.is_empty() {
        let values: Vec<Value> = tx
            .values
            .iter()
            .map(|v| json!({ "object_ref": v.object_ref, "value": v.value }))
            .collect();
        m.insert("values".into(), Value::Array(values));
    }
    if !tx.attributes.is_empty() {
        m.insert(
            "attributes".into(),
            Value::Object(
                tx.attributes
                    .iter()
                    .map(|(k, v)| (k.clone(), Value::String(v.clone())))
                    .collect(),
            ),
        );
    }
    if let Some(req) = &tx.request_summary {
        m.insert("request_summary".into(), json!(req));
    }
    if let Some(resp) = &tx.response_summary {
        m.insert("response_summary".into(), json!(resp));
    }
    if let Some(modbus) = &tx.modbus {
        m.insert(
            "modbus".into(),
            serde_json::to_value(modbus).unwrap_or(Value::Null),
        );
    }
    if let Some(pf) = &tx.protocol_fields {
        m.insert(
            "protocol_fields".into(),
            serde_json::to_value(pf).unwrap_or(Value::Null),
        );
    }
    Value::Object(m)
}

fn summary_message(tx: &ProtocolTransaction) -> Option<String> {
    match (&tx.request_summary, &tx.response_summary) {
        (Some(req), Some(resp)) => Some(format!("{req} → {resp}")),
        (Some(req), None) => Some(req.clone()),
        (None, Some(resp)) => Some(resp.clone()),
        (None, None) => None,
    }
}

// ─── AssetObservation → Device Inventory Info ──────────────────────────────

fn render_asset_observation(event: &BronzeEvent, obs: &AssetObservation) -> Value {
    let mut r = base_record(event, &DEVICE_INVENTORY);
    r.insert("activity_id".into(), json!(1));
    r.insert("activity_name".into(), json!("Log"));
    r.insert(
        "type_uid".into(),
        json!(DEVICE_INVENTORY.class_uid * 100 + 1),
    );
    r.insert(
        "type_name".into(),
        json!(format!("{}: Log", DEVICE_INVENTORY.class_name)),
    );

    let mut device = Map::new();
    device.insert("uid".into(), json!(obs.asset_key));
    if let Some(role) = &obs.role {
        device.insert("type".into(), json!(role));
    }
    if let Some(vendor) = &obs.vendor {
        device.insert("vendor_name".into(), json!(vendor));
    }
    if let Some(model) = &obs.model {
        device.insert("model".into(), json!(model));
    }
    if let Some(fw) = &obs.firmware {
        device.insert("os".into(), json!({ "version": fw }));
    }
    if let Some(hostname) = obs.hostnames.first() {
        device.insert("hostname".into(), json!(hostname));
    }
    if let Some(ip) = event.src_ip() {
        device.insert("ip".into(), json!(ip));
    }
    if let Some(mac) = event.src_mac() {
        device.insert("mac".into(), json!(mac));
    }
    r.insert("device".into(), Value::Object(device));

    let mut unmapped = Map::new();
    unmapped.insert("protocols".into(), json!(obs.protocols));
    if obs.hostnames.len() > 1 {
        unmapped.insert("hostnames".into(), json!(obs.hostnames));
    }
    if !obs.identifiers.is_empty() {
        unmapped.insert(
            "identifiers".into(),
            Value::Object(
                obs.identifiers
                    .iter()
                    .map(|(k, v)| (k.clone(), Value::String(v.clone())))
                    .collect(),
            ),
        );
    }
    r.insert("unmapped".into(), Value::Object(unmapped));

    Value::Object(r)
}

// ─── ParseAnomaly → Detection Finding ──────────────────────────────────────

fn render_parse_anomaly(event: &BronzeEvent, an: &ParseAnomaly) -> Value {
    let mut r = base_record(event, &DETECTION_FINDING);
    let (sev_id, sev_name) = anomaly_severity(&an.severity);
    r.insert("severity_id".into(), json!(sev_id));
    r.insert("severity".into(), json!(sev_name));

    r.insert("activity_id".into(), json!(1));
    r.insert("activity_name".into(), json!("Create"));
    r.insert(
        "type_uid".into(),
        json!(DETECTION_FINDING.class_uid * 100 + 1),
    );
    r.insert(
        "type_name".into(),
        json!(format!("{}: Create", DETECTION_FINDING.class_name)),
    );

    r.insert(
        "finding_info".into(),
        json!({
            "title": format!("Parse anomaly in {}", an.decoder),
            "uid": event.event_id,
            "desc": an.reason,
            "types": [an.decoder.clone()],
        }),
    );

    r.insert("src_endpoint".into(), endpoint(&event.envelope, Side::Src));
    r.insert("dst_endpoint".into(), endpoint(&event.envelope, Side::Dst));

    r.insert(
        "unmapped".into(),
        json!({
            "decoder": an.decoder,
            "reason": an.reason,
            "raw_excerpt_hex": an.raw_excerpt_hex,
            "protocol": event.protocol(),
        }),
    );

    Value::Object(r)
}

fn anomaly_severity(s: &str) -> (u32, &'static str) {
    match s.to_ascii_lowercase().as_str() {
        "low" => (2, "Low"),
        "medium" => (3, "Medium"),
        "high" => (4, "High"),
        "critical" => (5, "Critical"),
        _ => (1, "Informational"),
    }
}

// ─── Shared building blocks ────────────────────────────────────────────────

#[derive(Clone, Copy)]
enum Side {
    Src,
    Dst,
}

fn endpoint(env: &EventEnvelope, side: Side) -> Value {
    let (mac, ip, port) = match side {
        Side::Src => (env.src_mac.as_deref(), env.src_ip.as_deref(), env.src_port),
        Side::Dst => (env.dst_mac.as_deref(), env.dst_ip.as_deref(), env.dst_port),
    };
    let mut m = Map::new();
    if let Some(ip) = ip {
        m.insert("ip".into(), json!(ip));
    }
    if let Some(port) = port {
        m.insert("port".into(), json!(port));
    }
    if let Some(mac) = mac {
        m.insert("mac".into(), json!(mac));
    }
    if let Some(vlan) = env.vlan_id {
        m.insert("vlan_uid".into(), json!(vlan.to_string()));
    }
    Value::Object(m)
}

fn connection_info(env: &EventEnvelope) -> Value {
    let (num, name) = transport_iana(env.transport);
    json!({
        "protocol_num": num,
        "protocol_name": name,
        "direction_id": 0,
        "direction": "Unknown",
    })
}

fn transport_iana(t: TransportProtocol) -> (i32, &'static str) {
    match t {
        TransportProtocol::Tcp => (6, "tcp"),
        TransportProtocol::Udp => (17, "udp"),
        TransportProtocol::Icmp => (1, "icmp"),
        TransportProtocol::Ipv4 => (-1, "ipv4"),
        TransportProtocol::Arp => (-1, "arp"),
        TransportProtocol::Ethernet => (-1, "ethernet"),
        TransportProtocol::Unknown => (-1, "unknown"),
    }
}

fn status_for(s: &str) -> (u32, &'static str) {
    let lower = s.to_ascii_lowercase();
    if lower.is_empty() {
        return (0, "Unknown");
    }
    if matches!(lower.as_str(), "ok" | "success" | "successful") {
        return (1, "Success");
    }
    if lower.contains("error")
        || lower.contains("fail")
        || lower.contains("exception")
        || lower.contains("reject")
        || lower.contains("denied")
        || lower.contains("unauthorized")
        || lower.contains("abort")
        || lower.contains("timeout")
        || lower.contains("unreachable")
    {
        return (2, "Failure");
    }
    (99, "Other")
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use chrono::{DateTime, Utc};

    use super::*;
    use crate::bronze::{
        AssetObservation, BRONZE_SCHEMA_VERSION, BronzeEvent, BronzeEventFamily, EventEnvelope,
        ParseAnomaly, ProtocolTransaction, TransportProtocol,
    };

    fn envelope(proto: &str) -> EventEnvelope {
        EventEnvelope {
            timestamp: DateTime::<Utc>::from_timestamp(1_700_000_000, 0).unwrap(),
            interface_id: 0,
            segment_hash: "seg".into(),
            frame_index: 0,
            session_key: "k".into(),
            src_mac: Some("aa:bb:cc:dd:ee:ff".into()),
            dst_mac: Some("11:22:33:44:55:66".into()),
            src_ip: Some("10.0.0.1".into()),
            dst_ip: Some("10.0.0.2".into()),
            src_port: Some(50_000),
            dst_port: Some(502),
            vlan_id: None,
            transport: TransportProtocol::Tcp,
            protocol: Some(proto.into()),
            bytes_count: 128,
            packet_count: 2,
        }
    }

    fn tx_event(proto: &str, op: &str, status: &str) -> BronzeEvent {
        BronzeEvent {
            event_id: "evt-1".into(),
            capture_id: "cap-1".into(),
            schema_version: BRONZE_SCHEMA_VERSION.into(),
            envelope: envelope(proto),
            family: BronzeEventFamily::ProtocolTransaction(ProtocolTransaction {
                operation: op.into(),
                status: status.into(),
                request_summary: Some("REQ".into()),
                response_summary: Some("RESP".into()),
                object_refs: vec!["target/one".into()],
                values: vec![],
                attributes: BTreeMap::new(),
                modbus: None,
                protocol_fields: None,
            }),
        }
    }

    #[test]
    fn modbus_maps_to_network_activity() {
        let ev = tx_event("modbus", "read_holding_registers", "ok");
        let v = render_event(&ev).expect("rendered");
        assert_eq!(v["class_uid"], 4001);
        assert_eq!(v["category_uid"], 4);
        assert_eq!(v["status_id"], 1);
        assert_eq!(v["activity_id"], 6);
        assert_eq!(v["type_uid"], 4001 * 100 + 6);
        assert_eq!(v["src_endpoint"]["ip"], "10.0.0.1");
        assert_eq!(v["dst_endpoint"]["port"], 502);
        assert_eq!(v["connection_info"]["protocol_num"], 6);
        assert_eq!(v["unmapped"]["protocol"], "modbus");
        assert_eq!(v["unmapped"]["operation"], "read_holding_registers");
    }

    #[test]
    fn http_get_maps_to_http_activity() {
        let ev = tx_event("http", "GET", "ok");
        let v = render_event(&ev).expect("rendered");
        assert_eq!(v["class_uid"], 4002);
        assert_eq!(v["activity_id"], 3);
        assert_eq!(v["activity_name"], "Get");
        assert_eq!(v["http_request"]["http_method"], "GET");
        assert_eq!(v["http_request"]["url"], "target/one");
    }

    #[test]
    fn dns_response_maps_to_dns_activity() {
        let ev = tx_event("dns", "query", "response");
        let v = render_event(&ev).expect("rendered");
        assert_eq!(v["class_uid"], 4003);
        assert_eq!(v["activity_id"], 2);
        assert_eq!(v["activity_name"], "Response");
    }

    #[test]
    fn smb_maps_to_smb_activity() {
        let ev = tx_event("smb2_message", "open", "ok");
        let v = render_event(&ev).expect("rendered");
        assert_eq!(v["class_uid"], 4006);
    }

    #[test]
    fn ssh_maps_to_ssh_activity() {
        let ev = tx_event("ssh", "banner", "observed");
        let v = render_event(&ev).expect("rendered");
        assert_eq!(v["class_uid"], 4007);
    }

    #[test]
    fn kerberos_maps_to_authentication_logon() {
        let ev = tx_event("kerberos", "AS-REQ", "ok");
        let v = render_event(&ev).expect("rendered");
        assert_eq!(v["class_uid"], 3002);
        assert_eq!(v["category_uid"], 3);
        assert_eq!(v["activity_id"], 3);
        assert_eq!(v["activity_name"], "Authentication Ticket");
        assert_eq!(v["auth_protocol"], "kerberos");
    }

    #[test]
    fn ldap_bind_maps_to_authentication_logon() {
        let ev = tx_event("ldap", "bind_request", "ok");
        let v = render_event(&ev).expect("rendered");
        assert_eq!(v["class_uid"], 3002);
        assert_eq!(v["activity_id"], 1);
    }

    #[test]
    fn failure_status_maps_to_failure() {
        let ev = tx_event("modbus", "write_register", "exception");
        let v = render_event(&ev).expect("rendered");
        assert_eq!(v["status_id"], 2);
        assert_eq!(v["status"], "Failure");
        assert_eq!(v["activity_id"], 4);
        assert_eq!(v["activity_name"], "Fail");
    }

    #[test]
    fn other_status_keeps_detail() {
        let ev = tx_event("modbus", "read_holding_registers", "partial_request");
        let v = render_event(&ev).expect("rendered");
        assert_eq!(v["status_id"], 99);
        assert_eq!(v["status"], "Other");
        assert_eq!(v["status_detail"], "partial_request");
    }

    #[test]
    fn asset_observation_maps_to_device_inventory() {
        let env = envelope("opc_ua");
        let ev = BronzeEvent {
            event_id: "evt-2".into(),
            capture_id: "cap-1".into(),
            schema_version: BRONZE_SCHEMA_VERSION.into(),
            envelope: env,
            family: BronzeEventFamily::AssetObservation(AssetObservation {
                asset_key: "asset:plc-1".into(),
                role: Some("plc".into()),
                vendor: Some("Siemens".into()),
                model: Some("S7-1500".into()),
                firmware: Some("V2.9".into()),
                hostnames: vec!["plc-1.local".into()],
                protocols: vec!["s7comm".into(), "opc_ua".into()],
                identifiers: BTreeMap::new(),
            }),
        };
        let v = render_event(&ev).expect("rendered");
        assert_eq!(v["class_uid"], 5001);
        assert_eq!(v["category_uid"], 5);
        assert_eq!(v["device"]["uid"], "asset:plc-1");
        assert_eq!(v["device"]["vendor_name"], "Siemens");
        assert_eq!(v["device"]["model"], "S7-1500");
        assert_eq!(v["device"]["hostname"], "plc-1.local");
        assert_eq!(v["device"]["os"]["version"], "V2.9");
    }

    #[test]
    fn parse_anomaly_maps_to_detection_finding() {
        let ev = BronzeEvent {
            event_id: "evt-3".into(),
            capture_id: "cap-1".into(),
            schema_version: BRONZE_SCHEMA_VERSION.into(),
            envelope: envelope("modbus"),
            family: BronzeEventFamily::ParseAnomaly(ParseAnomaly {
                decoder: "modbus".into(),
                severity: "high".into(),
                reason: "truncated PDU".into(),
                raw_excerpt_hex: "deadbeef".into(),
            }),
        };
        let v = render_event(&ev).expect("rendered");
        assert_eq!(v["class_uid"], 2004);
        assert_eq!(v["category_uid"], 2);
        assert_eq!(v["severity_id"], 4);
        assert_eq!(v["severity"], "High");
        assert_eq!(v["finding_info"]["desc"], "truncated PDU");
        assert_eq!(v["unmapped"]["raw_excerpt_hex"], "deadbeef");
    }

    #[test]
    fn process_reading_returns_none() {
        use crate::bronze::{
            ModbusRegKind, PointIdentifier, PointValue, ProcessReading, RawQuality,
        };
        let ev = BronzeEvent {
            event_id: "evt-4".into(),
            capture_id: "cap-1".into(),
            schema_version: BRONZE_SCHEMA_VERSION.into(),
            envelope: envelope("modbus"),
            family: BronzeEventFamily::ProcessReading(ProcessReading {
                source_protocol: "modbus".into(),
                point_id: PointIdentifier::ModbusRegister {
                    unit_id: 1,
                    addr: 0,
                    register_type: ModbusRegKind::HoldingRegister,
                },
                value: PointValue::UInt16(1),
                quality: RawQuality::None,
                source_ts: None,
                observed_ts: 0,
            }),
        };
        assert!(render_event(&ev).is_none());
        assert!(render_event_string(&ev).is_none());
    }

    #[test]
    fn render_ndjson_skips_unmapped() {
        use crate::bronze::{
            ModbusRegKind, PointIdentifier, PointValue, ProcessReading, RawQuality,
        };
        let ev_tx = tx_event("modbus", "read_holding_registers", "ok");
        let ev_pr = BronzeEvent {
            event_id: "evt-pr".into(),
            capture_id: "cap-1".into(),
            schema_version: BRONZE_SCHEMA_VERSION.into(),
            envelope: envelope("modbus"),
            family: BronzeEventFamily::ProcessReading(ProcessReading {
                source_protocol: "modbus".into(),
                point_id: PointIdentifier::ModbusRegister {
                    unit_id: 1,
                    addr: 0,
                    register_type: ModbusRegKind::HoldingRegister,
                },
                value: PointValue::UInt16(1),
                quality: RawQuality::None,
                source_ts: None,
                observed_ts: 0,
            }),
        };
        let s = render_ndjson(&[ev_tx, ev_pr]);
        assert_eq!(s.lines().count(), 1, "process_reading should be skipped");
        assert!(s.contains("\"class_uid\":4001"));
    }

    #[test]
    fn metadata_carries_event_and_capture_uid() {
        let ev = tx_event("modbus", "read_holding_registers", "ok");
        let v = render_event(&ev).expect("rendered");
        assert_eq!(v["metadata"]["uid"], "evt-1");
        assert_eq!(v["metadata"]["correlation_uid"], "cap-1");
        assert_eq!(v["metadata"]["version"], OCSF_SCHEMA_VERSION);
        assert_eq!(v["metadata"]["product"]["name"], PRODUCT_NAME);
    }

    #[test]
    fn json_is_valid_and_roundtrips() {
        let ev = tx_event("modbus", "read_holding_registers", "ok");
        let s = render_event_string(&ev).expect("rendered");
        let v: Value = serde_json::from_str(&s).expect("valid JSON");
        assert_eq!(v["class_uid"], 4001);
    }
}
