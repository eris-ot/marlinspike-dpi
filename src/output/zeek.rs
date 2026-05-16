//! Zeek-compatible JSON Streaming Log renderer.
//!
//! Maps Bronze v2 events to Zeek JSON Streaming Log format (one JSON object per
//! line with a `_path` field naming the log type). This is the format preferred
//! by current OT-Zeek deployments for SIEM ingest.
//!
//! Log type dispatch:
//! - Every event with a flow 4-tuple → `conn` (one per unique session_key, deduped)
//! - `ProtocolTransaction` where protocol == "dns" → `dns`
//! - `ProtocolTransaction` where protocol == "http" → `http`
//! - `ProtocolTransaction` where protocol == "ssl" or "tls" → `ssl`
//! - `ProtocolTransaction` where protocol == "ssh" → `ssh`
//! - `ProtocolTransaction` where protocol == "modbus" → `modbus`
//! - `ProtocolTransaction` where protocol == "dnp3" → `dnp3`
//! - `ProtocolTransaction` where protocol == "smb2*" → `smb_files` / `smb_mapping`
//! - `ProtocolTransaction` where protocol == "kerberos" → `kerberos`
//! - `ProtocolTransaction` where protocol == "ldap" → `ldap`
//! - `ProtocolTransaction` where protocol == "dhcp" → `dhcp`
//! - `ProtocolTransaction` where protocol == "ntp" → `ntp`
//! - `ProtocolTransaction` where protocol == "snmp" → `snmp`
//! - `ProtocolTransaction` where protocol == "rdp" → `rdp`
//! - `AssetObservation` → `software`
//! - `ParseAnomaly` → `weird`
//! - Unknown ICS protocols → `ics` (our added value over native Zeek)
//! - `ProcessReading` → not emitted (out of scope for Zeek log format)
//!
//! Reference: <https://docs.zeek.org/en/master/log-formats.html>

use std::collections::HashSet;

use serde_json::{Map, Value, json};

use crate::bronze::{
    AssetObservation, BronzeEvent, BronzeEventFamily, EventEnvelope, ParseAnomaly, ProtocolFields,
    ProtocolTransaction, TransportProtocol,
};

const SYSTEM_NAME: &str = "marlinspike-dpi";

// Base62 alphabet used by Zeek for UIDs (uppercase letters, lowercase letters, digits).
const BASE62: &[u8; 62] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
const UID_LEN: usize = 18;

/// Generate a Zeek-compatible UID (18-char base62) deterministically from a
/// session_key string. The same session_key always produces the same UID across
/// runs, so conn.log rows correlate correctly with protocol-specific log rows.
pub fn conn_uid(session_key: &str) -> String {
    // FNV-1a hash over the UTF-8 bytes of session_key, then expand to 18 chars.
    // Using two FNV-1a passes with different primes gives 128 bits of state —
    // enough to fill 18 base62 characters without visible patterns.
    let mut h1: u64 = 0xcbf2_9ce4_8422_2325;
    let mut h2: u64 = 0x517c_c1b7_2722_0a95;
    for &b in session_key.as_bytes() {
        h1 ^= b as u64;
        h1 = h1.wrapping_mul(0x0000_0100_0000_01b3);
        h2 ^= b as u64;
        h2 = h2.wrapping_mul(0x0000_0100_0000_019b);
    }
    // Mix the two halves together.
    h2 = h2.wrapping_add(h1.rotate_left(17));
    h1 = h1.wrapping_add(h2.rotate_right(31));

    let mut uid = [0u8; UID_LEN];
    // First 9 chars from h1, next 9 from h2.
    let mut val = h1;
    for slot in uid[..9].iter_mut() {
        *slot = BASE62[(val % 62) as usize];
        val /= 62;
    }
    val = h2;
    for slot in uid[9..].iter_mut() {
        *slot = BASE62[(val % 62) as usize];
        val /= 62;
    }
    String::from_utf8(uid.to_vec()).expect("all bytes are ASCII")
}

/// Format a `DateTime<Utc>` as an RFC 3339 / ISO 8601 string with microsecond
/// precision, as Zeek JSON logs use.
fn fmt_ts(ts: &chrono::DateTime<chrono::Utc>) -> String {
    ts.format("%Y-%m-%dT%H:%M:%S%.6fZ").to_string()
}

/// Build the common header fields present on every Zeek log row.
fn common_header(path: &str, event: &BronzeEvent) -> Map<String, Value> {
    let ts = fmt_ts(&event.envelope.timestamp);
    let uid = conn_uid(&event.envelope.session_key);
    let mut m = Map::new();
    m.insert("_path".into(), json!(path));
    m.insert("_write_ts".into(), json!(&ts));
    m.insert("_system_name".into(), json!(SYSTEM_NAME));
    m.insert("ts".into(), json!(&ts));
    m.insert("uid".into(), json!(uid));
    id_fields(&mut m, &event.envelope);
    m
}

/// Insert Zeek `id.*` connection-tuple fields into `m`.
fn id_fields(m: &mut Map<String, Value>, env: &EventEnvelope) {
    m.insert(
        "id.orig_h".into(),
        json!(env.src_ip.as_deref().unwrap_or("-")),
    );
    m.insert("id.orig_p".into(), json!(env.src_port.unwrap_or(0)));
    m.insert(
        "id.resp_h".into(),
        json!(env.dst_ip.as_deref().unwrap_or("-")),
    );
    m.insert("id.resp_p".into(), json!(env.dst_port.unwrap_or(0)));
}

fn transport_str(t: TransportProtocol) -> &'static str {
    match t {
        TransportProtocol::Tcp => "tcp",
        TransportProtocol::Udp => "udp",
        TransportProtocol::Icmp => "icmp",
        TransportProtocol::Ethernet => "ethernet",
        TransportProtocol::Arp => "arp",
        TransportProtocol::Ipv4 => "ipv4",
        TransportProtocol::Unknown => "-",
    }
}

// ─── conn log ─────────────────────────────────────────────────────────────────

fn render_conn(event: &BronzeEvent) -> Value {
    let mut m = common_header("conn", event);
    let env = &event.envelope;
    m.insert("proto".into(), json!(transport_str(env.transport)));
    m.insert(
        "service".into(),
        json!(env.protocol.as_deref().unwrap_or("-")),
    );
    m.insert("orig_bytes".into(), json!(env.bytes_count));
    m.insert("resp_bytes".into(), json!(0u64)); // Bronze bytes_count is total; resp split unknown
    // Derive conn_state from event status when available.
    let conn_state = match &event.family {
        BronzeEventFamily::ProtocolTransaction(tx) => conn_state_from_status(&tx.status),
        _ => "OTH",
    };
    m.insert("conn_state".into(), json!(conn_state));
    m.insert("orig_pkts".into(), json!(env.packet_count));
    Value::Object(m)
}

fn conn_state_from_status(status: &str) -> &'static str {
    let lower = status.to_ascii_lowercase();
    if matches!(
        lower.as_str(),
        "ok" | "success" | "successful" | "complete" | "response"
    ) {
        "SF"
    } else if lower.contains("reset") || lower.contains("rst") {
        "RSTR"
    } else if lower.contains("timeout") {
        "S0"
    } else if lower.contains("reject") || lower.contains("denied") || lower.contains("abort") {
        "REJ"
    } else {
        "OTH"
    }
}

// ─── dns log ──────────────────────────────────────────────────────────────────

fn render_dns(event: &BronzeEvent, tx: &ProtocolTransaction) -> Value {
    let mut m = common_header("dns", event);
    // query: first object_ref or the "query_name" attribute
    let query = tx
        .object_refs
        .first()
        .cloned()
        .or_else(|| tx.attributes.get("query_name").cloned())
        .unwrap_or_else(|| "-".into());
    m.insert("query".into(), json!(query));
    m.insert(
        "qtype_name".into(),
        json!(
            tx.attributes
                .get("query_type")
                .map(|s| s.as_str())
                .unwrap_or("-")
        ),
    );
    m.insert(
        "rcode_name".into(),
        json!(
            tx.attributes
                .get("rcode")
                .map(|s| s.as_str())
                .unwrap_or("-")
        ),
    );
    // answers: split "answers" attribute by comma, or collect from values
    let answers: Vec<Value> = tx
        .attributes
        .get("answers")
        .map(|a| a.split(',').map(|s| json!(s.trim())).collect())
        .unwrap_or_else(|| {
            tx.values
                .iter()
                .filter_map(|v| v.value.as_ref().map(|s| json!(s)))
                .collect()
        });
    m.insert("answers".into(), json!(answers));
    let ttls: Vec<Value> = tx
        .attributes
        .get("ttls")
        .map(|t| {
            t.split(',')
                .map(|s| {
                    s.trim()
                        .parse::<u64>()
                        .map(|n| json!(n))
                        .unwrap_or(json!(0))
                })
                .collect()
        })
        .unwrap_or_default();
    m.insert("TTLs".into(), json!(ttls));
    Value::Object(m)
}

// ─── http log ─────────────────────────────────────────────────────────────────

fn render_http(event: &BronzeEvent, tx: &ProtocolTransaction) -> Value {
    let mut m = common_header("http", event);
    m.insert("method".into(), json!(tx.operation));
    m.insert(
        "host".into(),
        json!(tx.attributes.get("host").map(|s| s.as_str()).unwrap_or("-")),
    );
    let uri = tx
        .object_refs
        .first()
        .cloned()
        .or_else(|| tx.attributes.get("uri").cloned())
        .or_else(|| tx.attributes.get("url").cloned())
        .unwrap_or_else(|| "-".into());
    m.insert("uri".into(), json!(uri));
    let status_code = tx
        .attributes
        .get("status_code")
        .and_then(|s| s.parse::<u32>().ok());
    m.insert("status_code".into(), json!(status_code));
    m.insert(
        "status_msg".into(),
        json!(
            tx.attributes
                .get("status_msg")
                .map(|s| s.as_str())
                .unwrap_or("-")
        ),
    );
    m.insert(
        "user_agent".into(),
        json!(
            tx.attributes
                .get("user_agent")
                .map(|s| s.as_str())
                .unwrap_or("-")
        ),
    );
    m.insert(
        "resp_mime_types".into(),
        json!(
            tx.attributes
                .get("content_type")
                .map(|s| s.as_str())
                .unwrap_or("-")
        ),
    );
    Value::Object(m)
}

// ─── ssl log ──────────────────────────────────────────────────────────────────

fn render_ssl(event: &BronzeEvent, tx: &ProtocolTransaction) -> Value {
    let mut m = common_header("ssl", event);
    m.insert(
        "version".into(),
        json!(
            tx.attributes
                .get("version")
                .map(|s| s.as_str())
                .unwrap_or("-")
        ),
    );
    m.insert(
        "cipher".into(),
        json!(
            tx.attributes
                .get("cipher")
                .map(|s| s.as_str())
                .unwrap_or("-")
        ),
    );
    m.insert(
        "server_name".into(),
        json!(
            tx.attributes
                .get("server_name")
                .or_else(|| tx.attributes.get("sni"))
                .map(|s| s.as_str())
                .unwrap_or("-")
        ),
    );
    m.insert(
        "established".into(),
        json!(
            tx.status.to_ascii_lowercase().contains("ok")
                || tx.status.to_ascii_lowercase().contains("success")
        ),
    );
    Value::Object(m)
}

// ─── ssh log ──────────────────────────────────────────────────────────────────

fn render_ssh(event: &BronzeEvent, tx: &ProtocolTransaction) -> Value {
    let mut m = common_header("ssh", event);
    m.insert(
        "version".into(),
        json!(
            tx.attributes
                .get("version")
                .and_then(|s| s.parse::<u8>().ok())
                .unwrap_or(2)
        ),
    );
    m.insert(
        "auth_success".into(),
        json!(
            tx.status.to_ascii_lowercase().contains("ok")
                || tx.status.to_ascii_lowercase().contains("success")
        ),
    );
    m.insert(
        "client".into(),
        json!(
            tx.attributes
                .get("client_banner")
                .or_else(|| tx.attributes.get("client"))
                .map(|s| s.as_str())
                .unwrap_or("-")
        ),
    );
    m.insert(
        "server".into(),
        json!(
            tx.attributes
                .get("server_banner")
                .or_else(|| tx.attributes.get("server"))
                .map(|s| s.as_str())
                .unwrap_or("-")
        ),
    );
    Value::Object(m)
}

// ─── modbus log ───────────────────────────────────────────────────────────────

fn render_modbus(event: &BronzeEvent, tx: &ProtocolTransaction) -> Value {
    let mut m = common_header("modbus", event);

    // Prefer typed ProtocolFields::Modbus; fall back to legacy tx.modbus then attributes.
    let (func, exception, start_addr, qty, values_count) =
        if let Some(ProtocolFields::Modbus(mf)) = &tx.protocol_fields {
            let func = modbus_fc_name(mf.fc);
            let exc = mf.exception_code.map(|c| format!("{c}"));
            (func.into(), exc, mf.start_addr, mf.qty, mf.values.len())
        } else if let Some(mf) = &tx.modbus {
            let func = modbus_fc_name(mf.fc);
            let exc = mf.exception_code.map(|c| format!("{c}"));
            (func.into(), exc, mf.start_addr, mf.qty, mf.values.len())
        } else {
            let func = tx
                .attributes
                .get("function_code")
                .cloned()
                .unwrap_or_else(|| tx.operation.clone());
            (func, None, None, None, 0)
        };

    m.insert("func".into(), json!(func));
    m.insert(
        "exception".into(),
        json!(exception.as_deref().unwrap_or("-")),
    );
    // Extended fields (our added value)
    if let Some(addr) = start_addr {
        m.insert("start_addr".into(), json!(addr));
    }
    if let Some(q) = qty {
        m.insert("qty".into(), json!(q));
    }
    if values_count > 0 {
        m.insert("values_count".into(), json!(values_count));
    }
    Value::Object(m)
}

fn modbus_fc_name(fc: u8) -> &'static str {
    match fc {
        1 => "READ_COILS",
        2 => "READ_DISCRETE_INPUTS",
        3 => "READ_HOLDING_REGISTERS",
        4 => "READ_INPUT_REGISTERS",
        5 => "WRITE_SINGLE_COIL",
        6 => "WRITE_SINGLE_REGISTER",
        7 => "READ_EXCEPTION_STATUS",
        8 => "DIAGNOSTICS",
        11 => "GET_COMM_EVENT_COUNTER",
        12 => "GET_COMM_EVENT_LOG",
        15 => "WRITE_MULTIPLE_COILS",
        16 => "WRITE_MULTIPLE_REGISTERS",
        17 => "REPORT_SERVER_ID",
        20 => "READ_FILE_RECORD",
        21 => "WRITE_FILE_RECORD",
        22 => "MASK_WRITE_REGISTER",
        23 => "READ_WRITE_MULTIPLE_REGISTERS",
        24 => "READ_FIFO_QUEUE",
        43 => "ENCAPSULATED_INTERFACE_TRANSPORT",
        _ => "UNKNOWN",
    }
}

// ─── dnp3 log ─────────────────────────────────────────────────────────────────

fn render_dnp3(event: &BronzeEvent, tx: &ProtocolTransaction) -> Value {
    let mut m = common_header("dnp3", event);

    if let Some(ProtocolFields::Dnp3(df)) = &tx.protocol_fields {
        let (fc_request, fc_reply, iin) = if df.direction == "request" {
            (df.application_function_name.clone(), "-".into(), "-".into())
        } else {
            let iin_str = df
                .iin_flags
                .map(|i| format!("{i:#06x}"))
                .unwrap_or_else(|| "-".into());
            ("-".into(), df.application_function_name.clone(), iin_str)
        };
        m.insert("fc_request".into(), json!(fc_request));
        m.insert("fc_reply".into(), json!(fc_reply));
        m.insert("iin".into(), json!(iin));
        // Extended fields
        m.insert("src_addr".into(), json!(df.source_addr));
        m.insert("dst_addr".into(), json!(df.destination_addr));
        if !df.object_groups.is_empty() {
            m.insert("object_groups".into(), json!(df.object_groups));
        }
    } else {
        let fc = tx.operation.clone();
        m.insert("fc_request".into(), json!(fc));
        m.insert("fc_reply".into(), json!("-"));
        m.insert("iin".into(), json!("-"));
    }
    Value::Object(m)
}

// ─── smb_files / smb_mapping logs ────────────────────────────────────────────

fn render_smb(event: &BronzeEvent, tx: &ProtocolTransaction) -> Value {
    let op_lower = tx.operation.to_ascii_lowercase();
    let is_mapping = op_lower.contains("tree_connect")
        || op_lower.contains("tree connect")
        || op_lower.contains("negotiate")
        || op_lower.contains("session");

    if is_mapping {
        render_smb_mapping(event, tx)
    } else {
        render_smb_files(event, tx)
    }
}

fn render_smb_mapping(event: &BronzeEvent, tx: &ProtocolTransaction) -> Value {
    let mut m = common_header("smb_mapping", event);
    let path = tx
        .object_refs
        .first()
        .cloned()
        .or_else(|| tx.attributes.get("share_name").cloned())
        .or_else(|| tx.attributes.get("tree").cloned())
        .unwrap_or_else(|| "-".into());
    m.insert("path".into(), json!(path));
    m.insert(
        "share_type".into(),
        json!(
            tx.attributes
                .get("share_type")
                .map(|s| s.as_str())
                .unwrap_or("-")
        ),
    );
    m.insert("native_file_system".into(), json!("-"));
    Value::Object(m)
}

fn render_smb_files(event: &BronzeEvent, tx: &ProtocolTransaction) -> Value {
    let mut m = common_header("smb_files", event);
    m.insert("action".into(), json!(tx.operation));
    let name = tx
        .object_refs
        .first()
        .cloned()
        .or_else(|| tx.attributes.get("filename").cloned())
        .unwrap_or_else(|| "-".into());
    m.insert("name".into(), json!(name));
    m.insert(
        "size".into(),
        json!(
            tx.attributes
                .get("file_size")
                .and_then(|s| s.parse::<u64>().ok())
        ),
    );
    m.insert(
        "times.modified".into(),
        json!(
            tx.attributes
                .get("last_modified")
                .map(|s| s.as_str())
                .unwrap_or("-")
        ),
    );
    Value::Object(m)
}

// ─── kerberos log ─────────────────────────────────────────────────────────────

fn render_kerberos(event: &BronzeEvent, tx: &ProtocolTransaction) -> Value {
    let mut m = common_header("kerberos", event);
    // request_type: AS-REQ vs TGS-REQ from operation
    let req_type = if tx.operation.to_ascii_uppercase().contains("AS") {
        "AS"
    } else if tx.operation.to_ascii_uppercase().contains("TGS") {
        "TGS"
    } else {
        tx.operation.as_str()
    };
    m.insert("request_type".into(), json!(req_type));
    let client = tx
        .attributes
        .get("client")
        .or_else(|| tx.attributes.get("cname"))
        .or_else(|| tx.attributes.get("principal"))
        .map(|s| s.as_str())
        .unwrap_or("-");
    m.insert("client".into(), json!(client));
    let service = tx
        .attributes
        .get("service")
        .or_else(|| tx.attributes.get("sname"))
        .map(|s| s.as_str())
        .unwrap_or("-");
    m.insert("service".into(), json!(service));
    let success = tx.status.to_ascii_lowercase().contains("ok")
        || tx.status.to_ascii_lowercase().contains("success");
    m.insert("success".into(), json!(success));
    m.insert(
        "error_msg".into(),
        json!(if !success { tx.status.as_str() } else { "-" }),
    );
    m.insert(
        "forwardable".into(),
        json!(
            tx.attributes
                .get("forwardable")
                .map(|s| s == "true")
                .unwrap_or(false)
        ),
    );
    m.insert(
        "renewable".into(),
        json!(
            tx.attributes
                .get("renewable")
                .map(|s| s == "true")
                .unwrap_or(false)
        ),
    );
    Value::Object(m)
}

// ─── ldap log ─────────────────────────────────────────────────────────────────

fn render_ldap(event: &BronzeEvent, tx: &ProtocolTransaction) -> Value {
    let mut m = common_header("ldap", event);
    m.insert("operation".into(), json!(tx.operation));
    let object = tx
        .object_refs
        .first()
        .cloned()
        .or_else(|| tx.attributes.get("dn").cloned())
        .unwrap_or_else(|| "-".into());
    m.insert("object".into(), json!(object));
    m.insert(
        "search_filter".into(),
        json!(
            tx.attributes
                .get("filter")
                .map(|s| s.as_str())
                .unwrap_or("-")
        ),
    );
    m.insert(
        "search_base_object".into(),
        json!(
            tx.attributes
                .get("base_dn")
                .map(|s| s.as_str())
                .unwrap_or("-")
        ),
    );
    m.insert(
        "result_code".into(),
        json!(
            tx.attributes
                .get("result_code")
                .map(|s| s.as_str())
                .unwrap_or("-")
        ),
    );
    m.insert(
        "diagnostic_message".into(),
        json!(
            tx.attributes
                .get("error_message")
                .map(|s| s.as_str())
                .unwrap_or("-")
        ),
    );
    Value::Object(m)
}

// ─── dhcp log ─────────────────────────────────────────────────────────────────

fn render_dhcp(event: &BronzeEvent, tx: &ProtocolTransaction) -> Value {
    let mut m = common_header("dhcp", event);
    m.insert(
        "mac".into(),
        json!(
            tx.attributes
                .get("client_mac")
                .or_else(|| tx.attributes.get("mac"))
                .map(|s| s.as_str())
                .unwrap_or("-")
        ),
    );
    m.insert(
        "host_name".into(),
        json!(
            tx.attributes
                .get("hostname")
                .or_else(|| tx.attributes.get("host_name"))
                .map(|s| s.as_str())
                .unwrap_or("-")
        ),
    );
    m.insert(
        "requested_addr".into(),
        json!(
            tx.attributes
                .get("requested_ip")
                .or_else(|| tx.attributes.get("requested_addr"))
                .map(|s| s.as_str())
                .unwrap_or("-")
        ),
    );
    m.insert(
        "assigned_addr".into(),
        json!(
            tx.attributes
                .get("assigned_ip")
                .or_else(|| tx.attributes.get("yiaddr"))
                .map(|s| s.as_str())
                .unwrap_or("-")
        ),
    );
    m.insert("msg_type".into(), json!(tx.operation));
    Value::Object(m)
}

// ─── ntp log ──────────────────────────────────────────────────────────────────

fn render_ntp(event: &BronzeEvent, tx: &ProtocolTransaction) -> Value {
    let mut m = common_header("ntp", event);
    m.insert(
        "version".into(),
        json!(
            tx.attributes
                .get("version")
                .and_then(|s| s.parse::<u8>().ok())
                .unwrap_or(4)
        ),
    );
    m.insert(
        "mode".into(),
        json!(
            tx.attributes
                .get("mode")
                .and_then(|s| s.parse::<u8>().ok())
                .unwrap_or(0)
        ),
    );
    m.insert(
        "stratum".into(),
        json!(
            tx.attributes
                .get("stratum")
                .and_then(|s| s.parse::<u8>().ok())
                .unwrap_or(0)
        ),
    );
    m.insert(
        "poll".into(),
        json!(
            tx.attributes
                .get("poll")
                .and_then(|s| s.parse::<i8>().ok())
                .unwrap_or(0)
        ),
    );
    Value::Object(m)
}

// ─── snmp log ─────────────────────────────────────────────────────────────────

fn render_snmp(event: &BronzeEvent, tx: &ProtocolTransaction) -> Value {
    let mut m = common_header("snmp", event);
    m.insert(
        "version".into(),
        json!(
            tx.attributes
                .get("version")
                .map(|s| s.as_str())
                .unwrap_or("-")
        ),
    );
    m.insert(
        "community".into(),
        json!(
            tx.attributes
                .get("community")
                .map(|s| s.as_str())
                .unwrap_or("-")
        ),
    );
    m.insert(
        "get_requests".into(),
        json!(
            tx.attributes
                .get("get_requests")
                .and_then(|s| s.parse::<u32>().ok())
                .unwrap_or(0)
        ),
    );
    m.insert(
        "set_requests".into(),
        json!(
            tx.attributes
                .get("set_requests")
                .and_then(|s| s.parse::<u32>().ok())
                .unwrap_or(0)
        ),
    );
    Value::Object(m)
}

// ─── rdp log ──────────────────────────────────────────────────────────────────

fn render_rdp(event: &BronzeEvent, tx: &ProtocolTransaction) -> Value {
    let mut m = common_header("rdp", event);
    m.insert(
        "cookie".into(),
        json!(
            tx.attributes
                .get("cookie")
                .map(|s| s.as_str())
                .unwrap_or("-")
        ),
    );
    m.insert("result".into(), json!(tx.status));
    m.insert(
        "security_protocol".into(),
        json!(
            tx.attributes
                .get("security_protocol")
                .or_else(|| tx.attributes.get("protocol"))
                .map(|s| s.as_str())
                .unwrap_or("-")
        ),
    );
    m.insert(
        "keyboard_layout".into(),
        json!(
            tx.attributes
                .get("keyboard_layout")
                .map(|s| s.as_str())
                .unwrap_or("-")
        ),
    );
    m.insert(
        "client_build".into(),
        json!(
            tx.attributes
                .get("client_build")
                .map(|s| s.as_str())
                .unwrap_or("-")
        ),
    );
    Value::Object(m)
}

// ─── ics generic log (our added value) ───────────────────────────────────────

fn render_ics(event: &BronzeEvent, tx: &ProtocolTransaction) -> Value {
    let mut m = common_header("ics", event);
    let proto = event.envelope.protocol.as_deref().unwrap_or("-");
    m.insert("protocol".into(), json!(proto));
    m.insert("operation".into(), json!(tx.operation));
    m.insert("status".into(), json!(tx.status));
    if let Some(req) = &tx.request_summary {
        m.insert("request_summary".into(), json!(req));
    }
    if let Some(resp) = &tx.response_summary {
        m.insert("response_summary".into(), json!(resp));
    }
    if !tx.object_refs.is_empty() {
        m.insert("object_refs".into(), json!(tx.object_refs));
    }
    if !tx.attributes.is_empty() {
        let attrs: Map<String, Value> = tx
            .attributes
            .iter()
            .map(|(k, v)| (k.clone(), json!(v)))
            .collect();
        m.insert("attributes".into(), Value::Object(attrs));
    }
    // Flatten typed protocol fields if present
    if let Some(pf) = &tx.protocol_fields
        && let Ok(v) = serde_json::to_value(pf)
        && let Some(obj) = v.as_object()
    {
        for (k, val) in obj {
            m.insert(format!("pf_{k}"), val.clone());
        }
    }
    Value::Object(m)
}

// ─── software log ─────────────────────────────────────────────────────────────

fn render_software(event: &BronzeEvent, obs: &AssetObservation) -> Value {
    let mut m = Map::new();
    let ts = fmt_ts(&event.envelope.timestamp);
    m.insert("_path".into(), json!("software"));
    m.insert("_write_ts".into(), json!(&ts));
    m.insert("_system_name".into(), json!(SYSTEM_NAME));
    m.insert("ts".into(), json!(&ts));
    m.insert(
        "host".into(),
        json!(event.envelope.src_ip.as_deref().unwrap_or("-")),
    );

    // Software type from role
    let sw_type = obs.role.as_deref().unwrap_or("other").to_ascii_uppercase();
    m.insert("software_type".into(), json!(sw_type));

    // Name: vendor + model
    let name = match (&obs.vendor, &obs.model) {
        (Some(v), Some(mo)) => format!("{v} {mo}"),
        (Some(v), None) => v.clone(),
        (None, Some(mo)) => mo.clone(),
        (None, None) => obs.asset_key.clone(),
    };
    m.insert("name".into(), json!(name));

    // Version from firmware
    let version_str = obs.firmware.as_deref().unwrap_or("-");
    m.insert(
        "version".into(),
        json!({
            "major": version_str,
            "minor": "-",
            "minor2": "-",
            "addl": "-",
        }),
    );

    if !obs.hostnames.is_empty() {
        m.insert("host_p".into(), json!(obs.hostnames.first()));
    }
    m.insert("protocols".into(), json!(obs.protocols));

    Value::Object(m)
}

// ─── weird log ────────────────────────────────────────────────────────────────

fn render_weird(event: &BronzeEvent, an: &ParseAnomaly) -> Value {
    let mut m = Map::new();
    let ts = fmt_ts(&event.envelope.timestamp);
    m.insert("_path".into(), json!("weird"));
    m.insert("_write_ts".into(), json!(&ts));
    m.insert("_system_name".into(), json!(SYSTEM_NAME));
    m.insert("ts".into(), json!(&ts));
    m.insert("uid".into(), json!(conn_uid(&event.envelope.session_key)));
    id_fields(&mut m, &event.envelope);
    // name: decoder + brief reason summary (Zeek's weird.name is the classifier)
    let name = format!("{}_{}", an.decoder, slugify_reason(&an.reason));
    m.insert("name".into(), json!(name));
    m.insert("addl".into(), json!(an.reason));
    m.insert("notice".into(), json!(weird_notice(&an.severity)));
    m.insert("peer".into(), json!(SYSTEM_NAME));
    Value::Object(m)
}

fn slugify_reason(reason: &str) -> String {
    reason
        .chars()
        .map(|c| {
            if c.is_alphanumeric() {
                c.to_ascii_lowercase()
            } else {
                '_'
            }
        })
        .take(32)
        .collect::<String>()
        .trim_matches('_')
        .to_string()
}

fn weird_notice(severity: &str) -> bool {
    // Zeek's `notice` bool on weird.log = escalate to notice.log
    matches!(severity.to_ascii_lowercase().as_str(), "high" | "critical")
}

// ─── Public API ───────────────────────────────────────────────────────────────

/// The set of application-layer protocols that have native Zeek log mappings.
/// Protocols not in this set are emitted as `_path: "ics"`.
const ZEEK_NATIVE_PROTOCOLS: &[&str] = &[
    "dns", "http", "ssl", "tls", "ssh", "modbus", "dnp3", "smb2", "kerberos", "ldap", "dhcp",
    "ntp", "snmp", "rdp",
];

fn is_zeek_native(proto: &str) -> bool {
    let p = proto.to_ascii_lowercase();
    ZEEK_NATIVE_PROTOCOLS
        .iter()
        .any(|&n| p == n || p.starts_with(n))
}

/// Render a `BronzeEvent` to one or more Zeek JSON Streaming Log lines.
///
/// Returns a `String` containing concatenated NDJSON rows (each terminated by
/// `\n`), or `None` when the event has no Zeek mapping (e.g. `ProcessReading`).
///
/// Conn rows are NOT deduped here; call `render_many` or use `ZeekRenderer`
/// for deduplication across a batch.
pub fn render_event(event: &BronzeEvent) -> Option<String> {
    let mut rows: Vec<Value> = Vec::new();

    match &event.family {
        BronzeEventFamily::ProtocolTransaction(tx) => {
            // Always emit a conn row
            rows.push(render_conn(event));

            let proto = event.envelope.protocol.as_deref().unwrap_or("");
            let proto_lower = proto.to_ascii_lowercase();

            let tx_row = if proto_lower == "dns" {
                Some(render_dns(event, tx))
            } else if proto_lower == "http" {
                Some(render_http(event, tx))
            } else if proto_lower == "ssl" || proto_lower == "tls" {
                Some(render_ssl(event, tx))
            } else if proto_lower == "ssh" {
                Some(render_ssh(event, tx))
            } else if proto_lower == "modbus" {
                Some(render_modbus(event, tx))
            } else if proto_lower == "dnp3" {
                Some(render_dnp3(event, tx))
            } else if proto_lower.starts_with("smb") {
                Some(render_smb(event, tx))
            } else if proto_lower == "kerberos" {
                Some(render_kerberos(event, tx))
            } else if proto_lower == "ldap" {
                Some(render_ldap(event, tx))
            } else if proto_lower == "dhcp" {
                Some(render_dhcp(event, tx))
            } else if proto_lower == "ntp" {
                Some(render_ntp(event, tx))
            } else if proto_lower == "snmp" {
                Some(render_snmp(event, tx))
            } else if proto_lower == "rdp" {
                Some(render_rdp(event, tx))
            } else if !proto_lower.is_empty() && !is_zeek_native(&proto_lower) {
                // Non-Zeek ICS protocol → ics generic row
                Some(render_ics(event, tx))
            } else {
                None
            };

            if let Some(r) = tx_row {
                rows.push(r);
            }
        }
        BronzeEventFamily::AssetObservation(obs) => {
            rows.push(render_software(event, obs));
        }
        BronzeEventFamily::ParseAnomaly(an) => {
            rows.push(render_weird(event, an));
        }
        // ProcessReading, ExtractedArtifact, TopologyObservation → not mapped
        BronzeEventFamily::ProcessReading(_)
        | BronzeEventFamily::ExtractedArtifact(_)
        | BronzeEventFamily::TopologyObservation(_) => return None,
    }

    if rows.is_empty() {
        return None;
    }

    let mut out = String::new();
    for row in rows {
        if let Ok(s) = serde_json::to_string(&row) {
            out.push_str(&s);
            out.push('\n');
        }
    }
    if out.is_empty() { None } else { Some(out) }
}

/// Render many events as a Zeek JSON Streaming Log NDJSON stream.
///
/// Conn rows are deduplicated by session_key: only the first occurrence emits
/// a conn row. Protocol-specific rows (dns, modbus, etc.) are always emitted.
pub fn render_many(events: &[BronzeEvent]) -> String {
    let mut seen_sessions: HashSet<String> = HashSet::new();
    let mut out = String::new();

    for event in events {
        // For ProtocolTransaction events, separate the conn row from the
        // protocol-specific row so we can deduplicate conn.
        if let BronzeEventFamily::ProtocolTransaction(tx) = &event.family {
            let key = &event.envelope.session_key;
            let is_new_session = seen_sessions.insert(key.clone());

            if is_new_session {
                let conn = render_conn(event);
                if let Ok(s) = serde_json::to_string(&conn) {
                    out.push_str(&s);
                    out.push('\n');
                }
            }

            let proto = event.envelope.protocol.as_deref().unwrap_or("");
            let proto_lower = proto.to_ascii_lowercase();

            let tx_row = if proto_lower == "dns" {
                Some(render_dns(event, tx))
            } else if proto_lower == "http" {
                Some(render_http(event, tx))
            } else if proto_lower == "ssl" || proto_lower == "tls" {
                Some(render_ssl(event, tx))
            } else if proto_lower == "ssh" {
                Some(render_ssh(event, tx))
            } else if proto_lower == "modbus" {
                Some(render_modbus(event, tx))
            } else if proto_lower == "dnp3" {
                Some(render_dnp3(event, tx))
            } else if proto_lower.starts_with("smb") {
                Some(render_smb(event, tx))
            } else if proto_lower == "kerberos" {
                Some(render_kerberos(event, tx))
            } else if proto_lower == "ldap" {
                Some(render_ldap(event, tx))
            } else if proto_lower == "dhcp" {
                Some(render_dhcp(event, tx))
            } else if proto_lower == "ntp" {
                Some(render_ntp(event, tx))
            } else if proto_lower == "snmp" {
                Some(render_snmp(event, tx))
            } else if proto_lower == "rdp" {
                Some(render_rdp(event, tx))
            } else if !proto_lower.is_empty() && !is_zeek_native(&proto_lower) {
                Some(render_ics(event, tx))
            } else {
                None
            };

            if let Some(row) = tx_row
                && let Ok(s) = serde_json::to_string(&row)
            {
                out.push_str(&s);
                out.push('\n');
            }
        } else if let Some(rendered) = render_event(event) {
            out.push_str(&rendered);
        }
    }
    out
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use chrono::{DateTime, Utc};

    use super::*;
    use crate::bronze::{
        AssetObservation, BRONZE_SCHEMA_VERSION, BronzeEvent, BronzeEventFamily, Dnp3BronzeFields,
        EventEnvelope, ModbusBronzeFields, ModbusRegKind, ParseAnomaly, PointIdentifier,
        PointValue, ProcessReading, ProtocolFields, ProtocolTransaction, RawQuality,
        TransportProtocol,
    };

    fn envelope(proto: &str) -> EventEnvelope {
        EventEnvelope {
            timestamp: DateTime::<Utc>::from_timestamp(1_747_000_000, 0).unwrap(),
            interface_id: 0,
            segment_hash: "seg".into(),
            frame_index: 0,
            session_key: "10.0.0.1:49152-10.0.0.2:502-tcp".into(),
            src_mac: Some("aa:bb:cc:dd:ee:ff".into()),
            dst_mac: Some("11:22:33:44:55:66".into()),
            src_ip: Some("10.0.0.1".into()),
            dst_ip: Some("10.0.0.2".into()),
            src_port: Some(49152),
            dst_port: Some(502),
            vlan_id: None,
            transport: TransportProtocol::Tcp,
            protocol: Some(proto.into()),
            bytes_count: 64,
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
                request_summary: None,
                response_summary: None,
                object_refs: vec![],
                values: vec![],
                attributes: BTreeMap::new(),
                modbus: None,
                protocol_fields: None,
            }),
        }
    }

    fn tx_event_with_attrs(
        proto: &str,
        op: &str,
        status: &str,
        attrs: Vec<(&str, &str)>,
    ) -> BronzeEvent {
        let mut ev = tx_event(proto, op, status);
        if let BronzeEventFamily::ProtocolTransaction(tx) = &mut ev.family {
            for (k, v) in attrs {
                tx.attributes.insert(k.into(), v.into());
            }
        }
        ev
    }

    fn parse_row(s: &str) -> serde_json::Value {
        serde_json::from_str(s).expect("valid JSON row")
    }

    // ── conn ──────────────────────────────────────────────────────────────────

    #[test]
    fn conn_row_has_required_fields() {
        let ev = tx_event("modbus", "read_holding_registers", "ok");
        let rendered = render_event(&ev).expect("rendered");
        let first_line = rendered.lines().next().expect("at least one line");
        let v = parse_row(first_line);
        assert_eq!(v["_path"], "conn");
        assert_eq!(v["id.orig_h"], "10.0.0.1");
        assert_eq!(v["id.orig_p"], 49152);
        assert_eq!(v["id.resp_h"], "10.0.0.2");
        assert_eq!(v["id.resp_p"], 502);
        assert_eq!(v["proto"], "tcp");
        assert_eq!(v["service"], "modbus");
        assert_eq!(v["conn_state"], "SF");
        assert!(v["uid"].is_string());
        assert_eq!(v["_system_name"], "marlinspike-dpi");
    }

    // ── conn uid determinism ──────────────────────────────────────────────────

    #[test]
    fn conn_uid_is_deterministic() {
        let uid1 = conn_uid("10.0.0.1:49152-10.0.0.2:502-tcp");
        let uid2 = conn_uid("10.0.0.1:49152-10.0.0.2:502-tcp");
        assert_eq!(uid1, uid2);
    }

    #[test]
    fn conn_uid_length_and_charset() {
        let uid = conn_uid("some-session-key-here");
        assert_eq!(uid.len(), 18, "UID must be exactly 18 chars");
        assert!(
            uid.chars().all(|c| c.is_ascii_alphanumeric()),
            "UID must be base62: {uid}"
        );
    }

    #[test]
    fn conn_uid_different_keys_produce_different_uids() {
        let uid1 = conn_uid("session-1");
        let uid2 = conn_uid("session-2");
        assert_ne!(uid1, uid2);
    }

    // ── dns ───────────────────────────────────────────────────────────────────

    #[test]
    fn dns_row_maps_zeek_columns() {
        let ev = tx_event_with_attrs(
            "dns",
            "query",
            "response",
            vec![
                ("query_name", "example.com"),
                ("query_type", "A"),
                ("rcode", "NOERROR"),
                ("answers", "93.184.216.34"),
                ("ttls", "300"),
            ],
        );
        let rendered = render_event(&ev).expect("rendered");
        let lines: Vec<&str> = rendered.lines().collect();
        assert_eq!(lines.len(), 2, "conn + dns rows");
        let dns = parse_row(lines[1]);
        assert_eq!(dns["_path"], "dns");
        assert_eq!(dns["query"], "example.com");
        assert_eq!(dns["qtype_name"], "A");
        assert_eq!(dns["rcode_name"], "NOERROR");
        assert_eq!(dns["answers"][0], "93.184.216.34");
        assert_eq!(dns["TTLs"][0], 300);
    }

    // ── http ──────────────────────────────────────────────────────────────────

    #[test]
    fn http_row_maps_zeek_columns() {
        let mut ev = tx_event("http", "GET", "ok");
        if let BronzeEventFamily::ProtocolTransaction(tx) = &mut ev.family {
            tx.object_refs = vec!["/index.html".into()];
            tx.attributes.insert("host".into(), "example.com".into());
            tx.attributes.insert("status_code".into(), "200".into());
            tx.attributes.insert("status_msg".into(), "OK".into());
            tx.attributes
                .insert("user_agent".into(), "curl/7.85".into());
        }
        let rendered = render_event(&ev).expect("rendered");
        let lines: Vec<&str> = rendered.lines().collect();
        let http = parse_row(lines[1]);
        assert_eq!(http["_path"], "http");
        assert_eq!(http["method"], "GET");
        assert_eq!(http["host"], "example.com");
        assert_eq!(http["uri"], "/index.html");
        assert_eq!(http["status_code"], 200);
        assert_eq!(http["user_agent"], "curl/7.85");
    }

    // ── ssl ───────────────────────────────────────────────────────────────────

    #[test]
    fn ssl_row_maps_zeek_columns() {
        let ev = tx_event_with_attrs(
            "ssl",
            "handshake",
            "ok",
            vec![
                ("version", "TLSv1.3"),
                ("cipher", "TLS_AES_256_GCM_SHA384"),
                ("server_name", "api.example.com"),
            ],
        );
        let rendered = render_event(&ev).expect("rendered");
        let lines: Vec<&str> = rendered.lines().collect();
        let ssl = parse_row(lines[1]);
        assert_eq!(ssl["_path"], "ssl");
        assert_eq!(ssl["version"], "TLSv1.3");
        assert_eq!(ssl["cipher"], "TLS_AES_256_GCM_SHA384");
        assert_eq!(ssl["server_name"], "api.example.com");
        assert_eq!(ssl["established"], true);
    }

    // ── modbus ────────────────────────────────────────────────────────────────

    #[test]
    fn modbus_row_maps_zeek_columns_typed() {
        let mut ev = tx_event("modbus", "read_holding_registers", "ok");
        if let BronzeEventFamily::ProtocolTransaction(tx) = &mut ev.family {
            tx.protocol_fields = Some(ProtocolFields::Modbus(ModbusBronzeFields {
                fc: 3,
                start_addr: Some(100),
                qty: Some(10),
                values: vec![1, 2, 3],
                exception_code: None,
                direction: "request".into(),
            }));
        }
        let rendered = render_event(&ev).expect("rendered");
        let lines: Vec<&str> = rendered.lines().collect();
        let modbus = parse_row(lines[1]);
        assert_eq!(modbus["_path"], "modbus");
        assert_eq!(modbus["func"], "READ_HOLDING_REGISTERS");
        assert_eq!(modbus["exception"], "-");
        assert_eq!(modbus["start_addr"], 100);
        assert_eq!(modbus["qty"], 10);
        assert_eq!(modbus["values_count"], 3);
    }

    #[test]
    fn modbus_exception_is_mapped() {
        let mut ev = tx_event("modbus", "read_holding_registers", "exception");
        if let BronzeEventFamily::ProtocolTransaction(tx) = &mut ev.family {
            tx.protocol_fields = Some(ProtocolFields::Modbus(ModbusBronzeFields {
                fc: 3,
                start_addr: None,
                qty: None,
                values: vec![],
                exception_code: Some(2),
                direction: "response".into(),
            }));
        }
        let rendered = render_event(&ev).expect("rendered");
        let lines: Vec<&str> = rendered.lines().collect();
        let modbus = parse_row(lines[1]);
        assert_eq!(modbus["exception"], "2");
    }

    // ── dnp3 ──────────────────────────────────────────────────────────────────

    #[test]
    fn dnp3_row_maps_zeek_columns_typed() {
        let mut ev = tx_event("dnp3", "read", "ok");
        if let BronzeEventFamily::ProtocolTransaction(tx) = &mut ev.family {
            tx.protocol_fields = Some(ProtocolFields::Dnp3(Dnp3BronzeFields {
                source_addr: 1,
                destination_addr: 3,
                dll_control: 0xC4,
                transport_seq: 0,
                transport_fir: true,
                transport_fin: true,
                application_function_code: 1,
                application_function_name: "Read".into(),
                application_seq: 0,
                iin_flags: None,
                direction: "request".into(),
                object_groups: vec![30, 31],
            }));
        }
        let rendered = render_event(&ev).expect("rendered");
        let lines: Vec<&str> = rendered.lines().collect();
        let dnp3 = parse_row(lines[1]);
        assert_eq!(dnp3["_path"], "dnp3");
        assert_eq!(dnp3["fc_request"], "Read");
        assert_eq!(dnp3["fc_reply"], "-");
        assert_eq!(dnp3["iin"], "-");
        assert_eq!(dnp3["src_addr"], 1);
        assert_eq!(dnp3["dst_addr"], 3);
    }

    // ── smb2 ──────────────────────────────────────────────────────────────────

    #[test]
    fn smb2_tree_connect_maps_to_smb_mapping() {
        let ev = tx_event_with_attrs(
            "smb2",
            "tree_connect",
            "ok",
            vec![("share_name", "\\\\server\\share")],
        );
        let rendered = render_event(&ev).expect("rendered");
        let lines: Vec<&str> = rendered.lines().collect();
        let smb = parse_row(lines[1]);
        assert_eq!(smb["_path"], "smb_mapping");
        assert_eq!(smb["path"], "\\\\server\\share");
    }

    #[test]
    fn smb2_file_op_maps_to_smb_files() {
        let mut ev = tx_event("smb2", "create_file", "ok");
        if let BronzeEventFamily::ProtocolTransaction(tx) = &mut ev.family {
            tx.object_refs = vec!["document.docx".into()];
        }
        let rendered = render_event(&ev).expect("rendered");
        let lines: Vec<&str> = rendered.lines().collect();
        let smb = parse_row(lines[1]);
        assert_eq!(smb["_path"], "smb_files");
        assert_eq!(smb["action"], "create_file");
        assert_eq!(smb["name"], "document.docx");
    }

    // ── kerberos ──────────────────────────────────────────────────────────────

    #[test]
    fn kerberos_row_maps_zeek_columns() {
        let ev = tx_event_with_attrs(
            "kerberos",
            "AS-REQ",
            "ok",
            vec![
                ("client", "alice@EXAMPLE.COM"),
                ("service", "krbtgt/EXAMPLE.COM"),
            ],
        );
        let rendered = render_event(&ev).expect("rendered");
        let lines: Vec<&str> = rendered.lines().collect();
        let krb = parse_row(lines[1]);
        assert_eq!(krb["_path"], "kerberos");
        assert_eq!(krb["request_type"], "AS");
        assert_eq!(krb["client"], "alice@EXAMPLE.COM");
        assert_eq!(krb["service"], "krbtgt/EXAMPLE.COM");
        assert_eq!(krb["success"], true);
        assert_eq!(krb["error_msg"], "-");
    }

    // ── ldap ──────────────────────────────────────────────────────────────────

    #[test]
    fn ldap_row_maps_zeek_columns() {
        let ev = tx_event_with_attrs(
            "ldap",
            "searchRequest",
            "ok",
            vec![
                ("base_dn", "dc=example,dc=com"),
                ("filter", "(uid=alice)"),
                ("result_code", "success"),
            ],
        );
        let rendered = render_event(&ev).expect("rendered");
        let lines: Vec<&str> = rendered.lines().collect();
        let ldap = parse_row(lines[1]);
        assert_eq!(ldap["_path"], "ldap");
        assert_eq!(ldap["operation"], "searchRequest");
        assert_eq!(ldap["search_base_object"], "dc=example,dc=com");
        assert_eq!(ldap["search_filter"], "(uid=alice)");
        assert_eq!(ldap["result_code"], "success");
    }

    // ── weird ──────────────────────────────────────────────────────────────────

    #[test]
    fn weird_row_maps_parse_anomaly() {
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
        let rendered = render_event(&ev).expect("rendered");
        let v = parse_row(rendered.lines().next().expect("line"));
        assert_eq!(v["_path"], "weird");
        assert_eq!(v["notice"], true);
        assert!(v["name"].as_str().unwrap().starts_with("modbus_"));
        assert_eq!(v["addl"], "truncated PDU");
        assert_eq!(v["peer"], "marlinspike-dpi");
    }

    #[test]
    fn weird_severity_low_does_not_set_notice() {
        let ev = BronzeEvent {
            event_id: "evt-4".into(),
            capture_id: "cap-1".into(),
            schema_version: BRONZE_SCHEMA_VERSION.into(),
            envelope: envelope("modbus"),
            family: BronzeEventFamily::ParseAnomaly(ParseAnomaly {
                decoder: "modbus".into(),
                severity: "low".into(),
                reason: "minor issue".into(),
                raw_excerpt_hex: "ff".into(),
            }),
        };
        let rendered = render_event(&ev).expect("rendered");
        let v = parse_row(rendered.lines().next().expect("line"));
        assert_eq!(v["notice"], false);
    }

    // ── software ─────────────────────────────────────────────────────────────

    #[test]
    fn software_row_maps_asset_observation() {
        let ev = BronzeEvent {
            event_id: "evt-5".into(),
            capture_id: "cap-1".into(),
            schema_version: BRONZE_SCHEMA_VERSION.into(),
            envelope: envelope("s7comm"),
            family: BronzeEventFamily::AssetObservation(AssetObservation {
                asset_key: "asset:plc-1".into(),
                role: Some("plc".into()),
                vendor: Some("Siemens".into()),
                model: Some("S7-1500".into()),
                firmware: Some("V2.9.1".into()),
                hostnames: vec!["plc-1.local".into()],
                protocols: vec!["s7comm".into()],
                identifiers: BTreeMap::new(),
            }),
        };
        let rendered = render_event(&ev).expect("rendered");
        let v = parse_row(rendered.lines().next().expect("line"));
        assert_eq!(v["_path"], "software");
        assert_eq!(v["software_type"], "PLC");
        assert_eq!(v["name"], "Siemens S7-1500");
        assert_eq!(v["version"]["major"], "V2.9.1");
        assert_eq!(v["host"], "10.0.0.1");
    }

    // ── ics generic ───────────────────────────────────────────────────────────

    #[test]
    fn unmapped_ics_protocol_emits_ics_row() {
        let ev = tx_event("s7comm", "read_var", "ok");
        let rendered = render_event(&ev).expect("rendered");
        let lines: Vec<&str> = rendered.lines().collect();
        assert_eq!(lines.len(), 2, "conn + ics rows");
        let ics = parse_row(lines[1]);
        assert_eq!(ics["_path"], "ics");
        assert_eq!(ics["protocol"], "s7comm");
        assert_eq!(ics["operation"], "read_var");
    }

    #[test]
    fn opc_ua_maps_to_ics_row() {
        let ev = tx_event("opc_ua", "ReadRequest", "ok");
        let rendered = render_event(&ev).expect("rendered");
        let lines: Vec<&str> = rendered.lines().collect();
        let ics = parse_row(lines[1]);
        assert_eq!(ics["_path"], "ics");
        assert_eq!(ics["protocol"], "opc_ua");
    }

    // ── process_reading not emitted ───────────────────────────────────────────

    #[test]
    fn process_reading_is_not_emitted() {
        let ev = BronzeEvent {
            event_id: "evt-6".into(),
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
                value: PointValue::UInt16(42),
                quality: RawQuality::None,
                source_ts: None,
                observed_ts: 0,
            }),
        };
        assert!(render_event(&ev).is_none());
    }

    // ── conn dedup in render_many ─────────────────────────────────────────────

    #[test]
    fn render_many_deduplicates_conn_rows() {
        // Two events sharing the same session_key → only one conn row.
        let ev1 = tx_event("modbus", "read_coils", "ok");
        let ev2 = tx_event("modbus", "write_register", "ok");
        // They share the same session_key by construction of tx_event.
        let out = render_many(&[ev1, ev2]);
        let conn_rows = out
            .lines()
            .filter(|l| {
                serde_json::from_str::<serde_json::Value>(l)
                    .map(|v| v["_path"] == "conn")
                    .unwrap_or(false)
            })
            .count();
        assert_eq!(conn_rows, 1, "only one conn row per session_key");
    }

    // ── all rows are valid NDJSON ─────────────────────────────────────────────

    #[test]
    fn every_rendered_line_is_valid_json() {
        let events = vec![
            tx_event("modbus", "read", "ok"),
            tx_event("dns", "query", "response"),
            tx_event("http", "GET", "ok"),
            tx_event("s7comm", "read_var", "ok"),
        ];
        let out = render_many(&events);
        for line in out.lines().filter(|l| !l.is_empty()) {
            let r: Result<serde_json::Value, _> = serde_json::from_str(line);
            assert!(r.is_ok(), "invalid JSON line: {line}");
            assert!(r.unwrap()["_path"].is_string(), "_path missing");
        }
    }
}
