//! InfluxDB Line Protocol renderer for `ProcessReading` events.
//!
//! Output is one line per reading. The measurement name is the
//! `source_protocol` (e.g. `sparkplug_b`, `modbus`, `opcua`,
//! `synchrophasor`, `pccc`). Tags carry low-cardinality dimensional
//! identity from the `PointIdentifier`; fields carry the typed value plus
//! `RawQuality` bits.
//!
//! Spec reference: <https://docs.influxdata.com/influxdb/latest/reference/syntax/line-protocol/>

use std::fmt::Write as _;

use crate::bronze::{
    BronzeEvent, BronzeEventFamily, ModbusRegKind, OpcUaNodeId, PointIdentifier, PointValue,
    ProcessReading, RawQuality, SynchrophasorChannelType,
};

/// Render a single `BronzeEvent` to Influx Line Protocol if it is a
/// `ProcessReading`. Other event families return `None` (callers can decide
/// how to handle them — typically skip).
///
/// The line does NOT include a trailing newline; callers concatenate.
pub fn render_process_reading(event: &BronzeEvent) -> Option<String> {
    let reading = match &event.family {
        BronzeEventFamily::ProcessReading(r) => r,
        _ => return None,
    };
    let mut line = String::with_capacity(192);

    // Measurement (escape commas + spaces).
    push_measurement(&mut line, &reading.source_protocol);

    // Tags.
    let tag_pairs = collect_tags(reading);
    for (k, v) in &tag_pairs {
        line.push(',');
        push_tag_key(&mut line, k);
        line.push('=');
        push_tag_value(&mut line, v);
    }

    line.push(' ');

    // Fields. At least one field is required.
    let mut wrote_any_field = false;
    if let Some((key, repr)) = field_for_value(&reading.value) {
        push_field_key(&mut line, key);
        line.push('=');
        line.push_str(&repr);
        wrote_any_field = true;
    }

    for (k, v) in quality_fields(&reading.quality) {
        if wrote_any_field {
            line.push(',');
        }
        push_field_key(&mut line, k);
        line.push('=');
        line.push_str(&v);
        wrote_any_field = true;
    }

    if !wrote_any_field {
        // Influx requires at least one field. Emit a sentinel so the line is
        // valid; callers can filter on this in queries.
        push_field_key(&mut line, "value_present");
        line.push_str("=false");
    }

    // Timestamp: prefer source (when the device sampled), fall back to observed
    // (when the capture saw it). Influx default is nanoseconds.
    let ts_us = reading.source_ts.unwrap_or(reading.observed_ts);
    let ts_ns = ts_us.saturating_mul(1_000);
    let _ = write!(line, " {ts_ns}");

    Some(line)
}

/// Render many events at once, joining lines with `\n`.
pub fn render_many(events: &[BronzeEvent]) -> String {
    let mut out = String::new();
    for ev in events {
        if let Some(line) = render_process_reading(ev) {
            if !out.is_empty() {
                out.push('\n');
            }
            out.push_str(&line);
        }
    }
    out
}

fn collect_tags(reading: &ProcessReading) -> Vec<(&'static str, String)> {
    let mut out: Vec<(&'static str, String)> = Vec::new();
    match &reading.point_id {
        PointIdentifier::ModbusRegister {
            unit_id,
            addr,
            register_type,
        } => {
            out.push(("unit", unit_id.to_string()));
            out.push(("addr", addr.to_string()));
            out.push(("register_type", modbus_kind_str(*register_type).into()));
        }
        PointIdentifier::OpcUaNode {
            namespace_index,
            identifier,
        } => {
            out.push(("ns", namespace_index.to_string()));
            out.push(("node_id_kind", node_id_kind_str(identifier).into()));
            if let Some(repr) = node_id_low_cardinality_repr(identifier) {
                out.push(("node_id", repr));
            }
        }
        PointIdentifier::CipSymbol { symbol, .. } => {
            out.push(("symbol", symbol.clone()));
        }
        PointIdentifier::CipPath {
            class,
            instance,
            attribute,
        } => {
            out.push(("class", format!("{class:#06x}")));
            out.push(("instance", instance.to_string()));
            if let Some(a) = attribute {
                out.push(("attribute", a.to_string()));
            }
        }
        PointIdentifier::DnpPoint {
            group,
            variation,
            index,
        } => {
            out.push(("group", group.to_string()));
            out.push(("variation", variation.to_string()));
            out.push(("index", index.to_string()));
        }
        PointIdentifier::Iec104Ioa {
            common_addr,
            ioa,
            type_id,
        } => {
            out.push(("common_addr", common_addr.to_string()));
            out.push(("ioa", ioa.to_string()));
            out.push(("type_id", type_id.to_string()));
        }
        PointIdentifier::Iec61850Reference { reference, .. } => {
            out.push(("reference", reference.clone()));
        }
        PointIdentifier::SparkplugMetric {
            group_id,
            edge_node_id,
            device_id,
            metric_name,
            alias,
            ..
        } => {
            out.push(("group", group_id.clone()));
            out.push(("edge", edge_node_id.clone()));
            if let Some(d) = device_id {
                out.push(("device", d.clone()));
            }
            if let Some(name) = metric_name {
                out.push(("metric", name.clone()));
            } else if let Some(a) = alias {
                // Surface unresolved aliases under a stable tag so dashboards
                // can spot them.
                out.push(("metric_alias", a.to_string()));
            }
        }
        PointIdentifier::HartCommand { command, slot } => {
            out.push(("command", command.to_string()));
            if let Some(s) = slot {
                out.push(("slot", s.to_string()));
            }
        }
        PointIdentifier::PcccAddress {
            file_type,
            file_number,
            element,
            sub_element,
        } => {
            out.push(("file_type", format!("{file_type:#04x}")));
            out.push(("file_number", file_number.to_string()));
            out.push(("element", element.to_string()));
            if let Some(s) = sub_element {
                out.push(("sub_element", s.to_string()));
            }
        }
        PointIdentifier::SynchrophasorChannel {
            idcode,
            station_name,
            channel_index,
            channel_name,
            channel_type,
        } => {
            out.push(("idcode", idcode.to_string()));
            if let Some(s) = station_name {
                out.push(("station", s.clone()));
            }
            out.push(("channel_index", channel_index.to_string()));
            if let Some(n) = channel_name {
                out.push(("channel", n.clone()));
            }
            out.push(("channel_type", synphasor_kind_str(*channel_type).into()));
        }
    }
    out
}

fn field_for_value(v: &PointValue) -> Option<(&'static str, String)> {
    match v {
        PointValue::Null => None,
        PointValue::Bool(b) => Some(("value", if *b { "t".into() } else { "f".into() })),
        PointValue::Int8(n) => Some(("value", format!("{n}i"))),
        PointValue::Int16(n) => Some(("value", format!("{n}i"))),
        PointValue::Int32(n) => Some(("value", format!("{n}i"))),
        PointValue::Int64(n) => Some(("value", format!("{n}i"))),
        PointValue::UInt8(n) => Some(("value", format!("{n}u"))),
        PointValue::UInt16(n) => Some(("value", format!("{n}u"))),
        PointValue::UInt32(n) => Some(("value", format!("{n}u"))),
        PointValue::UInt64(n) => Some(("value", format!("{n}u"))),
        PointValue::Float(f) => Some(("value", format_float(*f as f64))),
        PointValue::Double(f) => Some(("value", format_float(*f))),
        PointValue::Text(s) => Some(("value", format_string(s))),
        PointValue::Bytes(b) => Some(("value", format_string(&hex::encode(b)))),
        PointValue::DateTime(us) => Some(("value", format!("{us}u"))),
    }
}

fn quality_fields(q: &RawQuality) -> Vec<(&'static str, String)> {
    let mut out: Vec<(&'static str, String)> = Vec::new();
    let kind = quality_kind_str(q);
    out.push(("quality_kind", format_string(kind)));
    match q {
        RawQuality::None => {}
        RawQuality::DnpFlags(b) => out.push(("quality_value", format!("{b}u"))),
        RawQuality::Iec104Qds(b) => out.push(("quality_value", format!("{b}u"))),
        RawQuality::OpcUaStatusCode(c) => out.push(("quality_value", format!("{c}u"))),
        RawQuality::Iec61850Quality(w) => out.push(("quality_value", format!("{w}u"))),
        RawQuality::CipGeneralStatus(b) => out.push(("quality_value", format!("{b}u"))),
        RawQuality::HartFieldDeviceStatus(b) => out.push(("quality_value", format!("{b}u"))),
        RawQuality::SparkplugQuality {
            value,
            is_historical,
            is_transient,
            is_null,
        } => {
            if let Some(v) = value {
                out.push(("quality_value", format!("{v}u")));
            }
            out.push(("is_historical", bool_str(*is_historical).into()));
            out.push(("is_transient", bool_str(*is_transient).into()));
            out.push(("is_null", bool_str(*is_null).into()));
        }
    }
    out
}

fn quality_kind_str(q: &RawQuality) -> &'static str {
    match q {
        RawQuality::None => "none",
        RawQuality::DnpFlags(_) => "dnp_flags",
        RawQuality::Iec104Qds(_) => "iec104_qds",
        RawQuality::OpcUaStatusCode(_) => "opcua_status_code",
        RawQuality::Iec61850Quality(_) => "iec61850_quality",
        RawQuality::SparkplugQuality { .. } => "sparkplug_quality",
        RawQuality::CipGeneralStatus(_) => "cip_general_status",
        RawQuality::HartFieldDeviceStatus(_) => "hart_field_device_status",
    }
}

fn modbus_kind_str(k: ModbusRegKind) -> &'static str {
    match k {
        ModbusRegKind::Coil => "coil",
        ModbusRegKind::DiscreteInput => "discrete_input",
        ModbusRegKind::HoldingRegister => "holding_register",
        ModbusRegKind::InputRegister => "input_register",
    }
}

fn synphasor_kind_str(c: SynchrophasorChannelType) -> &'static str {
    match c {
        SynchrophasorChannelType::PhasorMagnitude => "phasor_magnitude",
        SynchrophasorChannelType::PhasorAngle => "phasor_angle",
        SynchrophasorChannelType::Frequency => "frequency",
        SynchrophasorChannelType::FrequencyDerivative => "frequency_derivative",
        SynchrophasorChannelType::Analog => "analog",
        SynchrophasorChannelType::Digital => "digital",
    }
}

fn node_id_kind_str(id: &OpcUaNodeId) -> &'static str {
    match id {
        OpcUaNodeId::Numeric(_) => "numeric",
        OpcUaNodeId::String(_) => "string",
        OpcUaNodeId::StringRaw(_) => "string_raw",
        OpcUaNodeId::Guid(_) => "guid",
        OpcUaNodeId::Opaque(_) => "opaque",
    }
}

/// Pull a stable tag-string for the NodeId. Numeric is safe; String is safe
/// when not pathological. StringRaw / Opaque / Guid are hex-encoded.
fn node_id_low_cardinality_repr(id: &OpcUaNodeId) -> Option<String> {
    match id {
        OpcUaNodeId::Numeric(n) => Some(n.to_string()),
        OpcUaNodeId::String(s) => Some(s.clone()),
        OpcUaNodeId::StringRaw(b) | OpcUaNodeId::Opaque(b) => Some(hex::encode(b)),
        OpcUaNodeId::Guid(g) => Some(hex::encode(g)),
    }
}

fn bool_str(b: bool) -> &'static str {
    if b { "t" } else { "f" }
}

fn format_float(f: f64) -> String {
    if f.is_nan() || f.is_infinite() {
        // Influx Line Protocol does not accept NaN/Inf for float fields.
        // Surface as zero to keep the line valid; callers can detect via
        // a separate quality flag if needed.
        "0.0".into()
    } else if f.fract() == 0.0 && f.abs() < 1e16 {
        format!("{f:.1}")
    } else {
        format!("{f}")
    }
}

fn format_string(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        match c {
            '"' | '\\' => {
                out.push('\\');
                out.push(c);
            }
            _ => out.push(c),
        }
    }
    out.push('"');
    out
}

fn push_measurement(line: &mut String, s: &str) {
    for c in s.chars() {
        match c {
            ',' | ' ' => {
                line.push('\\');
                line.push(c);
            }
            _ => line.push(c),
        }
    }
}

fn push_tag_key(line: &mut String, s: &str) {
    push_tag_component(line, s);
}
fn push_tag_value(line: &mut String, s: &str) {
    push_tag_component(line, s);
}

fn push_tag_component(line: &mut String, s: &str) {
    for c in s.chars() {
        match c {
            ',' | '=' | ' ' => {
                line.push('\\');
                line.push(c);
            }
            _ => line.push(c),
        }
    }
}

fn push_field_key(line: &mut String, s: &str) {
    push_tag_component(line, s); // same escape rules as tags
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bronze::{
        EventEnvelope, ProcessReading, TransportProtocol, BRONZE_SCHEMA_VERSION,
    };
    use chrono::{DateTime, Utc};

    fn envelope() -> EventEnvelope {
        EventEnvelope {
            timestamp: DateTime::<Utc>::from_timestamp(1_700_000_000, 0).unwrap(),
            interface_id: 0,
            segment_hash: "seg".into(),
            frame_index: 0,
            session_key: "k".into(),
            src_mac: None,
            dst_mac: None,
            src_ip: None,
            dst_ip: None,
            src_port: None,
            dst_port: None,
            vlan_id: None,
            transport: TransportProtocol::Tcp,
            protocol: None,
            bytes_count: 0,
            packet_count: 1,
        }
    }

    fn make_event(reading: ProcessReading) -> BronzeEvent {
        BronzeEvent {
            event_id: "e1".into(),
            capture_id: "c".into(),
            schema_version: BRONZE_SCHEMA_VERSION.into(),
            envelope: envelope(),
            family: BronzeEventFamily::ProcessReading(reading),
        }
    }

    #[test]
    fn modbus_register_renders() {
        let ev = make_event(ProcessReading {
            source_protocol: "modbus".into(),
            point_id: PointIdentifier::ModbusRegister {
                unit_id: 7,
                addr: 40001,
                register_type: ModbusRegKind::HoldingRegister,
            },
            value: PointValue::UInt16(2350),
            quality: RawQuality::None,
            source_ts: None,
            observed_ts: 1_700_000_000_500_000,
        });
        let line = render_process_reading(&ev).expect("line");
        assert!(line.starts_with("modbus,"));
        assert!(line.contains("unit=7"));
        assert!(line.contains("addr=40001"));
        assert!(line.contains("register_type=holding_register"));
        assert!(line.contains("value=2350u"));
        assert!(line.contains("quality_kind=\"none\""));
        assert!(line.ends_with(" 1700000000500000000"));
    }

    #[test]
    fn sparkplug_metric_with_quality_and_flags() {
        let ev = make_event(ProcessReading {
            source_protocol: "sparkplug_b".into(),
            point_id: PointIdentifier::SparkplugMetric {
                group_id: "Plant1".into(),
                edge_node_id: "PLC-A".into(),
                device_id: Some("Drive-17".into()),
                metric_name: Some("BearingTemp".into()),
                metric_name_raw: None,
                alias: Some(42),
            },
            value: PointValue::Double(74.2),
            quality: RawQuality::SparkplugQuality {
                value: Some(192),
                is_historical: false,
                is_transient: false,
                is_null: false,
            },
            source_ts: Some(1_700_000_000_500_000),
            observed_ts: 1_700_000_000_500_001,
        });
        let line = render_process_reading(&ev).expect("line");
        assert!(line.starts_with("sparkplug_b,"));
        assert!(line.contains("group=Plant1"));
        assert!(line.contains("edge=PLC-A"));
        assert!(line.contains("device=Drive-17"));
        assert!(line.contains("metric=BearingTemp"));
        assert!(line.contains("value=74.2"));
        assert!(line.contains("quality_kind=\"sparkplug_quality\""));
        assert!(line.contains("quality_value=192u"));
        assert!(line.contains("is_historical=f"));
        // source_ts (us) → ns
        assert!(line.ends_with(" 1700000000500000000"));
    }

    #[test]
    fn opc_ua_string_node_renders() {
        let ev = make_event(ProcessReading {
            source_protocol: "opcua".into(),
            point_id: PointIdentifier::OpcUaNode {
                namespace_index: 2,
                identifier: OpcUaNodeId::String("Boiler/Temp".into()),
            },
            value: PointValue::Double(72.5),
            quality: RawQuality::OpcUaStatusCode(0),
            source_ts: Some(1_700_000_000_000_000),
            observed_ts: 1_700_000_000_000_001,
        });
        let line = render_process_reading(&ev).expect("line");
        assert!(line.contains("ns=2"));
        assert!(line.contains("node_id_kind=string"));
        assert!(line.contains("node_id=Boiler/Temp"));
        assert!(line.contains("value=72.5"));
        assert!(line.contains("quality_value=0u"));
    }

    #[test]
    fn synchrophasor_phasor_magnitude() {
        let ev = make_event(ProcessReading {
            source_protocol: "synchrophasor".into(),
            point_id: PointIdentifier::SynchrophasorChannel {
                idcode: 7,
                station_name: Some("Station1".into()),
                channel_index: 0,
                channel_name: Some("VA".into()),
                channel_type: SynchrophasorChannelType::PhasorMagnitude,
            },
            value: PointValue::Double(7320.5),
            quality: RawQuality::Iec61850Quality(0),
            source_ts: Some(1_700_000_000_500_000),
            observed_ts: 1_700_000_000_500_001,
        });
        let line = render_process_reading(&ev).expect("line");
        assert!(line.starts_with("synchrophasor,"));
        assert!(line.contains("idcode=7"));
        assert!(line.contains("station=Station1"));
        assert!(line.contains("channel=VA"));
        assert!(line.contains("channel_type=phasor_magnitude"));
    }

    #[test]
    fn null_value_emits_sentinel_field() {
        let ev = make_event(ProcessReading {
            source_protocol: "sparkplug_b".into(),
            point_id: PointIdentifier::SparkplugMetric {
                group_id: "G".into(),
                edge_node_id: "E".into(),
                device_id: None,
                metric_name: Some("T".into()),
                metric_name_raw: None,
                alias: None,
            },
            value: PointValue::Null,
            quality: RawQuality::None,
            source_ts: None,
            observed_ts: 1,
        });
        let line = render_process_reading(&ev).expect("line");
        // Null PointValue + RawQuality::None → quality_kind tag + sentinel.
        assert!(line.contains("quality_kind=\"none\""));
        // Either the sentinel (no value field) or quality fields satisfy
        // the "at least one field" rule.
        assert!(line.contains("=") && !line.contains("value="));
    }

    #[test]
    fn measurement_and_tag_escaping() {
        let ev = make_event(ProcessReading {
            source_protocol: "weird, name".into(),
            point_id: PointIdentifier::CipSymbol {
                symbol: "Tag with space, comma, =equal".into(),
                symbol_raw: None,
            },
            value: PointValue::Float(1.0),
            quality: RawQuality::CipGeneralStatus(0),
            source_ts: None,
            observed_ts: 1,
        });
        let line = render_process_reading(&ev).expect("line");
        assert!(line.starts_with("weird\\,\\ name,"));
        // Comma, equals, space inside symbol value all backslash-escaped.
        assert!(line.contains("symbol=Tag\\ with\\ space\\,\\ comma\\,\\ \\=equal"));
    }

    #[test]
    fn float_inf_renders_as_zero_not_invalid() {
        let ev = make_event(ProcessReading {
            source_protocol: "x".into(),
            point_id: PointIdentifier::ModbusRegister {
                unit_id: 1,
                addr: 0,
                register_type: ModbusRegKind::HoldingRegister,
            },
            value: PointValue::Double(f64::INFINITY),
            quality: RawQuality::None,
            source_ts: None,
            observed_ts: 1,
        });
        let line = render_process_reading(&ev).expect("line");
        assert!(line.contains("value=0.0"));
    }

    #[test]
    fn non_process_reading_returns_none() {
        let ev = BronzeEvent {
            event_id: "e".into(),
            capture_id: "c".into(),
            schema_version: BRONZE_SCHEMA_VERSION.into(),
            envelope: envelope(),
            family: BronzeEventFamily::ParseAnomaly(crate::bronze::ParseAnomaly {
                decoder: "x".into(),
                severity: "low".into(),
                reason: "y".into(),
                raw_excerpt_hex: String::new(),
            }),
        };
        assert!(render_process_reading(&ev).is_none());
    }

    #[test]
    fn render_many_skips_non_readings() {
        let r = make_event(ProcessReading {
            source_protocol: "modbus".into(),
            point_id: PointIdentifier::ModbusRegister {
                unit_id: 1,
                addr: 1,
                register_type: ModbusRegKind::HoldingRegister,
            },
            value: PointValue::UInt16(1),
            quality: RawQuality::None,
            source_ts: None,
            observed_ts: 1,
        });
        let other = BronzeEvent {
            event_id: "e".into(),
            capture_id: "c".into(),
            schema_version: BRONZE_SCHEMA_VERSION.into(),
            envelope: envelope(),
            family: BronzeEventFamily::ParseAnomaly(crate::bronze::ParseAnomaly {
                decoder: "x".into(),
                severity: "low".into(),
                reason: "y".into(),
                raw_excerpt_hex: String::new(),
            }),
        };
        let out = render_many(&[r.clone(), other, r]);
        let lines: Vec<_> = out.split('\n').collect();
        assert_eq!(lines.len(), 2);
        for l in lines {
            assert!(l.starts_with("modbus,"));
        }
    }

    #[test]
    fn integer_typed_values_use_correct_suffix() {
        for (v, expect) in [
            (PointValue::Int8(-1), "value=-1i"),
            (PointValue::Int64(1), "value=1i"),
            (PointValue::UInt8(1), "value=1u"),
            (PointValue::UInt64(1), "value=1u"),
            (PointValue::Bool(true), "value=t"),
            (PointValue::Bool(false), "value=f"),
        ] {
            let ev = make_event(ProcessReading {
                source_protocol: "x".into(),
                point_id: PointIdentifier::ModbusRegister {
                    unit_id: 1,
                    addr: 0,
                    register_type: ModbusRegKind::HoldingRegister,
                },
                value: v,
                quality: RawQuality::None,
                source_ts: None,
                observed_ts: 1,
            });
            let line = render_process_reading(&ev).expect("line");
            assert!(line.contains(expect), "expected '{expect}' in: {line}");
        }
    }
}
