//! Sparkplug Metric → `PointValue` / `RawQuality` conversion.

use crate::bronze::{PointValue, RawQuality};
use crate::sparkplug::proto::{
    DataType,
    payload::{Metric, PropertySet, metric, property_value},
};

/// The conventional Sparkplug "Quality" PropertySet key. Per Sparkplug B
/// convention the value is a uint32 following the OPC UA StatusCode quality
/// encoding (0 = Bad, 64 = Uncertain, 192 = Good).
const QUALITY_PROPERTY_KEY: &str = "Quality";

/// Convert a Sparkplug `Metric` to our typed [`PointValue`].
///
/// Honors the metric's `is_null` flag (returns `PointValue::Null` regardless of
/// any value bytes present). For unknown / unsupported datatypes (DataSet,
/// Template, arrays, File, etc. in this v1) returns `PointValue::Null` — the
/// caller can decide whether to suppress the reading or carry it as null.
pub fn metric_to_point_value(metric: &Metric) -> PointValue {
    if metric.is_null.unwrap_or(false) {
        return PointValue::Null;
    }
    let datatype = metric
        .datatype
        .and_then(|d| DataType::try_from(d as i32).ok())
        .unwrap_or(DataType::Unknown);

    match (&metric.value, datatype) {
        // Scalar primitives — narrow uint32-on-wire to the declared datatype.
        (Some(metric::Value::IntValue(v)), DataType::Int8) => PointValue::Int8(*v as i8),
        (Some(metric::Value::IntValue(v)), DataType::Int16) => PointValue::Int16(*v as i16),
        (Some(metric::Value::IntValue(v)), DataType::Int32) => PointValue::Int32(*v as i32),
        (Some(metric::Value::IntValue(v)), DataType::UInt8) => PointValue::UInt8(*v as u8),
        (Some(metric::Value::IntValue(v)), DataType::UInt16) => PointValue::UInt16(*v as u16),
        (Some(metric::Value::IntValue(v)), DataType::UInt32) => PointValue::UInt32(*v),
        // Default for IntValue with no/unknown datatype: surface as Int32.
        (Some(metric::Value::IntValue(v)), _) => PointValue::Int32(*v as i32),

        (Some(metric::Value::LongValue(v)), DataType::Int64) => PointValue::Int64(*v as i64),
        (Some(metric::Value::LongValue(v)), DataType::UInt64) => PointValue::UInt64(*v),
        (Some(metric::Value::LongValue(v)), DataType::DateTime) => PointValue::DateTime(*v),
        (Some(metric::Value::LongValue(v)), _) => PointValue::Int64(*v as i64),

        (Some(metric::Value::FloatValue(v)), _) => PointValue::Float(*v),
        (Some(metric::Value::DoubleValue(v)), _) => PointValue::Double(*v),
        (Some(metric::Value::BooleanValue(v)), _) => PointValue::Bool(*v),
        (Some(metric::Value::StringValue(v)), _) => PointValue::Text(v.clone()),
        (Some(metric::Value::BytesValue(v)), _) => PointValue::Bytes(v.clone()),

        // Aggregate value kinds not yet mapped — emit as null. Callers may
        // choose to skip these readings or carry them through as nulls.
        (Some(metric::Value::DatasetValue(_)), _) => PointValue::Null,
        (Some(metric::Value::TemplateValue(_)), _) => PointValue::Null,
        (Some(metric::Value::ExtensionValue(_)), _) => PointValue::Null,

        // No value oneof set — treat as null.
        (None, _) => PointValue::Null,
    }
}

/// Build a [`RawQuality::SparkplugQuality`] for a metric. Reads the optional
/// `Quality` property from the PropertySet (uint32, OPC UA convention) and the
/// metric's `is_historical` / `is_transient` / `is_null` flags.
pub fn metric_to_raw_quality(metric: &Metric) -> RawQuality {
    let quality_value = metric
        .properties
        .as_ref()
        .and_then(extract_quality_property);
    RawQuality::SparkplugQuality {
        value: quality_value,
        is_historical: metric.is_historical.unwrap_or(false),
        is_transient: metric.is_transient.unwrap_or(false),
        is_null: metric.is_null.unwrap_or(false),
    }
}

/// Walk a PropertySet for the conventional "Quality" property and return its
/// uint32 value if present and well-typed.
fn extract_quality_property(props: &PropertySet) -> Option<u32> {
    let idx = props.keys.iter().position(|k| k == QUALITY_PROPERTY_KEY)?;
    let value = props.values.get(idx)?;
    match &value.value {
        Some(property_value::Value::IntValue(v)) => Some(*v),
        Some(property_value::Value::LongValue(v)) => Some(*v as u32),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sparkplug::proto::payload::{PropertyValue, property_value};

    fn metric_with_value(datatype: DataType, value: metric::Value) -> Metric {
        Metric {
            datatype: Some(datatype as u32),
            value: Some(value),
            ..Default::default()
        }
    }

    #[test]
    fn int_value_narrows_by_datatype() {
        assert_eq!(
            metric_to_point_value(&metric_with_value(
                DataType::Int8,
                metric::Value::IntValue(0xFF)
            )),
            PointValue::Int8(-1)
        );
        assert_eq!(
            metric_to_point_value(&metric_with_value(
                DataType::UInt16,
                metric::Value::IntValue(60000)
            )),
            PointValue::UInt16(60000)
        );
        assert_eq!(
            metric_to_point_value(&metric_with_value(
                DataType::Int32,
                metric::Value::IntValue(0x8000_0000)
            )),
            PointValue::Int32(i32::MIN)
        );
    }

    #[test]
    fn long_value_routes_to_datetime_when_declared() {
        assert_eq!(
            metric_to_point_value(&metric_with_value(
                DataType::DateTime,
                metric::Value::LongValue(1_700_000_000_000)
            )),
            PointValue::DateTime(1_700_000_000_000)
        );
    }

    #[test]
    fn float_double_string_bool_bytes() {
        assert_eq!(
            metric_to_point_value(&metric_with_value(
                DataType::Float,
                metric::Value::FloatValue(3.14)
            )),
            PointValue::Float(3.14)
        );
        assert_eq!(
            metric_to_point_value(&metric_with_value(
                DataType::Double,
                metric::Value::DoubleValue(72.5)
            )),
            PointValue::Double(72.5)
        );
        assert_eq!(
            metric_to_point_value(&metric_with_value(
                DataType::String,
                metric::Value::StringValue("ok".into())
            )),
            PointValue::Text("ok".into())
        );
        assert_eq!(
            metric_to_point_value(&metric_with_value(
                DataType::Boolean,
                metric::Value::BooleanValue(true)
            )),
            PointValue::Bool(true)
        );
        assert_eq!(
            metric_to_point_value(&metric_with_value(
                DataType::Bytes,
                metric::Value::BytesValue(vec![1, 2, 3])
            )),
            PointValue::Bytes(vec![1, 2, 3])
        );
    }

    #[test]
    fn is_null_overrides_value() {
        let m = Metric {
            datatype: Some(DataType::Int32 as u32),
            is_null: Some(true),
            value: Some(metric::Value::IntValue(42)),
            ..Default::default()
        };
        assert_eq!(metric_to_point_value(&m), PointValue::Null);
    }

    #[test]
    fn quality_property_extracted_when_present() {
        let m = Metric {
            datatype: Some(DataType::Double as u32),
            value: Some(metric::Value::DoubleValue(1.0)),
            properties: Some(PropertySet {
                keys: vec!["Quality".into(), "Other".into()],
                values: vec![
                    PropertyValue {
                        value: Some(property_value::Value::IntValue(192)),
                        ..Default::default()
                    },
                    PropertyValue {
                        value: Some(property_value::Value::IntValue(0)),
                        ..Default::default()
                    },
                ],
            }),
            ..Default::default()
        };
        assert_eq!(
            metric_to_raw_quality(&m),
            RawQuality::SparkplugQuality {
                value: Some(192),
                is_historical: false,
                is_transient: false,
                is_null: false,
            }
        );
    }

    #[test]
    fn quality_flags_reflect_metric_flags() {
        let m = Metric {
            is_historical: Some(true),
            is_transient: Some(false),
            is_null: Some(true),
            ..Default::default()
        };
        assert_eq!(
            metric_to_raw_quality(&m),
            RawQuality::SparkplugQuality {
                value: None,
                is_historical: true,
                is_transient: false,
                is_null: true,
            }
        );
    }

    #[test]
    fn missing_value_oneof_is_null() {
        let m = Metric {
            datatype: Some(DataType::Double as u32),
            value: None,
            ..Default::default()
        };
        assert_eq!(metric_to_point_value(&m), PointValue::Null);
    }
}
