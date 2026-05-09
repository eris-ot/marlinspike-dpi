//! OPC UA Variant decoding into [`crate::bronze::PointValue`].
//!
//! A Variant carries a single value of one of OPC UA's built-in types. This
//! module handles scalars and the most common simple cases. Arrays, multi-
//! dimensional values, and aggregate types (ExtensionObject, DataValue,
//! Variant-of-Variant, DiagnosticInfo) decode to `PointValue::Null` so the
//! reading still emits — embedder can decide whether to drop or carry through.

use crate::bronze::PointValue;
use crate::opc_ua::datetime::opcua_datetime_to_unix_us;
use crate::opc_ua::reader::{Reader, ReaderError};

/// OPC UA built-in type IDs (low 6 bits of the Variant encoding mask).
const T_NULL: u8 = 0;
const T_BOOLEAN: u8 = 1;
const T_SBYTE: u8 = 2;
const T_BYTE: u8 = 3;
const T_INT16: u8 = 4;
const T_UINT16: u8 = 5;
const T_INT32: u8 = 6;
const T_UINT32: u8 = 7;
const T_INT64: u8 = 8;
const T_UINT64: u8 = 9;
const T_FLOAT: u8 = 10;
const T_DOUBLE: u8 = 11;
const T_STRING: u8 = 12;
const T_DATETIME: u8 = 13;
const T_GUID: u8 = 14;
const T_BYTESTRING: u8 = 15;

const FLAG_IS_ARRAY: u8 = 0x80;
const FLAG_HAS_DIMENSIONS: u8 = 0x40;

/// Read a Variant. Returns the typed [`PointValue`].
///
/// Arrays and multi-dimensional Variants are surfaced as `PointValue::Null`
/// (they're consumed from the stream so the cursor stays aligned, but no
/// scalar value is exposed in v1).
pub fn read_variant(r: &mut Reader<'_>) -> Result<PointValue, ReaderError> {
    let mask = r.read_u8()?;
    let type_id = mask & 0x3F;
    let is_array = mask & FLAG_IS_ARRAY != 0;
    let has_dimensions = mask & FLAG_HAS_DIMENSIONS != 0;

    if is_array {
        // Consume length-prefixed array of `type_id` values, then optional dims.
        consume_array(r, type_id)?;
        if has_dimensions {
            consume_array(r, T_INT32)?;
        }
        return Ok(PointValue::Null);
    }

    read_scalar(r, type_id)
}

fn read_scalar(r: &mut Reader<'_>, type_id: u8) -> Result<PointValue, ReaderError> {
    match type_id {
        T_NULL => Ok(PointValue::Null),
        T_BOOLEAN => Ok(PointValue::Bool(r.read_bool()?)),
        T_SBYTE => Ok(PointValue::Int8(r.read_i8()?)),
        T_BYTE => Ok(PointValue::UInt8(r.read_u8()?)),
        T_INT16 => Ok(PointValue::Int16(r.read_i16()?)),
        T_UINT16 => Ok(PointValue::UInt16(r.read_u16()?)),
        T_INT32 => Ok(PointValue::Int32(r.read_i32()?)),
        T_UINT32 => Ok(PointValue::UInt32(r.read_u32()?)),
        T_INT64 => Ok(PointValue::Int64(r.read_i64()?)),
        T_UINT64 => Ok(PointValue::UInt64(r.read_u64()?)),
        T_FLOAT => Ok(PointValue::Float(r.read_f32()?)),
        T_DOUBLE => Ok(PointValue::Double(r.read_f64()?)),
        T_STRING => Ok(match r.read_string()? {
            Some(s) => PointValue::Text(s.to_string()),
            None => PointValue::Null,
        }),
        T_DATETIME => {
            let ticks = r.read_i64()?;
            Ok(opcua_datetime_to_unix_us(ticks)
                .map(PointValue::DateTime)
                .unwrap_or(PointValue::Null))
        }
        T_GUID => {
            let bytes = r.read_array::<16>()?;
            Ok(PointValue::Bytes(bytes.to_vec()))
        }
        T_BYTESTRING => Ok(match r.read_byte_string()? {
            Some(b) => PointValue::Bytes(b.to_vec()),
            None => PointValue::Null,
        }),
        // ExtensionObject / DataValue / Variant / DiagnosticInfo / NodeId etc.
        // Out of scope for v1 — return Null. Caller does NOT advance past these
        // because we don't know the encoded size; the upstream parser must
        // not depend on the cursor position after an unsupported Variant.
        _ => Ok(PointValue::Null),
    }
}

fn consume_array(r: &mut Reader<'_>, type_id: u8) -> Result<(), ReaderError> {
    let len = match r.read_array_length()? {
        None => return Ok(()),
        Some(n) => n,
    };
    for _ in 0..len {
        let _ = read_scalar(r, type_id)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn variant_bytes(type_id: u8, payload: &[u8]) -> Vec<u8> {
        let mut v = vec![type_id];
        v.extend_from_slice(payload);
        v
    }

    #[test]
    fn scalar_double() {
        let bytes = variant_bytes(T_DOUBLE, &72.5f64.to_le_bytes());
        let mut r = Reader::new(&bytes);
        assert_eq!(read_variant(&mut r).unwrap(), PointValue::Double(72.5));
    }

    #[test]
    fn scalar_int32() {
        let bytes = variant_bytes(T_INT32, &(-1i32).to_le_bytes());
        let mut r = Reader::new(&bytes);
        assert_eq!(read_variant(&mut r).unwrap(), PointValue::Int32(-1));
    }

    #[test]
    fn scalar_string() {
        let mut payload = Vec::new();
        payload.extend_from_slice(&5i32.to_le_bytes());
        payload.extend_from_slice(b"hello");
        let bytes = variant_bytes(T_STRING, &payload);
        let mut r = Reader::new(&bytes);
        assert_eq!(
            read_variant(&mut r).unwrap(),
            PointValue::Text("hello".into())
        );
    }

    #[test]
    fn scalar_datetime() {
        // 1 second after Unix epoch in 100-ns ticks since 1601.
        let ticks: i64 = 116_444_736_000_000_000 + 10_000_000;
        let bytes = variant_bytes(T_DATETIME, &ticks.to_le_bytes());
        let mut r = Reader::new(&bytes);
        assert_eq!(
            read_variant(&mut r).unwrap(),
            PointValue::DateTime(1_000_000)
        );
    }

    #[test]
    fn scalar_null() {
        let bytes = variant_bytes(T_NULL, &[]);
        let mut r = Reader::new(&bytes);
        assert_eq!(read_variant(&mut r).unwrap(), PointValue::Null);
    }

    #[test]
    fn array_consumes_payload_returns_null() {
        // Array of 3 int32s.
        let mut payload = Vec::new();
        payload.extend_from_slice(&3i32.to_le_bytes());
        payload.extend_from_slice(&1i32.to_le_bytes());
        payload.extend_from_slice(&2i32.to_le_bytes());
        payload.extend_from_slice(&3i32.to_le_bytes());
        let mask = T_INT32 | FLAG_IS_ARRAY;
        let bytes = variant_bytes(mask, &payload);
        let mut r = Reader::new(&bytes);
        assert_eq!(read_variant(&mut r).unwrap(), PointValue::Null);
        assert_eq!(r.remaining(), 0);
    }

    #[test]
    fn null_array_consumes_only_length() {
        let mut payload = Vec::new();
        payload.extend_from_slice(&(-1i32).to_le_bytes());
        let mask = T_INT32 | FLAG_IS_ARRAY;
        let bytes = variant_bytes(mask, &payload);
        let mut r = Reader::new(&bytes);
        assert_eq!(read_variant(&mut r).unwrap(), PointValue::Null);
    }

    #[test]
    fn boolean_scalar() {
        let mut r = Reader::new(&[T_BOOLEAN, 0x01]);
        assert_eq!(read_variant(&mut r).unwrap(), PointValue::Bool(true));
    }
}
