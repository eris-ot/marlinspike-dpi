//! OPC UA DataValue decoding. A DataValue carries a Variant value plus
//! optional StatusCode, SourceTimestamp, ServerTimestamp, and picosecond
//! refinements, each gated by bits in the leading EncodingMask byte.

use crate::bronze::{PointValue, RawQuality};
use crate::opc_ua::datetime::opcua_datetime_to_unix_us;
use crate::opc_ua::reader::{Reader, ReaderError};
use crate::opc_ua::variant::read_variant;

const HAS_VALUE: u8 = 0x01;
const HAS_STATUS_CODE: u8 = 0x02;
const HAS_SOURCE_TIMESTAMP: u8 = 0x04;
const HAS_SERVER_TIMESTAMP: u8 = 0x08;
const HAS_SOURCE_PICOSECONDS: u8 = 0x10;
const HAS_SERVER_PICOSECONDS: u8 = 0x20;

#[derive(Debug, Clone)]
pub struct DecodedDataValue {
    pub value: PointValue,
    pub quality: RawQuality,
    /// Microseconds since Unix epoch, sourced from the device.
    pub source_ts: Option<u64>,
    /// Microseconds since Unix epoch, stamped by the server. Present in the
    /// returned struct for completeness but not used by ProcessReading.
    pub server_ts: Option<u64>,
}

pub fn read_data_value(r: &mut Reader<'_>) -> Result<DecodedDataValue, ReaderError> {
    let mask = r.read_u8()?;

    let value = if mask & HAS_VALUE != 0 {
        read_variant(r)?
    } else {
        PointValue::Null
    };

    let status_code = if mask & HAS_STATUS_CODE != 0 {
        Some(r.read_u32()?)
    } else {
        None
    };

    let source_ts = if mask & HAS_SOURCE_TIMESTAMP != 0 {
        opcua_datetime_to_unix_us(r.read_i64()?)
    } else {
        None
    };
    if mask & HAS_SOURCE_PICOSECONDS != 0 {
        let _ = r.read_u16()?;
    }

    let server_ts = if mask & HAS_SERVER_TIMESTAMP != 0 {
        opcua_datetime_to_unix_us(r.read_i64()?)
    } else {
        None
    };
    if mask & HAS_SERVER_PICOSECONDS != 0 {
        let _ = r.read_u16()?;
    }

    // OPC UA convention: status code 0 = Good. When the value is present and
    // no status was carried, treat it as Good (status_code = 0).
    let quality = RawQuality::OpcUaStatusCode(status_code.unwrap_or(0));

    Ok(DecodedDataValue {
        value,
        quality,
        source_ts,
        server_ts,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn value_only() {
        // mask = HAS_VALUE; variant = double(50.0)
        let mut bytes = vec![HAS_VALUE, 11]; // T_DOUBLE = 11
        bytes.extend_from_slice(&50.0f64.to_le_bytes());
        let mut r = Reader::new(&bytes);
        let dv = read_data_value(&mut r).unwrap();
        assert_eq!(dv.value, PointValue::Double(50.0));
        assert!(matches!(dv.quality, RawQuality::OpcUaStatusCode(0)));
        assert!(dv.source_ts.is_none());
        assert!(dv.server_ts.is_none());
    }

    #[test]
    fn value_status_source_timestamp() {
        let mask = HAS_VALUE | HAS_STATUS_CODE | HAS_SOURCE_TIMESTAMP;
        let mut bytes = vec![mask, 11]; // T_DOUBLE
        bytes.extend_from_slice(&72.5f64.to_le_bytes());
        bytes.extend_from_slice(&0x8000_0000u32.to_le_bytes()); // bad status
        // 1 second after Unix epoch in OPC UA ticks.
        let ts: i64 = 116_444_736_000_000_000 + 10_000_000;
        bytes.extend_from_slice(&ts.to_le_bytes());
        let mut r = Reader::new(&bytes);
        let dv = read_data_value(&mut r).unwrap();
        assert_eq!(dv.value, PointValue::Double(72.5));
        assert!(matches!(
            dv.quality,
            RawQuality::OpcUaStatusCode(0x8000_0000)
        ));
        assert_eq!(dv.source_ts, Some(1_000_000));
    }

    #[test]
    fn null_data_value_zero_mask() {
        let mut r = Reader::new(&[0x00]);
        let dv = read_data_value(&mut r).unwrap();
        assert_eq!(dv.value, PointValue::Null);
        assert!(matches!(dv.quality, RawQuality::OpcUaStatusCode(0)));
    }
}
