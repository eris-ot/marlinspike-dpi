//! OPC UA DateTime conversion. The wire format is an int64 of 100-nanosecond
//! ticks since 1601-01-01 00:00:00 UTC (a Windows FILETIME). We carry
//! microseconds since the Unix epoch (1970-01-01 00:00:00 UTC).

/// Number of 100-ns ticks between 1601-01-01 and 1970-01-01 (Unix epoch).
const TICKS_1601_TO_1970: i64 = 116_444_736_000_000_000;

/// Convert an OPC UA DateTime (ticks since 1601) to microseconds since Unix
/// epoch. Returns `None` if the value is the OPC UA "null DateTime" (0) or if
/// the converted value would be negative (pre-1970).
pub fn opcua_datetime_to_unix_us(ticks_since_1601: i64) -> Option<u64> {
    if ticks_since_1601 == 0 {
        return None;
    }
    let ticks_since_unix = ticks_since_1601.checked_sub(TICKS_1601_TO_1970)?;
    if ticks_since_unix < 0 {
        return None;
    }
    // 100-ns ticks → microseconds.
    Some((ticks_since_unix / 10) as u64)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn null_datetime_is_none() {
        assert_eq!(opcua_datetime_to_unix_us(0), None);
    }

    #[test]
    fn unix_epoch_is_zero_us() {
        assert_eq!(opcua_datetime_to_unix_us(TICKS_1601_TO_1970), Some(0));
    }

    #[test]
    fn one_second_after_epoch() {
        // 1 second = 10_000_000 100-ns ticks.
        let ts = TICKS_1601_TO_1970 + 10_000_000;
        assert_eq!(opcua_datetime_to_unix_us(ts), Some(1_000_000));
    }

    #[test]
    fn pre_1970_returns_none() {
        // 1601 itself is well before 1970.
        assert_eq!(opcua_datetime_to_unix_us(1), None);
    }
}
