//! Little-endian cursor over OPC UA Binary-encoded bytes.
//!
//! All OPC UA primitive integers are little-endian. Strings and byte arrays
//! are int32 length-prefixed; -1 means null. DateTime is int64 100-ns intervals
//! since 1601-01-01 UTC.

#[derive(Debug)]
pub struct Reader<'a> {
    bytes: &'a [u8],
    pos: usize,
}

#[derive(Debug, Clone, Copy)]
pub enum ReaderError {
    OutOfBounds,
    InvalidUtf8,
    InvalidLength,
}

impl<'a> Reader<'a> {
    pub fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, pos: 0 }
    }

    pub fn position(&self) -> usize {
        self.pos
    }

    pub fn remaining(&self) -> usize {
        self.bytes.len() - self.pos
    }

    pub fn skip(&mut self, n: usize) -> Result<(), ReaderError> {
        if self.pos + n > self.bytes.len() {
            return Err(ReaderError::OutOfBounds);
        }
        self.pos += n;
        Ok(())
    }

    pub fn read_u8(&mut self) -> Result<u8, ReaderError> {
        if self.pos >= self.bytes.len() {
            return Err(ReaderError::OutOfBounds);
        }
        let v = self.bytes[self.pos];
        self.pos += 1;
        Ok(v)
    }

    pub fn read_bool(&mut self) -> Result<bool, ReaderError> {
        Ok(self.read_u8()? != 0)
    }

    pub fn read_i8(&mut self) -> Result<i8, ReaderError> {
        Ok(self.read_u8()? as i8)
    }

    pub fn read_u16(&mut self) -> Result<u16, ReaderError> {
        let bytes = self.read_array::<2>()?;
        Ok(u16::from_le_bytes(bytes))
    }

    pub fn read_i16(&mut self) -> Result<i16, ReaderError> {
        Ok(self.read_u16()? as i16)
    }

    pub fn read_u32(&mut self) -> Result<u32, ReaderError> {
        let bytes = self.read_array::<4>()?;
        Ok(u32::from_le_bytes(bytes))
    }

    pub fn read_i32(&mut self) -> Result<i32, ReaderError> {
        Ok(self.read_u32()? as i32)
    }

    pub fn read_u64(&mut self) -> Result<u64, ReaderError> {
        let bytes = self.read_array::<8>()?;
        Ok(u64::from_le_bytes(bytes))
    }

    pub fn read_i64(&mut self) -> Result<i64, ReaderError> {
        Ok(self.read_u64()? as i64)
    }

    pub fn read_f32(&mut self) -> Result<f32, ReaderError> {
        let bytes = self.read_array::<4>()?;
        Ok(f32::from_le_bytes(bytes))
    }

    pub fn read_f64(&mut self) -> Result<f64, ReaderError> {
        let bytes = self.read_array::<8>()?;
        Ok(f64::from_le_bytes(bytes))
    }

    pub fn read_array<const N: usize>(&mut self) -> Result<[u8; N], ReaderError> {
        if self.pos + N > self.bytes.len() {
            return Err(ReaderError::OutOfBounds);
        }
        let mut out = [0u8; N];
        out.copy_from_slice(&self.bytes[self.pos..self.pos + N]);
        self.pos += N;
        Ok(out)
    }

    pub fn read_bytes(&mut self, n: usize) -> Result<&'a [u8], ReaderError> {
        if self.pos + n > self.bytes.len() {
            return Err(ReaderError::OutOfBounds);
        }
        let slice = &self.bytes[self.pos..self.pos + n];
        self.pos += n;
        Ok(slice)
    }

    /// Read an OPC UA String / ByteString. Returns `None` for null (length = -1).
    pub fn read_byte_string(&mut self) -> Result<Option<&'a [u8]>, ReaderError> {
        let len = self.read_i32()?;
        if len < 0 {
            return Ok(None);
        }
        let n = len as usize;
        Ok(Some(self.read_bytes(n)?))
    }

    /// Read an OPC UA String as &str. Returns `None` for null.
    pub fn read_string(&mut self) -> Result<Option<&'a str>, ReaderError> {
        match self.read_byte_string()? {
            None => Ok(None),
            Some(bytes) => std::str::from_utf8(bytes)
                .map(Some)
                .map_err(|_| ReaderError::InvalidUtf8),
        }
    }

    /// Read an int32 array length, returning `None` for null (-1).
    pub fn read_array_length(&mut self) -> Result<Option<usize>, ReaderError> {
        let len = self.read_i32()?;
        if len < 0 {
            return Ok(None);
        }
        Ok(Some(len as usize))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn read_primitives() {
        let bytes: Vec<u8> = vec![
            0x01, // u8
            0x02, 0x00, // u16 = 2
            0xFF, 0xFF, 0xFF, 0xFF, // i32 = -1
            0x00, 0x00, 0x80, 0x3F, // f32 = 1.0
        ];
        let mut r = Reader::new(&bytes);
        assert_eq!(r.read_u8().unwrap(), 1);
        assert_eq!(r.read_u16().unwrap(), 2);
        assert_eq!(r.read_i32().unwrap(), -1);
        assert_eq!(r.read_f32().unwrap(), 1.0);
        assert_eq!(r.remaining(), 0);
    }

    #[test]
    fn read_string_null_and_empty_and_real() {
        // null (-1), empty (0), "ok" (2 bytes)
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&(-1i32).to_le_bytes());
        bytes.extend_from_slice(&0i32.to_le_bytes());
        bytes.extend_from_slice(&2i32.to_le_bytes());
        bytes.extend_from_slice(b"ok");
        let mut r = Reader::new(&bytes);
        assert_eq!(r.read_string().unwrap(), None);
        assert_eq!(r.read_string().unwrap(), Some(""));
        assert_eq!(r.read_string().unwrap(), Some("ok"));
    }

    #[test]
    fn out_of_bounds() {
        let mut r = Reader::new(&[0x01]);
        assert!(matches!(r.read_u32(), Err(ReaderError::OutOfBounds)));
    }
}
