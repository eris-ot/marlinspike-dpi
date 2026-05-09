//! Big-endian cursor for IEEE C37.118 frame parsing. (Synchrophasor frames
//! are network-byte-order; this is distinct from OPC UA's little-endian.)

#[derive(Debug)]
pub struct Reader<'a> {
    bytes: &'a [u8],
    pos: usize,
}

#[derive(Debug, Clone, Copy)]
pub enum ReaderError {
    OutOfBounds,
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

    pub fn read_u16(&mut self) -> Result<u16, ReaderError> {
        let bytes = self.read_array::<2>()?;
        Ok(u16::from_be_bytes(bytes))
    }

    pub fn read_i16(&mut self) -> Result<i16, ReaderError> {
        Ok(self.read_u16()? as i16)
    }

    pub fn read_u32(&mut self) -> Result<u32, ReaderError> {
        let bytes = self.read_array::<4>()?;
        Ok(u32::from_be_bytes(bytes))
    }

    pub fn read_f32(&mut self) -> Result<f32, ReaderError> {
        let bytes = self.read_array::<4>()?;
        Ok(f32::from_be_bytes(bytes))
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
}
