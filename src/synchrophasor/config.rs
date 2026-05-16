//! Configuration frame (CFG-2) parser. CFG-2 declares the layout of
//! subsequent data frames: per-PMU number of phasors / analogs / digitals,
//! the format flags (integer vs float, polar vs rectangular), station name,
//! and channel names.
//!
//! Without a CFG-2 we cannot interpret a data frame's bytes — like Sparkplug
//! aliases or OPC UA NodeId pairing, the data wire format is layout-dependent.

use crate::synchrophasor::reader::{Reader, ReaderError};

/// Per-PMU layout extracted from CFG-2.
#[derive(Debug, Clone)]
pub struct PmuConfig {
    pub idcode: u16,
    /// Station name, ASCII, trimmed of trailing spaces.
    pub station_name: String,
    pub format: PmuFormat,
    pub phasor_names: Vec<String>,
    pub analog_names: Vec<String>,
    /// Digital-status-word names; each word has 16 bits, so this is grouped.
    pub digital_names: Vec<String>,
}

#[derive(Debug, Clone, Copy)]
pub struct PmuFormat {
    /// True = float (4 bytes per component), False = integer (2 bytes per).
    pub phasor_is_float: bool,
    pub analog_is_float: bool,
    pub freq_is_float: bool,
    /// True = polar (mag, angle), False = rectangular (real, imag).
    pub phasor_is_polar: bool,
}

impl PmuFormat {
    fn from_word(word: u16) -> Self {
        Self {
            freq_is_float: word & 0x0001 != 0,
            analog_is_float: word & 0x0002 != 0,
            phasor_is_float: word & 0x0004 != 0,
            phasor_is_polar: word & 0x0008 != 0,
        }
    }

    /// Bytes per phasor (mag+angle or real+imag).
    pub fn phasor_size(&self) -> usize {
        if self.phasor_is_float { 8 } else { 4 }
    }

    pub fn analog_size(&self) -> usize {
        if self.analog_is_float { 4 } else { 2 }
    }

    pub fn freq_size(&self) -> usize {
        if self.freq_is_float { 4 } else { 2 }
    }
}

/// Decoded CFG-2 frame body (everything after the 14-byte common header,
/// excluding the trailing 2-byte CRC).
#[derive(Debug, Clone)]
pub struct ConfigFrame {
    pub time_base: u32,
    pub pmus: Vec<PmuConfig>,
    pub data_rate: u16,
}

/// Read a 16-byte STN/CHNAM field, ASCII space-padded. Trim trailing spaces
/// and nulls.
fn read_chnam(r: &mut Reader<'_>) -> Result<String, ReaderError> {
    let bytes = r.read_array::<16>()?;
    let s = std::str::from_utf8(&bytes).unwrap_or("");
    Ok(s.trim_end_matches([' ', '\0']).to_string())
}

pub fn parse_config_frame(r: &mut Reader<'_>) -> Result<ConfigFrame, ReaderError> {
    let time_base_word = r.read_u32()?;
    let time_base = time_base_word & 0x00FF_FFFF; // low 24 bits per spec
    let num_pmu = r.read_u16()? as usize;
    let mut pmus = Vec::with_capacity(num_pmu);
    for _ in 0..num_pmu {
        let station_name = read_chnam(r)?;
        let idcode = r.read_u16()?;
        let format = PmuFormat::from_word(r.read_u16()?);
        let phnmr = r.read_u16()? as usize;
        let annmr = r.read_u16()? as usize;
        let dgnmr = r.read_u16()? as usize;

        let mut phasor_names = Vec::with_capacity(phnmr);
        for _ in 0..phnmr {
            phasor_names.push(read_chnam(r)?);
        }
        let mut analog_names = Vec::with_capacity(annmr);
        for _ in 0..annmr {
            analog_names.push(read_chnam(r)?);
        }
        // Each digital status WORD has 16 bit-channel names.
        let total_digital_bits = dgnmr.saturating_mul(16);
        let mut digital_names = Vec::with_capacity(total_digital_bits);
        for _ in 0..total_digital_bits {
            digital_names.push(read_chnam(r)?);
        }
        // PHUNIT / ANUNIT / DIGUNIT — skip 4 bytes each per channel/word.
        r.skip(4 * phnmr)?;
        r.skip(4 * annmr)?;
        r.skip(4 * dgnmr)?;
        // FNOM (2) + CFGCNT (2)
        r.skip(4)?;

        pmus.push(PmuConfig {
            idcode,
            station_name,
            format,
            phasor_names,
            analog_names,
            digital_names,
        });
    }
    let data_rate = r.read_u16()?;
    Ok(ConfigFrame {
        time_base,
        pmus,
        data_rate,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pad16(s: &str) -> [u8; 16] {
        let mut out = [b' '; 16];
        let bytes = s.as_bytes();
        let n = bytes.len().min(16);
        out[..n].copy_from_slice(&bytes[..n]);
        out
    }

    fn build_minimal_cfg2() -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&1_000_000u32.to_be_bytes()); // time_base
        bytes.extend_from_slice(&1u16.to_be_bytes()); // num_pmu
        // PMU 1: STN=Station1, IDCODE=7, FORMAT=polar+integer, PHNMR=2, ANNMR=1, DGNMR=1
        bytes.extend_from_slice(&pad16("Station1"));
        bytes.extend_from_slice(&7u16.to_be_bytes());
        bytes.extend_from_slice(&0x0008u16.to_be_bytes()); // polar phasor, all integer
        bytes.extend_from_slice(&2u16.to_be_bytes()); // PHNMR
        bytes.extend_from_slice(&1u16.to_be_bytes()); // ANNMR
        bytes.extend_from_slice(&1u16.to_be_bytes()); // DGNMR
        bytes.extend_from_slice(&pad16("VA")); // phasor 1 name
        bytes.extend_from_slice(&pad16("VB")); // phasor 2 name
        bytes.extend_from_slice(&pad16("Temp")); // analog 1 name
        for i in 0..16 {
            bytes.extend_from_slice(&pad16(&format!("D{i}")));
        }
        bytes.extend_from_slice(&[0; 4 * 2]); // PHUNIT × 2
        bytes.extend_from_slice(&[0; 4 * 1]); // ANUNIT × 1
        bytes.extend_from_slice(&[0; 4 * 1]); // DIGUNIT × 1
        bytes.extend_from_slice(&[0; 4]); // FNOM + CFGCNT
        bytes.extend_from_slice(&30u16.to_be_bytes()); // data_rate
        bytes
    }

    #[test]
    fn parse_minimal_cfg2() {
        let bytes = build_minimal_cfg2();
        let mut r = Reader::new(&bytes);
        let cfg = parse_config_frame(&mut r).unwrap();
        assert_eq!(cfg.time_base, 1_000_000);
        assert_eq!(cfg.pmus.len(), 1);
        assert_eq!(cfg.pmus[0].idcode, 7);
        assert_eq!(cfg.pmus[0].station_name, "Station1");
        assert_eq!(cfg.pmus[0].phasor_names, vec!["VA", "VB"]);
        assert_eq!(cfg.pmus[0].analog_names, vec!["Temp"]);
        assert_eq!(cfg.pmus[0].digital_names.len(), 16);
        assert_eq!(cfg.pmus[0].format.phasor_is_polar, true);
        assert_eq!(cfg.pmus[0].format.phasor_is_float, false);
        assert_eq!(cfg.data_rate, 30);
    }
}
