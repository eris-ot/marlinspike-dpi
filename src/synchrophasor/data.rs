//! IEEE C37.118 data frame parser. Decodes one frame's worth of samples
//! using a known-ahead-of-time `[PmuConfig]` (from a prior CFG-2 frame).
//!
//! Layout per PMU in a data frame:
//!   STAT (2 bytes)
//!   phasors[PHNMR]      (4 or 8 bytes each, integer or float)
//!   FREQ                (2 or 4 bytes)
//!   DFREQ               (2 or 4 bytes)
//!   analogs[ANNMR]      (2 or 4 bytes each)
//!   digitals[DGNMR]     (2 bytes each)

use crate::synchrophasor::config::{PmuConfig, PmuFormat};
use crate::synchrophasor::reader::{Reader, ReaderError};

#[derive(Debug, Clone)]
pub struct PmuData {
    pub idcode: u16,
    pub stat: u16,
    pub phasors: Vec<PhasorReading>,
    /// Frequency in Hz.
    pub freq: f64,
    /// Rate of change of frequency in Hz/s.
    pub dfreq: f64,
    pub analogs: Vec<f64>,
    pub digitals: Vec<u16>,
}

#[derive(Debug, Clone, Copy)]
pub struct PhasorReading {
    pub magnitude: f64,
    pub angle: f64, // radians
}

pub fn parse_data_frame(
    r: &mut Reader<'_>,
    pmus: &[PmuConfig],
) -> Result<Vec<PmuData>, ReaderError> {
    let mut out = Vec::with_capacity(pmus.len());
    for pmu in pmus {
        let stat = r.read_u16()?;
        let phasors = read_phasors(r, &pmu.format, pmu.phasor_names.len())?;
        let freq = read_freq(r, &pmu.format, true)?;
        let dfreq = read_freq(r, &pmu.format, false)?;
        let analogs = read_analogs(r, &pmu.format, pmu.analog_names.len())?;
        let digital_words = pmu.digital_names.len() / 16;
        let mut digitals = Vec::with_capacity(digital_words);
        for _ in 0..digital_words {
            digitals.push(r.read_u16()?);
        }
        out.push(PmuData {
            idcode: pmu.idcode,
            stat,
            phasors,
            freq,
            dfreq,
            analogs,
            digitals,
        });
    }
    Ok(out)
}

fn read_phasors(
    r: &mut Reader<'_>,
    fmt: &PmuFormat,
    n: usize,
) -> Result<Vec<PhasorReading>, ReaderError> {
    let mut out = Vec::with_capacity(n);
    for _ in 0..n {
        let (a, b) = if fmt.phasor_is_float {
            (r.read_f32()? as f64, r.read_f32()? as f64)
        } else {
            // Integer format: per spec, mag is unsigned 16-bit when polar,
            // and rect components are signed 16-bit. We surface both
            // components without scaling — full PHUNIT-aware scaling is
            // future work since it requires the per-channel unit factor.
            if fmt.phasor_is_polar {
                let mag = r.read_u16()? as f64;
                let angle_int = r.read_i16()? as f64;
                // Integer-format angle is in 1e-4 radians per spec.
                (mag, angle_int * 1e-4)
            } else {
                let real = r.read_i16()? as f64;
                let imag = r.read_i16()? as f64;
                (real, imag)
            }
        };
        let (magnitude, angle) = if fmt.phasor_is_polar {
            (a, b)
        } else {
            // Convert rect → polar.
            let mag = (a * a + b * b).sqrt();
            let ang = b.atan2(a);
            (mag, ang)
        };
        out.push(PhasorReading { magnitude, angle });
    }
    Ok(out)
}

fn read_freq(r: &mut Reader<'_>, fmt: &PmuFormat, is_freq: bool) -> Result<f64, ReaderError> {
    if fmt.freq_is_float {
        Ok(r.read_f32()? as f64)
    } else {
        // Integer format: signed 16-bit deviation from nominal in mHz (FREQ)
        // or Hz/s × 100 (DFREQ). We surface raw deviation; embedder applies
        // nominal frequency offset and unit interpretation if needed.
        let raw = r.read_i16()? as f64;
        if is_freq {
            Ok(raw / 1000.0) // mHz → Hz deviation
        } else {
            Ok(raw / 100.0) // 0.01 Hz/s units
        }
    }
}

fn read_analogs(r: &mut Reader<'_>, fmt: &PmuFormat, n: usize) -> Result<Vec<f64>, ReaderError> {
    let mut out = Vec::with_capacity(n);
    for _ in 0..n {
        if fmt.analog_is_float {
            out.push(r.read_f32()? as f64);
        } else {
            out.push(r.read_i16()? as f64);
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::synchrophasor::config::PmuFormat;

    fn cfg(format: PmuFormat, n_phasors: usize, n_analogs: usize) -> PmuConfig {
        PmuConfig {
            idcode: 1,
            station_name: "S".into(),
            format,
            phasor_names: (0..n_phasors).map(|i| format!("P{i}")).collect(),
            analog_names: (0..n_analogs).map(|i| format!("A{i}")).collect(),
            digital_names: Vec::new(),
        }
    }

    #[test]
    fn parses_float_polar_data() {
        let format = PmuFormat {
            phasor_is_float: true,
            analog_is_float: true,
            freq_is_float: true,
            phasor_is_polar: true,
        };
        let pmus = vec![cfg(format, 1, 1)];
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&0u16.to_be_bytes()); // STAT
        bytes.extend_from_slice(&7320.5f32.to_be_bytes()); // mag
        bytes.extend_from_slice(&0.523f32.to_be_bytes()); // angle (rad)
        bytes.extend_from_slice(&60.001f32.to_be_bytes()); // freq
        bytes.extend_from_slice(&0.05f32.to_be_bytes()); // dfreq
        bytes.extend_from_slice(&72.5f32.to_be_bytes()); // analog
        let mut r = Reader::new(&bytes);
        let pmus_out = parse_data_frame(&mut r, &pmus).unwrap();
        assert_eq!(pmus_out.len(), 1);
        let p = &pmus_out[0];
        assert_eq!(p.idcode, 1);
        assert!((p.phasors[0].magnitude - 7320.5).abs() < 1e-3);
        assert!((p.phasors[0].angle - 0.523).abs() < 1e-3);
        assert!((p.freq - 60.001).abs() < 1e-3);
        assert!((p.dfreq - 0.05).abs() < 1e-3);
        assert!((p.analogs[0] - 72.5).abs() < 1e-3);
    }

    #[test]
    fn parses_integer_polar_data() {
        let format = PmuFormat {
            phasor_is_float: false,
            analog_is_float: false,
            freq_is_float: false,
            phasor_is_polar: true,
        };
        let pmus = vec![cfg(format, 1, 0)];
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&0u16.to_be_bytes()); // STAT
        bytes.extend_from_slice(&12345u16.to_be_bytes()); // mag
        bytes.extend_from_slice(&5230i16.to_be_bytes()); // angle 0.523 rad
        bytes.extend_from_slice(&1i16.to_be_bytes()); // freq deviation +0.001 Hz
        bytes.extend_from_slice(&5i16.to_be_bytes()); // dfreq 0.05 Hz/s
        let mut r = Reader::new(&bytes);
        let p = &parse_data_frame(&mut r, &pmus).unwrap()[0];
        assert_eq!(p.phasors[0].magnitude as u32, 12345);
        assert!((p.phasors[0].angle - 0.523).abs() < 1e-3);
        assert!((p.freq - 0.001).abs() < 1e-6);
        assert!((p.dfreq - 0.05).abs() < 1e-6);
    }

    #[test]
    fn rectangular_phasor_converts_to_polar() {
        let format = PmuFormat {
            phasor_is_float: true,
            analog_is_float: true,
            freq_is_float: true,
            phasor_is_polar: false,
        };
        let pmus = vec![cfg(format, 1, 0)];
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&0u16.to_be_bytes());
        // real=3, imag=4 → mag=5, angle=atan2(4,3)
        bytes.extend_from_slice(&3.0f32.to_be_bytes());
        bytes.extend_from_slice(&4.0f32.to_be_bytes());
        bytes.extend_from_slice(&60.0f32.to_be_bytes());
        bytes.extend_from_slice(&0.0f32.to_be_bytes());
        let mut r = Reader::new(&bytes);
        let p = &parse_data_frame(&mut r, &pmus).unwrap()[0];
        assert!((p.phasors[0].magnitude - 5.0).abs() < 1e-6);
        assert!((p.phasors[0].angle - 4f64.atan2(3.0)).abs() < 1e-6);
    }
}
