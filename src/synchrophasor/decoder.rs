//! Stateful synchrophasor decoder. Tracks one CFG-2 per source IP+IDCODE so
//! that subsequent data frames can be decoded into typed
//! [`crate::bronze::ProcessReading`] events.

use std::collections::HashMap;
use std::net::IpAddr;

use crate::bronze::{
    BRONZE_SCHEMA_VERSION, BronzeEvent, BronzeEventFamily, EventEnvelope, PointIdentifier,
    PointValue, ProcessReading, RawQuality, SynchrophasorChannelType,
};
use crate::synchrophasor::config::{ConfigFrame, parse_config_frame};
use crate::synchrophasor::data::parse_data_frame;
use crate::synchrophasor::frame::{FrameType, read_common_header};
use crate::synchrophasor::reader::Reader;

const SOURCE_PROTOCOL: &str = "synchrophasor";

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct SessionKey {
    src_ip: IpAddr,
    pdc_idcode: u16,
}

#[derive(Default)]
pub struct SynchrophasorDecoder {
    configs: HashMap<SessionKey, ConfigFrame>,
    event_id_counter: u64,
}

impl SynchrophasorDecoder {
    pub fn new() -> Self {
        Self::default()
    }

    fn next_event_id(&mut self) -> String {
        self.event_id_counter = self.event_id_counter.wrapping_add(1);
        format!("synphasor-{}", self.event_id_counter)
    }

    pub fn config_count(&self) -> usize {
        self.configs.len()
    }

    /// Process one synchrophasor frame body. `src_ip` is used as part of the
    /// session key alongside the frame's IDCODE so configs from different
    /// publishers don't collide. Returns Bronze events for data frames; CFG
    /// frames update internal state and emit nothing.
    pub fn handle_frame(
        &mut self,
        bytes: &[u8],
        src_ip: IpAddr,
        envelope: &EventEnvelope,
        capture_id: &str,
    ) -> Vec<BronzeEvent> {
        let mut r = Reader::new(bytes);
        let header = match read_common_header(&mut r) {
            Ok(h) => h,
            Err(_) => return Vec::new(),
        };
        let key = SessionKey {
            src_ip,
            pdc_idcode: header.idcode,
        };

        match header.frame_type {
            FrameType::Config1 | FrameType::Config2 | FrameType::Config3 => {
                if let Ok(cfg) = parse_config_frame(&mut r) {
                    self.configs.insert(key, cfg);
                }
                Vec::new()
            }
            FrameType::Data => {
                let Some(cfg) = self.configs.get(&key) else {
                    return Vec::new();
                };
                let time_base = cfg.time_base;
                // Clone PMU layouts to release the borrow before mutable use.
                let pmus = cfg.pmus.clone();
                let Ok(pmu_data) = parse_data_frame(&mut r, &pmus) else {
                    return Vec::new();
                };
                let observed_ts = envelope_us(envelope);
                let source_ts = Some(header.timestamp_us(time_base));
                let mut out = Vec::new();
                for (pmu_cfg, pdata) in pmus.iter().zip(pmu_data.iter()) {
                    self.emit_pmu_readings(
                        pmu_cfg,
                        pdata,
                        envelope,
                        capture_id,
                        source_ts,
                        observed_ts,
                        &mut out,
                    );
                }
                out
            }
            FrameType::Header | FrameType::Command => Vec::new(),
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn emit_pmu_readings(
        &mut self,
        cfg: &crate::synchrophasor::config::PmuConfig,
        data: &crate::synchrophasor::data::PmuData,
        envelope: &EventEnvelope,
        capture_id: &str,
        source_ts: Option<u64>,
        observed_ts: u64,
        out: &mut Vec<BronzeEvent>,
    ) {
        let station_name = if cfg.station_name.is_empty() {
            None
        } else {
            Some(cfg.station_name.clone())
        };
        let make_event = |this: &mut Self,
                          channel_index: u16,
                          channel_name: Option<String>,
                          channel_type: SynchrophasorChannelType,
                          value: PointValue|
         -> BronzeEvent {
            BronzeEvent {
                event_id: this.next_event_id(),
                capture_id: capture_id.to_string(),
                schema_version: BRONZE_SCHEMA_VERSION.into(),
                envelope: envelope.clone(),
                family: BronzeEventFamily::ProcessReading(ProcessReading {
                    source_protocol: SOURCE_PROTOCOL.into(),
                    point_id: PointIdentifier::SynchrophasorChannel {
                        idcode: cfg.idcode,
                        station_name: station_name.clone(),
                        channel_index,
                        channel_name,
                        channel_type,
                    },
                    value,
                    // STAT word carries the C37.118 status flags; surface it
                    // through Iec61850Quality (16-bit) since RawQuality has
                    // no synchrophasor-specific variant. No interpretation
                    // applied — embedder owns mapping.
                    quality: RawQuality::Iec61850Quality(data.stat),
                    source_ts,
                    observed_ts,
                }),
            }
        };

        // Phasors → 2 channels each (magnitude + angle).
        let mut idx: u16 = 0;
        for (i, phasor) in data.phasors.iter().enumerate() {
            let name = cfg.phasor_names.get(i).cloned();
            out.push(make_event(
                self,
                idx,
                name.clone(),
                SynchrophasorChannelType::PhasorMagnitude,
                PointValue::Double(phasor.magnitude),
            ));
            idx += 1;
            out.push(make_event(
                self,
                idx,
                name,
                SynchrophasorChannelType::PhasorAngle,
                PointValue::Double(phasor.angle),
            ));
            idx += 1;
        }
        // FREQ + DFREQ (single-valued, no name in CFG-2).
        out.push(make_event(
            self,
            idx,
            None,
            SynchrophasorChannelType::Frequency,
            PointValue::Double(data.freq),
        ));
        idx += 1;
        out.push(make_event(
            self,
            idx,
            None,
            SynchrophasorChannelType::FrequencyDerivative,
            PointValue::Double(data.dfreq),
        ));
        idx += 1;
        // Analogs.
        for (i, v) in data.analogs.iter().enumerate() {
            out.push(make_event(
                self,
                idx,
                cfg.analog_names.get(i).cloned(),
                SynchrophasorChannelType::Analog,
                PointValue::Double(*v),
            ));
            idx += 1;
        }
        // Digital status words. Each word is one reading; bit-level decode
        // is left to the embedder using cfg.digital_names if needed.
        for (i, word) in data.digitals.iter().enumerate() {
            // Compose a name from the 16 bit-channel names of this word.
            let bit_start = i * 16;
            let name = cfg
                .digital_names
                .get(bit_start)
                .cloned()
                .map(|first| format!("{first}_word{i}"));
            out.push(make_event(
                self,
                idx,
                name,
                SynchrophasorChannelType::Digital,
                PointValue::UInt16(*word),
            ));
            idx += 1;
        }
    }
}

fn envelope_us(env: &EventEnvelope) -> u64 {
    let nanos = env.timestamp.timestamp_nanos_opt().unwrap_or(0);
    if nanos < 0 { 0 } else { (nanos / 1_000) as u64 }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bronze::TransportProtocol;
    use chrono::{DateTime, Utc};
    use std::net::Ipv4Addr;

    fn pad16(s: &str) -> [u8; 16] {
        let mut out = [b' '; 16];
        let bytes = s.as_bytes();
        let n = bytes.len().min(16);
        out[..n].copy_from_slice(&bytes[..n]);
        out
    }

    fn build_common(frame_type: u8, idcode: u16, soc: u32, fracsec: u32) -> Vec<u8> {
        let mut b = Vec::new();
        b.push(0xAA);
        b.push((frame_type << 4) | 0x01);
        b.extend_from_slice(&100u16.to_be_bytes());
        b.extend_from_slice(&idcode.to_be_bytes());
        b.extend_from_slice(&soc.to_be_bytes());
        b.extend_from_slice(&fracsec.to_be_bytes());
        b
    }

    fn build_cfg2_one_pmu_one_phasor_one_analog(idcode: u16) -> Vec<u8> {
        let mut bytes = build_common(3, idcode, 0, 0);
        // CFG body
        bytes.extend_from_slice(&1_000_000u32.to_be_bytes()); // time_base
        bytes.extend_from_slice(&1u16.to_be_bytes()); // num_pmu
        bytes.extend_from_slice(&pad16("Station1"));
        bytes.extend_from_slice(&idcode.to_be_bytes());
        // FORMAT: phasor float (0x04), polar (0x08), analog float (0x02), freq float (0x01)
        bytes.extend_from_slice(&0x000Fu16.to_be_bytes());
        bytes.extend_from_slice(&1u16.to_be_bytes()); // PHNMR
        bytes.extend_from_slice(&1u16.to_be_bytes()); // ANNMR
        bytes.extend_from_slice(&0u16.to_be_bytes()); // DGNMR
        bytes.extend_from_slice(&pad16("VA"));
        bytes.extend_from_slice(&pad16("Temp"));
        bytes.extend_from_slice(&[0; 4]); // PHUNIT
        bytes.extend_from_slice(&[0; 4]); // ANUNIT
        bytes.extend_from_slice(&60u16.to_be_bytes()); // FNOM
        bytes.extend_from_slice(&1u16.to_be_bytes()); // CFGCNT
        bytes.extend_from_slice(&30u16.to_be_bytes()); // data_rate
        bytes
    }

    fn build_data_one_pmu(idcode: u16, mag: f32, angle: f32, freq: f32, analog: f32) -> Vec<u8> {
        let mut bytes = build_common(0, idcode, 1_700_000_000, 500_000);
        bytes.extend_from_slice(&0u16.to_be_bytes()); // STAT
        bytes.extend_from_slice(&mag.to_be_bytes());
        bytes.extend_from_slice(&angle.to_be_bytes());
        bytes.extend_from_slice(&freq.to_be_bytes());
        bytes.extend_from_slice(&0.0f32.to_be_bytes()); // DFREQ
        bytes.extend_from_slice(&analog.to_be_bytes());
        bytes
    }

    fn envelope() -> EventEnvelope {
        EventEnvelope {
            timestamp: DateTime::<Utc>::from_timestamp(1_700_000_001, 0).unwrap(),
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
            protocol: Some("synchrophasor".into()),
            bytes_count: 0,
            packet_count: 1,
        }
    }

    #[test]
    fn cfg2_then_data_emits_paired_readings() {
        let mut d = SynchrophasorDecoder::new();
        let src: IpAddr = Ipv4Addr::new(10, 0, 0, 5).into();
        let cfg_bytes = build_cfg2_one_pmu_one_phasor_one_analog(7);
        let data_bytes = build_data_one_pmu(7, 7320.5, 0.523, 60.001, 72.5);
        let env = envelope();
        let cfg_events = d.handle_frame(&cfg_bytes, src, &env, "cap");
        assert!(cfg_events.is_empty(), "CFG emits no readings");
        assert_eq!(d.config_count(), 1);

        let data_events = d.handle_frame(&data_bytes, src, &env, "cap");
        // 1 phasor → 2 (mag+angle), 1 freq, 1 dfreq, 1 analog = 5
        assert_eq!(data_events.len(), 5);
        let kinds: Vec<_> = data_events
            .iter()
            .filter_map(|ev| match &ev.family {
                BronzeEventFamily::ProcessReading(r) => Some(&r.point_id),
                _ => None,
            })
            .collect();
        assert!(matches!(
            kinds[0],
            PointIdentifier::SynchrophasorChannel {
                channel_type: SynchrophasorChannelType::PhasorMagnitude,
                ..
            }
        ));
        assert!(matches!(
            kinds[1],
            PointIdentifier::SynchrophasorChannel {
                channel_type: SynchrophasorChannelType::PhasorAngle,
                ..
            }
        ));
        // Source timestamp should come from SOC + FRACSEC: 1_700_000_000s + 0.5s.
        let mag_reading = match &data_events[0].family {
            BronzeEventFamily::ProcessReading(r) => r,
            _ => panic!(),
        };
        assert_eq!(mag_reading.source_ts, Some(1_700_000_000_500_000));
    }

    #[test]
    fn data_without_prior_cfg_emits_nothing() {
        let mut d = SynchrophasorDecoder::new();
        let src: IpAddr = Ipv4Addr::new(10, 0, 0, 5).into();
        let data_bytes = build_data_one_pmu(7, 100.0, 0.0, 60.0, 0.0);
        let env = envelope();
        let events = d.handle_frame(&data_bytes, src, &env, "cap");
        assert!(events.is_empty());
    }

    #[test]
    fn different_src_ip_isolates_config_state() {
        let mut d = SynchrophasorDecoder::new();
        let cfg_bytes = build_cfg2_one_pmu_one_phasor_one_analog(7);
        let data_bytes = build_data_one_pmu(7, 1.0, 0.0, 60.0, 0.0);
        let env = envelope();
        let src_a: IpAddr = Ipv4Addr::new(10, 0, 0, 5).into();
        let src_b: IpAddr = Ipv4Addr::new(10, 0, 0, 6).into();
        let _ = d.handle_frame(&cfg_bytes, src_a, &env, "cap");
        // Same IDCODE on different IP → no config registered for that key.
        let events = d.handle_frame(&data_bytes, src_b, &env, "cap");
        assert!(events.is_empty());
    }
}
