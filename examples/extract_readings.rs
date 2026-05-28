//! Filter to ProcessReadings and render them as InfluxDB Line Protocol.
//! Identical to `marlinspike-dpi --format influx` but performed in-process —
//! a starting point for embedding the engine into a historian ingest path.
//!
//! ProcessReading emitters today (verified against the dissector tree):
//! Sparkplug B, OPC UA (client + PubSub), IEEE C37.118 synchrophasor, PCCC,
//! and Modbus-over-UDP. Note: Modbus/TCP, DNP3, IEC 104, IEC 61850 MMS, and
//! HART-IP do NOT emit ProcessReadings — they surface as ProtocolTransaction
//! events with values embedded in protocol-specific fields. A historian path
//! that needs VQTs from those protocols must read them off ProtocolTransaction.
//!
//! Run:
//!     cargo run --example extract_readings -- path/to/capture.pcap

use std::env;
use std::fs::File;
use std::process;

use fm_dpi::{BronzeEventFamily, DpiEngine, output::influx_line};

fn main() {
    let path = env::args().nth(1).unwrap_or_else(|| {
        eprintln!("usage: extract_readings <path-to-capture>");
        process::exit(2);
    });

    let file = File::open(&path).unwrap_or_else(|err| {
        eprintln!("cannot open {path}: {err}");
        process::exit(1);
    });

    let mut engine = DpiEngine::new();
    let events = engine.process_capture(&path, file).unwrap_or_else(|err| {
        eprintln!("DPI error: {err}");
        process::exit(1);
    });

    let readings: Vec<_> = events
        .iter()
        .filter(|event| matches!(event.family, BronzeEventFamily::ProcessReading(_)))
        .cloned()
        .collect();

    eprintln!(
        "found {} ProcessReadings (of {} total events) in {path}",
        readings.len(),
        events.len()
    );

    // Print the Influx Line Protocol output to stdout — redirect into your
    // historian's ingest endpoint, e.g.:
    //
    //   cargo run --example extract_readings -- capture.pcap | \
    //     curl --data-binary @- http://influx:8086/api/v2/write?bucket=ot
    let lp = influx_line::render_many(&readings);
    print!("{lp}");
}
