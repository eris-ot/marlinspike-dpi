//! Render Bronze events as OCSF v1.4.0 NDJSON. Equivalent to
//! `marlinspike-dpi --format ocsf` from the library side, so you can plug
//! this directly into a SIEM ingest pipeline.
//!
//! ProtocolTransaction → Network Activity (4001) / HTTP (4002) / DNS (4003) /
//! SMB (4006) / SSH (4007) / Authentication (3002), depending on protocol.
//! AssetObservation → Device Inventory Info (5001).
//! ParseAnomaly → Detection Finding (2004).
//! ProcessReading / ExtractedArtifact / TopologyObservation have no OCSF home
//! and are dropped (use Bronze JSON or InfluxDB Line Protocol for those).
//!
//! Run:
//!     cargo run --example ocsf_output -- path/to/capture.pcap > events.ndjson

use std::env;
use std::fs::File;
use std::io::{self, Write};
use std::process;

use fm_dpi::{DpiEngine, output::ocsf};

fn main() {
    let path = env::args().nth(1).unwrap_or_else(|| {
        eprintln!("usage: ocsf_output <path-to-capture> > events.ndjson");
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

    let stdout = io::stdout();
    let mut out = stdout.lock();
    let mut emitted = 0usize;
    for event in &events {
        if let Some(line) = ocsf::render_event_string(event) {
            writeln!(out, "{line}").expect("stdout write");
            emitted += 1;
        }
    }
    eprintln!(
        "rendered {emitted} OCSF records from {} Bronze events",
        events.len()
    );
}
