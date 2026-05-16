//! Custom `BronzeSink` example: count events by family in real time, with
//! memory-bounded back-pressure (no `Vec` accumulation of all events).
//!
//! This is the pattern to use for live ingest pipelines: implement
//! `BronzeSink` on whatever buffer / channel / file writer suits the
//! deployment, hand it to `engine.process_streaming(...)`, and let the
//! engine batch events to you as they're produced.
//!
//! Run:
//!     cargo run --example streaming -- path/to/capture.pcap

use std::collections::BTreeMap;
use std::env;
use std::fs::File;
use std::process;

use fm_dpi::{BronzeBatch, BronzeSink, DpiEngine, DpiError, SegmentMeta};

/// Sink that tallies events by family and protocol without buffering them.
#[derive(Default)]
struct TallySink {
    by_family: BTreeMap<&'static str, u64>,
    by_protocol: BTreeMap<String, u64>,
    batches_received: u64,
    events_total: u64,
}

impl BronzeSink for TallySink {
    fn push_batch(&mut self, batch: BronzeBatch) -> Result<(), DpiError> {
        self.batches_received += 1;
        for event in batch.events {
            self.events_total += 1;
            *self.by_family.entry(event.family_name()).or_default() += 1;
            if let Some(proto) = event.protocol() {
                *self.by_protocol.entry(proto.to_string()).or_default() += 1;
            }
        }
        Ok(())
    }
}

fn main() {
    let path = env::args().nth(1).unwrap_or_else(|| {
        eprintln!("usage: streaming <path-to-capture>");
        process::exit(2);
    });

    let file = File::open(&path).unwrap_or_else(|err| {
        eprintln!("cannot open {path}: {err}");
        process::exit(1);
    });

    let mut engine = DpiEngine::new().with_batch_size(64);
    let mut sink = TallySink::default();
    let meta = SegmentMeta::new(path.clone());

    let checkpoint = engine
        .process_streaming(&meta, file, &mut sink)
        .unwrap_or_else(|err| {
            eprintln!("DPI error: {err}");
            process::exit(1);
        });

    println!("checkpoint:");
    println!("  capture_id       = {}", checkpoint.capture_id);
    println!("  schema_version   = {}", checkpoint.schema_version);
    println!("  segment_hash     = {}", checkpoint.segment_hash);
    println!("  frames_processed = {}", checkpoint.frames_processed);
    println!("  events_emitted   = {}", checkpoint.events_emitted);
    println!();
    println!(
        "sink received {} batches, {} events",
        sink.batches_received, sink.events_total
    );
    println!();
    println!("by family:");
    for (family, count) in &sink.by_family {
        println!("  {family:<28} {count}");
    }
    println!();
    println!("top protocols:");
    let mut protos: Vec<_> = sink.by_protocol.iter().collect();
    protos.sort_by(|a, b| b.1.cmp(a.1));
    for (proto, count) in protos.iter().take(10) {
        println!("  {proto:<28} {count}");
    }
}
