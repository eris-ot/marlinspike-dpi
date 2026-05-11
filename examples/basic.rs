//! Basic example: process a PCAP / PCAPNG capture and summarise the emitted
//! Bronze v2 events by family and protocol.
//!
//! Run:
//!     cargo run --example basic -- path/to/capture.pcapng

use std::collections::BTreeMap;
use std::env;
use std::fs::File;
use std::process;

use fm_dpi::{BronzeEvent, BronzeEventFamily, DpiEngine};

fn main() {
    let path = env::args().nth(1).unwrap_or_else(|| {
        eprintln!("usage: basic <path-to-capture.pcap|pcapng>");
        process::exit(2);
    });

    let file = File::open(&path).unwrap_or_else(|err| {
        eprintln!("cannot open {path}: {err}");
        process::exit(1);
    });

    let mut engine = DpiEngine::new();
    let events = engine
        .process_capture(&path, file)
        .unwrap_or_else(|err| {
            eprintln!("DPI error: {err}");
            process::exit(1);
        });

    println!("processed {} events from {path}", events.len());
    println!();

    let mut by_family: BTreeMap<&'static str, usize> = BTreeMap::new();
    let mut by_protocol: BTreeMap<String, usize> = BTreeMap::new();
    let mut anomaly_severity: BTreeMap<String, usize> = BTreeMap::new();

    for event in &events {
        *by_family.entry(event.family_name()).or_default() += 1;
        if let Some(proto) = event.protocol() {
            *by_protocol.entry(proto.to_string()).or_default() += 1;
        }
        if let BronzeEventFamily::ParseAnomaly(anomaly) = &event.family {
            *anomaly_severity.entry(anomaly.severity.clone()).or_default() += 1;
        }
    }

    print_table("By family", by_family.iter().map(|(k, v)| (*k, *v)));
    print_table(
        "By protocol",
        by_protocol.iter().map(|(k, v)| (k.as_str(), *v)),
    );
    if !anomaly_severity.is_empty() {
        print_table(
            "ParseAnomaly severities",
            anomaly_severity.iter().map(|(k, v)| (k.as_str(), *v)),
        );
    }

    if let Some(first) = events.first() {
        println!();
        println!("first event sample:");
        print_event(first);
    }
}

fn print_table<'a>(title: &str, rows: impl Iterator<Item = (&'a str, usize)>) {
    println!("{title}:");
    for (label, count) in rows {
        println!("  {label:<28} {count}");
    }
    println!();
}

fn print_event(event: &BronzeEvent) {
    println!("  family   : {}", event.family_name());
    println!("  protocol : {}", event.protocol().unwrap_or("(none)"));
    println!("  session  : {}", event.envelope.session_key);
    if let (Some(src), Some(dst)) = (event.src_ip(), event.dst_ip()) {
        println!("  src→dst  : {src} → {dst}");
    }
    if let Some(op) = event.operation() {
        println!("  operation: {op} ({})", event.status().unwrap_or("-"));
    }
}
