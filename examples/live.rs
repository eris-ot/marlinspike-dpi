//! Live ingest: drive the engine from a non-file source, one frame at a time.
//!
//! The batch entry points (`process_capture`, `process_streaming`) want
//! PCAP/PCAPNG-framed bytes. A live source — libpcap, AF_PACKET, an XDP ring,
//! an FFI callback — already has *parsed* frames in hand and shouldn't have to
//! re-wrap them as fake file records just to feed the engine.
//!
//! [`DpiEngine::live_session`] (and the iterator form [`DpiEngine::process_frames`])
//! take a [`CapturedFrame`] — raw link-layer bytes plus the per-frame metadata
//! the engine tracks anyway (interface, capture timestamp, [`LinkType`], lengths)
//! — and run the same dissection, flow-tracking, idle-eviction, and batch
//! back-pressure as the file path. Flow state is preserved across the whole
//! session; nothing is finalized until you call `finish()`.
//!
//! NOTE: this does not capture packets — it does not bind sockets or read
//! interfaces. It is the entry point a capture source plugs *into*. Here we
//! synthesize a few `DLT_RAW` (L3-first) frames so the example runs with no NIC
//! and no capture file. A real AF_PACKET / XDP loop would substitute its own
//! frame bytes, link type, and kernel timestamp.
//!
//! Run:
//!     cargo run --example live

use chrono::{DateTime, TimeZone, Utc};

use fm_dpi::{
    BronzeBatch, BronzeSink, CapturedFrame, DpiEngine, DpiError, LinkType, SegmentMeta,
};

/// Minimal sink: tally events as the engine flushes them, no buffering.
#[derive(Default)]
struct CountingSink {
    batches: u64,
    events: u64,
    transactions: u64,
}

impl BronzeSink for CountingSink {
    fn push_batch(&mut self, batch: BronzeBatch) -> Result<(), DpiError> {
        self.batches += 1;
        for event in &batch.events {
            self.events += 1;
            if event.family_name() == "protocol_transaction" {
                self.transactions += 1;
            }
        }
        Ok(())
    }
}

/// Build a raw IPv4 + TCP segment (no Ethernet header) carrying `payload`.
/// This is exactly what a `DLT_RAW` / AF_PACKET cooked source hands you: bytes
/// that begin at the IP header.
fn raw_ipv4_tcp(
    src: [u8; 4],
    dst: [u8; 4],
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> Vec<u8> {
    let total_len = 20 + 20 + payload.len();
    let mut pkt = Vec::with_capacity(total_len);

    // IPv4 header (20 bytes, no options).
    pkt.extend_from_slice(&[
        0x45, // version 4, IHL 5
        0x00, // DSCP/ECN
        (total_len >> 8) as u8,
        (total_len & 0xFF) as u8,
        0x00,
        0x01, // identification
        0x00,
        0x00, // flags/fragment
        64,   // TTL
        6,    // protocol = TCP
        0x00,
        0x00, // header checksum (engine does not require a valid one)
    ]);
    pkt.extend_from_slice(&src);
    pkt.extend_from_slice(&dst);

    // TCP header (20 bytes, no options).
    pkt.extend_from_slice(&src_port.to_be_bytes());
    pkt.extend_from_slice(&dst_port.to_be_bytes());
    pkt.extend_from_slice(&1u32.to_be_bytes()); // seq
    pkt.extend_from_slice(&0u32.to_be_bytes()); // ack
    pkt.push(0x50); // data offset 5
    pkt.push(0x18); // PSH+ACK
    pkt.extend_from_slice(&0x2000u16.to_be_bytes()); // window
    pkt.extend_from_slice(&0u16.to_be_bytes()); // checksum
    pkt.extend_from_slice(&0u16.to_be_bytes()); // urgent ptr

    pkt.extend_from_slice(payload);
    pkt
}

fn main() {
    // Modbus/TCP read-holding-registers request, port 502.
    let modbus_req = [
        0x00, 0x01, 0x00, 0x00, 0x00, 0x06, 0x01, 0x03, 0x00, 0x64, 0x00, 0x02,
    ];
    let modbus_resp = [
        0x00, 0x01, 0x00, 0x00, 0x00, 0x07, 0x01, 0x03, 0x04, 0x00, 0x0A, 0x00, 0x14,
    ];

    // Pretend these arrived off the wire, oldest first. A real source supplies
    // its own kernel timestamps; we fabricate monotonic ones here.
    let frames = [
        raw_ipv4_tcp([10, 0, 0, 50], [10, 0, 0, 1], 49152, 502, &modbus_req),
        raw_ipv4_tcp([10, 0, 0, 1], [10, 0, 0, 50], 502, 49152, &modbus_resp),
    ];
    let base: DateTime<Utc> = Utc.timestamp_opt(1_700_000_000, 0).single().unwrap();

    let mut engine = DpiEngine::new().with_batch_size(16);
    let mut sink = CountingSink::default();

    // Push-style session — the shape an AF_PACKET poll loop or FFI callback
    // wants: feed frames as they arrive, finalize once at shutdown. (For a
    // source you can express as a Rust iterator, `engine.process_frames(&meta,
    // iter, &mut sink)` does the same in one call.)
    let mut session = engine.live_session(SegmentMeta::new("live-demo"), &mut sink);
    for (i, frame) in frames.iter().enumerate() {
        session
            .push(CapturedFrame {
                interface_id: 0,
                timestamp: base + chrono::Duration::milliseconds(i as i64 * 100),
                linktype: LinkType::RawIp,
                captured_len: frame.len(),
                orig_len: frame.len() as u32,
                data: frame,
            })
            .expect("push frame");
    }
    let checkpoint = session.finish().expect("finalize session");

    println!("checkpoint:");
    println!("  capture_id       = {}", checkpoint.capture_id);
    println!("  segment_hash     = {} (rolling SHA-256 over frame bytes)", checkpoint.segment_hash);
    println!("  frames_processed = {}", checkpoint.frames_processed);
    println!("  events_emitted   = {}", checkpoint.events_emitted);
    println!();
    println!(
        "sink saw {} batches / {} events / {} protocol transactions",
        sink.batches, sink.events, sink.transactions
    );
}
