//! Benchmarks for the streaming DPI engine over mixed protocol corpora.

use criterion::{BenchmarkId, Criterion, Throughput, black_box, criterion_group, criterion_main};

use fm_dpi::engine::{DpiEngine, SegmentMeta};

fn build_epb(packet: &[u8], timestamp_us: u64) -> Vec<u8> {
    let mut block = Vec::new();
    let block_len = 32 + packet.len() + ((4 - packet.len() % 4) % 4);
    block.extend_from_slice(&0x0000_0006u32.to_le_bytes());
    block.extend_from_slice(&(block_len as u32).to_le_bytes());
    block.extend_from_slice(&0u32.to_le_bytes());
    block.extend_from_slice(&((timestamp_us >> 32) as u32).to_le_bytes());
    block.extend_from_slice(&(timestamp_us as u32).to_le_bytes());
    block.extend_from_slice(&(packet.len() as u32).to_le_bytes());
    block.extend_from_slice(&(packet.len() as u32).to_le_bytes());
    block.extend_from_slice(packet);
    while block.len() < block_len - 4 {
        block.push(0);
    }
    block.extend_from_slice(&(block_len as u32).to_le_bytes());
    block
}

fn build_pcapng(packets: &[Vec<u8>]) -> Vec<u8> {
    let mut data = Vec::new();
    data.extend_from_slice(&0x0A0D0D0Au32.to_le_bytes());
    data.extend_from_slice(&28u32.to_le_bytes());
    data.extend_from_slice(&0x1A2B3C4Du32.to_le_bytes());
    data.extend_from_slice(&1u16.to_le_bytes());
    data.extend_from_slice(&0u16.to_le_bytes());
    data.extend_from_slice(&0xFFFF_FFFF_FFFF_FFFFu64.to_le_bytes());
    data.extend_from_slice(&28u32.to_le_bytes());
    for (index, packet) in packets.iter().enumerate() {
        data.extend_from_slice(&build_epb(
            packet,
            1_700_000_000_000_000 + (index as u64 * 100_000),
        ));
    }
    data
}

#[allow(clippy::too_many_arguments)]
fn ethernet_ipv4_tcp(
    src_mac: [u8; 6],
    dst_mac: [u8; 6],
    src_ip: [u8; 4],
    dst_ip: [u8; 4],
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
    vlan_id: Option<u16>,
) -> Vec<u8> {
    let mut frame = Vec::new();
    frame.extend_from_slice(&dst_mac);
    frame.extend_from_slice(&src_mac);
    if let Some(vlan_id) = vlan_id {
        frame.extend_from_slice(&0x8100u16.to_be_bytes());
        frame.extend_from_slice(&(vlan_id & 0x0FFF).to_be_bytes());
        frame.extend_from_slice(&0x0800u16.to_be_bytes());
    } else {
        frame.extend_from_slice(&0x0800u16.to_be_bytes());
    }

    let total_len = 20 + 20 + payload.len();
    frame.extend_from_slice(&[
        0x45,
        0x00,
        ((total_len >> 8) & 0xFF) as u8,
        (total_len & 0xFF) as u8,
        0x00,
        0x01,
        0x00,
        0x00,
        64,
        6,
        0,
        0,
    ]);
    frame.extend_from_slice(&src_ip);
    frame.extend_from_slice(&dst_ip);
    frame.extend_from_slice(&src_port.to_be_bytes());
    frame.extend_from_slice(&dst_port.to_be_bytes());
    frame.extend_from_slice(&1u32.to_be_bytes());
    frame.extend_from_slice(&0u32.to_be_bytes());
    frame.push(0x50);
    frame.push(0x18);
    frame.extend_from_slice(&0x2000u16.to_be_bytes());
    frame.extend_from_slice(&0u16.to_be_bytes());
    frame.extend_from_slice(&0u16.to_be_bytes());
    frame.extend_from_slice(payload);
    frame
}

fn ethernet_ipv4_udp(
    src_ip: [u8; 4],
    dst_ip: [u8; 4],
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> Vec<u8> {
    let mut frame = Vec::new();
    frame.extend_from_slice(&[0x02, 0x00, 0x00, 0x00, 0x00, 0x01]);
    frame.extend_from_slice(&[0x02, 0x00, 0x00, 0x00, 0x00, 0x02]);
    frame.extend_from_slice(&0x0800u16.to_be_bytes());
    let total_len = 20 + 8 + payload.len();
    frame.extend_from_slice(&[
        0x45,
        0x00,
        ((total_len >> 8) & 0xFF) as u8,
        (total_len & 0xFF) as u8,
        0x00,
        0x01,
        0x00,
        0x00,
        64,
        17,
        0,
        0,
    ]);
    frame.extend_from_slice(&src_ip);
    frame.extend_from_slice(&dst_ip);
    frame.extend_from_slice(&src_port.to_be_bytes());
    frame.extend_from_slice(&dst_port.to_be_bytes());
    frame.extend_from_slice(&((8 + payload.len()) as u16).to_be_bytes());
    frame.extend_from_slice(&0u16.to_be_bytes());
    frame.extend_from_slice(payload);
    frame
}

fn mixed_corpora() -> Vec<(&'static str, Vec<u8>)> {
    let modbus_request = vec![
        0x00, 0x01, 0x00, 0x00, 0x00, 0x06, 0x01, 0x03, 0x00, 0x64, 0x00, 0x02,
    ];
    let modbus_response = vec![
        0x00, 0x01, 0x00, 0x00, 0x00, 0x07, 0x01, 0x03, 0x04, 0x00, 0x0A, 0x00, 0x14,
    ];
    let vlan_modbus = build_pcapng(&[
        ethernet_ipv4_tcp(
            [0x02, 0x00, 0x00, 0x00, 0x00, 0x02],
            [0x02, 0x00, 0x00, 0x00, 0x00, 0x01],
            [10, 0, 0, 1],
            [10, 0, 0, 2],
            49152,
            502,
            &modbus_request,
            Some(100),
        ),
        ethernet_ipv4_tcp(
            [0x02, 0x00, 0x00, 0x00, 0x00, 0x01],
            [0x02, 0x00, 0x00, 0x00, 0x00, 0x02],
            [10, 0, 0, 2],
            [10, 0, 0, 1],
            502,
            49152,
            &modbus_response,
            Some(100),
        ),
    ]);

    let dns_response = vec![
        0xAB, 0xCD, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x07, b'e', b'x',
        b'a', b'm', b'p', b'l', b'e', 0x03, b'c', b'o', b'm', 0x00, 0x00, 0x01, 0x00, 0x01, 0xC0,
        0x0C, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x3C, 0x00, 0x04, 93, 184, 216, 34,
    ];
    let dns = build_pcapng(&[ethernet_ipv4_udp(
        [10, 0, 0, 53],
        [10, 0, 0, 10],
        53,
        53000,
        &dns_response,
    )]);

    let enip_payload = vec![
        0x65, 0x00, 0x04, 0x00, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    ];
    let enip = build_pcapng(&[ethernet_ipv4_tcp(
        [0x02, 0x00, 0x00, 0x00, 0x00, 0x04],
        [0x02, 0x00, 0x00, 0x00, 0x00, 0x03],
        [10, 0, 1, 1],
        [10, 0, 1, 2],
        44818,
        44818,
        &enip_payload,
        None,
    )]);

    vec![
        ("vlan_modbus", vlan_modbus),
        ("dns_response", dns),
        ("ethernet_ip", enip),
    ]
}

fn bench_segment_replay(c: &mut Criterion) {
    let corpora = mixed_corpora();
    let mut group = c.benchmark_group("segment_replay");

    for (name, corpus) in &corpora {
        group.throughput(Throughput::Bytes(corpus.len() as u64));
        group.bench_with_input(BenchmarkId::from_parameter(name), corpus, |b, corpus| {
            b.iter(|| {
                let mut engine = DpiEngine::new();
                let output = engine
                    .process_segment_to_vec(
                        &SegmentMeta::new(format!("bench-{name}")),
                        std::io::Cursor::new(corpus),
                    )
                    .unwrap();
                black_box(output.events.len())
            });
        });
    }

    group.finish();
}

fn bench_mixed_replay_batch(c: &mut Criterion) {
    let corpora = mixed_corpora();
    let total_bytes: usize = corpora.iter().map(|(_, corpus)| corpus.len()).sum();
    let mut group = c.benchmark_group("mixed_replay_batch");
    group.throughput(Throughput::Bytes((total_bytes * 100) as u64));

    group.bench_function("100_segments", |b| {
        b.iter(|| {
            let mut engine = DpiEngine::new();
            let mut emitted = 0usize;
            for round in 0..100usize {
                let (name, corpus) = &corpora[round % corpora.len()];
                let output = engine
                    .process_segment_to_vec(
                        &SegmentMeta::new(format!("{name}-{round}")),
                        std::io::Cursor::new(corpus),
                    )
                    .unwrap();
                emitted += output.events.len();
            }
            black_box(emitted)
        });
    });

    group.finish();
}

criterion_group!(benches, bench_segment_replay, bench_mixed_replay_batch);
criterion_main!(benches);
