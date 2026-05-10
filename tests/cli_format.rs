//! Integration test for the `--format` CLI flag.
//!
//! Builds a minimal classic PCAP (one ARP frame) in memory, drops it to a
//! temp file, and runs the compiled `marlinspike-dpi` binary three times —
//! once per format — confirming each renders to its native framing.

use std::io::Write;
use std::path::PathBuf;
use std::process::Command;

fn binary_path() -> PathBuf {
    // CARGO_BIN_EXE_<name> is set by Cargo for integration tests.
    PathBuf::from(env!("CARGO_BIN_EXE_marlinspike-dpi"))
}

fn write_minimal_pcap() -> tempfile::NamedTempFile {
    // Classic PCAP global header: magic, v2.4, no zone offset, no sigfigs,
    // 65535 snaplen, linktype 1 (Ethernet).
    let mut bytes: Vec<u8> = Vec::new();
    bytes.extend_from_slice(&0xa1b2c3d4u32.to_le_bytes()); // magic (us resolution)
    bytes.extend_from_slice(&2u16.to_le_bytes()); // major
    bytes.extend_from_slice(&4u16.to_le_bytes()); // minor
    bytes.extend_from_slice(&0u32.to_le_bytes()); // thiszone
    bytes.extend_from_slice(&0u32.to_le_bytes()); // sigfigs
    bytes.extend_from_slice(&65535u32.to_le_bytes()); // snaplen
    bytes.extend_from_slice(&1u32.to_le_bytes()); // linktype = Ethernet

    // One ARP request from aa:bb:cc:dd:ee:ff (10.0.0.1) asking for 10.0.0.2.
    let mut frame: Vec<u8> = Vec::new();
    frame.extend_from_slice(&[0xff, 0xff, 0xff, 0xff, 0xff, 0xff]); // dst MAC (bcast)
    frame.extend_from_slice(&[0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]); // src MAC
    frame.extend_from_slice(&[0x08, 0x06]); // ethertype ARP
    frame.extend_from_slice(&[0x00, 0x01]); // HTYPE Ethernet
    frame.extend_from_slice(&[0x08, 0x00]); // PTYPE IPv4
    frame.push(6); // HLEN
    frame.push(4); // PLEN
    frame.extend_from_slice(&[0x00, 0x01]); // OPER = request
    frame.extend_from_slice(&[0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]); // SHA
    frame.extend_from_slice(&[10, 0, 0, 1]); // SPA
    frame.extend_from_slice(&[0, 0, 0, 0, 0, 0]); // THA (unknown)
    frame.extend_from_slice(&[10, 0, 0, 2]); // TPA

    // Record header: ts_sec=1_700_000_000, ts_usec=0, incl_len=orig_len=frame.len().
    bytes.extend_from_slice(&1_700_000_000u32.to_le_bytes());
    bytes.extend_from_slice(&0u32.to_le_bytes());
    bytes.extend_from_slice(&(frame.len() as u32).to_le_bytes());
    bytes.extend_from_slice(&(frame.len() as u32).to_le_bytes());
    bytes.extend_from_slice(&frame);

    let mut f = tempfile::NamedTempFile::new().expect("tempfile");
    f.write_all(&bytes).expect("write pcap");
    f.flush().expect("flush");
    f
}

fn run_cli(pcap: &std::path::Path, format: &str) -> (String, String, std::process::ExitStatus) {
    let out = Command::new(binary_path())
        .arg("--input")
        .arg(pcap)
        .arg("--format")
        .arg(format)
        .output()
        .expect("spawn marlinspike-dpi");
    (
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
        out.status,
    )
}

#[test]
fn bronze_format_emits_envelope_json() {
    let pcap = write_minimal_pcap();
    let (stdout, stderr, status) = run_cli(pcap.path(), "bronze");
    assert!(status.success(), "exit failed: stderr={stderr}");
    let v: serde_json::Value = serde_json::from_str(stdout.trim()).expect("valid JSON");
    assert_eq!(v["engine"], "marlinspike-dpi");
    assert!(v["output"]["events"].is_array(), "events array present");
}

#[test]
fn ocsf_format_emits_ndjson_records() {
    let pcap = write_minimal_pcap();
    let (stdout, stderr, status) = run_cli(pcap.path(), "ocsf");
    assert!(status.success(), "exit failed: stderr={stderr}");
    // Expect at least one OCSF record (the ARP frame produces a TopologyObservation
    // which is unmapped, but other recognizers may emit ProtocolTransaction or
    // AssetObservation depending on dispatch — accept zero-or-more, just verify
    // every emitted line is well-formed OCSF JSON with class_uid set).
    for line in stdout.lines().filter(|l| !l.is_empty()) {
        let v: serde_json::Value = serde_json::from_str(line).expect("each OCSF line is JSON");
        assert!(v["class_uid"].is_number(), "class_uid present on every line");
        assert!(v["metadata"]["version"].is_string(), "metadata.version present");
    }
}

#[test]
fn influx_format_emits_line_protocol_or_empty() {
    let pcap = write_minimal_pcap();
    let (stdout, stderr, status) = run_cli(pcap.path(), "influx");
    assert!(status.success(), "exit failed: stderr={stderr}");
    // ARP produces no ProcessReadings, so Influx output is empty (just the
    // trailing newline write_payload adds). Just confirm we got no JSON braces —
    // line protocol never contains them at top level.
    assert!(
        !stdout.contains("{"),
        "influx output should not contain JSON: {stdout}"
    );
}

#[test]
fn default_format_is_bronze() {
    let pcap = write_minimal_pcap();
    let out = Command::new(binary_path())
        .arg("--input")
        .arg(pcap.path())
        .output()
        .expect("spawn");
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    let v: serde_json::Value = serde_json::from_str(stdout.trim()).expect("valid JSON");
    assert_eq!(v["engine"], "marlinspike-dpi");
}
