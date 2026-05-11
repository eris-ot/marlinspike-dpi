"""pytest suite for marlinspike-dpi Python bindings.

All test fixtures are generated in-memory — no external PCAP files required.
The helpers build minimal but valid classic PCAP payloads (global header +
packet records) containing real protocol frames so the engine can decode them.
"""

from __future__ import annotations

import struct
import tempfile
import os
from typing import List, Dict, Any

import pytest
import marlinspike_dpi as md


# ---------------------------------------------------------------------------
# PCAP builder helpers
# ---------------------------------------------------------------------------

PCAP_MAGIC_US = 0xA1B2C3D4  # microsecond timestamps
PCAP_LINKTYPE_ETHERNET = 1


def pcap_global_header(linktype: int = PCAP_LINKTYPE_ETHERNET) -> bytes:
    """Classic PCAP global header (24 bytes)."""
    return struct.pack(
        "<IHHiIII",
        PCAP_MAGIC_US,  # magic
        2,              # major version
        4,              # minor version
        0,              # thiszone
        0,              # sigfigs
        65535,          # snaplen
        linktype,       # network
    )


def pcap_record(frame: bytes, ts_sec: int = 1_700_000_000, ts_usec: int = 0) -> bytes:
    """Wrap an Ethernet frame in a classic PCAP record header."""
    n = len(frame)
    return struct.pack("<IIII", ts_sec, ts_usec, n, n) + frame


def build_pcap(*frames: bytes) -> bytes:
    """Assemble a complete PCAP from one or more Ethernet frames."""
    hdr = pcap_global_header()
    return hdr + b"".join(pcap_record(f) for f in frames)


# --- Frame factories -------------------------------------------------------

def arp_request_frame(
    src_mac: bytes = b"\xaa\xbb\xcc\xdd\xee\xff",
    src_ip: bytes = bytes([10, 0, 0, 1]),
    tgt_ip: bytes = bytes([10, 0, 0, 2]),
) -> bytes:
    """ARP who-has request (28-byte ARP payload in Ethernet frame)."""
    dst_mac = b"\xff\xff\xff\xff\xff\xff"
    ethertype = b"\x08\x06"
    arp = (
        b"\x00\x01"  # HTYPE Ethernet
        b"\x08\x00"  # PTYPE IPv4
        b"\x06"      # HLEN
        b"\x04"      # PLEN
        b"\x00\x01"  # OPER request
        + src_mac
        + src_ip
        + b"\x00\x00\x00\x00\x00\x00"  # THA unknown
        + tgt_ip
    )
    return dst_mac + src_mac + ethertype + arp


def udp_dns_query_frame(
    src_mac: bytes = b"\xaa\xbb\xcc\xdd\xee\x01",
    dst_mac: bytes = b"\x00\x11\x22\x33\x44\x55",
    src_ip: bytes = bytes([192, 168, 1, 10]),
    dst_ip: bytes = bytes([8, 8, 8, 8]),
    src_port: int = 54321,
    dst_port: int = 53,
) -> bytes:
    """Minimal DNS A-query for 'example.com' wrapped in UDP/IP/Ethernet."""
    # DNS wire format: query for example.com type A
    dns_id = b"\x12\x34"
    dns_flags = b"\x01\x00"   # standard query, recursion desired
    dns_counts = b"\x00\x01\x00\x00\x00\x00\x00\x00"  # 1 question
    # QNAME: 7 'example' 3 'com' 0
    qname = b"\x07example\x03com\x00"
    qtype_class = b"\x00\x01\x00\x01"  # A IN
    dns_payload = dns_id + dns_flags + dns_counts + qname + qtype_class

    udp_len = 8 + len(dns_payload)
    udp = (
        struct.pack(">HH", src_port, dst_port)
        + struct.pack(">H", udp_len)
        + b"\x00\x00"  # checksum (zero — not validated)
        + dns_payload
    )

    ip_len = 20 + len(udp)
    ip = (
        b"\x45"                          # ver=4, ihl=5
        b"\x00"                          # DSCP/ECN
        + struct.pack(">H", ip_len)
        + b"\xab\xcd"                    # identification
        + b"\x40\x00"                    # flags=DF, frag offset=0
        + b"\x40"                        # TTL=64
        + b"\x11"                        # proto=UDP
        + b"\x00\x00"                    # checksum (zero)
        + src_ip
        + dst_ip
        + udp
    )

    ethertype = b"\x08\x00"  # IPv4
    return dst_mac + src_mac + ethertype + ip


def modbus_tcp_frame(
    src_mac: bytes = b"\x00\x01\x02\x03\x04\x05",
    dst_mac: bytes = b"\x00\x0a\x0b\x0c\x0d\x0e",
    src_ip: bytes = bytes([10, 0, 1, 1]),
    dst_ip: bytes = bytes([10, 0, 1, 100]),
    src_port: int = 12345,
    dst_port: int = 502,
) -> bytes:
    """Modbus TCP Read Holding Registers request (FC=3, addr=0, qty=10)."""
    # Modbus Application Protocol header (6 bytes) + PDU
    tx_id = b"\x00\x01"
    proto_id = b"\x00\x00"
    modbus_pdu = b"\x01\x03\x00\x00\x00\x0a"  # unit=1, FC=3, addr=0, qty=10
    pdu_len = struct.pack(">H", len(modbus_pdu))
    modbus_payload = tx_id + proto_id + pdu_len + modbus_pdu

    # TCP (minimal header, no options, SYN-less data segment)
    tcp_data_offset = 5  # 20 bytes, no options
    tcp_flags = 0x018    # PSH + ACK
    tcp = (
        struct.pack(">HH", src_port, dst_port)
        + b"\x00\x00\x00\x01"   # seq
        + b"\x00\x00\x00\x00"   # ack
        + struct.pack(">BB", (tcp_data_offset << 4), tcp_flags & 0xFF)
        + struct.pack(">H", 65535)  # window
        + b"\x00\x00"           # checksum (zero)
        + b"\x00\x00"           # urgent
        + modbus_payload
    )

    ip_len = 20 + len(tcp)
    ip = (
        b"\x45\x00"
        + struct.pack(">H", ip_len)
        + b"\x00\x01\x40\x00\x40\x06"  # id, flags, TTL=64, proto=TCP
        + b"\x00\x00"                   # checksum
        + src_ip
        + dst_ip
        + tcp
    )

    ethertype = b"\x08\x00"
    return dst_mac + src_mac + ethertype + ip


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


def test_process_capture_bytes_returns_list():
    """process_capture_bytes returns a list (possibly empty) for a valid PCAP."""
    pcap = build_pcap(arp_request_frame())
    events = md.process_capture_bytes(pcap, capture_id="test-arp-01")
    assert isinstance(events, list)


def test_arp_event_has_required_keys():
    """Each event dict contains the mandatory top-level keys."""
    pcap = build_pcap(arp_request_frame())
    events = md.process_capture_bytes(pcap, capture_id="test-arp-02")
    assert len(events) >= 1
    ev = events[0]
    for key in ("event_id", "capture_id", "schema_version", "family", "envelope"):
        assert key in ev, f"missing key: {key}"


def test_capture_id_propagated():
    """The capture_id passed to process_capture_bytes appears in every event."""
    pcap = build_pcap(arp_request_frame())
    cid = "engagement-alpha-42"
    events = md.process_capture_bytes(pcap, capture_id=cid)
    assert len(events) >= 1
    for ev in events:
        assert ev["capture_id"] == cid


def test_dns_event_protocol_shortcut():
    """DNS UDP query produces at least one event; protocol shortcut is 'dns'."""
    pcap = build_pcap(udp_dns_query_frame())
    events = md.process_capture_bytes(pcap, capture_id="dns-01")
    protocols = [ev.get("protocol") for ev in events]
    assert any(p == "dns" for p in protocols), f"no dns event, protocols={protocols}"


def test_dns_event_envelope_fields():
    """DNS event envelope carries expected IP addresses and port."""
    pcap = build_pcap(udp_dns_query_frame())
    events = md.process_capture_bytes(pcap, capture_id="dns-02")
    dns_events = [ev for ev in events if ev.get("protocol") == "dns"]
    assert dns_events, "expected at least one dns event"
    ev = dns_events[0]
    env = ev["envelope"]
    assert env["src_ip"] == "192.168.1.10" or env["dst_ip"] == "8.8.8.8"
    assert env["dst_port"] == 53 or env["src_port"] == 53


def test_streaming_callback_fires():
    """process_capture_streaming fires the callback for each event."""
    pcap = build_pcap(arp_request_frame(), udp_dns_query_frame())
    collected: List[Dict[str, Any]] = []
    md.process_capture_streaming(
        path=_write_tmp_pcap(pcap),
        on_event=collected.append,
        capture_id="stream-01",
    )
    assert len(collected) >= 1
    assert all(isinstance(ev, dict) for ev in collected)


def test_dpi_engine_class():
    """DpiEngine.process_bytes returns a list and reports batch_size."""
    engine = md.DpiEngine(batch_size=32)
    assert engine.batch_size == 32
    pcap = build_pcap(arp_request_frame())
    events = engine.process_bytes(pcap, capture_id="engine-01")
    assert isinstance(events, list)


def test_modbus_protocol_transaction():
    """Modbus TCP frame produces a protocol_transaction event for 'modbus'."""
    pcap = build_pcap(modbus_tcp_frame())
    events = md.process_capture_bytes(pcap, capture_id="modbus-01")
    modbus_events = [ev for ev in events if ev.get("protocol") == "modbus"]
    assert modbus_events, f"no modbus events; all protocols: {[e.get('protocol') for e in events]}"
    ev = modbus_events[0]
    assert ev["family"] == "protocol_transaction"
    assert "protocol_transaction" in ev
    tx = ev["protocol_transaction"]
    assert "operation" in tx or ev.get("operation") is not None


def test_invalid_pcap_raises():
    """Feeding garbage bytes raises an exception."""
    with pytest.raises(Exception):
        md.process_capture_bytes(b"\x00\x01\x02\x03garbage", capture_id="bad")


def test_process_capture_file(tmp_path):
    """process_capture loads a file and returns events."""
    pcap = build_pcap(arp_request_frame())
    p = tmp_path / "test.pcap"
    p.write_bytes(pcap)
    events = md.process_capture(str(p), capture_id="file-01")
    assert isinstance(events, list)
    assert len(events) >= 1


def test_schema_version():
    """schema_version field is 'v2' on all events."""
    pcap = build_pcap(arp_request_frame())
    events = md.process_capture_bytes(pcap, capture_id="schema-01")
    for ev in events:
        assert ev["schema_version"] == "v2"


# ---------------------------------------------------------------------------
# Internal helper
# ---------------------------------------------------------------------------

_tmp_files: List[str] = []


def _write_tmp_pcap(data: bytes) -> str:
    """Write bytes to a named tempfile and return the path."""
    fd, path = tempfile.mkstemp(suffix=".pcap")
    os.write(fd, data)
    os.close(fd)
    _tmp_files.append(path)
    return path
