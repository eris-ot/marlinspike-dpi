# How does marlinspike-dpi compare to Zeek, Suricata, Wireshark, nDPI, and Arkime?

These tools all touch network traffic but solve different problems. This page is the honest head-to-head for anyone choosing a stack.

## TL;DR

| You want to… | Use |
|--------------|-----|
| Run an IDS/NIDS with signature-based detection on live traffic | **Suricata** or **Snort** |
| Run a behavioural network-security monitor with scripting on live traffic | **Zeek** |
| Interactively inspect packets with a GUI / per-packet drill-down | **Wireshark** / `tshark` |
| Index full-packet capture for retrospective analysis | **Arkime** (formerly Moloch) |
| Classify protocol-of-flow as a library, fast, with minimal parsing | **nDPI** |
| **Parse OT/ICS protocols deeply, in-process, pure Rust, no daemon, no C deps, with typed VQT extraction and Bronze v2 / OCSF / Influx output** | **marlinspike-dpi** |

## Quick comparison

| | marlinspike-dpi | Zeek | Suricata | Wireshark/tshark | nDPI | Arkime |
|--|----------------|------|----------|-------------------|------|--------|
| Language | Rust (pure) | C++ | C | C | C | Perl/JS, C plugin |
| Dependencies | Zero C deps | libpcap, Zeek deps | libpcap, libhtp, etc. | libpcap, GLib, many | libpcap | libpcap, ES, libpcap |
| Distribution | Library (rlib + cdylib + staticlib) + CLI | Daemon + scripts | Daemon | GUI / CLI tool | C library | Daemon + UI |
| Live capture | Out of scope (passive PCAP/PCAPNG) | ✓ | ✓ | ✓ | Library only | ✓ |
| OT/ICS protocols | **44 total (34 with deep/full parse)** | Modbus, DNP3, BACnet, S7 (scripts) | Modbus, DNP3, ENIP (limited) | Most (recognition + drilldown) | Limited | Whatever Wireshark does |
| IT protocols | DNS, DHCP, HTTP, TLS, SMB2/3, Kerberos, LDAP, RDP, etc. | Full | Full | Full | Yes | Full |
| VQT (Value/Quality/Timestamp) for historian | **Native — typed `ProcessReading`** | Possible via scripts | No | No | No | No |
| Stateful L2 detection (ARP spoof, VLAN hop, STP) | **Native (Bilgepump)** | Possible via scripts | Some | Manual | No | No |
| Output formats | Bronze v2 JSON / OCSF NDJSON / Influx Line Protocol | Zeek logs / JSON | EVE JSON | pdml / json / text | Library API | ES-indexed PCAP |
| Embeddable in another Rust app | **Yes — one `cargo add`** | No (subprocess) | No (subprocess) | No (subprocess) | Yes via C FFI | No |
| C ABI for other languages | **Yes (`fm_dpi_*`)** | No | No | No | Yes (native C) | No |
| Detection subsystems | Stovetop (frame integrity) + ICMPeeker (ICMP threats) + Bilgepump (L2 stateful) | Scripted | Signature engine | None | None | None |
| Test count | 880+ | Hundreds (varies) | Yes | Yes | Yes | Yes |
| Licence | AGPL-3.0-or-later / commercial | BSD | GPL-2.0 | GPL-2.0 | GPL-3.0 / LGPL | Apache 2.0 |

## Per-tool deep comparison

### vs. Zeek

**Zeek's strengths:** mature, battle-tested, large user community, script-based extensibility, runs live, has its own DSL for detection logic.

**Where marlinspike-dpi differs:**

- **OT/ICS depth.** Zeek has Modbus, DNP3, BACnet, and S7 — that's roughly 4 OT protocols at varying depths, mostly community-contributed. marlinspike-dpi has 44 OT/ICS protocols (34 with deep or full parse) with typed Bronze v2 emission for the 9 most-deployed (Modbus, DNP3, IEC 104, S7comm, OPC UA, EtherNet/IP, IEC 61850, HART-IP, Sparkplug). VQT extraction (Value/Quality/Timestamp) is built into the event model — `ProcessReading` with typed `PointIdentifier`, `PointValue`, and `RawQuality`.
- **Embedding model.** Zeek is a daemon; you write Zeek scripts. marlinspike-dpi is a library you import. You can call `DpiEngine::new()` from your Rust application and stream Bronze events via the `BronzeSink` trait — no subprocess, no IPC, no shared filesystem.
- **Dependency story.** Zeek depends on libpcap, OpenSSL, and a long C++ build chain. marlinspike-dpi has zero C dependencies; the entire stack is safe Rust.
- **What Zeek does better.** Live capture (we're passive-only — feed us PCAP / PCAPNG bytes); scripting (we don't have a DSL — you write Rust); the community ecosystem of Zeek packages.

**Pick Zeek if:** you're running a security operations centre with a Zeek-script-savvy team and need live-traffic behavioural detection.
**Pick marlinspike-dpi if:** you're building an OT/ICS monitoring product, an industrial historian pipeline, or any embedded packet-analysis surface that needs deep ICS protocol parsing without managing a separate daemon.

### vs. Suricata

**Suricata's strengths:** high-performance IDS with rule-based detection, multi-threaded packet processing, large rule ecosystem (ET rules, Snort-compatible).

**Where marlinspike-dpi differs:**

- **Different category.** Suricata is an IDS — its job is to fire alerts on signature matches. marlinspike-dpi is a *parser*. We emit structured events about every flow we see; what to alert on is the embedder's policy decision.
- **OT/ICS protocols.** Suricata has Modbus, DNP3, and ENIP at limited depths. marlinspike-dpi covers 44 OT/ICS protocols (34 with deep parse) including the harder ones (IEC 61850 GOOSE/SV, Sparkplug B with stateful alias resolution, Triconex TriStation, Modicon UMAS, etc.).
- **Output.** Suricata emits EVE JSON (alerts + flow records + protocol records). We emit a richer typed Bronze v2 schema and have native OCSF / Influx renderers.

**Pick Suricata if:** you want rule-based intrusion detection on live traffic.
**Pick marlinspike-dpi if:** you want structured per-flow protocol data for asset inventory, anomaly detection, compliance, or historian ingest. (They can also coexist — Suricata's alerts plus our events are complementary.)

### vs. Wireshark / tshark

**Wireshark's strengths:** the gold standard for interactive packet inspection. Hundreds of dissectors, GUI drill-down, rich filtering language.

**Where marlinspike-dpi differs:**

- **Use case.** Wireshark is for humans inspecting captures. marlinspike-dpi is for machines ingesting captures into a downstream pipeline.
- **Output.** Wireshark's `pdml` / JSON output is a near-1:1 dump of the wire format — every field, every layer, very large. marlinspike-dpi's Bronze v2 is curated for downstream consumers: transaction-level, asset-level, VQT-level — semantically grouped, smaller.
- **Embedding.** Wireshark's dissectors aren't available as a Rust library; `tshark` is invoked as a subprocess. marlinspike-dpi is `cargo add` away.

**Pick Wireshark if:** you're doing forensic packet inspection by hand.
**Pick marlinspike-dpi if:** you need protocol dissection in a Rust application or as a structured-event pipeline.

### vs. nDPI

**nDPI's strengths:** mature C library specifically for protocol classification, very fast, widely used in commercial network products.

**Where marlinspike-dpi differs:**

- **Depth.** nDPI is mostly *classification* — "this flow is Modbus", "this flow is BitTorrent". marlinspike-dpi does classification *plus* full PDU parsing — function codes, register values, identity blobs, request/response pairing.
- **Language.** nDPI is C with C bindings. marlinspike-dpi is Rust with optional C FFI. If your host application is Rust, ours is `cargo add`. If your host is C/C++, both work via FFI.
- **OT focus.** nDPI does protocol-of-flow classification across thousands of protocols. We do deep parsing for 50+ protocols weighted toward OT/ICS.

**Pick nDPI if:** you need fastest-possible classification of "what protocol is this flow" with broad coverage, and you're OK in C.
**Pick marlinspike-dpi if:** you need to actually understand the *contents* of those flows, especially OT flows, and you'd rather work in Rust.

### vs. Arkime (formerly Moloch)

**Arkime's strengths:** full-packet capture indexed in Elasticsearch with a session-search UI. Operates as a complete capture-and-retain system.

**Where marlinspike-dpi differs:**

- **Different category.** Arkime *captures and stores*. marlinspike-dpi *parses and emits*. They're complementary — Arkime could call us for OT-deep enrichment of the sessions it retains.
- **Operational model.** Arkime is a daemon + Elasticsearch + UI. We're a library you embed.

**Pick Arkime if:** you want a packet retention / session browser.
**Pick marlinspike-dpi if:** you want a parser to feed structured events into a system that's not packet-retention-shaped.

## What marlinspike-dpi does NOT do

Stated plainly:

- **No live capture.** Feed us PCAP / PCAPNG bytes. Use `tcpdump`, `dumpcap`, AF_PACKET, or another capture source.
- **No IDS rules.** No Snort/Suricata rule engine, no signature matching. Anomaly detection is structural (frame integrity, ARP spoofing, ICMP redirects) not signature-based.
- **No decryption.** TLS, SSH, IPsec ESP, WireGuard transport, SMB3 Transform PDUs, QUIC AEAD — encrypted payloads are observed at the handshake / framing layer and then opaque. We don't accept session keys.
- **No GUI.** CLI + library + FFI only. Use Wireshark for interactive drill-down.
- **No active probing.** Passive only — never sends a packet. This is deliberate for OT regulatory compatibility.

## See also

- [Parse-depth matrix](./parse-depth-matrix.md) — per-protocol Full / Deep / Shallow / Recognition / Opaque status.
- [Bronze v2 schema](./bronze-v2-schema.md) — the event model.
- [Per-protocol reference](./protocols.md) — consolidated decoder docs.
