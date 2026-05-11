# Awesome-list submission drafts

Pre-written PR submissions for the major curated lists. Copy-paste-edit when you're ready to submit.

## 1. Awesome Industrial Control System Security

**Target list:** [hslatman/awesome-industrial-control-system-security](https://github.com/hslatman/awesome-industrial-control-system-security)

**Likely section:** `### Tools` → `#### Network` (check the current README structure; sections do shift)

**Suggested entry (single line, list-formatted):**

```markdown
- [marlinspike-dpi](https://github.com/eris-ot/marlinspike-dpi) - Pure-Rust passive deep packet inspection for OT/ICS and IT. Parses 40+ industrial protocols (Modbus, DNP3, IEC 61850 GOOSE+SV+MMS, S7comm, OPC UA, EtherNet/IP, HART-IP, Sparkplug B, IEEE C37.118, etc.) plus 30+ IT protocols (SMB2/3, Kerberos, LDAP, DNS, TLS, NetFlow). PCAP/PCAPNG → Bronze v2 / OCSF v1.4.0 / InfluxDB Line Protocol. Zero C dependencies. AGPL-3.0 + commercial.
```

**PR body draft:**

> Adding marlinspike-dpi to the Network tools section.
>
> It's a pure-Rust passive DPI engine focused on OT/ICS protocol depth. The differentiator vs. existing entries (Zeek, Suricata, Wireshark) is **OT depth at the application layer** — full PDU parsing with typed Value/Quality/Timestamp extraction for process historian ingest, not just port-based classification.
>
> - 40+ industrial protocols parsed deeply
> - 9 OT protocols (Modbus, DNP3, IEC 104, S7comm, OPC UA, EtherNet/IP, IEC 61850, HART-IP, Sparkplug B) emit typed `ProtocolFields` enum variants
> - Three detection subsystems: frame-integrity inspector, ICMP threat detector, stateful L2 monitor (ARP spoofing, VLAN hopping, STP root manipulation, rogue DHCP)
> - 850 tests, zero ignored
> - Embeddable as a Rust library, CLI binary, or C FFI surface
> - Outputs Bronze v2 (canonical schema), OCSF v1.4.0 (SIEM ingest), InfluxDB Line Protocol (historian ingest)
>
> Repository: https://github.com/eris-ot/marlinspike-dpi
> Comparison vs. Zeek/Suricata/Wireshark/nDPI/Arkime: https://github.com/eris-ot/marlinspike-dpi/blob/main/docs/comparison.md
> Parse-depth matrix: https://github.com/eris-ot/marlinspike-dpi/blob/main/docs/parse-depth-matrix.md
>
> Happy to revise the description to match the list's style; flagging that the project is dual-licensed (AGPL-3.0-or-later + commercial), in case that affects categorisation.

## 2. Awesome Rust

**Target list:** [rust-unofficial/awesome-rust](https://github.com/rust-unofficial/awesome-rust)

**Likely section:** `## Applications` → search for `## Network` or `### Networking` (the list is large and section names shift). Could also fit under `## Libraries` → `### Network programming`. Probably fits in **both** as a tool+library hybrid; pick the better one based on the README at PR time.

**Suggested entry:**

```markdown
- [marlinspike-dpi](https://github.com/eris-ot/marlinspike-dpi) [[fm_dpi](https://crates.io/crates/marlinspike-dpi)] - Pure-Rust passive deep packet inspection engine for OT/ICS and IT network monitoring. PCAP/PCAPNG → Bronze v2 events (also OCSF, InfluxDB). 50+ protocol dissectors with deep parsing for Modbus, DNP3, OPC UA, IEC 61850, S7comm, SMB2/3, Kerberos, LDAP. Zero C dependencies.
```

*(Note: the `[fm_dpi]` crates.io link assumes the package gets published. The repo currently has `publish = false`. Remove that part if not publishing.)*

**PR body draft:**

> Adding marlinspike-dpi to the networking section.
>
> Pure-Rust passive DPI engine — zero C dependencies (no libpcap, no bindgen, no C FFI in the input path). 850 tests. The whole stack from PCAP parsing to CRC-32 validation is safe Rust.
>
> Distinctive Rust-ecosystem-relevant features:
> - Uses the `inventory` crate for decoder self-registration (link-time collection — adding a new protocol is one new file with one `submit!` block, no central wiring)
> - Streaming-first API via a `BronzeSink` trait for memory-bounded back-pressure
> - Typed `ProtocolFields` enum replacing string-bag attributes (9 OT protocols migrated as of v1.15.0)
> - Optional C FFI behind a feature flag
>
> Repo: https://github.com/eris-ot/marlinspike-dpi

## 3. Awesome PCAP

**Target list:** [caesar0301/awesome-pcaptools](https://github.com/caesar0301/awesome-pcaptools) (the most active PCAP-tooling list)

**Likely section:** `## File Manipulation` or `## Traffic Analysis & Inspection`

**Suggested entry:**

```markdown
* [marlinspike-dpi](https://github.com/eris-ot/marlinspike-dpi) - Pure-Rust passive DPI engine. Consumes PCAP/PCAPNG, emits structured Bronze v2 events. 50+ protocol dissectors with OT/ICS depth (Modbus, DNP3, OPC UA, IEC 61850, S7comm) plus IT (SMB2/3, Kerberos, LDAP). Outputs Bronze v2 JSON, OCSF v1.4.0, or InfluxDB Line Protocol. Zero C deps.
```

## 4. Awesome Network Analysis

**Target list:** [briatte/awesome-network-analysis](https://github.com/briatte/awesome-network-analysis)

This list leans social-network-analysis academic; we're not a great fit. Skip.

## 5. Awesome SCADA

**Target list:** Search for the current authoritative one — there are forks. As of 2026 the most-starred is [aenondynamics/awesome-scada-modbus](https://github.com/aenondynamics/awesome-scada-modbus) or similar. Verify before PRing.

**Suggested entry:**

```markdown
- [marlinspike-dpi](https://github.com/eris-ot/marlinspike-dpi) - Passive deep packet inspection for SCADA protocols. Modbus/TCP, Modbus/UDP, DNP3, IEC 104, OPC UA, S7comm, MELSEC, EtherNet/IP, BACnet, HART-IP, IEC 61850 (MMS/GOOSE/SV), Sparkplug B, IEEE C37.118, plus 30+ more. Typed Value/Quality/Timestamp extraction for process historian ingest. Pure Rust, zero C dependencies.
```

## 6. Awesome OPC UA

**Target list:** various — search current best when ready.

**Suggested entry:**

```markdown
- [marlinspike-dpi](https://github.com/eris-ot/marlinspike-dpi) - Passive OPC UA dissector (binary on TCP + PubSub UADP on UDP). Parses ReadRequest/ReadResponse correlation, Variant decoding, DataValue with StatusCode quality + Source/Server timestamps. PubSub DataSetMessage decode → typed `ProcessReading` events for historian ingest. Part of a broader pure-Rust OT DPI engine.
```

## Process notes

1. **Check the list's CONTRIBUTING.md before PRing.** Each awesome list has its own format conventions — alphabetical order within section, double-space-before-dash, license-line required, etc.
2. **Match the list's voice.** Some lists are terse; some are verbose. Mimic neighbouring entries.
3. **Stars matter for some lists.** Some maintainers gate on ≥100 stars / minimum age. If the repo is new, wait a bit or ask the maintainer first via an issue.
4. **Don't submit to dead lists.** Check the last-merged-PR date; if it's >6 months, the list is dormant.
5. **Open one PR per list.** Don't bundle.
