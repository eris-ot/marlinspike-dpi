# Conference talk abstract drafts

OT discovery is conference-driven. The community concentrates at a small number of venues, and a talk there carries more weight than weeks of organic GitHub momentum. Below are submission-ready drafts for the venues most worth submitting to.

These are starting points — adapt to the specific CFP, your speaker bio, and any new release content by the time of submission.

---

## S4 — SCADA Security Scientific Symposium

**Venue:** S4xYY (Miami, FL, January). [s4xevents.com](https://s4xevents.com)
**Why this venue:** S4 is the highest-prestige ICS-security conference. Vendor talks are common but Dale Peterson (organiser) heavily favours technical, novel, and field-tested content. Pure-Rust, OT-deep, zero-C-deps is in their wheelhouse.
**Format options:** S4 has several tracks — Main Stage (45 min), Stage 2 (30 min), Sponsor (paid), and the (S4)x5 Lightning slot. Aim for **Stage 2** as a first submission.

### Title

**Beyond Recognition: Deep Packet Inspection for OT, Without libpcap and Without a Vendor**

### Abstract (200 words, S4 typical)

Most "OT-aware" network monitoring stops at the port. Modbus traffic is labeled "Modbus" and you get a flow record. That's enough for asset inventory, not enough for detection. To distinguish a benign `Read Holding Registers` from a `Write Multiple Coils` against a safety PLC — or to extract Value/Quality/Timestamp from Sparkplug B alias-resolved metrics for your historian — you need **deep parsing**, not classification.

This talk presents marlinspike-dpi, a pure-Rust passive DPI engine purpose-built for OT/ICS depth. We'll cover three things:

1. **What deep parsing buys you on real OT wire data.** Worked examples for Modbus, DNP3, IEC 61850 GOOSE state-number tracking, Sparkplug B BIRTH-alias resolution, and SMB2 FSCTL_PIPE_TRANSCEIVE-on-svcctl detection (the classic lateral-movement signal). All from passive capture.

2. **How to make a DPI library that's actually embeddable.** Pure Rust, zero C dependencies (no libpcap, no bindgen). Self-registering decoders via the `inventory` crate — adding a protocol is one file, no central wiring. Streaming-first API. Outputs structured events (Bronze v2), OCSF for SIEM, or InfluxDB Line Protocol for historians. Built as a Rust library, CLI binary, or C FFI.

3. **Open questions.** Where deep parsing is hard or impossible — member-restricted specs (CC-Link IE, FF HSE), proprietary protocols with patchy reverse-engineering (Vnet/IP, OSIsoft PI), and the absolute limits at encrypted boundaries.

880+ tests. AGPL-3.0 + commercial. Working code on stage.

### Speaker bio template (60 words)

[Your name] is [role] at [org]. [One sentence on OT-relevant background — incident response, asset owner, vendor, researcher]. They have been working on passive DPI tooling for [years] and are the maintainer of marlinspike-dpi, a pure-Rust DPI engine focused on industrial protocol depth. [Optional: prior CVEs, conference talks, publications.]

---

## DEF CON ICS Village

**Venue:** DEF CON ICS Village (Las Vegas, NV, August). [icsvillage.com](https://icsvillage.com)
**Why this venue:** The ICS Village track at DEF CON pulls the operator/red-team/researcher crowd. CFPs accept both talks and tool demos. Heavily community-oriented — they'll like the OSS angle.
**Format options:** Talk (30–45 min) or Tool Demo (live walk-through, more interactive).

### Title

**Passive OT Defense in 850 Lines of Rust per Protocol**

### Abstract (250 words, more casual tone)

The OT defender story is bleak. The commercial offerings (Dragos, Claroty, Nozomi) cost six-to-seven figures and run as black-box appliances. The OSS offerings (Zeek, Suricata) have a handful of ICS-protocol dissectors that haven't shipped meaningful new coverage in years. If you're at a water utility or a mid-sized manufacturer, you're stuck between "buy a Lamborghini" and "fork Zeek scripts you don't understand".

marlinspike-dpi is an attempt at a third option: a passive DPI library that covers 44 OT/ICS protocols (34 parsed deeply), ships as a single Rust binary or Docker image, and emits structured events into whatever downstream pipeline you already have (SIEM via OCSF, historian via InfluxDB, custom via Bronze v2 JSON).

In this talk we'll:

- Walk a real Modbus + DNP3 + S7comm capture from raw PCAP to typed events live on stage
- Show **Sparkplug B alias resolution** working passively (without the BIRTH message, every DATA frame is opaque — we recover the metric name from the prior BIRTH)
- Demonstrate **SMB2 detection of `FSCTL_PIPE_TRANSCEIVE` on `\PIPE\svcctl`** — the classic lateral-movement signal — without paying anyone
- Show what happens at the spec-blocked boundaries (CC-Link IE, OSIsoft PI, FF HSE) and where reverse-engineering buys you something
- Walk the contribution path: how to add a new decoder in 30 minutes when your specific vendor's protocol isn't yet supported

The whole engine is pure Rust with zero C dependencies. AGPL-3.0 with commercial option. 880+ tests. Working code, no slideware that doesn't compile.

### Demo plan (for the tool-demo track variant)

1. `docker run -v ./modbus.pcap:/in.pcap marlinspike-dpi --input /in.pcap --pretty | head -50` — show Bronze v2 output
2. `--format ocsf` → pipe to a local Splunk/Wazuh demo, show events arriving
3. `--format influx` → pipe to Grafana, show Sparkplug B metrics graphed live
4. Live-add a decoder for a "made-up" protocol on stage in 5 minutes using the `inventory::submit!` pattern
5. Q&A

---

## Black Hat USA — Arsenal

**Venue:** Black Hat Arsenal (Las Vegas, NV, August). [blackhat.com](https://www.blackhat.com)
**Why this venue:** Arsenal is the open-source tool demo slot at Black Hat. Less prestigious than Briefings but better fit for an OSS project. The reach into the corporate / consultant crowd is larger than DEF CON.
**Format:** 2-hour or 4-hour kiosk demo. Less talk, more interactive — visitors walk up, you show them.

### Title

**marlinspike-dpi: Passive Deep Packet Inspection for OT/ICS Networks**

### Abstract (Arsenal is short — ~100 words)

A pure-Rust passive DPI engine for OT/ICS and IT network monitoring. PCAP/PCAPNG in, structured events out (Bronze v2 / OCSF / InfluxDB). 50+ protocol dissectors including the OT-deep ones: Modbus, DNP3, IEC 61850 GOOSE/SV/MMS, S7comm, OPC UA, EtherNet/IP, HART-IP, Sparkplug B with stateful alias resolution, IEEE C37.118 synchrophasor — full PDU parsing, not just port classification. Embeddable as a Rust library, CLI binary, or C FFI. Visit the kiosk for a live demo on real OT captures, including SMB2 lateral-movement detection and Sparkplug historian-feed extraction. Zero C dependencies. AGPL-3.0 + commercial.

### Demo handout (1-page leave-behind)

Front:
- Project name + GitHub URL + QR code
- One-paragraph elevator pitch
- Three bullet points on differentiator vs. Zeek / Suricata / nDPI

Back:
- Quickstart commands (Docker + library + FFI)
- Link to docs/quickstart.sh
- Link to docs/comparison.md
- Contact / sponsor info

---

## SANS ICS Summit

**Venue:** SANS ICS Security Summit (Orlando, FL, March). [sans.org/ics](https://www.sans.org/cyber-security-courses/ics-security/)
**Why this venue:** Operator-heavy audience, less researcher-y than S4. They appreciate operationally-relevant content. SANS CFPs are competitive but the talks land in front of asset-owner defenders.
**Format:** 30 or 45-min talks.

### Title

**Stop Paying Six Figures to Read Modbus: Passive OT Deep Packet Inspection as Open Source**

### Abstract (300 words, operator-friendly tone)

If you run an industrial control network, you've probably been pitched a commercial network-monitoring appliance. The pitch is compelling: "drop this box on a SPAN port, we'll tell you everything about your OT". The price is less compelling: six to seven figures, annual subscription, and your detection logic lives in the vendor's proprietary engine where you can't audit it, customise it, or take it with you.

This talk presents an alternative: marlinspike-dpi, a pure-Rust passive deep-packet-inspection library that does the same protocol parsing for free, ships as an embeddable component you control end-to-end, and emits events into whichever SIEM or historian you already run.

We'll cover, from an operator's perspective:

- **What it actually does:** 44 OT/ICS protocols (34 parsed deeply), not just port-classified. Worked examples on Modbus, DNP3, IEC 104, S7comm, OPC UA, IEC 61850, Sparkplug B. Plus 40+ IT protocols for the IT/OT bridge — SMB2/3, Kerberos, LDAP, DNS.

- **What it doesn't do:** It's a parser, not an IDS. No signature rules. No live capture (use `tcpdump` or your existing SPAN tap). No GUI. No decryption past TLS handshake. Stated up front so you don't get blindsided three months in.

- **How to deploy it:** Docker image, single-binary, or Rust library. Outputs OCSF (drop into Splunk / Wazuh / Elastic) or InfluxDB Line Protocol (drop into your historian). Lives entirely behind your perimeter.

- **What to do with the output:** Asset inventory; baseline behavioural detection; firmware-push detection (TFTP WRQ with `.bin` filename → high anomaly); STOP_PLC and SetControlProgram detection (UMAS / TriStation — the Industroyer2 / TRITON signals); SMB2 lateral-movement detection.

AGPL-3.0 with commercial option. Working code. Real captures.

---

## ICS-CSR — Annual Workshop on Industrial Control System Cyber Security Research

**Venue:** ICS-CSR (academic; co-located with various venues, often UK/Europe). [bcs.org/events/](https://www.bcs.org)
**Why this venue:** Academic-heavy crowd, good for the reverse-engineering / spec-coverage angle. Different audience from S4/DEF CON — researchers and grad students.
**Format:** Paper presentation (with submitted paper) or short talk.

### Title

**Passive Deep Packet Inspection of OT/ICS Protocols: Coverage, Limits, and a Public Implementation**

### Abstract (150 words — short conference abstract style)

We survey the state of passive deep packet inspection for industrial control system protocols, identify three regimes by spec availability — public specification (RFC, IEC, IEEE, ODVA), partial reverse-engineering with public writeups (TriStation, Modicon UMAS, Emerson ROC Plus, Yokogawa Vnet/IP), and member-restricted or proprietary (CC-Link IE Field, Foundation Fieldbus HSE, OSIsoft PI) — and present marlinspike-dpi, an open-source pure-Rust DPI engine that covers 50+ protocols across these regimes. We discuss the engineering trade-offs of self-registering decoder dispatch via link-time collection (`inventory` crate), the type-system encoding of protocol-specific fields (the typed `ProtocolFields` enum), and the security implications of high-volume cyclic OT traffic on event-budget design. We close with a parse-depth matrix documenting per-protocol coverage status and identify the protocols where further reverse-engineering would be highest-leverage for community defenders.

---

## Submission strategy

1. **Lead with S4 + DEF CON ICS Village**, in that order. They cover the same audience with different framings; S4 is the prestige play, DEF CON ICS Village is the community play.
2. **Black Hat Arsenal** is an easier-bar acceptance and the kiosk format means you don't need a polished slide deck — just a working demo.
3. **SANS ICS** is operator-facing; submit if you want enterprise contacts for the commercial-license side.
4. **ICS-CSR / academic** is a stretch but the abstract above is honest about what you have; consider after the project has a year of stability and at least one external contributor.

Most CFPs are 6 months out. Track [sec-cfp.com](https://sec-cfp.com) or similar for current calls.
