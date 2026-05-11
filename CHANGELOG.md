# Changelog

All notable changes to `marlinspike-dpi` are documented here.

The format is loosely based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html) —
breaking changes will bump the major version (planned `v2.0` removes the deprecated
`attributes: BTreeMap<String, String>` escape hatch and the `modbus` sub-field on
`ProtocolTransaction`).

## [1.14.0] — 2026-05-11

Depth release — six protocols promoted from recognition / shallow to full deep parse. The README headline number (50+ dissectors) doesn't change; depth does. Each promotion shipped via an isolated worktree agent and was merged after the full suite passed.

### Added — full deep parsers

- **Kerberos** (RFC 4120) — promoted from ASN.1 application-tag recognition to full parser. Per-message extraction in the clear: AS-REQ / AS-REP / TGS-REQ / TGS-REP / AP-REQ / KRB-ERROR with client principal (cname), server principal (sname), realm, etype lists, kdc-options, nonce, from/till/rtime timestamps, ap-options, embedded Ticket realm + sname, KRB-ERROR code + e-text. AssetObservation for KDC servers and authenticating clients. TCP 4-byte length prefix handled. EncryptedData payloads (EncTicketPart, EncKDCRepPart, EncAuthenticator, EncAPRepPart) and PA-DATA extensions (FAST, PKINIT) intentionally opaque. New file: `src/engine/decoders/kerberos.rs`.
- **LDAP / LDAPv3** (RFC 4511) — promoted from ASN.1 SEQUENCE recognition to full BER op parser. bind / search / modify / add / del / compare / abandon / extended / unbind ops; per-op DN, base, scope, sizeLimit, timeLimit, filter-type discriminator, attribute selectors, result codes. messageID-based req/response pairing. StartTLS OID (`1.3.6.1.4.1.1466.20037`) recognised. TCP chunk-straddling messages buffered. LDAPS port 636 stays recognition-only (TLS-encrypted). New file: `src/engine/decoders/ldap.rs`.
- **IGMP** (RFC 2236 + RFC 3376) — promoted from type-byte classification to full deep parse. v1/v2 8-byte header with group address; v3 Query S-flag / QRV / float-decoded QQIC / source-address list; v3 Membership Report group records with record-type / aux-data-len / per-record source addresses. Float-encoded max-resp-code + QQIC per §4.1.1. TopologyObservation `multicast_join` on Join-style ops. New file: `src/engine/decoders/igmp.rs`.
- **SMB2 / SMB3** (MS-SMB2) — promoted from signature recognition to full deep parser. NEGOTIATE / SESSION_SETUP / TREE_CONNECT / CREATE / CLOSE / READ / WRITE / IOCTL / LOGOFF. UNC path extraction on TREE_CONNECT; filename + DesiredAccess + ShareAccess + CreateDisposition on CREATE; FileId tracked from CREATE through subsequent READ / WRITE / CLOSE. **10 FSCTL codes named** with severity tagging — `FSCTL_PIPE_TRANSCEIVE` high-severity on `\PIPE\svcctl` / samr / atsvc / drsuapi (SCM access — classic lateral-movement signal). MessageId request/response pairing with LRU bounds. NetBIOS Session Service framing on 139 and 445; compound requests walked via NextCommand. NT-status code naming (`STATUS_LOGON_FAILURE`, `STATUS_ACCESS_DENIED`, etc.). SMB3 Transform PDUs (0xFD) recognised but encrypted payload opaque. New file: `src/engine/decoders/smb2.rs`. SMB1 stays in the recognizer (legacy, low-value).
- **OPC UA PubSub** DataSetMessage decode — promoted from NetworkMessage-header-only to per-field DSM decoder. Variant (built-in types 1–13) and DataValue field encodings; StatusCode → `RawQuality::OpcUaStatusCode`, SourceTimestamp → Unix-micros via Windows FILETIME conversion (`(ft - 116444736000000000) / 10`). Emits `ProcessReading` per field — completes the UADP VQT path. RawData encoding skipped (low anomaly emitted; requires out-of-band PublishedDataSet config). Field NodeIds fall back to `OpcUaNodeId::Numeric(field_index)` when config is not on the wire. AssetObservation per first-seen publisher_id. Modified file: `src/engine/decoders/ot/opc_ua_pubsub.rs`.

### Changed — cross-packet state

- **NetFlow / IPFIX** template tracking — the v1 deferral on template correlation is reversed. Cross-packet template store keyed by `(exporter, observation_domain, template_id)` with 1024-entry LRU eviction. NetFlow v9 FlowSet ID 0 (Template), 1 (Options Template), and ≥256 (Data FlowSets) handled; IPFIX (v10) Set ID 2 (Template), 3 (Options Template), and ≥256 (Data) handled. **24 IANA IPFIX Information Elements** mapped by name: octet/packet delta counts, IPv4 + IPv6 source + destination addresses + prefix lengths, transport ports, protocolIdentifier, ipClassOfService, tcpControlBits, BGP source + destination AS numbers, ingress + egress interfaces, ipNextHopIPv4Address, source + destination MAC addresses, flowStart/EndSysUpTime, flowStart/EndMilliseconds. IPv4 dotted-decimal, IPv6 colon-hex, MAC `aa:bb:cc:dd:ee:ff` formatting. PEN enterprise field bytes skipped at declared length. Options Template contents deferred (track existence, don't decode option records). `template_unresolved` low-severity anomaly when a Data FlowSet references an unknown template. Modified file: `src/engine/decoders/netflow.rs`.

### Removed

- `KerberosRecognizer`, `LdapRecognizer`, `IgmpRecognizer` structs removed from `src/engine/decoders/recognizers.rs` (the deeper decoders own these now). `SmbRecognizer` retained for SMB1 only — the SMB2 path in the recognizer silently returns to avoid double-emission.

### Tests

- +86 tests (786 lib + 4 CLI + 1 doctest = 791 total). Per-decoder deltas: IGMP +12, Kerberos +13, LDAP +14, NetFlow +11, OPC UA PubSub +11, SMB2 +25.



Telecom AAA + automotive/industrial TSN + gas-pipeline SCADA.

### Added

- **Diameter** (RFC 6733) — TCP 3868 (plaintext), 5868 (TLS). 5G/telecom-core control-plane AAA. Full 20-byte header parse, 4-byte-padded AVP walk with vendor-flag handling, command naming (Capabilities-Exchange / Device-Watchdog / Disconnect-Peer / Re-Auth / Accounting / Abort-Session / Session-Termination / EAP), request/answer pairing by hop_by_hop_id, AVP extraction (User-Name, Session-Id, Origin-Host, Origin-Realm, Result-Code).
- **RadSec** (RFC 6614) — TCP 2083. RADIUS-over-TLS recognition + TLS-record fingerprinting + AssetObservation. STARTTLS upgrade variant out of scope.
- **AVTP / IEEE 1722-2016** — EtherType 0x22F0. TSN audio-video bridging. Media subtypes (IEC61883/MMA/AAF/CVF/CRF/TSCF/SVF/RVF) sampled (first + every 1000th per stream); control subtypes (ADP/AECP/ACMP/MAAP) unconditional. ADP ENTITY_AVAILABLE yields AssetObservation with entity_id / model_id / role + gPTP grandmaster.
- **Modbus/UDP** — UDP 502. Sibling to Modbus/TCP for legacy RTUs. Full FC dispatch, 256-entry LRU pending-table pairing, request_only / response_only on idle flush, ProcessReading emission for register reads. UMAS FC 0x5A skipped (handled by `umas.rs` on TCP).
- **Emerson ROC Plus** — TCP 4000. Gas SCADA telemetry. 6-byte addressed header + opcode dispatch. High-severity ParseAnomaly on state-mutating opcodes (General Write 7, Set RTC 11, Send Commands 138). Vendor=`Emerson` AssetObservation on Login.

### Changed

- Cargo.toml license: `Proprietary` → `AGPL-3.0-or-later` (dual-licence: open-source AGPL or commercial; see `LICENSE-COMMERCIAL.md`).
- Crate-level rustdoc: dissector count `34` → `50+`.

### Tests

- +33 tests (700 total). Zero integration fixes — the inventory self-registration shape continues to pay off.

## [1.12.0] — 2026-05-10

Defender-yield + industrial-Ethernet completionism. 7 new protocols.

### Added

- **Modicon UMAS** — TCP 502 (inside Modbus FC 0x5A). Schneider proprietary engineering protocol used in Industroyer2 (2022 Ukraine power). High-severity ParseAnomaly on STOP_PLC / INITIALIZE_DOWNLOAD / DOWNLOAD_BLOCK / END_STRATEGY_DOWNLOAD — the control-takeover sequence.
- **NTLMSSP** — TCP 80, 135, 139, 445, 5985, 8080. Auth blob embedded in SMB / HTTP / DCE/RPC. Type1/2/3 message extraction via `NTLMSSP\0` magic scan. ParseAnomaly medium on plaintext HTTP NTLMSSP (credential exposure).
- **EtherNet/IP Class 1 cyclic I/O** — UDP 2222. The high-volume implicit messaging (servo positions, drive commands, safety I/O). Sampled (first + every 1000th).
- **POWERLINK** — EtherType 0x88AB. Real-time motion. SoC / PReq / PRes / SoA / ASnd / AInv / AMNI dispatch; ASnd IdentResponse → AssetObservation.
- **SERCOS III** — EtherType 0x88CD. Real-time motion / CNC. Telegram-type dispatch (MST / MDT / AT / NRT / HotPlug); sync-flag tracking with `sercos_sync_lost`.
- **PTPv2 / gPTP** — EtherType 0x88F7, UDP 319/320. IEEE 1588 / 802.1AS time sync. Announce extracts grandmasterClockIdentity + clockClass / accuracy / priority1/2 / stepsRemoved / timeSource. ParseAnomaly on grandmaster change.
- **Foundation Fieldbus HSE** — TCP / UDP 1089, 1090, 1091. Port-based recognition + magic-byte fingerprint. Deep FDA parse infeasible (member-restricted spec).

### Tests

- +48 tests (672 total).

## [1.11.0] — 2026-05-10

Industrial vision, sensor networks, brokered messaging, secure building automation, legacy AB Ethernet, voice/media, IoT REST, and DNP3 auth. 8 new protocols.

### Added

- **SIP + RTP + RTCP** — UDP/TCP 5060 (SIP), UDP 5004/5005 (canonical RTP/RTCP). Byte-pattern dispatch (not port-bound) so it works on SDP-negotiated media ports.
- **CoAP** (RFC 7252) — UDP 5683 (plain), 5684 (DTLS, opaque past handshake). Delta-encoded options parse (Uri-Host / Uri-Path / Uri-Query / Content-Format), method + response-class naming.
- **GVCP / GigE Vision** — UDP 3956. Industrial machine-vision control. DISCOVERY_ACK → AssetObservation with manufacturer / model / version / serial.
- **DNP3-SAv5** — TCP 20000 (sibling to DNP3). g120 challenge / reply / aggressive-mode / session-key / cert / MAC / update-key naming. High-severity flag on g120v7 (Authentication Error).
- **MQTT-SN** — UDP 1884. Constrained-network publish/subscribe with FORWARDER_ENCAPSULATION support.
- **AMQP 1.0** — TCP 5671 (TLS) / 5672. Described-type performative dispatch (OPEN/BEGIN/ATTACH/FLOW/TRANSFER/DISPOSITION/DETACH/END/CLOSE; SASL-MECHANISMS/INIT/CHALLENGE/RESPONSE/OUTCOME).
- **BACnet/SC** — TCP 47808, 4843. TLS-handshake recognition (typical), plaintext BVLC-SC parse for testbench captures; originating + destination VMAC extraction.
- **Allen-Bradley CSP** — TCP 2222. Pre-CIP legacy AB Ethernet (PLC-5E, SLC 5/05, MicroLogix 1100/1400). Transaction-id pairing, vendor=`Allen-Bradley` AssetObservation on register session.

### Tests

- +57 tests (624 total).

## [1.10.0] — 2026-05-09

OPC Classic gap closure (unblocked by v1.9.0's DCE/RPC), SIS-side CIP coverage, and the last common lateral-movement / discovery / VPN protocols. 9 new protocols.

### Added

- **OPC Classic** (DA / HDA / AE) — TCP 135 + dynamic. Detects OPC interface UUIDs in DCE/RPC BIND PDUs.
- **CIP Safety** — TCP 44818. Network Safety Segment (0x50) in Forward_Open / Large_Forward_Open paths.
- **NetBIOS NBNS + NBDS** — UDP 137, 138. Nibble-encoded names, suffix-byte role inference (workstation, file server, master browser, DC).
- **TACACS+** — TCP 49. 12-byte header always plaintext; AUTHEN START fully parsed when unencrypted-flag set.
- **WireGuard** — UDP 51820. Type+reserved-zeros sanity check identifies WG even off-port.
- **NetFlow v5 / v9 + IPFIX** — UDP 2055, 4739, 9995, 9996. Export-message header parse; template tracking deferred.
- **QUIC** — UDP 80, 443. Long-header parse (version, DCID, SCID). AEAD payload not decrypted — SNI extraction intentionally out of scope.
- **SMTP / SMTPS** — TCP 25, 465, 587. Banner + commands + STARTTLS boundary; 465 is TLS from byte 0.
- **OpenVPN** — UDP/TCP 1194. Opcode/key_id 5/3-bit split, all hard-reset variants, TCP 2-byte length-prefix reassembly.

### Fixed

- VNC tests now match RFB wire order (server_banner → client_banner → server_types → client_chosen) rather than bundled.
- CIP Safety segment marker corrected from 0x90 (Data segment) to 0x50 (Network segment). Forward_Open fixed_body_len 30 → 36 (Large 34 → 40).

### Tests

- +68 tests (567 total).

## [1.9.0] — 2026-05-09

Lateral-movement and OT-coverage gaps. 7 new protocols.

### Added

- **DCE/RPC** — TCP 135 + dynamic. BIND/ALTER_CONTEXT with mixed-endianness UUID decoding; well-known interface naming (samr, lsarpc, srvsvc, winreg, atsvc, eventlog, epmapper, svcctl, drsuapi, efsrpc); REQUEST/RESPONSE opnum extraction with call-id pairing. Enables OPC Classic in v1.10.0.
- **Yokogawa Vnet/IP** — UDP 32768. Honest recognition (proprietary, undocumented). Best-effort header parse per Wireshark dissector.
- **TFTP** — UDP 69. RRQ/WRQ/ERROR opcode dispatch; high-severity ParseAnomaly on firmware-shaped WRQ filenames (`.bin`, `.hex`, `.fw`).
- **IKE (IKEv1 + IKEv2)** — UDP 500, 4500. NAT-T non-ESP marker, Vendor ID prefix matching (Microsoft, Cisco Unity, DPD, NAT-T).
- **VNC / RFB** — TCP 5900–5910. RFB v3.3 + v3.7+ handshake (single-u32 vs. count+types+chosen); Invalid-with-reason path.
- **WinRM / WS-Management** — TCP 5985, 5986. Byte-pattern POST /wsman scan with SOAP Action URI extraction; 5986 TLS-opaque.
- **OSIsoft PI** — TCP 5450, 5460–5462. Port + magic-byte recognition. Deep parse infeasible (proprietary).

### Tests

- +48 tests (499 total).

## [1.8.0] — 2026-05-08

Major-vendor OT gaps, SIS coverage, OT pivot/discovery surfaces. 7 new protocols.

### Added

- **Beckhoff ADS** — TCP 48898. TwinCAT. AMS/TCP framing, full AMS header (NetIDs, ports, command, state flags, error code), invoke-ID pairing.
- **GE SRTP** — TCP 18245. PACSystems / 90-30 / 90-70. 56-byte header parse, service request code naming, sequence-number pairing.
- **Triconex TriStation** — UDP 1502. Schneider SIS (Tricon / Trident / Tri-GP). High-severity ParseAnomaly on `SetControlProgram` (0x70 — TRITON payload-delivery command).
- **OPC UA PubSub** — UDP 4840. UADP NetworkMessage parsing (version, publisher_id, group / dataset writer IDs).
- **MELSEC SLMP** — TCP 5007. Mitsubishi iQ-R / iQ-F / Q. 4E binary, command + subcommand naming, serial-number pairing, AssetObservation from Read CPU Model response.
- **RDP** — TCP 3389. TPKT + X.224 CR/CC parse; `mstshash=` cookie extraction (spoofable, noted); negotiation failure code.
- **mDNS + WS-Discovery** — UDP 5353 / 3702. Full DNS message parse with compression pointers; SOAP envelope byte-pattern match for WS-D.

### Tests

- +44 tests (451 total).

## [1.7.0] — 2026-05-07

### Added

- `--format <bronze|ocsf|influx>` CLI flag. Non-Bronze formats emit native line-oriented framing directly (no envelope wrapper) so SIEM / historian consumers can pipe stdout straight in.

### Tests

- +4 integration tests (407 total).

## [1.6.0] — 2026-05-07

### Added

- `output::ocsf` renderer mapping Bronze to **OCSF v1.4.0**. ProtocolTransactions dispatch to Network Activity (4001), HTTP (4002), DNS (4003), SMB (4006), SSH (4007), Authentication (3002). AssetObservations → Device Inventory Info (5001). ParseAnomalies → Detection Finding (2004). ProcessReadings / ExtractedArtifacts / TopologyObservations have no OCSF mapping (`output::influx_line` and Bronze JSON keep those).
- Protocol-specific richness preserved under `unmapped` so consumers don't lose information.

### Tests

- +15 tests (402 total).

## [1.5.0] — 2026-05-06

Three parallel structural refactors. No behavior change.

### Changed

- **OT per-protocol carve-out**: `src/engine/decoders/ot/mod.rs` (3,222 lines) split into 12 sibling files (bacnet, dnp3, ethercat, ethernet_ip, hart_ip, iec104, iec61850, modbus, omron_fins, opc_ua, profinet, s7comm). Each holds one decoder + helpers + state + `inventory::submit!`.
- **Fields-struct migration final**: Modbus / DNS / SNMP / MSTP and orphans (LacpPartner, IcmpFields) moved from `registry.rs` to their dissectors. `registry.rs`: 439 → 290 lines. Now purely the dispatch surface.
- **BronzeSink streaming-first API**: `process_streaming<R, S: BronzeSink>(meta, reader, sink)` is the canonical streaming entry point. `process_segment_to_vec` becomes a thin `VecBronzeSink` wrapper.

## [1.4.0] — 2026-05-06

### Changed

- 26 Fields structs moved from `src/registry.rs` to their dissector files; `registry.rs` re-exports each via `pub use`. `registry.rs`: 685 → 439 lines.
- `src/engine/decoders/ot.rs` → `src/engine/decoders/ot/mod.rs` (groundwork for v1.5.0 per-protocol files).

## [1.3.0] — 2026-05-05

### Added

- **Inventory-crate self-registration**: each decoder appends an `inventory::submit!` block; `DpiEngine::new()` walks `inventory::iter::<DecoderRegistration>` and instantiates via factory closures. Adding a new protocol is one new file — zero central edits.
- **Typed `ProtocolFields` enum** on `ProtocolTransaction`, externally tagged. First variant: `Modbus(ModbusBronzeFields)`. Decoders migrate from string `attributes` to typed emission per protocol; both surfaces co-exist through the v1.x line.

### Deprecated

- `ProtocolTransaction.attributes: BTreeMap<String, String>` — will be removed in v2.0 (use `protocol_fields`).
- `ProtocolTransaction.modbus: Option<ModbusBronzeFields>` — superseded by `ProtocolFields::Modbus(...)`. Removed in v2.0.

## [1.2.0] — 2026-05-05

### Changed

- `src/engine.rs` (10,221 lines) split into `src/engine/mod.rs` + per-family files (`recognizers.rs`, `synchrophasor.rs`, `link_layer.rs`, `it_basic.rs`, `it_app.rs`, `ot.rs`). 35+ `SessionDecoder` impls + state types + helpers relocated.

### Added

- **InfluxDB Line Protocol renderer** (`output::influx_line`) — emits one line per `ProcessReading` for direct ingest by Influx / Timescale / VictoriaMetrics / QuestDB / Telegraf. Per-protocol measurement names; low-cardinality dimensions as tags; typed value + raw quality bits as fields. Source timestamp preferred over observed. Spec-compliant escaping.

### Tests

- +10 tests (387 total).

## [1.1.0] — 2026-05-04

VQT (Value / Quality / Timestamp) extraction pipeline + 11 new protocols.

### Added

- **`BronzeEventFamily::ProcessReading`** variant — typed `PointIdentifier`, per-protocol `RawQuality`, source + observed timestamps. No normalization at the DPI layer.
- **`PointIdentifier`** variants: `ModbusRegister`, `OpcUaNode`, `CipSymbol`, `CipPath`, `DnpPoint`, `Iec104Ioa`, `Iec61850Reference`, `SparkplugMetric`, `HartCommand`, `PcccAddress`, `SynchrophasorChannel`.
- **`OpcUaNodeId`** enum with `String` / `StringRaw` / `Numeric` / `Guid` / `Opaque` (non-UTF-8 fallback for spec-compliant round-trip).
- **Sparkplug B over MQTT** — protobuf decode, BIRTH-derived alias resolution, bdSeq supersession, gap-epoch unresolvable-alias detection, TTL + LRU session eviction. Schema reconstructed clean-room from the public Sparkplug spec.
- **OPC UA** — ReadRequest/ReadResponse correlation by (secure_channel_id, request_id), Variant decoding, DataValue with StatusCode quality.
- **PCCC** (Allen-Bradley legacy) — Protected Typed Logical Read with TNS pairing; three-address-field decode.
- **IEEE C37.118 synchrophasor** — CFG-2 frame parser captures per-PMU layout; data frames decode phasors (mag+angle), frequency, dfreq, analogs, digitals.
- **Recognition-depth dissectors**: SMB (445, 139), Kerberos (88, 464), LDAP / LDAPS (389, 636), CC-Link IE Field (UDP 61450), CODESYS (TCP 1217/1740/2455/11740), IO-Link Wireless (UDP 59152), IGMP (IP proto 2).

### Tests

- +130 tests (377 total).

## [1.0.0] — 2026-05-04

Initial public release.

- 34 protocol dissectors.
- 21 anomaly detection signatures.
- Stovetop frame-integrity inspector (padding entropy, runt/oversized, FCS CRC, DNP3 DLL CRC).
- ICMPeeker (redirects, tunnel entropy, suspicious recon types).
- Bilgepump stateful L2 monitor (ARP spoofing, VLAN hopping, STP root manipulation, rogue DHCP, MAC anomalies, LLDP/CDP identity conflicts).
- Bronze v2 event model (ProtocolTransaction, AssetObservation, TopologyObservation, ParseAnomaly, ExtractedArtifact).
- SHA256 sliding-window deduplication.
- Pure Rust, zero C dependencies.
- 247 tests.

[1.14.0]: https://github.com/eris-ot/marlinspike-dpi/releases/tag/v1.14.0
[1.13.0]: https://github.com/eris-ot/marlinspike-dpi/releases/tag/v1.13.0
[1.12.0]: https://github.com/eris-ot/marlinspike-dpi/releases/tag/v1.12.0
[1.11.0]: https://github.com/eris-ot/marlinspike-dpi/releases/tag/v1.11.0
[1.10.0]: https://github.com/eris-ot/marlinspike-dpi/releases/tag/v1.10.0
[1.9.0]: https://github.com/eris-ot/marlinspike-dpi/releases/tag/v1.9.0
[1.8.0]: https://github.com/eris-ot/marlinspike-dpi/releases/tag/v1.8.0
[1.7.0]: https://github.com/eris-ot/marlinspike-dpi/releases/tag/v1.7.0
[1.6.0]: https://github.com/eris-ot/marlinspike-dpi/releases/tag/v1.6.0
[1.5.0]: https://github.com/eris-ot/marlinspike-dpi/releases/tag/v1.5.0
[1.4.0]: https://github.com/eris-ot/marlinspike-dpi/releases/tag/v1.4.0
[1.3.0]: https://github.com/eris-ot/marlinspike-dpi/releases/tag/v1.3.0
[1.2.0]: https://github.com/eris-ot/marlinspike-dpi/releases/tag/v1.2.0
[1.1.0]: https://github.com/eris-ot/marlinspike-dpi/releases/tag/v1.1.0
[1.0.0]: https://github.com/eris-ot/marlinspike-dpi/releases/tag/v1.0.0
