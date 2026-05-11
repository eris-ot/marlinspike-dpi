# marlinspike-dpi

**Pure-Rust passive deep packet inspection for OT/ICS and IT network monitoring.** PCAP / PCAPNG in → structured Bronze v2 events out (also OCSF v1.4.0 records for SIEM ingest and InfluxDB Line Protocol for historian feed). No libpcap, no C dependencies, no daemon.

> Protocols parsed at application layer: Modbus / Modbus-UDP / DNP3 / DNP3-SAv5 / IEC 60870-5-104 / IEC 61850 (MMS + GOOSE + SV) / S7comm / PROFINET / BACnet / BACnet/SC / EtherNet/IP / EtherNet/IP Class 1 I/O / OPC UA / OPC UA PubSub / OPC Classic / HART-IP / OMRON FINS / EtherCAT / MRP / PRP / PCCC / Sparkplug B / IEEE C37.118 synchrophasor / Beckhoff ADS / GE SRTP / Triconex TriStation / MELSEC SLMP / Yokogawa Vnet/IP / OSIsoft PI / GVCP / CIP Safety / Allen-Bradley CSP / Modicon UMAS / POWERLINK / SERCOS III / PTPv2 / Foundation Fieldbus HSE / AVTP / Emerson ROC Plus / Diameter — plus IT: DNS / DHCP / HTTP / TLS / SNMP / SSH / FTP / NTP / MQTT / MQTT-SN / Syslog / RADIUS / RadSec / ICMP / IGMP / SMB2/3 / Kerberos / LDAP / RDP / mDNS / WS-Discovery / DCE-RPC / TFTP / IKE / VNC / WinRM / NetBIOS / TACACS+ / WireGuard / NetFlow + IPFIX / QUIC / SMTP / OpenVPN / SIP / RTP / RTCP / CoAP / AMQP 1.0 / NTLMSSP.

**50+ protocol dissectors with deep parsing (not just port classification). 21 anomaly detection signatures. VQT (Value/Quality/Timestamp) extraction for process historians. 9 OT protocols with typed `ProtocolFields` enum variants. Zero C dependencies. 850 tests.**

See [docs/comparison.md](./docs/comparison.md) for how this differs from Zeek, Suricata, Wireshark, nDPI, and Arkime.

Three detection subsystems beyond protocol parsing:
- **Stovetop** -- frame-level integrity: padding covert channels, runt/oversized frames, CRC validation
- **ICMPeeker** -- ICMP threat detection: routing manipulation, tunnel detection, recon fingerprinting
- **Bilgepump** -- stateful L2 monitoring: ARP spoofing, VLAN hopping, STP hijacking, rogue DHCP, identity conflicts

Process-historian extraction:
- **Sparkplug B** over MQTT — protobuf-decoded with stateful alias resolution from BIRTH messages, gap-epoch unresolvable-alias detection, bdSeq supersession, configurable TTL + LRU session eviction
- **OPC UA** binary — ReadRequest/ReadResponse correlation, Variant decoding, DataValue with StatusCode quality and Source/Server timestamps
- **PCCC** (Allen-Bradley legacy) — Protected Typed Logical Read with TNS request/response correlation
- **IEEE C37.118 synchrophasor** — CFG-2-driven data frame decode emitting per-channel ProcessReadings (phasor magnitude, angle, frequency, dfreq, analogs, digitals)

Usable as a **Rust library** (`fm_dpi`), a **CLI binary** (`marlinspike-dpi`), or an optional **C FFI** surface (feature `ffi`).

**Docs:**
- [`CHANGELOG.md`](./CHANGELOG.md) — release history (1.0.0 → 1.15.0)
- [`docs/comparison.md`](./docs/comparison.md) — head-to-head vs. Zeek / Suricata / Wireshark / nDPI / Arkime
- [`docs/protocols.md`](./docs/protocols.md) — per-decoder reference (consolidated file-top docs)
- [`docs/parse-depth-matrix.md`](./docs/parse-depth-matrix.md) — per-protocol parse-depth matrix (Full / Deep / Shallow / Recognition / Opaque)
- [`docs/bronze-v2-schema.md`](./docs/bronze-v2-schema.md) — Bronze v2 event schema with sample JSON
- [`docs/llms.txt`](./docs/llms.txt) — single-file structured summary for LLM ingestion ([llmstxt.org](https://llmstxt.org/))
- [`examples/`](./examples/) — runnable examples: `basic`, `ocsf_output`, `extract_readings`, `streaming`

### What Sets This Apart

- **Pure Rust, zero C dependencies.** No libpcap, no libc FFI, no bindgen. The entire stack from PCAP parsing to CRC-32 validation is safe, auditable Rust. Builds anywhere `rustc` runs.
- **OT/ICS protocol depth.** 18 industrial protocols parsed to application layer -- Modbus, DNP3, IEC 104, IEC 61850 (GOOSE + SV + MMS), S7comm, PROFINET, BACnet, EtherNet/IP, OPC UA, HART-IP, FINS, EtherCAT, MRP, PRP, PCCC, Sparkplug B, IEEE C37.118 synchrophasor. Not just port identification -- full PDU parsing with function codes, register values, device identity, and Value/Quality/Timestamp extraction.
- **Process-historian-grade VQT extraction.** Typed `ProcessReading` event family with per-protocol native quality preservation (no normalization at the DPI layer — embedder owns policy). Sparkplug B alias resolution, OPC UA NodeId correlation, PCCC three-address-field decode, synchrophasor CFG-driven per-PMU layout. Three timestamps preserved per reading (source, observed, intermediate).
- **Frame-level integrity inspection (Stovetop).** Every frame is checked for structural anomalies before protocol dissection: runt/oversized detection, Ethernet padding entropy analysis for covert channel detection, FCS CRC-32 validation, DNP3 DLL CRC-16 validation, and capture truncation flagging using preserved `orig_len`.
- **ICMP threat detection (ICMPeeker).** ICMP redirect detection for routing manipulation attacks. Echo payload entropy analysis for covert tunnel detection (icmpsh, ptunnel). Suspicious type flagging for router advertisement injection, timestamp/address-mask recon.
- **Stateful L2 monitoring (Bilgepump).** Cross-frame state accumulation for temporal anomaly detection: ARP cache poisoning via MAC/IP binding changes, VLAN hopping via double-tagged 802.1Q analysis, STP root hijacking with whitelist enforcement, rogue DHCP server detection, LLDP/CDP identity conflict tracking, MAC flapping and locally-administered bit detection.
- **Structured Bronze v2 event model.** Six event families (ProtocolTransaction, AssetObservation, TopologyObservation, ParseAnomaly, ExtractedArtifact, ProcessReading) with full packet context in every envelope. Typed `PointIdentifier` and `RawQuality` enums preserve protocol-native addressing and quality bits without normalization.
- **Built-in deduplication.** SHA256-based sliding-window dedup for multi-collector deployments. 5-second window, 1-second quantization. Protocol events and anomaly findings dedup independently.
- **Embeddable.** `DpiEngine::new()` gives you a ready-to-use engine in one line. No configuration files, no runtime dependencies, no daemon. Process a capture, get structured events back.
- **850 tests.** Unit tests for every dissector and detector. Integration tests for full-pipeline capture processing. Zero ignored, zero flaky.
- **Self-registering decoders via `inventory`.** Adding a new protocol is one new file with an `inventory::submit!` block — no central registration list to edit. `DpiEngine::new()` collects every registration at startup and instantiates via factory closures.
- **Typed `ProtocolFields` enum** alongside the legacy `attributes: BTreeMap<String, String>` escape hatch. As of 1.15.0 the 9 most-deployed OT protocols (Modbus, DNP3, IEC 104, S7comm, OPC UA, EtherNet/IP, IEC 61850, HART-IP, Sparkplug B) all emit typed fields; downstream consumers pattern-match instead of guessing string keys. The deprecated `attributes` bag and the legacy `modbus` sub-field will be removed in v2.0.

---

## Signature Set

### OT / ICS Protocols

| Protocol | Transport | Port / EtherType | Parsing Depth |
|----------|-----------|-----------------|---------------|
| Modbus/TCP | TCP | 502 | MBAP header, function codes, register read/write, exception codes, device identification (FC 43) |
| DNP3 | TCP | 20000 | DLL + transport + application layer, function codes, source/dest address, role inference. DLL CRC-16 validation via stovetop. |
| IEC 60870-5-104 | TCP | 2404 | APCI frame types (I/S/U), ASDU type ID, cause of transmission, IOA |
| IEC 61850 MMS | TCP | 102 | ISO-on-TCP + COTP + MMS service identification, TSAP extraction, visible strings |
| IEC 61850 GOOSE | L2 | 0x88B8 | Application ID, dataset references |
| IEC 61850 SV | L2 | 0x88BA | Application ID, sample data |
| EtherNet/IP | TCP | 44818 | Encapsulation commands, session handle, CIP identity objects |
| OPC UA | TCP | 4840, 12001 | Message type/chunk, secure channel ID, sequence/request IDs |
| S7comm | TCP | 102 | TPKT/COTP/S7 PDU, ROSCTR, function codes, parameter/data blocks |
| PROFINET | UDP/L2 | 34964 / 0x8892 | Frame ID classification, DCP service parsing, cyclic IO, alarms |
| BACnet/IP | UDP/LLC | 47808 | BVLC + NPDU + APDU type, confirmed/unconfirmed services, device instance |
| HART-IP | TCP/UDP | 5094 | Session initiate, passthrough commands, device identity |
| OMRON FINS | TCP/UDP | 9600 | FINS header, command codes, memory area read/write |
| EtherCAT | L2 | 0x88A4 | Datagram headers, ADP/ADO addressing, working counters, vendor/product hints |
| MRP | L2 | 0x88E3 | MRP_Test/TopologyChange/LinkDown/LinkUp TLVs, domain UUID, ring state |
| PRP | L2 | 0x88FB | Supervision frames (PRP_Node/RedBox/VDAN/HSR_Node), RCT trailer detection |
| PCCC | TCP | (over CIP/ENIP 44818) | Allen-Bradley legacy SLC/PLC-5/MicroLogix. Service 0x4B Execute PCCC; Protected Typed Logical Read with TNS request/response correlation; per-element ProcessReading emission with PointIdentifier::PcccAddress |
| Sparkplug B | TCP | (over MQTT 1883/8883) | Stateful alias resolution from BIRTH messages; bdSeq supersession; gap-epoch unresolvable-alias detection; configurable TTL + LRU session eviction; full datatype-narrowed PointValue + RawQuality::SparkplugQuality emission |
| IEEE C37.118 (synchrophasor) | TCP/UDP | 4712, 4713 | CFG-2 frame parser captures per-PMU layout (station name, format flags, channel names); data frames decode phasors (mag+angle), frequency, dfreq, analogs, digitals — one ProcessReading per channel |
| CC-Link IE Field | UDP | 61450 | Port-based recognition (asset inventory; no PDU parsing) |
| CODESYS | TCP | 1217, 1740, 2455, 11740 | V2/V3 Gateway/Runtime recognition (asset inventory) |
| IO-Link Wireless | UDP | 59152 | Port-based recognition (asset inventory) |
| Beckhoff ADS | TCP | 48898 | TwinCAT. AMS/TCP framing, full AMS header (NetIDs, ports, command, state flags, error code), invoke-ID request/response pairing, command naming, AssetObservation per source NetID |
| GE SRTP | TCP | 18245 | GE PACSystems / 90-30 / 90-70 PLCs. 56-byte header parse, service request code naming, sequence-number request/response pairing, status code propagation |
| TriStation | UDP | 1502 | Schneider/Triconex SIS controllers (Tricon, Trident, Tri-GP). Function code naming per public TRITON write-ups; high-severity ParseAnomaly on `SetControlProgram` (0x70 — TRITON payload-delivery command); AssetObservation for engineering-workstation and controller roles |
| OPC UA PubSub | UDP | 4840 | UADP NetworkMessage parsing: version, publisher_id (all 5 types), group header, payload header / dataset writer IDs. **DataSetMessage decode** with Variant + DataValue field encodings → `ProcessReading` per field (StatusCode → `RawQuality::OpcUaStatusCode`, SourceTimestamp → Unix-micros via FILETIME conversion). RawData encoding skipped (requires out-of-band PublishedDataSet config). Field NodeIds fall back to `OpcUaNodeId::Numeric(field_index)` when config not on wire. TopologyObservation per publisher; AssetObservation per first-seen publisher_id. |
| MELSEC SLMP | TCP | 5007 | Mitsubishi iQ-R / iQ-F / Q series. 4E binary framing, command + subcommand naming for batch read/write, random read/write, remote run/stop/reset, CPU model. Serial-number request/response pairing, end-code propagation, AssetObservation from Read CPU Model response (model string captured) |
| Yokogawa Vnet/IP | UDP | 32768 | Centum VP / ProSafe-RS DCS. Best-effort header parsing per Wireshark dissector (length, sequence, function code, source/dest vnet addresses); spec is proprietary so unknown function codes are emitted by hex. AssetObservation per source vnet address |
| OSIsoft PI | TCP | 5450, 5460-5462 | PI Server / PI Connector / AF Server. Recognition by port and magic-byte fingerprint (`PINETMGR`, `PISystem`, `PI-API`, `AFServer`); version-string capture when `3.4.x.y` visible. AssetObservation role=`osisoft_pi_server`. Deep parse not feasible (proprietary). |
| OPC Classic (DA/HDA/AE) | TCP | 135 (+ dynamic) | DCOM-based legacy OPC riding DCE/RPC. Detects OPC interface UUIDs (`IOPCServer`, `IOPCAsyncIO2`, `IOPCHDA_Server`, `IOPCEventServer`, etc.) in BIND PDUs; mixed-endian UUID decoding. Endpoint-mapper dynamic-port tracking not yet implemented. |
| CIP Safety | TCP | 44818 | SIL-3 safety profile over CIP/EtherNet/IP. Detects Network Safety Segment (0x50) in Forward_Open (0x54) and Large_Forward_Open (0x5B) connection paths. Emits cip_safety_forward_open with connection serial / vendor / originator serial / RPI / transport type. Internal safety-segment fields not yet parsed (Type 1/2/Extended). |
| GVCP / GigE Vision | UDP | 3956 | Industrial machine-vision control protocol. 8-byte header parse; DISCOVERY / READREG / WRITEREG / READMEM / WRITEMEM / FORCEIP / ACTION / EVENT command naming; status code propagation on acks. DISCOVERY_ACK payload yields AssetObservation with manufacturer / model / device version / serial / user name. |
| DNP3-SAv5 | TCP | 20000 | DNP3 Secure Authentication v5 (IEEE 1815-2012). Recognizes Object Group 120 (g120v1-v15) in DNP3 application data; names challenge / reply / aggressive-mode / session-key-status / error / cert / MAC / update-key variants. High-severity ParseAnomaly on g120v7 (Authentication Error). |
| BACnet/SC | TCP | 47808, 4843 | BACnet Secure Connect (ASHRAE 135-2020 Addendum bj). TLS-handshake recognition (typical), plaintext BVLC-SC header parse with function-code naming (Encapsulated-NPDU / Address-Resolution / Connect-Request / Heartbeat / Proprietary). Originating + destination VMAC extraction when flags set. |
| Allen-Bradley CSP | TCP | 2222 | Pre-CIP legacy AB Ethernet protocol for PLC-5E, SLC 5/05, MicroLogix 1100/1400. CSP frame header parse, command + function naming (register session, PCCC request/reply, read/write), transaction-id pairing, status code propagation. AssetObservation with vendor=`Allen-Bradley` on register session. |
| Modicon UMAS | TCP | 502 | Schneider proprietary management protocol layered inside Modbus function code 0x5A. Sub-function naming for INIT_COMM / READ_ID / READ/WRITE_MEMORY_BLOCK / TAKE_PLC_RESERVATION / START_PLC / STOP_PLC / DOWNLOAD_BLOCK / AUTH_REQUEST etc. High-severity ParseAnomaly on Industroyer2-class commands (STOP_PLC, INITIALIZE_DOWNLOAD, DOWNLOAD_BLOCK, END_STRATEGY_DOWNLOAD). Reverse-engineered per NCC Group / Claroty / Forescout public write-ups. |
| EtherNet/IP Class 1 I/O | UDP | 2222 | High-volume cyclic implicit-messaging traffic (servo positions, drive commands, safety I/O). CPF parse with Sequenced Address Item + Connected Data Item; per-connection sequence tracking; Run/Idle flag extraction; sequence-gap ParseAnomaly. Sampled (first + every 1000th) to avoid event flood at 1-5 kHz cycle rates. |
| POWERLINK | L2 | EtherType 0x88AB | Real-time motion control. SoC / PReq / PRes / SoA / ASnd / AInv / AMNI dispatch; node-role inference (MN=240, CN=1-239, broadcast=255). ASnd IdentResponse yields AssetObservation with VendorId / ProductCode / RevisionNumber / SerialNumber / HostName. |
| SERCOS III | L2 | EtherType 0x88CD | Real-time motion / CNC. MST / MDT / AT / NRT / HotPlug telegram-type dispatch; slot index; MST cycle counter; sync-flag transition tracking with `sercos_sync_lost` event. Sampled (first per telegram-type + every 1000th). Deep Service Channel parse deferred (partial-public spec). |
| PTPv2 / gPTP | L2 / UDP | EtherType 0x88F7, UDP 319/320 | IEEE 1588 / 802.1AS time sync. Common 34-byte header parse; Sync / Delay_Req / Pdelay / Follow_Up / Announce / Signaling / Management dispatch. Announce extracts grandmasterClockIdentity + clockClass / clockAccuracy / priority1 / priority2 / stepsRemoved / timeSource. ParseAnomaly on grandmaster change in a domain. |
| Foundation Fieldbus HSE | TCP / UDP | 1089, 1090, 1091 | FF High Speed Ethernet (Annunciation / FMS / System Management). Port-based recognition with magic-byte fingerprint; AssetObservation per (server, port). Deep FDA parse infeasible (member-restricted spec FF-588/589). |
| AVTP / IEEE 1722 | L2 | EtherType 0x22F0 | Audio Video Transport Protocol for TSN audio-video bridging (automotive infotainment / ADAS, growing into industrial TSN camera + audio-over-Ethernet). Common 12-byte header parse (subtype, stream_valid, version, mr, tv, stream_id); media subtypes (IEC61883 / MMA / AAF / CVF / CRF / TSCF / SVF / RVF) sampled (first + every 1000th per stream); control subtypes (ADP / AECP / ACMP / MAAP) emitted unconditionally. ADP ENTITY_AVAILABLE yields AssetObservation with entity_id / model_id / role (talker / listener / entity) + gPTP grandmaster + domain. |
| Modbus/UDP | UDP | 502 | Sibling to Modbus/TCP — MBAP+PDU per datagram, no stream reassembly. Found on legacy RTUs and resource-constrained embedded controllers. Full FC dispatch (read coils / discretes / holding / input registers; write single / multiple; mask-write; read-write-multiple); LRU pending-table pairs (src_ip, dst_ip, txn_id) with request_only / response_only on idle flush; ProcessReading emission for register reads. UMAS FC 0x5A explicitly skipped (handled by umas.rs on TCP). |
| Emerson ROC Plus | TCP | 4000 | Gas SCADA telemetry for RTUs at compressor stations / pipeline meters / custody-transfer points across North American oil & gas. 6-byte addressed header + opcode dispatch (Comm Test / General Read/Write / Realtime-Clock Read/Set / Login / History Index / Alarm + Event Data / Configurable Opcode List + Data / Hourly + Daily History Records / Send Commands). High-severity ParseAnomaly on state-mutating opcodes (General Write 7, Set RTC 11, Send Commands 138). AssetObservation on Login with vendor=`Emerson`. Spec is partially proprietary — derived from Wireshark `packet-rocplus.c` + Emerson public docs + field observation. |

### IT / Infrastructure Protocols

| Protocol | Transport | Port / EtherType | Parsing Depth |
|----------|-----------|-----------------|---------------|
| DNS | UDP/TCP | 53, 5353 (mDNS) | Full RFC 1035: queries, answers, A/AAAA/PTR/TXT/SRV records, compression pointers. mDNS device enrichment (AirPlay, Google Cast, Roku, printers, HomeKit, Sonos, Hue, ESPHome) |
| DHCP | UDP | 67, 68 | BOOTP header + options: message type, hostname, vendor class, client ID, server ID, offered/requested IP |
| HTTP | TCP | 80, 8080 | Request line (method, URI, host), response status, Content-Type, Content-Length |
| TLS | TCP | 443, 4840 | Client Hello SNI extraction, cipher suites, TLS version |
| SNMP | UDP | 161, 162 | BER decoder: v1/v2c/v3, community string, PDU types (get/set/response/trap), var-binds, sysName/sysDescr/sysObjectID |
| SSH | TCP | 22 | Banner extraction: protocol version, software version, OS hint from comments |
| FTP | TCP | 21 | Commands (STOR/RETR/USER/QUIT), reply codes, server banner (220) for device fingerprinting |
| NTP | UDP | 123 | Version, mode (client/server/broadcast), stratum, reference ID, root delay/dispersion |
| MQTT | TCP | 1883, 8883 | CONNECT (client_id, username, protocol version, clean session), PUBLISH (topic, QoS, retain), SUBSCRIBE (topic) |
| Syslog | UDP | 514 | RFC 3164 + RFC 5424: facility, severity, hostname, app name, message |
| RADIUS | UDP | 1812, 1813 | Access-Request/Accept/Reject/Accounting, username, NAS-IP, NAS-Identifier, calling/called station ID |
| ICMP | IP proto 1 | -- | Type/code parsing, echo id/sequence, redirect gateway extraction, timestamp/mask requests, destination unreachable codes |
| IGMP | IP proto 2 | -- | RFC 2236 + RFC 3376 deep parse. v1/v2 8-byte header with group address; v3 Query extended fields (S-flag, QRV, float-decoded QQIC, source-address list); v3 Membership Report variable-length group records with record-type / aux-data-len / per-record source addresses. Float-encoded max-resp-code / QQIC per §4.1.1. TopologyObservation `multicast_join` on Join-style ops. |
| SMB1 | TCP | 445, 139 | SMB1 signature recognition (`\xFF SMB`); traffic classification only. SMB2 traffic is owned by the deeper `smb2` decoder below. |
| SMB2 / SMB3 | TCP | 445, 139 | MS-SMB2 deep parse: NEGOTIATE (dialects, capabilities, client_guid), SESSION_SETUP (security-blob length noted; NTLMSSP owned separately), TREE_CONNECT (UNC share path), CREATE (filename, DesiredAccess, ShareAccess, CreateDisposition), CLOSE, READ / WRITE (FileId-tracked across CREATE), IOCTL (10 FSCTL codes named — `FSCTL_PIPE_TRANSCEIVE` flagged high on `\PIPE\svcctl`/samr/atsvc/drsuapi; `FSCTL_DFS_GET_REFERRALS`; `FSCTL_VALIDATE_NEGOTIATE_INFO`). MessageId request/response pairing with LRU bounds. NetBIOS Session Service framing on 139 and 445. Compound requests walked via NextCommand. NT-status naming (`STATUS_LOGON_FAILURE`, `STATUS_ACCESS_DENIED`, etc.). SMB3 Transform PDUs (0xFD) recognised but encrypted payload opaque. |
| Kerberos | TCP/UDP | 88, 464 | RFC 4120 full ASN.1 parse: AS-REQ/REP, TGS-REQ/REP, AP-REQ, KRB-ERROR. Per-message extraction in the clear — client principal (cname), server principal (sname), realm, etype lists, kdc-options, nonce, from/till/rtime timestamps, ap-options, ticket realm + sname from embedded Ticket structures, KRB-ERROR error-code + e-text. AssetObservation for KDC servers and authenticating clients. EncryptedData payloads (EncTicketPart, EncKDCRepPart, EncAuthenticator, EncAPRepPart) and PA-DATA extensions (FAST, PKINIT) intentionally opaque. TCP 4-byte length prefix handled. |
| LDAP / LDAPS | TCP | 389 / 636 | RFC 4511 LDAPv3 BER parse: bind / search / modify / add / del / compare / abandon / extended / unbind. Per-op extraction — bind DN, SASL mechanism, search baseObject + scope + sizeLimit + timeLimit + filter-type discriminator + attribute selectors, modify/add/del/modifyDN target DN, extended-request OID (StartTLS `1.3.6.1.4.1.1466.20037` recognised). messageID-based req/response pairing within session; result-code naming (success=0, invalidCredentials=49, etc.). TCP chunk-straddling messages buffered. SearchResultEntry attribute values skipped (too noisy). LDAPS port 636 keeps recognition-only behavior (TLS-encrypted). |
| RDP | TCP | 3389 | TPKT + ITU X.224 Connection Request / Connection Confirm parsing; `mstshash=` cookie extraction (note: spoofable); requested/selected protocol bitmask; negotiation failure code propagation. Stops at encryption boundary. |
| mDNS / WS-Discovery | UDP | 5353 / 3702 | mDNS: full DNS message parse with compression pointers; PTR/SRV/TXT/A/AAAA → AssetObservation. WS-Discovery: byte-pattern SOAP envelope match for Probe / ProbeMatch / Hello / Bye / Resolve; XAddrs + Types extraction → AssetObservation |
| DCE/RPC | TCP | 135 + dynamic | MS-RPCE common header, BIND / ALTER_CONTEXT context-list with mixed-endianness UUID decoding; known interface naming (samr, lsarpc, srvsvc, winreg, atsvc, eventlog, epmapper, svcctl, drsuapi, efsrpc); REQUEST/RESPONSE opnum extraction; call-id pairing |
| TFTP | UDP | 69 | RFC 1350. RRQ/WRQ/ERROR opcode dispatch, filename + mode extraction; high-severity ParseAnomaly on firmware-shaped WRQ filenames (`.bin`, `.hex`, `.fw`, etc.) — unauthorized firmware push detection |
| IPsec IKE | UDP | 500, 4500 | IKEv1 + IKEv2 28-byte header; exchange-type naming (Main/Aggressive/Quick Mode; SA_INIT, IKE_AUTH, CREATE_CHILD_SA, INFORMATIONAL); initiator/responder SPI extraction; payload chain walk for Vendor ID payloads (Microsoft, Cisco Unity, DPD, NAT-T); NAT-T non-ESP marker handling on 4500 |
| VNC / RFB | TCP | 5900-5910 | RFC 6143 handshake: server/client ProtocolVersion banners, security-types list (v3.7+) or single u32 (v3.3); Invalid-with-reason path; chosen security type if observable. Stops at encryption boundary. |
| WinRM / WS-Management | TCP | 5985, 5986 | Byte-pattern POST /wsman detection on 5985, SOAP `<a:Action>` URI extraction (Get/Put/Create/Delete/Enumerate/Pull, MS Shell Command/Receive/Send/Signal); 5986 is TLS-opaque (recognition + AssetObservation only) |
| NetBIOS / NBT | UDP / TCP | 137, 138, 139 | NBNS name service (DNS-like, encoded names with suffix-byte role inference: workstation, file server, master browser, domain controllers); NetBIOS Datagram Service header parse with source-name/dest-name extraction |
| TACACS+ | TCP | 49 | RFC 8907. 12-byte plaintext header (type, seq, session_id, flags); for unencrypted bodies (flag bit 0), AUTHEN START extracts action / authen_type / service / priv_lvl / username / port / rem_addr. Body is XOR-obfuscated (not encrypted) — header alone gives login visibility |
| WireGuard | UDP | 51820 | Handshake Initiation / Response / Cookie Reply / Transport Data dispatch; sender_index + receiver_index extraction; reserved-byte sanity check identifies WG even on non-default ports |
| NetFlow / IPFIX | UDP | 2055, 4739, 9995, 9996 | v5 (24-byte header + records), v9 (FlowSets), IPFIX/v10 (Sets) export-message parse. **Cross-packet template tracking** keyed by (exporter, observation_domain, template_id) with 1024-entry LRU; Data FlowSets decoded against stored templates → `ProtocolTransaction` per flow record with 24 IANA IPFIX IEs named (octet/packet delta counts, IPv4/IPv6 src+dst addresses + prefixes, transport ports, protocol, BGP AS numbers, MAC addresses, flow start/end millis, ingress/egress interfaces). IPv4 dotted-decimal / IPv6 colon-hex / MAC `aa:bb:cc:dd:ee:ff` formatting. `template_unresolved` low-severity anomaly when a Data FlowSet references an unknown template. AssetObservation per exporter + collector. Options Template contents and PEN enterprise elements skipped (declared length skipped over). |
| QUIC | UDP | 80, 443 | Long-header parse (INITIAL / 0-RTT / HANDSHAKE / RETRY / Version Negotiation): version, DCID, SCID; short-header recognition only (DCID is context-dependent). AEAD payload not decrypted — SNI extraction intentionally out of scope. |
| SMTP / SMTPS | TCP | 25, 465, 587 | Line-oriented ASCII command parse (HELO/EHLO/MAIL FROM/RCPT TO/DATA/RSET/QUIT/STARTTLS/AUTH); server banner with vendor heuristic (Postfix/Sendmail/Exchange/Exim/IIS). STARTTLS-220 marks session as encrypted. 465 is TLS from byte 0 — recognition only. |
| OpenVPN | UDP / TCP | 1194 | Opcode/key_id 5-bit/3-bit split; HARD_RESET / SOFT_RESET / CONTROL / ACK / DATA / WKC dispatch including v1/v2/v3 hard-reset variants. Session ID (8 bytes) extraction; TCP 2-byte BE length-prefix reassembly |
| SIP / RTP / RTCP | UDP / TCP | 5060 (SIP), 5004 (RTP), 5005 (RTCP) | SIP request-line + response-line parse with method naming (INVITE/REGISTER/BYE/etc.); From / To / Call-ID / CSeq / User-Agent / Server headers. RTP V=2 header parse with PT naming (PCMU/PCMA/G722/G729/dynamic); per-SSRC throttling. RTCP SR/RR/SDES/BYE/APP dispatch. Byte-pattern dispatch (no port heuristic — works on SDP-negotiated ports). |
| CoAP | UDP | 5683, 5684 | RFC 7252. 4-byte fixed header (Ver/Type/TKL/Code/Message-ID); delta-encoded options (Uri-Host / Uri-Path / Uri-Query / Content-Format extraction); method (GET/POST/PUT/DELETE/FETCH/PATCH) + response-class naming (2.05 Content, 4.04 Not Found, etc.). 5684 (CoAPS / DTLS) is opaque past handshake. |
| MQTT-SN | UDP | 1884 | MQTT for Sensor Networks. Short and extended (3-byte) length variants; CONNECT / PUBLISH / SUBSCRIBE / REGISTER / WILL* / ADVERTISE / GWINFO / FORWARDER_ENCAPSULATION dispatch; topic_id + msg_id + return_code extraction; AssetObservation per CONNECT (client) and GWINFO (gateway). |
| AMQP 1.0 | TCP | 5671, 5672 | OASIS AMQP 1.0. 8-byte protocol header parse (proto_id: amqp / tls / sasl), frame header (size / DOFF / type / channel); described-type performative dispatch (OPEN / BEGIN / ATTACH / FLOW / TRANSFER / DISPOSITION / DETACH / END / CLOSE; SASL-MECHANISMS / INIT / CHALLENGE / RESPONSE / OUTCOME). 5671 is TLS-opaque. |
| NTLMSSP | TCP | 80, 135, 139, 445, 5985, 8080 | Microsoft AD challenge/response auth embedded inside SMB Session Setup, HTTP Negotiate, DCE/RPC AUTH3. Type1 NEGOTIATE / Type2 CHALLENGE / Type3 AUTHENTICATE recognition by `NTLMSSP\0` magic. Extracts domain / username / workstation / server challenge / target info (AV_PAIRs: NbComputerName, DnsDomainName, etc.). HTTP `Negotiate <base64>` header recognition. ParseAnomaly medium on plaintext HTTP (credential exposure). AssetObservation for AD authentication clients and targets. |
| Diameter | TCP | 3868, 5868 | RFC 6733 AAA — telecom / 5G core control plane. 20-byte header parse (version, message_length u24, command flags R/P/E/T, command_code u24, application_id, hop_by_hop_id, end_to_end_id); 4-byte-padded AVP walk with vendor-flag handling; command naming (Capabilities-Exchange / Device-Watchdog / Disconnect-Peer / Re-Auth / Accounting / Abort-Session / Session-Termination / EAP); request/answer pairing by hop_by_hop_id with status (ok / error / request_only). AVP extraction for User-Name, Session-Id, Origin-Host, Origin-Realm, Result-Code. AssetObservation on CER. 5868 (TLS-wrapped) emits single session marker. |
| RadSec | TCP | 2083 | RFC 6614 RADIUS-over-TLS. Payload is encrypted past handshake — decoder is recognition + TLS-record fingerprinting + AssetObservation only. Per-session first-byte classifier (ChangeCipherSpec / Alert / Handshake / ApplicationData); TLS version + record length extraction from header. ParseAnomaly low when port 2083 traffic does not begin with a TLS record byte. AssetObservation role=`radsec_server` on first observation. STARTTLS upgrade variant (§2.2) out of scope. |

### L2 / Link Layer Protocols

| Protocol | Match | Parsing Depth |
|----------|-------|---------------|
| ARP | EtherType 0x0806 | Operation, sender/target MAC+IP |
| LLDP | EtherType 0x88CC | Chassis ID, port ID, TTL, system name/description, capabilities |
| CDP | SNAP 00:00:0C / 0x2000 | Device ID, port, platform, software version, capabilities, native VLAN, duplex |
| STP/RSTP | LLC 0x42/0x42 | Root/bridge ID, root path cost, port ID, timers, flags |
| MSTP | LLC 0x42/0x42 (version >= 3) | MST config name, revision level, MSTI records (regional root, path cost, priority) |
| PVST+ | SNAP 00:00:0C / 0x010B | Standard BPDU fields + originating VLAN ID |
| LACP | EtherType 0x8809 | Actor/partner: system MAC, priority, key, port, state flags (activity, synchronization, collecting, distributing) |
| VTP | SNAP 00:00:0C / 0x2003 | Version, message type, domain name, revision, VLAN list |
| PRP | EtherType 0x88FB | Supervision type, source/RedBox MAC, sequence number |
| MRP | EtherType 0x88E3 | Frame type, domain UUID, ring state (open/closed), priority |

---

## Stovetop: Frame-Level Integrity & Anomaly Detection

The **stovetop** module (`src/stovetop/`) inspects every frame for structural anomalies that protocol-level dissectors ignore. It hooks into the engine at two points: pre-dissector (frame-level) and per-dissector (protocol-specific).

### Frame Integrity Checks

| Check | Decoder Tag | Severity | What It Catches |
|-------|-------------|----------|-----------------|
| Runt frame detection | `stovetop:runt` | Medium | Frames with `orig_len` below the 60-byte Ethernet minimum (FCS-stripped). Under-sized frames on OT networks can indicate misconfigured devices or crafted packets. |
| Oversized frame detection | `stovetop:oversized` | Low/High | Frames exceeding 1514 bytes (standard) or 9018 bytes (jumbo). Jumbo-range is Low; beyond jumbo is High. |
| Capture truncation | `stovetop:truncated` | Low | `captured_len < orig_len` — the capture interface snapped the packet. Flags data loss that could mask protocol content. |
| Non-zero Ethernet padding | `stovetop:padding` | Medium/High | Padding bytes after the IP total-length boundary that contain non-zero data. Medium for low-entropy fills (implementation quirks), High for high-entropy fills (possible covert channel or data exfiltration). Shannon entropy scoring. |
| Ethernet FCS validation | `stovetop:fcs` | High | CRC-32 validation of the Ethernet frame check sequence when present. Invalid FCS indicates tampering, corruption, or replay artifacts. |

### Protocol Integrity Checks

| Check | Decoder Tag | Severity | What It Catches |
|-------|-------------|----------|-----------------|
| DNP3 DLL CRC-16 | `stovetop:integrity` | High | Validates CRC-16 on DNP3 data-link-layer header and user-data blocks. CRC mismatches indicate data corruption, man-in-the-middle modification, or replay of tampered frames. Uses the DNP3 polynomial (0x3D65 reflected). |

---

## ICMPeeker: ICMP Anomaly Detection

The **icmpeeker** module (`src/icmpeeker.rs`) inspects ICMP packets for malicious patterns. Runs post-decoder alongside the ICMP protocol dissector: the dissector provides protocol visibility (`ProtocolTransaction`), ICMPeeker provides the threat signal (`ParseAnomaly`).

| Check | Decoder Tag | Severity | What It Catches |
|-------|-------------|----------|-----------------|
| ICMP Redirect | `icmpeeker:redirect` | Critical | Type 5 messages that instruct hosts to reroute traffic through an attacker-controlled gateway. Should never appear on OT/ICS networks. Extracts gateway IP for investigation. |
| ICMP Tunnel | `icmpeeker:tunnel` | High | Echo Request/Reply (types 0, 8) with payloads >= 64 bytes and Shannon entropy > 6.0. Detects covert channels using tools like icmpsh, ptunnel, or custom ICMP tunnels. Normal pings have predictable low-entropy padding. |
| Suspicious ICMP type | `icmpeeker:suspicious` | Medium/High | Router Advertisement (type 9), Router Solicitation (type 10) — rogue router injection. Timestamp Request/Reply (types 13/14), Address Mask Request/Reply (types 17/18) — host fingerprinting and subnet discovery via deprecated types. |

### Stovetop Configuration

All stovetop checks are enabled by default:

```rust
use fm_dpi::stovetop::config::StovetopConfig;

let mut config = StovetopConfig::default();
config.check_padding = false;           // disable padding inspection
config.padding_entropy_threshold = 3.0; // adjust covert channel sensitivity
config.max_ethernet_frame = 9018;       // jumbo frames are expected
```

### ICMPeeker Configuration

All ICMPeeker checks are enabled by default:

```rust
use fm_dpi::icmpeeker::IcmpeekerConfig;

let mut config = IcmpeekerConfig::default();
config.check_redirects = true;          // ICMP redirect detection
config.check_tunnels = true;            // covert channel via echo payloads
config.check_suspicious_types = true;   // deprecated/recon ICMP types
config.tunnel_min_payload = 64;         // minimum echo payload for tunnel check
config.tunnel_entropy_threshold = 6.0;  // Shannon entropy threshold (0.0-8.0)
```

---

## Bilgepump: Stateful L2 Monitoring

The **bilgepump** module (`src/bilgepump/`) accumulates state across frames to detect temporal L2 anomalies that per-frame inspection cannot catch. It hooks into the engine at two points: pre-VLAN-unwrap (VLAN hopping, MAC anomalies) and post-decoder (protocol-specific stateful analysis).

Unlike stovetop, bilgepump maintains **cross-frame state**: MAC/IP binding tables, STP root history, DHCP server identity tracking, and LLDP/CDP identity records. State ages out automatically via configurable TTLs and is evicted at end-of-segment.

### ARP Spoofing & Poisoning

| Check | Decoder Tag | Severity | What It Catches |
|-------|-------------|----------|-----------------|
| ARP spoof detection | `bilgepump:arp_spoof` | Critical | IP address claimed by a different MAC than the established binding. Classic MitM setup — the attacker poisons the ARP cache so traffic flows through them. Only fires within the binding TTL window. |
| Gratuitous ARP | `bilgepump:arp_gratuitous` | Medium | Unsolicited ARP replies (sender_ip == target_ip). Legitimate uses exist (IP failover, VRRP), but on OT networks these are often attack indicators. |
| ARP flood | `bilgepump:arp_flood` | High | Excessive ARP replies from a single MAC within a sliding window. Indicates ARP cache poisoning at scale or address pool flooding. |

### MAC Anomalies

| Check | Decoder Tag | Severity | What It Catches |
|-------|-------------|----------|-----------------|
| Locally-administered MAC | `bilgepump:mac_local` | Low | Source MAC with the locally-administered bit set (bit 1 of first octet). Indicates VMs, containers, or spoofed NICs — unusual on OT networks with physical devices. |
| Multicast source MAC | `bilgepump:mac_multicast` | High | Multicast bit set on a source MAC — this should never happen in legitimate unicast traffic. Indicates crafted frames. |
| MAC flapping | `bilgepump:mac_flap` | High | A single MAC associated with multiple distinct IPs within a sliding window. Indicates ARP spoofing, DHCP exhaustion, or a compromised device scanning the network. |

### VLAN Hopping

| Check | Decoder Tag | Severity | What It Catches |
|-------|-------------|----------|-----------------|
| Double-tagged 802.1Q | `bilgepump:vlan_hop` | Critical | Frame with nested 802.1Q tags where outer and inner VLAN IDs differ. Classic VLAN hopping attack — the outer tag is stripped by the first switch, and the inner tag routes the frame to a different VLAN the attacker shouldn't reach. |

### STP Manipulation

| Check | Decoder Tag | Severity | What It Catches |
|-------|-------------|----------|-----------------|
| STP root change | `bilgepump:stp_root_change` | High | The elected STP root bridge has changed. On a stable OT network, this should be rare. Frequent changes indicate topology manipulation or a rogue switch claiming root. |
| Unauthorized root | `bilgepump:stp_unauthorized` | High | A bridge claiming root status that is not on the configured whitelist. Direct indicator of a rogue switch or STP attack. Only active when `stp_root_whitelist` is configured. |

### DHCP Abuse

| Check | Decoder Tag | Severity | What It Catches |
|-------|-------------|----------|-----------------|
| Rogue DHCP server | `bilgepump:dhcp_rogue` | Critical | DHCP Offer or Ack from a server not in the `known_dhcp_servers` list. Rogue DHCP servers can redirect all network traffic or assign attacker-controlled DNS. |
| DHCP starvation | `bilgepump:dhcp_starvation` | High | Excessive DHCP Discover/Request volume within a sliding window. Indicates an attacker exhausting the DHCP address pool to force clients onto a rogue server. |

### Identity Conflicts

| Check | Decoder Tag | Severity | What It Catches |
|-------|-------------|----------|-----------------|
| LLDP identity conflict | `bilgepump:lldp_conflict` | High | Same source MAC advertising a different LLDP chassis_id than previously observed. Indicates device impersonation or a rogue device swapped onto the same port. |
| CDP identity conflict | `bilgepump:cdp_conflict` | High | Same source MAC advertising a different CDP device_id than previously observed. Same implications as LLDP conflict — device identity should be stable. |

### Configuration

All checks are enabled by default. Bilgepump supports blessed bindings, STP root whitelists, and known DHCP server lists:

```rust
use fm_dpi::bilgepump::config::{BilgepumpConfig, BlessedBinding};

let mut config = BilgepumpConfig::default();

// Known-good MAC/IP pairs that should never trigger ARP spoof alerts
config.blessed_bindings.push(BlessedBinding {
    mac: "00:1c:06:aa:bb:cc".to_string(),
    ip: "10.0.1.50".to_string(),
    description: Some("PLC-01 Siemens S7-1500".to_string()),
});

// Only these bridges should ever be STP root
config.stp_root_whitelist = vec!["8000.001c06aabbcc".to_string()];

// Only this server should respond to DHCP
config.known_dhcp_servers = vec!["10.0.0.1".to_string()];

// Tune thresholds
config.arp_binding_ttl_secs = 600;      // 10 minute binding TTL
config.arp_flood_threshold = 30;         // lower threshold for OT
config.mac_flap_threshold = 3;           // 3 distinct IPs = flapping
```

### State Persistence

Bilgepump state is in-memory by default. For long-running deployments that need state across process restarts, the `BilgepumpMonitor` can be serialized:

```rust
// State tables implement Serialize/Deserialize for snapshot/restore
// (caller handles I/O — the engine stays disk-free)
```

---

## Bronze v2 Event Model

Every packet processed produces zero or more `BronzeEvent`s, each wrapping an `EventEnvelope` (packet metadata) and one of five event families:

| Family | Purpose | Example |
|--------|---------|---------|
| **ProtocolTransaction** | Request-response pair or single operation | Modbus read_holding_registers, DNS query/response, ICMP Echo Request |
| **AssetObservation** | Device/service identification | LLDP system name, DHCP hostname, SSH banner |
| **TopologyObservation** | Network relationship | ARP neighbor, LACP bond, STP root path, MRP ring |
| **ParseAnomaly** | Malformed, invalid, or suspicious packet | Bad MBAP length, truncated DNP3 frame, ICMP redirect, non-zero padding |
| **ExtractedArtifact** | Binary payload extraction | Modbus write data, DNP3 application payload |
| **ProcessReading** | Process variable Value/Quality/Timestamp from the wire | Sparkplug B metric, OPC UA ReadResponse, PCCC data-table read, IEEE C37.118 phasor |

### EventEnvelope

Every event carries full packet context: timestamp, src/dst MAC, src/dst IP, src/dst port, VLAN ID, transport protocol, frame index, segment hash, and byte/packet counts.

## Output Formats

Bronze JSON is canonical. Renderers under `output::` transform it into common downstream formats; each is a pure function of the event stream with no engine dependency.

| Renderer | Purpose | Module |
|----------|---------|--------|
| **InfluxDB Line Protocol** | Process historian ingest for `ProcessReading` events | `output::influx_line` |
| **OCSF (Open Cybersecurity Schema Framework) v1.4.0** | SIEM ingest. Maps `ProtocolTransaction` to Network/HTTP/DNS/SMB/SSH/Authentication, `AssetObservation` to Device Inventory Info, `ParseAnomaly` to Detection Finding | `output::ocsf` |

`ProcessReading` events have no OCSF mapping (process telemetry is out of scope for OCSF) and `ProtocolTransaction` events have no Influx mapping (use OCSF or Bronze JSON for those).

## Deduplication

Multi-collector deployments produce overlapping captures. The engine deduplicates using SHA256 over `(quantized_timestamp, src_ip, dst_ip, src_port, dst_port, family_key)` with a 5-second sliding window and 1-second quantization bucket.

All subsystems dedup independently using their decoder prefix as part of the family key (`stovetop:*`, `icmpeeker:*`, `bilgepump:*`).

## Supported Inputs

- Classic PCAP (little/big endian, microsecond/nanosecond timestamps)
- PCAPNG (Enhanced Packet Blocks, preserves `orig_len` for truncation detection)
- Ethernet linktype only (unsupported linktypes fail fast)

## CLI

```bash
marlinspike-dpi --input capture.pcapng --pretty
```

```bash
marlinspike-dpi \
  --input capture.pcap \
  --capture-id engagement-a-01 \
  --output bronze.json \
  --pretty
```

```bash
marlinspike-dpi --input capture.pcap --format ocsf > events.ndjson
marlinspike-dpi --input capture.pcap --format influx > readings.lp
```

Options:

- `--input <path>` -- PCAP or PCAPNG capture file
- `--capture-id <id>` -- stable identifier stamped into Bronze output (defaults to filename)
- `--output <path>` -- output path (stdout when omitted)
- `--pretty` -- pretty-print Bronze JSON (no effect on `ocsf` / `influx`)
- `--format <bronze|ocsf|influx>` -- output format (default `bronze`)
    - `bronze` -- canonical Bronze envelope JSON
    - `ocsf` -- OCSF v1.4.0 records as NDJSON (one JSON object per line); skips ProcessReading / ExtractedArtifact / TopologyObservation
    - `influx` -- InfluxDB Line Protocol, one line per `ProcessReading`; skips every other family

Output envelope:

```json
{
  "engine": "marlinspike-dpi",
  "version": "1.0.0",
  "input": { "path": "...", "capture_id": "...", "size_bytes": 12345 },
  "output": {
    "checkpoint": {
      "capture_id": "...",
      "schema_version": "v2",
      "segment_hash": "abc123...",
      "frames_processed": 1000,
      "events_emitted": 42
    },
    "events": [ ... ]
  }
}
```

## Library Usage

```rust
use fm_dpi::DpiEngine;

let bytes = std::fs::read("capture.pcap")?;
let mut engine = DpiEngine::new();
let events = engine.process_capture("capture-1", std::io::Cursor::new(bytes))?;
# Ok::<(), Box<dyn std::error::Error>>(())
```

With checkpoint metadata:

```rust
use fm_dpi::{DpiEngine, SegmentMeta};

let bytes = std::fs::read("capture.pcapng")?;
let mut engine = DpiEngine::new();
let output = engine.process_capture_to_vec(&SegmentMeta::new("capture-1"), std::io::Cursor::new(bytes))?;
# Ok::<(), Box<dyn std::error::Error>>(())
```

## FFI

Enable the `ffi` feature to build a `cdylib` / `staticlib`:

```bash
cargo build --features ffi
```

Exported symbols:

```c
// Process capture bytes, return JSON.
FmDpiProcessResult fm_dpi_process_pcapng_json(
    const char *capture_id,
    const uint8_t *data_ptr,
    size_t data_len
);

void fm_dpi_string_free(char *ptr);
const char *fm_dpi_version();
```

Accepts both PCAP and PCAPNG despite the legacy symbol name. Returns a JSON envelope with `output` or `error` fields.

## ICS Defense Corpus Validation

Run the engine against the public ICS-Pcaps archive:

```bash
cargo run -p marlinspike-dpi --bin ics-defense-corpus -- \
  validate \
  --corpus-root /path/to/ICS-Pcaps
```

Options: `--filter <text>` to subset fixtures, `--allow-missing` for partial checkouts.

## Architecture

```
Iron (PCAP/PCAPNG bytes)
  -> capture format detection (magic bytes)
  -> per-packet: Ethernet header parsing (MAC extraction)
  -> bilgepump pre-VLAN: VLAN hopping detection, MAC anomalies
  -> VLAN unwrapping -> IP -> TCP/UDP/ICMP header parsing
  -> stovetop pre-dissector: frame integrity checks (runt, oversized, truncation, padding, FCS)
  -> route to decoders by DecoderInterest (EtherType, TcpPort, UdpPort, IpProto, LLC, SNAP)
  -> decoder calls dissector.parse(), synthesizes BronzeEvent(s)
  -> bilgepump post-decoder: stateful L2 analysis (ARP spoof, STP root, DHCP abuse, identity)
  -> icmpeeker: ICMP anomaly detection (redirects, tunnels, suspicious types)
  -> stovetop per-dissector: protocol integrity checks (DNP3 CRC)
  -> SHA256 dedup filter (5s window)
  -> batch (256 events) -> output
```

Five-tier design:

- **Dissectors** (`src/dissectors/*.rs`) -- stateless protocol parsers implementing `ProtocolDissector` trait. Extract binary fields from payload bytes.
- **Decoders** (`src/engine.rs`) -- stateful session managers implementing `SessionDecoder` trait. Correlate request/response pairs, manage session state, emit Bronze events.
- **Stovetop** (`src/stovetop/*.rs`) -- frame-level and protocol-level integrity inspector. Runs pre-dissector, emits `ParseAnomaly` events for structural anomalies (runt, padding, FCS, CRC).
- **ICMPeeker** (`src/icmpeeker.rs`) -- ICMP-specific anomaly detector. Flags routing manipulation (redirects), covert channels (tunnel entropy), and recon (deprecated types).
- **Bilgepump** (`src/bilgepump/*.rs`) -- stateful L2 monitor. Accumulates MAC/IP bindings, STP root history, DHCP server identity, and device identities across frames. Detects temporal anomalies: ARP spoofing, VLAN hopping, STP manipulation, rogue DHCP, identity conflicts.

```
src/
  dissectors/          34 protocol parsers
    modbus.rs          Modbus/TCP
    dnp3.rs            DNP3
    iec104.rs          IEC 60870-5-104
    iec61850.rs        IEC 61850 (MMS, GOOSE, SV)
    ethernet_ip.rs     EtherNet/IP + CIP
    opc_ua.rs          OPC UA
    s7comm.rs          S7comm
    profinet.rs        PROFINET
    bacnet.rs          BACnet/IP
    hart_ip.rs         HART-IP
    fins.rs            OMRON FINS
    ethercat.rs        EtherCAT
    mrp.rs             MRP
    prp.rs             PRP
    dns.rs             DNS + mDNS
    dhcp.rs            DHCP
    http.rs            HTTP
    tcp.rs             TLS
    snmp.rs            SNMP
    ssh.rs             SSH
    ftp.rs             FTP
    ntp.rs             NTP
    mqtt.rs            MQTT
    syslog.rs          Syslog
    radius.rs          RADIUS
    icmp.rs            ICMP
    arp.rs             ARP
    lldp.rs            LLDP
    cdp.rs             CDP
    stp.rs             STP/RSTP
    mstp.rs            MSTP
    pvst.rs            PVST+
    lacp.rs            LACP
    vtp.rs             VTP
  stovetop/            Frame-level integrity & anomaly detection
    mod.rs             Module root
    config.rs          StovetopConfig — per-check toggles and thresholds
    findings.rs        FindingKind enum, severity, reason formatting
    frame_inspector.rs FrameInspector — pre-dissector hook (runt, oversized, truncation, padding, FCS)
    padding.rs         Ethernet padding extraction, Shannon entropy, non-zero fill detection
    integrity.rs       CRC validation — Ethernet CRC-32, DNP3 CRC-16
  icmpeeker.rs         ICMP anomaly detection — redirects, tunnels, suspicious types
  bilgepump/           Stateful L2 monitoring
    mod.rs             Module root
    config.rs          BilgepumpConfig — thresholds, blessed bindings, whitelists
    state.rs           State table types — MAC/IP bindings, STP root, DHCP server, identity records
    alerts.rs          AlertKind enum, severity, reason formatting
    monitor.rs         BilgepumpMonitor — orchestrates all detectors, engine hook points
    detectors/
      arp.rs           ARP spoofing, gratuitous ARP, ARP flood
      mac.rs           Locally-administered MAC, multicast source, MAC flapping
      vlan.rs          VLAN hopping via double-tagged 802.1Q
      stp.rs           STP root change, unauthorized root claims
      dhcp.rs          Rogue DHCP server, DHCP starvation
      identity.rs      LLDP/CDP identity conflict detection
  engine.rs            DPI engine, session decoders, stovetop + bilgepump integration
  bronze.rs            Bronze v2 event model
  registry.rs          Dissector trait, ProtocolData enum, field structs
  dedup.rs             SHA256-based deduplication
  corpus.rs            ICS defense corpus manifest types and validation
  ffi.rs               C FFI surface (feature-gated, requires `ffi` feature)
  lib.rs               Library root
  main.rs              CLI binary
  bin/
    ics-defense-corpus.rs  Corpus validation binary
benches/
  throughput.rs        Criterion throughput benchmark
corpus/
  ics-defense-manifest.yaml  ICS-Pcaps fixture manifest
```

## Why This Crate Exists

This crate keeps DPI separate from the analyst workbench:

- MarlinSpike can call it as an external Stage 2 parser
- Fathom can embed it directly in Rust-native pipelines
- Other consumers can use JSON or FFI without reimplementing protocol parsing

`marlinspike-dpi` is the reusable packet-analysis core; MarlinSpike is the responder-facing workbench built on top of it.

## License

`marlinspike-dpi` is **dual-licensed**:

- **[AGPL-3.0-or-later](LICENSE)** — for open-source use, internal use within a single organisation, hosted services that offer the source to their users, and any deployment compatible with AGPL's terms.
- **[Commercial licence](LICENSE-COMMERCIAL.md)** — for embedding into proprietary products, vendor integrations, OEM bundles, and SIEM connectors where AGPL's source-disclosure obligations don't fit.

If AGPL works for you, you don't need to do anything — use it freely. For commercial licensing, contact `dpi@erisforge.com`.

Contributions are accepted under [CONTRIBUTING.md](CONTRIBUTING.md)'s dual-licence terms.

Used by:

- [`eris-ot/marlinspike`](https://github.com/eris-ot/marlinspike) — the multi-user OT/ICS analyst workbench (AGPL).
- [`eris-ot/glassmarlin`](https://github.com/eris-ot/glassmarlin) — the single-file desktop edition (AGPL).
