# Parse Depth Matrix

Per-protocol parse depth as of **v1.15.0**. Living doc — update when shipping a depth release.

## Legend

| Mark | Meaning |
|------|---------|
| **Full** | Wire format parsed end-to-end; per-message field extraction; stateful pairing where applicable; ProcessReading/AssetObservation emission for VQT-bearing protocols. |
| **Deep** | Header + per-op fields extracted; pairing usually present; some payload areas may be summarised rather than walked exhaustively. |
| **Shallow** | Header byte parse + light fingerprinting; classification only; no per-op field extraction. |
| **Recognition** | Port + magic-byte fingerprint, traffic-classification ProtocolTransaction only. |
| **Opaque** | Encrypted past handshake (TLS / CredSSP / AEAD / SASL). Hard limit for a passive sensor — improvable only with keys. |
| **Spec-blocked** | Wire format not publicly documented or member-restricted; depth bounded by reverse-engineering work. |

## OT / ICS

| Protocol | Depth | What's parsed | Deferred / blockers |
|----------|-------|---------------|---------------------|
| Modbus/TCP | **Full** | MBAP+PDU, all target FCs, exception codes, register VQT, request/response pairing | — |
| Modbus/UDP | **Full** | Same as TCP variant; LRU pending table per (src,dst,txn_id) | — |
| DNP3 | **Deep** | DLL + transport + application, function codes, source/dest, role inference; CRC-16 validation via stovetop. Typed `ProtocolFields::Dnp3` variant landed in 1.15.0 | Per-object g/var typed fields (point-level) still summarised |
| DNP3-SAv5 | **Deep** | g120 SAv5 object recognition; challenge/reply/aggressive/cert/MAC/update-key naming; g120v7 (Auth Error) high-severity | — |
| IEC 60870-5-104 | **Deep** | APCI I/S/U, ASDU type ID, cause of transmission, IOA; VQT emission | Typed `ProtocolFields::Iec104` variant landed in 1.15.0 |
| IEC 61850 MMS | **Deep** | ISO-on-TCP, COTP, MMS service ID, TSAP, visible strings | Typed `ProtocolFields` variant landed in 1.15.0 |
| IEC 61850 GOOSE | **Deep** | AppID, dataset references | — |
| IEC 61850 SV | **Deep** | AppID, sample data | — |
| S7comm | **Deep** | TPKT/COTP/S7 PDU, ROSCTR, FCs, parameter + data blocks | Typed `ProtocolFields` variant landed in 1.15.0 |
| PROFINET | **Deep** | Frame ID class, DCP service, cyclic IO, alarms | — |
| BACnet/IP | **Deep** | BVLC + NPDU + APDU, confirmed/unconfirmed, device instance | — |
| BACnet/SC | **Shallow** | TLS-handshake recognition (normal case); plaintext BVLC-SC parse for testbench | TLS payload **Opaque** in production |
| EtherNet/IP | **Deep** | Encapsulation commands, session handle, CIP identity | Typed `ProtocolFields::EthernetIp` variant landed in 1.15.0 |
| EtherNet/IP Class 1 I/O | **Deep** | CPF parse, sequence tracking, Run/Idle, sampled (first + every 1000th) | — |
| OPC UA (binary) | **Deep** | Message type/chunk, secure-channel ID, sequence/request IDs; ReadRequest/Response correlation; Variant decode; DataValue VQT | Typed `ProtocolFields::OpcUa` variant landed in 1.15.0 |
| OPC UA PubSub | **Full** | UADP NetworkMessage + DSM (Variant + DataValue → ProcessReading); FILETIME → Unix-micros | RawData encoding (config not on wire); aggregate Variant types; PublishedDataSet config-resolved NodeIds |
| HART-IP | **Deep** | Session-initiate, passthrough commands, device identity, VQT | Typed `ProtocolFields::HartIp` variant landed in 1.15.0 |
| OMRON FINS | **Deep** | FINS header, command codes, memory area R/W | — |
| EtherCAT | **Deep** | Datagram headers, ADP/ADO addressing, working counters | — |
| MRP | **Deep** | MRP_Test/Topology/Link TLVs, domain UUID, ring state | — |
| PRP | **Deep** | Supervision frames, RCT trailer | — |
| PCCC (AB legacy) | **Deep** | Protected Typed Logical Read with TNS pairing; three-address-field decode; VQT | — |
| Sparkplug B | **Full** | Protobuf decode, BIRTH alias resolution, bdSeq supersession, gap-epoch detection, TTL+LRU eviction; VQT; typed `ProtocolFields::Sparkplug` on session-management messages | — |
| IEEE C37.118 synchrophasor | **Full** | CFG-2 per-PMU layout; phasors / freq / dfreq / analogs / digitals → ProcessReading | — |
| CC-Link IE Field | **Recognition** | Port + multicast classification | **Spec-blocked** (member-restricted) |
| CODESYS | **Recognition** | Port-based V2 / V3 / Gateway / Runtime distinction | V2 partly documented; deep parse needs reverse-engineering |
| IO-Link Wireless | **Recognition** | UDP 59152 classification | **Spec-blocked** (constrained spec, niche) |
| Beckhoff ADS | **Deep** | AMS/TCP framing, full AMS header, invoke-ID pairing, AssetObservation per source NetID | Deeper per-command payload extraction |
| GE SRTP | **Deep** | 56-byte header, service request code naming, sequence-number pairing, status propagation | — |
| TriStation | **Shallow** | 4-byte header, command-type + subtype + length; conservative payload skip | **Spec-blocked** (proprietary); deeper parse would risk false positives |
| MELSEC SLMP | **Deep** | 4E binary, command + subcommand naming, serial-number pairing, AssetObservation from Read CPU Model | — |
| Yokogawa Vnet/IP | **Shallow** | Best-effort header per Wireshark dissector; named FC subset | **Spec-blocked** (proprietary) |
| OSIsoft PI | **Recognition** | Port + magic-byte fingerprint; version-string capture | **Spec-blocked** (proprietary) |
| OPC Classic (DA/HDA/AE) | **Shallow** | OPC interface UUIDs in DCE/RPC BIND; AssetObservation per server IP | Endpoint-mapper dynamic-port tracking; OPC method opnums |
| GVCP / GigE Vision | **Deep** | 8-byte header, command naming, DISCOVERY_ACK → AssetObservation with manufacturer/model/version/serial | — |
| CIP Safety | **Shallow** | Network Safety Segment (0x50) detection in Forward_Open paths | Type 1/2/Extended safety-segment internal fields (max_consumer, ping interval, etc.) |
| Modicon UMAS | **Deep** | FC 0x5A sub-functions; Industroyer2 sequence flagged high | — |
| POWERLINK | **Deep** | SoC/PReq/PRes/SoA/ASnd dispatch; ASnd IdentResponse → AssetObservation | — |
| SERCOS III | **Deep** | Telegram-type dispatch; sync-flag transition tracking | Deep Service Channel (partial-public spec) |
| PTPv2 / gPTP | **Deep** | Common 34-byte header; Sync/Delay/Pdelay/Follow/Announce/Signaling/Management dispatch; grandmaster-change anomaly | — |
| Foundation Fieldbus HSE | **Recognition** | Port + magic-byte fingerprint | **Spec-blocked** (FF-588/589 member-restricted) |
| AVTP / IEEE 1722 | **Deep** | 12-byte common header; media sampled (first + every 1000th per stream); ADP ENTITY_AVAILABLE → AssetObservation | — |
| Emerson ROC Plus | **Deep** | 6-byte header + opcode dispatch; control-opcode high anomaly | **Spec-blocked** partially (proprietary; Wireshark-derived) |
| Diameter | **Deep** | 20-byte header + AVP walk; command naming; hop_by_hop pairing | TLS-wrapped (5868) **Opaque** past handshake |

## IT / Infrastructure

| Protocol | Depth | What's parsed | Deferred / blockers |
|----------|-------|---------------|---------------------|
| DNS | **Deep** | RFC 1035 queries + answers, A/AAAA/PTR/TXT/SRV, compression pointers; mDNS device enrichment | — |
| DHCP | **Deep** | BOOTP + options: message type, hostname, vendor class, client ID, server ID, offered/requested IP | — |
| HTTP | **Shallow** | Request line, response status, Content-Type, Content-Length | Header set beyond a few fields; body inspection |
| TLS | **Shallow** | Client Hello SNI, cipher suites, TLS version | Payload **Opaque** past handshake |
| SNMP | **Deep** | BER decode v1/v2c/v3, community string, PDU types, var-binds, sysName/sysDescr/sysObjectID | — |
| SSH | **Shallow** | Banner extraction (protocol version, software, OS hint) | Payload **Opaque** past handshake |
| FTP | **Deep** | Commands (STOR/RETR/USER/QUIT), reply codes, server banner | Active/passive data-channel correlation |
| NTP | **Deep** | Version, mode, stratum, reference ID, root delay/dispersion | — |
| MQTT | **Deep** | CONNECT/PUBLISH/SUBSCRIBE with client_id, username, topic, QoS, retain | MQTT v5 properties; Will fields |
| Syslog | **Deep** | RFC 3164 + RFC 5424 facility, severity, hostname, app, message | — |
| RADIUS | **Deep** | Access-Request/Accept/Reject/Accounting, username, NAS-IP, NAS-Identifier, calling/called station | — |
| ICMP | **Deep** | Type/code, echo id/seq, redirect gateway, timestamp/mask, dest-unreachable codes | — |
| IGMP | **Full** | RFC 2236 + 3376 v1/v2/v3, group + sources + records, float-time decode, multicast topology | — |
| SMB1 | **Recognition** | `\xFF SMB` signature | **Deferred** — legacy, low-value vs. effort |
| SMB2 / SMB3 | **Deep** | MS-SMB2 negotiate/session-setup/tree-connect/create/io/ioctl/close/logoff; MessageId pairing; 10 FSCTLs named (PIPE_TRANSCEIVE high on svcctl/samr/atsvc/drsuapi); NetBIOS framing; compound NextCommand walk; NT-status naming | SMB3 Transform PDUs (0xFD) **Opaque** (encrypted); signature validation |
| Kerberos | **Full** | RFC 4120 AS/TGS/AP/KRB-ERROR with principal/realm/etype/options/timestamps/error-code in the clear | EncryptedData payloads **Opaque**; PA-DATA extensions (FAST, PKINIT) |
| LDAP | **Full** | RFC 4511 bind/search/modify/add/del/compare/abandon/extended/unbind with DN/scope/filter-type/attrs; msgID pairing; StartTLS OID recognised | Full filter-expression traversal; SearchResultEntry attribute values; SASL credential content |
| LDAPS | **Recognition** | Port 636 session marker | TLS payload **Opaque** |
| RDP | **Shallow** | TPKT + X.224 CR/CC; mstshash cookie (note: spoofable); negotiated protocol | Payload **Opaque** past Connection Confirm (CredSSP/TLS) |
| mDNS / WS-Discovery | **Deep** | Full DNS-message parse with compression pointers; SOAP byte-pattern for WS-D Probe/ProbeMatch/Hello/Bye/Resolve | — |
| DCE/RPC | **Deep** | BIND / ALTER_CONTEXT context-list with mixed-endian UUIDs; named interfaces (samr, lsarpc, srvsvc, winreg, atsvc, eventlog, epmapper, svcctl, drsuapi, efsrpc); REQUEST opnum + call-id pairing | Per-interface opnum→method name tables (e.g. `DRSGetNCChanges` for DRSUAPI — DCSync signal) |
| TFTP | **Deep** | RRQ/WRQ/ERROR opcode dispatch; filename + mode; firmware-shape filename → high anomaly | Per-block DATA/ACK (intentionally out of scope) |
| IPsec IKE | **Deep** | IKEv1 + IKEv2 28-byte header; exchange-type naming; SPI extraction; Vendor ID payloads | AUTH onward + ESP encrypted **Opaque** |
| VNC / RFB | **Shallow** | Handshake (server/client ProtocolVersion, security-types, Invalid-with-reason) | Payload **Opaque** post-Security |
| WinRM / WS-Management | **Shallow** | Byte-pattern POST /wsman + SOAP Action URI on 5985 | Port 5986 (TLS) **Opaque**; XML body inspection deferred |
| NetBIOS / NBT | **Deep** | NBNS name service with suffix-byte role inference; NBDS source/dest name + source IP/port | — |
| TACACS+ | **Deep** | 12-byte plaintext header always; AUTHEN START fields extracted when unencrypted-flag set | XOR-obfuscated body **Opaque** without shared secret |
| WireGuard | **Deep** | Type+reserved-zeros sanity; sender/receiver index | Transport payload **Opaque** (ChaCha20-Poly1305) |
| NetFlow / IPFIX | **Full** | v5/v9/IPFIX; **cross-packet template tracking** (1024-entry LRU); 24 IANA IEs named with typed decoding | Options Template *contents* (existence tracked, scope/option-field bodies skipped); PEN enterprise fields skipped |
| QUIC | **Shallow** | Long-header (INITIAL/0-RTT/HANDSHAKE/RETRY/VersNeg): version/DCID/SCID | AEAD payload **Opaque** (SNI/CH extraction would need DCID-derived keys — out of scope) |
| SMTP / SMTPS | **Deep** | Banner + commands + STARTTLS boundary; 465 TLS-from-byte-0 recognition | TLS post-STARTTLS / port-465 **Opaque** |
| OpenVPN | **Deep** | Opcode/key_id 5/3-bit split; all hard-reset variants; Session ID; TCP 2-byte length-prefix reassembly | Encrypted transport **Opaque** |
| SIP / RTP / RTCP | **Deep** | SIP request/response, From/To/Call-ID/CSeq/User-Agent/Server; RTP V=2 header with PT naming; RTCP SR/RR/SDES/BYE/APP | RTP per-SSRC throttling |
| CoAP | **Deep** | 4-byte fixed header; delta-encoded options (Uri-Host/Path/Query, Content-Format); method + response-class naming | CoAPS (5684) **Opaque** past handshake |
| MQTT-SN | **Deep** | Short + extended (3-byte) length variants; full message-type dispatch; FORWARDER_ENCAPSULATION | — |
| AMQP 1.0 | **Deep** | Protocol header preamble; described-type performative dispatch; SASL family | TLS (5671) **Opaque** |
| NTLMSSP | **Deep** | Type1 NEGOTIATE / Type2 CHALLENGE / Type3 AUTHENTICATE in-place scan; domain / username / workstation / server challenge / AV_PAIRs | Cryptographic challenge-response validation (would need cleartext password / NT hash) |
| Diameter | **Deep** | (Listed in OT — telecom/5G AAA) | — |
| RadSec | **Recognition** | TLS-record fingerprint + first-byte classifier | RADIUS payload **Opaque** (TLS) |

## L2 / Link Layer

All link-layer protocols listed in the README are at **Deep** depth — frame parse, full field extraction, AssetObservation/TopologyObservation. No depth gaps.

## Roadmap by leverage

**Highest leverage (next push candidates):**

1. **DCE/RPC opnum→method mapping** — per-interface opnum tables for the named interfaces. DRSUAPI opnum 3 = `DRSGetNCChanges` (the DCSync signal); SAMR opnum 36 = `SamrEnumerateDomainsInSamServer`; etc. Bounded; high defender yield.
2. **OPC Classic endpoint-mapper dynamic-port tracking** — complete the OPC story. Requires DCE/RPC EPM session memory.
3. **CIP Safety Type 1/2/Extended internals** — SIL-3 safety payload decode. CIP Networks Library Volume 5 is purchasable / partially public.
4. **Continue ProtocolFields enum migration** — protocols still on `attributes`-only: MELSEC, BACnet/IP, PROFINET, OMRON FINS, EtherCAT, OPC UA PubSub, ADS, GE SRTP, TriStation, Diameter, and the IT decoder set (DNS, DHCP, HTTP, MQTT, etc.).

**Shipped in 1.15.0:** typed `ProtocolFields` variants for DNP3, IEC 104, S7comm, OPC UA (binary), EtherNet/IP, IEC 61850, HART-IP, Sparkplug B (joining Modbus from 1.3.0).

**Spec-blocked (would need new sources):** CC-Link IE Field, IO-Link Wireless, OSIsoft PI, Vnet/IP deeper, FF HSE deeper, TriStation deeper.

**Hard limits (key-restricted, cannot improve without keys):** TLS payload, RDP CredSSP, VNC post-Security, WinRM 5986, SMB3 Transform PDUs, IKE AUTH+ESP, WireGuard transport, OpenVPN encrypted, SMTPS post-STARTTLS, AMQPS, CoAPS, RadSec.

**Deliberately deferred (low value vs. effort):** SMB1, RTP per-SSRC throttling refinement.
