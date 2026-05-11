# Per-Protocol Decoder Reference

This file consolidates the in-source documentation block (`//!`) at the top of every decoder file in `src/engine/decoders/`. Those modules are crate-private (`pub(crate)`), so this reference is the public-facing equivalent. It's hand-maintained — when a new decoder ships, copy its file-top `//!` block here.

For the high-level summary (port, transport, parsing depth) of every dissector, see the protocol tables in [README.md](../README.md). For Bronze v2 event-shape questions, see [`bronze-v2-schema.md`](./bronze-v2-schema.md).

---

## OT / ICS Decoders

### ab_csp (Allen-Bradley CSP)

CSP is the legacy AB Ethernet protocol for PLC-5E, SLC 5/05, and MicroLogix 1100/1400 controllers. It pre-dates EtherNet/IP and tunnels DH+ (Data Highway Plus) over TCP/2222. Many NA manufacturing sites have not migrated to CIP/EtherNet/IP.

**Protocol documentation:** CSP framing is only partially documented in public sources. The primary reference is the Wireshark dissector `packet-cspv4.c` (`epan/dissectors/`). Field offsets reflect that dissector; where the dissector is ambiguous or contradicts other sources, this implementation makes a best-effort interpretation — flagged with `// BEST-EFFORT:` comments.

### ads (Beckhoff ADS / TwinCAT)

*(No file-top doc comment in source — see commit message for v1.8.0 release notes and Wireshark `packet-ams.c` for wire format.)*

### avtp (AVTP / IEEE 1722-2016)

EtherType 0x22F0. Audio Video Transport Protocol is the wire format for TSN audio-video bridging. Originally automotive (in-vehicle infotainment, ADAS); growing into industrial TSN for camera feeds, audio-over-Ethernet, and other latency-bounded media.

### bacnet

*(No file-top doc comment in source — see `src/dissectors/bacnet.rs` for wire format references.)*

### bacnet_sc (BACnet Secure Connect, ASHRAE 135-2020 Addendum bj)

In production, BACnet/SC traffic is **always TLS-wrapped WebSocket**. A passive sensor cannot see past the TLS layer, so the primary function of this decoder is TLS-session recognition and asset observation on ports 47808 (TCP, reused from BACnet/IP) and 4843 (BACnet/SC hub-direct, some deployments).

Plaintext BVLC-SC header parsing is included for completeness — it applies only to testbench packet captures or the rare non-WSS deployment. In those cases the decoder parses the 4-byte BVLC-SC fixed header and optional variable-length MAC fields and emits per-frame `ProtocolTransaction` events.

### cip_safety (CIP Safety on EtherNet/IP)

Detects CIP Safety by recognizing Network Safety Segment (0x50) in Forward_Open connection paths. Safety segment internal fields (Type 1/2/Extended, max_consumer, ping interval) are not parsed in this version — detection is the v1 scope.

Shares TCP port 44818 with the EtherNet/IP decoder. Each decoder gets its own copy of the stream; this one ignores everything except CIP service 0x54 (Forward_Open) and 0x5B (Large_Forward_Open) that carry segment type 0x50 in their connection path.

### dnp3

*(No file-top doc comment in source — see `src/dissectors/dnp3.rs` for DNP3 wire-format and CRC validation.)*

### dnp3_sav5 (DNP3 Secure Authentication v5, IEEE 1815-2012)

Recognition-only layer, co-registered on TCP/20000 alongside the main DNP3 decoder (`ot/dnp3.rs`). Each decoder receives its own copy of the stream; this one specifically looks for Object Group 120 (g120) SAv5 authentication messages defined in IEEE 1815-2012.

### eip_io (EtherNet/IP Class 1 cyclic I/O, UDP/2222 implicit messaging)

The sibling `ethernet_ip` decoder (TCP/44818) handles explicit messaging. Class 1 implicit (cyclic) I/O connections carry servo positions, drive commands, and safety I/O at 1–10 ms scan rates over UDP/2222 with no EIP encapsulation header — just a raw CPF packet on the wire.

### ethercat

*(No file-top doc comment in source — EtherType 0x88A4.)*

### ethernet_ip

*(No file-top doc comment in source — TCP 44818 explicit messaging; see `src/dissectors/ethernet_ip.rs` and the CIP helpers in `ot/ethernet_ip.rs`.)*

### ff_hse (Foundation Fieldbus HSE)

**IMPORTANT — SPEC STATUS:** Foundation Fieldbus HSE wire spec (FF-588/FF-589) is member-restricted. This decoder is honest port-based recognition + magic-byte fingerprinting + AssetObservation. Deep FDA / FMS parsing is not feasible without spec access.

- Ports: 1089 (Annunciation), 1090 (FMS), 1091 (System Management).
- Magic strings searched in first 16 bytes: `"FOUNDATION"`, `"FF-HSE"`.
- Header layout (Wireshark `packet-fcp.c` reference): byte 0 = version, byte 1 = message_type, bytes 2..4 = declared_length BE, bytes 4+ = opaque FDA payload.

### ge_srtp (GE SRTP / Service Request Transport Protocol)

Port 18245/TCP. GE PACSystems and Series 90 (90-30, 90-70) PLCs. Wire format: 56-byte fixed header + optional variable payload. References: Wireshark `epan/dissectors/packet-gesrtp.c`, Talos 2018 SRTP research, GE GFK-2224 (partial public release).

### gvcp (GVCP / GigE Vision Control Protocol)

UDP 3956. GigE Vision Standard 2.x §14–16. Command packets begin with key_code 0x42; acknowledge packets begin with a status u16 BE (0x0000 = success).

### hart_ip

*(No file-top doc comment in source — TCP/UDP 5094; see `src/dissectors/hart_ip.rs`.)*

### iec104

*(No file-top doc comment in source — IEC 60870-5-104 on TCP 2404.)*

### iec61850

*(No file-top doc comment in source — MMS on TCP 102; GOOSE EtherType 0x88B8; SV EtherType 0x88BA.)*

### melsec (MELSEC SLMP — Seamless Message Protocol)

Targets Mitsubishi iQ-R / iQ-F / Q series PLCs on TCP port 5007.

**Subheader byte-order note:** the spec documents the subheader as a u16 LE value, so `[0x54, 0x00]` on the wire reads as `0x0054` in code (request), and `[0xD4, 0x00]` as `0x00D4` (response). SLMP is little-endian throughout, which surprises readers expecting big-endian network order.

### modbus

*(No file-top doc comment in source — Modbus/TCP on 502; see `src/dissectors/modbus.rs` for FC dispatch and `ModbusPdu` typed fields.)*

### modbus_udp (Modbus over UDP)

Sibling to the TCP variant in `modbus.rs`. Modbus/UDP carries one Modbus/TCP-style MBAP+PDU frame per datagram (no stream reassembly). Found on legacy RTUs and resource-constrained embedded controllers. Wire port is UDP/502.

- MBAP (7 B BE): `[txn_id:u16][proto_id:u16=0][length:u16][unit_id:u8]`
- PDU: `[fc:u8][function-specific bytes…]`
- FC 0x5A (UMAS) is intentionally skipped — handled by `umas.rs` on TCP.
- Pairing is keyed by `(src_ip, dst_ip, transaction_id)` with a 256-entry LRU pending map; UDP loss is common so unpaired halves emit `request_only` / `response_only` on flush.

### omron_fins

*(No file-top doc comment in source — OMRON FINS on TCP/UDP 9600.)*

### opc_classic (OPC DA / HDA / AE)

Layers OPC-specific semantics on top of the DCE/RPC BIND and ALTER_CONTEXT PDU shapes. When a BIND carried on TCP/135 contains at least one recognized OPC Classic interface UUID, this decoder emits:

- A `ProtocolTransaction` annotating the OPC family and interface names.
- An `AssetObservation` for the destination (server-side) IP.
- A `ParseAnomaly` (severity=`"low"`) for a malformed `p_context_elem` list.

If the BIND carries no OPC UUID no event is emitted; the generic DCE/RPC decoder handles that case.

### opc_ua

*(No file-top doc comment in source — TCP 4840, 12001; see `src/dissectors/opc_ua.rs` and the VQT pipeline in `src/opc_ua.rs`.)*

### opc_ua_pubsub (OPC UA PubSub — UADP over UDP)

Decodes UADP NetworkMessage headers (Part 14 §7.2) arriving on UDP 4840. Emits one `ProtocolTransaction` per datagram and a `TopologyObservation` per unique publisher_id seen on the session. Dataset payload decoding (DataSetMessages) is deferred to a future phase.

### osi_pi (OSIsoft PI Server / PI Web API)

OSIsoft PI Server protocol is proprietary and undocumented. This decoder does port-based recognition plus byte-pattern fingerprinting of known magic strings. Deep PDU parsing is not feasible without vendor documentation.

- Ports: 5450 (PI Net Manager), 5460–5462 (PI Connector / AF variants).
- Magic strings searched in first 256 bytes: `"PINETMGR"`, `"PISystem"`, `"PI-API"`, `"AFServer"`.
- Version pattern in first 512 bytes: `"3.4.<digits>.<digits>"`.

Emits one ProtocolTransaction + one AssetObservation per session/server on first matching chunk. Subsequent chunks are silently skipped.

### powerlink (Ethernet POWERLINK — EPSG DS 301 V1.5)

POWERLINK is a real-time Ethernet motion-control protocol used in European machine-automation builds (B&R Automation, Bachmann, Lenze, Hilscher). It runs directly over Ethernet — EtherType 0x88AB — with no IP layer.

### profinet

*(No file-top doc comment in source — UDP 34964 + EtherType 0x8892.)*

### ptp (PTPv2 / gPTP — IEEE 1588-2008 / IEEE 802.1AS)

EtherType 0x88F7, UDP 319/320. Common 34-byte header parse; Sync / Delay_Req / Pdelay / Follow_Up / Announce / Signaling / Management dispatch. Announce extracts grandmasterClockIdentity + clockClass / accuracy / priority1 / priority2 / stepsRemoved / timeSource. ParseAnomaly on grandmaster change within a domain.

### roc_plus (Emerson ROC Plus)

Port 4000/TCP. ROC Plus is Emerson's gas SCADA telemetry protocol used on RTUs at compressor stations, pipeline meters, and custody-transfer points across North American oil & gas infrastructure.

**Spec note — partially proprietary.** The ROC Plus specification is Emerson-proprietary. This implementation is derived from the Wireshark dissector `epan/dissectors/packet-rocplus.c` (GPL-2.0), publicly available Emerson application notes, and field observation. Opcode semantics are best-effort; unknown opcodes are emitted with a `"low"` anomaly event.

### s7comm

*(No file-top doc comment in source — TPKT/COTP/S7 on TCP 102.)*

### sercos (SERCOS III — IEC 61491 / IEC 61784-2 CPF 3)

EtherType 0x88CD. Spec is partial-public; this decoder does recognition + telegram-type identification + slot index. Deep Service Channel (SVC) parsing is future work.

Wire format (payload after Ethernet header):

```
[0] bits 0..6 = MST Cycle Count, bit 7 = Sync Flag
[1] bits 0..2 = Telegram Type (MST/MDT/AT/NRT/HotPlug/reserved)
[2..4] Slot Index u16 LE  [4..6] Data Length u16 LE  [6..] payload
```

Sampling: first per (session, type) → `_first` event; every 1000th → `_periodic`; sync-flag set→clear → `sercos_sync_lost`. Reference: `packet-sercosiii.c`.

### tristation (Schneider Electric / Triconex SIS)

Covers Tricon, Trident, and Tri-GP controllers. TriStation is a proprietary, undocumented protocol. This parser is built from publicly available reverse-engineering research:

- FireEye/Mandiant: "TRITON: The First ICS Malware Designed to Attack Safety Instrumented Systems" (2017) — function code names and 0x70 significance.
- Nozomi Networks: "Triton/Trisis ICS Malware Analysis" (2017/2018) — header layout (command_type byte 0, subtype byte 1, length bytes 2-3 LE).
- Dragos: "TRISIS Malware Analysis of Safety Instrumented System Targeting" (2017) — supplementary function code identification.

**No official Schneider/Triconex vendor specification is publicly available.** All field names and semantics are best-effort from the sources above. Intentionally conservative: only decodes the header (4 bytes) and records observed function codes — payload bytes are not further interpreted to avoid false positives from protocol ambiguity.

### umas (Modicon UMAS — Unified Messaging Application Services)

UMAS is Schneider Electric's proprietary management protocol encapsulated inside Modbus/TCP function code 0x5A (90). Used for engineering operations on Modicon M340, M580, and Quantum PLCs. Involved in the 2022 Industroyer2 attacks against Ukrainian power infrastructure.

Protocol is partially reverse-engineered. Public sources: NCC Group (2021), Claroty (2021), Forescout Research Labs (2022), Nozomi Networks (2023). No official Schneider specification is publicly available.

### vnet_ip (Yokogawa Vnet/IP)

UDP port 32768, "Vnet" control plane.

**IMPORTANT — SPEC STATUS:** The Vnet/IP wire format is **not publicly documented** by Yokogawa. This decoder is **best-effort recognition** based on the Wireshark open-source dissector (`epan/dissectors/packet-vnetip.c`), a small number of CVE write-ups, and passive traffic analysis. The function-code subset named here (0x0001–0x0004, 0x0010, 0x0020) is the only publicly referenced subset; all other codes are emitted as `vnet_unknown_0x<hex>` so embedders can assign names as field knowledge improves. **Do not treat any field offset or byte-order assumption below as authoritative.** Deploy only for passive observation; never use for control decisions.

---

## IT / Infrastructure Decoders

### amqp (AMQP 1.0 — OASIS standard)

Covers plaintext port 5672 and TLS-wrapped port 5671. Used in OT for: OPC UA PubSub broker fan-out, Azure IoT Hub, AWS IoT Core, Solace appliances.

### coap (CoAP — RFC 7252)

UDP port 5683 (plaintext) and 5684 (DTLS).

- Port 5683: parse the 4-byte fixed header, walk delta-encoded options, emit a ProtocolTransaction per message.
- Port 5684 (CoAPS / DTLS): inspect the record-type byte but do not decrypt; emit one ProtocolTransaction per session noting the payload is opaque.

### dcerpc (DCE/RPC — MS-RPCE / DCE 1.1)

Decodes BIND/ALTER_CONTEXT and REQUEST PDUs over TCP, pairing each with its ACK/response by call_id. Extracts interface UUIDs from `p_context_elem` arrays and resolves them to well-known names (samr, lsarpc, srvsvc, winreg, …).

### diameter (Diameter — RFC 6733)

AAA protocol used in telecom/5G OT.

Header (20 bytes, all big-endian):

```
byte 0: version(=1) | bytes 1..4: message_length u24 BE (incl. header)
byte 4: flags(R=b7,P=b6,E=b5,T=b4) | bytes 5..8: command_code u24 BE
bytes 8..12: application_id u32 | 12..16: hop_by_hop_id u32 | 16..20: end_to_end_id u32
```

AVP (4-byte-padded): `code u32 | flags u8 | length u24 BE (incl. header) | [vendor_id u32 — only when V flag set] | data bytes`.

### discovery (mDNS — RFC 6762, WS-Discovery — OASIS 1.1)

Both protocols are high-yield for passive OT asset identification: HMIs, cameras, printers, and embedded controllers announce themselves via mDNS and WS-Discovery on every OT subnet that hasn't explicitly blocked multicast.

Routing: destination port 5353 → mDNS, 3702 → WS-Discovery.

WS-Discovery parsing is intentionally byte-pattern based — NOT a real XML parser. We search for fixed byte sequences (tag boundaries) to extract message type, Types, and XAddrs. This is sufficient for passive asset identification and avoids any XML dependency.

### ike (IKEv1 — RFC 2409, IKEv2 — RFC 7296)

UDP 500 (plain IKE) and 4500 (NAT-T).

The SA negotiation is in the clear; only AUTH onward and ESP are encrypted. Port 4500 NAT-T: four zero-bytes prefix an IKE message; a non-zero first byte means ESP — skip those silently.

### it_app (DNS, DHCP, SNMP, HTTP, TLS, MQTT)

Application-protocol `SessionDecoder` impls — DNS, DHCP, SNMP, HTTP, TLS, MQTT. Includes per-protocol helpers (DNS payload extraction, DHCP status mapping, SNMP status mapping, TLS Client Hello parser) and the MQTT-payload-decoder fanout context builder used to dispatch Sparkplug B and other future MQTT-payload protocols.

### it_basic (NTP, Syslog, FTP, SSH, RADIUS, ICMP)

Simple IT-protocol `SessionDecoder` impls — port-based decoders that emit one ProtocolTransaction (and sometimes an AssetObservation) per parsed packet.

### link_layer (ARP, LLDP, CDP, STP, RSTP, MSTP, PVST+, LACP, PRP, MRP, VTP)

Layer-2 / link-layer `SessionDecoder` impls. Each is a small, mostly-self-contained decoder; grouped because they share the L2 frame surface and have minimal interaction beyond emitting AssetObservation + TopologyObservation events.

### mqtt_sn (MQTT-SN — Sensor Networks)

The constrained-network publish/subscribe protocol for low-power OT field devices: ZigBee/IPv6 bridges, battery sensors, LPWAN nodes. Runs over UDP with much smaller frames than full MQTT.

Reference: MQTT-SN Specification Version 1.2 (MQTT.org, 2013-11-14).

### netbios (NetBIOS / NBT — NBNS UDP 137, NBDS UDP 138)

NetBIOS Name Service leaks hostnames, workgroup names, domain names, and browser-service roles on virtually every OT/legacy Windows VLAN. This decoder surfaces that data as AssetObservation events, making it a reliable passive asset-identification source even without any active scanning.

References: RFC 1001 (concepts), RFC 1002 (wire format).

### netflow (NetFlow v5 / v9 + IPFIX v10)

Listens on the conventional flow-export UDP ports and emits:

- `ProtocolTransaction` — one per datagram, carrying header-level metadata.
- `AssetObservation` — for the exporter (src IP) and collector (dst IP), deduplicated per session via `HashSet`.
- `ParseAnomaly` — for unknown versions or wire-length mismatches.

Template tracking across packets is intentionally not implemented. NetFlow v9 Data FlowSets reference template IDs advertised in Template FlowSets, which may arrive in earlier datagrams or on a different UDP 5-tuple entirely. Stateful correlation would require a shared, session-keyed store, is expensive under lock contention, and is outside the scope of passive header-level visibility. The decoder emits `flowset_ids` as-seen so downstream consumers can determine whether a collector received its templates. Full template correlation is a Silver-tier enrichment concern, not a Bronze DPI concern.

### ntlmssp (NTLMSSP — embedded-protocol scanner)

NTLMSSP is not a standalone wire protocol. It is an authentication blob embedded inside higher-layer protocols:

- SMB Session Setup (ports 139, 445)
- HTTP `WWW-Authenticate: Negotiate` / `Authorization: Negotiate` (80, 8080)
- DCE/RPC AUTH3 (port 135)
- WinRM over HTTP (port 5985)

This decoder scans stream chunks for the `NTLMSSP\0` magic and parses Type1/Type2/Type3 messages in-place without speaking the outer framing protocol. NTLM-relay is the dominant AD attack on OT/IT-bridge networks; recognising these flows surfaces relay targets and credential exposure.

### openvpn (OpenVPN)

Control-channel handshake visibility for OT/ICS remote-access tunnels.

Every OpenVPN packet begins with a 1-byte opcode/key_id field packed as:

```
bits 7..3 (high 5 bits) = opcode (>> 3)
bits 2..0 (low  3 bits) = key_id (& 0x07)
```

Bytes 1..=8 carry the 8-byte sender Session ID. TCP transport prefixes each packet with a 2-byte big-endian length header; this decoder buffers per-session bytes and extracts complete packets before parsing.

### quic (QUIC — RFC 9000)

Long-header recognition. QUIC INITIAL payload is AEAD-encrypted with keys derived from DCID. We do NOT decrypt. SNI/ClientHello extraction is intentionally out of scope.

Parsed in the clear: version, DCID, SCID, packet type, supported versions (Version Negotiation), and token length estimate (Retry). Short-header packets are recognized but not parsed — DCID length is connection-context-dependent without state tracking.

### radsec (RadSec — RFC 6614)

RADIUS over TLS. Payload is encrypted; this decoder is recognition + TLS-handshake-byte fingerprinting + AssetObservation only.

Without TLS session keys a passive sensor cannot read RADIUS attributes. The decoder fingerprints the TLS record type from the first byte of each new session on TCP port 2083 and records the server endpoint as an asset. The STARTTLS upgrade variant (RFC 6614 §2.2) is out of scope.

### rdp (Microsoft Remote Desktop Protocol — MS-RDPBCGR §5)

Passive DPI for OT/ICS pivot detection. RDP is the dominant lateral-movement vector on plant networks: jump hosts and HMI workstations almost universally expose port 3389. The negotiation handshake (CR + CC) is cleartext; once the Connection Confirm arrives, traffic becomes opaque TLS/CredSSP.

This decoder targets only those first two TPKT/X.224 PDUs. After the first CR/CC pair is resolved it stops emitting on the session.

Wire layers (outermost → innermost): TPKT (RFC 1006, 4 B) → X.224 Class 0 TPDU → optional RDP Negotiation IE.

### sip_rtp (SIP — RFC 3261, RTP/RTCP — RFC 3550)

SIP and RTP share UDP carriage but are byte-incompatible at byte 0:

- SIP is ASCII text; every valid SIP message begins with a letter (request method: I, R, A, C, B, O, S, N, M, U, P) or 'S' from "SIP/2.0" responses. High bit is always 0 — ASCII range.
- RTP/RTCP version-2 packets have bits 7-6 of byte 0 = `10` (binary), i.e. `byte & 0xC0 == 0x80`. That bit pattern is never valid ASCII.

We therefore dispatch purely on the first byte rather than port — this lets the decoder handle SIP over ephemeral ports and RTP sessions that the SDP negotiated to ports other than 5004/5005, as long as they land in our interest window. Port 5060 is registered for SIP; 5004/5005 for canonical RTP/RTCP defaults. Real RTP media lands on negotiated ephemeral ports that the engine may route here via wildcard matching in future.

### smtp (SMTP / SMTPS — RFC 5321)

- Port 25 / 587: plaintext ESMTP. Parses server banners and client commands.
- Port 465: SMTPS — TLS from byte 1. Emits `smtp_tls_session` once per session and an `AssetObservation` for the server; no command parsing.

After a STARTTLS command is acknowledged by the server with a 220 reply the session flips opaque and further bytes are silently dropped. QUIT similarly halts further emission.

### synchrophasor (IEEE C37.118)

Synchrophasor `SessionDecoder` wrapper. The wire-format parsing and stateful CFG/data-frame logic live in `crate::synchrophasor`; this module just bridges that to the engine's dispatch surface.

### tacacs (TACACS+ — RFC 8907)

Port 49/TCP. Body obfuscation is XOR-based, not encryption: the body is XORed with a pad derived from `MD5(session_id || secret || version || seq_no || ...)`. Without the shared secret the pad is unrecoverable; obfuscated bodies are treated as opaque. The 12-byte header is always plaintext and yields: `session_id`, packet type, sequence number, and the unencrypted-flag bit. When `TAC_PLUS_UNENCRYPTED_FLAG` (bit 0 of flags) is set the body is cleartext; for AUTHEN START packets we extract user, port, rem_addr, etc.

### tftp (TFTP — RFC 1350)

UDP port 69. Catches RRQ/WRQ request openers on port 69. Per-block DATA/ACK noise on ephemeral ports is intentionally out of scope; those are not visible here and would flood telemetry with no diagnostic value.

### vnc (VNC / RFB — RFC 6143)

Passive DPI for OT/ICS Linux HMI and legacy industrial gear visibility. VNC is the dominant Linux-side remote-access protocol (counterpart to RDP). The RFB handshake is pre-encryption and high-value: ProtocolVersion banners and SecurityTypes list are always cleartext regardless of chosen auth.

### winrm (WinRM / WS-Management)

WinRM rides plain HTTP on TCP/5985 and TLS-wrapped HTTP on TCP/5986. This decoder byte-pattern scans TCP stream chunks — it does NOT duplicate the HTTP dissector and does NOT attempt real XML parsing. All SOAP element extraction is byte-pattern search only; comments call this out explicitly.

### wireguard (WireGuard — Donenfeld 2017)

Recognition fingerprint: bytes 0..4 = type (1–4) + three mandatory zeros. Non-zero reserved bytes → low-severity ParseAnomaly, not parsed as WireGuard.

| Type | Name | Total bytes |
|------|------|-------------|
| 0x01 | Handshake Initiation | 148 |
| 0x02 | Handshake Response | 92 |
| 0x03 | Cookie Reply | 64 |
| 0x04 | Transport Data | ≥ 32 |
