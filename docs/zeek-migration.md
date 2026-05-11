# Migrating from Zeek to marlinspike-dpi Zeek output

This guide is for operators running Zeek (with or without the `zeek/packages/icsnpp-*` plugins)
who want deeper OT/ICS protocol coverage without rebuilding their dashboards, alerting rules,
or downstream SIEM pipelines.

---

## 1. Why migrate

Zeek is excellent for IT protocol analysis and decent for OT basics via the ICSNPP package set.
marlinspike-dpi complements it in three ways:

| Dimension | Zeek + ICSNPP | marlinspike-dpi |
|---|---|---|
| Modbus / DNP3 | Function code + exception | Function code, exception, start\_addr, qty, values\_count, typed PDU fields |
| S7comm | ICSNPP optional | Native: ROSCTR, function name, area, error codes |
| OPC UA Binary | ICSNPP optional | Native: message type, secure channel, service name/NodeId |
| IEC 61850 (GOOSE/SV/MMS) | ICSNPP optional | Native: sub-protocol, APPID, stNum, sqNum, test bit |
| IEC 104 | ICSNPP optional | Native: APCI type, ASDU type, COT, IOA addressing |
| HART-IP | No | Native: message type, pass-through command, device status |
| EtherNet/IP + CIP | ICSNPP optional | Native: encap command, CIP service, class/instance, PCCC |
| Sparkplug B | No | Native: BIRTH/DEATH/DATA/CMD, group/node/device topology |
| Synchrophasor (C37.118) | No | Native: per-PMU per-channel typed values |
| Output format | TSV or JSON Streaming | JSON Streaming only (Zeek 4.x+ compatible) |
| Live capture | Yes (built in) | No — PCAP/PCAPNG file input only |
| Scripting DSL | Yes (Zeek Script) | No |

**The migration path** keeps your existing Zeek pipeline intact for live capture and IT
protocols while adding marlinspike-dpi in parallel (or as a file-replay replacement) for
offline/forensic PCAP analysis and OT-deep coverage.

---

## 2. What we map natively

The `--format zeek` flag emits JSON Streaming Log rows with a `_path` field that matches the
Zeek log name. Consumers can route by `_path` with the same logic they use for native Zeek.

| `_path` | Trigger | Key Zeek-compatible columns |
|---|---|---|
| `conn` | Every ProtocolTransaction (one per session\_key, deduped) | `ts`, `uid`, `id.orig_h`, `id.orig_p`, `id.resp_h`, `id.resp_p`, `proto`, `service`, `orig_bytes`, `conn_state`, `orig_pkts` |
| `dns` | protocol == "dns" | `query`, `qtype_name`, `rcode_name`, `answers`, `TTLs` |
| `http` | protocol == "http" | `method`, `host`, `uri`, `status_code`, `status_msg`, `user_agent` |
| `ssl` | protocol == "ssl" or "tls" | `version`, `cipher`, `server_name`, `established` |
| `ssh` | protocol == "ssh" | `version`, `auth_success`, `client`, `server` |
| `modbus` | protocol == "modbus" | `func`, `exception` + extras: `start_addr`, `qty`, `values_count` |
| `dnp3` | protocol == "dnp3" | `fc_request`, `fc_reply`, `iin` + extras: `src_addr`, `dst_addr`, `object_groups` |
| `smb_files` | protocol starts with "smb2", file op | `action`, `name`, `size`, `times.modified` |
| `smb_mapping` | protocol starts with "smb2", tree/session op | `path`, `share_type`, `native_file_system` |
| `kerberos` | protocol == "kerberos" | `request_type`, `client`, `service`, `success`, `error_msg`, `forwardable`, `renewable` |
| `ldap` | protocol == "ldap" | `operation`, `object`, `search_base_object`, `search_filter`, `result_code`, `diagnostic_message` |
| `dhcp` | protocol == "dhcp" | `mac`, `host_name`, `requested_addr`, `assigned_addr`, `msg_type` |
| `ntp` | protocol == "ntp" | `version`, `mode`, `stratum`, `poll` |
| `snmp` | protocol == "snmp" | `version`, `community`, `get_requests`, `set_requests` |
| `rdp` | protocol == "rdp" | `cookie`, `result`, `security_protocol`, `keyboard_layout`, `client_build` |
| `software` | AssetObservation | `host`, `software_type`, `name`, `version.major`, `protocols` |
| `weird` | ParseAnomaly | `name`, `addl`, `notice`, `peer` |

### conn UID

We generate a Zeek-compatible 18-character base62 UID deterministically from the
`session_key` (4-tuple hash). The **same flow always gets the same UID** across runs of the
same PCAP, so you can correlate `conn.log` rows with `modbus.log` / `dns.log` rows in your
SIEM without a join key problem.

---

## 3. What's new — the `ics` log type

Protocols that have no native Zeek log type are emitted as `_path: "ics"` rows. This is our
primary added value over Zeek: typed, structured coverage for ICS protocols that Zeek has no
equivalent for even with ICSNPP.

```json
{
  "_path": "ics",
  "_write_ts": "2026-05-11T14:23:01.123456Z",
  "_system_name": "marlinspike-dpi",
  "ts": "2026-05-11T14:23:01.123456Z",
  "uid": "CxUFtB4pM2nRqKaW7y",
  "id.orig_h": "192.168.1.10",
  "id.orig_p": 49200,
  "id.resp_h": "192.168.1.1",
  "id.resp_p": 102,
  "protocol": "s7comm",
  "operation": "read_var",
  "status": "ok",
  "pf_protocol": "s7comm",
  "pf_fields": { "rosctr": 1, "rosctr_name": "job", "function_code": 4, "function_name": "ReadVar", ... }
}
```

Protocols emitted as `ics`:

| Protocol | Port(s) | Notes |
|---|---|---|
| S7comm | TCP/102 | ROSCTR, function code, PDU ref, area, error class/code |
| OPC UA Binary | TCP/4840, 12001 | Message type, chunk type, secure channel, service name/NodeId |
| IEC 61850 MMS | TCP/102 | MMS service, invoke-ID, visible string |
| IEC 61850 GOOSE | Ethernet 0x88B8 | APPID, dataset ref, stNum, sqNum, test bit |
| IEC 61850 SV | Ethernet 0x88BA | APPID, smpCnt, smpSynch |
| IEC 104 | TCP/2404 | APCI type, ASDU type, COT, originator/common/IOA addressing |
| EtherNet/IP | TCP/44818, UDP/44818 | EIP encap command, CIP service, class/instance/attribute |
| HART-IP | TCP/5094, UDP/5094 | Message type/ID, pass-through command, device status |
| Sparkplug B | TCP/1883 (MQTT) | BIRTH/DEATH/DATA/CMD, group/node/device IDs, bdseq/seq |
| FINS | UDP/9600 | Omron FINS command/response |
| PROFINET | Ethernet 0x8892 | Service ID, block type |
| BACnet | UDP/47808 | Service choice, APDU type |
| MQTT | TCP/1883 | Topic, QoS, retain |
| CoAP | UDP/5683 | Method, URI, response code |
| Synchrophasor | TCP/4712, UDP/4713 | Per-PMU per-channel typed values |

In your log shipper (Filebeat, Vector, Cribl, etc.), route `_path == "ics"` to a dedicated
index or stream — this data has no Zeek equivalent to merge with, so keep it separate.

---

## 4. Drop-in replacement steps

### Step 1: Install marlinspike-dpi

```bash
# Via cargo
cargo install --git https://github.com/riverman-io/marlinspike-dpi marlinspike-dpi

# Or via Docker
docker pull ghcr.io/riverman-io/marlinspike-dpi:latest
```

### Step 2: Replace zeek -r with marlinspike-dpi --format zeek

```bash
# Before
zeek -r capture.pcap

# After — single NDJSON stream to stdout
marlinspike-dpi --input capture.pcap --format zeek

# Write to file
marlinspike-dpi --input capture.pcap --format zeek --output zeek.ndjson

# Docker
docker run --rm -v "$(pwd)":/data ghcr.io/riverman-io/marlinspike-dpi \
  --input /data/capture.pcap --format zeek > zeek.ndjson
```

### Step 3: Point your log shipper at the new output

The NDJSON stream is a single file/stream; your shipper routes by `_path`:

**Filebeat example:**

```yaml
filebeat.inputs:
  - type: log
    paths: ["/data/zeek.ndjson"]
    json.keys_under_root: true
    json.message_key: _path

processors:
  - add_fields:
      fields:
        source: marlinspike-dpi
```

**Vector example (route by _path):**

```toml
[sources.zeek_ndjson]
type = "file"
include = ["/data/zeek.ndjson"]
data_dir = "/var/lib/vector"

[transforms.route_zeek]
type = "route"
inputs = ["zeek_ndjson"]
route.conn    = '._path == "conn"'
route.dns     = '._path == "dns"'
route.modbus  = '._path == "modbus"'
route.ics     = '._path == "ics"'
```

**Splunk HEC:** index by `_path` using a transform that maps `_path` to `sourcetype`:

```
TRANSFORMS-zeek_sourcetype = zeek_path_to_sourcetype
[zeek_path_to_sourcetype]
REGEX = "_path":"(\w+)"
FORMAT = sourcetype::zeek_$1
DEST_KEY = MetaData:Sourcetype
```

---

## 5. Schema differences

### Where we are stricter

- **Timestamps** are always RFC 3339 with microsecond precision (`2026-05-11T14:23:01.123456Z`).
  Native Zeek uses epoch float (`1747000000.123456`). If your pipeline parses the `ts` field
  as a float, update your parsing to ISO 8601.
- **UIDs** are deterministic (same PCAP replay = same UIDs). Zeek UIDs are random per session.

### Where we are looser

- `conn_state` is inferred from the Bronze transaction status, not from the full TCP state
  machine. You will see `SF` (success), `RSTR` (reset), `S0` (timeout), `REJ` (rejected),
  or `OTH` (other) — not the full Zeek conn_state alphabet (`S1`, `S2`, `SF`, `RSTO`, etc.).
- `resp_bytes` on `conn` rows is always `0`. Bronze's `bytes_count` is the total for the
  session; we do not have a per-direction byte split. Use `orig_bytes` for total session bytes.
- The `ssl` log omits certificate chain fields (`cert_chain_fuids`, `validation_status`).
  marlinspike-dpi does not extract X.509 certificates from the TLS handshake in this release.
- The `http` log omits `request_body_len` / `response_body_len` and `orig_fuids` / `resp_fuids`.
  File extraction is handled via `ExtractedArtifact` events in the Bronze output; use
  `--format bronze` to access them.

### What's missing vs. native Zeek

| Native Zeek feature | Status in marlinspike-dpi |
|---|---|
| Live capture (zeekctl) | Not supported — PCAP/PCAPNG file input only |
| Zeek scripting DSL | Not supported — use Bronze event API or output renderers |
| x509.log / files.log | Not in Zeek output format; artifacts in Bronze JSON |
| pe.log / ftp.log / irc.log | Not mapped (low OT relevance) — available in Bronze |
| notice.log | Partial — `weird.log` `notice: true` flags high/critical anomalies |
| Multiple log files on disk | Not supported — single NDJSON stream to stdout or one file |
| conn.log `history` field | Not implemented |

### Common migration gotchas

1. **Dashboard UID joins**: If your dashboards join `conn.log` and `modbus.log` on `uid`,
   this works as-is — UIDs are consistent within a single `render_many` call.

2. **Kibana index patterns**: The single-stream NDJSON means all log types land in one index.
   Add `_path` as a keyword field and use it as a filter instead of separate indices. Or use
   an ingest pipeline to route to separate indices by `_path`.

3. **Zeek TSV consumers**: We emit JSON only. If you have consumers reading Zeek TSV (`.log`
   files with `#fields` headers), they need to switch to JSON mode. Zeek 4.x+ supports
   `LogAscii::use_json = T` for parity. No TSV output is planned for marlinspike-dpi.

4. **`_write_ts` vs `ts`**: Both fields carry the same timestamp. `_write_ts` is the Zeek
   JSON Streaming convention for "when was this row written". Use `ts` for event timing in
   queries (consistent with native Zeek behaviour).
