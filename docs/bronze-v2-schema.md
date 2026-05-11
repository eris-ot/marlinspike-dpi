# Bronze v2 Event Schema Reference

Bronze v2 is the canonical event model emitted by `marlinspike-dpi`. Every event is a `BronzeEvent` wrapping a metadata `EventEnvelope` and exactly one of six tagged `BronzeEventFamily` variants.

The hot path uses the native Rust types in [`src/bronze.rs`](../src/bronze.rs); JSON is produced via `serde_json` for the CLI surface and at the FFI boundary. Protobuf is only used at the Historian boundary downstream — `marlinspike-dpi` itself has no protobuf dependency.

Schema version constant: `BRONZE_SCHEMA_VERSION = "v2"` (also stamped into every `BronzeEvent.schema_version`).

---

## Top-level event

```rust
pub struct BronzeEvent {
    pub event_id: String,
    pub capture_id: String,
    pub schema_version: String,
    pub envelope: EventEnvelope,
    pub family: BronzeEventFamily,
}
```

| Field | Type | Notes |
|-------|------|-------|
| `event_id` | `String` | Stable per-event identifier, deterministic from envelope + family payload. |
| `capture_id` | `String` | Caller-supplied identifier passed into `DpiEngine::process_capture` / `SegmentMeta::new`. |
| `schema_version` | `String` | Always `"v2"` for this release. |
| `envelope` | `EventEnvelope` | Packet metadata. See below. |
| `family` | `BronzeEventFamily` | Tagged enum, one of six variants. See below. |

`BronzeEventFamily` is serialized as `{ "<family_snake_name>": { ...fields } }` (serde `snake_case` rename, externally tagged).

---

## EventEnvelope

Every event carries full packet context.

```rust
pub struct EventEnvelope {
    pub timestamp: DateTime<Utc>,
    pub interface_id: u32,
    pub segment_hash: String,
    pub frame_index: u64,
    pub session_key: String,
    pub src_mac: Option<String>,
    pub dst_mac: Option<String>,
    pub src_ip: Option<String>,
    pub dst_ip: Option<String>,
    pub src_port: Option<u16>,
    pub dst_port: Option<u16>,
    pub vlan_id: Option<u16>,
    pub transport: TransportProtocol,
    pub protocol: Option<String>,
    pub bytes_count: u64,
    pub packet_count: u64,
}
```

| Field | Type | Notes |
|-------|------|-------|
| `timestamp` | RFC 3339 UTC | Frame timestamp (microsecond precision when source is PCAPNG or `usec`-mode PCAP). |
| `interface_id` | `u32` | PCAPNG interface index; `0` for classic PCAP. |
| `segment_hash` | `String` | SHA-256 over the captured segment bytes — stable across replays. |
| `frame_index` | `u64` | 0-based frame index within the segment. |
| `session_key` | `String` | Stable per-flow key, e.g. `tcp:10.0.0.1:49152:10.0.0.2:502`. |
| `src_mac` / `dst_mac` | `Option<String>` | Canonical `aa:bb:cc:dd:ee:ff`. |
| `src_ip` / `dst_ip` | `Option<String>` | v4 dotted-quad or v6 canonical. |
| `src_port` / `dst_port` | `Option<u16>` | TCP / UDP port; `None` for L2-only frames. |
| `vlan_id` | `Option<u16>` | First 802.1Q tag, if present. |
| `transport` | enum (see below) | `"ethernet"` \| `"arp"` \| `"ipv4"` \| `"tcp"` \| `"udp"` \| `"icmp"` \| `"unknown"`. |
| `protocol` | `Option<String>` | Decoder slug, e.g. `"modbus"`, `"sparkplug_b"`. |
| `bytes_count` | `u64` | Bytes attributed to this event's flow segment. |
| `packet_count` | `u64` | Packets attributed to this event's flow segment. |

### `TransportProtocol`

Serialized as snake_case string.

```rust
pub enum TransportProtocol {
    Ethernet, Arp, Ipv4, Tcp, Udp, Icmp, Unknown,
}
```

---

## BronzeEventFamily

Tagged enum, externally tagged with snake_case rename.

```rust
pub enum BronzeEventFamily {
    ProtocolTransaction(ProtocolTransaction),
    AssetObservation(AssetObservation),
    TopologyObservation(TopologyObservation),
    ParseAnomaly(ParseAnomaly),
    ExtractedArtifact(ExtractedArtifact),
    ProcessReading(ProcessReading),
}
```

Helper accessors on `BronzeEvent`:

- `family_name() -> &'static str` — `"protocol_transaction"` / `"asset_observation"` / etc.
- `protocol() -> Option<&str>` — alias for `envelope.protocol.as_deref()`.
- `operation() -> Option<&str>` — populated for `ProtocolTransaction` only.
- `status() -> Option<&str>` — populated for `ProtocolTransaction` only.
- `src_ip()` / `dst_ip()` / `src_mac()` / `dst_mac()` — alias accessors into envelope.

---

### `ProtocolTransaction`

A request-response pair, single operation, or session marker.

```rust
pub struct ProtocolTransaction {
    pub operation: String,
    pub status: String,
    pub request_summary: Option<String>,
    pub response_summary: Option<String>,
    pub object_refs: Vec<String>,
    pub values: Vec<ObjectValue>,
    pub attributes: BTreeMap<String, String>,
    pub modbus: Option<ModbusBronzeFields>,        // DEPRECATED — removed in v2.0
    pub protocol_fields: Option<ProtocolFields>,
}
```

| Field | Notes |
|-------|-------|
| `operation` | Snake-case operation slug. Examples: `modbus_read_holding_registers`, `dns_query`, `diameter_capabilities_exchange_request`. |
| `status` | `"ok"` \| `"error"` \| `"request_only"` \| `"response_only"` \| `"observed"` \| protocol-specific (e.g. `"exception_0x02"`). |
| `request_summary` / `response_summary` | Human-readable one-liner, optional. |
| `object_refs` | Protocol-native object references the operation acted on (file paths, register addresses, AVP session IDs, etc.). |
| `values` | Per-object values when applicable. |
| `attributes` | **Deprecated escape hatch.** String-keyed bag for protocols not yet migrated to `protocol_fields`. Will be removed in v2.0. |
| `modbus` | **Deprecated.** Use `protocol_fields: Some(ProtocolFields::Modbus(...))` instead. Removed in v2.0. |
| `protocol_fields` | Tagged enum of typed per-protocol data. Currently `Modbus(ModbusBronzeFields)`; future variants land here as decoders migrate. |

#### `ObjectValue`

```rust
pub struct ObjectValue { pub object_ref: String, pub value: Option<String> }
```

#### `ProtocolFields` enum

Externally tagged on `{ "protocol": "...", "fields": { ... } }`. Currently:

```rust
ProtocolFields::Modbus(ModbusBronzeFields)
```

Planned next variants (see `bronze.rs:101`): `Dnp3`, `Iec104`, `S7comm`, `OpcUa`, `EthernetIp`, `Iec61850`, `HartIp`, `Sparkplug`.

#### `ModbusBronzeFields`

```rust
pub struct ModbusBronzeFields {
    pub fc: u8,                        // base function code (0x80 stripped)
    pub start_addr: Option<u16>,       // None on unpaired responses
    pub qty: Option<u16>,              // None on single-item writes / unpaired
    pub values: Vec<u16>,              // read FC → from response; write FC → from request
    pub exception_code: Option<u8>,
    pub direction: String,             // "request" | "response" | "paired"
}
```

---

### `AssetObservation`

Device / service identification.

```rust
pub struct AssetObservation {
    pub asset_key: String,
    pub role: Option<String>,
    pub vendor: Option<String>,
    pub model: Option<String>,
    pub firmware: Option<String>,
    pub hostnames: Vec<String>,
    pub protocols: Vec<String>,
    pub identifiers: BTreeMap<String, String>,
}
```

| Field | Notes |
|-------|-------|
| `asset_key` | Stable per-asset identity. Usually an IP, sometimes a MAC, sometimes a protocol-native ID (e.g. `avtp_entity:{eid_hex}`). |
| `role` | Decoder-assigned role: `"plc"`, `"hmi"`, `"diameter_peer"`, `"radsec_server"`, etc. |
| `vendor` / `model` / `firmware` | When the wire reveals them (CIP Identity, DISCOVERY_ACK, LLDP, mDNS, etc.). |
| `hostnames` | mDNS, NetBIOS, DHCP-supplied hostnames. |
| `protocols` | Protocols this asset has been observed speaking. |
| `identifiers` | Free-form key-value identifiers (CIP serial, AVTP entity_id_hex, Diameter origin_realm, etc.). |

---

### `TopologyObservation`

Relationship between two assets / endpoints.

```rust
pub struct TopologyObservation {
    pub observation_type: String,
    pub local_id: String,
    pub remote_id: Option<String>,
    pub description: Option<String>,
    pub capabilities: Vec<String>,
    pub metadata: BTreeMap<String, String>,
}
```

| Field | Notes |
|-------|-------|
| `observation_type` | `"arp_neighbor"`, `"lldp_neighbor"`, `"lacp_bond"`, `"stp_root"`, `"mrp_ring"`, etc. |
| `local_id` | Local endpoint identifier. |
| `remote_id` | Remote endpoint identifier when known. |
| `description` | Human-readable. |
| `capabilities` | Protocol-native capability strings (LLDP capability bits, MRP role, etc.). |
| `metadata` | Free-form. |

---

### `ParseAnomaly`

Malformed, invalid, or suspicious packet. Also the carrier for the detector subsystems (Stovetop, ICMPeeker, Bilgepump).

```rust
pub struct ParseAnomaly {
    pub decoder: String,
    pub severity: String,
    pub reason: String,
    pub raw_excerpt_hex: String,
}
```

| Field | Notes |
|-------|-------|
| `decoder` | Source decoder slug, or detector prefix: `"stovetop:padding"`, `"icmpeeker:redirect"`, `"bilgepump:arp_spoof"`. |
| `severity` | `"low"` \| `"medium"` \| `"high"` \| `"critical"`. |
| `reason` | Human-readable explanation. |
| `raw_excerpt_hex` | First few dozen bytes of the offending payload, hex-encoded. Truncated; not the full packet. |

---

### `ExtractedArtifact`

Binary payload extraction (firmware blobs, captured files, embedded blobs).

```rust
pub struct ExtractedArtifact {
    pub artifact_type: String,
    pub artifact_key: String,
    pub sha256: String,
    pub mime_type: Option<String>,
    pub content_hex: String,
    pub description: Option<String>,
}
```

`content_hex` is the full artifact body, hex-encoded.

---

### `ProcessReading`

Process variable Value/Quality/Timestamp from the wire. Emitted by VQT-bearing dissectors: Sparkplug B, OPC UA ReadResponse, CIP Read Tag, Modbus, DNP3, IEC 104, IEC 61850 MMS, HART-IP, IEEE C37.118.

```rust
pub struct ProcessReading {
    pub source_protocol: String,
    pub point_id: PointIdentifier,
    pub value: PointValue,
    pub quality: RawQuality,
    pub source_ts: Option<u64>,    // microseconds since epoch, device time
    pub observed_ts: u64,          // microseconds since epoch, capture time
}
```

#### `PointIdentifier`

Externally tagged, snake_case. One variant per protocol family.

| Variant | Fields |
|---------|--------|
| `modbus_register` | `unit_id: u8`, `addr: u16`, `register_type: ModbusRegKind` (`"coil"` \| `"discrete_input"` \| `"holding_register"` \| `"input_register"`) |
| `opc_ua_node` | `namespace_index: u16`, `identifier: OpcUaNodeId` |
| `cip_symbol` | `symbol: String`, `symbol_raw: Option<Vec<u8>>` (non-UTF-8 fallback) |
| `cip_path` | `class: u16`, `instance: u32`, `attribute: Option<u16>` |
| `dnp_point` | `group: u8`, `variation: u8`, `index: u32` |
| `iec104_ioa` | `common_addr: u16`, `ioa: u32`, `type_id: u8` |
| `iec61850_reference` | `reference: String`, `reference_raw: Option<Vec<u8>>` |
| `sparkplug_metric` | `group_id`, `edge_node_id`, `device_id`, `metric_name`, `metric_name_raw`, `alias: Option<u64>` |
| `hart_command` | `command: u8`, `slot: Option<u8>` |
| `pccc_address` | `file_type: u8`, `file_number: u8`, `element: u16`, `sub_element: Option<u8>` |
| `synchrophasor_channel` | `idcode: u16`, `station_name: Option<String>`, `channel_index: u16`, `channel_name: Option<String>`, `channel_type: SynchrophasorChannelType` |

#### `OpcUaNodeId`

```rust
pub enum OpcUaNodeId {
    Numeric(u32),
    String(String),
    StringRaw(Vec<u8>),    // when wire bytes were not valid UTF-8
    Guid([u8; 16]),
    Opaque(Vec<u8>),
}
```

#### `SynchrophasorChannelType`

```rust
pub enum SynchrophasorChannelType {
    PhasorMagnitude, PhasorAngle, Frequency, FrequencyDerivative, Analog, Digital,
}
```

#### `PointValue`

Externally tagged on `{ "type": "...", "value": ... }`. Primitive types only; aggregate types (DataSet, Template, arrays) are deferred until a protocol needs them.

```rust
pub enum PointValue {
    Null,
    Bool(bool),
    Int8(i8), Int16(i16), Int32(i32), Int64(i64),
    UInt8(u8), UInt16(u16), UInt32(u32), UInt64(u64),
    Float(f32), Double(f64),
    Text(String),
    Bytes(Vec<u8>),
    DateTime(u64),   // microseconds since Unix epoch
}
```

#### `RawQuality`

Externally tagged on `{ "kind": "...", "data": ... }`. **Intentionally minimal API**: this enum exposes raw bits and nothing else. No `is_good()`, no `severity()`, no `to_normalized()` — quality interpretation is operator policy and lives in the embedder, not in the DPI engine.

| Variant | Data |
|---------|------|
| `none` | (Modbus, classic S7) |
| `dnp_flags` | `u8` |
| `iec104_qds` | `u8` |
| `opc_ua_status_code` | `u32` |
| `iec61850_quality` | `u16` |
| `sparkplug_quality` | `{ value: Option<u32>, is_historical: bool, is_transient: bool, is_null: bool }` |
| `cip_general_status` | `u8` |
| `hart_field_device_status` | `u8` |

---

## Sample JSON

### `ProtocolTransaction` (Modbus read with typed fields)

```json
{
  "event_id": "f3d7…",
  "capture_id": "engagement-a-01",
  "schema_version": "v2",
  "envelope": {
    "timestamp": "2026-05-11T14:23:01.123456Z",
    "interface_id": 0,
    "segment_hash": "9c3a…",
    "frame_index": 412,
    "session_key": "tcp:10.0.0.10:49152:10.0.0.20:502",
    "src_mac": "aa:bb:cc:00:11:01",
    "dst_mac": "aa:bb:cc:00:11:02",
    "src_ip": "10.0.0.10",
    "dst_ip": "10.0.0.20",
    "src_port": 49152,
    "dst_port": 502,
    "vlan_id": null,
    "transport": "tcp",
    "protocol": "modbus",
    "bytes_count": 23,
    "packet_count": 1
  },
  "family": {
    "protocol_transaction": {
      "operation": "modbus_read_holding_registers",
      "status": "ok",
      "request_summary": "unit=1 start=40001 qty=10",
      "response_summary": null,
      "object_refs": [],
      "values": [],
      "attributes": {},
      "protocol_fields": {
        "protocol": "modbus",
        "fields": {
          "fc": 3,
          "start_addr": 40001,
          "qty": 10,
          "values": [1234, 5678, 9, 0, 0, 0, 0, 0, 0, 0],
          "exception_code": null,
          "direction": "paired"
        }
      }
    }
  }
}
```

### `ProcessReading` (Sparkplug B metric)

```json
{
  "family": {
    "process_reading": {
      "source_protocol": "sparkplug_b",
      "point_id": {
        "kind": "sparkplug_metric",
        "group_id": "Plant1",
        "edge_node_id": "PLC-A",
        "device_id": "Drive-17",
        "metric_name": "BearingTemp",
        "alias": 42
      },
      "value": { "type": "double", "value": 74.2 },
      "quality": {
        "kind": "sparkplug_quality",
        "data": { "value": 192, "is_historical": false, "is_transient": false, "is_null": false }
      },
      "source_ts": 1715438581123456,
      "observed_ts": 1715438581123890
    }
  }
}
```

### `AssetObservation` (mDNS-discovered camera)

```json
{
  "family": {
    "asset_observation": {
      "asset_key": "10.0.5.42",
      "role": "camera",
      "vendor": "Acme",
      "model": "AX-2000",
      "firmware": "1.4.3",
      "hostnames": ["cam-42.local"],
      "protocols": ["mdns", "rtsp"],
      "identifiers": { "mdns_service": "_rtsp._tcp" }
    }
  }
}
```

### `ParseAnomaly` (Stovetop detection)

```json
{
  "family": {
    "parse_anomaly": {
      "decoder": "stovetop:padding",
      "severity": "high",
      "reason": "non-zero Ethernet padding with shannon entropy 7.42 (covert channel likely)",
      "raw_excerpt_hex": "9c3a4e7b…"
    }
  }
}
```

---

## CLI envelope (Bronze JSON output)

The CLI binary wraps events in an outer envelope:

```json
{
  "engine": "marlinspike-dpi",
  "version": "1.13.0",
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

`--format ocsf` and `--format influx` emit line-oriented framing directly — no outer envelope — so SIEM / historian consumers can pipe stdout straight in.

---

## Related types (utility)

### `ActivityRecord`

Flat per-flow row derived from a `ProtocolTransaction` for tabular consumers. Returned by `BronzeEvent::activity_record()` and `activity_records(&[BronzeEvent])`.

### `SegmentCheckpoint`

```rust
pub struct SegmentCheckpoint {
    pub capture_id: String,
    pub schema_version: String,
    pub segment_hash: String,
    pub frames_processed: u64,
    pub events_emitted: u64,
}
```

Stamped onto the CLI envelope and returned from `process_streaming` callers via `BronzeSink`.

### `BronzeBatch`

```rust
pub struct BronzeBatch {
    pub capture_id: String,
    pub schema_version: String,
    pub segment_hash: String,
    pub events: Vec<BronzeEvent>,
    pub checkpoint: SegmentCheckpoint,
}
```

A batch of events plus its checkpoint — the streaming-API delivery unit.
