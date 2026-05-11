# Adding a new protocol decoder

This is a step-by-step walkthrough for adding a new protocol decoder to marlinspike-dpi. The target time-to-first-event for a competent Rust developer is **30 minutes** for a recognition-level decoder and **2–4 hours** for a deep decoder with request/response pairing.

The codebase uses [`inventory`](https://docs.rs/inventory) for decoder self-registration — there is **no central registration list to edit**. One new file with one `inventory::submit!` block at the bottom is the whole wiring story.

## The 30-second tour

1. Create `src/engine/decoders/<protocol>.rs` (or `src/engine/decoders/ot/<protocol>.rs` for industrial protocols).
2. Define a decoder struct.
3. Implement `SessionDecoder` for it.
4. `inventory::submit!` it at the bottom.
5. Add `pub(crate) mod <protocol>;` to the relevant `mod.rs`.
6. Write tests.

That's it. `DpiEngine::new()` will pick up your decoder automatically at startup via the inventory crate's link-time collection.

## Reference decoders to copy from

Different protocols need different amounts of decoder machinery. Pick the closest match:

| If your protocol is… | Copy the shape of |
|---|---|
| TCP, header + per-message parse, request/response pairing | [`src/engine/decoders/diameter.rs`](../src/engine/decoders/diameter.rs) — 650 lines, RFC 6733, full AVP walk, hop_by_hop pairing |
| TCP, simple per-message parse, no pairing | [`src/engine/decoders/openvpn.rs`](../src/engine/decoders/openvpn.rs) |
| UDP datagram, header + dispatch | [`src/engine/decoders/ot/avtp.rs`](../src/engine/decoders/ot/avtp.rs) — EtherType-based, subtype dispatch |
| UDP per-datagram with pending-table pairing | [`src/engine/decoders/ot/modbus_udp.rs`](../src/engine/decoders/ot/modbus_udp.rs) — MBAP, LRU pending table |
| L2 frame with EtherType match | [`src/engine/decoders/ot/sercos.rs`](../src/engine/decoders/ot/sercos.rs) |
| Recognition-only (no spec or member-restricted) | [`src/engine/decoders/recognizers.rs`](../src/engine/decoders/recognizers.rs) — multiple small stubs in one file |
| TLS-wrapped (handshake fingerprint then opaque) | [`src/engine/decoders/radsec.rs`](../src/engine/decoders/radsec.rs) |
| Emits VQT (ProcessReading) | [`src/engine/decoders/ot/modbus.rs`](../src/engine/decoders/ot/modbus.rs) or `ot/opc_ua_pubsub.rs` |

## Step-by-step (using diameter.rs as the model)

### 1. Create the file

`src/engine/decoders/diameter.rs` lives at the top level because Diameter is an IT-ish protocol (telecom AAA). Industrial protocols live in `src/engine/decoders/ot/`. Pick whichever fits.

### 2. Decoder struct

```rust
pub(crate) struct DiameterDecoder {
    pending: HashMap<u32, PendingRequest>,
    tls_session_emitted: bool,
    asset_emitted: bool,
}
```

Keep state minimal. Use `HashMap` for per-session pending requests with an LRU bound if it can grow (see `modbus_udp.rs` for the LRU pattern).

### 3. Self-registration

```rust
inventory::submit!(crate::engine::decoders::DecoderRegistration {
    name: "diameter",
    factory: || Box::new(DiameterDecoder::default()),
});
```

The `name` is the protocol slug — snake_case, no spaces. It appears in `envelope.protocol` and is what consumers filter on.

### 4. Implement `SessionDecoder`

```rust
impl SessionDecoder for DiameterDecoder {
    fn name(&self) -> &'static str { "diameter" }

    fn interest(&self) -> &'static [DecoderInterest] {
        &[
            DecoderInterest::TcpPort(3868),  // plaintext Diameter
            DecoderInterest::TcpPort(5868),  // Diameter over TLS
        ]
    }

    fn on_stream_chunk(&mut self, chunk: &StreamChunk<'_>, out: &mut Vec<BronzeEvent>) {
        // … parse, emit events to `out` …
    }
}
```

`DecoderInterest` variants tell the engine when to call you:

| Variant | When the engine routes traffic to you |
|---|---|
| `TcpPort(u16)` | TCP traffic with src or dst port == this |
| `UdpPort(u16)` | UDP datagrams with src or dst port == this |
| `EtherType(u16)` | L2 frames carrying this EtherType (e.g. 0x88B8 for GOOSE) |
| `IpProto(u8)` | IP protocol number (e.g. 2 for IGMP, 47 for GRE) |
| `Llc { dsap, ssap }` | LLC frames matching the DSAP/SSAP |
| `Snap { oui, pid }` | SNAP-encapsulated frames matching the OUI + protocol id |

Use the most specific match available. TCP and UDP ports are by far the most common.

For stream-based protocols (TCP), implement `on_stream_chunk`. For per-datagram protocols (UDP), implement `on_datagram` (or both, if your protocol can ride either).

### 5. Build the envelope and emit events

The engine gives you a `StreamChunk` (or `Datagram`) per call. Build a Bronze envelope using the `build_envelope` helper:

```rust
let envelope = build_envelope(
    &chunk.context,
    chunk.interface_id,
    chunk.frame_index,
    chunk.timestamp,
    chunk.segment_hash,
    TransportProtocol::Tcp,
    Some("diameter"),
    chunk.captured_len,
    chunk.session_key.clone(),
);
```

Then emit one or more events into `out`:

```rust
out.push(new_event(
    chunk.capture_id.to_string(),
    envelope,
    BronzeEventFamily::ProtocolTransaction(ProtocolTransaction {
        operation: "diameter_capabilities_exchange_request".to_string(),
        status: "ok".to_string(),
        request_summary: Some(format!("cmd={} app={} hbh={:#010x}", cmd, app, hbh)),
        response_summary: None,
        object_refs: vec![],
        values: vec![],
        attributes: BTreeMap::new(),
        modbus: None,
        protocol_fields: None,
    }),
));
```

The six Bronze families you can emit:

| Family | Use when |
|---|---|
| `ProtocolTransaction` | Request, response, or paired operation — the most common event |
| `AssetObservation` | You learned something about a device (vendor, model, role, hostnames, protocol set) |
| `TopologyObservation` | You observed a network relationship (neighbour, peer, bond, ring) |
| `ParseAnomaly` | The packet was malformed, unrecognised, or structurally suspicious |
| `ExtractedArtifact` | You pulled binary content out (firmware blob, file, payload) — emit with SHA-256 |
| `ProcessReading` | A process variable Value/Quality/Timestamp reading was on the wire (Sparkplug, OPC UA, Modbus register, DNP3 point, etc.) |

See [`docs/bronze-v2-schema.md`](./bronze-v2-schema.md) for every field.

### 6. (Optional) typed `ProtocolFields` variant

For deep-parsed protocols, add a typed field struct in `src/bronze.rs` so consumers can pattern-match instead of reading string attributes. This is the v2.0 prep — the `attributes: BTreeMap<String, String>` bag gets removed in v2.0.

See [`ProtocolFields::Modbus`](../src/bronze.rs) for the precedent. Add your variant to the `ProtocolFields` enum and populate it on every emitted `ProtocolTransaction` alongside `attributes` for backward compatibility.

### 7. Wire the module

Add one line to the relevant `mod.rs`:

```rust
// src/engine/decoders/mod.rs  — IT protocols
pub(crate) mod diameter;

// src/engine/decoders/ot/mod.rs  — OT protocols
pub(crate) mod roc_plus;
```

Keep the list alphabetical.

### 8. Tests

Inline `#[cfg(test)] mod tests` block at the bottom of your decoder file. Aim for at least:

- One test per major message type / command code
- One test for request/response pairing if your decoder pairs
- One test for malformed input → ParseAnomaly
- One test for the unknown-but-valid case (unrecognised opcode → low anomaly + best-effort emission)

Look at `src/engine/decoders/diameter.rs` (650 lines, 7 tests covering CER, CER+CEA pair, Device-Watchdog, accounting answer with error, TLS session on port 5868, unknown command code, AssetObservation identifiers).

For test fixtures, hand-craft byte slices using the wire format. The `tests/cli_format.rs` file has a minimal-PCAP byte-construction example if you need a full-frame fixture.

### 9. Verify

```bash
cargo build --quiet                   # must be clean
cargo test --quiet                    # all existing tests plus yours
cargo test <protocol_name> --quiet    # just your new tests
```

### 10. Commit message style

Match the existing pattern:

```
feat(<protocol>): <one-line description>

<paragraph explaining what's parsed, what's deferred, and any notable
edge cases or anomaly emission rules>
```

Example: `feat(roc_plus): Emerson ROC Plus gas SCADA decoder (TCP 4000)`.

## Common gotchas

**Endianness varies.** Most network protocols are big-endian, but plenty of industrial protocols are little-endian (Modbus body is BE but Modbus/UMAS sub-headers are LE; MELSEC is LE end-to-end; UADP/OPC PubSub is LE). Don't assume.

**TCP stream chunking.** Your `on_stream_chunk` may be called with a partial PDU, multiple PDUs concatenated, or a PDU split across calls. If your protocol has explicit framing (length prefix, magic bytes), buffer per-session bytes and extract complete PDUs before parsing. See `src/engine/decoders/openvpn.rs` for the 2-byte length-prefix reassembly pattern, or `src/engine/decoders/ldap.rs` for BER-message buffering.

**Per-session state needs eviction.** If you store state per session_key, implement `on_idle_flush` so memory doesn't leak across long captures. The engine calls `on_idle_flush` periodically and at end-of-segment.

**Sampling for high-volume protocols.** Cyclic protocols (EtherNet/IP Class 1 I/O, AVTP media streams, SERCOS) emit at 1–10 kHz. Emitting one Bronze event per packet floods consumers. The codebase convention is: emit on first sight of a (session, stream_id) pair, then every 1000th packet. See `src/engine/decoders/ot/avtp.rs` for the pattern.

**Encrypted-past-handshake protocols.** TLS, SSH, IPsec ESP, WireGuard transport, QUIC, SMB3 Transform PDUs — for these, parse the handshake and stop. Emit a single session marker event. Don't try to decrypt; we don't accept session keys.

**ParseAnomaly severity.** Calibrate:
- `low` — unknown opcode in a recognised protocol, vendor extension we don't know yet
- `medium` — truncated PDU, length-field mismatch, suspicious header
- `high` — state-mutating command in a context where it shouldn't appear (e.g. `STOP_PLC` in UMAS, `SetControlProgram` in TriStation, `FSCTL_PIPE_TRANSCEIVE` on `\PIPE\svcctl` in SMB2 — defender signals)
- `critical` — definite attack indicator (ICMP redirect on OT network, VLAN double-tag hopping)

## Recognition-only when you can't do better

If the wire format is member-restricted (CC-Link IE, Foundation Fieldbus HSE, IO-Link Wireless) or proprietary with no public reverse-engineering (OSIsoft PI), implement a recognition-only decoder in [`src/engine/decoders/recognizers.rs`](../src/engine/decoders/recognizers.rs) instead of a full-file decoder. Recognition emits a single `ProtocolTransaction` with `operation: "<protocol>_traffic"` and `status: "ok"` per session. This is honest — defenders can still build asset inventory from a port + magic-byte fingerprint.

## After you ship

- Add an entry to [`docs/parse-depth-matrix.md`](./parse-depth-matrix.md) with your depth + what's deferred
- Update the protocol table in `README.md`
- Add the file-top `//!` doc to [`docs/protocols.md`](./protocols.md) (or just rely on the README table)
- Add a `CHANGELOG.md` entry under the next release header

## Questions

Open a [GitHub Discussion](https://github.com/eris-ot/marlinspike-dpi/discussions) under the **Q&A** category. Decoder-authoring questions are explicitly welcome — the inventory-based registration is designed to keep the contribution surface small.
