# marlinspike-dpi Python bindings

PyO3 bindings for the `marlinspike-dpi` Rust engine. Gives ICS analysts
a `pip`-installable package for scripting DPI workflows in Python.

## Requirements

- Python >= 3.8
- Rust toolchain (`curl https://sh.rustup.rs | sh`)
- maturin: `pip install maturin`

## Development install

```bash
cd marlinspike-dpi-py
maturin develop --release
```

This compiles the Rust cdylib and installs the package into your active
Python environment. After that:

```python
import marlinspike_dpi as md
print(md.__version__)
```

## Usage

### One-shot (returns all events)

```python
import marlinspike_dpi as md

events = md.process_capture("capture.pcap", capture_id="engagement-a-01")
for ev in events:
    print(ev["family"], ev["protocol"], ev["operation"])
```

### From bytes (no temp file needed)

```python
data = open("capture.pcap", "rb").read()
events = md.process_capture_bytes(data, capture_id="session-1")
```

### Streaming (memory-bounded for large captures)

```python
md.process_capture_streaming(
    "capture.pcap",
    capture_id="engagement-a-01",
    on_event=lambda ev: print(ev["protocol"]),
)
```

### Reusable engine instance

```python
engine = md.DpiEngine(batch_size=64)
for segment in segment_files:
    events = engine.process_capture(segment, capture_id="run-1")
    handle(events)
```

## Event shape

Each event is a plain Python `dict`:

```python
{
    "event_id":       "uuid-...",
    "capture_id":     "engagement-a-01",
    "schema_version": "v2",
    "family":         "protocol_transaction",  # snake_case family name
    "protocol":       "modbus",                # shortcut → envelope.protocol
    "operation":      "read_holding_registers",# shortcut (ProtocolTransaction only)
    "status":         "ok",                    # shortcut (ProtocolTransaction only)
    "envelope":       { ... },                 # EventEnvelope fields
    "protocol_transaction": { ... },           # family payload
}
```

Other family names: `asset_observation`, `topology_observation`,
`parse_anomaly`, `extracted_artifact`, `process_reading`.

Type stubs for mypy/pyright are in
`python/marlinspike_dpi/_types.pyi`.

## Running tests

```bash
pip install pytest
pytest marlinspike-dpi-py/tests/
```

## Building a wheel

```bash
maturin build --release
# wheel lands in target/wheels/
```
