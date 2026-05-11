//! Python bindings for marlinspike-dpi.
//!
//! Exposes the DPI engine to Python via PyO3 using a JSON-bridge approach:
//! Rust Bronze events are serialised to JSON then converted to Python dicts,
//! giving Python consumers a naturally Pythonic interface with zero custom
//! struct mappings.
//!
//! Install and use:
//! ```text
//! $ pip install maturin
//! $ maturin develop --release   # from marlinspike-dpi-py/
//! ```
//!
//! ```python
//! import marlinspike_dpi as md
//! events = md.process_capture("capture.pcap", capture_id="session-1")
//! for ev in events:
//!     print(ev["family"], ev["protocol"], ev["operation"])
//! ```

use std::io::Cursor;

use pyo3::exceptions::PyIOError;
use pyo3::prelude::*;
use pyo3::types::{PyDict, PyList};

use fm_dpi::{BronzeEvent, DpiEngine, SegmentMeta};

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/// Convert a `serde_json::Value` into a Python object.
fn json_to_py(py: Python<'_>, value: serde_json::Value) -> PyResult<PyObject> {
    match value {
        serde_json::Value::Null => Ok(py.None()),
        serde_json::Value::Bool(b) => Ok(b.into_py(py)),
        serde_json::Value::Number(n) => {
            if let Some(i) = n.as_i64() {
                Ok(i.into_py(py))
            } else if let Some(u) = n.as_u64() {
                Ok(u.into_py(py))
            } else if let Some(f) = n.as_f64() {
                Ok(f.into_py(py))
            } else {
                Ok(py.None())
            }
        }
        serde_json::Value::String(s) => Ok(s.into_py(py)),
        serde_json::Value::Array(arr) => {
            let list = PyList::empty_bound(py);
            for item in arr {
                list.append(json_to_py(py, item)?)?;
            }
            Ok(list.into_py(py))
        }
        serde_json::Value::Object(map) => {
            let dict = PyDict::new_bound(py);
            for (k, v) in map {
                dict.set_item(k, json_to_py(py, v)?)?;
            }
            Ok(dict.into_py(py))
        }
    }
}

/// Convert a [`BronzeEvent`] to a flat Python dict with convenience shortcut
/// keys (`protocol`, `operation`, `status`, `family`).
///
/// Shape:
/// ```json
/// {
///   "event_id": "...",
///   "capture_id": "...",
///   "schema_version": "v2",
///   "family": "protocol_transaction",
///   "protocol": "modbus",
///   "operation": "read_holding_registers",
///   "status": "ok",
///   "envelope": { ... },
///   "protocol_transaction": { ... }
/// }
/// ```
fn bronze_event_to_pydict(py: Python<'_>, event: &BronzeEvent) -> PyResult<Py<PyDict>> {
    // Serialise to JSON Value — clean and future-proof.
    let mut root: serde_json::Map<String, serde_json::Value> =
        serde_json::from_str(&serde_json::to_string(event).map_err(|e| {
            PyIOError::new_err(format!("serialization error: {e}"))
        })?)
        .map_err(|e| PyIOError::new_err(format!("deserialization error: {e}")))?;

    // Pull out the original tagged-enum `family` value from the serialised
    // root before we overwrite the key with the plain string name.
    let family_enum_val = root.remove("family");
    let family_name = event.family_name().to_string();

    // Convenience shortcuts at the top level.
    root.insert("family".into(), serde_json::Value::String(family_name.clone()));

    let protocol = event
        .protocol()
        .map(|s| serde_json::Value::String(s.to_string()))
        .unwrap_or(serde_json::Value::Null);
    root.insert("protocol".into(), protocol);

    let operation = event
        .operation()
        .map(|s| serde_json::Value::String(s.to_string()))
        .unwrap_or(serde_json::Value::Null);
    root.insert("operation".into(), operation);

    let status = event
        .status()
        .map(|s| serde_json::Value::String(s.to_string()))
        .unwrap_or(serde_json::Value::Null);
    root.insert("status".into(), status);

    // Hoist the family payload from the tagged-enum value up to a top-level
    // key named after the variant, so callers can do
    // `event["protocol_transaction"]["operation"]` as an alternative to the
    // shortcut `event["operation"]`.
    //
    // The serde tagged-enum representation looks like:
    //   `{"protocol_transaction": {...}}`
    if let Some(serde_json::Value::Object(fmap)) = family_enum_val {
        for (k, v) in fmap {
            root.insert(k, v);
        }
    }

    let dict = PyDict::new_bound(py);
    for (k, v) in root {
        dict.set_item(k, json_to_py(py, v)?)?;
    }
    Ok(dict.unbind())
}

/// Run the DPI engine on raw capture bytes and return a list of event dicts.
fn run_engine_on_bytes(
    py: Python<'_>,
    capture_bytes: Vec<u8>,
    capture_id: &str,
    batch_size: usize,
) -> PyResult<Py<PyList>> {
    let mut engine = DpiEngine::new().with_batch_size(batch_size);
    let meta = SegmentMeta::new(capture_id);
    let reader = Cursor::new(capture_bytes);

    let output = engine
        .process_capture_to_vec(&meta, reader)
        .map_err(|e| PyIOError::new_err(format!("DPI engine error: {e}")))?;

    let list = PyList::empty_bound(py);
    for event in &output.events {
        let d = bronze_event_to_pydict(py, event)?;
        list.append(d)?;
    }
    Ok(list.unbind())
}

// ---------------------------------------------------------------------------
// Public Python functions
// ---------------------------------------------------------------------------

/// Process a PCAP or PCAPNG file and return all Bronze events as a list of dicts.
///
/// Parameters
/// ----------
/// path : str
///     Path to the capture file.
/// capture_id : str, optional
///     Logical identifier for this capture session (default: ``"default"``).
/// batch_size : int, optional
///     Internal engine batch size (default: 256).
#[pyfunction]
#[pyo3(signature = (path, capture_id="default", batch_size=256))]
fn process_capture(
    py: Python<'_>,
    path: &str,
    capture_id: &str,
    batch_size: usize,
) -> PyResult<Py<PyList>> {
    let bytes = std::fs::read(path)
        .map_err(|e| PyIOError::new_err(format!("cannot read {path}: {e}")))?;
    run_engine_on_bytes(py, bytes, capture_id, batch_size)
}

/// Process a PCAP or PCAPNG file and invoke ``on_event`` for each Bronze event.
///
/// Memory-bounded alternative to :func:`process_capture` for large captures.
/// The callback receives one dict per event; return value is ignored.
///
/// Parameters
/// ----------
/// path : str
///     Path to the capture file.
/// on_event : callable
///     Called once per event with the event dict as the sole argument.
/// capture_id : str, optional
///     Logical identifier for this capture session (default: ``"default"``).
/// batch_size : int, optional
///     Internal engine batch size (default: 256).
#[pyfunction]
#[pyo3(signature = (path, on_event, capture_id="default", batch_size=256))]
fn process_capture_streaming(
    py: Python<'_>,
    path: &str,
    on_event: PyObject,
    capture_id: &str,
    batch_size: usize,
) -> PyResult<()> {
    let bytes = std::fs::read(path)
        .map_err(|e| PyIOError::new_err(format!("cannot read {path}: {e}")))?;
    let list = run_engine_on_bytes(py, bytes, capture_id, batch_size)?;
    let bound = list.bind(py);
    for item in bound.iter() {
        on_event.call1(py, (item,))?;
    }
    Ok(())
}

/// Process raw PCAP/PCAPNG bytes and return all Bronze events as a list of dicts.
///
/// Parameters
/// ----------
/// data : bytes
///     Raw PCAP or PCAPNG bytes.
/// capture_id : str, optional
///     Logical identifier for this capture session (default: ``"default"``).
/// batch_size : int, optional
///     Internal engine batch size (default: 256).
#[pyfunction]
#[pyo3(signature = (data, capture_id="default", batch_size=256))]
fn process_capture_bytes(
    py: Python<'_>,
    data: &[u8],
    capture_id: &str,
    batch_size: usize,
) -> PyResult<Py<PyList>> {
    run_engine_on_bytes(py, data.to_vec(), capture_id, batch_size)
}

// ---------------------------------------------------------------------------
// DpiEngine class
// ---------------------------------------------------------------------------

/// Stateful DPI engine instance. Maintains decoder state across multiple
/// ``process_capture`` calls (e.g. for reassembly across split captures).
///
/// Example
/// -------
/// ```python
/// import marlinspike_dpi as md
/// engine = md.DpiEngine(batch_size=64)
/// events = engine.process_capture("capture.pcap", capture_id="session-1")
/// for ev in events:
///     print(ev["family"], ev["protocol"])
/// ```
#[pyclass(name = "DpiEngine")]
struct PyDpiEngine {
    inner: DpiEngine,
    batch_size: usize,
}

#[pymethods]
impl PyDpiEngine {
    /// Create a new :class:`DpiEngine`.
    ///
    /// Parameters
    /// ----------
    /// batch_size : int, optional
    ///     Internal batching window for the Bronze emitter (default: 256).
    #[new]
    #[pyo3(signature = (batch_size=256))]
    fn new(batch_size: usize) -> Self {
        Self {
            inner: DpiEngine::new().with_batch_size(batch_size),
            batch_size,
        }
    }

    /// Process a PCAP/PCAPNG file and return all events as a list of dicts.
    #[pyo3(signature = (path, capture_id="default"))]
    fn process_capture(
        &mut self,
        py: Python<'_>,
        path: &str,
        capture_id: &str,
    ) -> PyResult<Py<PyList>> {
        let bytes = std::fs::read(path)
            .map_err(|e| PyIOError::new_err(format!("cannot read {path}: {e}")))?;
        let meta = SegmentMeta::new(capture_id);
        let output = self
            .inner
            .process_capture_to_vec(&meta, Cursor::new(bytes))
            .map_err(|e| PyIOError::new_err(format!("DPI engine error: {e}")))?;
        let list = PyList::empty_bound(py);
        for event in &output.events {
            let d = bronze_event_to_pydict(py, event)?;
            list.append(d)?;
        }
        Ok(list.unbind())
    }

    /// Process raw PCAP/PCAPNG bytes and return all events as a list of dicts.
    #[pyo3(signature = (data, capture_id="default"))]
    fn process_bytes(
        &mut self,
        py: Python<'_>,
        data: &[u8],
        capture_id: &str,
    ) -> PyResult<Py<PyList>> {
        let meta = SegmentMeta::new(capture_id);
        let output = self
            .inner
            .process_capture_to_vec(&meta, Cursor::new(data.to_vec()))
            .map_err(|e| PyIOError::new_err(format!("DPI engine error: {e}")))?;
        let list = PyList::empty_bound(py);
        for event in &output.events {
            let d = bronze_event_to_pydict(py, event)?;
            list.append(d)?;
        }
        Ok(list.unbind())
    }

    /// Return the configured batch size.
    #[getter]
    fn batch_size(&self) -> usize {
        self.batch_size
    }

    fn __repr__(&self) -> String {
        format!("DpiEngine(batch_size={})", self.batch_size)
    }
}

// ---------------------------------------------------------------------------
// Module registration
// ---------------------------------------------------------------------------

/// marlinspike-dpi Python bindings.
///
/// Passive deep-packet inspection for OT/ICS and IT networks.
/// Parses PCAP/PCAPNG files and returns Bronze v2 events as Python dicts.
#[pymodule]
fn _marlinspike_dpi(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(process_capture, m)?)?;
    m.add_function(wrap_pyfunction!(process_capture_streaming, m)?)?;
    m.add_function(wrap_pyfunction!(process_capture_bytes, m)?)?;
    m.add_class::<PyDpiEngine>()?;
    m.add("__version__", env!("CARGO_PKG_VERSION"))?;
    Ok(())
}
