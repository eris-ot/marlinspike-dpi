"""marlinspike-dpi — passive DPI for OT/ICS and IT networks.

Parses PCAP and PCAPNG captures and returns Bronze v2 events as Python
dicts.  Each event dict contains standard envelope fields plus
protocol-specific payload under its snake_case family name.

Quick start
-----------
>>> import marlinspike_dpi as md
>>> events = md.process_capture("capture.pcap", capture_id="session-1")
>>> for ev in events:
...     print(ev["family"], ev["protocol"], ev["operation"])

Streaming (memory-bounded for large captures)
----------------------------------------------
>>> md.process_capture_streaming(
...     "capture.pcap",
...     capture_id="session-1",
...     on_event=lambda ev: print(ev["family"]),
... )

DpiEngine class (reuse state across segments)
----------------------------------------------
>>> engine = md.DpiEngine(batch_size=64)
>>> events = engine.process_capture("capture.pcap", capture_id="seg-1")
"""

from ._marlinspike_dpi import (
    DpiEngine,
    __version__,
    process_capture,
    process_capture_bytes,
    process_capture_streaming,
)

__all__ = [
    "DpiEngine",
    "process_capture",
    "process_capture_bytes",
    "process_capture_streaming",
    "__version__",
]
