"""Type stubs for marlinspike-dpi Bronze v2 event dicts.

These TypedDicts describe the shape of every dict returned by
:func:`process_capture`, :func:`process_capture_bytes`, and
:meth:`DpiEngine.process_capture`.

They are purely informational for type-checkers (mypy, pyright) — at runtime
the engine returns plain :class:`dict` objects.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

# ---------------------------------------------------------------------------
# Envelope
# ---------------------------------------------------------------------------

class EventEnvelope(Dict[str, Any]):
    timestamp: str           # ISO-8601 UTC, e.g. "2023-11-14T21:46:40Z"
    interface_id: int
    segment_hash: str
    frame_index: int
    session_key: str
    src_mac: Optional[str]
    dst_mac: Optional[str]
    src_ip: Optional[str]
    dst_ip: Optional[str]
    src_port: Optional[int]
    dst_port: Optional[int]
    vlan_id: Optional[int]
    transport: str           # "ethernet" | "arp" | "ipv4" | "tcp" | "udp" | "icmp" | "unknown"
    protocol: Optional[str]  # e.g. "modbus", "dnp3", "opc_ua"
    bytes_count: int
    packet_count: int

# ---------------------------------------------------------------------------
# Family payloads
# ---------------------------------------------------------------------------

class ProtocolTransaction(Dict[str, Any]):
    operation: str
    status: str
    request_summary: Optional[str]
    response_summary: Optional[str]
    object_refs: List[str]
    attributes: Dict[str, str]

class AssetObservation(Dict[str, Any]):
    asset_key: str
    role: Optional[str]
    vendor: Optional[str]
    model: Optional[str]
    firmware: Optional[str]
    hostnames: List[str]
    protocols: List[str]
    identifiers: Dict[str, str]

class TopologyObservation(Dict[str, Any]):
    observation_type: str
    local_id: str
    remote_id: Optional[str]
    description: Optional[str]
    capabilities: List[str]
    metadata: Dict[str, str]

class ParseAnomaly(Dict[str, Any]):
    decoder: str
    severity: str
    reason: str
    raw_excerpt_hex: str

class ExtractedArtifact(Dict[str, Any]):
    artifact_type: str
    artifact_key: str
    sha256: str
    mime_type: Optional[str]
    content_hex: str
    description: Optional[str]

class ProcessReading(Dict[str, Any]):
    source_protocol: str     # e.g. "modbus", "opc_ua", "sparkplug_b"
    point_id: Dict[str, Any]
    value: Dict[str, Any]    # {"type": "float", "value": 3.14}
    quality: Dict[str, Any]
    source_ts: Optional[int] # microseconds since Unix epoch
    observed_ts: int         # microseconds since Unix epoch

# ---------------------------------------------------------------------------
# Top-level event dict
# ---------------------------------------------------------------------------

class BronzeEvent(Dict[str, Any]):
    event_id: str
    capture_id: str
    schema_version: str      # "v2"
    family: str              # "protocol_transaction" | "asset_observation" | ...
    protocol: Optional[str]  # shortcut → envelope.protocol
    operation: Optional[str] # shortcut → protocol_transaction.operation
    status: Optional[str]    # shortcut → protocol_transaction.status
    envelope: EventEnvelope
    # Family payload is present under its snake_case name, e.g.:
    #   event["protocol_transaction"]  → ProtocolTransaction
    #   event["process_reading"]       → ProcessReading
    #   event["asset_observation"]     → AssetObservation
    #   event["topology_observation"]  → TopologyObservation
    #   event["parse_anomaly"]         → ParseAnomaly
    #   event["extracted_artifact"]    → ExtractedArtifact
