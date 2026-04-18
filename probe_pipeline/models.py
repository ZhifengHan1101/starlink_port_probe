from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any


@dataclass(slots=True)
class OpenPortRecord:
    run_id: str
    source_file: str
    source_group: str
    ip: str
    port: int
    protocol: str = "tcp"
    state: str = "open"
    scan_tool: str = "nmap"
    timestamp: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(slots=True)
class FingerprintRecord:
    run_id: str
    source_file: str
    source_group: str
    ip: str
    port: int
    transport: str
    service: str | None = None
    product: str | None = None
    version: str | None = None
    os_name: str | None = None
    os_vendor: str | None = None
    os_family: str | None = None
    os_generation: str | None = None
    os_accuracy: float = 0.0
    os_cpe: list[str] = field(default_factory=list)
    cpe: list[str] = field(default_factory=list)
    confidence: float = 0.0
    evidence_path: str | None = None
    fingerprint_method: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    raw_summary: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(slots=True)
class CVERecord:
    cve_id: str
    severity: str | None
    score: float | None
    published: str | None
    last_modified: str | None
    match_reason: str
    description: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(slots=True)
class EnrichedRecord(FingerprintRecord):
    cves: list[dict[str, Any]] = field(default_factory=list)
    enrichment_status: str = "not_run"

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
