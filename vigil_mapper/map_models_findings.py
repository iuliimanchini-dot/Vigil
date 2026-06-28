"""Data models for findings map (Map 8).

Finding -- synthesized diagnosis of architecture/conflict issues across all maps.
"""
from __future__ import annotations

import sys
import logging
from dataclasses import dataclass
from typing import Any

__all__ = [
    "EvidenceItem",
    "Finding",
]

_log = logging.getLogger(__name__)

_DATACLASS_KWARGS: dict[str, Any] = {"frozen": True}
if sys.version_info >= (3, 10):
    _DATACLASS_KWARGS["slots"] = True
    _DATACLASS_KWARGS["kw_only"] = True


# ---------------------------------------------------------------------------
# Map 8: Finding Entry
# ---------------------------------------------------------------------------

@dataclass(**_DATACLASS_KWARGS)
class EvidenceItem:
    """Evidence pointing to a source of the finding."""
    kind: str                      # "source_location" | "map_entry" | "target_path"
    file: str = ""                 # for source_location
    line: int | None = None        # for source_location
    map: str = ""                  # for map_entry or source_location
    entry_id: str = ""             # for map_entry
    path: str = ""                 # for target_path

    def to_dict(self) -> dict:
        result = {"kind": self.kind}
        if self.file:
            result["file"] = self.file
        if self.line is not None:
            result["line"] = self.line
        if self.map:
            result["map"] = self.map
        if self.entry_id:
            result["entry_id"] = self.entry_id
        if self.path:
            result["path"] = self.path
        return result

    @classmethod
    def from_dict(cls, d: dict) -> "EvidenceItem":
        return cls(
            kind=str(d.get("kind", "unknown")),
            file=str(d.get("file", "")),
            line=d.get("line"),
            map=str(d.get("map", "")),
            entry_id=str(d.get("entry_id", "")),
            path=str(d.get("path", "")),
        )


@dataclass(**_DATACLASS_KWARGS)
class Finding:
    """One finding in the findings map (Map 8)."""
    finding_id: str                        # stable hash of finding
    category: str                          # architecture_cycle | state_ownership_conflict |
                                          # schema_drift_risk | runtime_config_risk |
                                          # write_authority_violation
    title: str
    severity: str                          # critical | high | medium | low
    confidence: float
    why_it_matters: str
    suggested_fix: str
    affected_files: tuple[str, ...]
    evidence: tuple[str, ...]              # JSON-serialised EvidenceItem strings
    source_maps: tuple[str, ...]           # which maps contributed to this finding
    finding_status: str                    # new | existing | worsened | resolved | accepted
    # Metadata
    source: str
    freshness: str
    status: str

    def to_dict(self) -> dict:
        import json as _json
        return {
            "finding_id": self.finding_id,
            "category": self.category,
            "title": self.title,
            "severity": self.severity,
            "confidence": self.confidence,
            "why_it_matters": self.why_it_matters,
            "suggested_fix": self.suggested_fix,
            "affected_files": list(self.affected_files),
            "evidence": [
                _json.loads(e) if isinstance(e, str) else e for e in self.evidence
            ],
            "source_maps": list(self.source_maps),
            "finding_status": self.finding_status,
            "source": self.source,
            "freshness": self.freshness,
            "status": self.status,
        }

    @classmethod
    def from_dict(cls, d: dict) -> "Finding":
        import json as _json
        def _serialize_evidence(items: list) -> tuple[str, ...]:
            return tuple(
                _json.dumps(item, sort_keys=True) if isinstance(item, dict) else str(item)
                for item in items
            )
        return cls(
            finding_id=str(d.get("finding_id", "")),
            category=str(d.get("category", "")),
            title=str(d.get("title", "")),
            severity=str(d.get("severity", "medium")),
            confidence=float(d.get("confidence", 0.5)),
            why_it_matters=str(d.get("why_it_matters", "")),
            suggested_fix=str(d.get("suggested_fix", "")),
            affected_files=tuple(d.get("affected_files", [])),
            evidence=_serialize_evidence(d.get("evidence", [])),
            source_maps=tuple(d.get("source_maps", [])),
            finding_status=str(d.get("finding_status", "new")),
            source=str(d.get("source", "synthesis")),
            freshness=str(d.get("freshness", "")),
            status=str(d.get("status", "validated")),
        )
