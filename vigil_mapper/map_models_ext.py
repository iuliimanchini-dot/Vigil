"""Data models for the map builder subsystem -- Maps 5-7.

Continuation of map_models.py:
    ConflictEntry  -- Map 5: Conflict Map
    HotspotEntry   -- Map 6: Hotspot Map
    RefactorBoundary -- Map 7: Refactor Boundary Map
"""
from __future__ import annotations

import sys
import logging
from dataclasses import dataclass
from typing import Any

__all__ = [
    "ConflictEntry",
    "HotspotEntry",
    "RefactorBoundary",
]

_log = logging.getLogger(__name__)

_DATACLASS_KWARGS: dict[str, Any] = {"frozen": True}
if sys.version_info >= (3, 10):
    _DATACLASS_KWARGS["slots"] = True
    _DATACLASS_KWARGS["kw_only"] = True


# ---------------------------------------------------------------------------
# Map 5: Conflict Entry
# ---------------------------------------------------------------------------

@dataclass(**_DATACLASS_KWARGS)
class ConflictEntry:
    """One conflict entry in the conflict map."""
    conflict_id: str
    domain: str
    subject: str
    sources: tuple[str, ...]   # JSON-serialised source dicts as strings
    severity: str              # low / medium / high / critical
    conflict_status: str       # open / in_progress / resolved
    action: str
    # Metadata
    source: str
    evidence: tuple[str, ...]
    confidence: float
    freshness: str
    status: str

    def to_dict(self) -> dict:
        import json as _json
        return {
            "conflict_id": self.conflict_id,
            "domain": self.domain,
            "subject": self.subject,
            "sources": [
                _json.loads(s) if isinstance(s, str) else s for s in self.sources
            ],
            "severity": self.severity,
            "conflict_status": self.conflict_status,
            "action": self.action,
            "source": self.source,
            "evidence": list(self.evidence),
            "confidence": self.confidence,
            "freshness": self.freshness,
            "status": self.status,
        }

    @classmethod
    def from_dict(cls, d: dict) -> "ConflictEntry":
        import json as _json
        def _serialize(items: list) -> tuple[str, ...]:
            return tuple(
                _json.dumps(item, sort_keys=True) if isinstance(item, dict) else str(item)
                for item in items
            )
        return cls(
            conflict_id=str(d["conflict_id"]),
            domain=str(d.get("domain", "")),
            subject=str(d.get("subject", "")),
            sources=_serialize(d.get("sources", [])),
            severity=str(d.get("severity", "medium")),
            conflict_status=str(d.get("conflict_status", "open")),
            action=str(d.get("action", "investigate")),
            source=str(d.get("source", "inter_map_comparison")),
            evidence=tuple(d.get("evidence", [])),
            confidence=float(d.get("confidence", 0.9)),
            freshness=str(d.get("freshness", "")),
            status=str(d.get("status", "validated")),
        )


# ---------------------------------------------------------------------------
# Map 6: Hotspot Entry
# ---------------------------------------------------------------------------

@dataclass(**_DATACLASS_KWARGS)
class HotspotEntry:
    """One entry in the hotspot map."""
    target: str
    hotspot_score: int
    reasons: tuple[str, ...]
    recommended_mode: str
    # Metadata
    source: str
    evidence: tuple[str, ...]
    confidence: float
    freshness: str
    status: str

    def to_dict(self) -> dict:
        return {
            "target": self.target,
            "hotspot_score": self.hotspot_score,
            "reasons": list(self.reasons),
            "recommended_mode": self.recommended_mode,
            "source": self.source,
            "evidence": list(self.evidence),
            "confidence": self.confidence,
            "freshness": self.freshness,
            "status": self.status,
        }

    @classmethod
    def from_dict(cls, d: dict) -> "HotspotEntry":
        return cls(
            target=str(d["target"]),
            hotspot_score=int(d.get("hotspot_score", 0)),
            reasons=tuple(d.get("reasons", [])),
            recommended_mode=str(d.get("recommended_mode", "safe_refactor")),
            source=str(d.get("source", "automated_scoring")),
            evidence=tuple(d.get("evidence", [])),
            confidence=float(d.get("confidence", 0.88)),
            freshness=str(d.get("freshness", "")),
            status=str(d.get("status", "observed")),
        )


# ---------------------------------------------------------------------------
# Map 7: Refactor Boundary
# ---------------------------------------------------------------------------

@dataclass(**_DATACLASS_KWARGS)
class RefactorBoundary:
    """One refactor boundary entry."""
    boundary_id: str
    goal: str
    phase: str
    allowed_files: tuple[str, ...]
    watch_files: tuple[str, ...]
    forbidden_files: tuple[str, ...]
    entrypoints: tuple[str, ...]
    must_hold_invariants: tuple[str, ...]
    # Metadata
    source: str
    evidence: tuple[str, ...]
    confidence: float
    freshness: str
    status: str
    # FOC extension (Wave 1.6, schema 1.1 — additive, backwards compat preserved).
    # Defaults match pre-extension behaviour: any boundary loaded from an old
    # payload (no FOC keys) is treated as freely patchable by FOC.
    safe_auto_patch: bool = True
    suggest_only: bool = False
    forbidden_for_foc: bool = False

    def to_dict(self) -> dict:
        return {
            "boundary_id": self.boundary_id,
            "goal": self.goal,
            "phase": self.phase,
            "allowed_files": list(self.allowed_files),
            "watch_files": list(self.watch_files),
            "forbidden_files": list(self.forbidden_files),
            "entrypoints": list(self.entrypoints),
            "must_hold_invariants": list(self.must_hold_invariants),
            "source": self.source,
            "evidence": list(self.evidence),
            "confidence": self.confidence,
            "freshness": self.freshness,
            "status": self.status,
            "safe_auto_patch": self.safe_auto_patch,
            "suggest_only": self.suggest_only,
            "forbidden_for_foc": self.forbidden_for_foc,
        }

    @classmethod
    def from_dict(cls, d: dict) -> "RefactorBoundary":
        return cls(
            boundary_id=str(d["boundary_id"]),
            goal=str(d.get("goal", "")),
            phase=str(d.get("phase", "")),
            allowed_files=tuple(d.get("allowed_files", [])),
            watch_files=tuple(d.get("watch_files", [])),
            forbidden_files=tuple(d.get("forbidden_files", [])),
            entrypoints=tuple(d.get("entrypoints", [])),
            must_hold_invariants=tuple(d.get("must_hold_invariants", [])),
            source=str(d.get("source", "manual_planning")),
            evidence=tuple(d.get("evidence", [])),
            confidence=float(d.get("confidence", 1.0)),
            freshness=str(d.get("freshness", "")),
            status=str(d.get("status", "canonical")),
            safe_auto_patch=bool(d.get("safe_auto_patch", True)),
            suggest_only=bool(d.get("suggest_only", False)),
            forbidden_for_foc=bool(d.get("forbidden_for_foc", False)),
        )
