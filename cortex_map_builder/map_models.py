"""Data models for the map builder subsystem -- Maps 1-4 + envelope + container.

Seven frozen dataclasses (one per map) + MapMetadata envelope + RepoMaps container.
Each dataclass implements to_dict() / from_dict() for JSON round-trip.

Maps 5-7 (ConflictEntry, HotspotEntry, RefactorBoundary) are in map_models_ext.py.

Python 3.11 -> slots=True, kw_only=True supported.
"""
from __future__ import annotations

import sys
import logging
from dataclasses import dataclass, field
from typing import Any, Literal

__all__ = [
    "BuildMeta",
    "MapMetadata",
    "StructuralEntry",
    "RuntimeNode",
    "DataContractEntry",
    "AuthorityDomain",
    "ConflictEntry",
    "HotspotEntry",
    "RefactorBoundary",
    "Finding",
    "RepoMaps",
]

_log = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# BuildMeta — per-map build provenance (schema v2.0.0)
# ---------------------------------------------------------------------------

@dataclass
class BuildMeta:
    """Build provenance metadata for one map payload (schema v2.0.0).

    NOT frozen -- constructed incrementally in cli_entry._build_build_meta().
    """
    analysis_mode: str   # "python_ast" | "regex_signals" | "seed_only" | "derived" | "unsupported"
    status: str          # "ok" | "partial" | "unsupported"
    reason: str          # human-readable; empty string if status="ok"
    confidence_avg: float
    coverage: dict       # {"files_scanned_by_lang": {...}, "files_supported_by_lang": {...}, "coverage_ratio": float}
    producer: str        # "BRAIN.autoforensics.map_builder.<module>"
    built_at: str        # ISO8601 UTC Z-suffix
    duration_s: float
    # Phase 5.2: representative sample of files with no coverage for this map.
    # 5-10 entries; empty list when all scanned files are supported (coverage_ratio=1.0)
    # or when the caller does not populate the field (backward compat).
    unsupported_files_sample: list = field(default_factory=list)

    def to_dict(self) -> dict:
        # NOTE: "built_at" and "build_duration_s" are in semantic_diff._IGNORED_FIELDS
        # and will be stripped during I2 semantic comparisons, keeping builds deterministic.
        # The key is "build_duration_s" (not "duration_s") so it matches _IGNORED_FIELDS.
        return {
            "analysis_mode": self.analysis_mode,
            "build_duration_s": self.duration_s,
            "built_at": self.built_at,
            "confidence_avg": self.confidence_avg,
            "coverage": self.coverage,
            "producer": self.producer,
            "reason": self.reason,
            "status": self.status,
            "unsupported_files_sample": list(self.unsupported_files_sample),
        }

    @classmethod
    def from_dict(cls, d: dict) -> "BuildMeta":
        """Deserialise from a payload dict.

        Backward-compat: if ``d`` is missing any required field (old v1.0.0
        payload without build_meta), returns a sentinel with sensible defaults.
        "build_duration_s" is the canonical key in the payload; "duration_s"
        is accepted as a fallback for any pre-canonical payloads.
        "unsupported_files_sample" defaults to [] for pre-Phase-5 payloads.
        """
        return cls(
            analysis_mode=str(d.get("analysis_mode", "python_ast")),
            status=str(d.get("status", "ok")),
            reason=str(d.get("reason", "")),
            confidence_avg=float(d.get("confidence_avg", 1.0)),
            coverage=dict(d.get("coverage", {
                "files_scanned_by_lang": {},
                "files_supported_by_lang": {},
                "coverage_ratio": 0.0,
            })),
            producer=str(d.get("producer", "BRAIN.autoforensics.map_builder.unknown")),
            built_at=str(d.get("built_at", "")),
            # Accept both "build_duration_s" (canonical) and legacy "duration_s".
            duration_s=float(
                d.get("build_duration_s", d.get("duration_s", 0.0))
            ),
            unsupported_files_sample=list(d.get("unsupported_files_sample", [])),
        )


# Re-export Maps 5-7 from the extension module so callers can import all
# models from a single location: `from .map_models import ConflictEntry`.
from .map_models_ext import ConflictEntry, HotspotEntry, RefactorBoundary  # noqa: E402

# Re-export Map 8 (Finding) from findings module
from .map_models_findings import Finding  # noqa: E402

# Python 3.10+ supports slots + kw_only in @dataclass
_DATACLASS_KWARGS: dict[str, Any] = {"frozen": True}
if sys.version_info >= (3, 10):
    _DATACLASS_KWARGS["slots"] = True
    _DATACLASS_KWARGS["kw_only"] = True


# ---------------------------------------------------------------------------
# MapMetadata envelope (embedded in every entry)
# ---------------------------------------------------------------------------

@dataclass(**_DATACLASS_KWARGS)
class MapMetadata:
    """Common metadata envelope for all map entries."""
    source: str
    evidence: tuple[str, ...]
    confidence: float
    freshness: str  # ISO8601 UTC Z-suffix
    status: Literal["observed", "inferred", "validated", "canonical", "deprecated"]

    def to_dict(self) -> dict:
        return {
            "source": self.source,
            "evidence": list(self.evidence),
            "confidence": self.confidence,
            "freshness": self.freshness,
            "status": self.status,
        }

    @classmethod
    def from_dict(cls, d: dict) -> "MapMetadata":
        return cls(
            source=str(d["source"]),
            evidence=tuple(d.get("evidence", [])),
            confidence=float(d["confidence"]),
            freshness=str(d["freshness"]),
            status=d["status"],  # type: ignore[arg-type]
        )


# ---------------------------------------------------------------------------
# Map 1: Structural Entry
# ---------------------------------------------------------------------------

@dataclass(**_DATACLASS_KWARGS)
class StructuralEntry:
    """One entry in the structural map -- represents a single Python file."""
    file: str
    language: str
    size_lines: int
    imports_out: tuple[str, ...]
    imports_in: tuple[str, ...]
    symbols_defined: tuple[str, ...]
    symbols_used_external: tuple[str, ...]
    cycles: tuple[str, ...]
    tags: tuple[str, ...]
    # Metadata fields (flattened for storage)
    source: str
    evidence: tuple[str, ...]
    confidence: float
    freshness: str
    status: str

    def to_dict(self) -> dict:
        return {
            "file": self.file,
            "language": self.language,
            "size_lines": self.size_lines,
            "imports_out": list(self.imports_out),
            "imports_in": list(self.imports_in),
            "symbols_defined": list(self.symbols_defined),
            "symbols_used_external": list(self.symbols_used_external),
            "cycles": list(self.cycles),
            "tags": list(self.tags),
            "source": self.source,
            "evidence": list(self.evidence),
            "confidence": self.confidence,
            "freshness": self.freshness,
            "status": self.status,
        }

    @classmethod
    def from_dict(cls, d: dict) -> "StructuralEntry":
        return cls(
            file=str(d["file"]),
            language=str(d.get("language", "python")),
            size_lines=int(d["size_lines"]),
            imports_out=tuple(d.get("imports_out", [])),
            imports_in=tuple(d.get("imports_in", [])),
            symbols_defined=tuple(d.get("symbols_defined", [])),
            symbols_used_external=tuple(d.get("symbols_used_external", [])),
            cycles=tuple(d.get("cycles", [])),
            tags=tuple(d.get("tags", [])),
            source=str(d.get("source", "static_scan")),
            evidence=tuple(d.get("evidence", [])),
            confidence=float(d.get("confidence", 0.9)),
            freshness=str(d.get("freshness", "")),
            status=str(d.get("status", "observed")),
        )


# ---------------------------------------------------------------------------
# Map 2: Runtime Node
# ---------------------------------------------------------------------------

@dataclass(**_DATACLASS_KWARGS)
class RuntimeNode:
    """One node in the runtime map -- represents a runtime entry point or service."""
    node: str
    defined_in: str
    kind: str
    calls: tuple[str, ...]
    side_effects: tuple[str, ...]
    depends_on_env: tuple[str, ...]
    order_constraints: tuple[str, ...]
    hidden_runtime_dependencies: tuple[str, ...]
    tags: tuple[str, ...]
    # Metadata
    source: str
    evidence: tuple[str, ...]
    confidence: float
    freshness: str
    status: str

    def to_dict(self) -> dict:
        return {
            "node": self.node,
            "defined_in": self.defined_in,
            "kind": self.kind,
            "calls": list(self.calls),
            "side_effects": list(self.side_effects),
            "depends_on_env": list(self.depends_on_env),
            "order_constraints": list(self.order_constraints),
            "hidden_runtime_dependencies": list(self.hidden_runtime_dependencies),
            "tags": list(self.tags),
            "source": self.source,
            "evidence": list(self.evidence),
            "confidence": self.confidence,
            "freshness": self.freshness,
            "status": self.status,
        }

    @classmethod
    def from_dict(cls, d: dict) -> "RuntimeNode":
        return cls(
            node=str(d["node"]),
            defined_in=str(d["defined_in"]),
            kind=str(d.get("kind", "unknown")),
            calls=tuple(d.get("calls", [])),
            side_effects=tuple(d.get("side_effects", [])),
            depends_on_env=tuple(d.get("depends_on_env", [])),
            order_constraints=tuple(d.get("order_constraints", [])),
            hidden_runtime_dependencies=tuple(d.get("hidden_runtime_dependencies", [])),
            tags=tuple(d.get("tags", [])),
            source=str(d.get("source", "static_scan")),
            evidence=tuple(d.get("evidence", [])),
            confidence=float(d.get("confidence", 0.8)),
            freshness=str(d.get("freshness", "")),
            status=str(d.get("status", "inferred")),
        )


# ---------------------------------------------------------------------------
# Map 3: Data Contract Entry
# ---------------------------------------------------------------------------

@dataclass(**_DATACLASS_KWARGS)
class DataContractEntry:
    """One entity in the data contract map."""
    entity: str
    canonical_schema: str
    variants: tuple[str, ...]          # JSON-serialised variant dicts as strings
    transformations: tuple[str, ...]   # JSON-serialised transformation dicts as strings
    writers: tuple[str, ...]
    readers: tuple[str, ...]
    drift_flags: tuple[str, ...]
    # Metadata
    source: str
    evidence: tuple[str, ...]
    confidence: float
    freshness: str
    status: str

    def to_dict(self) -> dict:
        import json as _json
        return {
            "entity": self.entity,
            "canonical_schema": self.canonical_schema,
            "variants": [_json.loads(v) if isinstance(v, str) else v for v in self.variants],
            "transformations": [_json.loads(t) if isinstance(t, str) else t for t in self.transformations],
            "writers": list(self.writers),
            "readers": list(self.readers),
            "drift_flags": list(self.drift_flags),
            "source": self.source,
            "evidence": list(self.evidence),
            "confidence": self.confidence,
            "freshness": self.freshness,
            "status": self.status,
        }

    @classmethod
    def from_dict(cls, d: dict) -> "DataContractEntry":
        import json as _json
        def _serialize(items: list) -> tuple[str, ...]:
            return tuple(
                _json.dumps(item, sort_keys=True) if isinstance(item, dict) else str(item)
                for item in items
            )
        return cls(
            entity=str(d["entity"]),
            canonical_schema=str(d.get("canonical_schema", "")),
            variants=_serialize(d.get("variants", [])),
            transformations=_serialize(d.get("transformations", [])),
            writers=tuple(d.get("writers", [])),
            readers=tuple(d.get("readers", [])),
            drift_flags=tuple(d.get("drift_flags", [])),
            source=str(d.get("source", "static_scan")),
            evidence=tuple(d.get("evidence", [])),
            confidence=float(d.get("confidence", 0.9)),
            freshness=str(d.get("freshness", "")),
            status=str(d.get("status", "observed")),
        )


# ---------------------------------------------------------------------------
# Map 4: Authority Domain
# ---------------------------------------------------------------------------

@dataclass(**_DATACLASS_KWARGS)
class AuthorityDomain:
    """One domain in the authority map."""
    authority_domain: str
    canonical_owner: str
    allowed_writers: tuple[str, ...]
    derived_readers: tuple[str, ...]
    cache_layers: tuple[str, ...]
    freshness_sla: str
    invalidation_rule: str
    drift_policy: str
    writers_detected: tuple[str, ...]  # JSON-serialised dicts as strings
    last_drift_events: tuple[str, ...]
    # Metadata
    source: str
    evidence: tuple[str, ...]
    confidence: float
    freshness: str
    status: str
    # Per-domain target file patterns for auto-discovery filtering.
    # Glob patterns (fnmatch style) that a write call's resolved target must
    # match for the writer to be attributed to this domain.
    # Empty tuple → no auto-discovery (only seed-based allowed_writers remain).
    target_file_patterns: tuple[str, ...] = ()

    def to_dict(self) -> dict:
        import json as _json
        return {
            "authority_domain": self.authority_domain,
            "canonical_owner": self.canonical_owner,
            "allowed_writers": list(self.allowed_writers),
            "derived_readers": list(self.derived_readers),
            "cache_layers": list(self.cache_layers),
            "freshness_sla": self.freshness_sla,
            "invalidation_rule": self.invalidation_rule,
            "drift_policy": self.drift_policy,
            "writers_detected": [
                _json.loads(w) if isinstance(w, str) else w for w in self.writers_detected
            ],
            "last_drift_events": list(self.last_drift_events),
            "target_file_patterns": list(self.target_file_patterns),
            "source": self.source,
            "evidence": list(self.evidence),
            "confidence": self.confidence,
            "freshness": self.freshness,
            "status": self.status,
        }

    @classmethod
    def from_dict(cls, d: dict) -> "AuthorityDomain":
        import json as _json
        def _serialize(items: list) -> tuple[str, ...]:
            return tuple(
                _json.dumps(item, sort_keys=True) if isinstance(item, dict) else str(item)
                for item in items
            )
        return cls(
            authority_domain=str(d["authority_domain"]),
            canonical_owner=str(d.get("canonical_owner", "")),
            allowed_writers=tuple(d.get("allowed_writers", [])),
            derived_readers=tuple(d.get("derived_readers", [])),
            cache_layers=tuple(d.get("cache_layers", [])),
            freshness_sla=str(d.get("freshness_sla", "immediate")),
            invalidation_rule=str(d.get("invalidation_rule", "")),
            drift_policy=str(d.get("drift_policy", "fail_close")),
            writers_detected=_serialize(d.get("writers_detected", [])),
            last_drift_events=tuple(d.get("last_drift_events", [])),
            # Backward-compat: missing field → empty tuple (no auto-discovery)
            target_file_patterns=tuple(d.get("target_file_patterns", [])),
            source=str(d.get("source", "static_scan")),
            evidence=tuple(d.get("evidence", [])),
            confidence=float(d.get("confidence", 0.85)),
            freshness=str(d.get("freshness", "")),
            status=str(d.get("status", "observed")),
        )


# ---------------------------------------------------------------------------
# RepoMaps container (imports ext models lazily to avoid circular imports)
# ---------------------------------------------------------------------------

@dataclass(**_DATACLASS_KWARGS)
class RepoMaps:
    """Container for all 8 maps loaded from disk."""
    structural: tuple = field(default_factory=tuple)        # tuple[StructuralEntry, ...]
    runtime: tuple = field(default_factory=tuple)           # tuple[RuntimeNode, ...]
    data_contract: tuple = field(default_factory=tuple)     # tuple[DataContractEntry, ...]
    authority: tuple = field(default_factory=tuple)         # tuple[AuthorityDomain, ...]
    conflict: tuple = field(default_factory=tuple)          # tuple[ConflictEntry, ...]
    hotspot: tuple = field(default_factory=tuple)           # tuple[HotspotEntry, ...]
    refactor_boundary: tuple = field(default_factory=tuple) # tuple[RefactorBoundary, ...]
    findings: tuple = field(default_factory=tuple)          # tuple[Finding, ...] — Map 8
    missing: bool = False
    schema_version: str = "2.0.0"
