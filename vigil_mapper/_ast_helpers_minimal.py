"""Minimal inlined AST helpers — no cross-cluster imports.

Inlined from the originating modules in the parent app (pure stdlib, no external deps):
  - gate_models: GateFinding, EvidenceReference, enums
  - _ast_helpers: parse_python_source_or_emit_finding
"""
from __future__ import annotations

import ast
import hashlib
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Optional


# ---------------------------------------------------------------------------
# Gate model vocabulary (inlined — pure stdlib enums and dataclasses)
# ---------------------------------------------------------------------------

class GateVerdict(str, Enum):
    PASS = "pass"
    REVISE = "revise"
    BLOCK = "block"


class RepairKind(str, Enum):
    REFACTOR               = "refactor"
    CONSOLIDATE            = "consolidate"
    ADD_PROOF              = "add_proof"
    ADD_TEST               = "add_test"
    FIX_CONTRACT           = "fix_contract"
    REMOVE_FALLBACK        = "remove_fallback"
    SPLIT_MODULE           = "split_module"
    EXTRACT_SHARED         = "extract_shared"
    VALIDATE_BOUNDARY      = "validate_boundary"
    REMOVE_DUPLICATE       = "remove_duplicate"
    EDIT_CANONICAL         = "edit_canonical_module"
    ADD_BOUNDARY_CHECK     = "add_boundary_check"
    REPLACE_WITH_FAIL_LOUD = "replace_fallback_with_fail_loud"
    ADD_MISSING_PROOF      = "add_missing_proof"
    ADD_REGRESSION_TEST    = "add_regression_test"
    REMOVE_DEAD_SURFACE    = "remove_dead_surface"
    NORMALIZE_SHAPE        = "normalize_shape"
    FIX_ENCODING           = "fix_encoding_safety"
    INVESTIGATE_GATE_FAILURE = "investigate_gate_failure"
    FIX_SYNTAX             = "fix_syntax"


class GateSeverity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class GateImpact(str, Enum):
    WARN = "warn"
    REVISE = "revise"
    BLOCK = "block"


class GateCategory(str, Enum):
    CONTRACT = "contract_integrity"
    TRUTH_BOUNDARY = "truth_boundary"
    DRIFT = "drift"
    FALLBACK = "fallback_hack_workaround"
    DUPLICATION = "duplication_shadow_logic"
    CONFIG_SSOT = "config_ssot"
    RUNTIME_BEHAVIOR = "runtime_behavior"
    PERFORMANCE = "performance"
    SIZE_COMPLEXITY = "size_complexity"
    TESTING = "testing_anti_patterns"
    REPORTING = "reporting_artifact_integrity"
    PIPELINE_CHAIN = "pipeline_chain_integrity"
    SEMANTIC_INTENT = "semantic_intent"
    TEMPORAL_FRESHNESS = "temporal_freshness"
    TOOL_HOOK_COVERAGE = "tool_hook_coverage"
    META = "meta_integrity"
    OBSERVABILITY = "observability"


@dataclass(frozen=True)
class EvidenceReference:
    kind: str
    path: str = ""
    detail: str = ""
    ok: bool = True

    def to_dict(self) -> dict[str, Any]:
        return {"kind": self.kind, "path": self.path, "detail": self.detail, "ok": self.ok}


@dataclass(frozen=True)
class GateFinding:
    check_id: str
    category: GateCategory
    title: str
    severity: GateSeverity
    impact: GateImpact
    summary: str
    recommendation: str
    evidence: tuple[EvidenceReference, ...] = field(default_factory=tuple)
    fingerprint: str = ""
    repair_kind: str = ""
    executor_action: str = ""
    proof_required: str = ""
    allowlist_allowed: bool = True
    preferred_fix_shape: str = ""
    confidence: float = 1.0
    applicability: str = "applicable"
    analysis_mode: str = "heuristic"
    applicability_reason: str = ""

    def __post_init__(self) -> None:
        if not (0.0 <= float(self.confidence) <= 1.0):
            raise ValueError(
                f"GateFinding.confidence must be in [0.0, 1.0], got {self.confidence!r}"
            )
        if self.applicability not in ("applicable", "not_applicable", "unknown"):
            raise ValueError(
                f"GateFinding.applicability must be one of "
                f"{{applicable, not_applicable, unknown}}, got {self.applicability!r}"
            )
        if self.applicability != "applicable" and not (self.applicability_reason or "").strip():
            raise ValueError(
                f"GateFinding.applicability_reason is required when applicability != 'applicable' "
                f"(applicability={self.applicability!r}, check_id={self.check_id!r})"
            )

    def to_dict(self) -> dict[str, Any]:
        return {
            "check_id": self.check_id,
            "category": self.category.value,
            "title": self.title,
            "severity": self.severity.value,
            "impact": self.impact.value,
            "summary": self.summary,
            "recommendation": self.recommendation,
            "evidence": [e.to_dict() for e in self.evidence],
            "fingerprint": self.fingerprint,
        }


# ---------------------------------------------------------------------------
# parse_python_source_or_emit_finding (inlined from _ast_helpers.py)
# ---------------------------------------------------------------------------

_PYTHON_EXTENSIONS: frozenset[str] = frozenset({".py", ".pyi"})


def _looks_like_python_path(rel_path: str) -> bool:
    if not rel_path:
        return False
    normalized = rel_path.replace("\\", "/").lower()
    dot = normalized.rfind(".")
    if dot < 0:
        return False
    return normalized[dot:] in _PYTHON_EXTENSIONS


def build_syntax_parse_error_finding(
    *,
    rel_path: str,
    exc: SyntaxError,
    emitting_gate: str = "",
) -> GateFinding:
    line_info = f"line {exc.lineno}" if exc.lineno else "unknown line"
    msg = str(exc.msg) if exc.msg else "unknown parse error"
    evidence = (
        EvidenceReference(
            kind="syntax_error",
            path=rel_path,
            detail=f"{line_info}: {msg}"[:512],
        ),
    )
    fp_source = f"meta.syntax_parse_error|{rel_path}|{exc.lineno}"
    fingerprint = hashlib.sha256(fp_source.encode("utf-8")).hexdigest()[:16]
    emitter_tag = f" [emitted by {emitting_gate}]" if emitting_gate else ""
    return GateFinding(
        check_id="meta.syntax_parse_error",
        category=GateCategory.META,
        title=f"Python syntax error in {rel_path} ({line_info})",
        severity=GateSeverity.HIGH,
        impact=GateImpact.REVISE,
        summary=(
            f"{rel_path}:{exc.lineno}: {msg}. Autoforensics gate could not "
            f"parse this file and skipped its checks for this path.{emitter_tag}"
        ),
        recommendation=(
            "Fix the Python syntax error so gates can parse and audit this "
            "file. A silent skip hides real bugs from the audit."
        ),
        evidence=evidence,
        fingerprint=fingerprint,
        repair_kind=RepairKind.FIX_SYNTAX.value,
        executor_action="fix Python syntax error",
        proof_required="ast.parse succeeds on the file",
        allowlist_allowed=False,
        preferred_fix_shape="restore valid Python grammar; do not silence via except",
    )


def parse_python_source_or_emit_finding(
    source: str,
    *,
    rel_path: str,
    emit_finding: Optional[Callable[[GateFinding], None]] = None,
    emitting_gate: str = "",
    filename: str | None = None,
) -> ast.Module | None:
    """Parse Python source and return the AST module, or emit a meta finding."""
    if not source:
        return None
    try:
        return ast.parse(source, filename=filename or rel_path or "<unknown>")
    except SyntaxError as exc:
        if emit_finding is not None and _looks_like_python_path(rel_path):
            try:
                emit_finding(
                    build_syntax_parse_error_finding(
                        rel_path=rel_path,
                        exc=exc,
                        emitting_gate=emitting_gate,
                    )
                )
            except Exception:
                pass
        return None
