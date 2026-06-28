"""Inlined shared helpers for vigil_forensic.

Contains copies/extracts of:
  - SYSTEM.shared_helpers.gate_models        (enums + dataclasses)
  - SYSTEM.shared_helpers.coerce_helpers     (coerce_float etc.)
  - SYSTEM.shared_helpers.file_lock          (acquire_file_lock)
  - SYSTEM.shared_helpers.redaction          (FORBIDDEN_KEYS + helpers)
  - SYSTEM.execution.executor_contract       (is_executor_metadata_path)
  - SYSTEM.shared_helpers.file_extensions    (WINDOWS_CLI_RUNTIME_EXTENSIONS)

All stdlib only — no BRAIN/SYSTEM/INTERFACE imports.
"""
from __future__ import annotations

# ---------------------------------------------------------------------------
# coerce_helpers
# ---------------------------------------------------------------------------
from collections.abc import Mapping as _Mapping
from typing import Any

import contextlib
import hashlib
import json
import logging
import os
import re
import sys
import time
import threading
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Generator, Optional


def coerce_int(value: object, default: int = 0) -> int:
    if isinstance(value, bool):
        return int(value)
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        return int(value)
    if isinstance(value, str):
        try:
            return int(value)
        except ValueError:
            return default
    return default


def coerce_float(value: object, default: float = 0.0) -> float:
    if isinstance(value, bool):
        return float(value)
    if isinstance(value, (int, float)):
        return float(value)
    if isinstance(value, str):
        try:
            return float(value)
        except ValueError:
            return default
    return default


def coerce_str(value: Any) -> str:
    return str(value) if value is not None else ""


def coerce_str_tuple(value: Any) -> tuple[str, ...]:
    if value is None:
        return ()
    if isinstance(value, (list, tuple)):
        return tuple(str(item) for item in value if item is not None)
    return ()


def coerce_dict(value: Any) -> dict[str, object]:
    if isinstance(value, dict):
        return dict(value)
    return {}


def collect_extras(
    data: _Mapping[str, object],
    known_keys: frozenset[str],
) -> tuple[tuple[str, object], ...]:
    extras = [(key, value) for key, value in data.items() if key not in known_keys]
    extras.sort(key=lambda item: item[0])
    return tuple(extras)


# ---------------------------------------------------------------------------
# file_lock
# ---------------------------------------------------------------------------

_flock_log = logging.getLogger(__name__ + ".file_lock")


@contextlib.contextmanager
def acquire_file_lock(
    lock_path: Path,
    *,
    timeout: float = 5.0,
    retry_interval: float = 0.05,
) -> Generator[None, None, None]:
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    fd: int | None = None
    deadline = time.monotonic() + timeout
    try:
        fd = os.open(str(lock_path), os.O_CREAT | os.O_RDWR)
        if sys.platform == "win32":
            import msvcrt
            while True:
                try:
                    msvcrt.locking(fd, msvcrt.LK_NBLCK, 1)
                    break
                except (OSError, IOError):
                    if time.monotonic() >= deadline:
                        raise TimeoutError(
                            f"Could not acquire file lock at {lock_path} "
                            f"within {timeout}s"
                        )
                    time.sleep(retry_interval)
        else:
            import fcntl
            while True:
                try:
                    fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    break
                except (OSError, IOError):
                    if time.monotonic() >= deadline:
                        raise TimeoutError(
                            f"Could not acquire file lock at {lock_path} "
                            f"within {timeout}s"
                        )
                    time.sleep(retry_interval)
        yield
    finally:
        if fd is not None:
            if sys.platform == "win32":
                import msvcrt
                try:
                    msvcrt.locking(fd, msvcrt.LK_UNLCK, 1)
                except (OSError, IOError):
                    _flock_log.warning("acquire_file_lock: failed to unlock fd", exc_info=True)
            else:
                import fcntl
                try:
                    fcntl.flock(fd, fcntl.LOCK_UN)
                except (OSError, IOError):
                    _flock_log.warning("acquire_file_lock: failed to unlock fd", exc_info=True)
            os.close(fd)


# ---------------------------------------------------------------------------
# redaction
# ---------------------------------------------------------------------------

FORBIDDEN_KEYS: frozenset[str] = frozenset({
    "api_key", "apikey", "authorization", "token", "access_token",
    "refresh_token", "password", "passwd", "secret", "private_key",
    "cookie", "session", "set-cookie", "x-api-key", "bearer",
    "prompt", "full_prompt", "raw_context", "private_context",
})

REDACTED_PLACEHOLDER = "[REDACTED]"
MAX_PREVIEW_CHARS = 200

_BEARER_RE = re.compile(r"\bBearer\s+\S+", re.IGNORECASE)
_AKID_RE = re.compile(r"\bAKIA[0-9A-Z]{16}\b")
_TOKEN_LIKE_RE = re.compile(r"\b(?:sk-|gh[pousr]_|xox[abps]-)\w{16,}\b")


def truncate_preview(text: object, *, max_chars: int = MAX_PREVIEW_CHARS) -> str:
    s = str(text)
    if len(s) <= max_chars:
        return s
    return s[: max_chars - 3] + "..."


def hash_payload(payload: object) -> str:
    try:
        canonical = json.dumps(payload, sort_keys=True, default=str)
    except (TypeError, ValueError):
        canonical = repr(payload)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()[:16]


def safe_command(cmd: object) -> str:
    if isinstance(cmd, (list, tuple)) and cmd:
        return str(cmd[0])
    if isinstance(cmd, str):
        parts = cmd.split()
        return parts[0] if parts else REDACTED_PLACEHOLDER
    return REDACTED_PLACEHOLDER


def safe_path(path: object) -> str:
    s = str(path).replace("\\", "/")
    parts = [p for p in s.split("/") if p]
    if len(parts) >= 2:
        return ".../" + "/".join(parts[-2:])
    return s or REDACTED_PLACEHOLDER


def safe_url(url: object) -> str:
    s = str(url)
    if "://" not in s:
        return REDACTED_PLACEHOLDER
    scheme, rest = s.split("://", 1)
    host = rest.split("/", 1)[0].split("?", 1)[0].split("#", 1)[0]
    if "@" in host:
        host = host.rsplit("@", 1)[1]
    return f"{scheme}://{host}"


def safe_error(exc: BaseException) -> dict[str, str]:
    return {"error_type": type(exc).__name__, "error_message": truncate_preview(str(exc))}


def redact_dict(payload: _Mapping[str, Any]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for k, v in payload.items():
        if str(k).lower() in FORBIDDEN_KEYS:
            out[k] = REDACTED_PLACEHOLDER
            continue
        if isinstance(v, _Mapping):
            out[k] = redact_dict(v)
        elif isinstance(v, (list, tuple)):
            out[k] = [
                redact_dict(item) if isinstance(item, _Mapping) else _scrub_value(item)
                for item in v
            ]
        else:
            out[k] = _scrub_value(v)
    return out


def _scrub_value(v: object) -> object:
    if not isinstance(v, str):
        return v
    if _BEARER_RE.search(v):
        return _BEARER_RE.sub(REDACTED_PLACEHOLDER, v)
    if _AKID_RE.search(v):
        return _AKID_RE.sub(REDACTED_PLACEHOLDER, v)
    if _TOKEN_LIKE_RE.search(v):
        return _TOKEN_LIKE_RE.sub(REDACTED_PLACEHOLDER, v)
    return v


# ---------------------------------------------------------------------------
# executor_contract helpers
# ---------------------------------------------------------------------------

METADATA_PREFIXES = (".a1/", ".cortex/", ".claude/", ".prompt-engineer/")


def is_executor_metadata_path(path: str) -> bool:
    normalized = str(path or "").strip().replace("\\", "/")
    return any(normalized.startswith(prefix) for prefix in METADATA_PREFIXES)


# ---------------------------------------------------------------------------
# file_extensions
# ---------------------------------------------------------------------------

WINDOWS_CLI_RUNTIME_EXTENSIONS: frozenset[str] = frozenset({
    ".bash", ".bat", ".cmd", ".cs", ".go", ".java",
    ".ps1", ".psm1", ".py", ".rs", ".sh",
})

BINARY_EXTENSIONS: frozenset[str] = frozenset({
    ".dll", ".eot", ".exe", ".gif", ".ico", ".jpeg", ".jpg",
    ".png", ".pyc", ".pyo", ".so", ".ttf", ".woff", ".woff2",
})

SOURCE_EXTENSIONS: frozenset[str] = frozenset({
    ".cs", ".go", ".java", ".js", ".jsx", ".py", ".rb", ".rs", ".ts", ".tsx",
})


# ---------------------------------------------------------------------------
# gate_models (vocabulary types)  — copied from the Vigil shared_helpers.gate_models
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
    ML = "ml_correctness"


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
            raise ValueError(f"GateFinding.confidence must be in [0.0, 1.0], got {self.confidence!r}")
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
            "evidence": [item.to_dict() for item in self.evidence],
            "fingerprint": self.fingerprint,
            "repair_kind": self.repair_kind,
            "executor_action": self.executor_action,
            "proof_required": self.proof_required,
            "allowlist_allowed": self.allowlist_allowed,
            "preferred_fix_shape": self.preferred_fix_shape,
            "confidence": self.confidence,
            "applicability": self.applicability,
            "analysis_mode": self.analysis_mode,
            "applicability_reason": self.applicability_reason,
        }


@dataclass(frozen=True)
class GateCheckResult:
    check_id: str
    category: GateCategory
    findings: tuple[GateFinding, ...] = field(default_factory=tuple)
    notes: tuple[str, ...] = field(default_factory=tuple)

    def to_dict(self) -> dict[str, Any]:
        return {
            "check_id": self.check_id,
            "category": self.category.value,
            "findings": [item.to_dict() for item in self.findings],
            "notes": list(self.notes),
        }


@dataclass(frozen=True)
class GateFileSnapshot:
    path: str
    exists: bool
    size: int
    line_count: int
    text: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "path": self.path,
            "exists": self.exists,
            "size": self.size,
            "line_count": self.line_count,
        }


@dataclass(frozen=True)
class RepoGateProfile:
    profile_name: str
    version: str
    generated_roots: tuple[str, ...] = field(default_factory=tuple)
    vendored_roots: tuple[str, ...] = field(default_factory=tuple)
    forbidden_roots: tuple[str, ...] = field(default_factory=tuple)
    critical_roots: tuple[str, ...] = field(default_factory=tuple)
    allowlisted_large_files: tuple[str, ...] = field(default_factory=tuple)
    performance_sensitive_roots: tuple[str, ...] = field(default_factory=tuple)
    required_test_roots: tuple[str, ...] = field(default_factory=tuple)
    canonical_literal_owners: dict[str, tuple[str, ...]] = field(default_factory=dict)
    forbidden_fallback_patterns: dict[str, GateImpact] = field(default_factory=dict)
    size_thresholds: dict[str, int] = field(default_factory=dict)
    severity_overrides: dict[str, GateImpact] = field(default_factory=dict)
    required_proofs_overrides: dict[str, tuple[str, ...]] = field(default_factory=dict)
    reporting_required_artifacts: tuple[str, ...] = field(default_factory=tuple)
    enabled_categories: tuple[GateCategory, ...] = field(default_factory=lambda: tuple(GateCategory))
    enabled_checks: tuple[str, ...] = field(default_factory=tuple)
    disabled_checks: tuple[str, ...] = field(default_factory=tuple)
    profile_path: str = ""

    def is_generated_or_vendored(self, path: str) -> bool:
        return _starts_with_any(path, self.generated_roots + self.vendored_roots)

    def is_critical(self, path: str) -> bool:
        return _starts_with_any(path, self.critical_roots)

    def is_performance_sensitive(self, path: str) -> bool:
        return _starts_with_any(path, self.performance_sensitive_roots)

    def to_dict(self) -> dict[str, Any]:
        return {
            "profile_name": self.profile_name,
            "version": self.version,
            "generated_roots": list(self.generated_roots),
            "vendored_roots": list(self.vendored_roots),
            "forbidden_roots": list(self.forbidden_roots),
            "critical_roots": list(self.critical_roots),
            "allowlisted_large_files": list(self.allowlisted_large_files),
            "performance_sensitive_roots": list(self.performance_sensitive_roots),
            "required_test_roots": list(self.required_test_roots),
            "canonical_literal_owners": {k: list(v) for k, v in self.canonical_literal_owners.items()},
            "forbidden_fallback_patterns": {k: v.value for k, v in self.forbidden_fallback_patterns.items()},
            "size_thresholds": self.size_thresholds,
            "severity_overrides": {k: v.value for k, v in self.severity_overrides.items()},
            "required_proofs_overrides": {k: list(v) for k, v in self.required_proofs_overrides.items()},
            "reporting_required_artifacts": list(self.reporting_required_artifacts),
            "enabled_categories": [item.value for item in self.enabled_categories],
            "enabled_checks": list(self.enabled_checks),
            "disabled_checks": list(self.disabled_checks),
            "profile_path": self.profile_path,
        }


def _starts_with_any(path: str, prefixes: tuple[str, ...]) -> bool:
    normalized = path.replace("\\", "/").lstrip("./")
    return any(
        normalized == prefix or normalized.startswith(prefix.rstrip("/") + "/")
        for prefix in prefixes
    )
