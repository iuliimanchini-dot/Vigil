"""Defensive meta-integrity findings collector for cortex_forensic.

Adapted from the Vigil autoforensics meta_findings.
All cluster gate_models imports rewritten to cortex_forensic._shared.
"""
from __future__ import annotations

import logging
import threading
from collections import deque
from typing import Any, Optional

from cortex_forensic._shared import (
    EvidenceReference,
    GateCategory,
    GateCheckResult,
    GateFinding,
    GateImpact,
    GateSeverity,
)

_log = logging.getLogger(__name__)

_pending: deque[GateFinding] = deque()
_lock = threading.Lock()

META_CHECK_SPECS: dict[str, dict[str, Any]] = {
    "meta.profile_load_failed": {
        "severity": GateSeverity.HIGH,
        "impact": GateImpact.WARN,
        "title": "Gate profile failed to load",
        "recommendation": (
            "Inspect the referenced profile/config file for JSON syntax errors or "
            "missing keys. Gates were executed WITHOUT profile context and may "
            "produce incomplete or misleading results."
        ),
    },
    "meta.git_unavailable": {
        "severity": GateSeverity.LOW,
        "impact": GateImpact.WARN,
        "title": "Git unavailable for --with-git audit",
        "recommendation": (
            "Install git and ensure the project directory is a git repository, "
            "or rerun the audit without --with-git. Git-dependent gates were "
            "skipped or produced incomplete findings."
        ),
    },
    "meta.artifact_corrupted": {
        "severity": GateSeverity.HIGH,
        "impact": GateImpact.WARN,
        "title": "Forensic artifact is corrupted (JSON decode failed)",
        "recommendation": (
            "The referenced .cortex artifact exists but could not be parsed. "
            "Inspect, repair or delete and rerun."
        ),
    },
    "meta.artifact_unreadable": {
        "severity": GateSeverity.HIGH,
        "impact": GateImpact.WARN,
        "title": "Forensic artifact is unreadable (OS error)",
        "recommendation": (
            "The referenced .cortex artifact exists but could not be opened "
            "due to a filesystem/permission error. Check file permissions and disk health."
        ),
    },
    "meta.syntax_parse_error": {
        "severity": GateSeverity.HIGH,
        "impact": GateImpact.REVISE,
        "title": "Python syntax error blocked gate from parsing file",
        "recommendation": (
            "Fix the Python syntax error in the referenced file so gates can parse and audit it."
        ),
    },
    "meta.file_unreadable": {
        "severity": GateSeverity.MEDIUM,
        "impact": GateImpact.WARN,
        "title": "Source file exists but is unreadable",
        "recommendation": (
            "Investigate the filesystem/permission error on the referenced path."
        ),
    },
    "meta.allowlist_corrupted": {
        "severity": GateSeverity.HIGH,
        "impact": GateImpact.WARN,
        "title": "False-positive allowlist JSON is corrupted",
        "recommendation": (
            "Repair or delete .prompt-engineer/forensic_gates/false_positive_allowlist.json."
        ),
    },
    "context_health.empty_file_snapshots": {
        "severity": GateSeverity.HIGH,
        "impact": GateImpact.WARN,
        "title": "Audit context has no file snapshots",
        "recommendation": (
            "Write-safety gates rely on ctx.file_snapshots. An empty snapshots map means "
            "every such gate trivially PASSes."
        ),
    },
    "context_health.git_state_unavailable": {
        "severity": GateSeverity.MEDIUM,
        "impact": GateImpact.WARN,
        "title": "Audit context is missing git state",
        "recommendation": (
            "Diff / blame / authorship-sensitive gates will be inconclusive."
        ),
    },
    "context_health.session_artifacts_missing": {
        "severity": GateSeverity.MEDIUM,
        "impact": GateImpact.WARN,
        "title": "Session artifacts directory is missing",
        "recommendation": (
            "session_number was set but the expected .cortex/sessions/<N>/ directory "
            "does not exist on disk."
        ),
    },
    "context_health.touched_files_empty": {
        "severity": GateSeverity.LOW,
        "impact": GateImpact.WARN,
        "title": "Audit context reports zero touched files",
        "recommendation": (
            "ctx.touched_files is empty outside static-scan mode."
        ),
    },
}


def emit_meta_finding(
    check_id: str,
    *,
    path: str = "",
    detail: str = "",
    summary: Optional[str] = None,
    severity: Optional[GateSeverity] = None,
    impact: Optional[GateImpact] = None,
) -> GateFinding:
    spec = META_CHECK_SPECS.get(check_id)
    if spec is None:
        _log.warning("emit_meta_finding: unregistered check_id=%r — using HIGH/WARN defaults", check_id)
        title = check_id
        recommendation = "(unregistered meta finding — extend META_CHECK_SPECS)"
        eff_severity = severity or GateSeverity.HIGH
        eff_impact = impact or GateImpact.WARN
    else:
        title = spec["title"]
        recommendation = spec["recommendation"]
        eff_severity = severity or spec["severity"]
        eff_impact = impact or spec["impact"]

    if summary is None:
        parts = [title]
        if path:
            parts.append(f"path={path}")
        if detail:
            parts.append(detail)
        summary = " | ".join(parts)

    evidence = (EvidenceReference(kind="meta_finding", path=path, detail=detail, ok=False),)

    finding = GateFinding(
        check_id=check_id,
        category=GateCategory.META,
        title=title,
        severity=eff_severity,
        impact=eff_impact,
        summary=summary,
        recommendation=recommendation,
        evidence=evidence,
        fingerprint=f"meta:{check_id}:{path}:{detail}"[:200],
    )

    with _lock:
        _pending.append(finding)
    _log.warning("[meta-finding] %s severity=%s path=%r detail=%r", check_id, eff_severity.value, path, detail)
    return finding


def drain_meta_findings() -> list[GateFinding]:
    with _lock:
        raw = list(_pending)
        _pending.clear()
    # Dedup by fingerprint: two gates emitting the same parse-error for the same
    # (file, line) produce identical fingerprints — collapse to one finding.
    seen: set[str] = set()
    out: list[GateFinding] = []
    for f in raw:
        fp = getattr(f, "fingerprint", None) or ""
        if fp and fp in seen:
            continue
        if fp:
            seen.add(fp)
        out.append(f)
    return out


def peek_meta_findings() -> list[GateFinding]:
    with _lock:
        return list(_pending)


def reset_meta_findings() -> None:
    with _lock:
        _pending.clear()


def meta_runner_stub(ctx: Any) -> GateCheckResult:
    """No-op runner for meta.* gate registrations."""
    return GateCheckResult(check_id="meta", category=GateCategory.META, findings=(), notes=())
