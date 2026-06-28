"""cortex_forensic — standalone static forensic gate package.

Public API
----------
run_forensic_audit(project_dir, *, gates=None, severity="LOW", all_languages=True) -> dict
    Run static forensic gates on a project directory and return findings as data.

Returned dict shape::

    {
        "exit_code": int,          # 0 = clean, 1 = high/critical findings, 2 = error
        "findings": [              # list of finding dicts (filtered by severity)
            {
                "check_id": str,
                "category": str,
                "title": str,
                "severity": str,   # "low" | "medium" | "high" | "critical"
                "impact": str,
                "summary": str,
                "recommendation": str,
                "evidence": [{"kind": str, "path": str, "detail": str}],
                "fingerprint": str,
                "confidence": float,
                "applicability": str,
                "analysis_mode": str,
                "applicability_reason": str,
            },
            ...
        ],
        "meta": {
            "project_dir": str,
            "source_files_scanned": int,
            "gates_attempted": int,
            "gates_succeeded": int,
            "gates_errored": int,
            "total_findings": int,
            "severity_counts": {"low": int, "medium": int, ...},
            "category_counts": {str: int},
            "schema_version": "1.1",
            "gates_skipped": [{"gate_id": str, "reason": str}],
            ...
        },
        "errors": [{"check_id": str, "error": str}],
    }

Zero imports from BRAIN, SYSTEM, or INTERFACE. May import cortex_map_builder
(sibling standalone package).
"""
from __future__ import annotations

from pathlib import Path
from typing import Any, Optional


def run_forensic_audit(
    project_dir: str | Path,
    *,
    gates: Optional[list[str]] = None,
    severity: str = "LOW",
    all_languages: bool = True,
    max_files: int = 800,
    cancel_event: Optional[Any] = None,
) -> dict[str, Any]:
    """Run static forensic gates on *project_dir* and return structured findings.

    Parameters
    ----------
    project_dir:
        Path to the project root to audit.
    gates:
        Optional list of gate check_ids to run. None means run all applicable
        file-based gates (skipping runtime-only gates as per skip_in_static policy).
        Gates listed in ``<project_dir>/.cortex/disabled_gates.json`` are always
        skipped (reported in ``meta["gates_skipped"]`` with reason
        ``"disabled_by_project"``) regardless of this argument.
    severity:
        Minimum severity floor for the returned ``findings``. One of
        "LOW", "MEDIUM", "HIGH", "CRITICAL" (case-insensitive); ordering is
        LOW < MEDIUM < HIGH < CRITICAL. Defaults to "LOW" (all findings).
        Findings below the floor are removed from ``findings``; the ``meta.*``
        counts are computed BEFORE this filter (so they always reflect the full
        finding set), and ``meta["findings_after_severity_filter"]`` records the
        post-filter count when a non-LOW floor is used.
    all_languages:
        Reserved for future use. Currently all source extensions recognized by
        cortex_map_builder.source_adapters are included automatically.
    max_files:
        Anti-hang ceiling on the COLLECTED source-file count. Forensic does a
        per-gate AST walk over every file (~0.4 s/file), so on a repo with
        thousands of files a full scan takes hours and effectively hangs. When
        the collected count exceeds ``max_files`` (default 800 ≈ a ~5 min
        ceiling) NO gates run; instead a FAST structured result is returned with
        ``meta["skipped_reason"] == "too_many_files"`` plus ``top_subdirs`` and a
        ``suggestion`` to narrow scope. Raise ``max_files`` to force a full scan.

    Returns
    -------
    dict with keys: "exit_code", "findings", "meta", "errors".
    Never raises — errors are captured in the returned dict.
    """
    import traceback
    from cortex_forensic.self_audit import (
        discover_source_files,
        build_synthetic_context,
        run_gates,
        build_json_report,
        filter_findings_by_severity,
        _load_project_disabled_gates,
        _probe_meta_integrity,
        GateOutcome,
    )
    from cortex_forensic.meta_findings import drain_meta_findings

    project_dir = Path(project_dir).resolve()
    if not project_dir.is_dir():
        return {
            "exit_code": 2,
            "findings": [],
            "meta": {"error": f"project_dir is not a directory: {project_dir}"},
            "errors": [{"check_id": "init", "error": f"Not a directory: {project_dir}"}],
        }

    gates_filter: Optional[set[str]] = set(gates) if gates else None

    try:
        source_files = discover_source_files(project_dir)
    except Exception as exc:
        return {
            "exit_code": 2,
            "findings": [],
            "meta": {"error": f"file discovery failed: {exc}"},
            "errors": [{"check_id": "discover", "error": traceback.format_exc()}],
        }

    if not source_files:
        return {
            "exit_code": 0,
            "findings": [],
            "meta": {
                "project_dir": str(project_dir),
                "source_files_scanned": 0,
                "gates_attempted": 0,
                "gates_succeeded": 0,
                "gates_errored": 0,
                "total_findings": 0,
                "severity_counts": {},
                "category_counts": {},
                "schema_version": "1.1",
                "gates_skipped": [],
                "gates_skipped_in_static": [],
                "note": "no source files found",
            },
            "errors": [],
        }

    # Anti-hang file-COUNT guard. Forensic walks every file per gate (~0.4 s/file)
    # so thousands of files = hours. When the collected count exceeds max_files we
    # do NOT build context or run gates; we return a FAST structured skip result
    # (just count + group-by-top-subdir) telling the caller to narrow scope.
    if len(source_files) > max_files:
        from cortex_map_builder._file_count_guard import build_too_many_files_meta

        meta = build_too_many_files_meta(
            source_files, max_files, entry_call="start_forensic_audit"
        )
        meta["project_dir"] = str(project_dir)
        return {
            "exit_code": 0,
            "findings": [],
            "meta": meta,
            "errors": [],
        }

    try:
        ctx = build_synthetic_context(project_dir, source_files)
    except Exception as exc:
        return {
            "exit_code": 2,
            "findings": [],
            "meta": {"error": f"context build failed: {exc}"},
            "errors": [{"check_id": "build_context", "error": traceback.format_exc()}],
        }

    # Per-project gate opt-out: <project_dir>/.cortex/disabled_gates.json.
    # Malformed file → meta finding + empty set (never raises, never silently
    # disables). Loaded here so the meta finding is drained with the rest below.
    disabled_gates = _load_project_disabled_gates(project_dir)

    outcomes, gates_skipped = run_gates(
        ctx, gates_filter, workers=1, cancel_event=cancel_event,
        disabled_gates=disabled_gates,
    )

    # Probe audit infrastructure for corrupted artifacts
    _probe_meta_integrity(project_dir)
    meta_findings = drain_meta_findings()
    if meta_findings:
        outcomes.append(GateOutcome(check_id="meta_integrity_probe", ok=True, findings=list(meta_findings)))

    report = build_json_report(outcomes, project_dir, len(source_files), gates_skipped=gates_skipped)

    # Apply severity filter to findings list (meta counts are pre-filter)
    min_sev = severity.lower()
    if min_sev != "low":
        filtered = filter_findings_by_severity(report["findings"], min_sev)
        report = dict(report)
        report["findings"] = filtered
        report["meta"] = dict(report["meta"])
        report["meta"]["findings_after_severity_filter"] = len(filtered)

    # Compute exit code
    sev_counts = report["meta"].get("severity_counts", {})
    critical_or_high = sev_counts.get("critical", 0) + sev_counts.get("high", 0)
    exit_code = 1 if critical_or_high > 0 else 0

    return {
        "exit_code": exit_code,
        "findings": report["findings"],
        "meta": report["meta"],
        "errors": report.get("errors", []),
    }


__all__ = ["run_forensic_audit"]
