"""Forensic Self-Audit — standalone static audit using autoforensics gates.

Adapted from the Vigil autoforensics self_audit.
All cluster imports rewritten to cortex_forensic.* or _stubs.
"""
from __future__ import annotations

import argparse
import concurrent.futures
import json
import sys
import time
import traceback
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Optional
import logging

from cortex_forensic._shared import GateCheckResult, GateFinding
from cortex_forensic.gate_models import (
    PostExecGateContext, RuntimeState, VerificationSummary, detect_source_package_roots,
)
from cortex_forensic.gate_packs.universal import GATE_FLAGS
from cortex_forensic.gate_registry import DEFAULT_GATE_CHECKS
from cortex_forensic._stubs import ValidationContractProfile, PocketCoderForensicReport

_log = logging.getLogger(__name__)

_MAX_ERRORS_BEFORE_TRUNCATE = 10

_SKIP_IN_STATIC_MODE: frozenset[str] = frozenset(
    gid for gid, flags in GATE_FLAGS.items() if "skip_in_static" in flags
)

_SELF_MATCH_PRONE_GATES = frozenset({
    "magic_number_scan",
    "todo_scan",
    "legacy_compat_debt.stale_migration_marker",
})

_SELF_MATCH_PATH_PREFIX = "gate_checks/"


def _is_self_match_finding(finding: GateFinding) -> bool:
    check_id = getattr(finding, "check_id", "") or ""
    if check_id not in _SELF_MATCH_PRONE_GATES:
        return False
    evidence = getattr(finding, "evidence", ()) or ()
    if not evidence:
        return False
    path = getattr(evidence[0], "path", "") or ""
    normalized = path.replace("\\", "/").lstrip("./")
    return normalized.startswith(_SELF_MATCH_PATH_PREFIX)


_DEFAULT_EXCLUDE_DIRS = frozenset({
    "__pycache__", ".git", ".venv", "venv", ".cortex", "node_modules",
    "libs", ".pytest_cache", "build", "dist", ".mypy_cache", ".ruff_cache", ".tox",
})


def discover_source_files(
    project_dir: Path,
    exclude_dirs: frozenset[str] = _DEFAULT_EXCLUDE_DIRS,
) -> list[str]:
    """Return sorted list of relative source-file paths under project_dir."""
    from cortex_forensic.source_analysis import is_source_file
    src_files: list[str] = []
    for path in project_dir.rglob("*"):
        if not path.is_file():
            continue
        try:
            rel = path.relative_to(project_dir)
        except ValueError:
            continue
        if any(part in exclude_dirs for part in rel.parts):
            continue
        rel_str = str(rel).replace("\\", "/")
        if is_source_file(rel_str):
            src_files.append(rel_str)
    return sorted(src_files)


def _probe_meta_integrity(project_dir: Path) -> None:
    """Walk well-known audit artifact locations and emit meta findings for corrupted / unreadable files."""
    from cortex_forensic.meta_findings import emit_meta_finding

    project_dir = Path(project_dir)
    profile_path = project_dir / "gate_profile.json"
    if profile_path.is_file():
        try:
            json.loads(profile_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            emit_meta_finding("meta.profile_load_failed", path=str(profile_path), detail=f"JSONDecodeError: {exc}")
        except (OSError, PermissionError) as exc:
            emit_meta_finding("meta.profile_load_failed", path=str(profile_path), detail=f"{type(exc).__name__}: {exc}")

    allowlist_path = project_dir / ".prompt-engineer" / "forensic_gates" / "false_positive_allowlist.json"
    if allowlist_path.is_file():
        try:
            json.loads(allowlist_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            emit_meta_finding("meta.allowlist_corrupted", path=str(allowlist_path), detail=f"JSONDecodeError: {exc}")
        except (OSError, PermissionError) as exc:
            emit_meta_finding("meta.allowlist_corrupted", path=str(allowlist_path), detail=f"{type(exc).__name__}: {exc}")

    cortex = project_dir / ".cortex"
    if cortex.is_dir():
        try:
            cortex_children = sorted(cortex.rglob("*.json"))
        except (OSError, PermissionError) as exc:
            emit_meta_finding("meta.artifact_unreadable", path=str(cortex), detail=f"{type(exc).__name__} walking .cortex: {exc}")
            cortex_children = []
        for artifact in cortex_children:
            if not artifact.is_file():
                continue
            try:
                raw = artifact.read_text(encoding="utf-8")
            except (OSError, PermissionError) as exc:
                emit_meta_finding("meta.artifact_unreadable", path=str(artifact), detail=f"{type(exc).__name__}: {exc}")
                continue
            try:
                json.loads(raw)
            except json.JSONDecodeError as exc:
                emit_meta_finding("meta.artifact_corrupted", path=str(artifact), detail=f"JSONDecodeError: {exc}")


_FILE_BASED_GATES: frozenset[str] = frozenset({
    "broad_except", "broad_except.hidden_sentinel", "fallback", "context_fallback_save",
    "embedded_string", "duplication", "file_proliferation", "config_ssot", "size_complexity",
    "empty_output", "syntax_validity", "heartbeat_staleness", "god_object_zones",
    "hotspot_inflation", "toctou_check_then_act", "atomic_write_safety", "encoding_safety",
    "subprocess_encoding", "contract_shape_drift", "import_integrity", "drift",
    "authority_checks", "boundary_breach", "performance", "runtime_behavior",
    "runtime_duplicate_side_effect", "init_order_regression", "conflict_touch",
    "test_quality", "test_suite_masking", "empty_test_module", "simulated_instead_of_executed_test",
    "temporal_freshness", "provenance", "reporting", "fix_without_test", "semantic_intent",
    "testing", "forensic_clusters", "project_specific", "hallucination", "artifact_completeness",
    "tool_hook_coverage", "codex_state", "policy_boundary", "draft_boundary", "codex_supervision",
})


def build_synthetic_context(project_dir: Path, source_files: list[str]) -> PostExecGateContext:
    """Build minimal PostExecGateContext treating every source file as touched."""
    from cortex_forensic.gate_checks.common import normalize_path, read_snapshot

    file_snapshots = {
        normalize_path(p): read_snapshot(project_dir, p)
        for p in source_files
    }
    return PostExecGateContext(
        project_dir=project_dir,
        session_number=0,
        task_id="FORENSIC_SELF_AUDIT",
        a1_task_id="FORENSIC_SELF_AUDIT",
        validation_contract=ValidationContractProfile.from_mapping({}),
        forensic_report=PocketCoderForensicReport.from_mapping({}),
        runtime_state=RuntimeState.from_mapping({}),
        verification_summary=VerificationSummary.from_mapping({}),
        attempt_id="self_audit",
        gate_round=1,
        touched_files=tuple(source_files),
        changed_files_observed=tuple(source_files),
        source_package_roots=detect_source_package_roots(project_dir),
        file_snapshots=file_snapshots,
        project_context=None,
    )


@dataclass
class GateOutcome:
    check_id: str
    ok: bool
    error: str = ""
    findings: list[GateFinding] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)


def run_gates(
    ctx: PostExecGateContext,
    gates_filter: Optional[set[str]] = None,
    *,
    workers: int = 1,
) -> tuple[list[GateOutcome], list[dict[str, str]]]:
    """Run all file-based gates (or the subset in gates_filter) against ctx."""
    gates_skipped: list[dict[str, str]] = []
    runnable: list[tuple[str, Callable[[PostExecGateContext], GateCheckResult]]] = []
    for check_id, _, runner in DEFAULT_GATE_CHECKS:
        if check_id in _SKIP_IN_STATIC_MODE:
            gates_skipped.append({"gate_id": check_id, "reason": "skipped_in_static_mode"})
            continue
        if check_id not in _FILE_BASED_GATES:
            gates_skipped.append({"gate_id": check_id, "reason": "not_file_based"})
            continue
        if gates_filter and check_id not in gates_filter:
            gates_skipped.append({"gate_id": check_id, "reason": "not_in_gates_filter"})
            continue
        runnable.append((check_id, runner))

    if workers > 1 and len(runnable) > 1:
        outcomes = _run_gates_parallel(runnable, ctx, workers)
    else:
        outcomes = [_run_single_gate(check_id, runner, ctx) for check_id, runner in runnable]
    return outcomes, gates_skipped


def _run_gates_parallel(
    runnable: list[tuple[str, Callable[[PostExecGateContext], GateCheckResult]]],
    ctx: PostExecGateContext,
    workers: int,
) -> list[GateOutcome]:
    effective_workers = max(1, min(int(workers), len(runnable)))
    outcomes_by_id: dict[str, GateOutcome] = {}
    with concurrent.futures.ThreadPoolExecutor(
        max_workers=effective_workers, thread_name_prefix="forensic-gate",
    ) as pool:
        future_to_gate = {
            pool.submit(_run_single_gate, check_id, runner, ctx): check_id
            for check_id, runner in runnable
        }
        for fut in future_to_gate:
            gate_id = future_to_gate[fut]
            try:
                outcomes_by_id[gate_id] = fut.result()
            except BaseException as exc:
                outcomes_by_id[gate_id] = GateOutcome(check_id=gate_id, ok=False, error=f"{type(exc).__name__}: {exc}")
    return [outcomes_by_id[check_id] for check_id, _ in runnable]


def _run_single_gate(
    check_id: str,
    runner: Callable[[PostExecGateContext], GateCheckResult],
    ctx: PostExecGateContext,
) -> GateOutcome:
    try:
        result = runner(ctx)
        findings = list(getattr(result, "findings", ()) or ())
        notes = list(getattr(result, "notes", ()) or ())
        return GateOutcome(check_id=check_id, ok=True, findings=findings, notes=notes)
    except Exception as exc:
        return GateOutcome(check_id=check_id, ok=False, error=f"{type(exc).__name__}: {exc}")


_SEVERITY_ORDER: dict[str, int] = {"low": 0, "medium": 1, "high": 2, "critical": 3}


def finding_to_dict(f: GateFinding) -> dict[str, Any]:
    return {
        "check_id": f.check_id,
        "category": str(getattr(f.category, "value", f.category) or ""),
        "title": f.title,
        "severity": str(getattr(f.severity, "value", f.severity) or ""),
        "impact": str(getattr(f.impact, "value", f.impact) or ""),
        "summary": f.summary,
        "recommendation": f.recommendation,
        "evidence": [{"kind": e.kind, "path": e.path, "detail": e.detail} for e in (f.evidence or ())],
        "fingerprint": f.fingerprint,
        "confidence": getattr(f, "confidence", 1.0),
        "applicability": getattr(f, "applicability", "applicable"),
        "analysis_mode": getattr(f, "analysis_mode", "heuristic"),
        "applicability_reason": getattr(f, "applicability_reason", ""),
    }


def build_json_report(
    outcomes: list[GateOutcome],
    project_dir: Path,
    source_file_count: int,
    gates_skipped: Optional[list[dict[str, str]]] = None,
) -> dict[str, Any]:
    raw_findings: list[GateFinding] = []
    errors: list[dict[str, str]] = []
    ok_count = 0
    for outcome in outcomes:
        if outcome.ok:
            ok_count += 1
            raw_findings.extend(outcome.findings)
        else:
            errors.append({"check_id": outcome.check_id, "error": outcome.error})

    suppressed_na = [f for f in raw_findings if getattr(f, "applicability", "applicable") == "not_applicable"]
    uncertain_findings = [f for f in raw_findings if getattr(f, "applicability", "applicable") == "unknown"]
    applicable_findings = [f for f in raw_findings if getattr(f, "applicability", "applicable") != "not_applicable"]
    all_findings = [f for f in applicable_findings if not _is_self_match_finding(f)]

    sev_counts: dict[str, int] = {}
    for finding in all_findings:
        sev = str(getattr(finding.severity, "value", "unknown") or "unknown").lower()
        sev_counts[sev] = sev_counts.get(sev, 0) + 1

    category_counts: dict[str, int] = {}
    for finding in all_findings:
        cat = str(getattr(finding.category, "value", "unknown") or "unknown")
        category_counts[cat] = category_counts.get(cat, 0) + 1

    suppressed_by_gate: dict[str, int] = {}
    for finding in suppressed_na:
        cid = getattr(finding, "check_id", "") or "unknown"
        suppressed_by_gate[cid] = suppressed_by_gate.get(cid, 0) + 1

    uncertain_by_gate: dict[str, int] = {}
    for finding in uncertain_findings:
        cid = getattr(finding, "check_id", "") or "unknown"
        uncertain_by_gate[cid] = uncertain_by_gate.get(cid, 0) + 1

    gates_skipped_list = list(gates_skipped or [])
    gates_skipped_in_static = [e["gate_id"] for e in gates_skipped_list if e.get("reason") == "skipped_in_static_mode"]

    return {
        "meta": {
            "project_dir": str(project_dir),
            "source_files_scanned": source_file_count,
            "gates_attempted": len(outcomes),
            "gates_succeeded": ok_count,
            "gates_errored": len(errors),
            "total_findings": len(all_findings),
            "severity_counts": sev_counts,
            "category_counts": category_counts,
            "schema_version": "1.1",
            "suppressed_not_applicable_count": len(suppressed_na),
            "suppressed_not_applicable_by_gate": suppressed_by_gate,
            "uncertain_findings_count": len(uncertain_findings),
            "uncertain_findings_by_gate": uncertain_by_gate,
            "gates_skipped": gates_skipped_list,
            "gates_skipped_in_static": gates_skipped_in_static,
        },
        "errors": errors,
        "findings": [finding_to_dict(f) for f in all_findings],
        "uncertain_findings": [finding_to_dict(f) for f in uncertain_findings],
    }


def filter_findings_by_severity(findings: list[dict[str, Any]], min_sev: str) -> list[dict[str, Any]]:
    threshold = _SEVERITY_ORDER.get(min_sev.lower(), 0)
    return [f for f in findings if _SEVERITY_ORDER.get(str(f["severity"]).lower(), 0) >= threshold]


def print_human_summary(report: dict[str, Any], top_n: int = 20) -> None:
    meta = report["meta"]
    print("=" * 72)
    print(" FORENSIC SELF-AUDIT SUMMARY")
    print("=" * 72)
    print(f"  Project:           {meta['project_dir']}")
    print(f"  Source files scanned: {meta['source_files_scanned']}")
    print(f"  Gates attempted:   {meta['gates_attempted']}")
    print(f"  Gates succeeded:   {meta['gates_succeeded']}")
    print(f"  Gates errored:     {meta['gates_errored']}")
    print(f"  Total findings:    {meta['total_findings']}")
    print()
    sev_counts = meta.get("severity_counts", {})
    if sev_counts:
        print("  By severity:")
        for sev in ("critical", "high", "medium", "low"):
            if sev in sev_counts:
                print(f"    {sev:>10}: {sev_counts[sev]}")
        print()
    errors = report.get("errors", [])
    if errors:
        print(f"  GATE ERRORS ({len(errors)}):")
        for err in errors[:_MAX_ERRORS_BEFORE_TRUNCATE]:
            print(f"    {err['check_id']:>30}: {err['error']}")
        if len(errors) > _MAX_ERRORS_BEFORE_TRUNCATE:
            print(f"    ... +{len(errors) - _MAX_ERRORS_BEFORE_TRUNCATE} more")
        print()
    findings = report.get("findings", [])
    if findings:
        by_sev = sorted(findings, key=lambda f: -_SEVERITY_ORDER.get(str(f["severity"]).lower(), 0))
        print(f"  TOP {min(top_n, len(by_sev))} FINDINGS (by severity):")
        for f in by_sev[:top_n]:
            evidence = f.get("evidence") or []
            path = evidence[0]["path"] if evidence else "<no path>"
            detail = evidence[0]["detail"] if evidence else ""
            loc = f"{path}:{detail}" if detail else path
            sev_tag = f["severity"].upper() if f.get("severity") else "?"
            print(f"    [{sev_tag:>8}] {f['check_id']:>30}  {loc}")
            print(f"             {f['title']}")


def main(argv: Optional[list[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Forensic Self-Audit (cortex_forensic)")
    parser.add_argument("--project", default="", help="Target project directory")
    parser.add_argument("--gates", default="", help="Comma-separated gate check_ids")
    parser.add_argument("--list-gates", action="store_true", help="Print file-based gates and exit")
    parser.add_argument("--severity", default="low", choices=["low", "medium", "high", "critical"])
    parser.add_argument("--json-out", default="")
    parser.add_argument("--top", type=int, default=20)
    parser.add_argument("--quiet", action="store_true")
    parser.add_argument("--workers", type=int, default=1)
    args = parser.parse_args(argv)

    if args.list_gates:
        print("File-based gates wired into forensic self-audit:")
        for check_id in sorted(_FILE_BASED_GATES):
            print(f"  {check_id}")
        return 0

    project_dir = Path(args.project).resolve()
    if not project_dir.is_dir():
        print(f"ERROR: {project_dir} is not a directory", file=sys.stderr)
        return 2

    gates_filter = {g.strip() for g in args.gates.split(",") if g.strip()} or None

    print(f"[1/3] Discovering source files in {project_dir}...", file=sys.stderr)
    source_files = discover_source_files(project_dir)
    print(f"      Found {len(source_files)} files", file=sys.stderr)
    if not source_files:
        print("ERROR: no source files found under project_dir", file=sys.stderr)
        return 2

    print("[2/3] Building synthetic PostExecGateContext...", file=sys.stderr)
    try:
        ctx = build_synthetic_context(project_dir, source_files)
    except Exception as exc:
        print(f"ERROR: failed to build context: {type(exc).__name__}: {exc}", file=sys.stderr)
        traceback.print_exc(file=sys.stderr)
        return 2

    workers = max(1, int(getattr(args, "workers", 1) or 1))
    print(f"[3/3] Running gates ({'parallel x' + str(workers) if workers > 1 else 'sequential'})...", file=sys.stderr)
    outcomes, gates_skipped = run_gates(ctx, gates_filter, workers=workers)

    from cortex_forensic.meta_findings import drain_meta_findings
    _probe_meta_integrity(project_dir)
    meta_findings = drain_meta_findings()
    if meta_findings:
        outcomes.append(GateOutcome(check_id="meta_integrity_probe", ok=True, findings=list(meta_findings)))

    report = build_json_report(outcomes, project_dir, len(source_files), gates_skipped=gates_skipped)

    if args.severity != "low":
        filtered = filter_findings_by_severity(report["findings"], args.severity)
        report["findings"] = filtered
        report["meta"]["findings_after_severity_filter"] = len(filtered)

    if args.json_out:
        out_path = Path(args.json_out).resolve()
        out_path.write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
        print(f"JSON report written to: {out_path}", file=sys.stderr)

    if not args.quiet:
        print_human_summary(report, top_n=args.top)

    critical_or_high = sum(report["meta"]["severity_counts"].get(s, 0) for s in ("critical", "high"))
    return 1 if critical_or_high > 0 else 0


if __name__ == "__main__":
    sys.exit(main())
