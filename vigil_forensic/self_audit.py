"""Forensic Self-Audit — standalone static audit using autoforensics gates.

Adapted from the Vigil autoforensics self_audit.
All cluster imports rewritten to vigil_forensic.* or _stubs.
"""
from __future__ import annotations

import argparse
import concurrent.futures
import json
import sys
import threading
import time
import traceback
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Optional
import logging

# Thread-local storage: run_gates sets _tl_cancel.event before dispatching each
# gate so cluster runners (which don't receive cancel_event directly) can check
# the same event via get_cancel_event().
_tl_cancel = threading.local()


def get_cancel_event() -> Optional[Any]:
    """Return the cancel_event for the current thread, or None."""
    return getattr(_tl_cancel, "event", None)

from vigil_forensic._shared import GateCheckResult, GateFinding
from vigil_forensic.gate_models import (
    PostExecGateContext, RuntimeState, VerificationSummary, detect_source_package_roots,
)
from vigil_forensic.gate_packs.universal import GATE_FLAGS
from vigil_forensic.gate_registry import DEFAULT_GATE_CHECKS
from vigil_forensic._stubs import ValidationContractProfile, PocketCoderForensicReport

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

# Noisy, opt-in-only gates. These run ONLY when explicitly named in the gates
# filter (run_forensic_audit(..., gates=[...]) / --gates). They are excluded
# from a default full scan because they produce a high false-positive rate on
# finished third-party code.
#
# god_object_zones infers "responsibility zones" from FUNCTION-NAME PREFIXES
# against a fixed verb list (acquire/release/read/write/open/close/...). A
# cohesive class whose natural method names happen to match several verbs (e.g.
# a read/write lock) is wrongly flagged as a god object — ~0 true positives on
# the filelock/click/mcp corpus. The capability is preserved (opt in via
# gates=["god_object_zones"]); it is just not part of the default set. Re-enable
# for your own repo by listing it in the `gates` argument or, project-wide, by
# NOT listing it in `.cortex/disabled_gates.json` and passing it explicitly.
#
# The twin name-prefix heuristic that previously lived in
# size_complexity.zone_overload was REMOVED outright (it double-reported the
# same files as god_object_zones); the zone heuristic now has a single home here.
_NOISY_OPT_IN_GATES: frozenset[str] = frozenset({
    "god_object_zones",
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
    # Vendored / build-output dirs that can appear OUTSIDE a venv (e.g. a repo
    # that ships a checked-in dependency tree). Excluded so the file-count guard
    # and the gate walk never spend time on third-party code.
    "site-packages", "dist-packages", ".eggs", ".next",
    # Tool / agent config dirs — never project source, and (e.g. .claude) can
    # hold thousands of files (worktrees, plans, memory). Mirrors the code-map
    # exclusion set so both tools agree on what "project source" means.
    ".claude", ".codex", ".prompt-engineer", ".a1",
})


def discover_source_files(
    project_dir: Path,
    exclude_dirs: frozenset[str] = _DEFAULT_EXCLUDE_DIRS,
) -> list[str]:
    """Return sorted list of relative source-file paths under project_dir.

    Uses ``os.walk`` with ``topdown=True`` and PRUNES excluded directories from
    ``dirnames`` in place so the walk never descends into them. This is both a
    correctness and a performance fix: the previous ``rglob('*')`` walked INTO
    excluded trees (e.g. a 7000-file ``.claude``) and only filtered afterward,
    which dominated the runtime on large repos and made the anti-hang file-count
    guard itself slow.
    """
    import os
    from vigil_forensic.source_analysis import is_source_file

    project_dir = project_dir.resolve()
    src_files: list[str] = []
    for dirpath_str, dirnames, filenames in os.walk(str(project_dir), topdown=True):
        # Prune excluded dirs in place — os.walk will not descend into them.
        dirnames[:] = [d for d in dirnames if d not in exclude_dirs]
        dirpath = Path(dirpath_str)
        for fname in filenames:
            full = dirpath / fname
            if not full.is_file():
                continue
            try:
                rel = full.relative_to(project_dir)
            except ValueError:
                continue
            rel_str = str(rel).replace("\\", "/")
            if is_source_file(rel_str):
                src_files.append(rel_str)
    return sorted(src_files)


def _probe_meta_integrity(project_dir: Path) -> None:
    """Walk well-known audit artifact locations and emit meta findings for corrupted / unreadable files."""
    from vigil_forensic.meta_findings import emit_meta_finding

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


def _load_project_disabled_gates(project_dir: Path) -> frozenset[str]:
    """Load the set of project-disabled gate IDs from ``.cortex/disabled_gates.json``.

    Ported from the Vigil ``cli_forensic_audit._load_project_disabled_gates``.
    Lets a project switch off noisy gates without code changes. The file may be
    either a bare JSON list of gate IDs::

        ["broad_except", "duplication"]

    or an object with a ``"disabled"`` key::

        {"disabled": ["broad_except", "duplication"]}

    Narrow exception handling: only JSON-decode, IO/permission, and
    coercion errors are caught. A corrupt / unreadable file surfaces as a
    ``meta.profile_load_failed`` finding (via the ``emit_meta_finding``
    side-channel) and yields an empty set — it never raises and never silently
    disables. Any other exception (a bug inside json/pathlib, or an upstream
    monkeypatch) must propagate rather than be swallowed.
    """
    from vigil_forensic.meta_findings import emit_meta_finding

    path = Path(project_dir) / ".cortex" / "disabled_gates.json"
    if not path.is_file():
        return frozenset()
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        emit_meta_finding(
            "meta.profile_load_failed",
            path=str(path),
            detail=f"JSONDecodeError in disabled_gates.json: {exc}",
        )
        return frozenset()
    except (FileNotFoundError, PermissionError, OSError) as exc:
        emit_meta_finding(
            "meta.profile_load_failed",
            path=str(path),
            detail=f"{type(exc).__name__} reading disabled_gates.json: {exc}",
        )
        return frozenset()

    if isinstance(payload, dict):
        raw = payload.get("disabled", [])
    else:
        raw = payload
    try:
        return frozenset(str(gid) for gid in raw)
    except TypeError as exc:
        emit_meta_finding(
            "meta.profile_load_failed",
            path=str(path),
            detail=f"disabled_gates.json payload is not iterable: {type(raw).__name__}: {exc}",
        )
        return frozenset()


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


def _load_gate_profile_if_present(project_dir: Path) -> "Optional[Any]":
    """Load gate_profile.json from project_dir (or .cortex/gate_profile.json).

    Returns a RepoGateProfile on success, None if no file found or on error.
    Error is logged but never raised — missing profile is not fatal.
    """
    from vigil_forensic._shared import RepoGateProfile, GateCategory, GateImpact

    _PROFILE_CANDIDATES = ("gate_profile.json", ".cortex/gate_profile.json")
    _GENERIC_GENERATED_ROOTS: tuple[str, ...] = (
        ".git", "__pycache__", ".pytest_cache", "dist", "build",
        "node_modules", "venv", ".venv",
    )
    _GENERIC_SIZE_THRESHOLDS: dict[str, int] = {
        "file_warn": 600, "file_revise": 800,
        "function_warn": 80, "function_revise": 120,
        "nesting_warn": 4, "nesting_revise": 6,
    }

    def _impact_from_value(v: object) -> GateImpact:
        try:
            return GateImpact(str(v))
        except ValueError:
            return GateImpact.WARN

    def _profile_from_dict(payload: dict, path: Path) -> RepoGateProfile:
        enabled_raw = payload.get("enabled_categories") or [item.value for item in GateCategory]
        fallback_raw = payload.get("forbidden_fallback_patterns") or {}
        canonical_raw = payload.get("canonical_literal_owners") or {}
        size = payload.get("size_thresholds") or {}
        defaults = _GENERIC_SIZE_THRESHOLDS
        return RepoGateProfile(
            profile_name=str(payload.get("profile_name") or "generic"),
            version=str(payload.get("version") or "1.0"),
            generated_roots=tuple(payload.get("generated_roots") or _GENERIC_GENERATED_ROOTS),
            vendored_roots=tuple(payload.get("vendored_roots") or (".vendor", "vendor", "node_modules")),
            forbidden_roots=tuple(payload.get("forbidden_roots") or ()),
            critical_roots=tuple(payload.get("critical_roots") or ()),
            allowlisted_large_files=tuple(payload.get("allowlisted_large_files") or ()),
            performance_sensitive_roots=tuple(payload.get("performance_sensitive_roots") or ()),
            required_test_roots=tuple(payload.get("required_test_roots") or ()),
            canonical_literal_owners={str(k): tuple(v) for k, v in canonical_raw.items()},
            forbidden_fallback_patterns={str(k): _impact_from_value(v) for k, v in fallback_raw.items()},
            size_thresholds={
                "file_warn": int(size.get("file_warn", defaults["file_warn"])),
                "file_revise": int(size.get("file_revise", defaults["file_revise"])),
                "function_warn": int(size.get("function_warn", defaults["function_warn"])),
                "function_revise": int(size.get("function_revise", defaults["function_revise"])),
                "nesting_warn": int(size.get("nesting_warn", defaults["nesting_warn"])),
                "nesting_revise": int(size.get("nesting_revise", defaults["nesting_revise"])),
            },
            severity_overrides={str(k): _impact_from_value(v) for k, v in (payload.get("severity_overrides") or {}).items()},
            required_proofs_overrides={str(k): tuple(v) for k, v in (payload.get("required_proofs_overrides") or {}).items()},
            reporting_required_artifacts=tuple(payload.get("reporting_required_artifacts") or ()),
            enabled_categories=tuple(GateCategory(item) for item in enabled_raw),
            enabled_checks=tuple(payload.get("enabled_checks") or ()),
            disabled_checks=tuple(payload.get("disabled_checks") or ()),
            profile_path=str(path),
        )

    import json as _json

    def _try_load(path: Path) -> "Optional[RepoGateProfile]":
        if not path.is_file():
            return None
        try:
            payload = _json.loads(path.read_text(encoding="utf-8"))
        except Exception as exc:
            _log.warning("gate_profile load failed (%s): %s", path, exc)
            return None
        return _profile_from_dict(payload, path)

    root = Path(project_dir).resolve()

    # 1) Prefer a profile co-located with the audit target (existing behavior).
    for candidate in _PROFILE_CANDIDATES:
        result = _try_load(root / candidate)
        if result is not None:
            return result

    # 2) Fallback: walk up to find a shipped default `gate_profile.json` in an
    #    ancestor directory (e.g. the repo root) when the audit target is a
    #    sub-package or an external path. Config discovery by ancestor-walk is
    #    the same pattern linters/git use; the target-local profile always wins.
    #    A malformed ancestor file is logged-and-skipped, never raised.
    for ancestor in root.parents:
        candidate_path = ancestor / "gate_profile.json"
        if candidate_path.is_file():
            return _try_load(candidate_path)

    # 3) Last resort: the package's OWN shipped gate_profile.json. Without this,
    #    an external target (e.g. an arbitrary path with no ancestor profile)
    #    silently fell back to the STRICT code-default thresholds (600/800/4)
    #    instead of the shipped, documented defaults (750/1000/5). The shipped
    #    profile is the effective default for every target. Located INSIDE the
    #    vigil_forensic package so it ships in the wheel (see
    #    _packaged_gate_profile_path).
    packaged = _packaged_gate_profile_path()
    if packaged is not None and packaged.is_file():
        result = _try_load(packaged)
        if result is not None:
            return result

    return None


def _packaged_gate_profile_path() -> "Optional[Path]":
    """Return the path to the package's shipped ``gate_profile.json``.

    The default profile ships INSIDE the ``vigil_forensic`` package (next to
    this module) so it is included in the wheel/sdist via
    ``[tool.setuptools.package-data]`` and is therefore available after a plain
    ``pip install`` — there is no repo root at install time. Resolved relative
    to this module so it works regardless of the caller's cwd or the audit
    target location. Returns None if the file cannot be located.
    """
    here = Path(__file__).resolve()
    # here == .../vigil_forensic/self_audit.py → .../vigil_forensic/gate_profile.json
    candidate = here.parent / "gate_profile.json"
    return candidate if candidate.is_file() else None


def build_synthetic_context(project_dir: Path, source_files: list[str]) -> PostExecGateContext:
    """Build minimal PostExecGateContext treating every source file as touched."""
    from vigil_forensic.gate_checks.common import normalize_path, read_snapshot

    file_snapshots = {
        normalize_path(p): read_snapshot(project_dir, p)
        for p in source_files
    }
    repo_profile = _load_gate_profile_if_present(project_dir)
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
        is_full_scan=True,  # standalone audit is always a full scan, not an incremental diff
        source_package_roots=detect_source_package_roots(project_dir),
        file_snapshots=file_snapshots,
        repo_profile=repo_profile,
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
    cancel_event: Optional[Any] = None,
    disabled_gates: Optional[frozenset[str]] = None,
) -> tuple[list[GateOutcome], list[dict[str, str]]]:
    """Run all file-based gates (or the subset in gates_filter) against ctx.

    Parameters
    ----------
    cancel_event:
        Optional threading.Event (or any object with an .is_set() method).
        When set, the per-gate loop stops before the next gate starts.
        The MCP _jobs.py injects this by inspecting co_varnames, so the
        parameter name must stay as ``cancel_event``.
    disabled_gates:
        Optional set of gate check_ids the project has switched off (loaded
        from ``.cortex/disabled_gates.json``). A disabled gate never runs and
        is reported in the returned skip list with reason
        ``"disabled_by_project"``. This takes precedence over every other
        resolution rule so a project's intent to silence a gate is always
        visible in ``meta.gates_skipped``.
    """
    disabled = disabled_gates or frozenset()
    gates_skipped: list[dict[str, str]] = []
    runnable: list[tuple[str, Callable[[PostExecGateContext], GateCheckResult]]] = []
    for check_id, _, runner in DEFAULT_GATE_CHECKS:
        if check_id in disabled:
            gates_skipped.append({"gate_id": check_id, "reason": "disabled_by_project"})
            continue
        if check_id in _SKIP_IN_STATIC_MODE:
            gates_skipped.append({"gate_id": check_id, "reason": "skipped_in_static_mode"})
            continue
        if check_id not in _FILE_BASED_GATES:
            gates_skipped.append({"gate_id": check_id, "reason": "not_file_based"})
            continue
        # Noisy opt-in gates run ONLY when explicitly named in the gates filter.
        if check_id in _NOISY_OPT_IN_GATES and not (gates_filter and check_id in gates_filter):
            gates_skipped.append({"gate_id": check_id, "reason": "opt_in_only"})
            continue
        if gates_filter and check_id not in gates_filter:
            gates_skipped.append({"gate_id": check_id, "reason": "not_in_gates_filter"})
            continue
        runnable.append((check_id, runner))

    if workers > 1 and len(runnable) > 1:
        outcomes = _run_gates_parallel(runnable, ctx, workers)
    else:
        outcomes = []
        # Store cancel_event in thread-local so cluster runners can access it
        # without a signature change (get_cancel_event() from this module).
        _tl_cancel.event = cancel_event
        try:
            for check_id, runner in runnable:
                if cancel_event is not None and cancel_event.is_set():
                    _log.info("run_gates: cancel_event set, stopping after %d gates", len(outcomes))
                    break
                outcomes.append(_run_single_gate(check_id, runner, ctx))
        finally:
            _tl_cancel.event = None
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
    parser = argparse.ArgumentParser(description="Forensic Self-Audit (vigil_forensic)")
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
    disabled_gates = _load_project_disabled_gates(project_dir)
    if disabled_gates:
        print(f"      {len(disabled_gates)} gate(s) disabled by project (.cortex/disabled_gates.json)", file=sys.stderr)
    print(f"[3/3] Running gates ({'parallel x' + str(workers) if workers > 1 else 'sequential'})...", file=sys.stderr)
    outcomes, gates_skipped = run_gates(ctx, gates_filter, workers=workers, disabled_gates=disabled_gates)

    from vigil_forensic.meta_findings import drain_meta_findings
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
