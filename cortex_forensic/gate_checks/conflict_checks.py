"""Unresolved high-conflict touch forensic gate (Finding 6.6).

conflict_touch: detect when a PR touches files flagged in the conflict map
as unresolved and with severity high or critical.

Primary path: use ctx.maps.conflict when hydrated.
Fallback: read .cortex/maps/50_conflict_map.json from disk (legacy callers).

Fail-open: map missing, unreadable, or malformed -> return empty findings.
"""
from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

from cortex_forensic._shared import EvidenceReference, GateCategory, GateImpact, GateSeverity, RepairKind
from cortex_forensic.gate_models import PostExecGateContext

_CATEGORY = GateCategory.CONTRACT
from .common import build_check_result, build_finding, normalize_path

_log = logging.getLogger(__name__)

_MAP_REL_PATH = ".cortex/maps/50_conflict_map.json"

_HIGH_SEVERITIES = frozenset({"high", "critical"})


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _load_conflicts(project_dir: Path) -> list[dict[str, Any]] | None:
    """Load conflict entries from the map file.

    Returns a list of conflict dicts on success, or None on any failure
    (missing file, JSON error, unexpected top-level shape).
    """
    map_path = project_dir / _MAP_REL_PATH
    try:
        raw = map_path.read_text(encoding="utf-8")
    except OSError as exc:
        _log.debug("conflict_touch: map not found at %s: %s", map_path, exc)
        return None

    try:
        data = json.loads(raw)
    except json.JSONDecodeError as exc:
        _log.debug("conflict_touch: map JSON malformed: %s", exc)
        return None

    if not isinstance(data, dict):
        _log.debug("conflict_touch: map root is not a dict")
        return None

    conflicts_raw = data.get("conflicts")
    if not isinstance(conflicts_raw, list):
        _log.debug("conflict_touch: map has no 'conflicts' list")
        return None

    return [c for c in conflicts_raw if isinstance(c, dict)]


def _entry_from_conflict(c: Any) -> dict[str, Any]:
    """Convert a ConflictEntry dataclass instance to the dict format used internally.

    ConflictEntry uses ``conflict_status`` (open/in_progress/resolved) rather than
    a boolean ``resolved`` field.  Map to the dict shape that _build_high_conflict_files
    expects: ``resolved`` = True only when conflict_status == "resolved".
    """
    conflict_status = str(getattr(c, "conflict_status", "open") or "open").lower()
    # Gather files from ``sources`` tuples (JSON strings containing {"file": ...} dicts)
    # and from the subject field as a best-effort path hint.
    import json as _json
    files: list[str] = []
    for src_raw in (getattr(c, "sources", ()) or ()):
        try:
            src = _json.loads(src_raw) if isinstance(src_raw, str) else src_raw
            if isinstance(src, dict):
                # Sources may carry a "file" key
                if "file" in src:
                    files.append(str(src["file"]))
        except _json.JSONDecodeError as exc:
            _log.debug("conflict_checks: skipping malformed source JSON %r: %s", src_raw, exc)
            # Fallback safe here: one unparseable source string doesn't affect other sources
    # Evidence strings may also contain file paths
    for ev in (getattr(c, "evidence", ()) or ()):
        ev_str = str(ev)
        if ev_str and ("/" in ev_str or "\\" in ev_str) and not ev_str.startswith("{"):
            files.append(ev_str)
    return {
        "files": files,
        "severity": str(getattr(c, "severity", "medium") or "medium"),
        "resolved": conflict_status == "resolved",
        "summary": str(getattr(c, "subject", "") or ""),
    }


def _build_high_conflict_files(conflicts: list[dict[str, Any]]) -> set[str]:
    """Return the set of file paths that are unresolved AND high/critical severity."""
    result: set[str] = set()
    for entry in conflicts:
        resolved = entry.get("resolved", True)
        if resolved:
            continue
        severity = str(entry.get("severity", "")).lower()
        if severity not in _HIGH_SEVERITIES:
            continue
        files_raw = entry.get("files")
        if isinstance(files_raw, list):
            for f in files_raw:
                if f:
                    result.add(normalize_path(str(f)))
    return result


# ---------------------------------------------------------------------------
# Public gate function
# ---------------------------------------------------------------------------


def run_conflict_touch_checks(ctx: PostExecGateContext):
    """Emit a finding for every changed file that is an unresolved high/critical conflict.

    Primary path: use ctx.maps.conflict when hydrated and not missing.
    Fallback: read map JSON file from disk (legacy callers / maps not loaded).

    Fail-open: if the map is missing or malformed, return empty findings.
    """
    # --- Primary: ctx.maps ---------------------------------------------------
    conflicts: list[dict[str, Any]] | None = None
    if ctx.maps is not None and not getattr(ctx.maps, "missing", False):
        cm = getattr(ctx.maps, "conflict", None)
        if cm:
            conflicts = [_entry_from_conflict(c) for c in cm]
            _log.debug("conflict_touch: using %d entries from ctx.maps", len(conflicts))

    # --- Fallback: file read --------------------------------------------------
    if conflicts is None:
        conflicts = _load_conflicts(ctx.project_dir)

    if conflicts is None:
        return build_check_result(
            check_id="conflict_touch",
            category=_CATEGORY,
            notes=["conflict_touch: map missing or malformed -- skipped (fail-open)"],
        )

    high_conflict_files = _build_high_conflict_files(conflicts)

    findings = []
    for raw_path in ctx.changed_files_observed:
        normalized = normalize_path(raw_path)
        if normalized in high_conflict_files:
            findings.append(
                build_finding(
                    check_id="conflict_touch.unresolved_high_conflict",
                    category=_CATEGORY,
                    title="Changed file has an unresolved high-severity conflict",
                    severity=GateSeverity.MEDIUM,
                    impact=GateImpact.REVISE,
                    summary=(
                        f"File '{normalized}' was changed and is flagged in the conflict map "
                        f"as unresolved with high or critical severity."
                    ),
                    recommendation=(
                        "Resolve the conflict recorded in the conflict map before landing "
                        f"this change, or update {_MAP_REL_PATH} if the conflict was "
                        "already addressed."
                    ),
                    evidence=[
                        EvidenceReference(
                            kind="changed_file",
                            path=normalized,
                            detail="unresolved high/critical conflict in conflict map",
                        )
                    ],
                
                    repair_kind='fix_contract',
                    executor_action='Fix conflict',
                    proof_required='No conflict',
                    allowlist_allowed=False,
                )
            )

    return build_check_result(
        check_id="conflict_touch",
        category=_CATEGORY,
        findings=findings,
    )
