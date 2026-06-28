"""Boundary breach forensic gate (Finding 6.5).

boundary_breach: detect when a PR touches files that fall outside every
declared refactor boundary listed in .cortex/maps/70_refactor_boundaries.json.

Primary path: use ctx.maps.refactor_boundary when hydrated.
Fallback: read JSON file directly (legacy callers / maps not loaded).

Fail-open: map missing, unreadable, or malformed -> return empty findings.
"""
from __future__ import annotations

import fnmatch
import json
import logging
from pathlib import Path
from typing import Any

from vigil_forensic._shared import EvidenceReference, GateCategory, GateCheckResult, GateImpact, GateSeverity, RepairKind
from vigil_forensic.gate_models import PostExecGateContext

_CATEGORY = GateCategory.CONTRACT
from .common import build_check_result, build_finding, normalize_path

_log = logging.getLogger(__name__)

_MAP_REL_PATH = ".cortex/maps/70_refactor_boundaries.json"


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _file_in_boundary(file_path: str, includes: list[str]) -> bool:
    """Return True if *file_path* matches any include glob."""
    for pattern in includes:
        if fnmatch.fnmatch(file_path, pattern):
            return True
    return False


def _load_boundaries(project_dir: Path) -> list[dict[str, Any]] | None:
    """Load boundary entries from the map file.

    Returns a list of entry dicts on success, or None on any failure
    (missing file, JSON error, unexpected top-level shape).
    """
    map_path = project_dir / _MAP_REL_PATH
    try:
        raw = map_path.read_text(encoding="utf-8")
    except OSError as exc:
        _log.debug("boundary_breach: map not found at %s: %s", map_path, exc)
        return None

    try:
        data = json.loads(raw)
    except json.JSONDecodeError as exc:
        _log.debug("boundary_breach: map JSON malformed: %s", exc)
        return None

    if not isinstance(data, dict):
        _log.debug("boundary_breach: map root is not a dict")
        return None

    # Support both top-level keys used across spec versions.
    entries_raw = data.get("entries") or data.get("boundaries")
    if not isinstance(entries_raw, list):
        _log.debug("boundary_breach: map has no 'entries' or 'boundaries' list")
        return None

    return [e for e in entries_raw if isinstance(e, dict)]


def _build_includes(entry: dict[str, Any]) -> list[str]:
    """Extract glob patterns from an entry regardless of which key is used.

    Supported keys (in order of preference):
      - ``includes``     (spec-documented key)
      - ``allowed_files`` (map_builder key, exact paths treated as globs)
    """
    includes_raw = entry.get("includes") or entry.get("allowed_files")
    if isinstance(includes_raw, list):
        return [str(p) for p in includes_raw if p]
    return []


def _entry_from_boundary(b: Any) -> dict[str, Any]:
    """Convert a RefactorBoundary dataclass instance to the dict format used internally."""
    return {
        "boundary_id": b.boundary_id,
        "allowed_files": list(b.allowed_files),
        "watch_files": list(b.watch_files),
        "forbidden_files": list(b.forbidden_files),
        # no "active" key → _is_boundary_active returns True (all are active)
    }


def _is_boundary_active(entry: dict[str, Any]) -> bool:
    """Return True if the boundary should be checked.

    When no ``active`` flag is present all boundaries are considered active.
    When the flag is present it must be truthy to be active.
    """
    if "active" not in entry:
        return True
    return bool(entry["active"])


# ---------------------------------------------------------------------------
# Public gate function
# ---------------------------------------------------------------------------


def run_boundary_breach_checks(ctx: PostExecGateContext) -> GateCheckResult:
    """Emit a finding for every changed file that matches no active boundary.

    Primary path: use ctx.maps.refactor_boundary when hydrated and not missing.
    Fallback: read map JSON file from disk (legacy callers / maps not loaded).

    Fail-open: if the map is missing or malformed, return empty findings.
    """
    # --- Primary: ctx.maps ---------------------------------------------------
    boundaries: list[dict[str, Any]] | None = None
    if ctx.maps is not None and not getattr(ctx.maps, "missing", False):
        rb = getattr(ctx.maps, "refactor_boundary", None)
        if rb:
            boundaries = [_entry_from_boundary(b) for b in rb]
            _log.debug("boundary_breach: using %d entries from ctx.maps", len(boundaries))

    # --- Fallback: file read --------------------------------------------------
    if boundaries is None:
        boundaries = _load_boundaries(ctx.project_dir)

    if boundaries is None:
        return build_check_result(
            check_id="boundary_breach",
            category=_CATEGORY,
            notes=["boundary_breach: map missing or malformed -- skipped (fail-open)"],
        )

    active_include_lists: list[tuple[str, list[str]]] = []
    for entry in boundaries:
        if not _is_boundary_active(entry):
            continue
        includes = _build_includes(entry)
        if not includes:
            continue
        name = str(entry.get("boundary_id") or entry.get("name") or "unnamed")
        active_include_lists.append((name, includes))

    if not active_include_lists:
        return build_check_result(
            check_id="boundary_breach",
            category=_CATEGORY,
            notes=["boundary_breach: no active boundaries with include patterns -- skipped"],
        )

    findings = []
    for raw_path in ctx.changed_files_observed:
        normalized = normalize_path(raw_path)
        in_any = any(
            _file_in_boundary(normalized, includes)
            for _name, includes in active_include_lists
        )
        if not in_any:
            boundary_names = [name for name, _ in active_include_lists]
            findings.append(
                build_finding(
                    check_id="boundary_breach.file_outside_all_boundaries",
                    category=_CATEGORY,
                    title="Changed file is outside all declared refactor boundaries",
                    severity=GateSeverity.MEDIUM,
                    impact=GateImpact.REVISE,
                    summary=(
                        f"File '{normalized}' was changed but does not match any active "
                        f"boundary ({', '.join(boundary_names)})."
                    ),
                    recommendation=(
                        "Confirm that this change is intentional.  If it is part of the "
                        "current refactor, update the boundary definition in "
                        f"{_MAP_REL_PATH} to include this file."
                    ),
                    evidence=[
                        EvidenceReference(
                            kind="changed_file",
                            path=normalized,
                            detail=f"not matched by boundaries: {boundary_names}",
                        )
                    ],
                    repair_kind=RepairKind.VALIDATE_BOUNDARY.value,
                    executor_action="Address finding details",
                    proof_required="Authority respected",
                    allowlist_allowed=False,
                )
            )

    return build_check_result(
        check_id="boundary_breach",
        category=_CATEGORY,
        findings=findings,
    )
