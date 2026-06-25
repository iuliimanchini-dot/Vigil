"""Gate G.6 -- god_object_zones: detects responsibility-zone inflation in Python files.

A file is flagged when it exposes >=3 distinct function-name zones (everything
before the first underscore in the name maps to a zone in KNOWN_ZONES) AND the
file is at least MIN_FILE_LINES lines long.  Compact utility modules with fewer
than MIN_FILE_LINES lines are excluded to reduce false positives.

Fail-open: SyntaxError or missing file -> no finding, no exception.
"""
from __future__ import annotations

import ast
import logging

from cortex_forensic._shared import EvidenceReference, GateCategory, GateImpact, GateSeverity, RepairKind
from cortex_forensic.gate_models import PostExecGateContext
from cortex_forensic.source_analysis import is_source_file
from .common import build_check_result, build_finding, is_generated_file, normalize_path

_log = logging.getLogger(__name__)

# Minimum file length (lines) required before a zone-count finding is emitted.
MIN_FILE_LINES: int = 150

# Minimum number of distinct zones that must be present to trigger a finding.
MIN_ZONE_COUNT: int = 3

# Canonical set of concern-indicating prefixes.
KNOWN_ZONES: frozenset[str] = frozenset({
    "write",
    "save",
    "read",
    "load",
    "build",
    "compute",
    "render",
    "parse",
    "dispatch",
    "handle",
    "validate",
    "run",
    "start",
    "stop",
    "close",
    "open",
    "fetch",
    "send",
    "commit",
    "rollback",
    "acquire",
    "release",
})


def _extract_zone(name: str) -> str | None:
    """Return the zone prefix for a function name, or None if not in KNOWN_ZONES.

    Rules:
    - Strip a leading underscore before extracting (``_compute_hash`` -> ``compute``).
    - Take everything before the first ``_`` that occurs after position 0 of the
      (possibly stripped) name.
    - Return the prefix only when it belongs to KNOWN_ZONES.
    """
    stripped = name.lstrip("_")
    if not stripped:
        return None
    idx = stripped.find("_")
    prefix = stripped[:idx] if idx > 0 else stripped
    return prefix if prefix in KNOWN_ZONES else None


def _collect_zones(text: str) -> set[str]:
    """Parse *text* as Python source and return the set of known zone prefixes found.

    Returns an empty set on SyntaxError (fail-open).
    """
    try:
        tree = ast.parse(text)
    except SyntaxError:
        return set()

    zones: set[str] = set()
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        zone = _extract_zone(node.name)
        if zone is not None:
            zones.add(zone)
    return zones


def run_god_object_zones_checks(ctx: PostExecGateContext):
    """Check changed .py files for responsibility-zone inflation."""
    findings = []

    for raw_path in ctx.changed_files_observed:
        normalized = normalize_path(raw_path)
        if not is_source_file(normalized):
            continue

        abs_path = ctx.project_dir / normalized
        try:
            text = abs_path.read_text(encoding="utf-8", errors="replace")
        except OSError as exc:
            _log.debug("god_object_zones: cannot read %s: %s", normalized, exc)
            continue

        # F16d: skip auto-generated files and sanctioned asset bundles.
        if is_generated_file(text):
            _log.debug(
                "god_object_zones: skipping generated/sanctioned file %s",
                normalized,
            )
            continue

        line_count = len(text.splitlines())
        if line_count < MIN_FILE_LINES:
            _log.debug(
                "god_object_zones: skipping %s (%d lines < %d threshold)",
                normalized,
                line_count,
                MIN_FILE_LINES,
            )
            continue

        zones = _collect_zones(text)
        if len(zones) < MIN_ZONE_COUNT:
            _log.debug(
                "god_object_zones: %s has %d zone(s) -- below threshold",
                normalized,
                len(zones),
            )
            continue

        sorted_zones = sorted(zones)
        _log.info(
            "god_object_zones: %s triggers with zones %s",
            normalized,
            sorted_zones,
        )
        findings.append(
            build_finding(
                check_id="god_object_zones.zone_inflation",
                category=GateCategory.DRIFT,
                title="File owns multiple responsibility zones",
                severity=GateSeverity.MEDIUM,
                impact=GateImpact.REVISE,
                summary=(
                    f"{normalized} ({line_count} lines) exposes "
                    f"{len(zones)} distinct zones: {sorted_zones}.  "
                    f"Split into focused modules or extract shared helpers."
                ),
                recommendation=(
                    "Split this file by responsibility zone. "
                    "If zones share common helpers — move them to `<package>/shared.py` or `<package>/utils.py` "
                    "and import from there. "
                    "If zones are unrelated — move each into its own domain module. "
                    "A single module should own exactly one concern."
                ),
                evidence=[EvidenceReference(kind="file", path=normalized)],
            
                repair_kind='split_module',
                executor_action='Split file into modules',
                proof_required='Below complexity threshold',
                allowlist_allowed=False,
            )
        )

    return build_check_result(
        check_id="god_object_zones",
        category=GateCategory.DRIFT,
        findings=findings,
    )
