"""FX-V5-012 hunter artifact completeness check.

Soft-severity gate that scans <project>/.cortex/context_hunter/*.json and
emits a finding for each file that is corrupted, unparseable, or missing
expected schema fields. Prevents silent hunter cache corruption from going
undetected by downstream consumers.

Out of scope:
  - Cache directory missing -> no finding (hunter may simply not have run
    for this project; FX-V4-002 remote_authoritative mode also produces
    files under .cortex/_hunter_remote_cache/ which we do NOT scan here).
  - Empty cache directory -> no finding (same reasoning).
  - Stale-by-TTL files -> not our concern (FIX-025 cleanup_stale_cache owns).

Fail-open: any I/O / parse error on the *check itself* is logged at DEBUG
and produces no finding — same contract as every gate runner in this pack.

Severity policy:
  - Unparseable JSON      -> MEDIUM (operator should inspect / clear)
  - Missing required keys -> LOW    (gate uses heuristic; schema may
                                     evolve faster than the check)
  - I/O failure on read   -> LOW    (likely transient; symptom not cause)

Each finding is per-file (fingerprint includes the relative path).
"""
from __future__ import annotations

import json
import logging

from vigil_forensic._shared import (
    EvidenceReference, GateCategory, GateImpact, GateSeverity,
)
from vigil_forensic.gate_models import PostExecGateContext
from .common import build_check_result, build_finding

_log = logging.getLogger(__name__)

_CHECK_ID = "hunter_artifact_completeness"
_HUNTER_CACHE_SUBPATH = (".cortex", "context_hunter")

# Minimum keys a well-formed hunter artifact JSON should have. Hunter writes
# {"stage": <name>, "data": {...}} as canonical format; some legacy artifacts
# may omit "stage" — we treat both keys missing as schema divergence rather
# than just one (avoid noisy false positives during the v5 schema migration).
_REQUIRED_KEYS_ANY = ("data", "stage")


def run_hunter_artifact_completeness_checks(ctx: PostExecGateContext):
    findings = []

    cache_dir = ctx.project_dir.joinpath(*_HUNTER_CACHE_SUBPATH)
    if not cache_dir.exists() or not cache_dir.is_dir():
        return build_check_result(check_id=_CHECK_ID, category=GateCategory.META, findings=findings)

    for json_path in sorted(cache_dir.glob("*.json")):
        # Skip codex temp schemas — they are not hunter artifacts and have
        # their own cleanup contract (FIX-020 in hunter_runner.cleanup_stale_cache).
        if json_path.name.startswith("_tmp_"):
            continue

        rel_path = str(json_path.relative_to(ctx.project_dir)).replace("\\", "/")

        try:
            raw = json_path.read_text(encoding="utf-8")
        except OSError as exc:
            _log.debug("FX-V5-012: I/O failure reading %s: %s", rel_path, exc)
            findings.append(
                build_finding(
                    check_id=_CHECK_ID,
                    category=GateCategory.META,
                    title=f"hunter artifact unreadable: {json_path.name}",
                    severity=GateSeverity.LOW,
                    impact=GateImpact.WARN,
                    summary=f"OSError reading hunter cache artifact: {exc!s}",
                    recommendation=(
                        "Investigate filesystem permissions / disk health. "
                        "Safe to delete the file — hunter will regenerate on next call."
                    ),
                    evidence=(EvidenceReference(kind="file", path=rel_path, detail=str(exc)),),
                    repair_kind="manual_inspection",
                )
            )
            continue

        try:
            parsed = json.loads(raw)
        except (json.JSONDecodeError, ValueError) as exc:
            findings.append(
                build_finding(
                    check_id=_CHECK_ID,
                    category=GateCategory.META,
                    title=f"hunter artifact corrupted: {json_path.name}",
                    severity=GateSeverity.MEDIUM,
                    impact=GateImpact.WARN,
                    summary=(
                        f"JSON parse error in hunter cache artifact: {exc!s}. "
                        f"Cache hit on this file would deliver garbage to the "
                        f"caller of the hunter intake helper."
                    ),
                    recommendation=(
                        "Delete the corrupted file. Hunter will regenerate it on next "
                        "matching stage call. If recurring, investigate the writer in "
                        "BRAIN/context_hunter/hunter_runner.py for partial-write race."
                    ),
                    evidence=(EvidenceReference(kind="file", path=rel_path, detail=f"parse error at offset {getattr(exc, 'pos', '?')}"),),
                    repair_kind="delete_artifact",
                )
            )
            continue

        # Schema sanity: well-formed hunter artifact should have at least
        # one of the required keys. Hunter v5 writes {"stage": ..., "data": ...}.
        # An artifact with neither is suspicious — either a foreign file
        # accidentally placed in the cache dir, or a writer regression.
        if isinstance(parsed, dict) and not any(k in parsed for k in _REQUIRED_KEYS_ANY):
            findings.append(
                build_finding(
                    check_id=_CHECK_ID,
                    category=GateCategory.META,
                    title=f"hunter artifact schema divergence: {json_path.name}",
                    severity=GateSeverity.LOW,
                    impact=GateImpact.WARN,
                    summary=(
                        f"Hunter cache artifact lacks required keys "
                        f"({' or '.join(_REQUIRED_KEYS_ANY)}). Parsed top-level keys: "
                        f"{sorted(parsed.keys())[:10]}."
                    ),
                    recommendation=(
                        "Confirm the file was written by hunter_runner. If not, move it "
                        "out of .cortex/context_hunter/. If yes, investigate writer for "
                        "schema regression."
                    ),
                    evidence=(EvidenceReference(kind="file", path=rel_path, detail=f"top_keys={sorted(parsed.keys() if isinstance(parsed, dict) else [])[:10]}"),),
                    repair_kind="schema_inspection",
                )
            )

    return build_check_result(check_id=_CHECK_ID, category=GateCategory.META, findings=findings)
