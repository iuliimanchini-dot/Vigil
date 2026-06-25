"""Hotspot map builder -- Map 6.

Aggregates multi-dimensional risk factors from all available maps into a
ranked list of file-level hotspot entries.

Generic: operates on any RepoMaps, does not assume Vigil project layout.
Sanctioned-asset patterns are passed by the caller (resolved from seed at
the CLI entry layer in Phase 7).

Public API:
    build_hotspot_map(repo_maps, sanctioned_patterns=(), churn_data=None) -> list[HotspotEntry]
    compute_hotspot_churn_metadata(project_dir, since_window="90.days") -> tuple[dict, dict]
"""
from __future__ import annotations

import fnmatch
import json
import logging
import math
from collections.abc import Sequence
from datetime import datetime, timezone
from pathlib import Path

from .map_common import HOTSPOT_WEIGHTS, hotspot_mode_for_score, make_metadata
from .map_errors import MapIntegrityError
from .map_models import AuthorityDomain, DataContractEntry, RepoMaps, StructuralEntry
from .map_models_ext import ConflictEntry, HotspotEntry

__all__ = ["build_hotspot_map", "compute_hotspot_churn_metadata"]

_log = logging.getLogger(__name__)

_SOURCE = "automated_scoring"
_CONFIDENCE = 0.88


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _is_sanctioned(file: str, patterns: Sequence[str]) -> bool:
    """Return True if file matches any of the given fnmatch patterns."""
    for pat in patterns:
        if fnmatch.fnmatch(file, pat):
            return True
    return False


# ---------------------------------------------------------------------------
# Per-component scoring functions
# ---------------------------------------------------------------------------

def _structural_risk(file: str, structural_map: tuple) -> tuple[int, list[str]]:
    """Score based on structural tags. Range 0-20.

    Tag weights are read from HOTSPOT_WEIGHTS["structural_tags"] so they
    remain in one place (map_common.py).
    """
    tag_weights: dict = HOTSPOT_WEIGHTS.get("structural_tags", {
        "large_file": 10,
        "high_fan_in": 8,
        "high_fan_out": 3,
        "cycle_member": 5,
        "unparseable": 0,
    })
    score = 0
    reasons: list[str] = []
    for entry in structural_map:
        if not isinstance(entry, StructuralEntry) or entry.file != file:
            continue
        for tag in entry.tags:
            w = tag_weights.get(tag, 0)
            if w:
                score += w
                reasons.append("structural_tag:%s(+%d)" % (tag, w))
        break
    capped = min(score, HOTSPOT_WEIGHTS.get("structural_risk_max", 20))
    return capped, reasons


def _runtime_risk(file: str, runtime_map: tuple) -> tuple[int, list[str]]:
    """Score based on runtime tags. Range 0-20.

    Tag weights are read from HOTSPOT_WEIGHTS["runtime_tags"] so they
    remain in one place (map_common.py).
    """
    tag_weights: dict = HOTSPOT_WEIGHTS.get("runtime_tags", {
        "import_time_side_effects": 8,
        "background_task": 5,
        "decorator_registry": 3,
    })
    score = 0
    reasons: list[str] = []
    for node in runtime_map:
        defined_in = getattr(node, "defined_in", "")
        if defined_in != file:
            continue
        tags = getattr(node, "tags", ())
        for tag in tags:
            w = tag_weights.get(tag, 0)
            if w:
                score += w
                reasons.append("runtime_tag:%s(+%d)" % (tag, w))
    capped = min(score, HOTSPOT_WEIGHTS.get("runtime_risk_max", 20))
    return capped, reasons


def _authority_risk(
    file: str,
    authority_map: tuple,
    conflict_map: tuple = (),
) -> tuple[int, list[str]]:
    """Score based on authority ownership and open conflicts. Range 0-20.

    Scoring tiers (conflict-aware, Wave A Agent 3):
      - canonical_owner + any open conflict in that domain  -> authority_risk_with_conflict (20)
      - canonical_owner + no open conflicts                 -> authority_risk_base (5)
      - file is a source in any open conflict (writer role) -> authority_writer_in_conflict (+10)

    The canonical-owner tier is evaluated first (set, not add).  The writer
    role is additive so a file can score both as owner and as conflict writer.
    """
    import json as _json

    w_base: int = HOTSPOT_WEIGHTS.get("authority_risk_base", 5)
    w_conflict: int = HOTSPOT_WEIGHTS.get("authority_risk_with_conflict", 20)
    w_writer: int = HOTSPOT_WEIGHTS.get("authority_writer_in_conflict", 10)

    score = 0
    reasons: list[str] = []

    # --- Canonical-owner tier ---
    for domain in authority_map:
        if not isinstance(domain, AuthorityDomain):
            continue
        if domain.canonical_owner != file:
            continue
        # Check whether any open ConflictEntry belongs to this domain.
        has_open_conflict = _domain_has_open_conflict(domain.authority_domain, conflict_map)
        if has_open_conflict:
            score = w_conflict
            reasons.append(
                "canonical_owner_of:%s_with_open_conflict(+%d)" % (domain.authority_domain, w_conflict)
            )
        else:
            # Preserve legacy drift-event check as fallback when no conflict map.
            if not conflict_map and domain.last_drift_events:
                score = w_conflict
                reasons.append(
                    "canonical_owner_of:%s_with_drift_events(+%d)" % (domain.authority_domain, w_conflict)
                )
            else:
                score = w_base
                reasons.append(
                    "canonical_owner_of:%s_clean(+%d)" % (domain.authority_domain, w_base)
                )
        break  # Only count the first matching domain; cap applied below.

    # --- Writer-in-conflict tier (additive) ---
    writer_hit = False
    for conflict in conflict_map:
        conflict_status = getattr(conflict, "conflict_status", "")
        if conflict_status != "open":
            continue
        sources = getattr(conflict, "sources", ())
        for src_raw in sources:
            # sources are stored as JSON strings (per ConflictEntry model).
            if isinstance(src_raw, str):
                try:
                    src = _json.loads(src_raw)
                except Exception:
                    src = {}
            else:
                src = src_raw if isinstance(src_raw, dict) else {}
            if src.get("file") == file:
                if not writer_hit:
                    score += w_writer
                    reasons.append("writer_in_open_conflict(+%d)" % w_writer)
                    writer_hit = True
                break

    capped = min(score, HOTSPOT_WEIGHTS.get("authority_risk_max", 20))
    _log.debug("_authority_risk: file=%s raw=%d capped=%d", file, score, capped)
    return capped, reasons


def _domain_has_open_conflict(domain: str, conflict_map: tuple) -> bool:
    """Return True if any ConflictEntry in conflict_map is open and targets domain."""
    for conflict in conflict_map:
        if getattr(conflict, "conflict_status", "") != "open":
            continue
        # Match by domain field or subject prefix (e.g. "my_domain::symbol").
        if getattr(conflict, "domain", "") == domain:
            return True
        subject = getattr(conflict, "subject", "")
        if subject.startswith(domain + "::"):
            return True
    return False


def _duplication_score(
    file: str,
    contract_map: tuple,
) -> tuple[int, list[str]]:
    """Score +10 if file is involved in contract drift_flags. Range 0-20."""
    score = 0
    reasons: list[str] = []
    for contract in contract_map:
        if not isinstance(contract, DataContractEntry):
            continue
        if not contract.drift_flags:
            continue
        # Check if file is a writer or reader in this contract.
        if file in contract.writers or file in contract.readers:
            score += 10
            reasons.append(
                "drift_flags_in_contract:%s(+10)" % contract.entity
            )
            break  # Once is enough for the cap.
    capped = min(score, HOTSPOT_WEIGHTS.get("duplication_score_max", 20))
    return capped, reasons


def _test_gap(file: str, structural_map: tuple) -> tuple[int, list[str]]:
    """Score +10 if no test_<basename> file exists in structural map. Range 0-20."""
    import posixpath

    basename = posixpath.basename(file.replace("\\", "/"))
    stem = basename[: -len(".py")] if basename.endswith(".py") else basename
    expected_test = "test_" + stem

    for entry in structural_map:
        if not isinstance(entry, StructuralEntry):
            continue
        entry_base = posixpath.basename(entry.file.replace("\\", "/"))
        if entry_base.startswith("test_") and expected_test in entry_base:
            return 0, []

    score = min(10, HOTSPOT_WEIGHTS.get("test_gap_max", 20))
    return score, ["no_test_file_for:%s(+%d)" % (stem, score)]


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def _populate_hotspot_evidence(
    file: str,
    repo_maps: RepoMaps,
    all_reasons: list[str],
) -> tuple[str, ...]:
    """Build evidence tuples linking hotspot to contributing sources.

    Evidence strategy:
      1. Top fan-in sources from runtime map (kind="source_location")
      2. Related open conflicts (kind="map_entry", map="conflict")
      3. Representative list (max 8 items) to avoid bloat

    Returns:
        Tuple of JSON-serialized EvidenceItem strings.
    """
    from .map_models_findings import EvidenceItem

    evidence_items: list[EvidenceItem] = []

    # Build index of conflicts affecting this file
    conflict_evidence_added = False
    for conflict in repo_maps.conflict:
        conflict_status = getattr(conflict, "conflict_status", "")
        if conflict_status != "open":
            continue
        conflict_id = getattr(conflict, "conflict_id", "")
        domain = getattr(conflict, "domain", "")
        subject = getattr(conflict, "subject", "")

        # Check if this file is involved in the conflict (subject match or in sources)
        involved = (file == subject)
        if not involved:
            sources = getattr(conflict, "sources", ())
            for src_raw in sources:
                try:
                    import json as _json
                    src = _json.loads(src_raw) if isinstance(src_raw, str) else src_raw
                    if isinstance(src, dict) and src.get("file") == file:
                        involved = True
                        break
                except Exception:
                    pass

        if involved and conflict_id and not conflict_evidence_added:
            evidence_items.append(EvidenceItem(
                kind="map_entry",
                map="conflict",
                entry_id=conflict_id,
            ))
            conflict_evidence_added = True

    # Add high fan-in sources from structural map (top 3-5 importers)
    fan_in_sources: list[tuple[str, int]] = []
    for entry in repo_maps.structural:
        if not isinstance(entry, StructuralEntry) or entry.file != file:
            continue
        # Collect importers of this file, ranked by fan-in
        for importer in entry.imports_in:
            fan_in_sources.append((importer, 1))  # Each importer counts as 1
        break

    # Add top 3-5 fan-in contributors
    for importer, _ in sorted(fan_in_sources, key=lambda x: x[0])[:5]:
        evidence_items.append(EvidenceItem(
            kind="source_location",
            file=importer,
            map="structural",
        ))

    # Add runtime nodes defined in this file (if any high-risk tags)
    runtime_sources_added = 0
    for node in repo_maps.runtime:
        if runtime_sources_added >= 3:
            break
        defined_in = getattr(node, "defined_in", "")
        if defined_in != file:
            continue
        tags = getattr(node, "tags", ())
        # Only add runtime sources with significant tags
        if any(tag in ("import_time_side_effects", "background_task") for tag in tags):
            evidence_items.append(EvidenceItem(
                kind="source_location",
                file=file,
                map="runtime",
            ))
            runtime_sources_added += 1

    # Serialize to JSON strings
    result: list[str] = []
    for item in evidence_items[:8]:  # Cap at 8 items total
        result.append(json.dumps(item.to_dict(), sort_keys=True))

    return tuple(result)


def build_hotspot_map(
    repo_maps: RepoMaps,
    sanctioned_patterns: Sequence[str] = (),
    *,
    churn_data: dict[str, int] | None = None,
) -> list[HotspotEntry]:
    """Build a hotspot map ranking files by multi-dimensional risk score.

    Scoring formula (per spec Map 6, plan sec.19):
        score = structural_risk[0-20] + runtime_risk[0-20]
              + authority_risk[0-20] + duplication_score[0-20]
              + failure_frequency[0] + test_gap[0-20] + churn[0-20]
              - confidence_penalty[5]
        clamped to [0, 130].

    Mode assignment:
        0-30   -> safe_refactor
        31-60  -> contained_refactor
        61-90  -> forensic_first
        91+    -> do_not_touch_without_runtime_trace

    Sanctioned files (matching any sanctioned_patterns fnmatch) are excluded.

    Args:
        repo_maps: Container with all available maps.
        sanctioned_patterns: Glob/fnmatch patterns for files to exclude.
        churn_data: Optional per-file churn line counts (relative paths ->
            total added+deleted lines). If None (default), the churn
            component is 0 for all files (backward-compatible behaviour).
            Compute via :func:`compute_hotspot_churn_metadata`.

    Returns:
        List of HotspotEntry sorted by (-score, target) for deterministic
        tie-breaking.

    Raises:
        MapIntegrityError: If structural map is empty (minimum requirement).
    """
    if not repo_maps.structural:
        _log.info("hotspot: skipping -- structural map is empty (non-Python project or empty source tree)")
        return []

    churn: dict[str, int] = churn_data or {}

    _log.info(
        "build_hotspot_map: starting -- structural=%d runtime=%d "
        "contract=%d authority=%d sanctioned_patterns=%d churn_files=%d",
        len(repo_maps.structural),
        len(repo_maps.runtime),
        len(repo_maps.data_contract),
        len(repo_maps.authority),
        len(sanctioned_patterns),
        len(churn),
    )

    freshness = _utc_now()

    # Collect unique file targets from structural map (primary source of files).
    candidate_files: list[str] = []
    seen_files: set[str] = set()
    for entry in repo_maps.structural:
        if isinstance(entry, StructuralEntry) and entry.file not in seen_files:
            candidate_files.append(entry.file)
            seen_files.add(entry.file)

    entries: list[HotspotEntry] = []

    for file in candidate_files:
        # Exclude sanctioned assets.
        if _is_sanctioned(file, sanctioned_patterns):
            _log.debug("build_hotspot_map: skipping sanctioned file %s", file)
            continue

        all_reasons: list[str] = []

        sr, sr_reasons = _structural_risk(file, repo_maps.structural)
        rr, rr_reasons = _runtime_risk(file, repo_maps.runtime)
        ar, ar_reasons = _authority_risk(file, repo_maps.authority, repo_maps.conflict)
        ds, ds_reasons = _duplication_score(file, repo_maps.data_contract)
        tg, tg_reasons = _test_gap(file, repo_maps.structural)

        # Not yet implemented (no historical data).
        failure_frequency = 0
        # Churn component: log-scale dampened, capped at churn_cap (default 20).
        churn_raw = churn.get(file, 0)
        _churn_cap_raw = HOTSPOT_WEIGHTS.get("churn_cap", 20)
        _churn_cap = _churn_cap_raw if isinstance(_churn_cap_raw, int) else 20
        churn_component = min(
            _churn_cap,
            int(math.log1p(churn_raw) * 4),
        )
        # Default confidence penalty.
        confidence_penalty = 5

        raw_score = sr + rr + ar + ds + failure_frequency + tg + churn_component - confidence_penalty

        # Test-file penalty: test_*.py or *_test.py get a score reduction so
        # that production files with comparable structural risk rank higher.
        import posixpath as _posixpath
        _basename = _posixpath.basename(file.replace("\\", "/"))
        _penalty: int = 0
        if _basename.startswith("test_") or _basename.endswith("_test.py"):
            _penalty = HOTSPOT_WEIGHTS.get("test_file_penalty", -10)
            _penalty = _penalty if _penalty < 0 else -abs(_penalty)  # ensure negative
            all_reasons.append("test_file_penalty(%d)" % _penalty)
            _log.debug("build_hotspot_map: test file penalty applied to %s (%d)", file, _penalty)

        raw_score += _penalty
        score = max(0, min(130, raw_score))

        all_reasons.extend(sr_reasons)
        all_reasons.extend(rr_reasons)
        all_reasons.extend(ar_reasons)
        all_reasons.extend(ds_reasons)
        all_reasons.extend(tg_reasons)
        if churn_raw > 0:
            all_reasons.append("churn_%d(+%d)" % (churn_raw, churn_component))

        mode = hotspot_mode_for_score(score)

        # Populate evidence from contributing sources
        evidence = _populate_hotspot_evidence(file, repo_maps, all_reasons)

        entries.append(HotspotEntry(
            target=file,
            hotspot_score=score,
            reasons=tuple(all_reasons),
            recommended_mode=mode,
            source=_SOURCE,
            evidence=evidence,
            confidence=_CONFIDENCE,
            freshness=freshness,
            status="observed",
        ))

    # Sort: highest score first, then alphabetically by target for tie-break.
    entries.sort(key=lambda e: (-e.hotspot_score, e.target))

    _log.info(
        "build_hotspot_map: done -- %d entries, top score=%d",
        len(entries),
        entries[0].hotspot_score if entries else 0,
    )
    return entries


def compute_hotspot_churn_metadata(
    project_dir: Path,
    since_window: str = "90.days",
) -> tuple[dict[str, int], dict]:
    """Compute per-file churn and metadata for index audit.

    Build-scoped: no module-level caching. Each invocation executes a
    ``git log --numstat`` subprocess (fail-open -- returns empty dict on any
    error or when project_dir is not inside a git repo).

    Args:
        project_dir: Absolute path to the project root.
        since_window: ``--since`` window passed to ``git log``. Format:
            ``"90.days"``, ``"6.months"``, ``"2025-01-01"``, etc.

    Returns:
        ``(churn_data, metadata)`` where:
        - ``churn_data``: ``{relative_path: total_churn_lines}`` dict suitable
          for passing as ``churn_data`` kwarg to :func:`build_hotspot_map`.
        - ``metadata``: ``{churn_source, git_head_sha, since_window}`` dict
          for embedding in the map index under ``maps.hotspot``.
    """
    from ._git_utils import git_head_sha, git_has_repo, git_log_numstat

    churn_data: dict[str, int] = {}
    churn_source = "skipped"
    git_head = None

    if git_has_repo(project_dir):
        churn_data = git_log_numstat(project_dir, since=since_window)
        if churn_data:
            churn_source = "git_log_numstat"
        else:
            churn_source = "git_log_numstat_empty"
        git_head = git_head_sha(project_dir)

    metadata: dict = {
        "churn_source": churn_source,
        "git_head_sha": git_head,
        "since_window": since_window if churn_source.startswith("git_log_numstat") else None,
    }

    _log.info(
        "compute_hotspot_churn_metadata: source=%s files=%d git_head=%s",
        churn_source,
        len(churn_data),
        git_head,
    )
    return churn_data, metadata
