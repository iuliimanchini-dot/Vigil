"""Shared utilities, constants and helpers for the map builder subsystem.

Contains: iter_py_files, make_metadata, STRUCTURAL_THRESHOLDS,
HOTSPOT_WEIGHTS, hotspot_mode_for_score.

Generic design: operates on any target project_dir, not on Vigil itself.
Default layout per-project:
    <project_dir>/.cortex/maps/      -- generated map outputs
    <project_dir>/.cortex/map_seeds/ -- optional seed config
"""
from __future__ import annotations

import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator, Sequence

__all__ = [
    "classify_file_role",
    "iter_py_files",
    "iter_source_files",
    "make_metadata",
    "get_coverage_metadata",
    "get_file_inventory_cache",
    "update_file_inventory_cache",
    "STRUCTURAL_THRESHOLDS",
    "CONTRACT_THRESHOLDS",
    "HOTSPOT_WEIGHTS",
    "hotspot_mode_for_score",
    "MAPS_SUBDIR",
    "SEEDS_SUBDIR",
]

_log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Convention paths (per-project, relative to project_dir)
# ---------------------------------------------------------------------------

# Default per-project layout (under target project):
#   <project_dir>/.cortex/maps/          -- generated map outputs
#   <project_dir>/.cortex/map_seeds/     -- optional seed config
# Matches existing .cortex/ convention in Vigil (gate_profile.json etc).
MAPS_SUBDIR = ".cortex/maps"
SEEDS_SUBDIR = ".cortex/map_seeds"

# ---------------------------------------------------------------------------
# Threshold constants
# ---------------------------------------------------------------------------

STRUCTURAL_THRESHOLDS: dict[str, int] = {
    "large_file_lines": 1200,
    "high_fan_in": 10,
    "high_fan_out": 15,
}

CONTRACT_THRESHOLDS: dict[str, int] = {
    "max_drift_flags": 10,
    "max_variants": 20,
}

# Hotspot scoring weights per spec Part 6 formula.
# hotspot_score =
#   structural_risk[0-20] + runtime_risk[0-20] + authority_risk[0-20]
#   + duplication_score[0-20] + failure_frequency[0-20]
#   + test_gap[0-20] + churn[0-20] - confidence[0-10]
#
# Keys marked NEW were added in Wave A / Agent 3 to fix test-file overscoring
# and improve authority/structural signal fidelity.
HOTSPOT_WEIGHTS: dict = {
    # --- Per-component caps (unchanged from spec) ---
    "structural_risk_max": 20,
    "runtime_risk_max": 20,
    "authority_risk_max": 20,
    "duplication_score_max": 20,
    "failure_frequency_max": 20,
    "test_gap_max": 20,
    "churn_max": 20,
    "confidence_penalty_max": 10,
    # --- Structural tag weights (NEW: fan_in 5→8, cycle_member 2→5, unparseable=0) ---
    "structural_tags": {
        "large_file": 10,
        "high_fan_in": 8,       # up from 5: fan-in is a critical structural signal
        "high_fan_out": 3,
        "cycle_member": 5,      # up from 2: cycle membership = elevated risk
        "unparseable": 0,       # no score bonus for parse errors
    },
    # --- Runtime tag weights (unchanged) ---
    "runtime_tags": {
        "import_time_side_effects": 8,
        "background_task": 5,
        "decorator_registry": 3,
    },
    # --- Authority risk weights (NEW: replaces flat +15 with conflict-aware tiers) ---
    "authority_risk_base": 5,               # NEW: canonical_owner, no open conflicts -> +5
    "authority_risk_with_conflict": 20,     # NEW: canonical_owner + any open conflict -> +20
    "authority_writer_in_conflict": 10,     # NEW: file is a source in an open conflict -> +10
    # --- Test file penalty (NEW) ---
    "test_file_penalty": -10,               # NEW: test_*.py / *_test.py -> -10
    # --- Churn cap (E2) ---
    "churn_cap": 20,                        # E2: log-scale churn component ceiling
}

# Hotspot mode thresholds (inclusive lower bound)
_HOTSPOT_MODE_THRESHOLDS: list[tuple[int, str]] = [
    (90, "do_not_touch_without_runtime_trace"),
    (60, "forensic_first"),
    (30, "contained_refactor"),
    (0,  "safe_refactor"),
]

# ---------------------------------------------------------------------------
# Exclusion set for iter_py_files
# ---------------------------------------------------------------------------

# Directory names (any path component) that are always excluded.
# SYSTEM/libs is a special case: excluded by subtree prefix matching below.
_DEFAULT_EXCLUSIONS: frozenset[str] = frozenset({
    ".git",
    "__pycache__",
    ".venv",
    "venv",
    "env",
    "node_modules",
    ".tox",
    "build",
    "dist",
    ".pytest_cache",
    ".mypy_cache",
    ".ruff_cache",
    # Don't scan map outputs or seeds themselves
    ".cortex",
    # Exclude tool/agent config directories
    ".claude",           # Claude Code config + agent worktrees
    ".codex",            # Codex cache directory
    ".prompt-engineer",  # PE Supervisor docs (roadmap.md, AGREEMENTS.md)
    ".a1",               # Task manager artifacts (tasks.json, plans/{id}.md)
})

# Subtree prefixes (as posix relative paths) that are excluded even if
# their directory name doesn't appear in _DEFAULT_EXCLUSIONS.
# SYSTEM/libs is a vendor bundle in Vigil — harmless for user projects
# (path simply won't exist), and correctly excluded for Vigil self-diag.
_EXCLUDED_SUBTREE_PREFIXES: tuple[str, ...] = (
    "SYSTEM/libs/",
    ".claude/",      # Entire .claude subtree (includes worktrees, plans, memory)
    ".codex/",       # Codex cache directory
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def classify_file_role(rel_posix: str) -> str:
    """Classify file role: 'test', 'fixture', 'generated', or 'production'.

    Used to distinguish production code from test/fixture/generated artifacts.
    """
    s = rel_posix.lower().replace("\\", "/")

    # Fixture patterns take precedence
    if any(p in s for p in ("/fixtures/", "/snapshots/", "/mocks/")):
        return "fixture"

    # Test patterns
    test_patterns = ("/tests/", "/test/", "test_", "_test.py", "/conftest.py")
    if any(p in s for p in test_patterns):
        return "test"

    # Generated patterns
    generated_patterns = ("/generated/", "/migrations/", "/alembic/")
    if any(p in s for p in generated_patterns):
        return "generated"

    return "production"


def iter_source_files(
    project_dir: Path,
    languages: Sequence[str] | None = None,
    include_roots: Sequence[str] | None = None,
) -> Iterator[Path]:
    """Yield absolute paths to source files handled by registered adapters.

    Args:
        project_dir: Root of the target project to scan.
        languages: Optional list of language names (e.g. ``["python"]``) to
            restrict the scan to. If None, all extensions registered in
            ``ADAPTERS`` are included. Unknown language names silently
            contribute zero extensions.
        include_roots: Optional list of subdirectory names relative to
            project_dir to restrict the scan to. If None (default), the
            entire project_dir is walked (minus exclusions).

    Exclusions applied always:
        - Any path component matching _DEFAULT_EXCLUSIONS (.git, __pycache__,
          .venv, venv, env, node_modules, .tox, build, dist, .pytest_cache,
          .mypy_cache, .ruff_cache, .cortex).
        - SYSTEM/libs/ subtree (Vigil vendor bundle; harmless for user
          projects where that path simply does not exist).
        - Symlinks resolving outside project_dir.

    Output is sorted for deterministic ordering.

    Notes:
        ADAPTERS currently registers 5 languages: Python, TypeScript, JavaScript,
        Go, and Java.  ``iter_source_files`` yields files for all of them by
        default (no ``languages`` filter).  Pass ``languages=["python"]`` to
        restrict to ``.py`` only (see ``iter_py_files``).
    """
    # Import here to avoid circular import (source_adapters imports map_common
    # indirectly through builder utilities in L2+; keeping deferred is safe).
    from .source_adapters import ADAPTERS  # noqa: PLC0415

    if languages is None:
        target_exts: frozenset[str] = frozenset(ADAPTERS.keys())
    else:
        target_exts = frozenset(
            ext
            for ext, adapter in ADAPTERS.items()
            if adapter.language in languages
        )

    if not target_exts:
        _log.debug(
            "iter_source_files: no registered extensions for languages=%r -- returning empty",
            languages,
        )
        return

    results: list[Path] = []
    project_dir = project_dir.resolve()

    if include_roots is not None:
        roots: list[Path] = []
        for root_name in include_roots:
            root = project_dir / root_name
            if not root.is_dir():
                _log.debug(
                    "iter_source_files: include_root missing, skipping: %s", root_name
                )
                continue
            roots.append(root)
    else:
        roots = [project_dir]

    import os
    for root in roots:
        for dirpath_str, dirnames, filenames in os.walk(str(root), topdown=True):
            dirpath = Path(dirpath_str)
            try:
                rel_dir = dirpath.relative_to(project_dir)
            except ValueError:
                rel_dir = Path()

            # Prune directories that match _DEFAULT_EXCLUSIONS
            dirnames[:] = [d for d in dirnames if d not in _DEFAULT_EXCLUSIONS]

            # Prune directories that match _EXCLUDED_SUBTREE_PREFIXES
            dirnames_to_keep = []
            for d in dirnames:
                child_rel = rel_dir / d
                child_posix = child_rel.as_posix() + "/"
                if any(child_posix.startswith(prefix) for prefix in _EXCLUDED_SUBTREE_PREFIXES):
                    continue
                dirnames_to_keep.append(d)
            dirnames[:] = dirnames_to_keep

            for fname in filenames:
                src_file = dirpath / fname
                if not src_file.is_file():
                    continue
                if src_file.suffix.lower() not in target_exts:
                    continue

                # Resolve path (no strict — file may be a symlink target)
                resolved = src_file.resolve(strict=False)

                # Skip if not inside project_dir (symlink escape)
                try:
                    resolved.relative_to(project_dir)
                except ValueError:
                    _log.debug(
                        "iter_source_files: skipping symlink escape: %s", src_file
                    )
                    continue

                results.append(src_file)

    results.sort()
    _log.debug(
        "iter_source_files: found %d files (languages=%r) under %s",
        len(results),
        languages,
        project_dir,
    )
    yield from results


def iter_py_files(
    project_dir: Path,
    include_roots: Sequence[str] | None = None,
) -> Iterator[Path]:
    """Yield absolute paths to .py files under project_dir.

    Backward-compatible alias for ``iter_source_files(project_dir,
    languages=["python"], include_roots=include_roots)``.

    Args:
        project_dir: Root of the target project to scan.
        include_roots: Optional list of subdirectory names relative to
            project_dir to restrict the scan to. If None (default), the
            entire project_dir is walked (minus exclusions).

    Exclusions applied always:
        - Any path component matching _DEFAULT_EXCLUSIONS (.git, __pycache__,
          .venv, venv, env, node_modules, .tox, build, dist, .pytest_cache,
          .mypy_cache, .ruff_cache, .cortex).
        - SYSTEM/libs/ subtree (Vigil vendor bundle; harmless for user
          projects where that path simply does not exist).
        - Symlinks resolving outside project_dir.

    Output is sorted for deterministic ordering.
    """
    yield from iter_source_files(
        project_dir,
        languages=["python"],
        include_roots=include_roots,
    )


def make_metadata(
    source: str,
    confidence: float,
    status: str,
    evidence: tuple[str, ...] = (),
) -> dict:
    """Build a standard MapMetadata-compatible dict with UTC freshness."""
    freshness = (
        datetime.now(timezone.utc)
        .isoformat()
        .replace("+00:00", "Z")
    )
    return {
        "source": source,
        "evidence": list(evidence),
        "confidence": confidence,
        "freshness": freshness,
        "status": status,
    }


def hotspot_mode_for_score(score: int) -> str:
    """Return recommended_mode string for a given hotspot score.

    Thresholds: >=90 -> do_not_touch, >=60 -> forensic_first,
    >=30 -> contained_refactor, else safe_refactor.
    """
    for threshold, mode in _HOTSPOT_MODE_THRESHOLDS:
        if score >= threshold:
            return mode
    return "safe_refactor"


def get_file_inventory_cache(project_dir: Path) -> "Any":
    """Return a ParseCacheL2 instance for persistent on-disk parse caching.

    Convenience wrapper so callers can obtain an L2 cache without importing
    parse_cache directly.  Returns a ``ParseCacheL2`` whose cache dir lives
    under ``<project_dir>/.cortex/.map_cache/``.
    """
    from .parse_cache import ParseCacheL2  # noqa: PLC0415
    return ParseCacheL2(project_dir)


def update_file_inventory_cache(project_dir: Path, cache: "Any") -> None:
    """Flush and finalise the file inventory cache after a build.

    Currently a no-op — ParseCacheL2 writes are already atomic — but
    callers should call this so future cleanup logic can be added here.
    """
    if cache is not None:
        cache.flush()


def get_coverage_metadata(builder_name: str) -> dict:
    """Return supported language coverage for a specific builder.

    Args:
        builder_name: one of 'structural', 'runtime', 'data_contract', 'authority'
            ('contract' is accepted as alias for 'data_contract')

    Returns:
        dict with 'supported_languages' and 'feature_matrix' keys.
        Example:
        {
            'supported_languages': ['python', 'typescript', 'javascript', 'go', 'java'],
            'feature_matrix': {
                'python': {'imports': True, 'contracts': True, 'runtime': True, 'writes': True},
                'typescript': {'imports': True, 'contracts': False, 'runtime': True, 'writes': False},
                ...
            }
        }
    """
    from .source_adapters import ADAPTERS  # noqa: PLC0415

    # Normalize builder name (data_contract is primary, contract is alias)
    normalized_name = 'contract' if builder_name in ('data_contract', 'contract') else builder_name

    feature_map = {
        'structural': lambda a: a.supports_structural,
        'runtime': lambda a: a.supports_runtime_signals,
        'contract': lambda a: a.supports_contracts,
        'authority': lambda a: a.supports_authority_writes,
    }

    get_supported = feature_map.get(normalized_name, lambda a: False)

    # Build feature matrix: language -> {feature: supported}
    feature_matrix = {}
    for ext, adapter in sorted(ADAPTERS.items()):
        lang = adapter.language
        if lang not in feature_matrix:
            feature_matrix[lang] = {
                'imports': adapter.supports_structural,
                'contracts': adapter.supports_contracts,
                'runtime': adapter.supports_runtime_signals,
                'writes': adapter.supports_authority_writes,
            }

    # Supported languages for this builder
    supported = [
        adapter.language for adapter in ADAPTERS.values()
        if get_supported(adapter)
    ]
    supported = sorted(set(supported))

    return {
        'supported_languages': supported,
        'feature_matrix': feature_matrix,
    }
