"""Semantic diff for map JSON files, ignoring timestamp-like fields.

Used by rebuild worker (Phase E1) to decide whether to promote temp-dir
rebuild output to canonical location -- skip write if content unchanged
modulo ignored timestamps.
"""
from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

__all__ = ["semantic_map_diff"]

_log = logging.getLogger(__name__)

_IGNORED_FIELDS: frozenset[str] = frozenset({
    # Build timestamps / envelope — never semantic content
    "built_at",
    "freshness",
    "produced_by",
    "build_duration_s",
    "generated_at",
    "map_name",
    # Build-environment git metadata (hotspot map only — see cli_entry.py
    # `_hotspot_churn_meta`).  `git_head_sha` leaks into the payload when any
    # git activity occurs between the two rebuild runs (commit, branch move,
    # rebase).  `churn_source` toggles between "git_log_numstat",
    # "git_log_numstat_empty", and "skipped" depending on whether the index
    # refresh picked up a git hiccup.  `since_window` is stable for a given
    # build config but belongs to the same metadata class and is therefore
    # excluded for consistency.  Excluding these three fields keeps the
    # semantic-diff focused on map *content*, not build environment.
    "git_head_sha",
    "churn_source",
    "since_window",
    # Derived size of the serialized map file — jitters ±1 byte whenever
    # build_duration_s crosses a decimal-digit boundary (e.g. "0.42" → "0.395").
    # Recorded in 00_map_index.json per-map entry; not semantic payload.
    "file_bytes",
})


def semantic_map_diff(new_path: Path, old_path: Path) -> bool:
    """Return True if two map JSONs are semantically identical (ignoring timestamp fields).

    Returns True (identical) if both parse and stripped structures equal.
    Returns False if either file unreadable/invalid JSON or content differs.
    Fail-safe: any error -> False (treat as "changed", triggers write).
    """
    try:
        new_data = json.loads(new_path.read_text(encoding="utf-8"))
        old_data = json.loads(old_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        _log.debug(
            "semantic_map_diff: read/parse failed (%s): %s",
            type(exc).__name__,
            new_path,
        )
        return False  # treat as changed on any error
    return _strip_ignored(new_data) == _strip_ignored(old_data)


def _strip_ignored(obj: Any) -> Any:
    """Recursively strip ignored fields from nested dict/list structure."""
    if isinstance(obj, dict):
        return {k: _strip_ignored(v) for k, v in obj.items() if k not in _IGNORED_FIELDS}
    if isinstance(obj, list):
        return [_strip_ignored(x) for x in obj]
    return obj
