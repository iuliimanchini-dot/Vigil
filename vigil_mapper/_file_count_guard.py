"""Shared file-count guard (anti-hang on huge repos).

Both the forensic auditor and the code-map builder do per-file work that scales
with the number of source files (forensic averages ~0.4 s/file across its gate
AST walks). On a real repo with thousands of files this turns into hours and
effectively hangs the machine. A per-file *size* guard already exists but does
nothing against thousands of *small* files — only a guard on the file COUNT can.

This module is pure stdlib (no project imports) so it is safe to import from
either package without circular-import risk. It lives in ``vigil_mapper``
because the dependency arrow is forensic -> map (forensic may import map; map
never imports forensic), so this is the one place both sides can share.

Helpers
-------
summarize_top_subdirs(rel_paths, limit)
    Group relative paths by their top-level directory component and return the
    ``limit`` biggest as ``[{"dir": str, "files": int}, ...]`` (descending).
    Files directly under the project root are grouped under ``"."``.
build_too_many_files_meta(rel_paths, max_files, *, entry_call=...)
    Build the structured ``too_many_files`` meta dict returned by both tools
    when ``len(rel_paths) > max_files``.

Default ceiling
---------------
``DEFAULT_MAX_FILES = 800``. Forensic averages ~0.4 s/file, so ~800 files is a
~5-minute ceiling — a sane upper bound for an interactive tool. Callers can pass
a larger ``max_files`` to force a full scan.
"""
from __future__ import annotations

from collections import Counter

__all__ = [
    "DEFAULT_MAX_FILES",
    "summarize_top_subdirs",
    "build_too_many_files_meta",
]

# Forensic averages ~0.4 s/file -> ~800 files is a ~5 min ceiling.
DEFAULT_MAX_FILES = 800

# How many top sub-directories to report in the skip result.
_TOP_SUBDIRS = 8


def _top_component(rel_path: str) -> str:
    """Return the first path component of a posix-ish relative path.

    Files directly under the project root (no separator) are grouped under
    ``"."`` so the caller always gets a stable bucket name. Leading ``"./"`` is
    stripped, but a leading-dot directory name (e.g. ``.claude``) is preserved.
    """
    norm = rel_path.replace("\\", "/")
    while norm.startswith("./"):
        norm = norm[2:]
    norm = norm.lstrip("/")
    if not norm:
        return "."
    head, sep, _tail = norm.partition("/")
    if not sep:
        return "."
    return head


def summarize_top_subdirs(
    rel_paths: list[str] | tuple[str, ...],
    limit: int = _TOP_SUBDIRS,
) -> list[dict[str, int]]:
    """Group *rel_paths* by top-level dir; return the *limit* biggest buckets.

    Args:
        rel_paths: Relative source-file paths (``"/"`` or ``"\\"`` separated).
        limit: Max number of buckets to return.

    Returns:
        ``[{"dir": str, "files": int}, ...]`` sorted by ``files`` descending,
        ties broken by directory name for determinism.
    """
    counter: Counter[str] = Counter(_top_component(p) for p in rel_paths)
    # Sort by count desc, then dir name asc (deterministic).
    ordered = sorted(counter.items(), key=lambda kv: (-kv[1], kv[0]))
    return [{"dir": d, "files": n} for d, n in ordered[:limit]]


def build_too_many_files_meta(
    rel_paths: list[str] | tuple[str, ...],
    max_files: int,
    *,
    entry_call: str = "start_forensic_audit",
) -> dict:
    """Build the structured ``too_many_files`` meta payload.

    Args:
        rel_paths: The collected relative source-file paths (the over-limit set).
        max_files: The ceiling that was exceeded.
        entry_call: Name of the MCP entry the suggestion should reference, e.g.
            ``"start_forensic_audit"`` or ``"start_code_map"``.

    Returns:
        A dict with ``skipped_reason``, ``file_count``, ``max_files``,
        ``top_subdirs`` and a human ``suggestion`` naming the biggest subdir.
    """
    top_subdirs = summarize_top_subdirs(rel_paths)
    # Pick the biggest *named* subdir (skip the root "." bucket) for the example.
    example_dir = None
    for entry in top_subdirs:
        if entry["dir"] != ".":
            example_dir = entry["dir"]
            break

    if example_dir is not None:
        suggestion = (
            f"Scan a submodule, e.g. {entry_call}(path='<dir>/{example_dir}'), "
            f"or raise max_files to force a full scan."
        )
    else:
        suggestion = (
            f"Scan a submodule, e.g. {entry_call}(path='<dir>/<subdir>'), "
            f"or raise max_files to force a full scan."
        )

    return {
        "skipped_reason": "too_many_files",
        "file_count": len(rel_paths),
        "max_files": max_files,
        "top_subdirs": top_subdirs,
        "suggestion": suggestion,
    }
