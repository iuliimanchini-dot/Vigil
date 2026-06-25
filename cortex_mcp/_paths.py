"""Project-root resolution for cortex_mcp servers.

Used by the auto project-targeting feature: when a tool is called with an
empty/absent ``path`` the server walks up from a starting directory looking
for a project marker (``.git`` / ``pyproject.toml`` / ``package.json`` and a
few common siblings).  If no marker is found it falls back to the starting
directory.  ``None`` starts the walk from the current working directory.
"""
from __future__ import annotations

import os
from pathlib import Path

# Markers that identify a project root, in no particular priority — the walk
# returns the *nearest* ancestor (starting dir first) that contains ANY marker.
_PROJECT_MARKERS: tuple[str, ...] = (
    ".git",
    "pyproject.toml",
    "package.json",
    "setup.py",
    "setup.cfg",
    "Cargo.toml",
    "go.mod",
    "pom.xml",
    "build.gradle",
)


def _has_marker(directory: Path) -> bool:
    """True if *directory* contains any recognised project marker."""
    for marker in _PROJECT_MARKERS:
        if (directory / marker).exists():
            return True
    return False


def _resolve_project_root(start: str | None) -> str:
    """Resolve the project root by walking up from *start*.

    Args:
        start: Directory to begin the search from.  When ``None`` (or empty)
               the current working directory is used.

    Returns:
        Absolute path (as ``str``) of the nearest ancestor containing a
        project marker, or — when no marker is found — the starting directory
        itself.

    Notes:
        Never raises for a missing/odd ``start``; it falls back to ``cwd`` so
        callers always get a usable directory string.
    """
    if not start:
        start_path = Path(os.getcwd())
    else:
        start_path = Path(start)

    # Resolve to an absolute path without requiring the path to exist.
    try:
        start_path = start_path.resolve()
    except (OSError, RuntimeError):
        start_path = Path(os.getcwd()).resolve()

    # Boundary for the *upward* walk: never auto-adopt the user's home
    # directory (or anything above it) as a project root — "audit my whole
    # home folder" is never the intent.  The start dir itself is exempt from
    # this rule (an explicit project that happens to live at home is fine);
    # the boundary only stops the ancestor search.
    try:
        home = Path.home().resolve()
    except (OSError, RuntimeError):
        home = None

    # The start dir itself always wins if it carries a marker (covers
    # "find in current dir" and "prefer dir that holds both markers").
    if _has_marker(start_path):
        return str(start_path)

    candidate = start_path
    while True:
        parent = candidate.parent
        if parent == candidate:  # reached filesystem root
            break
        candidate = parent
        # Stop when the walk reaches the home directory or any ancestor of it.
        # (home itself or above → never auto-adopt as a project root.)
        if home is not None and (candidate == home or candidate in home.parents):
            break
        if _has_marker(candidate):
            return str(candidate)

    # No marker found within bounds → fall back to the starting directory.
    return str(start_path)
