"""Neutral shared git helpers. Depends only on stdlib.

Used by map_builder (churn) and gate_checks (diff-based checks).
Never imports from gate_checks or map_builder (correct dependency direction).

Public API:
    git_show(path, ref, project_dir)        -- file content at git ref
    git_log_numstat(project_dir, since)     -- churn line counts per file
    git_has_repo(project_dir)               -- is inside a git work tree?
    git_head_sha(project_dir)               -- current HEAD SHA
"""
from __future__ import annotations

import logging
import subprocess
from pathlib import Path

_log = logging.getLogger(__name__)

__all__ = [
    "git_show",
    "git_log_numstat",
    "git_has_repo",
    "git_head_sha",
]


def git_show(
    path: str,
    ref: str = "HEAD~1",
    project_dir: Path | None = None,
) -> str | None:
    """Return file content at git ref or None on failure.

    Args:
        path: Relative file path (as stored in git, e.g. "BRAIN/foo.py").
        ref: Git ref to read from. Defaults to "HEAD~1".
        project_dir: If given, passes ``-C project_dir`` to git so the command
            runs in the correct working directory regardless of the caller's cwd.

    Returns:
        File content as a string, or None if the file didn't exist at that ref,
        git is unavailable, or any other error occurs (fail-open).
    """
    args = ["git"]
    if project_dir is not None:
        args += ["-C", str(project_dir)]
    args += ["show", "%s:%s" % (ref, path)]

    try:
        r = subprocess.run(
            args,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=10,
            shell=False,
        )
        if r.returncode != 0:
            return None
        return r.stdout
    except (subprocess.SubprocessError, FileNotFoundError, OSError) as exc:
        _log.debug("git_show failed for %s@%s: %s", path, ref, type(exc).__name__)
        return None


def git_log_numstat(
    project_dir: Path,
    since: str = "90.days",
) -> dict[str, int]:
    """Return ``{relative_path: churn_line_count}`` for commits since *since*.

    Churn is defined as added + deleted lines across all commits in the window.
    Binary files (where git outputs ``-`` for line counts) are skipped.

    Args:
        project_dir: Absolute path to the project root (must be inside a git repo).
        since: ``--since`` value passed to ``git log``, e.g. ``"90.days"`` or
            ``"2025-01-01"``.

    Returns:
        Dict mapping each file path to total churn line count. Returns an empty
        dict if the directory is not a git repo, git is unavailable, or any
        subprocess error occurs (fail-open).
    """
    try:
        r = subprocess.run(
            [
                "git",
                "-C", str(project_dir),
                "log",
                "--numstat",
                "--since=%s" % since,
                "--pretty=format:",
            ],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=30,
            shell=False,
        )
        if r.returncode != 0:
            return {}
        result: dict[str, int] = {}
        for line in r.stdout.splitlines():
            parts = line.split("\t")
            if len(parts) != 3:
                continue
            added, deleted, path = parts
            # Binary files have "-" for line counts — skip them
            if added == "-" or deleted == "-":
                continue
            try:
                churn = int(added) + int(deleted)
            except ValueError:
                continue
            result[path] = result.get(path, 0) + churn
        return result
    except (subprocess.SubprocessError, FileNotFoundError, OSError) as exc:
        _log.debug("git_log_numstat failed in %s: %s", project_dir, type(exc).__name__)
        return {}


def git_has_repo(project_dir: Path) -> bool:
    """Return True if *project_dir* is inside a git work tree.

    Uses ``git rev-parse --is-inside-work-tree``. Returns False on any error,
    including git not installed or directory not being a repo (fail-open).
    """
    try:
        r = subprocess.run(
            [
                "git",
                "-C", str(project_dir),
                "rev-parse",
                "--is-inside-work-tree",
            ],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=5,
            shell=False,
        )
        return r.returncode == 0 and r.stdout.strip() == "true"
    except (subprocess.SubprocessError, FileNotFoundError, OSError):
        return False


def git_head_sha(project_dir: Path) -> str | None:
    """Return current HEAD SHA or None on non-git / error.

    Returns:
        40-character hex SHA string, or None if git is unavailable, the
        directory is not a repo, or any other error occurs (fail-open).
    """
    try:
        r = subprocess.run(
            [
                "git",
                "-C", str(project_dir),
                "rev-parse",
                "HEAD",
            ],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=5,
            shell=False,
        )
        if r.returncode != 0:
            return None
        return r.stdout.strip() or None
    except (subprocess.SubprocessError, FileNotFoundError, OSError):
        return None
