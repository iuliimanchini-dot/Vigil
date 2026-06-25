"""Dirty baseline pre-launch gate.

Phase C7 — closes the regression where Rubik's working copy carried 17+
untracked paths (``.codex_*backup/`` artefacts, ``.scratch/``, foreign
report files, half-finished scripts) that polluted the executor's
context AND broke commit-delta reconciliation. The auto-commit step
could not tell which paths belonged to "this task" vs "leftover from a
previous run", so it returned ``status=committed_reported_unreconciled``
even on otherwise successful sessions.

The fix introduces an opt-in pre-launch gate:

    .cortex/dirty_baseline_policy.json
    {
      "enabled": true,
      "whitelist": [
        ".cortex/", ".vscode/", "*.lock", ".scratch/"
      ],
      "max_files": 5,
      "action": "warn"           # "block" once policy hardens
    }

The check runs ``git status --porcelain``, filters paths against the
whitelist, and returns a structured verdict the orchestrator wires
into pre-launch decisions.

Architecture:

- This module is a pure helper. It performs no I/O beyond the single
  ``git status`` invocation and a JSON read; callers decide how to
  surface the verdict (banner, hard-fail, log entry).
- The whitelist supports glob-style patterns (``*.lock``) and prefix
  matches (``.cortex/`` matches any path under that directory).
- ``max_files`` is the hard ceiling for the **non-whitelisted** count.
  Whitelisted paths never count toward the limit, regardless of
  quantity.
- ``action="warn"`` returns ``DirtyBaselineVerdict(blocking=False)``
  with the dirty paths populated so the UI can show a banner; the
  caller proceeds with the launch. ``action="block"`` returns
  ``blocking=True`` and the caller refuses the launch.
- Defaults match the plan: ``warn`` for the first 7 days post-rollout,
  then a follow-up flips the default to ``block``. The policy file
  is the source of truth — defaults only apply when the file is
  absent.
"""
from __future__ import annotations

import fnmatch
import json
import logging
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable

_log = logging.getLogger(__name__)


# Defaults — apply when no .cortex/dirty_baseline_policy.json is present.
# The whitelist covers the standard Vigil + IDE state that should never
# count toward the dirty-files budget.
_DEFAULT_WHITELIST: tuple[str, ...] = (
    ".cortex/",
    ".vscode/",
    "*.lock",
    "__pycache__/",
)
_DEFAULT_MAX_FILES = 5
_DEFAULT_ACTION = "warn"  # one of "warn" | "block"


@dataclass(frozen=True)
class DirtyBaselineVerdict:
    """Outcome of a single dirty-baseline check.

    Attributes:
        ok: ``True`` when the verdict is clean OR within budget OR the
            check is disabled. ``False`` when the launch should be
            blocked or warned about.
        action: ``"warn"`` / ``"block"`` / ``"disabled"`` /
            ``"git_unavailable"`` describing why the verdict landed
            this way.
        blocking: ``True`` only when ``action == "block"`` and the
            count exceeds the budget. Callers gate the launch on this
            field.
        count: Number of dirty paths after whitelist filtering.
        max_files: Configured ceiling.
        dirty_paths: Up to 50 representative non-whitelisted paths;
            surfaces in the UI banner.
        whitelisted_count: How many paths the whitelist absorbed (for
            diagnostics — confirms the policy is doing what it claims).
    """

    ok: bool
    action: str
    blocking: bool
    count: int
    max_files: int
    dirty_paths: tuple[str, ...] = field(default_factory=tuple)
    whitelisted_count: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "ok": self.ok,
            "action": self.action,
            "blocking": self.blocking,
            "count": self.count,
            "max_files": self.max_files,
            "dirty_paths": list(self.dirty_paths),
            "whitelisted_count": self.whitelisted_count,
        }


def _load_policy(project_dir: Path) -> dict[str, Any]:
    policy_path = project_dir / ".cortex" / "dirty_baseline_policy.json"
    if not policy_path.exists():
        return {
            "enabled": True,
            "whitelist": list(_DEFAULT_WHITELIST),
            "max_files": _DEFAULT_MAX_FILES,
            "action": _DEFAULT_ACTION,
        }
    try:
        raw = json.loads(policy_path.read_text(encoding="utf-8"))
        if not isinstance(raw, dict):
            raise ValueError("dirty_baseline_policy.json must be a JSON object")
    except (OSError, json.JSONDecodeError, ValueError) as exc:
        _log.warning(
            "dirty_baseline_check: policy load failed, using defaults: %s", exc,
        )
        return {
            "enabled": True,
            "whitelist": list(_DEFAULT_WHITELIST),
            "max_files": _DEFAULT_MAX_FILES,
            "action": _DEFAULT_ACTION,
        }
    whitelist = raw.get("whitelist")
    if not isinstance(whitelist, list):
        whitelist = list(_DEFAULT_WHITELIST)
    action = str(raw.get("action") or _DEFAULT_ACTION).strip().lower()
    if action not in ("warn", "block"):
        action = _DEFAULT_ACTION
    return {
        "enabled": bool(raw.get("enabled", True)),
        "whitelist": [str(item) for item in whitelist],
        "max_files": int(raw.get("max_files", _DEFAULT_MAX_FILES)),
        "action": action,
    }


def _is_whitelisted(path: str, whitelist: Iterable[str]) -> bool:
    """True if ``path`` matches any entry in the whitelist.

    Matching rules (in order):
        1. Glob (``fnmatch``) — handles ``*.lock`` and similar.
        2. Directory prefix — entries ending in ``/`` match any path
           under that directory (``.cortex/`` matches ``.cortex/x.json``
           AND ``.cortex/sub/y.json``).
        3. Exact equality fallback.
    """
    p = path.replace("\\", "/").lstrip("./")
    for pattern in whitelist:
        pat = pattern.replace("\\", "/").lstrip("./")
        if fnmatch.fnmatch(p, pat):
            return True
        if pat.endswith("/") and (p == pat.rstrip("/") or p.startswith(pat)):
            return True
        if p == pat:
            return True
    return False


def _parse_porcelain(output: str) -> list[str]:
    """Extract paths from ``git status --porcelain`` output.

    Each line is ``XY <path>`` or ``XY <orig> -> <new>`` for renames.
    We capture the new path in renames and the only path otherwise.
    Empty lines (no dirty state) yield an empty list.
    """
    paths: list[str] = []
    for raw_line in output.splitlines():
        line = raw_line.rstrip()
        if len(line) < 4:
            continue
        # Strip the 2-char status + 1 space prefix.
        rest = line[3:]
        if " -> " in rest:
            _orig, _, new = rest.partition(" -> ")
            paths.append(new.strip().strip('"'))
        else:
            paths.append(rest.strip().strip('"'))
    return paths


def check_dirty_baseline(
    project_dir: Path,
    *,
    git_status_output: str | None = None,
) -> DirtyBaselineVerdict:
    """Run the dirty-baseline gate against ``project_dir``.

    Args:
        project_dir: Project root containing the ``.git`` directory.
        git_status_output: Optional pre-captured ``git status --porcelain``
            output. When ``None`` the function shells out to ``git``;
            tests inject deterministic output via this parameter.

    Returns:
        ``DirtyBaselineVerdict`` describing the outcome. The function
        never raises on git failures — instead it returns ``ok=True``
        with ``action="git_unavailable"`` so the launch proceeds. The
        caller can log the missing-git case but it should not block a
        legitimate run.
    """
    project_dir = Path(project_dir)
    policy = _load_policy(project_dir)
    if not policy.get("enabled", True):
        return DirtyBaselineVerdict(
            ok=True, action="disabled", blocking=False,
            count=0, max_files=policy["max_files"],
        )

    if git_status_output is None:
        try:
            completed = subprocess.run(
                ["git", "status", "--porcelain"],
                cwd=str(project_dir),
                capture_output=True,
                text=True,
                timeout=30,
                check=False,
            )
        except (OSError, subprocess.SubprocessError) as exc:
            _log.warning("dirty_baseline_check: git invocation failed: %s", exc)
            return DirtyBaselineVerdict(
                ok=True, action="git_unavailable", blocking=False,
                count=0, max_files=policy["max_files"],
            )
        if completed.returncode != 0:
            _log.warning(
                "dirty_baseline_check: git status rc=%s stderr=%s",
                completed.returncode, (completed.stderr or "")[:200],
            )
            return DirtyBaselineVerdict(
                ok=True, action="git_unavailable", blocking=False,
                count=0, max_files=policy["max_files"],
            )
        git_status_output = completed.stdout or ""

    all_paths = _parse_porcelain(git_status_output)
    whitelist = policy["whitelist"]
    dirty: list[str] = []
    whitelisted = 0
    for path in all_paths:
        if _is_whitelisted(path, whitelist):
            whitelisted += 1
        else:
            dirty.append(path)

    max_files = int(policy["max_files"])
    over_budget = len(dirty) > max_files
    action = str(policy["action"])
    blocking = over_budget and action == "block"
    ok = not over_budget

    return DirtyBaselineVerdict(
        ok=ok,
        action=action if over_budget else "clean",
        blocking=blocking,
        count=len(dirty),
        max_files=max_files,
        dirty_paths=tuple(dirty[:50]),
        whitelisted_count=whitelisted,
    )
