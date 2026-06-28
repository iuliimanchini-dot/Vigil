"""Deployment-target detection for forensic gates (F19).

Some gates are only meaningful when code actually runs on a specific platform.
The canonical example is ``encoding.windows_unsafe_char`` — cp1252 console
crash risk only exists when the Python/shell/Java source actually executes on
a Windows host. A pure-Linux trading stack has no such risk, so the 1k+
findings the gate raises on Linux-deployed code are false positives.

This module implements a 3-layer cascade for detecting where a target project
actually runs:

Layer 3 — explicit override (highest precedence)
    * ``<project>/.autoforensics/config.json`` with
      ``{"deployment_target": "linux-only" | "windows-only" | "cross-platform" | "auto"}``
    * Environment variable ``AUTOFORENSICS_DEPLOYMENT=<value>``. The CLI flag
      ``--deployment-target`` is plumbed through the env var so a single
      reader handles both cases.

Layer 2 — project-level signals (cached per project dir)
    * ``pyproject.toml`` ``classifiers`` — "POSIX :: Linux" / "Microsoft ::
      Windows" / "OS Independent".
    * ``setup.py`` ``classifiers`` — same semantics, parsed via AST to avoid
      executing arbitrary setup code.
    * ``Dockerfile`` present in project root → container, usually Linux.
    * ``.github/workflows/*.yml`` — if every job uses ``ubuntu-latest``
      only, that is a Linux-only deployment signal.
    * ``.bat`` / ``.ps1`` / ``.cmd`` / ``.psm1`` files present OUTSIDE dev
      infra paths (``.venv``, ``venv``, ``node_modules``, etc.) → the project
      is Windows-aware. Dev-infra-only Windows scripts do not change
      deployment target.

Layer 1 — file-level hints (per-file, content-based)
    * Shebang ``#!/usr/bin/env python`` / ``#!/bin/bash`` / ``#!/bin/sh`` →
      Unix signal.
    * Imports ``winreg`` / ``ctypes.windll`` / ``win32com`` / ``pywin32`` →
      Windows signal.
    * Imports ``fcntl`` / ``pwd`` / ``grp`` / ``resource`` / ``uvloop`` /
      ``daemonize`` → Unix signal.
    * AST pattern ``if sys.platform == "win32":`` / ``if os.name == "nt":``
      → Windows-aware code (Windows signal).

File-level signals are score-based with a ±2 threshold: small accidental
matches (e.g. a docstring containing the word "winreg") do not flip the
classification.

Precedence (strictest → weakest): explicit > file > project > unknown.

Conservative default: when no layer decides, callers treat the target as
"unknown" and **scan** — a false positive is recoverable (suppression); a
false negative hides a real bug.
"""
from __future__ import annotations

import ast
import json
import logging
import os
import re
from pathlib import Path
from typing import Literal

_log = logging.getLogger(__name__)

DeploymentTarget = Literal[
    "linux-only",
    "windows-only",
    "cross-platform",
    "auto",
    "unknown",
]

# Accepted values in config / env. "auto" means "fall through to signals".
_VALID_EXPLICIT: frozenset[str] = frozenset({
    "linux-only", "windows-only", "cross-platform", "auto",
})

# Module-level cache keyed by resolved project-dir string. Rubik has ~1958
# source files and every file triggers the encoding scan; we MUST NOT
# re-scan the project tree for every file.
_PROJECT_CACHE: dict[str, DeploymentTarget] = {}

# ---------------------------------------------------------------------------
# Layer 3 — explicit override
# ---------------------------------------------------------------------------

_ENV_VAR = "AUTOFORENSICS_DEPLOYMENT"
_CONFIG_REL = Path(".autoforensics") / "config.json"


def _normalize_explicit(value: str | None) -> DeploymentTarget | None:
    """Coerce a raw string into a valid DeploymentTarget or None.

    Unknown / empty values return None so the caller falls through to the
    next layer. "auto" returns None as well — the whole point of "auto" is
    "let the detector decide".
    """
    if not value:
        return None
    normalized = value.strip().lower()
    if normalized == "auto":
        return None
    if normalized in _VALID_EXPLICIT:
        return normalized  # type: ignore[return-value]
    _log.warning(
        "AUTOFORENSICS: ignoring invalid deployment_target=%r (expected one of %s)",
        value,
        sorted(_VALID_EXPLICIT),
    )
    return None


def get_explicit_deployment(project_dir: Path) -> DeploymentTarget | None:
    """Return explicit override (Layer 3) or None.

    Env var wins over config file: the CLI flag plumbs through the env var,
    so the most recent caller intention is honoured. Config-file values that
    are syntactically invalid are ignored (no crash — return None so we fall
    through to signal detection).
    """
    env_value = os.environ.get(_ENV_VAR)
    normalized = _normalize_explicit(env_value)
    if normalized is not None:
        return normalized

    config_path = project_dir / _CONFIG_REL
    if not config_path.is_file():
        return None
    try:
        payload = json.loads(config_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        _log.warning(
            "AUTOFORENSICS: cannot read %s (%s: %s) — falling through to signal detection",
            config_path, type(exc).__name__, exc,
        )
        return None
    if not isinstance(payload, dict):
        return None
    return _normalize_explicit(payload.get("deployment_target"))


# ---------------------------------------------------------------------------
# Layer 1 — file-level hints
# ---------------------------------------------------------------------------

# Score threshold: a file must score >= +2 (unix) or <= -2 (windows) to be
# classified. Small accidental matches fall below threshold and stay unknown.
_FILE_THRESHOLD = 2

# Regexes are module-level so Python compiles them once per process.
_SHEBANG_UNIX_RE = re.compile(
    r"^#!\s*/(?:usr/bin/env\s+(?:python\d*|bash|sh|zsh)|bin/(?:bash|sh|zsh))\b"
)

# Import patterns. These are deliberately conservative — we match
# module-top-level imports only, not references inside strings/comments.
_UNIX_IMPORT_RE = re.compile(
    r"^\s*(?:from|import)\s+(fcntl|pwd|grp|resource|uvloop|daemonize|"
    r"termios|syslog|posix|spwd|crypt)\b",
    re.MULTILINE,
)
_WINDOWS_IMPORT_RE = re.compile(
    r"^\s*(?:from|import)\s+(winreg|_winreg|win32com|win32api|win32con|"
    r"win32process|win32security|pywin32|msvcrt|winsound)\b",
    re.MULTILINE,
)
# ctypes.windll / ctypes.WinDLL — Windows-only ctypes surface.
_CTYPES_WIN_RE = re.compile(
    r"\bctypes\.(?:windll|WinDLL|oledll|OleDLL)\b"
)
# sys.platform == "win32" / os.name == "nt" — Windows-aware branching.
_SYS_PLATFORM_WIN_RE = re.compile(
    r"\bsys\.platform\s*==\s*['\"]win32['\"]|"
    r"\bos\.name\s*==\s*['\"]nt['\"]"
)
_SYS_PLATFORM_LINUX_RE = re.compile(
    r"\bsys\.platform\s*==\s*['\"]linux['\"]|"
    r"\bsys\.platform\.startswith\(\s*['\"]linux['\"]\s*\)|"
    r"\bos\.name\s*==\s*['\"]posix['\"]"
)


def detect_file_deployment(content: str) -> Literal["unix", "windows", "unknown"]:
    """Classify a single file's content by platform affinity.

    Score-based, threshold ±2. Strong single signals (``import winreg``,
    ``import fcntl``, ``#!/usr/bin/env python`` + matching imports) are
    worth 2 points so one signal alone flips classification. Weaker
    supporting signals (``sys.platform == 'win32'``) are worth 1.

    Returns:
      "unix"     — score >= +2
      "windows"  — score <= -2
      "unknown"  — between (ambiguous or no clear signal)

    Anti-FP property: a file that imports BOTH a winreg and a fcntl module
    (e.g. a cross-platform shim with explicit branches) scores 0 and stays
    "unknown" — we let Layer 2 / default decide.
    """
    if not content:
        return "unknown"

    score = 0

    # Shebang (first line only). Canonical Unix signal, worth +2 on its own.
    # A shebang is a deliberate runtime declaration, not an accidental string
    # match, so we treat it as a strong signal.
    first_newline = content.find("\n")
    first_line = content[:first_newline] if first_newline >= 0 else content
    if _SHEBANG_UNIX_RE.match(first_line):
        score += 2

    # Unix imports. ``import fcntl`` / ``from pwd import getpwnam`` are hard
    # dependencies on Unix-only stdlib modules. Each distinct module adds
    # +2 (strong), capped at +3 so mass-import files don't dominate.
    unix_hits = len(set(_UNIX_IMPORT_RE.findall(content)))
    if unix_hits:
        score += min(2 * unix_hits, 3)

    # Windows imports. Same reasoning mirrored.
    windows_hits = len(set(_WINDOWS_IMPORT_RE.findall(content)))
    if windows_hits:
        score -= min(2 * windows_hits, 3)

    # ctypes.windll / ctypes.WinDLL — Windows-specific ctypes surface.
    # Weaker (+1) because projects sometimes reference it conditionally.
    if _CTYPES_WIN_RE.search(content):
        score -= 1

    # Platform-branch hints. A file that explicitly checks win32 branch is
    # Windows-aware but not necessarily Windows-only — weight 1.
    if _SYS_PLATFORM_WIN_RE.search(content):
        score -= 1
    if _SYS_PLATFORM_LINUX_RE.search(content):
        score += 1

    if score >= _FILE_THRESHOLD:
        return "unix"
    if score <= -_FILE_THRESHOLD:
        return "windows"
    return "unknown"


# ---------------------------------------------------------------------------
# Layer 2 — project-level signals
# ---------------------------------------------------------------------------

# Directories whose contents do NOT represent the project's deployment
# target — virtualenvs, bundled vendor libs, build output, etc. .bat/.ps1
# files under these paths are dev/tooling artifacts, not a signal that the
# project itself targets Windows.
_IGNORED_DIR_PARTS: frozenset[str] = frozenset({
    ".venv", "venv", "env", ".env",
    "node_modules",
    "__pycache__",
    ".git", ".hg", ".svn",
    "build", "dist",
    ".tox", ".mypy_cache", ".pytest_cache", ".ruff_cache",
    "libs",  # SYSTEM/libs vendor tree
    ".cortex",
})

_WINDOWS_SCRIPT_EXTS: tuple[str, ...] = (".bat", ".cmd", ".ps1", ".psm1")


def _path_in_ignored_tree(rel_parts: tuple[str, ...]) -> bool:
    return any(part in _IGNORED_DIR_PARTS for part in rel_parts)


def _read_pyproject_classifiers(project_dir: Path) -> list[str]:
    """Return list of classifier strings from pyproject.toml, or [] if absent
    / unreadable. Uses tomllib (stdlib 3.11+)."""
    path = project_dir / "pyproject.toml"
    if not path.is_file():
        return []
    try:
        import tomllib
    except ImportError:  # pragma: no cover — 3.11+ always has it
        return []
    try:
        with path.open("rb") as fh:
            data = tomllib.load(fh)
    except (OSError, tomllib.TOMLDecodeError) as exc:
        _log.debug("AUTOFORENSICS: cannot read %s (%s)", path, exc)
        return []
    project = data.get("project") or {}
    classifiers = project.get("classifiers") or []
    if not isinstance(classifiers, list):
        return []
    return [str(c) for c in classifiers]


def _read_setuppy_classifiers(project_dir: Path) -> list[str]:
    """Extract classifiers list from setup.py via AST (no exec).

    Returns [] if setup.py missing, unparseable, or has no ``classifiers=``
    keyword on a setup() call.
    """
    path = project_dir / "setup.py"
    if not path.is_file():
        return []
    try:
        source = path.read_text(encoding="utf-8", errors="replace")
        tree = ast.parse(source)
    except (OSError, SyntaxError) as exc:
        _log.debug("AUTOFORENSICS: cannot parse %s (%s)", path, exc)
        return []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        func = node.func
        # Match setup(...) — either bare name or <module>.setup.
        if isinstance(func, ast.Name) and func.id == "setup":
            pass
        elif isinstance(func, ast.Attribute) and func.attr == "setup":
            pass
        else:
            continue
        for kw in node.keywords:
            if kw.arg != "classifiers":
                continue
            if not isinstance(kw.value, (ast.List, ast.Tuple)):
                continue
            result: list[str] = []
            for elt in kw.value.elts:
                if isinstance(elt, ast.Constant) and isinstance(elt.value, str):
                    result.append(elt.value)
            return result
    return []


def _classify_from_classifiers(classifiers: list[str]) -> DeploymentTarget | None:
    """Map Python trove classifiers to a deployment target.

    Matches Trove strings like:
      * "Operating System :: POSIX :: Linux"
      * "Operating System :: Microsoft :: Windows"
      * "Operating System :: OS Independent"
    """
    if not classifiers:
        return None
    has_linux = any("POSIX" in c or "Linux" in c for c in classifiers)
    has_windows = any("Microsoft" in c or "Windows" in c for c in classifiers)
    has_independent = any("OS Independent" in c for c in classifiers)
    if has_independent:
        return "cross-platform"
    if has_linux and has_windows:
        return "cross-platform"
    if has_linux:
        return "linux-only"
    if has_windows:
        return "windows-only"
    return None


def _has_dockerfile(project_dir: Path) -> bool:
    """True when a Dockerfile exists at the project root (case-insensitive
    for the basename)."""
    for name in ("Dockerfile", "dockerfile", "Dockerfile.prod", "Dockerfile.ci"):
        if (project_dir / name).is_file():
            return True
    # Some projects put it under build/ or docker/ — accept up to depth 2.
    for pattern in ("**/Dockerfile", "**/Dockerfile.*"):
        for candidate in project_dir.glob(pattern):
            try:
                rel = candidate.relative_to(project_dir)
            except ValueError:
                continue
            if _path_in_ignored_tree(rel.parts):
                continue
            return True
    return False


_GHA_JOB_OS_RE = re.compile(
    r"^\s*runs-on\s*:\s*[\"']?([A-Za-z0-9._-]+)[\"']?",
    re.MULTILINE,
)


def _gha_runners(project_dir: Path) -> set[str]:
    """Return the set of all ``runs-on`` values used across GitHub Actions
    workflows. Empty set when no workflows present.

    We avoid a YAML dependency by matching a simple regex — ``runs-on`` is
    conventionally a single-line scalar. Matrix expressions (``${{...}}``)
    are returned verbatim; callers treat non-ubuntu/windows/macos values as
    unknown runners.
    """
    wf_dir = project_dir / ".github" / "workflows"
    if not wf_dir.is_dir():
        return set()
    runners: set[str] = set()
    for wf in wf_dir.glob("*.yml"):
        try:
            text = wf.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        for m in _GHA_JOB_OS_RE.finditer(text):
            runners.add(m.group(1).lower())
    for wf in wf_dir.glob("*.yaml"):
        try:
            text = wf.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        for m in _GHA_JOB_OS_RE.finditer(text):
            runners.add(m.group(1).lower())
    return runners


def _windows_scripts_outside_dev(project_dir: Path, cap: int = 4) -> bool:
    """True when ≥1 .bat/.ps1/.cmd/.psm1 file exists outside dev-infra trees.

    We short-circuit after finding `cap` hits so the scan stays bounded even
    on huge repos.
    """
    found = 0
    for ext in _WINDOWS_SCRIPT_EXTS:
        for path in project_dir.rglob(f"*{ext}"):
            try:
                rel = path.relative_to(project_dir)
            except ValueError:
                continue
            if _path_in_ignored_tree(rel.parts):
                continue
            found += 1
            if found >= cap:
                return True
    return found > 0


def _linux_only_deps_in_requirements(project_dir: Path) -> bool:
    """True when requirements*.txt lists a Linux-exclusive package (uvloop,
    daemonize, sdnotify, systemd-python, etc.)."""
    linux_pkgs = ("uvloop", "daemonize", "sdnotify", "systemd-python", "python-systemd")
    for pattern in ("requirements.txt", "requirements-*.txt", "requirements/*.txt"):
        for path in project_dir.glob(pattern):
            try:
                text = path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            for pkg in linux_pkgs:
                if re.search(rf"(?m)^\s*{re.escape(pkg)}\b", text):
                    return True
    return False


def _detect_project_uncached(project_dir: Path) -> DeploymentTarget:
    """Run Layer 2 detection (no cache). Returns 'unknown' when signals
    are absent or contradictory.

    Priority order:
      1. pyproject.toml / setup.py classifiers (authoritative upstream metadata).
      2. GitHub Actions runners (deployment-test target).
      3. Dockerfile (containerisation signal).
      4. Linux-exclusive deps in requirements*.txt.
      5. Windows scripts outside dev-infra — downgrade to cross-platform.
    """
    # 1. Classifiers — most authoritative.
    classifiers = _read_pyproject_classifiers(project_dir)
    if not classifiers:
        classifiers = _read_setuppy_classifiers(project_dir)
    decision = _classify_from_classifiers(classifiers)
    if decision is not None:
        _log.debug(
            "AUTOFORENSICS: %s classified %s via pyproject/setup.py classifiers",
            project_dir, decision,
        )
        return decision

    # 2. GitHub Actions runners.
    runners = _gha_runners(project_dir)
    if runners:
        has_ubuntu = any(r.startswith("ubuntu") for r in runners)
        has_windows = any(r.startswith("windows") for r in runners)
        has_macos = any(r.startswith("macos") for r in runners)
        # Unknown runners (matrix expressions, self-hosted) count as
        # "unresolved" — we do not force a linux-only conclusion when they
        # appear alongside ubuntu.
        has_unknown = any(
            not (r.startswith("ubuntu") or r.startswith("windows") or r.startswith("macos"))
            for r in runners
        )
        if has_windows and not has_ubuntu:
            return "windows-only"
        if has_ubuntu and not has_windows and not has_unknown:
            # Linux-only CI is a deployment signal. macOS runners alongside
            # ubuntu still indicate a Unix-only test matrix — classify as
            # linux-only for encoding-gate purposes (macOS console is UTF-8
            # by default, not cp1252).
            if not has_macos or has_macos:
                return "linux-only"

    # 3. Dockerfile → container → Linux in the overwhelming majority of
    # cases. We do not downgrade for the rare Windows-container project;
    # callers can override via explicit config.
    if _has_dockerfile(project_dir):
        return "linux-only"

    # 4. Linux-exclusive deps.
    if _linux_only_deps_in_requirements(project_dir):
        return "linux-only"

    # 5. Windows scripts outside dev-infra → at least cross-platform.
    # This only fires when steps 1–4 did not decide. A project with a
    # start_vigil.bat launcher but no deployment metadata is assumed to be
    # Windows-aware.
    if _windows_scripts_outside_dev(project_dir):
        return "cross-platform"

    return "unknown"


def detect_project_deployment(project_dir: Path) -> DeploymentTarget:
    """Cached entry-point for Layer 2 detection.

    Cache key is the resolved, case-normalised string path. A rubik-scale
    project (~2000 files) asks this function once per file; we MUST amortise.
    """
    try:
        key = str(project_dir.resolve()).lower()
    except OSError:
        key = str(project_dir).lower()
    cached = _PROJECT_CACHE.get(key)
    if cached is not None:
        return cached
    result = _detect_project_uncached(project_dir)
    _PROJECT_CACHE[key] = result
    return result


def clear_project_cache() -> None:
    """Drop all memoised project-level detections. Intended for tests."""
    _PROJECT_CACHE.clear()


# ---------------------------------------------------------------------------
# Cascade — the single entrypoint callers should use
# ---------------------------------------------------------------------------

def resolve_deployment(
    project_dir: Path,
    file_content: str | None = None,
) -> DeploymentTarget:
    """Resolve a deployment target using the full 3-layer cascade.

    Precedence (strictest wins):
      1. Explicit override (config.json / env var).
      2. File-level signal — when content is provided and classifies as
         'unix' or 'windows'.
      3. Project-level signal.
      4. 'unknown' — caller decides how to handle (conservative default:
         scan).
    """
    explicit = get_explicit_deployment(project_dir)
    if explicit is not None:
        return explicit
    if file_content is not None:
        file_signal = detect_file_deployment(file_content)
        if file_signal == "unix":
            return "linux-only"
        if file_signal == "windows":
            return "windows-only"
    return detect_project_deployment(project_dir)


__all__ = [
    "DeploymentTarget",
    "get_explicit_deployment",
    "detect_file_deployment",
    "detect_project_deployment",
    "clear_project_cache",
    "resolve_deployment",
]
