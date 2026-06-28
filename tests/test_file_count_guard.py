"""TDD tests for the file-count guard (anti-hang on huge repos).

Problem: on a real 9000+ file repo the forensic per-gate AST walk (~0.4 s/file)
and the code-map build take hours -> effectively hang. There must be a guard on
the *number* of collected files (a per-file SIZE guard already exists, but it
does nothing for thousands of small files).

Guarantee under test: when the collected file count exceeds ``max_files`` the
tools DO NOT scan. They return a structured, FAST ``too_many_files`` result that
tells the caller to narrow scope (top sub-directories by file count + a concrete
suggestion). ``max_files`` is overridable to force a full scan.

Run:
    python -m pytest tests/test_file_count_guard.py -p no:cacheprovider -q
"""
from __future__ import annotations

import sys
import time
from pathlib import Path

import pytest

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_small_py(path: Path, idx: int) -> None:
    """Write a tiny, syntactically valid Python file."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(f"def fn_{idx}(x):\n    return x + {idx}\n", encoding="utf-8")


def _make_project(root: Path, n_files: int, subdirs: tuple[str, ...] = ("scripts", "lib", "tests")) -> None:
    """Create a project with *n_files* small .py files spread across *subdirs*.

    A couple of files live at the project root too, so the top-subdir grouping
    has both a named-dir bucket and a root bucket.
    """
    root.mkdir(parents=True, exist_ok=True)
    _make_small_py(root / "main.py", 0)
    for i in range(1, n_files):
        sub = subdirs[i % len(subdirs)]
        _make_small_py(root / sub / f"mod_{i:04d}.py", i)


# ===========================================================================
# Forensic guard
# ===========================================================================

class TestForensicFileCountGuard:
    def test_small_project_scans_normally(self, tmp_path):
        """A 30-file project (< limit) is scanned: not skipped, gates ran."""
        from cortex_forensic import run_forensic_audit

        proj = tmp_path / "proj"
        _make_project(proj, n_files=30)

        r = run_forensic_audit(proj)  # default max_files=800
        meta = r.get("meta", {})
        assert meta.get("skipped_reason") != "too_many_files", (
            "30-file project must NOT be skipped"
        )
        # gates actually ran -> a positive count of scanned files is recorded
        assert meta.get("source_files_scanned", 0) >= 1

    def test_over_limit_returns_skip_dict_fast(self, tmp_path):
        """> max_files small files -> structured too_many_files skip, FAST.

        Uses max_files=10 so the test stays light. The decisive evidence that
        no gate work ran is findings == [] together with the skip marker.
        """
        from cortex_forensic import run_forensic_audit

        proj = tmp_path / "proj"
        _make_project(proj, n_files=40)

        t0 = time.perf_counter()
        r = run_forensic_audit(proj, max_files=10)
        dt = time.perf_counter() - t0

        assert r["exit_code"] == 0
        assert r["findings"] == [], "guard must not run gates -> no findings"

        meta = r["meta"]
        assert meta["skipped_reason"] == "too_many_files"
        assert meta["file_count"] == 40
        assert meta["max_files"] == 10

        top = meta["top_subdirs"]
        assert isinstance(top, list) and len(top) >= 1
        # Each entry is {"dir": str, "files": int}; descending by file count.
        counts = [e["files"] for e in top]
        assert counts == sorted(counts, reverse=True)
        assert all({"dir", "files"} <= set(e) for e in top)
        assert "suggestion" in meta and "max_files" in meta["suggestion"]

        # FAST: counting + grouping only. Generous ceiling (no per-gate walk).
        assert dt < 5.0, f"guard took {dt:.2f}s — must be fast (no gate work)"

    def test_max_files_override_forces_scan(self, tmp_path):
        """Raising max_files above the count makes the same project scan."""
        from cortex_forensic import run_forensic_audit

        proj = tmp_path / "proj"
        _make_project(proj, n_files=40)

        r = run_forensic_audit(proj, max_files=10_000)
        meta = r.get("meta", {})
        assert meta.get("skipped_reason") != "too_many_files"
        assert meta.get("source_files_scanned", 0) >= 1

    def test_vendored_site_packages_not_counted(self, tmp_path):
        """A site-packages/ tree of .py files is excluded from the count.

        With max_files small, the project would be skipped IF site-packages were
        counted. Because it must be excluded, only the handful of real files
        remain and the project scans normally.
        """
        from cortex_forensic import run_forensic_audit

        proj = tmp_path / "proj"
        proj.mkdir()
        _make_small_py(proj / "main.py", 0)
        _make_small_py(proj / "app.py", 1)
        # A big vendored tree that must NOT be counted/scanned.
        for i in range(50):
            _make_small_py(proj / "site-packages" / f"vendor_{i:03d}.py", i)

        r = run_forensic_audit(proj, max_files=10)
        meta = r.get("meta", {})
        assert meta.get("skipped_reason") != "too_many_files", (
            "site-packages must be excluded -> only 2 real files -> scans"
        )
        assert meta.get("source_files_scanned", 1) <= 5, (
            "vendored files must not be scanned"
        )

    def test_discover_source_files_excludes_new_vendored_dirs(self, tmp_path):
        """discover_source_files drops the broadened vendored/build dir set."""
        from cortex_forensic.self_audit import discover_source_files

        proj = tmp_path / "proj"
        proj.mkdir()
        _make_small_py(proj / "real.py", 0)
        for d in ("site-packages", "dist-packages", ".tox", ".eggs",
                  ".mypy_cache", ".pytest_cache", "build", ".next"):
            _make_small_py(proj / d / "x.py", 1)

        files = discover_source_files(proj)
        assert files == ["real.py"], f"vendored dirs leaked into discovery: {files}"


# ===========================================================================
# Code-map guard
# ===========================================================================

class TestMapFileCountGuard:
    def test_small_project_builds_maps(self, tmp_path):
        """A 30-file project (< limit) builds maps normally (not skipped)."""
        from cortex_mcp.map_server import _run_map_build_with_path

        proj = tmp_path / "proj"
        _make_project(proj, n_files=30)
        out = tmp_path / "out"
        out.mkdir()

        res = _run_map_build_with_path(str(proj), map="structural")
        assert res.get("skipped_reason") != "too_many_files"
        assert res.get("exit_code") == 0
        # maps were actually built
        maps = list((proj / ".cortex" / "maps").glob("*structural_map.json"))
        assert maps, "structural map should have been written"

    def test_over_limit_returns_skip_dict_fast(self, tmp_path):
        """> max_files -> structured too_many_files skip instead of a build."""
        from cortex_mcp.map_server import _run_map_build_with_path

        proj = tmp_path / "proj"
        _make_project(proj, n_files=40)

        t0 = time.perf_counter()
        res = _run_map_build_with_path(str(proj), map="all", max_files=10)
        dt = time.perf_counter() - t0

        assert res["skipped_reason"] == "too_many_files"
        assert res["file_count"] == 40
        assert res["max_files"] == 10
        top = res["top_subdirs"]
        assert isinstance(top, list) and len(top) >= 1
        assert all({"dir", "files"} <= set(e) for e in top)
        counts = [e["files"] for e in top]
        assert counts == sorted(counts, reverse=True)
        assert "suggestion" in res

        # No maps were built (the guard returned before building).
        maps = list((proj / ".cortex" / "maps").glob("*structural_map.json"))
        assert not maps, "guard must not build maps"
        assert dt < 5.0, f"map guard took {dt:.2f}s — must be fast"

    def test_max_files_override_builds(self, tmp_path):
        """Raising max_files makes the same project build maps."""
        from cortex_mcp.map_server import _run_map_build_with_path

        proj = tmp_path / "proj"
        _make_project(proj, n_files=40)

        res = _run_map_build_with_path(str(proj), map="structural", max_files=10_000)
        assert res.get("skipped_reason") != "too_many_files"
        assert res.get("exit_code") == 0
        maps = list((proj / ".cortex" / "maps").glob("*structural_map.json"))
        assert maps, "structural map should have been written on override"

    def test_map_excludes_new_vendored_dirs(self, tmp_path):
        """iter_source_files drops the broadened vendored/build dir set."""
        from cortex_map_builder.map_common import iter_source_files

        proj = tmp_path / "proj"
        proj.mkdir()
        _make_small_py(proj / "real.py", 0)
        for d in ("site-packages", "dist-packages", ".eggs", ".next"):
            _make_small_py(proj / d / "x.py", 1)

        rels = sorted(
            p.resolve().relative_to(proj.resolve()).as_posix()
            for p in iter_source_files(proj)
        )
        assert rels == ["real.py"], f"vendored dirs leaked into map scan: {rels}"


# ===========================================================================
# Shared helper
# ===========================================================================

class TestGuardHelper:
    def test_summarize_top_subdirs_groups_and_sorts(self):
        from cortex_map_builder._file_count_guard import summarize_top_subdirs

        rels = (
            ["scripts/a.py"] * 5
            + ["v21/b.py"] * 3
            + ["root.py"] * 2  # top-level files -> grouped under "."
        )
        top = summarize_top_subdirs(rels, limit=8)
        assert top[0] == {"dir": "scripts", "files": 5}
        assert top[1] == {"dir": "v21", "files": 3}
        # descending order
        counts = [e["files"] for e in top]
        assert counts == sorted(counts, reverse=True)

    def test_build_too_many_files_result_shape(self):
        from cortex_map_builder._file_count_guard import build_too_many_files_meta

        rels = ["scripts/a.py"] * 900 + ["lib/b.py"] * 50
        meta = build_too_many_files_meta(rels, max_files=800)
        assert meta["skipped_reason"] == "too_many_files"
        assert meta["file_count"] == 950
        assert meta["max_files"] == 800
        assert meta["top_subdirs"][0] == {"dir": "scripts", "files": 900}
        # suggestion references a real subdir and the override knob
        assert "scripts" in meta["suggestion"]
        assert "max_files" in meta["suggestion"]
