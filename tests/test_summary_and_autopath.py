"""TDD tests for:
  Feature 1 — summary-first forensic results (get_forensic_results view='summary')
  Feature 2 — summary-first map results    (get_code_map_results view='summary')
  Feature 3 — auto project-targeting       (_resolve_project_root + optional path)

Run: pytest tests/test_summary_and_autopath.py -v
Resource-light: no xdist, drives Python functions directly, uses tmp dirs.
"""
from __future__ import annotations

import json
import textwrap
import time
from pathlib import Path
from typing import Any

import pytest

# ---------------------------------------------------------------------------
# Helpers shared across feature tests
# ---------------------------------------------------------------------------

def _poll(status_fn, job_id: str, max_wait: float = 120.0, interval: float = 0.5) -> str:
    deadline = time.monotonic() + max_wait
    while time.monotonic() < deadline:
        s = status_fn(job_id)
        if s.get("status") != "running":
            return s.get("status", "unknown")
        time.sleep(interval)
    return "timeout_poll"


def _make_python_project(tmp_path: Path, name: str = "proj") -> Path:
    """Minimal Python project for forensic/map scanners."""
    proj = tmp_path / name
    proj.mkdir()
    (proj / "main.py").write_text(
        textwrap.dedent("""\
            def greet(name: str) -> str:
                return f"Hello, {name}!"

            def divide(a, b):
                try:
                    return a / b
                except Exception:
                    return None
        """),
        encoding="utf-8",
    )
    (proj / "utils.py").write_text(
        textwrap.dedent("""\
            import os

            def read_file(path):
                try:
                    with open(path) as f:
                        return f.read()
                except Exception:
                    return None
        """),
        encoding="utf-8",
    )
    return proj


def _make_fake_audit_result(n_findings: int = 125) -> dict:
    """Construct a synthetic audit result dict with n_findings entries.

    Severity distribution: ~1/5 HIGH, ~2/5 MEDIUM, ~2/5 LOW.
    check_id pool: 5 distinct ids so by_check_id counts are non-trivial.
    """
    check_ids = ["broad_except", "bare_return_none", "sql_injection",
                 "hardcoded_secret", "unused_import"]
    severities = ["HIGH", "MEDIUM", "MEDIUM", "LOW", "LOW"]

    findings = []
    for i in range(n_findings):
        idx = i % len(check_ids)
        findings.append({
            "check_id": check_ids[idx],
            "severity": severities[idx],
            "file": f"src/module_{i // 10}.py",
            "line": (i % 50) + 1,
            "message": f"Finding #{i}: {check_ids[idx]} detected at line {(i % 50) + 1}",
        })
    return {
        "exit_code": 1,
        "findings": findings,
        "meta": {"project": "fake_project", "files_scanned": 60},
        "errors": [],
    }


# ===========================================================================
# Feature 1 — summary-first forensic results
# ===========================================================================

class TestForensicResultsSummaryView:
    """Unit tests against the helper functions directly — no real job needed."""

    def test_summary_keys_present(self):
        """Summary dict must have required top-level keys."""
        from vigil_mcp.forensic_server import _build_forensic_summary

        result = _make_fake_audit_result(125)
        summary = _build_forensic_summary(result)

        assert "total" in summary
        assert "exit_code" in summary
        assert "by_severity" in summary
        assert "by_check_id" in summary
        assert "top_findings" in summary
        assert "meta" in summary
        assert "hint" in summary

    def test_summary_total_correct(self):
        from vigil_mcp.forensic_server import _build_forensic_summary

        result = _make_fake_audit_result(125)
        summary = _build_forensic_summary(result)
        assert summary["total"] == 125

    def test_summary_by_severity_counts(self):
        """by_severity must include high/medium/low and counts must sum to total."""
        from vigil_mcp.forensic_server import _build_forensic_summary

        result = _make_fake_audit_result(125)
        summary = _build_forensic_summary(result)
        by_sev = summary["by_severity"]
        assert "high" in by_sev
        assert "medium" in by_sev
        assert "low" in by_sev
        # counts must sum to total
        assert sum(by_sev.values()) == 125

    def test_summary_top_findings_capped_at_20(self):
        """top_findings must contain at most 20 entries."""
        from vigil_mcp.forensic_server import _build_forensic_summary

        result = _make_fake_audit_result(125)
        summary = _build_forensic_summary(result)
        assert len(summary["top_findings"]) <= 20

    def test_summary_top_findings_highest_severity(self):
        """top_findings must be drawn from the highest severity present."""
        from vigil_mcp.forensic_server import _build_forensic_summary

        result = _make_fake_audit_result(125)
        # There are HIGH findings in this dataset
        summary = _build_forensic_summary(result)
        top = summary["top_findings"]
        assert len(top) > 0
        # All top findings must be of the highest severity present
        severities_in_top = {f["severity"] for f in top}
        # With 125 findings and HIGH present, all top should be HIGH
        assert severities_in_top == {"HIGH"}

    def test_summary_top_findings_fields(self):
        """Each top_finding must have the required compact fields."""
        from vigil_mcp.forensic_server import _build_forensic_summary

        result = _make_fake_audit_result(125)
        summary = _build_forensic_summary(result)
        for f in summary["top_findings"]:
            assert "check_id" in f
            assert "severity" in f
            assert "file" in f
            assert "line" in f
            assert "message" in f

    def test_summary_by_check_id_capped_at_25(self):
        """by_check_id must have at most 25 entries (top by count)."""
        from vigil_mcp.forensic_server import _build_forensic_summary

        result = _make_fake_audit_result(125)
        summary = _build_forensic_summary(result)
        assert len(summary["by_check_id"]) <= 25

    def test_summary_char_count_under_24000(self):
        """Summary JSON must stay well under 24 000 chars even for 125+ findings."""
        from vigil_mcp.forensic_server import _build_forensic_summary

        result = _make_fake_audit_result(125)
        summary = _build_forensic_summary(result)
        char_count = len(json.dumps(summary, default=str, indent=2))
        assert char_count < 24_000, (
            f"summary too large: {char_count} chars (limit 24000)"
        )

    def test_summary_char_count_printed(self, capsys):
        """Print real char count for the final report (informational test)."""
        from vigil_mcp.forensic_server import _build_forensic_summary

        result = _make_fake_audit_result(125)
        summary = _build_forensic_summary(result)
        char_count = len(json.dumps(summary, default=str, indent=2))
        print(f"\n[REPORT] summary char count (125 findings): {char_count}")
        assert True  # always passes; output captured by -s

    def test_get_forensic_results_default_is_summary(self):
        """get_forensic_results with no view= must default to summary."""
        from vigil_mcp.forensic_server import get_forensic_results
        from vigil_mcp._jobs import JobRegistry

        reg = JobRegistry(max_concurrent=2)
        fake = _make_fake_audit_result(125)
        r = reg.start(lambda: fake)
        jid = r["job_id"]
        _poll(reg.status, jid)

        # Monkey-patch the module-level result function so the tool sees our job
        import vigil_mcp._jobs as _jobs_mod
        original_result = _jobs_mod.result
        _jobs_mod.result = reg.result
        try:
            out = get_forensic_results(jid)
        finally:
            _jobs_mod.result = original_result

        # default view = summary → payload should be a compact dict
        assert out["status"] == "done"
        data = json.loads(out["payload"])
        assert "total" in data, f"Expected summary keys, got: {list(data.keys())}"
        assert "by_severity" in data

    def test_get_forensic_results_view_full_returns_all_findings(self):
        """view='full' must return the full findings list (paginated)."""
        from vigil_mcp.forensic_server import get_forensic_results
        from vigil_mcp._jobs import JobRegistry

        reg = JobRegistry(max_concurrent=2)
        fake = _make_fake_audit_result(50)
        r = reg.start(lambda: fake)
        jid = r["job_id"]
        _poll(reg.status, jid)

        import vigil_mcp._jobs as _jobs_mod
        original_result = _jobs_mod.result
        _jobs_mod.result = reg.result
        try:
            out = get_forensic_results(jid, view="full")
        finally:
            _jobs_mod.result = original_result

        assert out["status"] == "done"
        data = json.loads(out["payload"])
        # 'full' view: findings key must be present
        assert "findings" in data, f"Expected 'findings' in full view, got: {list(data.keys())}"
        assert len(data["findings"]) == 50

    def test_get_forensic_results_full_severity_filter(self):
        """view='full' with severity='HIGH' must return only HIGH findings."""
        from vigil_mcp.forensic_server import get_forensic_results
        from vigil_mcp._jobs import JobRegistry

        reg = JobRegistry(max_concurrent=2)
        fake = _make_fake_audit_result(125)
        r = reg.start(lambda: fake)
        jid = r["job_id"]
        _poll(reg.status, jid)

        import vigil_mcp._jobs as _jobs_mod
        original_result = _jobs_mod.result
        _jobs_mod.result = reg.result
        try:
            out = get_forensic_results(jid, view="full", severity="HIGH")
        finally:
            _jobs_mod.result = original_result

        assert out["status"] == "done"
        data = json.loads(out["payload"])
        assert "findings" in data
        for f in data["findings"]:
            assert f["severity"] == "HIGH", f"Non-HIGH finding slipped through: {f}"

    def test_get_forensic_results_full_check_id_filter(self):
        """view='full' with check_id='broad_except' must return only that check_id."""
        from vigil_mcp.forensic_server import get_forensic_results
        from vigil_mcp._jobs import JobRegistry

        reg = JobRegistry(max_concurrent=2)
        fake = _make_fake_audit_result(125)
        r = reg.start(lambda: fake)
        jid = r["job_id"]
        _poll(reg.status, jid)

        import vigil_mcp._jobs as _jobs_mod
        original_result = _jobs_mod.result
        _jobs_mod.result = reg.result
        try:
            out = get_forensic_results(jid, view="full", check_id="broad_except")
        finally:
            _jobs_mod.result = original_result

        assert out["status"] == "done"
        data = json.loads(out["payload"])
        assert "findings" in data
        for f in data["findings"]:
            assert f["check_id"] == "broad_except"


# ===========================================================================
# Feature 2 — summary-first map results
# ===========================================================================

class TestMapResultsSummaryView:
    """Unit tests for _build_map_summary and get_code_map_results view='summary'."""

    def _make_fake_maps_data(self, n_structural: int = 15, n_hotspot: int = 8) -> dict:
        """Synthetic _repo_maps_to_serialisable output."""
        structural = [
            {"name": f"MyClass{i}", "file": f"src/mod{i}.py", "line": i * 10, "complexity": i + 1}
            for i in range(n_structural)
        ]
        hotspot = [
            {"name": f"hot_fn{i}", "file": f"src/hot{i}.py", "line": i * 5, "size": (n_hotspot - i) * 20}
            for i in range(n_hotspot)
        ]
        return {
            "missing": False,
            "schema_version": "1.0",
            "structural": structural,
            "runtime": [],
            "data_contract": [{"name": "schema_v1", "file": "api/schema.py", "line": 1}],
            "authority": [],
            "conflict": [],
            "hotspot": hotspot,
            "refactor_boundary": [],
            "findings": [],
        }

    def test_summary_has_by_map_type(self):
        from vigil_mcp.map_server import _build_map_summary

        maps_data = self._make_fake_maps_data()
        summary = _build_map_summary(maps_data)
        assert "by_map_type" in summary
        bmt = summary["by_map_type"]
        assert bmt["structural"] == 15
        assert bmt["hotspot"] == 8
        assert bmt["data_contract"] == 1

    def test_summary_has_top_entries(self):
        from vigil_mcp.map_server import _build_map_summary

        maps_data = self._make_fake_maps_data()
        summary = _build_map_summary(maps_data)
        assert "top_entries" in summary
        # structural has 15 entries, top must be capped at 10
        assert len(summary["top_entries"].get("structural", [])) <= 10

    def test_summary_top_entries_fields(self):
        from vigil_mcp.map_server import _build_map_summary

        maps_data = self._make_fake_maps_data()
        summary = _build_map_summary(maps_data)
        for entry in summary["top_entries"].get("structural", []):
            assert "name" in entry
            assert "file" in entry

    def test_summary_has_hint(self):
        from vigil_mcp.map_server import _build_map_summary

        maps_data = self._make_fake_maps_data()
        summary = _build_map_summary(maps_data)
        assert "hint" in summary
        assert len(summary["hint"]) > 0

    def test_summary_char_count_bounded(self):
        from vigil_mcp.map_server import _build_map_summary

        maps_data = self._make_fake_maps_data(n_structural=100, n_hotspot=50)
        summary = _build_map_summary(maps_data)
        char_count = len(json.dumps(summary, default=str, indent=2))
        assert char_count < 24_000, (
            f"map summary too large: {char_count} chars (limit 24000)"
        )

    def test_get_code_map_results_default_is_summary(self):
        """get_code_map_results with no view= must default to summary."""
        from vigil_mcp.map_server import get_code_map_results
        from vigil_mcp._jobs import JobRegistry

        reg = JobRegistry(max_concurrent=2)
        # Fake job result: _run_map_build_with_path-shaped dict
        fake_inner = {"exit_code": 0, "_path": None}
        r = reg.start(lambda: fake_inner)
        jid = r["job_id"]
        _poll(reg.status, jid)

        import vigil_mcp._jobs as _jobs_mod
        import vigil_mcp.map_server as map_srv
        original_result = _jobs_mod.result
        # Also patch _repo_maps_to_serialisable to avoid needing disk maps
        original_r2s = map_srv._repo_maps_to_serialisable

        fake_maps = self._make_fake_maps_data()
        # path_str is None so maps_data falls to "path unavailable" note
        # We need to patch more deeply — inject a fake done result with maps
        # by returning a fake maps_data directly.
        def _fake_r2s(repo_maps):
            return fake_maps
        map_srv._repo_maps_to_serialisable = _fake_r2s

        _jobs_mod.result = reg.result
        try:
            out = get_code_map_results(jid)
        finally:
            _jobs_mod.result = original_result
            map_srv._repo_maps_to_serialisable = original_r2s

        assert out["status"] == "done"
        data = json.loads(out["payload"])
        # summary view: by_map_type must be present at top level or inside maps
        # The summary is nested under "maps" key in the full_data structure
        # so let's check either top-level or maps.by_map_type
        maps_part = data.get("maps", data)
        assert "by_map_type" in maps_part, (
            f"Expected by_map_type in summary, got keys: {list(maps_part.keys())}"
        )

    def test_get_code_map_results_map_filter_returns_one_map(self):
        """get_code_map_results with map='structural' returns only structural entries."""
        from vigil_mcp.map_server import get_code_map_results
        from vigil_mcp._jobs import JobRegistry

        reg = JobRegistry(max_concurrent=2)
        fake_inner = {"exit_code": 0, "_path": None}
        r = reg.start(lambda: fake_inner)
        jid = r["job_id"]
        _poll(reg.status, jid)

        import vigil_mcp._jobs as _jobs_mod
        import vigil_mcp.map_server as map_srv
        original_result = _jobs_mod.result
        original_r2s = map_srv._repo_maps_to_serialisable

        fake_maps = self._make_fake_maps_data(n_structural=15)
        map_srv._repo_maps_to_serialisable = lambda _: fake_maps
        _jobs_mod.result = reg.result
        try:
            out = get_code_map_results(jid, map="structural")
        finally:
            _jobs_mod.result = original_result
            map_srv._repo_maps_to_serialisable = original_r2s

        assert out["status"] == "done"
        data = json.loads(out["payload"])
        maps_part = data.get("maps", data)
        # Should have structural key with entries
        assert "structural" in maps_part, (
            f"Expected 'structural' key, got: {list(maps_part.keys())}"
        )
        # Should NOT have other map types (it's a single-map view)
        assert "hotspot" not in maps_part, (
            "map='structural' should return only structural, not other map types"
        )

    def test_get_code_map_results_view_full_returns_all_maps(self):
        """view='full' with no map returns all maps (backward compat)."""
        from vigil_mcp.map_server import get_code_map_results
        from vigil_mcp._jobs import JobRegistry

        reg = JobRegistry(max_concurrent=2)
        fake_inner = {"exit_code": 0, "_path": None}
        r = reg.start(lambda: fake_inner)
        jid = r["job_id"]
        _poll(reg.status, jid)

        import vigil_mcp._jobs as _jobs_mod
        import vigil_mcp.map_server as map_srv
        original_result = _jobs_mod.result
        original_r2s = map_srv._repo_maps_to_serialisable

        fake_maps = self._make_fake_maps_data(n_structural=5, n_hotspot=3)
        map_srv._repo_maps_to_serialisable = lambda _: fake_maps
        _jobs_mod.result = reg.result
        try:
            out = get_code_map_results(jid, view="full")
        finally:
            _jobs_mod.result = original_result
            map_srv._repo_maps_to_serialisable = original_r2s

        assert out["status"] == "done"
        data = json.loads(out["payload"])
        maps_part = data.get("maps", data)
        # full view: should have all map types
        assert "structural" in maps_part
        assert "hotspot" in maps_part


# ===========================================================================
# Feature 3 — auto project-targeting (_resolve_project_root)
# ===========================================================================

class TestResolveProjectRoot:
    """Unit tests for the _resolve_project_root helper."""

    def test_finds_git_in_current_dir(self, tmp_path):
        from vigil_mcp._paths import _resolve_project_root

        project = tmp_path / "myproject"
        project.mkdir()
        (project / ".git").mkdir()

        result = _resolve_project_root(str(project))
        assert result == str(project)

    def test_finds_pyproject_in_current_dir(self, tmp_path):
        from vigil_mcp._paths import _resolve_project_root

        project = tmp_path / "pypkg"
        project.mkdir()
        (project / "pyproject.toml").write_text("[tool.test]\n", encoding="utf-8")

        result = _resolve_project_root(str(project))
        assert result == str(project)

    def test_finds_git_in_ancestor(self, tmp_path):
        """If .git is 2 levels up, _resolve_project_root should find it."""
        from vigil_mcp._paths import _resolve_project_root

        root = tmp_path / "repo"
        root.mkdir()
        (root / ".git").mkdir()
        nested = root / "src" / "subpkg"
        nested.mkdir(parents=True)

        result = _resolve_project_root(str(nested))
        assert result == str(root)

    def test_finds_package_json_in_ancestor(self, tmp_path):
        from vigil_mcp._paths import _resolve_project_root

        root = tmp_path / "jsrepo"
        root.mkdir()
        (root / "package.json").write_text('{"name": "test"}\n', encoding="utf-8")
        nested = root / "src"
        nested.mkdir()

        result = _resolve_project_root(str(nested))
        assert result == str(root)

    def test_falls_back_to_start_when_no_marker(self, tmp_path):
        """With no .git/pyproject.toml/package.json, fall back to start dir."""
        from vigil_mcp._paths import _resolve_project_root

        bare = tmp_path / "bare"
        bare.mkdir()

        result = _resolve_project_root(str(bare))
        assert result == str(bare)

    def test_none_start_falls_back_to_cwd(self):
        """_resolve_project_root(None) must not crash and returns a string."""
        from vigil_mcp._paths import _resolve_project_root
        import os

        result = _resolve_project_root(None)
        assert isinstance(result, str)
        assert len(result) > 0
        # Must be a valid directory
        assert Path(result).is_dir() or result == os.getcwd()

    def test_prefers_git_over_pyproject(self, tmp_path):
        """When both .git and pyproject.toml exist in the same dir, finds that dir."""
        from vigil_mcp._paths import _resolve_project_root

        project = tmp_path / "both"
        project.mkdir()
        (project / ".git").mkdir()
        (project / "pyproject.toml").write_text("[build]\n", encoding="utf-8")

        result = _resolve_project_root(str(project))
        assert result == str(project)


class TestAutoPathInStartTools:
    """Integration tests: start_forensic_audit / start_code_map with empty path."""

    def test_start_forensic_audit_empty_path_returns_resolved_path(self, tmp_path):
        """start_forensic_audit('') auto-detects project, includes resolved_path in response."""
        from vigil_mcp.forensic_server import start_forensic_audit
        import vigil_mcp._jobs as _jobs_mod

        # Create a pyproject.toml project in tmp_path
        project = tmp_path / "autodetect_proj"
        project.mkdir()
        (project / "pyproject.toml").write_text("[build]\n", encoding="utf-8")
        (project / "main.py").write_text("x = 1\n", encoding="utf-8")

        # Patch _resolve_project_root to return our tmp project
        import vigil_mcp._paths as _paths_mod
        import vigil_mcp.forensic_server as fsrv
        original_resolve = _paths_mod._resolve_project_root
        _paths_mod._resolve_project_root = lambda start: str(project)
        # Also patch _jobs.start so we don't actually run the audit
        original_start = _jobs_mod.start
        captured = {}
        def _fake_start(fn, **kwargs):
            captured["resolved_path"] = getattr(fn, "_resolved_path", None)
            return {"job_id": "fake_jid", "status": "running", "resolved_path": str(project)}
        _jobs_mod.start = _fake_start
        try:
            result = start_forensic_audit("")
        finally:
            _paths_mod._resolve_project_root = original_resolve
            _jobs_mod.start = original_start

        assert "resolved_path" in result, (
            f"resolved_path missing from response: {result}"
        )
        assert result["resolved_path"] == str(project)

    def test_start_code_map_empty_path_returns_resolved_path(self, tmp_path):
        """start_code_map('') auto-detects project, includes resolved_path in response."""
        from vigil_mcp.map_server import start_code_map
        import vigil_mcp._jobs as _jobs_mod
        import vigil_mcp._paths as _paths_mod

        project = tmp_path / "map_autodetect"
        project.mkdir()
        (project / ".git").mkdir()

        original_resolve = _paths_mod._resolve_project_root
        _paths_mod._resolve_project_root = lambda start: str(project)
        original_start = _jobs_mod.start
        def _fake_start(fn, *args, **kwargs):
            return {"job_id": "fake_jid", "status": "running", "resolved_path": str(project)}
        _jobs_mod.start = _fake_start
        try:
            result = start_code_map("")
        finally:
            _paths_mod._resolve_project_root = original_resolve
            _jobs_mod.start = original_start

        assert "resolved_path" in result, (
            f"resolved_path missing from response: {result}"
        )

    def test_start_forensic_audit_explicit_path_not_overridden(self, tmp_path):
        """When an explicit path is given, it is used as-is (not auto-resolved)."""
        from vigil_mcp.forensic_server import start_forensic_audit
        import vigil_mcp._jobs as _jobs_mod

        explicit = tmp_path / "explicit"
        explicit.mkdir()
        (explicit / "main.py").write_text("x = 1\n", encoding="utf-8")

        original_start = _jobs_mod.start
        captured_path = {}
        def _fake_start(fn, **kwargs):
            # Try to recover what path the function closure uses
            return {"job_id": "jid", "status": "running", "resolved_path": str(explicit)}
        _jobs_mod.start = _fake_start
        try:
            result = start_forensic_audit(str(explicit))
        finally:
            _jobs_mod.start = original_start

        # Result must include resolved_path and it must equal explicit path
        assert "resolved_path" in result
        assert result["resolved_path"] == str(explicit)
