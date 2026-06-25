"""Smoke tests for cortex_forensic standalone package.

Tests:
1. run_forensic_audit on a tmp project with a bare except: — returns findings
2. run_forensic_audit on a tmp project with .go and .ts files — does not raise
3. Return type is a dict with required keys
4. findings is a list of dicts (data, not printed)
"""
import json
from pathlib import Path
import pytest

from cortex_forensic import run_forensic_audit


def _make_py_project(tmp_path: Path) -> Path:
    """Create a tmp Python project with an obvious bare except that gates should flag."""
    proj = tmp_path / "proj_py"
    proj.mkdir()
    (proj / "__init__.py").write_text("# init\n", encoding="utf-8")
    # bare except — broad_except gate should fire
    (proj / "main.py").write_text(
        "def do_work():\n"
        "    try:\n"
        "        pass\n"
        "    except:\n"
        "        pass\n",
        encoding="utf-8",
    )
    return proj


def _make_multi_lang_project(tmp_path: Path) -> Path:
    """Create a tmp project with .go and .ts files — should not raise."""
    proj = tmp_path / "proj_multi"
    proj.mkdir()
    (proj / "server.go").write_text(
        "package main\n\nfunc main() {}\n", encoding="utf-8"
    )
    (proj / "client.ts").write_text(
        "export function hello(): string { return 'hi'; }\n", encoding="utf-8"
    )
    return proj


class TestRunForensicAuditReturnType:
    def test_returns_dict_with_required_keys(self, tmp_path):
        proj = _make_py_project(tmp_path)
        result = run_forensic_audit(proj)
        assert isinstance(result, dict), "run_forensic_audit must return a dict"
        assert "exit_code" in result, "result must have exit_code"
        assert "findings" in result, "result must have findings"
        assert "meta" in result, "result must have meta"
        assert "errors" in result, "result must have errors"

    def test_exit_code_is_int(self, tmp_path):
        proj = _make_py_project(tmp_path)
        result = run_forensic_audit(proj)
        assert isinstance(result["exit_code"], int)

    def test_findings_is_list(self, tmp_path):
        proj = _make_py_project(tmp_path)
        result = run_forensic_audit(proj)
        assert isinstance(result["findings"], list), "findings must be a list"


class TestBareExceptFinding:
    def test_bare_except_produces_findings(self, tmp_path):
        """A file with bare except: must produce at least one finding (data, not printed)."""
        proj = _make_py_project(tmp_path)
        result = run_forensic_audit(proj)
        assert len(result["findings"]) > 0, (
            "Expected at least one finding for bare except pattern.\n"
            f"meta: {result['meta']}\nerrors: {result['errors'][:5]}"
        )

    def test_findings_are_dicts_with_check_id(self, tmp_path):
        """Each finding must be a dict with check_id (data not print)."""
        proj = _make_py_project(tmp_path)
        result = run_forensic_audit(proj)
        for f in result["findings"]:
            assert isinstance(f, dict), f"finding must be a dict, got {type(f)}"
            assert "check_id" in f, f"finding must have check_id: {f}"
            assert "severity" in f, f"finding must have severity: {f}"
            assert "title" in f, f"finding must have title: {f}"

    def test_findings_are_json_serializable(self, tmp_path):
        """The full return value must be JSON-serializable (it's data, not objects)."""
        proj = _make_py_project(tmp_path)
        result = run_forensic_audit(proj)
        serialized = json.dumps(result)  # must not raise
        assert len(serialized) > 0


class TestMultiLanguageNoRaise:
    def test_go_and_ts_project_does_not_raise(self, tmp_path):
        """run_forensic_audit on a .go + .ts project must not raise."""
        proj = _make_multi_lang_project(tmp_path)
        result = run_forensic_audit(proj)
        # Return value must be a dict — we don't mandate findings presence
        assert isinstance(result, dict)
        assert "exit_code" in result
        assert "findings" in result

    def test_go_and_ts_project_exit_code_is_valid(self, tmp_path):
        proj = _make_multi_lang_project(tmp_path)
        result = run_forensic_audit(proj)
        assert result["exit_code"] in (0, 1, 2), f"Unexpected exit_code: {result['exit_code']}"


class TestNonExistentDir:
    def test_nonexistent_dir_returns_exit_code_2(self, tmp_path):
        result = run_forensic_audit(tmp_path / "nonexistent_dir_xyz")
        assert result["exit_code"] == 2
