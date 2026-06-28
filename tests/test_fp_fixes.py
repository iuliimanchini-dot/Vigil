"""TDD tests for false-positive reduction fixes.

Fix areas:
  1. BOM double-count — files with UTF-8 BOM trigger parse errors x2 (meta + syntax)
  2. Duplication false positives — cross_touched_duplicate fires on full scans
  3. broad_except.return_none misfires on narrow exception types (except OSError)
  4. Lost repo_profile config — profile_path param + auto-discovery
  5. Cancellation — cancel_event stops gate loop early

Run:  pytest tests/test_fp_fixes.py -v
"""
from __future__ import annotations

import json
import threading
from pathlib import Path
from typing import Any
from unittest.mock import patch, MagicMock

import pytest

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _write_utf8_bom(path: Path, content: str) -> None:
    """Write content with a UTF-8 BOM prefix."""
    path.write_bytes(b"\xef\xbb\xbf" + content.encode("utf-8"))


def _make_minimal_ctx(tmp_path: Path, touched_files=None, source_files=None):
    """Build a minimal PostExecGateContext for tests."""
    from vigil_forensic.gate_models import PostExecGateContext, RuntimeState, VerificationSummary, detect_source_package_roots
    from vigil_forensic._stubs import ValidationContractProfile, PocketCoderForensicReport
    from vigil_forensic.gate_checks.common import normalize_path, read_snapshot

    if source_files is None:
        source_files = []
    if touched_files is None:
        touched_files = source_files

    file_snapshots = {normalize_path(p): read_snapshot(tmp_path, p) for p in source_files}
    return PostExecGateContext(
        project_dir=tmp_path,
        session_number=0,
        task_id="TEST",
        a1_task_id="TEST",
        validation_contract=ValidationContractProfile.from_mapping({}),
        forensic_report=PocketCoderForensicReport.from_mapping({}),
        runtime_state=RuntimeState.from_mapping({}),
        verification_summary=VerificationSummary.from_mapping({}),
        attempt_id="test",
        gate_round=1,
        touched_files=tuple(touched_files),
        changed_files_observed=tuple(touched_files),
        source_package_roots=detect_source_package_roots(tmp_path),
        file_snapshots=file_snapshots,
        project_context=None,
    )


# ===========================================================================
# FIX 1: BOM stripping
# ===========================================================================

class TestBomStripping:
    """Fix 1a: read_snapshot uses utf-8-sig so BOM is consumed, ast.parse succeeds."""

    def test_bom_file_parsed_without_syntax_error(self, tmp_path):
        """A .py file starting with BOM must parse cleanly — no syntax error finding."""
        from vigil_forensic.gate_checks.syntax_validity_checks import run_syntax_validity_checks

        bom_file = tmp_path / "bom_module.py"
        _write_utf8_bom(bom_file, "def hello():\n    return 42\n")

        ctx = _make_minimal_ctx(tmp_path, source_files=["bom_module.py"])
        result = run_syntax_validity_checks(ctx)
        parse_errors = [f for f in result.findings if "parse_error" in f.check_id]
        assert parse_errors == [], (
            f"BOM file should parse cleanly but got: {[f.check_id for f in parse_errors]}"
        )

    def test_bom_file_no_meta_syntax_parse_error(self, tmp_path):
        """BOM file must not trigger meta.syntax_parse_error from _ast_helpers."""
        from vigil_forensic.gate_checks._ast_helpers import parse_python_source_or_emit_finding
        from vigil_forensic.gate_checks.common import read_snapshot

        bom_file = tmp_path / "bom_ast.py"
        _write_utf8_bom(bom_file, "x = 1\n")

        snap = read_snapshot(tmp_path, "bom_ast.py")
        emitted = []
        result = parse_python_source_or_emit_finding(
            snap.text,
            rel_path="bom_ast.py",
            emit_finding=emitted.append,
        )
        assert result is not None, "BOM file should parse; got None (SyntaxError emitted)"
        assert emitted == [], f"Should emit no findings for BOM file, got: {emitted}"

    def test_non_bom_file_still_parses(self, tmp_path):
        """Regression: non-BOM valid Python must still parse cleanly."""
        from vigil_forensic.gate_checks.syntax_validity_checks import run_syntax_validity_checks

        clean_file = tmp_path / "clean.py"
        clean_file.write_text("def foo():\n    pass\n", encoding="utf-8")

        ctx = _make_minimal_ctx(tmp_path, source_files=["clean.py"])
        result = run_syntax_validity_checks(ctx)
        parse_errors = [f for f in result.findings if "parse_error" in f.check_id]
        assert parse_errors == []


class TestBomFingerprintDedup:
    """Fix 1b: Two gates emitting same fingerprint for same file/line → one finding only."""

    def test_duplicate_fingerprint_collapses_to_one(self):
        """meta_findings dedup: identical (check_id, path, line) emitted twice → one finding."""
        from vigil_forensic.meta_findings import emit_meta_finding, drain_meta_findings, reset_meta_findings
        from vigil_forensic.gate_checks._ast_helpers import build_syntax_parse_error_finding

        reset_meta_findings()
        # Simulate same parse error from two different gates via the same helper
        exc = SyntaxError("invalid syntax")
        exc.lineno = 5
        exc.msg = "invalid syntax"

        f1 = build_syntax_parse_error_finding(rel_path="foo.py", exc=exc, emitting_gate="gate_a")
        f2 = build_syntax_parse_error_finding(rel_path="foo.py", exc=exc, emitting_gate="gate_b")

        # Same file + line → same fingerprint by design in _ast_helpers
        assert f1.fingerprint == f2.fingerprint, (
            "Both findings must share a fingerprint so dedup can collapse them"
        )

        # Now test drain_meta_findings dedup (the actual fix):
        # Inject two findings with same fingerprint into the pending queue
        from vigil_forensic import meta_findings as mf
        import threading
        with mf._lock:
            mf._pending.clear()
            mf._pending.append(f1)
            mf._pending.append(f2)

        drained = drain_meta_findings()
        unique_fps = {f.fingerprint for f in drained}
        assert len(drained) == len(unique_fps), (
            f"Expected dedup to collapse duplicate fingerprints. Got {len(drained)} "
            f"findings but only {len(unique_fps)} unique fingerprints."
        )


# ===========================================================================
# FIX 2: Duplication — cross_touched_duplicate skipped in full-scan mode
# ===========================================================================

class TestDuplicationFullScanSkip:
    """Fix 2: full-scan contexts must emit zero cross_touched_duplicate findings."""

    def _make_dispatch_wrappers(self, tmp_path: Path, n: int) -> list[str]:
        """Write n structurally-identical dispatch wrapper functions."""
        files = []
        for i in range(n):
            p = tmp_path / f"wrapper_{i:02d}.py"
            p.write_text(
                f"def dispatch_{i}(ctx, payload):\n"
                f"    result = _inner_dispatch(ctx, payload)\n"
                f"    if result is None:\n"
                f"        raise RuntimeError('dispatch_{i} returned None')\n"
                f"    return result\n",
                encoding="utf-8",
            )
            files.append(p.name)
        return files

    def test_full_scan_zero_cross_touched_findings(self, tmp_path):
        """17 identical dispatch wrappers in a full-scan → zero cross_touched_duplicate."""
        from vigil_forensic.gate_checks.duplication_checks import run_duplication_checks

        files = self._make_dispatch_wrappers(tmp_path, 17)
        # Full scan: touched_files == ALL source files (self_audit.py pattern)
        ctx = _make_minimal_ctx(tmp_path, source_files=files, touched_files=files)

        # Mark context as full-scan (all touched == all source)
        # The fix must detect this automatically (touched_files == all source files)
        result = run_duplication_checks(ctx)
        cross_touched = [f for f in result.findings if f.check_id == "duplication.cross_touched_duplicate"]
        assert cross_touched == [], (
            f"Full-scan must emit zero cross_touched_duplicate, got {len(cross_touched)}"
        )

    def test_incremental_two_file_still_flags(self, tmp_path):
        """2-file incremental scan with a real duplicate → still flags it."""
        from vigil_forensic.gate_checks.duplication_checks import run_duplication_checks

        # Two files with identical functions; rest of project untouched
        for name in ("a.py", "b.py"):
            (tmp_path / name).write_text(
                "def process_event(event, state):\n"
                "    validate = state.get('validated', False)\n"
                "    if not validate:\n"
                "        raise ValueError('not validated')\n"
                "    return event['data']\n",
                encoding="utf-8",
            )
        # Also create some untouched files
        for i in range(5):
            (tmp_path / f"other_{i}.py").write_text(
                f"def unrelated_{i}(): pass\n", encoding="utf-8"
            )

        # Only touch a.py and b.py (incremental)
        ctx = _make_minimal_ctx(tmp_path, source_files=["a.py", "b.py"], touched_files=["a.py", "b.py"])
        result = run_duplication_checks(ctx)
        cross_touched = [f for f in result.findings if f.check_id == "duplication.cross_touched_duplicate"]
        assert len(cross_touched) >= 1, (
            "Incremental 2-file scan with real duplicate must still be flagged"
        )


# ===========================================================================
# FIX 3: broad_except.return_none — narrow exception types not flagged
# ===========================================================================

class TestBroadExceptReturnNone:
    """Fix 3: _EXCEPT_RETURN_SENTINEL_RE must not fire on narrow except types."""

    def _run_checks_on_code(self, tmp_path: Path, code: str) -> list[Any]:
        from vigil_forensic.gate_checks.broad_except_checks import run_broad_except_checks
        f = tmp_path / "subject.py"
        f.write_text(code, encoding="utf-8")
        ctx = _make_minimal_ctx(tmp_path, source_files=["subject.py"])
        result = run_broad_except_checks(ctx)
        return [f for f in result.findings if f.check_id == "broad_except.return_none"]

    def test_oserror_return_none_not_flagged(self, tmp_path):
        """except OSError: + intermediate line + return None is narrow — must NOT be flagged."""
        code = (
            "def read_file(path):\n"
            "    try:\n"
            "        with open(path) as f:\n"
            "            return f.read()\n"
            "    except OSError:\n"
            "        _log.warning('file not found')\n"
            "        return None\n"
        )
        findings = self._run_checks_on_code(tmp_path, code)
        assert findings == [], (
            f"except OSError: return None is narrow — must not trigger broad_except.return_none, got: {findings}"
        )

    def test_bare_exception_return_none_flagged(self, tmp_path):
        """except Exception: + intermediate line + return None IS broad — must be flagged.

        The regex requires one intermediate line before the return statement.
        """
        code = (
            "def risky():\n"
            "    try:\n"
            "        do_thing()\n"
            "    except Exception:\n"
            "        _log.warning('failed')\n"
            "        return None\n"
        )
        findings = self._run_checks_on_code(tmp_path, code)
        assert len(findings) >= 1, (
            "except Exception: (intermediate line) return None must be flagged by broad_except.return_none"
        )

    def test_base_exception_return_none_flagged(self, tmp_path):
        """except BaseException: + intermediate line + return None IS broad — must be flagged."""
        code = (
            "def risky():\n"
            "    try:\n"
            "        do_thing()\n"
            "    except BaseException:\n"
            "        _log.warning('failed')\n"
            "        return None\n"
        )
        findings = self._run_checks_on_code(tmp_path, code)
        assert len(findings) >= 1, (
            "except BaseException: (intermediate line) return None must be flagged by broad_except.return_none"
        )

    def test_value_error_return_empty_dict_not_flagged(self, tmp_path):
        """except ValueError: + intermediate + return {} — narrow catch, must NOT be flagged."""
        code = (
            "def parse(data):\n"
            "    try:\n"
            "        return int(data)\n"
            "    except ValueError:\n"
            "        _log.debug('parse failed')\n"
            "        return {}\n"
        )
        findings = self._run_checks_on_code(tmp_path, code)
        assert findings == [], (
            f"except ValueError: return {{}} is narrow — must not flag, got: {findings}"
        )


# ===========================================================================
# FIX 4: repo_profile auto-discovery via profile_path param
# ===========================================================================

class TestRepoProfileLoading:
    """Fix 4: run_forensic_audit with profile_path loads RepoGateProfile into ctx."""

    def _make_project_with_profile(self, tmp_path: Path, profile_data: dict) -> Path:
        proj = tmp_path / "proj"
        proj.mkdir()
        (proj / "__init__.py").write_text("# init\n", encoding="utf-8")
        (proj / "main.py").write_text("def foo(): pass\n", encoding="utf-8")
        profile_path = proj / "gate_profile.json"
        profile_path.write_text(json.dumps(profile_data), encoding="utf-8")
        return proj

    def test_auto_discover_profile_in_project_dir(self, tmp_path):
        """gate_profile.json in project_dir is auto-discovered and loaded."""
        profile_data = {
            "profile_name": "test_profile",
            "version": "1.0",
            "size_thresholds": {"file_warn": 999, "file_revise": 1500, "function_warn": 80, "function_revise": 120, "nesting_warn": 4, "nesting_revise": 6},
        }
        proj = self._make_project_with_profile(tmp_path, profile_data)

        from vigil_forensic import run_forensic_audit
        # Profile auto-discovery happens inside run_forensic_audit
        result = run_forensic_audit(proj)
        # The key assertion: no profile_load_failed meta finding
        all_check_ids = [f["check_id"] for f in result["findings"]]
        assert "meta.profile_load_failed" not in all_check_ids, (
            "Profile should load cleanly — no meta.profile_load_failed expected"
        )

    def test_profile_reaches_context_via_build_synthetic_context(self, tmp_path):
        """build_synthetic_context with a profile file present sets ctx.repo_profile."""
        profile_data = {
            "profile_name": "ctx_test",
            "version": "2.0",
            "generated_roots": ["generated/"],
        }
        proj = tmp_path / "proj2"
        proj.mkdir()
        (proj / "gate_profile.json").write_text(json.dumps(profile_data), encoding="utf-8")
        (proj / "main.py").write_text("x = 1\n", encoding="utf-8")

        from vigil_forensic.self_audit import build_synthetic_context, discover_source_files
        source_files = discover_source_files(proj)
        ctx = build_synthetic_context(proj, source_files)

        assert ctx.repo_profile is not None, (
            "build_synthetic_context must load gate_profile.json into ctx.repo_profile"
        )
        assert ctx.repo_profile.profile_name == "ctx_test"

    def test_no_profile_file_falls_back_to_packaged_default(self, tmp_path):
        """If no gate_profile.json exists in the target or any ancestor, the
        loader falls back to the package's shipped default profile (FP fix:
        previously left repo_profile=None → strict code-defaults)."""
        proj = tmp_path / "no_profile"
        proj.mkdir()
        (proj / "main.py").write_text("x = 1\n", encoding="utf-8")

        from vigil_forensic.self_audit import build_synthetic_context, discover_source_files
        source_files = discover_source_files(proj)
        ctx = build_synthetic_context(proj, source_files)
        # No exception; packaged default profile is used when no file present.
        assert ctx.repo_profile is not None
        assert ctx.repo_profile.profile_name == "cortex-default"


# ===========================================================================
# FIX 5: Cancel event wires into run_gates and cluster runner
# ===========================================================================

class TestCancellation:
    """Fix 5: cancel_event=threading.Event() stops gate loop before all gates finish."""

    def test_pre_set_cancel_event_bails_early_from_run_gates(self, tmp_path):
        """A pre-set cancel_event causes run_gates to stop before processing all gates."""
        (tmp_path / "main.py").write_text("x = 1\n", encoding="utf-8")

        from vigil_forensic.self_audit import build_synthetic_context, discover_source_files, run_gates

        source_files = discover_source_files(tmp_path)
        ctx = build_synthetic_context(tmp_path, source_files)

        # Count how many gates would normally run (no cancel)
        outcomes_full, _ = run_gates(ctx)
        normal_count = len(outcomes_full)

        # Now with pre-set cancel event
        event = threading.Event()
        event.set()  # already cancelled

        outcomes_cancelled, _ = run_gates(ctx, cancel_event=event)
        # Should have processed zero or very few gates
        assert len(outcomes_cancelled) < normal_count, (
            f"Pre-set cancel_event must stop gate processing early. "
            f"Full run: {normal_count} gates, cancelled run: {len(outcomes_cancelled)} gates."
        )

    def test_run_forensic_audit_accepts_cancel_event_param(self, tmp_path):
        """run_forensic_audit must accept cancel_event kwarg without raising."""
        (tmp_path / "main.py").write_text("x = 1\n", encoding="utf-8")

        from vigil_forensic import run_forensic_audit
        event = threading.Event()
        # Should not raise TypeError for unexpected keyword argument
        result = run_forensic_audit(tmp_path, cancel_event=event)
        assert isinstance(result, dict)
        assert "exit_code" in result

    def test_cancel_event_none_runs_normally(self, tmp_path):
        """cancel_event=None (default) must not affect normal operation."""
        (tmp_path / "main.py").write_text(
            "def foo():\n    try:\n        pass\n    except:\n        pass\n",
            encoding="utf-8",
        )
        from vigil_forensic import run_forensic_audit
        result = run_forensic_audit(tmp_path, cancel_event=None)
        assert isinstance(result, dict)
        # Should find the bare except
        assert len(result["findings"]) > 0
