"""TDD tests: cut ~50% false-positives on clean third-party code.

Each fix has a PAIRED test:
  - a reproduction case that asserts the verified false-positive is GONE, and
  - a true-positive control that asserts a genuine issue STILL fires
    (guards against over-correction).

Verified FP sources (inspected against real file:line in filelock/click/mcp):

  1. broad_except misfires on cleanup-then-reraise
     (filelock/_api.py:513  `except BaseException: <cleanup>; raise`)
  2. duplication.text_block per-line inflation + docstrings/param-lists
     (one duplicated sync↔async region emitted ~13 findings on filelock)
  3. zone-inference gates (god_object_zones.zone_inflation +
     size_complexity.zone_overload) — name-prefix heuristics, double-count,
     ~0 true positives on a cohesive RW-lock class → opt-in (off by default)
  4. api.public_function_signature_change misfires in no-git mode on variadic
     APIs (click.decorators.option(*param_decls, ...) → "0 params vs N
     documented")
  5. gate_profile fallback foot-gun — external target with no ancestor profile
     silently used strict code-defaults; should use the package's shipped
     gate_profile.json.

Run:  pytest tests/test_forensic_fp_clean_code.py -v
"""
from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest


# ---------------------------------------------------------------------------
# Shared minimal context builder (mirrors tests/test_fp_fixes.py)
# ---------------------------------------------------------------------------

def _make_ctx(tmp_path: Path, source_files, touched_files=None):
    from vigil_forensic.gate_models import (
        PostExecGateContext, RuntimeState, VerificationSummary, detect_source_package_roots,
    )
    from vigil_forensic._stubs import ValidationContractProfile, PocketCoderForensicReport
    from vigil_forensic.gate_checks.common import normalize_path, read_snapshot

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


def _write(tmp_path: Path, name: str, code: str) -> str:
    (tmp_path / name).write_text(code, encoding="utf-8")
    return name


# ===========================================================================
# FIX 1: broad_except cleanup-then-reraise is NOT a swallow
# ===========================================================================

class TestBroadExceptReraise:
    """`except BaseException: <cleanup>; raise` re-raises — must not be flagged.

    Covers both detectors:
      - broad_except_checks.py (regex: broad_except.base_exception / .bare)
      - broad_except_hidden_sentinel_checks.py (AST: .bare_or_base)
    """

    # The exact filelock/_api.py:513-517 cancel-cleanup idiom.
    _RERAISE = (
        "import time\n"
        "class Lock:\n"
        "    def acquire(self):\n"
        "        try:\n"
        "            self._poll()\n"
        "        except BaseException:\n"
        "            self._context.lock_counter = max(0, self._context.lock_counter - 1)\n"
        "            if self._context.lock_counter == 0:\n"
        "                _registry.held.pop(self._canonical, None)\n"
        "            raise\n"
        "        return self\n"
    )

    _BARE_RERAISE = (
        "def run():\n"
        "    try:\n"
        "        work()\n"
        "    except:\n"
        "        cleanup()\n"
        "        raise\n"
    )

    # Genuine swallow — broad catch, no re-raise, no surfacing.
    _SWALLOW = (
        "def run():\n"
        "    try:\n"
        "        work()\n"
        "    except BaseException:\n"
        "        cleanup()\n"
        "        x = 1\n"
    )

    def _broad_findings(self, tmp_path: Path, code: str) -> list[Any]:
        from vigil_forensic.gate_checks.broad_except_checks import run_broad_except_checks
        from vigil_forensic.gate_checks.broad_except_hidden_sentinel_checks import (
            run_broad_except_hidden_sentinel_checks,
        )
        name = _write(tmp_path, "subject.py", code)
        ctx = _make_ctx(tmp_path, [name])
        out = list(run_broad_except_checks(ctx).findings)
        out += list(run_broad_except_hidden_sentinel_checks(ctx).findings)
        return out

    def test_baseexception_reraise_not_flagged(self, tmp_path):
        findings = self._broad_findings(tmp_path, self._RERAISE)
        assert findings == [], (
            "except BaseException with a bare `raise` re-raises (cancel-cleanup "
            f"idiom) — must NOT be flagged. Got: {[f.check_id for f in findings]}"
        )

    def test_bare_except_reraise_not_flagged(self, tmp_path):
        findings = self._broad_findings(tmp_path, self._BARE_RERAISE)
        assert findings == [], (
            "bare except: cleanup; raise re-raises — must NOT be flagged. "
            f"Got: {[f.check_id for f in findings]}"
        )

    def test_genuine_swallow_still_flagged(self, tmp_path):
        """except BaseException with NO re-raise IS a swallow — must still fire."""
        findings = self._broad_findings(tmp_path, self._SWALLOW)
        assert len(findings) >= 1, (
            "except BaseException that does not re-raise must still be flagged"
        )


# ===========================================================================
# FIX 2: duplication.text_block — one finding per region, no docstring noise
# ===========================================================================

class TestDuplicationTextBlock:
    """A single duplicated region must emit ONE finding, not one per line.

    Pure-docstring / param-list duplication (sync↔async API mirrors) must not
    be flagged. Genuine copy-pasted CODE blocks must still be detected.
    """

    def _text_block_findings(self, tmp_path: Path, files) -> list[Any]:
        from vigil_forensic.gate_checks.duplication_checks import run_duplication_checks
        ctx = _make_ctx(tmp_path, files)
        return [
            f for f in run_duplication_checks(ctx).findings
            if f.check_id in ("duplication.text_block", "duplication.text_block_intra")
        ]

    def _make_dup_code_region(self, varname: str) -> str:
        # A 16-line block of real, identical executable statements.
        lines = [f"def {varname}(state):"]
        for i in range(16):
            lines.append(f"    step_{i} = transform(state, {i}) + offset_{i}")
        lines.append("    return step_0")
        return "\n".join(lines) + "\n"

    def test_single_duplicated_region_emits_one_finding(self, tmp_path):
        """20 consecutive identical CODE lines shared by 2 files → ONE finding,
        not ~9 (one per sliding-window position)."""
        block = self._make_dup_code_region("alpha")
        files = [
            _write(tmp_path, "mod_a.py", block),
            _write(tmp_path, "mod_b.py", block.replace("def alpha", "def beta")),
        ]
        findings = self._text_block_findings(tmp_path, files)
        assert len(findings) == 1, (
            "One duplicated region across two files must produce exactly one "
            f"text_block finding (per-line inflation bug). Got {len(findings)}: "
            f"{[f.summary[:80] for f in findings]}"
        )

    def test_shared_docstring_not_flagged(self, tmp_path):
        """A long shared docstring / :param list (sync↔async mirror) is not a
        code duplication — must NOT be flagged."""
        doc = '    """\n' + "".join(
            f"    :param arg{i}: description of argument number {i} that is long\n"
            for i in range(16)
        ) + '    """\n'
        sync_mod = "def configure(\n" + "".join(f"    arg{i}=None,\n" for i in range(16)) + "):\n" + doc + "    return 1\n"
        async_mod = "async def configure(\n" + "".join(f"    arg{i}=None,\n" for i in range(16)) + "):\n" + doc + "    return 1\n"
        files = [
            _write(tmp_path, "sync_api.py", sync_mod),
            _write(tmp_path, "async_api.py", async_mod),
        ]
        findings = self._text_block_findings(tmp_path, files)
        assert findings == [], (
            "Shared docstring / param-list across sync↔async mirrors is not code "
            f"duplication — must not be flagged. Got: {[f.summary[:80] for f in findings]}"
        )

    def test_genuine_code_duplication_still_flagged(self, tmp_path):
        """A real copy-pasted executable block across two files must still fire."""
        block = self._make_dup_code_region("gamma")
        files = [
            _write(tmp_path, "svc_a.py", block),
            _write(tmp_path, "svc_b.py", block.replace("def gamma", "def delta")),
        ]
        findings = self._text_block_findings(tmp_path, files)
        assert len(findings) >= 1, (
            "Genuine copy-pasted CODE block across files must still be detected"
        )


# ===========================================================================
# FIX 3: zone-inference gates default OFF (opt-in), no double-count
# ===========================================================================

class TestZoneGatesOptIn:
    """god_object_zones + size_complexity.zone_overload are name-prefix
    heuristics with ~0 true positives on cohesive RW-lock classes. They must be
    OFF by default (opt-in), and must not double-count the same file.
    """

    def test_god_object_zones_marked_opt_in(self):
        """The zone gate must be registered as a noisy opt-in gate."""
        from vigil_forensic.self_audit import _NOISY_OPT_IN_GATES
        assert "god_object_zones" in _NOISY_OPT_IN_GATES, (
            "god_object_zones is a noisy name-prefix heuristic and must be "
            "registered opt-in (in _NOISY_OPT_IN_GATES)"
        )

    def test_god_object_zones_skipped_in_default_run_gates(self, tmp_path):
        """A default run_gates (no filter) must NOT run god_object_zones — it is
        reported in gates_skipped with reason 'opt_in_only'."""
        from vigil_forensic.self_audit import (
            build_synthetic_context, discover_source_files, run_gates,
        )
        (tmp_path / "main.py").write_text("def acquire_x(): pass\n", encoding="utf-8")
        source_files = discover_source_files(tmp_path)
        ctx = build_synthetic_context(tmp_path, source_files)
        outcomes, skipped = run_gates(ctx)  # no gates_filter → default scan
        ran = {o.check_id for o in outcomes}
        assert "god_object_zones" not in ran, (
            "god_object_zones must be skipped in a default (unfiltered) scan"
        )
        opt_in_skipped = {
            e["gate_id"] for e in skipped if e.get("reason") == "opt_in_only"
        }
        assert "god_object_zones" in opt_in_skipped, (
            "skip must be recorded with reason 'opt_in_only'"
        )

    def test_zone_overload_off_by_default_in_audit(self, tmp_path):
        """A lock-like class with many RW method names must NOT produce zone
        findings in a default run_forensic_audit."""
        # 8 distinct zone prefixes (acquire/release/read/write/open/close/...),
        # 160+ lines — would trip BOTH zone gates under the old default.
        verbs = ["acquire", "release", "read", "write", "open", "close", "load", "save"]
        body_pad = "\n".join(f"    _pad_{i} = {i}" for i in range(140))
        code = "class RWLock:\n"
        for v in verbs:
            code += f"    def {v}_thing(self):\n        return None\n"
        code += body_pad + "\n"
        _write(tmp_path, "rwlock.py", code)

        from vigil_forensic import run_forensic_audit
        result = run_forensic_audit(tmp_path)
        zone_ids = {"god_object_zones.zone_inflation", "size_complexity.zone_overload"}
        zone_findings = [f for f in result["findings"] if f["check_id"] in zone_ids]
        assert zone_findings == [], (
            "Zone gates must be off by default — a cohesive RW-lock class must "
            f"not be flagged. Got: {[f['check_id'] for f in zone_findings]}"
        )

    def test_zone_gate_still_runnable_when_opted_in(self, tmp_path):
        """The capability must NOT be deleted — explicitly requesting the gate
        via the gates filter must still run it and flag a multi-zone file."""
        verbs = ["acquire", "release", "read", "write", "open"]
        body_pad = "\n".join(f"    _pad_{i} = {i}" for i in range(160))
        code = "class Mega:\n"
        for v in verbs:
            code += f"    def {v}_it(self):\n        return None\n"
        code += body_pad + "\n"
        _write(tmp_path, "mega.py", code)

        from vigil_forensic import run_forensic_audit
        result = run_forensic_audit(tmp_path, gates=["god_object_zones"])
        zone_findings = [
            f for f in result["findings"]
            if f["check_id"] == "god_object_zones.zone_inflation"
        ]
        assert len(zone_findings) >= 1, (
            "god_object_zones must remain runnable when explicitly opted in via "
            "the gates filter (capability preserved, just not default)"
        )


# ===========================================================================
# FIX 4: api.public_function_signature_change skipped in no-git mode
# ===========================================================================

class TestApiSignatureNoGit:
    """In degraded no-git mode the signature-drift check must not run — it needs
    a git baseline to be meaningful, and it misfires on documented variadic APIs.
    """

    _VARIADIC_API = (
        "def option(*param_decls, **attrs):\n"
        '    """Attaches an option to the command.\n'
        "\n"
        "    :param param_decls: the parameter declarations.\n"
        "    :param cls: the option class to instantiate.\n"
        "    :param attrs: extra keyword arguments.\n"
        '    """\n'
        "    return _make_option(param_decls, attrs)\n"
    )

    def test_variadic_api_not_flagged_without_git(self, tmp_path):
        """option(*param_decls, **attrs) with a 3-param docstring must NOT be
        flagged as '0 params vs 3 documented' when there is no git baseline."""
        from vigil_forensic.gate_checks.contract_shape_drift_checks import (
            run_contract_shape_drift_checks,
        )
        name = _write(tmp_path, "decorators.py", self._VARIADIC_API)
        # tmp_path is NOT a git repo → git_show returns None → degraded mode.
        ctx = _make_ctx(tmp_path, [name])
        findings = [
            f for f in run_contract_shape_drift_checks(ctx).findings
            if f.check_id == "api.public_function_signature_change"
        ]
        assert findings == [], (
            "Signature-drift must be skipped in no-git mode (needs a baseline). "
            f"Variadic API wrongly flagged: {[f.summary[:90] for f in findings]}"
        )

    def test_no_git_emits_skip_meta_finding(self, tmp_path):
        """When the signature check is skipped for lack of a git baseline, that
        fact is surfaced once via a meta finding."""
        from vigil_forensic.meta_findings import reset_meta_findings, drain_meta_findings
        from vigil_forensic.gate_checks.contract_shape_drift_checks import (
            run_contract_shape_drift_checks,
        )
        reset_meta_findings()
        name = _write(tmp_path, "decorators.py", self._VARIADIC_API)
        ctx = _make_ctx(tmp_path, [name])
        run_contract_shape_drift_checks(ctx)
        meta = drain_meta_findings()
        skip_ids = {m.check_id for m in meta}
        assert "meta.git_unavailable" in skip_ids, (
            "no-git signature skip must be reported once via meta.git_unavailable; "
            f"got meta ids: {skip_ids}"
        )


# ===========================================================================
# FIX 5: profile fallback to the package's shipped gate_profile.json
# ===========================================================================

class TestPackagedProfileFallback:
    """An external target with no ancestor gate_profile.json must fall back to
    the package's OWN shipped profile (750/1000/...), not strict code-defaults.
    """

    def test_external_target_uses_packaged_profile(self, tmp_path):
        """Isolated dir outside the repo → loader returns the shipped profile."""
        from vigil_forensic.self_audit import _load_gate_profile_if_present
        proj = tmp_path / "isolated_ext"
        proj.mkdir()
        (proj / "main.py").write_text("x = 1\n", encoding="utf-8")
        profile = _load_gate_profile_if_present(proj)
        assert profile is not None, (
            "External target with no ancestor profile must fall back to the "
            "package's shipped gate_profile.json (not None / strict code-defaults)"
        )
        assert profile.profile_name == "vigil-default"
        assert profile.size_thresholds["file_warn"] == 750
        assert profile.size_thresholds["file_revise"] == 1000

    def test_target_local_profile_still_wins(self, tmp_path):
        """A co-located profile must still take precedence over the packaged
        fallback."""
        import json as _json
        from vigil_forensic.self_audit import _load_gate_profile_if_present
        proj = tmp_path / "with_local"
        proj.mkdir()
        (proj / "gate_profile.json").write_text(
            _json.dumps({"profile_name": "local-override", "version": "9.9"}),
            encoding="utf-8",
        )
        (proj / "main.py").write_text("x = 1\n", encoding="utf-8")
        profile = _load_gate_profile_if_present(proj)
        assert profile is not None
        assert profile.profile_name == "local-override", (
            "A target-local gate_profile.json must win over the packaged fallback"
        )
