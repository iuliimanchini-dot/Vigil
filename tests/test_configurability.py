"""Tests for per-project forensic configurability (G2.4).

Three capabilities, mirroring the original Vigil CLI:

A. Disabled-gates list — ``<project>/.cortex/disabled_gates.json`` lets a project
   switch off noisy gates. A disabled gate must NOT run (produce no findings) and
   must surface in ``meta["gates_skipped"]`` with reason ``"disabled_by_project"``.
   A missing/empty file is a no-op; a malformed file must never raise.

B. Severity floor — ``run_forensic_audit(..., severity=...)`` filters the returned
   ``findings`` to those at or above the floor (LOW < MEDIUM < HIGH < CRITICAL).

These are integration tests against the public ``run_forensic_audit`` entry point
plus the ``self_audit`` helpers, using a tiny on-disk fixture project.

Run:  pytest tests/test_configurability.py -v
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from vigil_forensic import run_forensic_audit


# ---------------------------------------------------------------------------
# Fixture: a project whose `broad_except` gate reliably triggers.
#
# A bare ``except Exception: return None`` fires:
#   - ``broad_except.return_none``                  (gate id: ``broad_except``)
#   - ``broad_except.hidden_sentinel.silent_return`` (gate id:
#     ``broad_except.hidden_sentinel`` — a SEPARATE gate)
# Disabling ``broad_except`` must drop the first and keep the second, proving
# the skip is gate-scoped, not a blanket suppression.
# ---------------------------------------------------------------------------

_SWALLOWING_SOURCE = (
    "def parse(x):\n"
    "    try:\n"
    "        return int(x)\n"
    "    except Exception:\n"
    "        return None\n"
)


def _make_project(tmp_path: Path) -> Path:
    proj = tmp_path / "proj"
    proj.mkdir()
    (proj / "app.py").write_text(_SWALLOWING_SOURCE, encoding="utf-8")
    return proj


def _make_mixed_severity_project(tmp_path: Path) -> Path:
    """A project that yields more than one severity level.

    - ``app.py`` (swallowing source) → two MEDIUM ``broad_except`` findings.
    - ``huge.py`` (a 162-line function) → one HIGH ``size.function_too_large``
      (exceeds the generic ``function_revise`` of 120 even with no profile;
      tmp_path lives outside the repo so the ancestor-walk finds no profile).

    The heterogeneous set lets the severity-floor reduction be tested actively
    rather than skipped.
    """
    proj = tmp_path / "proj"
    proj.mkdir()
    (proj / "app.py").write_text(_SWALLOWING_SOURCE, encoding="utf-8")
    body = "\n".join(f"    y{i} = {i}" for i in range(160))
    (proj / "huge.py").write_text("def huge():\n" + body + "\n    return 1\n", encoding="utf-8")
    return proj


def _write_disabled(proj: Path, payload) -> None:
    cortex = proj / ".cortex"
    cortex.mkdir(parents=True, exist_ok=True)
    (cortex / "disabled_gates.json").write_text(
        json.dumps(payload), encoding="utf-8"
    )


def _check_ids(result: dict) -> set[str]:
    return {f["check_id"] for f in result["findings"]}


def _skipped_with_reason(result: dict, reason: str) -> set[str]:
    return {
        e["gate_id"]
        for e in result["meta"].get("gates_skipped", [])
        if e.get("reason") == reason
    }


# ---------------------------------------------------------------------------
# A. disabled_gates.json
# ---------------------------------------------------------------------------

class TestDisabledGates:
    def test_baseline_triggers_broad_except(self, tmp_path):
        """Sanity: with NO disabled file, the broad_except gate fires.

        Without this the disable test could pass vacuously (a gate that never
        fires looks 'disabled' regardless of config)."""
        proj = _make_project(tmp_path)
        res = run_forensic_audit(proj)
        ids = _check_ids(res)
        assert any(cid.startswith("broad_except") for cid in ids), (
            f"fixture must trigger broad_except; got {sorted(ids)}"
        )
        # broad_except itself produced at least one finding
        assert "broad_except.return_none" in ids

    def test_disabled_gate_does_not_run_and_is_in_meta(self, tmp_path):
        """A gate listed in disabled_gates.json produces no findings and appears
        in meta.gates_skipped with reason 'disabled_by_project'."""
        proj = _make_project(tmp_path)
        baseline = run_forensic_audit(proj)
        baseline_ids = _check_ids(baseline)

        _write_disabled(proj, ["broad_except"])
        disabled = run_forensic_audit(proj)
        disabled_ids = _check_ids(disabled)

        # 1) The disabled gate produced NO findings.
        assert not any(cid == "broad_except" or cid.startswith("broad_except.return")
                       for cid in disabled_ids), (
            f"disabled gate still produced findings: {sorted(disabled_ids)}"
        )
        # broad_except.return_none was present at baseline, gone when disabled.
        assert "broad_except.return_none" in baseline_ids
        assert "broad_except.return_none" not in disabled_ids

        # 2) It appears in meta.gates_skipped with the right reason.
        assert "broad_except" in _skipped_with_reason(disabled, "disabled_by_project")

        # 3) Total finding count strictly dropped (disabling removed findings).
        assert len(disabled["findings"]) < len(baseline["findings"]), (
            f"finding count must drop: baseline={len(baseline['findings'])} "
            f"disabled={len(disabled['findings'])}"
        )

        # 4) A DIFFERENT gate (hidden_sentinel) still runs — skip is gate-scoped.
        assert "broad_except.hidden_sentinel.silent_return" in disabled_ids, (
            "disabling broad_except must NOT silence the separate "
            "broad_except.hidden_sentinel gate"
        )

    def test_disabled_supports_object_form(self, tmp_path):
        """The file may be {"disabled": [...]} as well as a bare list."""
        proj = _make_project(tmp_path)
        _write_disabled(proj, {"disabled": ["broad_except", "broad_except.hidden_sentinel"]})
        res = run_forensic_audit(proj)
        skipped = _skipped_with_reason(res, "disabled_by_project")
        assert "broad_except" in skipped
        assert "broad_except.hidden_sentinel" in skipped
        # Both broad_except findings are now gone.
        assert not any(cid.startswith("broad_except") for cid in _check_ids(res))

    def test_no_disabled_file_runs_all_gates(self, tmp_path):
        """No .cortex/disabled_gates.json → no error, nothing skipped for that
        reason, broad_except still runs."""
        proj = _make_project(tmp_path)
        assert not (proj / ".cortex" / "disabled_gates.json").exists()
        res = run_forensic_audit(proj)
        assert res["exit_code"] in (0, 1)  # ran fine, not an error (2)
        assert _skipped_with_reason(res, "disabled_by_project") == set()
        assert "broad_except.return_none" in _check_ids(res)

    def test_empty_disabled_file_runs_all_gates(self, tmp_path):
        """An empty list disables nothing."""
        proj = _make_project(tmp_path)
        _write_disabled(proj, [])
        res = run_forensic_audit(proj)
        assert res["exit_code"] in (0, 1)
        assert _skipped_with_reason(res, "disabled_by_project") == set()
        assert "broad_except.return_none" in _check_ids(res)

    def test_malformed_json_does_not_raise_and_audit_completes(self, tmp_path):
        """A corrupt disabled_gates.json must not crash the audit. The audit
        completes, all gates run (nothing disabled), and a meta finding records
        the load failure."""
        proj = _make_project(tmp_path)
        cortex = proj / ".cortex"
        cortex.mkdir(parents=True, exist_ok=True)
        (cortex / "disabled_gates.json").write_text(
            "{ this is not valid json ]", encoding="utf-8"
        )

        # Must not raise.
        res = run_forensic_audit(proj)

        # Audit still completed normally (not the error exit code 2).
        assert res["exit_code"] in (0, 1), res["meta"]
        # Nothing was disabled (malformed → ignored).
        assert _skipped_with_reason(res, "disabled_by_project") == set()
        # broad_except still ran despite the malformed file.
        assert "broad_except.return_none" in _check_ids(res)
        # The load failure is recorded as a meta finding (fail-loud, not silent).
        meta_ids = {f["check_id"] for f in res["findings"]}
        assert "meta.profile_load_failed" in meta_ids, (
            "malformed disabled_gates.json must surface as a meta finding"
        )

    def test_malformed_type_does_not_raise(self, tmp_path):
        """A JSON object without a 'disabled' key, or a non-list payload, must
        be handled without raising and disable nothing."""
        proj = _make_project(tmp_path)
        # Valid JSON, but wrong shape (a plain int).
        cortex = proj / ".cortex"
        cortex.mkdir(parents=True, exist_ok=True)
        (cortex / "disabled_gates.json").write_text("42", encoding="utf-8")
        res = run_forensic_audit(proj)
        assert res["exit_code"] in (0, 1)
        assert _skipped_with_reason(res, "disabled_by_project") == set()
        assert "broad_except.return_none" in _check_ids(res)


# ---------------------------------------------------------------------------
# B. Severity floor
# ---------------------------------------------------------------------------

class TestSeverityFloor:
    def test_floor_filters_below_threshold(self, tmp_path):
        """severity='CRITICAL' must drop every finding below CRITICAL, and the
        floored list is a strict subset of the LOW (unfiltered) list."""
        proj = _make_project(tmp_path)

        low = run_forensic_audit(proj, severity="LOW")
        assert low["findings"], "fixture must produce at least one finding at LOW"

        order = {"low": 0, "medium": 1, "high": 2, "critical": 3}

        # Filtering at CRITICAL keeps only critical findings.
        crit = run_forensic_audit(proj, severity="CRITICAL")
        for f in crit["findings"]:
            assert order[f["severity"].lower()] >= order["critical"], (
                f"CRITICAL floor leaked a {f['severity']} finding: {f['check_id']}"
            )
        assert len(crit["findings"]) <= len(low["findings"])

        # Filtering at HIGH keeps only HIGH+ and is a subset of LOW.
        high = run_forensic_audit(proj, severity="HIGH")
        for f in high["findings"]:
            assert order[f["severity"].lower()] >= order["high"], (
                f"HIGH floor leaked a {f['severity']} finding: {f['check_id']}"
            )
        assert len(high["findings"]) <= len(low["findings"])

    def test_floor_is_case_insensitive_and_default_is_low(self, tmp_path):
        """Default severity (LOW) returns everything; floor is case-insensitive."""
        proj = _make_project(tmp_path)
        default = run_forensic_audit(proj)
        low_upper = run_forensic_audit(proj, severity="LOW")
        low_lower = run_forensic_audit(proj, severity="low")
        assert len(default["findings"]) == len(low_upper["findings"]) == len(low_lower["findings"])

    def test_floor_actually_reduces_a_heterogeneous_finding_set(self, tmp_path):
        """A higher floor must yield strictly fewer findings than LOW when the
        fixture spans multiple severity levels (here: MEDIUM broad_except +
        HIGH size). Proves the floor genuinely removes findings, not a no-op."""
        proj = _make_mixed_severity_project(tmp_path)
        low = run_forensic_audit(proj, severity="LOW")
        severities = {f["severity"].lower() for f in low["findings"]}
        assert "medium" in severities and "high" in severities, (
            f"fixture must span MEDIUM and HIGH; got {sorted(severities)} "
            f"({sorted(f['check_id'] for f in low['findings'])})"
        )
        # HIGH floor must drop the MEDIUM broad_except findings.
        high = run_forensic_audit(proj, severity="HIGH")
        assert len(high["findings"]) < len(low["findings"]), (
            f"HIGH floor must reduce the set: low={len(low['findings'])} "
            f"high={len(high['findings'])}"
        )
        assert all(f["severity"].lower() == "high" for f in high["findings"]) or all(
            f["severity"].lower() in ("high", "critical") for f in high["findings"]
        )
        # meta records the post-filter count.
        assert high["meta"]["findings_after_severity_filter"] == len(high["findings"])
