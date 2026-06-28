"""Tests for the default forensic gate profile (size-noise FP control).

Covers (G4):
  1. The shipped ``gate_profile.json`` ships INSIDE the vigil_forensic package
     (so it is included in the wheel), is valid JSON, loads via the real loader,
     and carries the documented industry-standard thresholds.
  2. Ancestor-walk fallback: a target with no co-located profile discovers an
     ancestor default profile.
  3. Precedence: a target-local profile wins over an ancestor profile.
  4. Behavior: the profile silences NOISE (moderately-large code) but still
     surfaces genuinely-extreme outliers.

Run:  pytest tests/test_gate_profile_default.py -v
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from vigil_forensic.self_audit import _load_gate_profile_if_present


# Thresholds documented in README.md "Default gate profile" section. Each value
# is a published linter default (SonarQube S138/PMD=100, pylint
# max-nested-blocks=5, SonarQube file=750, pylint max-module-lines=1000).
_EXPECTED_THRESHOLDS = {
    "file_warn": 750,
    "file_revise": 1000,
    "function_warn": 100,
    "function_revise": 150,
    "nesting_warn": 5,
    "nesting_revise": 8,
}

_REPO_ROOT = Path(__file__).resolve().parent.parent
# The default profile ships INSIDE the package so it is bundled in the wheel
# (repo root is not present after `pip install`). Mirrors
# self_audit._packaged_gate_profile_path().
_SHIPPED_PROFILE = _REPO_ROOT / "vigil_forensic" / "gate_profile.json"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _run_size_checks_with_thresholds(tmp_path: Path, source_files, thresholds):
    """Run run_size_complexity_checks against source_files with an explicit
    size-threshold profile, return the list of size findings."""
    from vigil_forensic._shared import RepoGateProfile, GateCategory
    from vigil_forensic.gate_models import (
        PostExecGateContext, RuntimeState, VerificationSummary, detect_source_package_roots,
    )
    from vigil_forensic._stubs import ValidationContractProfile, PocketCoderForensicReport
    from vigil_forensic.gate_checks.common import normalize_path, read_snapshot
    from vigil_forensic.gate_checks.size_complexity_checks import run_size_complexity_checks

    profile = RepoGateProfile(
        profile_name="test",
        version="1.0",
        enabled_categories=tuple(GateCategory),
        size_thresholds=dict(thresholds),
    )
    file_snapshots = {normalize_path(p): read_snapshot(tmp_path, p) for p in source_files}
    ctx = PostExecGateContext(
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
        touched_files=tuple(source_files),
        changed_files_observed=tuple(source_files),
        source_package_roots=detect_source_package_roots(tmp_path),
        file_snapshots=file_snapshots,
        repo_profile=profile,
        project_context=None,
    )
    result = run_size_complexity_checks(ctx)
    return [f for f in result.findings if str(f.check_id).startswith("size")]


# ---------------------------------------------------------------------------
# 1. Shipped default profile loads with the documented thresholds
# ---------------------------------------------------------------------------

class TestShippedDefaultProfile:
    def test_shipped_profile_file_exists(self):
        assert _SHIPPED_PROFILE.is_file(), (
            f"Default gate profile must ship inside the package "
            f"(bundled in the wheel): {_SHIPPED_PROFILE}"
        )

    def test_shipped_profile_is_inside_package(self):
        """The profile must live next to self_audit.py so package-data ships it
        in the wheel and _packaged_gate_profile_path() can find it post-install."""
        from vigil_forensic.self_audit import _packaged_gate_profile_path
        packaged = _packaged_gate_profile_path()
        assert packaged is not None and packaged.is_file(), (
            "_packaged_gate_profile_path() must resolve the in-package profile"
        )
        assert packaged.resolve() == _SHIPPED_PROFILE.resolve()
        import vigil_forensic
        pkg_dir = Path(vigil_forensic.__file__).resolve().parent
        assert packaged.resolve().parent == pkg_dir, (
            "profile must be co-located with the vigil_forensic package"
        )

    def test_shipped_profile_is_valid_json(self):
        # Strict json.loads — this is exactly what the loader and
        # _probe_meta_integrity do; comments are not allowed.
        payload = json.loads(_SHIPPED_PROFILE.read_text(encoding="utf-8"))
        assert isinstance(payload, dict)
        assert payload.get("profile_name") == "vigil-default"

    def test_shipped_profile_loads_via_loader(self):
        profile = _load_gate_profile_if_present(_REPO_ROOT)
        assert profile is not None, "loader must find the repo-root gate_profile.json"
        assert profile.profile_name == "vigil-default"

    def test_shipped_profile_thresholds_match_documented_values(self):
        profile = _load_gate_profile_if_present(_REPO_ROOT)
        assert profile is not None
        assert profile.size_thresholds == _EXPECTED_THRESHOLDS, (
            "Shipped thresholds drifted from the cited values documented in README.md"
        )


# ---------------------------------------------------------------------------
# 2. Ancestor-walk fallback discovers the repo-root default
# ---------------------------------------------------------------------------

class TestAncestorWalkFallback:
    def test_subpackage_audit_resolves_inpackage_profile(self):
        """Auditing the vigil_forensic package itself must resolve the shipped
        default profile. The profile is now co-located INSIDE the package, so it
        is picked up directly (candidate step 1), proving the in-package copy is
        the effective default for a sub-package target."""
        target = _REPO_ROOT / "vigil_forensic"
        assert (target / "gate_profile.json").is_file(), (
            "the default profile must be co-located inside vigil_forensic/"
        )
        profile = _load_gate_profile_if_present(target)
        assert profile is not None, "loader must find the in-package profile"
        assert profile.profile_name == "vigil-default"
        assert Path(profile.profile_path).resolve() == _SHIPPED_PROFILE.resolve()

    def test_ancestor_walk_finds_default_for_subdir_without_profile(self, tmp_path):
        """A target dir with no co-located profile, nested under an ancestor that
        DOES have one, must discover the ancestor profile via the upward walk."""
        ancestor = tmp_path / "repo"
        ancestor.mkdir()
        (ancestor / "gate_profile.json").write_text(
            json.dumps({"profile_name": "ancestor-default", "version": "1.0"}),
            encoding="utf-8",
        )
        target = ancestor / "pkg" / "sub"
        target.mkdir(parents=True)
        assert not (target / "gate_profile.json").is_file()
        profile = _load_gate_profile_if_present(target)
        assert profile is not None, "ancestor-walk must find the ancestor profile"
        assert profile.profile_name == "ancestor-default"

    def test_no_profile_anywhere_falls_back_to_packaged_default(self, tmp_path):
        """An isolated tmp dir with no profile in any ancestor falls back to the
        package's shipped default (FP fix: was returning None → strict
        code-defaults; now returns the documented 750/1000 profile)."""
        proj = tmp_path / "isolated"
        proj.mkdir()
        (proj / "main.py").write_text("x = 1\n", encoding="utf-8")
        # tmp_path is outside the repo, so no ancestor gate_profile.json exists.
        profile = _load_gate_profile_if_present(proj)
        assert profile is not None, (
            "External target with no ancestor profile must fall back to the "
            "package's shipped gate_profile.json, not None / strict code-defaults"
        )
        assert profile.profile_name == "vigil-default"
        assert profile.size_thresholds == _EXPECTED_THRESHOLDS

    def test_target_local_profile_wins_over_ancestor(self, tmp_path):
        """A profile co-located with the target takes precedence over any
        ancestor profile."""
        ancestor = tmp_path
        (ancestor / "gate_profile.json").write_text(
            json.dumps({"profile_name": "ancestor", "version": "1.0"}),
            encoding="utf-8",
        )
        target = ancestor / "sub"
        target.mkdir()
        (target / "gate_profile.json").write_text(
            json.dumps({"profile_name": "local", "version": "1.0"}),
            encoding="utf-8",
        )
        profile = _load_gate_profile_if_present(target)
        assert profile is not None
        assert profile.profile_name == "local", "target-local profile must win"


# ---------------------------------------------------------------------------
# 3. Behavior: silences noise, keeps genuine outliers
# ---------------------------------------------------------------------------

class TestProfileSilencesNoiseNotOutliers:
    # Strict built-in defaults from self_audit._GENERIC_SIZE_THRESHOLDS, used
    # when no profile is present. These are the source of the size noise.
    _STRICT = {
        "file_warn": 600, "file_revise": 800,
        "function_warn": 80, "function_revise": 120,
        "nesting_warn": 4, "nesting_revise": 6,
    }

    def _write_moderate_function(self, tmp_path: Path) -> str:
        """A 90-line function: >= strict function_warn (80) but < profile
        function_warn (100). Ordinary moderately-large code = noise."""
        body = "\n".join(f"    x{i} = {i}" for i in range(88))
        (tmp_path / "moderate.py").write_text(
            "def moderate():\n" + body + "\n    return 0\n", encoding="utf-8"
        )
        return "moderate.py"

    def _write_deep4_nesting(self, tmp_path: Path) -> str:
        """Nesting depth 4: >= strict nesting_warn (4) but < profile
        nesting_warn (5). Ordinary control flow = noise."""
        (tmp_path / "nest4.py").write_text(
            "def f(a, b, c, d):\n"
            "    if a:\n"
            "        if b:\n"
            "            if c:\n"
            "                if d:\n"
            "                    return 1\n",
            encoding="utf-8",
        )
        return "nest4.py"

    def _write_huge_function(self, tmp_path: Path) -> str:
        """A 162-line function: >= BOTH function_revise values (120 strict,
        150 profile). A genuine outlier that must still surface."""
        body = "\n".join(f"    y{i} = {i}" for i in range(160))
        (tmp_path / "huge.py").write_text(
            "def huge():\n" + body + "\n    return 1\n", encoding="utf-8"
        )
        return "huge.py"

    def test_moderate_code_is_noise_under_strict_defaults(self, tmp_path):
        files = [self._write_moderate_function(tmp_path), self._write_deep4_nesting(tmp_path)]
        strict = _run_size_checks_with_thresholds(tmp_path, files, self._STRICT)
        assert len(strict) > 0, (
            "Sanity: strict built-in defaults must flag the moderate fixtures "
            "(otherwise the noise the profile targets does not exist)"
        )

    def test_profile_silences_moderate_noise(self, tmp_path):
        files = [self._write_moderate_function(tmp_path), self._write_deep4_nesting(tmp_path)]
        strict = _run_size_checks_with_thresholds(tmp_path, files, self._STRICT)
        profiled = _run_size_checks_with_thresholds(tmp_path, files, _EXPECTED_THRESHOLDS)
        assert len(profiled) < len(strict), (
            f"Profile must lower size findings on moderate code: "
            f"strict={len(strict)} profiled={len(profiled)}"
        )
        # The moderate fixtures specifically must be fully silenced.
        assert profiled == [], (
            f"90-line function and depth-4 nesting are noise under the cited "
            f"thresholds and must be silent; got {[f.check_id for f in profiled]}"
        )

    def test_profile_still_surfaces_genuine_outlier(self, tmp_path):
        huge = self._write_huge_function(tmp_path)
        profiled = _run_size_checks_with_thresholds(tmp_path, [huge], _EXPECTED_THRESHOLDS)
        outliers = [f for f in profiled if f.check_id == "size.function_too_large"]
        assert len(outliers) >= 1, (
            "A 162-line function exceeds the profile's function_revise (150) and "
            "must still be flagged — the profile silences noise, not outliers"
        )
