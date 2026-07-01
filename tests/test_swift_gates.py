"""Tests for the Swift-specific forensic gates.

Covers:
    - the AST line detectors (force-unwrap, implicitly-unwrapped optional),
      including FP-control assertions against look-alikes (!=, !flag, try!, ?.);
    - the gate runners through build_synthetic_context (pipeline integration);
    - registration in DEFAULT_GATE_CHECKS and _FILE_BASED_GATES;
    - zero false positives on the clean tests/oracle_swift fixtures.

These gates are ADDITIVE: they run only on .swift files and never touch any
other language's behavior.
"""
from __future__ import annotations

from pathlib import Path

from vigil_forensic.gate_checks.swift_safety_checks import (
    _force_unwrap_lines,
    _iuo_lines,
    run_swift_force_unwrap_checks,
    run_swift_iuo_checks,
)
from vigil_forensic.self_audit import (
    _FILE_BASED_GATES,
    build_synthetic_context,
    discover_source_files,
)
from vigil_forensic.gate_registry import DEFAULT_GATE_CHECKS

ORACLE_DIR = Path(__file__).parent / "oracle_swift"


# ---------------------------------------------------------------------------
# Line detectors — positives
# ---------------------------------------------------------------------------

class TestForceUnwrapDetector:
    def test_simple_unwraps_flagged(self):
        src = (
            "let a = value!\n"
            'let b = dict["key"]!\n'
            "let c = obj!.property\n"
        )
        assert _force_unwrap_lines(src) == [1, 2, 3]

    def test_chained_unwrap_flagged(self):
        # a!.b!.c yields one postfix line; self.delegate!.notify() another.
        src = "let chained = a!.b!.c\nself.delegate!.notify()\n"
        assert _force_unwrap_lines(src) == [1, 2]

    def test_force_unwrap_fp_control(self):
        """!=, logical-not, try!, optional chaining, ?? must NOT be flagged."""
        src = (
            "if x != y { print(\"ne\") }\n"
            "let flag = !done\n"
            "guard !items.isEmpty else { return }\n"
            "let t = try! riskyCall()\n"
            "let safe = optionalValue?.property\n"
            "let nilco = a ?? b\n"
            "let cmp = (a != b) && !c\n"
        )
        assert _force_unwrap_lines(src) == []


class TestIUODetector:
    def test_iuo_declarations_flagged(self):
        src = "var window: UIWindow!\nvar name: String!\nlet label: UILabel!\n"
        assert _iuo_lines(src) == [1, 2, 3]

    def test_iuo_fp_control(self):
        """Regular optionals, plain types, params, force-unwrap must NOT flag."""
        src = (
            "var opt: String?\n"
            "let count: Int = 0\n"
            "var arr: [Int]?\n"
            "func f(x: Int) {}\n"
            "let forced = value!\n"
        )
        assert _iuo_lines(src) == []

    def test_parse_failure_is_fail_open(self):
        # Garbage that still parses to *something*; detector must never raise.
        assert isinstance(_force_unwrap_lines("@@@!!!"), list)
        assert isinstance(_iuo_lines("@@@!!!"), list)


# ---------------------------------------------------------------------------
# Registration
# ---------------------------------------------------------------------------

class TestSwiftGateRegistration:
    def test_gates_in_default_registry(self):
        ids = {g[0] for g in DEFAULT_GATE_CHECKS}
        assert "swift.force_unwrap" in ids
        assert "swift.implicitly_unwrapped_optional" in ids

    def test_gates_are_file_based(self):
        assert "swift.force_unwrap" in _FILE_BASED_GATES
        assert "swift.implicitly_unwrapped_optional" in _FILE_BASED_GATES


# ---------------------------------------------------------------------------
# Pipeline integration via synthetic context
# ---------------------------------------------------------------------------

def _ctx_for_file(tmp_path: Path, name: str, content: str):
    (tmp_path / name).write_text(content, encoding="utf-8")
    files = discover_source_files(tmp_path)
    return build_synthetic_context(tmp_path, files)


class TestSwiftGatePipeline:
    def test_force_unwrap_gate_fires(self, tmp_path):
        ctx = _ctx_for_file(
            tmp_path, "Risky.swift",
            "class S {\n  func f() {\n    let x = load()!\n    let y = cache[\"k\"]!\n  }\n}\n",
        )
        result = run_swift_force_unwrap_checks(ctx)
        assert len(result.findings) == 2
        assert all(f.check_id == "swift.force_unwrap" for f in result.findings)
        assert all(str(f.severity.value) == "high" for f in result.findings)

    def test_iuo_gate_fires(self, tmp_path):
        ctx = _ctx_for_file(
            tmp_path, "Vc.swift",
            "class VC {\n  var window: UIWindow!\n  var name: String!\n}\n",
        )
        result = run_swift_iuo_checks(ctx)
        assert len(result.findings) == 2
        assert all(f.check_id == "swift.implicitly_unwrapped_optional" for f in result.findings)

    def test_test_file_excluded(self, tmp_path):
        # A *Tests.swift file with an unwrap must NOT be flagged.
        ctx = _ctx_for_file(
            tmp_path, "FooTests.swift",
            "class T {\n  func test() {\n    let x = value!\n  }\n}\n",
        )
        assert run_swift_force_unwrap_checks(ctx).findings == ()

    def test_allowlist_helper_is_invoked(self, tmp_path):
        """The gate routes each line through has_allowlist_for.

        NOTE: the shared ``has_allowlist_for`` recognises only ``#``-style
        (Python) allowlist comments (``# noqa: <id>``); Swift's ``//`` comment
        syntax is NOT yet recognised by that helper, so a ``// noqa`` on a
        Swift line does NOT suppress the finding today.  This test pins the
        CURRENT behaviour (no suppression via ``//``) so the limitation is
        explicit; suppression via the helper's supported ``#`` form is covered
        by the helper's own tests.
        """
        ctx = _ctx_for_file(
            tmp_path, "Ok.swift",
            "class S {\n  func f() {\n    let x = load()!  // noqa: swift.force_unwrap\n  }\n}\n",
        )
        # `//`-style allowlist is not honoured by the shared helper -> still flagged.
        assert len(run_swift_force_unwrap_checks(ctx).findings) == 1

    def test_non_swift_ignored(self, tmp_path):
        # A Python file with a trailing `!` in a string must not be processed
        # by the swift gate (language guard).
        ctx = _ctx_for_file(tmp_path, "mod.py", "x = '!'\nvalue = 1\n")
        assert run_swift_force_unwrap_checks(ctx).findings == ()
        assert run_swift_iuo_checks(ctx).findings == ()


# ---------------------------------------------------------------------------
# Zero false positives on the clean oracle fixtures
# ---------------------------------------------------------------------------

class TestSwiftGatesCleanOnOracle:
    def test_no_findings_on_oracle(self):
        files = discover_source_files(ORACLE_DIR)
        ctx = build_synthetic_context(ORACLE_DIR, files)
        assert run_swift_force_unwrap_checks(ctx).findings == ()
        assert run_swift_iuo_checks(ctx).findings == ()
