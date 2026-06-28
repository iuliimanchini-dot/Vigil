"""TDD tests for debug_print_scan false-positive precision.

The ``debug_print_scan`` gate (``assess_debug_prints``) historically matched the
substring ``print(`` anywhere on a line — including:

  * ``print(`` appearing inside a *string literal* (e.g. a detector pattern
    tuple ``(... "print(", ...)``),
  * lines explicitly suppressed with ``# noqa: debug_print_scan`` / bare
    ``# noqa``,
  * ``print()`` calls inside intentional CLI/output functions such as
    ``print_human_summary()`` / ``main()``.

These tests pin the corrected behavior:

  1. A real statement-level ``print("DEBUG", x)`` in a normal function IS flagged
     (recall preserved).
  2. ``print(`` inside a string literal is NOT flagged.
  3. A line carrying ``# noqa: debug_print_scan`` (or bare ``# noqa``) is NOT
     flagged.
  4. A ``print()`` inside a ``print_*`` / ``_print_*`` / ``main`` / ``cli``
     function is NOT flagged.

Run:  pytest tests/test_debug_print_fp.py -v
"""
from __future__ import annotations

from vigil_forensic.gate_checks.forensic_clusters.async_quality import (
    assess_debug_prints,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _titles(findings) -> list[str]:
    return [f.title for f in findings]


def _flagged_lines(findings) -> set[int]:
    # title shape: "[debug_prints] <path>:<line>"
    out: set[int] = set()
    for f in findings:
        try:
            out.add(int(f.title.rsplit(":", 1)[1]))
        except (ValueError, IndexError):
            pass
    return out


# ---------------------------------------------------------------------------
# 1. Recall: a genuine stray print() in normal code IS flagged.
# ---------------------------------------------------------------------------

def test_real_debug_print_statement_is_flagged():
    src = (
        "def trace_value(x):\n"
        '    print("DEBUG", x)\n'
        "    return x\n"
    )
    findings = assess_debug_prints("module.py", src)
    assert findings, "a real statement-level print() must still be flagged"
    assert 2 in _flagged_lines(findings)


def test_real_debug_print_with_leading_indent_is_flagged():
    # Nested inside an if — still a statement-position print, still flagged.
    src = (
        "def handler(x):\n"
        "    if x:\n"
        '        print("got", x)\n'
        "    return x\n"
    )
    findings = assess_debug_prints("svc.py", src)
    assert 3 in _flagged_lines(findings)


# ---------------------------------------------------------------------------
# 2. print( inside a string literal is NOT flagged.
# ---------------------------------------------------------------------------

def test_print_inside_string_literal_tuple_not_flagged():
    # Mirrors async_quality.py:71 / exception_boundary.py:46 — a detector
    # pattern tuple that contains the substring "print(".
    src = (
        "def is_log_only(body_lines):\n"
        "    return all(\n"
        '        l.startswith(("log", "logger", "print(", "#"))\n'
        "        for l in body_lines\n"
        "    )\n"
    )
    findings = assess_debug_prints("detector.py", src)
    assert not findings, f"print( in a string literal must not be flagged: {_titles(findings)}"


def test_print_in_single_string_assignment_not_flagged():
    src = (
        "def describe():\n"
        '    msg = "use print( for output"\n'
        "    return msg\n"
    )
    findings = assess_debug_prints("doc.py", src)
    assert not findings, f"print( inside a string must not be flagged: {_titles(findings)}"


# ---------------------------------------------------------------------------
# 3. # noqa suppression is respected.
# ---------------------------------------------------------------------------

def test_noqa_specific_check_suppresses():
    src = (
        "def trace_value(x):\n"
        '    print("DEBUG", x)  # noqa: debug_print_scan\n'
        "    return x\n"
    )
    findings = assess_debug_prints("module.py", src)
    assert not findings, f"# noqa: debug_print_scan must suppress: {_titles(findings)}"


def test_bare_noqa_suppresses():
    src = (
        "def trace_value(x):\n"
        '    print("DEBUG", x)  # noqa\n'
        "    return x\n"
    )
    findings = assess_debug_prints("module.py", src)
    assert not findings, f"bare # noqa must suppress: {_titles(findings)}"


def test_noqa_for_other_check_does_not_suppress():
    # A noqa for an *unrelated* check_id must NOT suppress debug_print_scan.
    src = (
        "def trace_value(x):\n"
        '    print("DEBUG", x)  # noqa: some_other_check\n'
        "    return x\n"
    )
    findings = assess_debug_prints("module.py", src)
    assert findings, "noqa for an unrelated check must not suppress debug_print_scan"


# ---------------------------------------------------------------------------
# 4. print() inside CLI/output functions is NOT flagged.
# ---------------------------------------------------------------------------

def test_print_inside_print_prefixed_function_not_flagged():
    # Mirrors self_audit.py::print_human_summary — intentional user-facing output.
    src = (
        "def print_human_summary(report):\n"
        '    print("=" * 72)\n'
        '    print(" FORENSIC SELF-AUDIT SUMMARY")\n'
        '    print("=" * 72)\n'
    )
    findings = assess_debug_prints("self_audit.py", src)
    assert not findings, f"print() in a print_* function must not be flagged: {_titles(findings)}"


def test_print_inside_underscore_print_function_not_flagged():
    src = (
        "def _print_reports(items):\n"
        "    for it in items:\n"
        "        print(it)\n"
    )
    findings = assess_debug_prints("report.py", src)
    assert not findings, f"print() in a _print_* function must not be flagged: {_titles(findings)}"


def test_print_inside_main_function_not_flagged():
    src = (
        "def main():\n"
        '    print("starting")\n'
        "    return 0\n"
    )
    findings = assess_debug_prints("entry.py", src)
    assert not findings, f"print() in main() must not be flagged: {_titles(findings)}"


def test_print_in_normal_function_still_flagged_even_with_cli_func_elsewhere():
    # A print_* function elsewhere in the file must NOT silence a stray print
    # in an unrelated normal function.
    src = (
        "def print_banner():\n"
        '    print("banner")\n'
        "\n"
        "def compute(x):\n"
        '    print("DEBUG", x)\n'
        "    return x * 2\n"
    )
    findings = assess_debug_prints("mixed.py", src)
    lines = _flagged_lines(findings)
    assert 5 in lines, "stray print in compute() must be flagged"
    assert 2 not in lines, "print in print_banner() must not be flagged"
