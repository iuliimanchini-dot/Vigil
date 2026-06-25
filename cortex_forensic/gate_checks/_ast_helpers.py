"""AST-based helpers shared across line-based forensic gates.

Motivation (F14a, 2026-04-23)
----------------------------
Several "AST-sounding" gates (``test_quality_scan``, ``dead_code_scan``,
``unreachable_scan``) are implemented as line-based regex scans over
``content.splitlines()``. Those scans cannot distinguish between real Python
source and source that appears *inside a string literal* (test fixtures,
embedded code examples in docstrings, scripted-generation tests, etc.).

Example false positive
~~~~~~~~~~~~~~~~~~~~~~
Inside a test file::

    FIXTURE_CODE = '''
    def func_c():
        return x
        dead_line()
    '''

The line-based ``unreachable_scan`` regex saw ``return x`` on one line
followed by statements on the next line at the same indent and flagged
the fixture body as unreachable code. But those bytes are a string literal,
not real code.

Fix shape
~~~~~~~~~
``collect_string_constant_line_ranges(source)`` parses the source once via
``ast.parse`` and returns the set of 1-based line numbers that are covered
by any string ``Constant`` node or ``JoinedStr`` (f-string) node. Line-based
gates then skip matches whose line is in this set.

The helper is AST-only — no regex over source text — and degrades gracefully
to an empty ``frozenset()`` when ``ast.parse`` raises ``SyntaxError``, which
preserves prior gate behavior for unparseable files. Non-Python files are
expected to be rejected upstream by ``detect_language(...) != "python"``;
calling this helper with non-Python source is not an error but will almost
certainly fail to parse and produce an empty result (safe default).

The helper is **intentionally** conservative in what it excludes:

* Only the lines spanned by ``ast.Constant(value=str)`` and ``ast.JoinedStr``.
* Pure ``ast.Expression`` docstrings appear as ``Constant(str)`` already.
* Byte strings (``b"..."``) are ``Constant(value=bytes)`` and are NOT
  excluded — they cannot host Python source interpretation anyway.
* String-typed *annotations* (forward refs) are string constants but they
  span a single token; excluding them causes no false negatives because
  they do not contain statement-level code.

No reachable code ever lives inside a ``Constant(str)`` or ``JoinedStr``,
so false-negative risk is zero by construction.
"""
from __future__ import annotations

import ast
import hashlib
import re
from functools import lru_cache
from typing import Callable, Optional

from cortex_forensic._shared import (
    EvidenceReference,
    GateCategory,
    GateFinding,
    GateImpact,
    GateSeverity,
    RepairKind,
)


# ---------------------------------------------------------------------------
# F14c: Detector self-match suppression helpers
# ---------------------------------------------------------------------------
# Shared by text-scanning gates (todo_scan,
# legacy_compat_debt.stale_migration_marker, debug_print_scan) to avoid
# "detector self-match" false positives where a gate finds its own pattern
# definitions in its own source.

_UPPER_NAME_RE = re.compile(r"^_?[A-Z][A-Z0-9_]*$")

# A comment line used as a visual section separator:
#   # --- section ---
#   # === Legacy Debt (C53) ===
#   # ----- DEBUG -----
#   # -- legacy_debt (C53) --
# Regular prose comments never match.
_SECTION_HEADER_COMMENT_RE = re.compile(
    r"""
    ^\s*\#\s*
    (?:
        (?:[-=]{2,})\s*\S.*?\s*(?:[-=]{2,})?
        |
        \S.*?\s*[-=]{2,}
    )
    \s*$
    """,
    re.VERBOSE,
)

# F14c sub-fix 3: files where ``print()`` is legitimate CLI output.
_CLI_SURFACE_FILE_PREFIXES: tuple[str, ...] = (
    "INTERFACE/cli/",
)

_CLI_SURFACE_FILE_EXACT: frozenset[str] = frozenset({
    "BRAIN/autoforensics/self_audit.py",
    "BRAIN/autoforensics/cli_forensic_audit.py",
    # Protocol-layer output helper — safe_print() wraps print(); flagging its
    # own implementation is a false positive.
    "SYSTEM/execution/pocketcoder_command.py",
    # CLI dispatch entry point — cmd_list() renders project table to stdout;
    # this is user-facing output, not a debug print.
    "SYSTEM/runtime/app.py",
    # Test runner utility — progress banners printed to stdout for operator
    # visibility; not production code.
    "SYSTEM/dev/tests/run_all_stress_tests.py",
    # Map Builder CLI entry — cmd_map_invariants() + _print_reports() emit
    # invariant results to stdout; Category D user-facing output.
    "BRAIN/autoforensics/map_builder/invariant_suite.py",
})

# Filename suffixes that mark a file as a user-facing CLI entrypoint.
# Convention: ``<feature>/cli_entry.py`` exposes a ``cmd_*`` dispatcher for
# the Vigil app parser and prints human-readable progress/status.
_CLI_SURFACE_FILE_SUFFIXES: tuple[str, ...] = (
    "/cli_entry.py",
)

_CLI_FUNC_NAMES: frozenset[str] = frozenset({
    "main", "_main", "cli_main", "_cli_main", "run", "cli", "_cli",
})


__all__ = [
    "collect_string_constant_line_ranges",
    "line_is_inside_string_constant",
    "collect_constant_container_literal_lines",
    "is_section_header_comment",
    "is_cli_surface_file",
    "collect_main_block_line_ranges",
    "line_in_ranges",
    "parse_python_source_or_emit_finding",
    "build_syntax_parse_error_finding",
]


# ---------------------------------------------------------------------------
# B2 (2026-04-23) -- defensive meta-integrity
# ---------------------------------------------------------------------------
# Rationale
#   Historically every "AST gate" in autoforensics opened with:
#       try:
#           tree = ast.parse(source)
#       except SyntaxError:
#           return []   # or ``continue``
#   A real SyntaxError in production code is a REAL BUG, but that try/except
#   made the gate *blind* -- zero findings emitted => file looks clean.
#
# Fix shape
#   ``parse_python_source_or_emit_finding`` is a drop-in replacement for the
#   silent try/except. On SyntaxError it calls the caller-supplied
#   ``emit_finding`` hook with a ``meta.syntax_parse_error`` finding, then
#   returns ``None`` so the caller preserves its own control flow.
#
# Do NOT use this for helpers that are BY DESIGN syntax-tolerant
# (``collect_string_constant_line_ranges``, ``collect_main_block_line_ranges``,
# ``collect_constant_container_literal_lines``) -- those fall back to empty
# results on purpose and must remain silent.

_PYTHON_EXTENSIONS: frozenset[str] = frozenset({".py", ".pyi"})


def _looks_like_python_path(rel_path: str) -> bool:
    """True iff ``rel_path`` looks like a Python source file by extension."""
    if not rel_path:
        return False
    normalized = rel_path.replace("\\", "/").lower()
    dot = normalized.rfind(".")
    if dot < 0:
        return False
    return normalized[dot:] in _PYTHON_EXTENSIONS


def build_syntax_parse_error_finding(
    *,
    rel_path: str,
    exc: SyntaxError,
    emitting_gate: str = "",
) -> GateFinding:
    """Construct the canonical ``meta.syntax_parse_error`` GateFinding.

    Separated from :func:`parse_python_source_or_emit_finding` so tests can
    assert shape without spinning up a parser.
    """
    line_info = f"line {exc.lineno}" if exc.lineno else "unknown line"
    msg = str(exc.msg) if exc.msg else "unknown parse error"
    evidence = (
        EvidenceReference(
            kind="syntax_error",
            path=rel_path,
            detail=f"{line_info}: {msg}"[:512],
        ),
    )
    # Deterministic fingerprint: (path, line) - if same file + same line has
    # two gates each emit meta.syntax_parse_error, they share a fingerprint
    # and self-audit dedup can collapse them downstream.
    fp_source = f"meta.syntax_parse_error|{rel_path}|{exc.lineno}"
    fingerprint = hashlib.sha256(fp_source.encode("utf-8")).hexdigest()[:16]
    emitter_tag = f" [emitted by {emitting_gate}]" if emitting_gate else ""
    return GateFinding(
        check_id="meta.syntax_parse_error",
        category=GateCategory.META,
        title=f"Python syntax error in {rel_path} ({line_info})",
        severity=GateSeverity.HIGH,
        impact=GateImpact.REVISE,
        summary=(
            f"{rel_path}:{exc.lineno}: {msg}. Autoforensics gate could not "
            f"parse this file and skipped its checks for this path.{emitter_tag}"
        ),
        recommendation=(
            "Fix the Python syntax error so gates can parse and audit this "
            "file. A silent skip hides real bugs from the audit."
        ),
        evidence=evidence,
        fingerprint=fingerprint,
        repair_kind=RepairKind.FIX_SYNTAX.value,
        executor_action="fix Python syntax error",
        proof_required="ast.parse succeeds on the file",
        allowlist_allowed=False,
        preferred_fix_shape="restore valid Python grammar; do not silence via except",
    )


def parse_python_source_or_emit_finding(
    source: str,
    *,
    rel_path: str,
    emit_finding: Optional[Callable[[GateFinding], None]] = None,
    emitting_gate: str = "",
    filename: str | None = None,
) -> ast.Module | None:
    """Parse Python source and return the AST module, or emit a meta finding.

    Behavior:
      * On success: returns the ``ast.Module``.
      * On ``SyntaxError``: if ``emit_finding`` was provided, calls it with a
        ``meta.syntax_parse_error`` finding, then returns ``None``. Caller is
        responsible for mirroring its own control flow (``return``/``continue``).
      * When ``emit_finding is None`` (unit tests, utility helpers): no
        side-effects on error; simply returns ``None``.
    """
    if not source:
        return None
    try:
        return ast.parse(source, filename=filename or rel_path or "<unknown>")
    except SyntaxError as exc:
        if emit_finding is not None and _looks_like_python_path(rel_path):
            try:
                emit_finding(
                    build_syntax_parse_error_finding(
                        rel_path=rel_path,
                        exc=exc,
                        emitting_gate=emitting_gate,
                    )
                )
            except Exception:  # noqa: BLE001 -- never crash a gate on emit failure
                pass
        return None


def _collect_impl(source: str) -> frozenset[int]:
    try:
        tree = ast.parse(source)
    except (SyntaxError, ValueError):
        # ValueError catches things like source containing a null byte.
        return frozenset()

    lines: set[int] = set()
    for node in ast.walk(tree):
        # ast.Constant(value=str) — covers plain "..."/'...', triple-quoted
        # """...""", docstrings, and string-type forward refs.
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            start = getattr(node, "lineno", None)
            end = getattr(node, "end_lineno", None)
            if start is None or end is None:
                continue
            start = int(start)
            end = int(end)
            # Only the *interior* lines of a multi-line string are purely
            # inside the literal. The opening line (``x = '''``) and the
            # closing line (``'''``) may carry real code before the opening
            # quote or after the closing quote (e.g. ``raise ValueError("bad")``
            # is a single-line string on a real statement line). A single-line
            # string (start == end) contributes no excluded line.
            if end - start < 2:
                continue
            for ln in range(start + 1, end):
                lines.add(ln)
            continue

        # ast.JoinedStr — f-strings. Same interior-only rule: only middle
        # lines of a multi-line f-string are purely string content.
        if isinstance(node, ast.JoinedStr):
            start = getattr(node, "lineno", None)
            end = getattr(node, "end_lineno", None)
            if start is None or end is None:
                continue
            start = int(start)
            end = int(end)
            if end - start < 2:
                continue
            for ln in range(start + 1, end):
                lines.add(ln)
            continue

    return frozenset(lines)


@lru_cache(maxsize=256)
def _collect_cached(source: str) -> frozenset[int]:
    """LRU-cached parse. Keyed on the full source string so repeated calls
    during a single gate run (multiple regex passes on the same file) parse
    the file exactly once. Cache size is bounded to keep memory flat."""
    return _collect_impl(source)


def collect_string_constant_line_ranges(source: str) -> frozenset[int]:
    """Return 1-based line numbers that fall inside any Python string literal.

    Covers:
      * single-quoted / double-quoted string constants,
      * triple-quoted string constants (docstrings and plain literals),
      * f-strings (``ast.JoinedStr``).

    Returns ``frozenset()`` if ``source`` is not valid Python — no safe
    exclusions means unchanged prior behavior for that file.

    Intended use
    ------------
    At the top of a line-based gate runner::

        excluded = collect_string_constant_line_ranges(content)
        for i, line in enumerate(content.splitlines(), 1):
            if i in excluded:
                continue
            ...

    For regex matches on the whole ``content`` (not per-line), convert the
    match offset to a line number via ``content[:m.start()].count("\\n") + 1``
    and check that line against ``excluded``.
    """
    if not source:
        return frozenset()
    try:
        return _collect_cached(source)
    except TypeError:
        # lru_cache requires hashable; source is str, so this should never
        # happen. Keep defense in depth anyway.
        return _collect_impl(source)


def line_is_inside_string_constant(source: str, lineno: int) -> bool:
    """Convenience wrapper — True iff ``lineno`` is covered by any string literal."""
    return lineno in collect_string_constant_line_ranges(source)


# ---------------------------------------------------------------------------
# F14c implementations
# ---------------------------------------------------------------------------


def collect_constant_container_literal_lines(source: str) -> frozenset[int]:
    """F14c sub-fix 1: return line numbers of string literals inside
    UPPER_CASE module-level tuple/list/set/frozenset/dict assignments.

    Used by text-scanning gates to skip their own marker definitions such as::

        _TECH_DEBT_MARKERS = ("TODO", "FIXME", "HACK", "XXX")

    Criteria (AST-based, conservative):
      * ``ast.Assign`` or ``ast.AnnAssign`` at module top level
      * single target: ``ast.Name`` whose ``id`` matches ``_?[A-Z][A-Z0-9_]*``
      * value is ``ast.Tuple``/``ast.List``/``ast.Set``/``ast.Dict``
        OR ``ast.Call(func=Name('frozenset'|'set'|'tuple'|'list'))``

    For each qualifying container we walk every string ``ast.Constant`` and
    add the inclusive ``lineno..end_lineno`` range to the returned frozenset.

    Syntax-invalid sources return an empty frozenset (fail-open to avoid
    suppressing real findings on broken files).
    """
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return frozenset()

    out: set[int] = set()

    def _string_literal_lines(value: ast.AST) -> None:
        for sub in ast.walk(value):
            if isinstance(sub, ast.Constant) and isinstance(sub.value, str):
                start = int(getattr(sub, "lineno", 0) or 0)
                end = int(getattr(sub, "end_lineno", start) or start)
                if start <= 0:
                    continue
                for ln in range(start, end + 1):
                    out.add(ln)

    def _is_container_literal(value: ast.AST) -> bool:
        if isinstance(value, (ast.Tuple, ast.List, ast.Set, ast.Dict)):
            return True
        if isinstance(value, ast.Call) and isinstance(value.func, ast.Name):
            if value.func.id in ("frozenset", "set", "tuple", "list"):
                return True
        return False

    for node in ast.iter_child_nodes(tree):
        if isinstance(node, ast.Assign):
            if len(node.targets) != 1:
                continue
            target = node.targets[0]
            if not isinstance(target, ast.Name):
                continue
            if not _UPPER_NAME_RE.match(target.id):
                continue
            if _is_container_literal(node.value):
                _string_literal_lines(node.value)
            continue

        if isinstance(node, ast.AnnAssign):
            target = node.target
            if not isinstance(target, ast.Name):
                continue
            if not _UPPER_NAME_RE.match(target.id):
                continue
            if node.value is not None and _is_container_literal(node.value):
                _string_literal_lines(node.value)
            continue

    return frozenset(out)


def is_section_header_comment(line: str) -> bool:
    """F14c sub-fix 2: return True if ``line`` looks like a visual section
    separator comment.

    Matches::

        # --- section ---
        # === Legacy Debt (C53) ===
        # -- legacy_debt (C53) --
        # ----- DEBUG -----
        # end ---

    Regular prose comments (``# this is a normal comment.``) do NOT match.
    """
    if not line:
        return False
    return bool(_SECTION_HEADER_COMMENT_RE.match(line))


def is_cli_surface_file(file_path: str) -> bool:
    """F14c sub-fix 3: return True if ``file_path`` is a user-facing CLI
    surface where ``print()`` is legitimate.

    Covers:
      * Anything under ``INTERFACE/cli/``
      * ``BRAIN/autoforensics/self_audit.py`` and
        ``BRAIN/autoforensics/cli_forensic_audit.py`` (CLI entrypoints for
        the autoforensics subsystem).
    """
    if not file_path:
        return False
    normalized = file_path.replace("\\", "/").lstrip("./")
    for hub in _CLI_SURFACE_FILE_EXACT:
        if normalized == hub or normalized.endswith("/" + hub):
            return True
    for prefix in _CLI_SURFACE_FILE_PREFIXES:
        if prefix in normalized:
            return True
    for suffix in _CLI_SURFACE_FILE_SUFFIXES:
        if normalized.endswith(suffix) or normalized == suffix.lstrip("/"):
            return True
    return False


def collect_main_block_line_ranges(source: str) -> list[tuple[int, int]]:
    """F14c sub-fix 3: return inclusive line ranges covered by
    ``if __name__ == "__main__":`` blocks at module top level, plus
    conventionally-named CLI entrypoint functions (``main``, ``cli_main``,
    ``run``, ``_cli_*`` etc.).

    ``print()`` inside any of these ranges is legitimate CLI output.

    Fail-open: syntax errors return ``[]``.
    """
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return []

    ranges: list[tuple[int, int]] = []

    def _is_main_guard(node: ast.AST) -> bool:
        if not isinstance(node, ast.If):
            return False
        test = node.test
        if not isinstance(test, ast.Compare):
            return False
        if len(test.ops) != 1 or not isinstance(test.ops[0], ast.Eq):
            return False
        left = test.left
        right = test.comparators[0]

        def _is_name(n: ast.AST) -> bool:
            return isinstance(n, ast.Name) and n.id == "__name__"

        def _is_main_const(n: ast.AST) -> bool:
            return isinstance(n, ast.Constant) and n.value == "__main__"

        return (_is_name(left) and _is_main_const(right)) or (
            _is_name(right) and _is_main_const(left)
        )

    for node in ast.iter_child_nodes(tree):
        if _is_main_guard(node):
            start = int(getattr(node, "lineno", 0) or 0)
            end = int(getattr(node, "end_lineno", start) or start)
            if start > 0:
                ranges.append((start, end))
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            if node.name in _CLI_FUNC_NAMES or node.name.startswith("_cli_"):
                start = int(getattr(node, "lineno", 0) or 0)
                end = int(getattr(node, "end_lineno", start) or start)
                if start > 0:
                    ranges.append((start, end))

    return ranges


def line_in_ranges(
    line_num: int,
    ranges: list[tuple[int, int]] | tuple[tuple[int, int], ...],
) -> bool:
    """F14c helper: return True if ``line_num`` falls within any inclusive
    ``(start, end)`` range in ``ranges``.
    """
    for start, end in ranges:
        if start <= line_num <= end:
            return True
    return False
