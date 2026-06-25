"""Async correctness, debug prints, commented-out code, HTTP response checks.
Clusters 39-43.

Clusters:
  39 - Broad Catch + Log Without Reraise
  40 - Debug Prints in Production
  41 - Commented-Out Code Blocks
  42 - Missing Await / Unawaited Coroutines
  43 - API Response Without Status Check
"""
from __future__ import annotations

from .core import detect_language
from .exception_boundary import _extract_except_body
from ...gate_models import (
    EvidenceReference,
    GateCategory,
    GateFinding,
    GateImpact,
    GateSeverity,
    RepairKind,
)
from ..common import (
    build_finding,
    collect_constant_container_literal_lines,
    collect_main_block_line_ranges,
    is_cli_surface_file,
    line_in_ranges,
)
from .._ast_helpers import collect_string_constant_line_ranges
import logging
_log = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Cluster 39: Broad Catch + Log Without Reraise
# ---------------------------------------------------------------------------


def assess_broad_catch_no_reraise(
    file_path: str,
    content: str,
) -> list[GateFinding]:
    """Cluster 39: Detect except Exception/BaseException with log-only (no reraise)."""
    import re

    if not content.strip():
        return []

    lang = detect_language(file_path)
    basename = file_path.replace("\\", "/").rsplit("/", 1)[-1] if "/" in file_path.replace("\\", "/") else file_path
    if basename.startswith("test_") or basename.startswith("conftest"):
        return []

    findings: list[GateFinding] = []

    if lang == "python":
        lines = content.splitlines()
        for i, line in enumerate(lines):
            stripped = line.strip()
            if re.match(r'^except\s+(Exception|BaseException)(\s+as\s+\w+)?\s*:', stripped):
                body = _extract_except_body(lines, i)
                body_lines = [l.strip() for l in body.splitlines() if l.strip()]
                if not body_lines:
                    continue
                has_raise = any(l.startswith("raise") for l in body_lines)
                has_return = any(l.startswith("return ") for l in body_lines)
                if has_raise or has_return:
                    continue
                is_log_only = all(
                    l.startswith(("log", "logger", "logging", "print(", "#", "warnings.warn", "traceback"))  # noqa: debug_print_scan  # gate pattern reference, not a production print call
                    for l in body_lines
                )
                if is_log_only:
                    exc_m = re.match(r'^except\s+(\w+)', stripped)
                    exc_type = exc_m.group(1) if exc_m else "Exception"
                    detail = f"`except {exc_type}` logs but doesn't reraise (line {i + 1}) -- error silently consumed"
                    findings.append(build_finding(
                        check_id="broad_catch_scan",
                        category=GateCategory.RUNTIME_BEHAVIOR,
                        title=f"[broad_catch_no_reraise] {file_path}:{i + 1}",
                        severity=GateSeverity.HIGH,
                        impact=GateImpact.REVISE,
                        summary=detail,
                        recommendation="Add `raise` after logging, or use `logger.exception()` and reraise.",
                        evidence=(EvidenceReference(kind="probe", path=file_path, detail=detail, ok=False),),
                        repair_kind=RepairKind.REPLACE_WITH_FAIL_LOUD.value,
                        executor_action=f"Fix broad catch without reraise at {file_path}:{i + 1}",
                    ))
            if len(findings) >= 10:
                break

    elif lang in ("javascript", "typescript"):
        lines = content.splitlines()
        for i, line in enumerate(lines):
            stripped = line.strip()
            if re.match(r'^catch\s*\(', stripped) or stripped == "catch {":
                body_lines = []
                indent = len(line) - len(line.lstrip())
                for j in range(i + 1, min(i + 15, len(lines))):
                    bl = lines[j]
                    if not bl.strip():
                        continue
                    bl_indent = len(bl) - len(bl.lstrip())
                    if bl_indent <= indent and bl.strip() not in ("}",):
                        break
                    body_lines.append(bl.strip())
                has_throw = any(l.startswith("throw") for l in body_lines)
                if has_throw:
                    continue
                is_log_only = all(
                    l.startswith(("console.", "//", "}")) or not l
                    for l in body_lines
                )
                if is_log_only and any(l.startswith("console.") for l in body_lines):
                    detail = f"catch block logs but doesn't rethrow (line {i + 1})"
                    findings.append(build_finding(
                        check_id="broad_catch_scan",
                        category=GateCategory.RUNTIME_BEHAVIOR,
                        title=f"[broad_catch_no_reraise] {file_path}:{i + 1}",
                        severity=GateSeverity.HIGH,
                        impact=GateImpact.REVISE,
                        summary=detail,
                        recommendation="Add `throw err` after logging to propagate the error.",
                        evidence=(EvidenceReference(kind="probe", path=file_path, detail=detail, ok=False),),
                        repair_kind=RepairKind.REPLACE_WITH_FAIL_LOUD.value,
                        executor_action=f"Fix broad catch without rethrow at {file_path}:{i + 1}",
                    ))
            if len(findings) >= 10:
                break

    elif lang == "java":
        lines = content.splitlines()
        for i, line in enumerate(lines):
            stripped = line.strip()
            if re.match(r'^catch\s*\(\s*(Exception|Throwable|RuntimeException)\s+', stripped):
                body_lines = []
                indent = len(line) - len(line.lstrip())
                for j in range(i + 1, min(i + 15, len(lines))):
                    bl = lines[j]
                    if not bl.strip():
                        continue
                    bl_indent = len(bl) - len(bl.lstrip())
                    if bl_indent <= indent and bl.strip() not in ("}",):
                        break
                    body_lines.append(bl.strip())
                has_throw = any(l.startswith("throw") for l in body_lines)
                if has_throw:
                    continue
                is_log_only = all(
                    l.startswith(("log", "logger", "System.err", "System.out", "e.print", "//", "}")) or not l
                    for l in body_lines
                )
                if is_log_only and len(body_lines) > 0:
                    detail = f"Broad catch logs but doesn't rethrow (line {i + 1})"
                    findings.append(build_finding(
                        check_id="broad_catch_scan",
                        category=GateCategory.RUNTIME_BEHAVIOR,
                        title=f"[broad_catch_no_reraise] {file_path}:{i + 1}",
                        severity=GateSeverity.HIGH,
                        impact=GateImpact.REVISE,
                        summary=detail,
                        recommendation="Add `throw` after logging to propagate the exception.",
                        evidence=(EvidenceReference(kind="probe", path=file_path, detail=detail, ok=False),),
                        repair_kind=RepairKind.REPLACE_WITH_FAIL_LOUD.value,
                        executor_action=f"Fix broad catch without rethrow at {file_path}:{i + 1}",
                    ))
            if len(findings) >= 10:
                break

    return findings


# ---------------------------------------------------------------------------
# Cluster 40: Debug Prints in Production
# ---------------------------------------------------------------------------

_DEBUG_PRINT_PATTERNS: dict[str, list[str]] = {
    "python": [r'\bprint\s*\('],
    "javascript": [r'\bconsole\.(log|debug|info|warn|dir|trace|table)\s*\('],
    "typescript": [r'\bconsole\.(log|debug|info|warn|dir|trace|table)\s*\('],
    "go": [r'\bfmt\.(Print|Println|Printf)\s*\('],
    "rust": [r'\b(println|dbg|eprintln)!\s*\('],
    "java": [r'\bSystem\.(out|err)\.(print|println)\s*\('],
    "kotlin": [r'\bprintln\s*\('],
    "ruby": [r'\bputs\s+', r'\bp\s+\w'],
    "php": [r'\b(var_dump|print_r|echo)\s*\('],
}


def assess_debug_prints(
    file_path: str,
    content: str,
) -> list[GateFinding]:
    """Cluster 40: Detect debug print/log statements left in production code."""
    import re

    if not content.strip():
        return []

    lang = detect_language(file_path)
    patterns = _DEBUG_PRINT_PATTERNS.get(lang)
    if not patterns:
        return []

    basename = file_path.replace("\\", "/").rsplit("/", 1)[-1] if "/" in file_path.replace("\\", "/") else file_path
    if basename.startswith("test_") or basename.startswith("conftest"):
        return []

    # Test fixture files (e.g. polyglot JS/JSX samples under fixtures/) are
    # never production code; gate should not flag them regardless of language.
    if "fixtures/" in file_path.replace("\\", "/"):
        return []

    # F14c sub-fix 3: ``print()`` is legitimate user-facing output in CLI
    # surface files (INTERFACE/cli/**, self_audit.py, cli_forensic_audit.py).
    # Skip the entire file for Python CLI surfaces.
    if lang == "python" and is_cli_surface_file(file_path):
        return []

    # F14c sub-fix 3: also skip ``print()`` calls that live inside a
    # ``if __name__ == "__main__":`` guard or a conventionally-named CLI
    # entrypoint function (``main`` / ``cli_main`` / ``run`` / ``_cli_*``).
    # AST-derived inclusive line ranges.
    main_ranges: list[tuple[int, int]] = []
    # F14c extra: skip interior lines of multi-line string constants
    # (docstrings that *describe* ``print()`` patterns, regex pattern tuples
    # that contain the substring ``print(``).
    string_literal_lines: frozenset[int] = frozenset()
    # F14c sub-fix 1 (applied to debug_prints too): skip string literals
    # inside UPPER_CASE module-level container assignments such as
    # ``_TEXTUAL_STDOUT_SINKS = ("print(", "console.log(", ...)`` so the
    # gate doesn't self-match on its own pattern definitions.
    container_lines: frozenset[int] = frozenset()
    if lang == "python":
        main_ranges = collect_main_block_line_ranges(content)
        string_literal_lines = collect_string_constant_line_ranges(content)
        container_lines = collect_constant_container_literal_lines(content)

    findings: list[GateFinding] = []

    for i, line in enumerate(content.splitlines(), 1):
        stripped = line.strip()
        if stripped.startswith("#") or stripped.startswith("//") or stripped.startswith("*"):
            continue
        if lang == "python":
            if '__name__' in stripped and '__main__' in stripped:
                continue
            if 'help=' in stripped or 'parser.add' in stripped:
                continue
            # F14c sub-fix 3: skip lines inside main-guard / CLI-entrypoint
            # AST ranges.
            if main_ranges and line_in_ranges(i, main_ranges):
                continue
            # F14c extra: skip lines inside multi-line string constants.
            if i in string_literal_lines:
                continue
            # F14c sub-fix 1: skip UPPER_CASE container literal lines.
            if i in container_lines:
                continue

        for pat in patterns:
            if re.search(pat, stripped):
                detail = f"Debug print in production code (line {i}): {stripped[:60]}"
                findings.append(build_finding(
                    check_id="debug_print_scan",
                    category=GateCategory.DRIFT,
                    title=f"[debug_prints] {file_path}:{i}",
                    severity=GateSeverity.LOW,
                    impact=GateImpact.WARN,
                    summary=detail,
                    recommendation="Remove debug print or replace with proper logging.",
                    evidence=(EvidenceReference(kind="probe", path=file_path, detail=detail, ok=False),),
                    repair_kind=RepairKind.REMOVE_DUPLICATE.value,
                    executor_action=f"Remove debug print at {file_path}:{i}",
                ))
                break
        if len(findings) >= 10:
            break

    return findings


# ---------------------------------------------------------------------------
# Cluster 41: Commented-Out Code Blocks
# ---------------------------------------------------------------------------


def _collect_docstring_line_ranges(content: str) -> list[tuple[int, int]]:
    """Return list of (start_line, end_line) ranges covered by module/class/
    function docstrings. AST-based (F2 reuse).

    1-based inclusive line numbers.
    """
    import ast

    try:
        tree = ast.parse(content)
    except SyntaxError:
        return []

    ranges: list[tuple[int, int]] = []
    for node in ast.walk(tree):
        if not isinstance(
            node,
            (ast.Module, ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef),
        ):
            continue
        body = getattr(node, "body", None)
        if not body:
            continue
        first = body[0]
        if (
            isinstance(first, ast.Expr)
            and isinstance(first.value, ast.Constant)
            and isinstance(first.value.value, str)
        ):
            start = first.lineno
            end = getattr(first, "end_lineno", start) or start
            ranges.append((start, end))
    return ranges


# F9d: audit-trail allowlist markers. If a commented-code block is preceded
# within 3 lines by one of these markers, skip the finding.
_AUDIT_TRAIL_MARKERS: tuple[str, ...] = (
    "# ALLOWLIST_AUDIT_TRAIL",
    "# AUDIT_TRAIL:",
)

# F9d: commented-code blocks longer than this threshold are likely preserved
# spec / algorithm documentation and are skipped to avoid false positives.
_COMMENTED_CODE_LONG_BLOCK_THRESHOLD = 10


def assess_commented_code(
    file_path: str,
    content: str,
) -> list[GateFinding]:
    """Cluster 41: Detect blocks of commented-out code (3+ consecutive lines).

    F9d: skip blocks that (a) are preceded by a `# ALLOWLIST_AUDIT_TRAIL` /
    `# AUDIT_TRAIL:` marker within 3 lines, (b) are located inside a docstring
    (AST-based), or (c) are longer than 10 consecutive commented lines
    (preserved spec text).
    """
    import re

    if not content.strip():
        return []

    lang = detect_language(file_path)
    if lang in ("json", "yaml", "toml", "markdown", "restructuredtext"):
        return []

    if lang == "python":
        comment_re = re.compile(r'^\s*#\s?(.*)')
    elif lang in ("shell", "ruby", "php"):
        comment_re = re.compile(r'^\s*#\s?(.*)')
    else:
        comment_re = re.compile(r'^\s*//\s?(.*)')

    code_indicators = re.compile(
        r'(?:'
        r'\w+\s*=\s*\w'
        r'|def\s+\w+\s*\('
        r'|class\s+\w+'
        r'|function\s+\w+'
        r'|return\s+\w'
        r'|if\s+\w.*:'
        r'|if\s*\(.*\)\s*\{'
        r'|for\s+\w'
        r'|while\s+\w'
        r'|import\s+\w'
        r'|from\s+\w+\s+import'
        r'|\w+\.\w+\s*\('
        r'|raise\s+\w'
        r'|throw\s+\w'
        r'|except\s+\w'
        r'|catch\s*\('
        r'|try\s*[:{]'
        r')'
    )

    lines = content.splitlines()
    # F9d: AST docstring ranges (only meaningful for Python).
    docstring_ranges: list[tuple[int, int]] = []
    if lang == "python":
        docstring_ranges = _collect_docstring_line_ranges(content)

    def _line_in_docstring(lineno_1based: int) -> bool:
        return any(s <= lineno_1based <= e for s, e in docstring_ranges)

    def _has_audit_trail_marker_above(block_start_idx: int, block_end_idx: int) -> bool:
        # block_start_idx is 0-based. Check up to 3 preceding non-blank lines
        # AND the first 3 lines of the block itself (since the marker is
        # typically placed as the first comment of a preserved block).
        def _line_has_marker(line_text: str) -> bool:
            stripped = line_text.strip()
            if not stripped:
                return False
            for marker in _AUDIT_TRAIL_MARKERS:
                if marker in stripped:
                    return True
            return False

        # Check block's own first 3 lines.
        for idx in range(block_start_idx, min(block_start_idx + 3, block_end_idx)):
            if _line_has_marker(lines[idx]):
                return True

        # Check up to 3 preceding non-blank lines.
        inspected = 0
        j = block_start_idx - 1
        while j >= 0 and inspected < 3:
            ln = lines[j].strip()
            if not ln:
                j -= 1
                continue
            inspected += 1
            if _line_has_marker(lines[j]):
                return True
            j -= 1
        return False

    findings: list[GateFinding] = []
    i = 0

    while i < len(lines):
        m = comment_re.match(lines[i])
        if m:
            block_start = i
            code_lines = 0
            j = i
            while j < len(lines):
                cm = comment_re.match(lines[j])
                if not cm:
                    break
                body = cm.group(1)
                if code_indicators.search(body):
                    code_lines += 1
                j += 1
            block_len = j - block_start

            if block_len >= 3 and code_lines >= 2:
                if block_start < 4:
                    i = j
                    continue
                # F9d: audit-trail marker allowlist
                if _has_audit_trail_marker_above(block_start, j):
                    i = j
                    continue
                # F9d: docstring skip (block fully inside a docstring range)
                if _line_in_docstring(block_start + 1):
                    i = j
                    continue
                # F9d: long-block skip (likely preserved algorithm doc)
                if block_len > _COMMENTED_CODE_LONG_BLOCK_THRESHOLD:
                    i = j
                    continue
                detail = f"Block of {block_len} commented-out code lines starting at line {block_start + 1}"
                findings.append(build_finding(
                    check_id="commented_code_scan",
                    category=GateCategory.DRIFT,
                    title=f"[commented_code] {file_path}:{block_start + 1}",
                    severity=GateSeverity.LOW,
                    impact=GateImpact.WARN,
                    summary=detail,
                    recommendation="Remove commented-out code; use version control to recover old code if needed.",
                    evidence=(EvidenceReference(kind="probe", path=file_path, detail=detail, ok=False),),
                    repair_kind=RepairKind.REMOVE_DUPLICATE.value,
                    executor_action=f"Remove commented-out code block at {file_path}:{block_start + 1}",
                ))
            i = j
        else:
            i += 1
        if len(findings) >= 10:
            break

    return findings


# ---------------------------------------------------------------------------
# Cluster 42: Missing Await / Unawaited Coroutines
# ---------------------------------------------------------------------------


def _build_missing_await_findings_ast(
    file_path: str,
    content: str,
) -> list[GateFinding]:
    """AST-based missing-await detection for Python.

    Algorithm:
    1. Parse module into AST.
    2. Collect all names defined with `async def` in the module (not just
       reachable — a name defined both as sync and async triggers a
       name-collision skip for that name).
    3. Pre-pass: build an "async-reachable" set of sync function names that
       are clearly invoked under an async runtime (`asyncio.run(...)`,
       `asyncio.gather(...)`, `asyncio.ensure_future(...)`,
       `asyncio.create_task(...)`, `loop.run_until_complete(...)`) or
       decorated with `@pytest.mark.asyncio`, `@asyncio.coroutine`,
       `@async_timeout`. These sync defs behave like async contexts — closure
       depth 1 only (no transitive resolution to avoid FP).
    4. Walk every ast.Call node; for each call whose callee name matches an
       async def:
       a. Walk up the parent chain to find the nearest enclosing function.
       b. If enclosing function is ast.AsyncFunctionDef: require ast.Await
          wrapper. Missing wrapper → real finding.
       c. If enclosing function is ast.FunctionDef AND its name is in the
          async-reachable set: treat like async context → emit finding.
       d. If enclosing function is ast.FunctionDef (sync) and NOT reachable:
          conservative skip (assume legitimate sync wrapper: thread executor
          / deliberate fire-and-forget / pure sync call that happens to
          share a name).
       e. If no enclosing function (module-level call): also skip (likely
          asyncio.run(main()) at script entry point).
    5. Pointless-async detection: async def that never contains await /
       async for / async with in its body. Stubs (pass / ... /
       raise NotImplementedError) are exempt.

    Skip heuristics applied:
    - Names with both `def X` and `async def X` → name collision, skip.
    - Inside TYPE_CHECKING blocks.
    - Inside @pytest.mark.asyncio decorated functions (treated like async
      context for flag purposes, but those are already AsyncFunctionDef).
    """
    import ast

    try:
        tree = ast.parse(content)
    except SyntaxError:
        return []

    findings: list[GateFinding] = []

    # ------------------------------------------------------------------
    # Step 1: collect async def names and detect name collisions
    # ------------------------------------------------------------------
    async_names: set[str] = set()
    sync_names: set[str] = set()

    for node in ast.walk(tree):
        if isinstance(node, ast.AsyncFunctionDef):
            async_names.add(node.name)
        elif isinstance(node, ast.FunctionDef):
            sync_names.add(node.name)

    # Names that exist as BOTH sync and async — ambiguous, skip entirely
    collision_names = async_names & sync_names

    # ------------------------------------------------------------------
    # Step 1b: async-reachability pre-pass
    #   - Sync `def` targets of asyncio.run / gather / ensure_future /
    #     create_task / loop.run_until_complete are treated as async context.
    #   - Sync defs decorated with @pytest.mark.asyncio, @asyncio.coroutine,
    #     @async_timeout also qualify.
    #   - Closure depth 1 only (no transitive resolution).
    # ------------------------------------------------------------------
    _ASYNC_RUNNER_ATTRS = {
        "run",
        "gather",
        "ensure_future",
        "create_task",
        "run_until_complete",
        "run_coroutine_threadsafe",
    }
    _ASYNC_RUNNER_BARE = {"gather", "ensure_future", "create_task"}
    _ASYNC_DECO_NAMES = {"asyncio.coroutine", "async_timeout"}
    _ASYNC_DECO_PYTEST_ATTR = "asyncio"  # for @pytest.mark.asyncio

    def _arg_callee_name(arg: ast.AST) -> str | None:
        """Extract simple name from a call-arg that is either Name or Call(Name)."""
        if isinstance(arg, ast.Call):
            func = arg.func
            if isinstance(func, ast.Name):
                return func.id
            if isinstance(func, ast.Attribute):
                return func.attr
            return None
        if isinstance(arg, ast.Name):
            return arg.id
        if isinstance(arg, ast.Attribute):
            return arg.attr
        return None

    def _is_async_runner_call(call: ast.Call) -> bool:
        func = call.func
        if isinstance(func, ast.Attribute) and func.attr in _ASYNC_RUNNER_ATTRS:
            return True
        if isinstance(func, ast.Name) and func.id in _ASYNC_RUNNER_BARE:
            # bare `gather(x())` / `create_task(x())` after `from asyncio import ...`
            return True
        return False

    def _decorator_marks_async(dec: ast.AST) -> bool:
        # @asyncio.coroutine / @async_timeout / @pytest.mark.asyncio
        if isinstance(dec, ast.Call):
            dec = dec.func
        if isinstance(dec, ast.Name):
            return dec.id == "async_timeout"
        if isinstance(dec, ast.Attribute):
            # @asyncio.coroutine
            if isinstance(dec.value, ast.Name) and dec.value.id == "asyncio" and dec.attr == "coroutine":
                return True
            # @async_timeout.timeout — also async scope
            if isinstance(dec.value, ast.Name) and dec.value.id == "async_timeout":
                return True
            # @pytest.mark.asyncio  (Attribute: value=Attribute(pytest, mark), attr=asyncio)
            if dec.attr == _ASYNC_DECO_PYTEST_ATTR:
                inner = dec.value
                if isinstance(inner, ast.Attribute) and inner.attr == "mark":
                    if isinstance(inner.value, ast.Name) and inner.value.id == "pytest":
                        return True
        return False

    async_reachable_syncs: set[str] = set()

    # Decorator-driven reachability
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef):
            for dec in node.decorator_list:
                if _decorator_marks_async(dec):
                    async_reachable_syncs.add(node.name)
                    break

    # Runner-argument-driven reachability
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        if not _is_async_runner_call(node):
            continue
        for arg in list(node.args) + [kw.value for kw in node.keywords]:
            name = _arg_callee_name(arg)
            if name is None:
                continue
            # Only promote to "reachable" if this name is defined as a sync def
            # in THIS module (closure depth 1). Async defs need no promotion.
            if name in sync_names and name not in async_names:
                async_reachable_syncs.add(name)

    if not async_names:
        return []

    # ------------------------------------------------------------------
    # Step 2: detect TYPE_CHECKING blocks to exclude their contents
    # ------------------------------------------------------------------
    # Collect line ranges that are inside `if TYPE_CHECKING:` guards.
    type_checking_ranges: list[tuple[int, int]] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.If):
            test = node.test
            is_tc = (
                (isinstance(test, ast.Name) and test.id == "TYPE_CHECKING")
                or (isinstance(test, ast.Attribute) and test.attr == "TYPE_CHECKING")
            )
            if is_tc and hasattr(node, "lineno") and hasattr(node, "end_lineno"):
                type_checking_ranges.append((node.lineno, node.end_lineno or node.lineno))

    def _in_type_checking(lineno: int) -> bool:
        return any(start <= lineno <= end for start, end in type_checking_ranges)

    # ------------------------------------------------------------------
    # Step 3: build parent map for ancestor walking
    # ------------------------------------------------------------------
    parent_map: dict[int, ast.AST] = {}
    for node in ast.walk(tree):
        for child in ast.iter_child_nodes(node):
            parent_map[id(child)] = node

    def _get_enclosing_func(node: ast.AST) -> ast.AsyncFunctionDef | ast.FunctionDef | None:
        """Walk parent chain, return nearest enclosing function def or None."""
        current = parent_map.get(id(node))
        while current is not None:
            if isinstance(current, (ast.AsyncFunctionDef, ast.FunctionDef)):
                return current
            current = parent_map.get(id(current))
        return None

    def _is_directly_awaited(call_node: ast.Call) -> bool:
        """Return True if the Call node is the direct expression of an Await."""
        parent = parent_map.get(id(call_node))
        return isinstance(parent, ast.Await)

    def _is_asyncio_run_call(call_node: ast.Call) -> bool:
        """Return True if this call is the argument to asyncio.run() or
        loop.run_until_complete() in the same statement."""
        parent = parent_map.get(id(call_node))
        if not isinstance(parent, ast.Call):
            return False
        func = parent.func
        if isinstance(func, ast.Attribute):
            if func.attr in ("run", "run_until_complete", "run_coroutine_threadsafe"):
                return True
        if isinstance(func, ast.Name) and func.id == "run":
            return True
        return False

    def _callee_name(call_node: ast.Call) -> str | None:
        """Extract simple name from a Call node's func field."""
        func = call_node.func
        if isinstance(func, ast.Name):
            return func.id
        if isinstance(func, ast.Attribute):
            return func.attr
        return None

    # ------------------------------------------------------------------
    # Step 4: walk all Call nodes; flag un-awaited calls to async funcs
    #         inside async context
    # ------------------------------------------------------------------
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        if not hasattr(node, "lineno"):
            continue
        if _in_type_checking(node.lineno):
            continue

        name = _callee_name(node)
        if name is None or name not in async_names or name in collision_names:
            continue

        # Skip if already awaited
        if _is_directly_awaited(node):
            continue

        # Skip if passed into asyncio.run() / run_until_complete() etc.
        if _is_asyncio_run_call(node):
            continue

        enclosing = _get_enclosing_func(node)

        if enclosing is None:
            # Module-level call — conservative skip (likely asyncio.run(main()))
            continue

        if isinstance(enclosing, ast.FunctionDef):
            # Sync enclosing function. Only treat as async context if this
            # sync def is in the async-reachable set (closure depth 1:
            # invoked under asyncio.run/gather/ensure_future/create_task/
            # run_until_complete OR decorated with @pytest.mark.asyncio,
            # @asyncio.coroutine, @async_timeout). Otherwise keep
            # conservative skip.
            if enclosing.name not in async_reachable_syncs:
                continue
            # Fall through → emit finding (sync def runs in async context).

        # enclosing is AsyncFunctionDef (or async-reachable sync) and call is
        # NOT awaited → real bug
        lineno = node.lineno
        if len(findings) >= 10:
            break
        detail = f"Async function '{name}()' called without `await` (line {lineno})"
        findings.append(build_finding(
            check_id="missing_await_scan",
            category=GateCategory.RUNTIME_BEHAVIOR,
            title=f"[missing_await] {file_path}:{lineno}",
            severity=GateSeverity.HIGH,
            impact=GateImpact.REVISE,
            summary=detail,
            recommendation=f"Add `await` before calling `{name}()` inside an async context.",
            evidence=(EvidenceReference(kind="probe", path=file_path, detail=detail, ok=False),),
            repair_kind=RepairKind.FIX_CONTRACT.value,
            executor_action=f"Add missing await at {file_path}:{lineno}",
        ))

    # ------------------------------------------------------------------
    # Step 5: pointless-async detection (unchanged logic, regex-free)
    # ------------------------------------------------------------------
    for node in ast.walk(tree):
        if not isinstance(node, ast.AsyncFunctionDef):
            continue
        # Check body for any await / async for / async with
        has_await = False
        for child in ast.walk(node):
            if child is node:
                continue
            if isinstance(child, (ast.Await, ast.AsyncFor, ast.AsyncWith)):
                has_await = True
                break
        if has_await:
            continue
        # Exempt stubs
        body_nodes = node.body
        if len(body_nodes) == 1:
            stmt = body_nodes[0]
            if isinstance(stmt, ast.Pass):
                continue
            if isinstance(stmt, ast.Expr) and isinstance(stmt.value, ast.Constant):
                if stmt.value.value is ...:
                    continue
            if isinstance(stmt, ast.Raise):
                continue
        lineno = node.lineno
        func_name = node.name
        detail = f"async def {func_name}() never uses await -- pointless async"
        findings.append(build_finding(
            check_id="missing_await_scan",
            category=GateCategory.RUNTIME_BEHAVIOR,
            title=f"[missing_await] {file_path}:{lineno}:{func_name}",
            severity=GateSeverity.LOW,
            impact=GateImpact.WARN,
            summary=detail,
            recommendation=f"Remove `async` from `{func_name}()` if it doesn't need to be async.",
            evidence=(EvidenceReference(kind="probe", path=file_path, detail=detail, ok=False),),
            repair_kind=RepairKind.FIX_CONTRACT.value,
            executor_action=f"Remove pointless async from {func_name}() at {file_path}:{lineno}",
        ))

    return findings


def assess_missing_await(
    file_path: str,
    content: str,
) -> list[GateFinding]:
    """Cluster 42: Detect async calls without await and pointless async functions."""
    import re

    if not content.strip():
        return []

    lang = detect_language(file_path)
    if lang not in ("python", "javascript", "typescript"):
        return []

    findings: list[GateFinding] = []

    if lang == "python":
        findings = _build_missing_await_findings_ast(file_path, content)

    elif lang in ("javascript", "typescript"):
        for i, line in enumerate(content.splitlines(), 1):
            stripped = line.strip()
            if stripped.startswith("//"):
                continue
            if re.search(r'\bfetch\s*\(', stripped) and "await" not in stripped:
                if ".then(" not in stripped:
                    detail = f"fetch() called without `await` or `.then()` (line {i})"
                    findings.append(build_finding(
                        check_id="missing_await_scan",
                        category=GateCategory.RUNTIME_BEHAVIOR,
                        title=f"[missing_await] {file_path}:{i}",
                        severity=GateSeverity.HIGH,
                        impact=GateImpact.REVISE,
                        summary=detail,
                        recommendation="Add `await` before `fetch()` or chain `.then()` to handle the promise.",
                        evidence=(EvidenceReference(kind="probe", path=file_path, detail=detail, ok=False),),
                        repair_kind=RepairKind.FIX_CONTRACT.value,
                        executor_action=f"Add missing await/then at {file_path}:{i}",
                    ))
            if len(findings) >= 10:
                break

    return findings


# ---------------------------------------------------------------------------
# Cluster 43: API Response Without Status Check
# ---------------------------------------------------------------------------


def assess_unchecked_response(
    file_path: str,
    content: str,
) -> list[GateFinding]:
    """Cluster 43: Detect HTTP responses used without checking status."""
    import re

    if not content.strip():
        return []

    lang = detect_language(file_path)
    if lang not in ("python", "javascript", "typescript"):
        return []

    basename = file_path.replace("\\", "/").rsplit("/", 1)[-1] if "/" in file_path.replace("\\", "/") else file_path
    if basename.startswith("test_") or basename.startswith("conftest"):
        return []

    findings: list[GateFinding] = []
    lines = content.splitlines()

    if lang == "python":
        for i, line in enumerate(lines, 1):
            stripped = line.strip()
            if stripped.startswith("#"):
                continue
            m = re.search(r'(\w+)\s*=\s*requests\.(get|post|put|delete|patch)\s*\(', stripped)
            if m:
                var_name = m.group(1)
                has_check = False
                for j in range(i, min(i + 10, len(lines))):
                    check_line = lines[j]
                    if f"{var_name}.raise_for_status()" in check_line:
                        has_check = True
                        break
                    if f"{var_name}.status_code" in check_line:
                        has_check = True
                        break
                    if f"{var_name}.ok" in check_line:
                        has_check = True
                        break
                if not has_check:
                    detail = f"requests.{m.group(2)}() without status check (line {i}) -- use .raise_for_status()"
                    findings.append(build_finding(
                        check_id="response_status_scan",
                        category=GateCategory.RUNTIME_BEHAVIOR,
                        title=f"[unchecked_response] {file_path}:{i}",
                        severity=GateSeverity.MEDIUM,
                        impact=GateImpact.REVISE,
                        summary=detail,
                        recommendation="Call `.raise_for_status()` or check `.status_code` before using the response.",
                        evidence=(EvidenceReference(kind="probe", path=file_path, detail=detail, ok=False),),
                        repair_kind=RepairKind.ADD_BOUNDARY_CHECK.value,
                        executor_action=f"Add status check at {file_path}:{i}",
                    ))
            if re.search(r'(\w+)\s*=\s*(?:httpx\.\w+|urllib\.request\.urlopen)\s*\(', stripped):
                var_m = re.match(r'\s*(\w+)\s*=', stripped)
                if var_m:
                    var_name = var_m.group(1)
                    has_check = any(
                        f"{var_name}.status" in lines[j] or f"{var_name}.raise_for_status" in lines[j]
                        for j in range(i, min(i + 10, len(lines)))
                    )
                    if not has_check:
                        detail = f"HTTP response without status check (line {i})"
                        findings.append(build_finding(
                            check_id="response_status_scan",
                            category=GateCategory.RUNTIME_BEHAVIOR,
                            title=f"[unchecked_response] {file_path}:{i}",
                            severity=GateSeverity.MEDIUM,
                            impact=GateImpact.REVISE,
                            summary=detail,
                            recommendation="Check the response status before processing.",
                            evidence=(EvidenceReference(kind="probe", path=file_path, detail=detail, ok=False),),
                            repair_kind=RepairKind.ADD_BOUNDARY_CHECK.value,
                            executor_action=f"Add status check at {file_path}:{i}",
                        ))
            if len(findings) >= 10:
                break

    elif lang in ("javascript", "typescript"):
        for i, line in enumerate(lines, 1):
            stripped = line.strip()
            if stripped.startswith("//"):
                continue
            m = re.search(r'(\w+)\s*=\s*await\s+fetch\s*\(', stripped)
            if m:
                var_name = m.group(1)
                has_check = False
                for j in range(i, min(i + 10, len(lines))):
                    cl = lines[j]
                    if f"{var_name}.ok" in cl or f"{var_name}.status" in cl:
                        has_check = True
                        break
                    if f"!{var_name}.ok" in cl or f"{var_name}.status !==" in cl:
                        has_check = True
                        break
                if not has_check:
                    detail = f"fetch() result used without .ok/.status check (line {i})"
                    findings.append(build_finding(
                        check_id="response_status_scan",
                        category=GateCategory.RUNTIME_BEHAVIOR,
                        title=f"[unchecked_response] {file_path}:{i}",
                        severity=GateSeverity.MEDIUM,
                        impact=GateImpact.REVISE,
                        summary=detail,
                        recommendation="Check `response.ok` or `response.status` before processing the response.",
                        evidence=(EvidenceReference(kind="probe", path=file_path, detail=detail, ok=False),),
                        repair_kind=RepairKind.ADD_BOUNDARY_CHECK.value,
                        executor_action=f"Add status check at {file_path}:{i}",
                    ))
            if len(findings) >= 10:
                break

    return findings
