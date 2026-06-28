"""Code style, quality metrics, and false-positive allowlist. Clusters 21, 22, 24, 25, 26, 28, 29.

Clusters:
  21 - Magic Numbers
  22 - Error Message Quality
  24 - Naming Consistency
  25 - Secrets in Code
  26 - TODO/FIXME Tracker
  28 - Log Level Appropriateness
  29 - File Encoding Consistency

Also contains the false-positive allowlist infrastructure (AllowlistEntry,
load_allowlist, revalidate_allowlist, save_allowlist, filter_by_allowlist).
"""
from __future__ import annotations


from .core import detect_language
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
    is_section_header_comment,
)
from .._ast_helpers import collect_string_constant_line_ranges
import logging
_log = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Cluster 25: Secrets in Code
# ---------------------------------------------------------------------------


_SECRET_PATTERNS: tuple[tuple[str, str], ...] = (
    (r"(?:password|passwd|pwd)\s*=\s*['\"][^'\"]{4,}['\"]", "Hardcoded password"),
    (r"(?:api_key|apikey|api_secret)\s*=\s*['\"][^'\"]{8,}['\"]", "Hardcoded API key"),
    (r"(?:secret|token|auth)\s*=\s*['\"][A-Za-z0-9+/=]{16,}['\"]", "Hardcoded secret/token"),
    (r"sk-[a-zA-Z0-9]{20,}", "OpenAI-style API key"),
    (r"ghp_[a-zA-Z0-9]{36,}", "GitHub personal access token"),
    (r"glpat-[a-zA-Z0-9\-]{20,}", "GitLab personal access token"),
    (r"AKIA[0-9A-Z]{16}", "AWS access key ID"),
    (r"-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-----", "Private key in source"),
    (r"(?:mongodb|postgres|mysql|redis)://[^'\"\s]+:[^'\"\s]+@", "Database connection string with credentials"),
)


def assess_secrets_in_code(
    file_path: str,
    content: str,
) -> list[GateFinding]:
    """Cluster 25: Detect hardcoded secrets, API keys, and credentials in source code."""
    import re

    if not content.strip():
        return []  # NOT_APPLICABLE

    findings: list[GateFinding] = []
    for i, line in enumerate(content.splitlines(), 1):
        stripped = line.lstrip()
        if stripped.startswith("#") or stripped.startswith("//") or stripped.startswith("*"):
            continue
        if any(marker in line.lower() for marker in ("example", "placeholder", "xxx", "changeme", "your_", "test_key", "<your", "fake")):
            continue

        for pattern, description in _SECRET_PATTERNS:
            if re.search(pattern, line, re.IGNORECASE):
                findings.append(build_finding(
                    check_id="secrets_scan",
                    category=GateCategory.TRUTH_BOUNDARY,
                    title=f"[secrets_in_code] {file_path}:{i}",
                    severity=GateSeverity.CRITICAL,
                    impact=GateImpact.BLOCK,
                    summary=f"{description} (line {i})",
                    recommendation=f"Remove hardcoded secret from source. Use environment variables or a secrets manager.",
                    evidence=(EvidenceReference(kind="probe", path=file_path, detail=f"{description} (line {i})", ok=False),),
                    repair_kind=RepairKind.FIX_CONTRACT.value,
                    executor_action=f"Remove hardcoded secret at {file_path}:{i}",
                    allowlist_allowed=False,
                ))
                break  # one finding per line is enough
    return findings


# ---------------------------------------------------------------------------
# Cluster 21: Magic Numbers
# ---------------------------------------------------------------------------


_SAFE_NUMBERS = frozenset({
    0, 1, 2, 3, 4, 5, -1, -2,
    10, 100, 1000,
    200, 201, 204, 301, 302, 400, 401, 403, 404, 409, 500, 501, 503,
    60, 120, 300, 3600,
    8, 16, 32, 64, 128, 256, 512, 1024, 2048, 4096,
})

# F9f: values that are always safe, regardless of context.
_ALWAYS_SAFE_NUMBERS = frozenset({0, 1, 2, -1})

# FP-round2-B (2026-06-28): integer literals with |value| below this bound are
# treated as benign small constants (terminal widths, ASCII codes, byte values,
# small counts) and not reported. Only larger / unusual literals are flagged.
_MAGIC_INT_BOUND = 256

# F9f: comment markers that document a fixed count (e.g., "C1..C11", "11 clusters").
_DOCUMENTED_COUNT_MARKERS: tuple[str, ...] = (
    "c1..c",       # "C1..C11"
    "1..n",
    "0..n",
    "clusters",
    "documented count",
    "fixed count",
)


def _collect_constant_assignment_lines(content: str) -> set[int]:
    """F9f: return line numbers of assignments whose target is a single
    UPPER_CASE Name AND whose RHS is a simple compile-time literal.

    F9f-tighten (2026-04-23): RHS scrutiny.
    Previously ANY UPPER_CASE assignment skipped the entire line, which hid
    magic numbers inside expressions like ``FOO = compute(42)``. We now only
    skip when the RHS is a pure literal (Constant or container-of-Constants).
    If the RHS contains Call / BinOp / Name / Attribute / Subscript / Compare,
    the line stays eligible for magic-number scanning.
    """
    import ast

    try:
        tree = ast.parse(content)
    except SyntaxError:
        return set()

    lines: set[int] = set()

    def _is_const_name(name: str) -> bool:
        if not name or not name.isidentifier():
            return False
        # Allow underscore prefix (e.g. _MAX_...) and digits; must be all upper.
        stripped = name.lstrip("_")
        if not stripped:
            return False
        return stripped.upper() == stripped and any(ch.isalpha() for ch in stripped)

    def _is_pure_literal_rhs(value: ast.AST) -> bool:
        """True if *value* is a pure literal (no Call / Name / BinOp / etc.)."""
        if isinstance(value, ast.Constant):
            return True
        if isinstance(value, ast.UnaryOp) and isinstance(value.operand, ast.Constant):
            return True
        if isinstance(value, (ast.List, ast.Tuple, ast.Set)):
            return all(_is_pure_literal_rhs(e) for e in value.elts)
        if isinstance(value, ast.Dict):
            keys = [k for k in value.keys if k is not None]
            return all(_is_pure_literal_rhs(k) for k in keys) and all(
                _is_pure_literal_rhs(v) for v in value.values
            )
        return False

    for node in ast.walk(tree):
        if isinstance(node, ast.Assign):
            targets = node.targets
            if (
                len(targets) == 1
                and isinstance(targets[0], ast.Name)
                and _is_const_name(targets[0].id)
                and _is_pure_literal_rhs(node.value)
            ):
                start = node.lineno
                end = getattr(node, "end_lineno", start) or start
                for ln in range(start, end + 1):
                    lines.add(ln)
        elif isinstance(node, ast.AnnAssign):
            if (
                isinstance(node.target, ast.Name)
                and _is_const_name(node.target.id)
                and node.value is not None
                and _is_pure_literal_rhs(node.value)
            ):
                start = node.lineno
                end = getattr(node, "end_lineno", start) or start
                for ln in range(start, end + 1):
                    lines.add(ln)
    return lines


def _collect_docstring_ranges_for_magic(content: str) -> list[tuple[int, int]]:
    """F9f: docstring ranges to skip literals inside them. AST-based."""
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


def _has_documented_count_marker(lines: list[str], lineno_1based: int) -> bool:
    """F9f: look within 3 preceding non-blank lines for a comment marker
    indicating the literal is a documented count."""
    inspected = 0
    j = lineno_1based - 2  # 0-based previous line
    while j >= 0 and inspected < 3:
        ln = lines[j].strip()
        if not ln:
            j -= 1
            continue
        inspected += 1
        lowered = ln.lower()
        if lowered.startswith("#") or lowered.startswith("//"):
            for marker in _DOCUMENTED_COUNT_MARKERS:
                if marker in lowered:
                    return True
        j -= 1
    return False


def assess_magic_numbers(
    file_path: str,
    content: str,
) -> list[GateFinding]:
    """Cluster 21: Detect hardcoded numeric literals in business logic.

    F9f refinements:
      - Always skip 0, 1, 2, -1.
      - Skip literals that are the RHS of an UPPER_CASE constant assignment
        (AST-based).
      - Skip literals preceded by a `# C1..CN` / `# N clusters` / similar
        "documented count" comment marker within 3 lines.
      - Skip literals inside docstrings (AST-based).
    """
    import re

    lang = detect_language(file_path)
    if lang not in ("python", "javascript", "typescript"):
        return []  # NOT_APPLICABLE

    if not content.strip():
        return []  # NOT_APPLICABLE

    basename = file_path.replace("\\", "/").split("/")[-1]
    if basename.startswith("test_") or basename.startswith("conftest"):
        return []  # NOT_APPLICABLE

    # F9f AST pre-pass (Python only — JS/TS fall back to heuristics).
    const_assign_lines: set[int] = set()
    docstring_ranges: list[tuple[int, int]] = []
    if lang == "python":
        const_assign_lines = _collect_constant_assignment_lines(content)
        docstring_ranges = _collect_docstring_ranges_for_magic(content)

    def _in_docstring(lineno_1based: int) -> bool:
        return any(s <= lineno_1based <= e for s, e in docstring_ranges)

    all_lines = content.splitlines()

    findings: list[GateFinding] = []
    for i, line in enumerate(all_lines, 1):
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or stripped.startswith("//"):
            continue
        # F9f-tighten (2026-04-23): the old regex ``^[A-Z_]+\s*[=:]`` skipped
        # any UPPER-prefixed assignment unconditionally. For Python we now
        # defer to the AST pre-pass (``const_assign_lines``) which is precise
        # about RHS shape. For JS/TS we keep the legacy regex as a
        # best-effort heuristic (no AST pre-pass available).
        if lang != "python" and re.match(r"^[A-Z_][A-Z_0-9]*\s*[=:]", stripped):
            continue
        if stripped.startswith(("import ", "from ", "@", '"""', "'''")):
            continue
        if stripped.startswith(("'", '"', 'f"', "f'", 'b"', "b'", 'r"', "r'")):
            continue

        # F9f: line inside docstring range → skip entirely.
        if _in_docstring(i):
            continue

        # F9f: line is part of an UPPER_CASE constant assignment → skip.
        if i in const_assign_lines:
            continue

        # F9f: documented count marker in preceding 3 lines → skip line.
        if _has_documented_count_marker(all_lines, i):
            continue

        for m in re.finditer(r"\b(\d+(?:\.\d+)?)\b", line):
            try:
                val = float(m.group(1))
                int_val = int(val) if val == int(val) else None
            except (ValueError, OverflowError):
                continue

            # F9f: 0, 1, 2, -1 always skipped.
            if int_val is not None and int_val in _ALWAYS_SAFE_NUMBERS:
                continue

            if int_val is not None and int_val in _SAFE_NUMBERS:
                continue
            # FP-round2-B (2026-06-28): raise the small-int suppression bound.
            # On real codebases the vast majority of bare small integers are
            # benign (terminal widths like 24/80, ASCII control codes like 127,
            # byte values, small column/limit counts like 11/12/20/50). The
            # old window was only -10..10, which flagged every such value as a
            # "magic number" and dominated the noise on click/mcp/filelock.
            # We now suppress |int| < _MAGIC_INT_BOUND (256). Genuinely unusual
            # magic constants (timeouts in seconds like 86400, bit masks like
            # 65537, large sizes) are >= 256 and stay flagged. HTTP codes,
            # powers of two up to 4096, and time constants are still covered
            # explicitly by _SAFE_NUMBERS above.
            if int_val is not None and -_MAGIC_INT_BOUND < int_val < _MAGIC_INT_BOUND:
                continue
            # FP-round2-B: sub-unit floats (|x| < 1.0) are almost always benign
            # ratios / poll intervals / probabilities (e.g. 0.5, 0.1) rather
            # than load-bearing magic constants. Suppress them conservatively.
            if int_val is None:
                try:
                    if abs(val) < 1.0:
                        continue
                except (TypeError, ValueError):
                    pass
            col = m.start()
            pre = line[:col]
            if pre.count('"') % 2 == 1 or pre.count("'") % 2 == 1:
                continue
            if re.search(r"range\s*\(|enumerate\s*\(|\[\s*$", pre[-20:] if len(pre) >= 20 else pre):
                continue
            if "field(" in line or "= field(" in line:
                continue
            if re.search(r'\w+\s*=\s*' + re.escape(m.group(1)) + r'\b', line):
                continue
            # F9f-tighten (2026-04-23): narrow the bracket/colon suppression.
            # Old: ``[:N`` / ``N:`` anywhere in line — which suppressed
            # legitimate threshold checks like ``if file_count > 2000:``.
            # New: only suppress when the literal is inside an index/slice
            # expression, i.e. wrapped by ``[ ... ]`` with ``:`` adjacent.
            # Patterns that must still be suppressed:
            #   foo[42]          — subscript index
            #   foo[42:]         — open-end slice
            #   foo[:42]         — open-start slice
            #   foo[10:42]       — bounded slice
            # Pattern that MUST flag (new):
            #   if x > 2000:      — trailing colon is statement terminator
            lit = re.escape(m.group(1))
            # subscript: [...lit...] — scan for a nearest-preceding '[' and
            # a following ']' without an intervening statement boundary.
            # We keep it simple: check whether the literal is inside any
            # ``[...]`` span on this line. A Python statement never has a
            # trailing ``:`` inside brackets.
            in_brackets = False
            open_cnt = 0
            lit_start = m.start()
            lit_end = m.end()
            for k, ch in enumerate(line):
                if ch == "[":
                    open_cnt += 1
                elif ch == "]":
                    open_cnt = max(0, open_cnt - 1)
                if k == lit_start and open_cnt > 0:
                    in_brackets = True
                    break
            if in_brackets:
                continue
            # Dict-key / dict-value context: ``{42: ...}`` or ``{...: 42}``.
            # Suppress only when braces genuinely enclose the literal.
            in_braces = False
            brace_cnt = 0
            for k, ch in enumerate(line):
                if ch == "{":
                    brace_cnt += 1
                elif ch == "}":
                    brace_cnt = max(0, brace_cnt - 1)
                if k == lit_start and brace_cnt > 0:
                    in_braces = True
                    break
            if in_braces:
                continue

            findings.append(build_finding(
                check_id="magic_number_scan",
                category=GateCategory.RUNTIME_BEHAVIOR,
                title=f"[magic_numbers] {file_path}:{i}",
                severity=GateSeverity.LOW,
                impact=GateImpact.WARN,
                summary=f"Magic number {m.group(1)} at line {i} -- consider naming as a constant",
                recommendation=f"Extract magic number {m.group(1)} into a named constant.",
                evidence=(EvidenceReference(kind="probe", path=file_path, detail=f"Magic number {m.group(1)} at line {i} -- consider naming as a constant", ok=False),),
                repair_kind=RepairKind.REFACTOR.value,
                executor_action=f"Extract magic number at {file_path}:{i} into a named constant",
            ))
        if len(findings) >= 20:
            break
    return findings[:20]


# ---------------------------------------------------------------------------
# Cluster 22: Error Message Quality
# ---------------------------------------------------------------------------


def assess_error_message_quality(
    file_path: str,
    content: str,
) -> list[GateFinding]:
    """Cluster 22: Detect generic/unhelpful error messages in raise/throw statements."""
    import re

    if not content.strip():
        return []  # NOT_APPLICABLE

    basename = file_path.replace("\\", "/").split("/")[-1]
    if basename.startswith("test_"):
        return []  # NOT_APPLICABLE

    _GENERIC_MESSAGES = (
        r'raise\s+\w+Error\s*\(\s*["\'](?:error|failed|bad|invalid|wrong|oops|problem|issue)["\']',
        r'raise\s+Exception\s*\(\s*["\'][^"\']{0,10}["\']',
        r'raise\s+\w+Error\s*\(\s*\)\s*$',
        r'raise\s+Exception\s*\(\s*\)\s*$',
    )

    findings: list[GateFinding] = []
    for i, line in enumerate(content.splitlines(), 1):
        stripped = line.strip()
        if stripped.startswith("#"):
            continue
        for pattern in _GENERIC_MESSAGES:
            if re.search(pattern, stripped, re.IGNORECASE):
                findings.append(build_finding(
                    check_id="error_msg_scan",
                    category=GateCategory.REPORTING,
                    title=f"[error_message_quality] {file_path}:{i}",
                    severity=GateSeverity.LOW,
                    impact=GateImpact.WARN,
                    summary=f"Generic error message at line {i}: {stripped[:60]}",
                    recommendation="Use descriptive error messages that include context (variable values, expected vs actual).",
                    evidence=(EvidenceReference(kind="probe", path=file_path, detail=f"Generic error message at line {i}: {stripped[:60]}", ok=False),),
                    repair_kind=RepairKind.REFACTOR.value,
                    executor_action=f"Improve error message at {file_path}:{i}",
                ))
                break
    return findings


# ---------------------------------------------------------------------------
# Cluster 24: Naming Consistency
# ---------------------------------------------------------------------------


def assess_naming_consistency(
    file_path: str,
    content: str,
) -> list[GateFinding]:
    """Cluster 24: Detect mixed naming conventions (camelCase vs snake_case) in one module."""
    import re

    lang = detect_language(file_path)
    if lang not in ("python", "javascript", "typescript"):
        return []  # NOT_APPLICABLE

    if not content.strip():
        return []  # NOT_APPLICABLE

    func_names = re.findall(r"(?:^|\n)\s*def (\w+)\s*\(", content)
    if len(func_names) < 3:
        return []  # NOT_APPLICABLE

    snake = []
    camel = []
    for name in func_names:
        if name.startswith("_"):
            name = name.lstrip("_")
        if not name:
            continue
        if name == name.lower():
            snake.append(name)
        elif re.match(r"[a-z][a-zA-Z0-9]*$", name) and any(c.isupper() for c in name):
            camel.append(name)

    total = len(snake) + len(camel)
    if total == 0:
        return []  # NOT_APPLICABLE

    snake_ratio = len(snake) / total if total else 0

    findings: list[GateFinding] = []
    if snake_ratio > 0.8 and camel:
        for name in camel:
            findings.append(build_finding(
                check_id="naming_scan",
                category=GateCategory.DRIFT,
                title=f"[naming_consistency] {file_path}:{name}",
                severity=GateSeverity.LOW,
                impact=GateImpact.WARN,
                summary=f"camelCase '{name}' in snake_case-dominant module",
                recommendation="Rename to snake_case to match the dominant convention.",
                evidence=(EvidenceReference(kind="probe", path=file_path, detail=f"camelCase '{name}' in snake_case-dominant module", ok=False),),
                repair_kind=RepairKind.REFACTOR.value,
                executor_action=f"Rename '{name}' to snake_case in {file_path}",
            ))
    elif snake_ratio < 0.2 and snake:
        for name in snake[:10]:
            findings.append(build_finding(
                check_id="naming_scan",
                category=GateCategory.DRIFT,
                title=f"[naming_consistency] {file_path}:{name}",
                severity=GateSeverity.LOW,
                impact=GateImpact.WARN,
                summary=f"snake_case '{name}' in camelCase-dominant module",
                recommendation="Rename to camelCase to match the dominant convention.",
                evidence=(EvidenceReference(kind="probe", path=file_path, detail=f"snake_case '{name}' in camelCase-dominant module", ok=False),),
                repair_kind=RepairKind.REFACTOR.value,
                executor_action=f"Rename '{name}' to camelCase in {file_path}",
            ))
    elif 0.3 <= snake_ratio <= 0.7:
        findings.append(build_finding(
            check_id="naming_scan",
            category=GateCategory.DRIFT,
            title=f"[naming_consistency] {file_path}",
            severity=GateSeverity.LOW,
            impact=GateImpact.WARN,
            summary=f"Mixed naming: {len(snake)} snake_case + {len(camel)} camelCase",
            recommendation="Standardize on one naming convention (prefer snake_case for Python).",
            evidence=(EvidenceReference(kind="probe", path=file_path, detail=f"Mixed naming: {len(snake)} snake_case + {len(camel)} camelCase", ok=False),),
            repair_kind=RepairKind.REFACTOR.value,
            executor_action=f"Standardize naming convention in {file_path}",
        ))
    return findings


# ---------------------------------------------------------------------------
# Cluster 26: TODO/FIXME Tracker
# ---------------------------------------------------------------------------


_TECH_DEBT_MARKERS = ("TODO", "FIXME", "HACK", "XXX", "TEMP", "WORKAROUND", "KLUDGE")


def assess_todo_debt(
    file_path: str,
    content: str,
    max_per_file: int = 5,
) -> list[GateFinding]:
    """Cluster 26: Track TODO/FIXME/HACK comments as tech debt inventory.

    Individual TODOs are info findings. More than max_per_file = warn finding.
    Returns findings for each marker found (as info-level), plus a warn finding
    if count exceeds threshold.
    """
    import re

    if not content.strip():
        return []  # NOT_APPLICABLE

    # F14c sub-fix 1: skip lines inside UPPER_CASE module-level container
    # literals (e.g. ``_TECH_DEBT_MARKERS = ("TODO", "FIXME")``). The gate
    # must not self-match on its own marker definitions.
    skip_lines = set(collect_constant_container_literal_lines(content))
    # F14c extra: also skip interior lines of multi-line string constants
    # (docstrings that explain marker patterns). Reuses F14a helper.
    skip_lines |= set(collect_string_constant_line_ranges(content))

    found: list[tuple[int, str, str]] = []
    for i, line in enumerate(content.splitlines(), 1):
        if i in skip_lines:
            continue
        # F14c sub-fix 2: skip visual section-header separator comments such
        # as ``# --- section ---`` or ``# === Legacy Debt (C53) ===``.
        if is_section_header_comment(line):
            continue
        for marker in _TECH_DEBT_MARKERS:
            if re.search(rf"\b{marker}\b", line, re.IGNORECASE):
                found.append((i, marker, line.strip()[:80]))
                break

    if not found:
        return []  # PASS

    # Always return a finding per marker (info-level)
    findings: list[GateFinding] = []
    for line_num, marker, text in found:
        findings.append(build_finding(
            check_id="todo_scan",
            category=GateCategory.REPORTING,
            title=f"[todo_debt] {file_path}:{line_num}",
            severity=GateSeverity.INFO,
            impact=GateImpact.WARN,
            summary=f"[{marker}] {text}",
            recommendation="Address tech debt marker or convert to a tracked issue.",
            evidence=(EvidenceReference(kind="probe", path=file_path, detail=f"[{marker}] {text}", ok=len(found) <= max_per_file),),
            repair_kind=RepairKind.REFACTOR.value,
            executor_action=f"Address {marker} at {file_path}:{line_num}",
        ))

    # If over threshold, add a warn-level summary finding
    if len(found) > max_per_file:
        findings.append(build_finding(
            check_id="todo_scan",
            category=GateCategory.REPORTING,
            title=f"[todo_debt] {file_path}: {len(found)} markers exceed threshold",
            severity=GateSeverity.MEDIUM,
            impact=GateImpact.REVISE,
            summary=f"{len(found)} tech debt markers in {file_path} (threshold: {max_per_file})",
            recommendation=f"Reduce TODO/FIXME count below {max_per_file} per file.",
            evidence=(EvidenceReference(kind="probe", path=file_path, detail=f"{len(found)} markers exceed threshold {max_per_file}", ok=False),),
            repair_kind=RepairKind.REFACTOR.value,
            executor_action=f"Reduce tech debt markers in {file_path}",
        ))
    return findings


# ---------------------------------------------------------------------------
# Cluster 28: Log Level Appropriateness
# ---------------------------------------------------------------------------


def assess_log_level_quality(
    file_path: str,
    content: str,
) -> list[GateFinding]:
    """Cluster 28: Detect mismatched log levels vs message severity."""
    import re

    if not content.strip():
        return []  # NOT_APPLICABLE

    basename = file_path.replace("\\", "/").split("/")[-1]
    if basename.startswith("test_"):
        return []  # NOT_APPLICABLE

    _ERROR_KEYWORDS = ("error", "fail", "crash", "fatal", "critical", "exception", "broken", "corrupt")
    _DEBUG_LEVELS = ("debug", "trace")
    _INFO_LEVELS = ("info",)

    findings: list[GateFinding] = []
    for i, line in enumerate(content.splitlines(), 1):
        stripped = line.strip()
        if stripped.startswith("#"):
            continue

        m = re.search(r"\b(?:log(?:ger)?|_log|logging)\.(debug|info|warning|error|critical)\s*\(\s*[f\"'](.{5,80})", stripped, re.IGNORECASE)
        if not m:
            continue

        level = m.group(1).lower()
        msg_preview = m.group(2).lower()

        if level in _DEBUG_LEVELS or level in _INFO_LEVELS:
            if any(kw in msg_preview for kw in _ERROR_KEYWORDS):
                _EXPECTED_FAILURE_PATTERNS = (
                    "failed to", "could not", "unable to", "cannot ",
                    "timeout", "timed out", "not found", "not available",
                    "skipping", "falling back", "does not exist",
                    "missing", "unavailable", "unreachable",
                    "ignored", "discarded", "dropped", "closed",
                    "no longer", "already ", "stale",
                )
                if any(pat in msg_preview for pat in _EXPECTED_FAILURE_PATTERNS):
                    continue
                findings.append(build_finding(
                    check_id="log_level_scan",
                    category=GateCategory.REPORTING,
                    title=f"[log_level_quality] {file_path}:{i}",
                    severity=GateSeverity.LOW,
                    impact=GateImpact.WARN,
                    summary=f"log.{level}() with error-severity message at line {i}",
                    recommendation=f"Use log.error() or log.warning() for error-severity messages.",
                    evidence=(EvidenceReference(kind="probe", path=file_path, detail=f"log.{level}() with error-severity message at line {i}", ok=False),),
                    repair_kind=RepairKind.REFACTOR.value,
                    executor_action=f"Change log level at {file_path}:{i}",
                ))

        if level in ("error", "critical"):
            _NORMAL_KEYWORDS = ("start", "ready", "success", "loaded", "initialized", "connected", "listening")
            if any(kw in msg_preview for kw in _NORMAL_KEYWORDS) and not any(kw in msg_preview for kw in _ERROR_KEYWORDS):
                findings.append(build_finding(
                    check_id="log_level_scan",
                    category=GateCategory.REPORTING,
                    title=f"[log_level_quality] {file_path}:{i}",
                    severity=GateSeverity.LOW,
                    impact=GateImpact.WARN,
                    summary=f"log.{level}() with normal-severity message at line {i}",
                    recommendation=f"Use log.info() for normal/success messages.",
                    evidence=(EvidenceReference(kind="probe", path=file_path, detail=f"log.{level}() with normal-severity message at line {i}", ok=False),),
                    repair_kind=RepairKind.REFACTOR.value,
                    executor_action=f"Change log level at {file_path}:{i}",
                ))
    return findings


# ---------------------------------------------------------------------------
# Cluster 29: File Encoding Consistency
# ---------------------------------------------------------------------------


def assess_encoding_consistency(
    file_path: str,
    raw_bytes: bytes,
) -> list[GateFinding]:
    """Cluster 29: Check file encoding, BOM, and line ending consistency."""
    if not raw_bytes:
        return []  # NOT_APPLICABLE

    findings: list[GateFinding] = []

    if raw_bytes.startswith(b"\xef\xbb\xbf"):
        findings.append(build_finding(
            check_id="encoding_scan",
            category=GateCategory.CONTRACT,
            title=f"[encoding_consistency] {file_path}:BOM",
            severity=GateSeverity.LOW,
            impact=GateImpact.WARN,
            summary="UTF-8 BOM detected -- most tools/editors don't need BOM for UTF-8",
            recommendation="Remove the UTF-8 BOM from the file.",
            evidence=(EvidenceReference(kind="probe", path=file_path, detail="UTF-8 BOM detected -- most tools/editors don't need BOM for UTF-8", ok=False),),
            repair_kind=RepairKind.FIX_ENCODING.value,
            executor_action=f"Remove BOM from {file_path}",
        ))

    try:
        raw_bytes.decode("utf-8")
    except UnicodeDecodeError:
        findings.append(build_finding(
            check_id="encoding_scan",
            category=GateCategory.CONTRACT,
            title=f"[encoding_consistency] {file_path}:encoding",
            severity=GateSeverity.MEDIUM,
            impact=GateImpact.REVISE,
            summary="File is not valid UTF-8 -- may be Latin-1 or CP1252",
            recommendation="Re-encode the file as UTF-8.",
            evidence=(EvidenceReference(kind="probe", path=file_path, detail="File is not valid UTF-8 -- may be Latin-1 or CP1252", ok=False),),
            repair_kind=RepairKind.FIX_ENCODING.value,
            executor_action=f"Re-encode {file_path} as UTF-8",
        ))

    has_crlf = b"\r\n" in raw_bytes
    lf_only = raw_bytes.replace(b"\r\n", b"")
    has_bare_lf = b"\n" in lf_only
    has_bare_cr = b"\r" in lf_only

    if has_crlf and has_bare_lf:
        findings.append(build_finding(
            check_id="encoding_scan",
            category=GateCategory.CONTRACT,
            title=f"[encoding_consistency] {file_path}:line_endings",
            severity=GateSeverity.LOW,
            impact=GateImpact.WARN,
            summary="Mixed line endings: both CRLF and LF detected",
            recommendation="Normalize to LF line endings.",
            evidence=(EvidenceReference(kind="probe", path=file_path, detail="Mixed line endings: both CRLF and LF detected", ok=False),),
            repair_kind=RepairKind.FIX_ENCODING.value,
            executor_action=f"Normalize line endings in {file_path}",
        ))
    if has_bare_cr:
        findings.append(build_finding(
            check_id="encoding_scan",
            category=GateCategory.CONTRACT,
            title=f"[encoding_consistency] {file_path}:line_endings",
            severity=GateSeverity.LOW,
            impact=GateImpact.WARN,
            summary="Old Mac-style CR line endings detected",
            recommendation="Normalize to LF line endings.",
            evidence=(EvidenceReference(kind="probe", path=file_path, detail="Old Mac-style CR line endings detected", ok=False),),
            repair_kind=RepairKind.FIX_ENCODING.value,
            executor_action=f"Normalize line endings in {file_path}",
        ))

    if b"\x00" in raw_bytes[:1000]:
        findings.append(build_finding(
            check_id="encoding_scan",
            category=GateCategory.CONTRACT,
            title=f"[encoding_consistency] {file_path}:null_bytes",
            severity=GateSeverity.MEDIUM,
            impact=GateImpact.REVISE,
            summary="Null bytes in file -- may be binary file with text extension",
            recommendation="Remove null bytes or use a binary-safe encoding.",
            evidence=(EvidenceReference(kind="probe", path=file_path, detail="Null bytes in file -- may be binary file with text extension", ok=False),),
            repair_kind=RepairKind.FIX_ENCODING.value,
            executor_action=f"Remove null bytes from {file_path}",
        ))
    return findings
