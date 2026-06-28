"""Edit, mutation, and static scan clusters 10-17.

Clusters:
  10 - Edit Consistency (LLM-specific)
  11 - Mutation Without Verification (LLM-specific)
  12 - Security Patterns
  13 - Test Quality
  14 - Import Cycles
  15 - Roundtrip Consistency
  16 - Shared Mutable State
  17 - Dependency Vulnerabilities
"""
from __future__ import annotations

import ast
import hashlib
from pathlib import Path
from typing import Optional

from .core import detect_language, _insufficient_evidence_finding
from ...gate_models import (
    EvidenceReference,
    GateCategory,
    GateFinding,
    GateImpact,
    GateSeverity,
    RepairKind,
)
from ..common import build_finding
from .._ast_helpers import collect_string_constant_line_ranges
import logging
_log = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Cluster 10: Edit Consistency (LLM-specific)
# ---------------------------------------------------------------------------


def assess_edit_consistency(
    instances: dict[str, str],
    expected_pattern: str,
) -> list[GateFinding]:
    """Cluster 10: All instances that should match a pattern actually match.

    Catches LLM Edit Amnesia: fix one occurrence, miss others.
    instances: {"file:line": "actual_code", ...}
    expected_pattern: regex that all instances should match
    """
    import re

    if not instances:
        return []  # NOT_APPLICABLE

    findings: list[GateFinding] = []
    for location, code in instances.items():
        matches = bool(re.search(expected_pattern, code))
        if not matches:
            findings.append(build_finding(
                check_id="edit_consistency",
                category=GateCategory.DRIFT,
                title=f"[edit_consistency] {location}",
                severity=GateSeverity.MEDIUM,
                impact=GateImpact.REVISE,
                summary=f"Instance at {location} DOES NOT match expected pattern",
                recommendation=f"Fix inconsistent edit at {location} to match pattern: {expected_pattern}",
                evidence=(EvidenceReference(kind="probe", path=location.split(":", 1)[0] if ":" in location else location, detail="DOES NOT match pattern", ok=False),),
                repair_kind=RepairKind.EDIT_CANONICAL.value,
                executor_action=f"Fix inconsistent edit at {location}",
            ))
    return findings


# ---------------------------------------------------------------------------
# Cluster 11: Mutation Without Verification (LLM-specific)
# ---------------------------------------------------------------------------


def assess_mutation_verified(
    file_path: str,
    expected_content_hash: str,
    actual_content_hash: Optional[str] = None,
    project_dir: Optional[Path] = None,
) -> list[GateFinding]:
    """Cluster 11: After mutation, verify the file actually contains expected content.

    Catches LLM Stale Reference: edit applied mentally but not on disk (stash drop,
    parallel agent overwrite, linter revert).

    Sprint C3 (2026-04-25): when ``project_dir`` is supplied, relative
    ``file_path`` values resolve against it instead of CWD. The runner stores
    snapshot keys in repo-relative form (see ``normalize_path``), so without
    the explicit anchor a "file missing" finding fired on files that exist on
    disk simply because the gate's CWD differed from the project root.
    """
    if actual_content_hash is None:
        # Compute from disk. Resolve relative paths against project_dir when
        # the caller supplies it; absolute paths pass through unchanged.
        candidate = Path(file_path)
        if project_dir is not None and not candidate.is_absolute():
            p = (Path(project_dir) / candidate).resolve()
        else:
            p = candidate
        if not p.exists():
            return [build_finding(
                check_id="mutation_verified",
                category=GateCategory.DRIFT,
                title=f"[mutation_unverified] {file_path}",
                severity=GateSeverity.HIGH,
                impact=GateImpact.REVISE,
                summary=f"Mutated file missing: {file_path}",
                recommendation="Verify the file was actually written to disk.",
                evidence=(EvidenceReference(kind="probe", path=file_path, detail="File does not exist after mutation", ok=False),),
                repair_kind=RepairKind.ADD_REGRESSION_TEST.value,
                executor_action=f"Re-apply mutation to {file_path}",
            )]
        actual_content_hash = hashlib.sha256(p.read_bytes()).hexdigest()

    if expected_content_hash != actual_content_hash:
        return [build_finding(
            check_id="mutation_verified",
            category=GateCategory.DRIFT,
            title=f"[mutation_unverified] {file_path}",
            severity=GateSeverity.HIGH,
            impact=GateImpact.REVISE,
            summary=f"File content DIVERGED from expected: {file_path}",
            recommendation="Re-apply the intended mutation; content was overwritten or reverted.",
            evidence=(EvidenceReference(
                kind="probe",
                path=file_path,
                detail=f"MISMATCH: expected {expected_content_hash[:16]}..., got {actual_content_hash[:16]}...",
                ok=False,
            ),),
            repair_kind=RepairKind.ADD_REGRESSION_TEST.value,
            executor_action=f"Re-apply mutation to {file_path}",
        )]
    return []  # PASS


# ---------------------------------------------------------------------------
# Cluster 12: Security Patterns
# ---------------------------------------------------------------------------


_SECURITY_DANGEROUS_PATTERNS: tuple[tuple[str, str], ...] = (
    (r"\beval\s*\(", "eval() usage -- potential code injection"),
    (r"\bexec\s*\(", "exec() usage -- potential code injection"),
    (r"\bos\.system\s*\(", "os.system() -- prefer subprocess with shell=False"),
    (r"shell\s*=\s*True", "subprocess with shell=True -- command injection risk"),
    (r"__import__\s*\([^'\"]", "dynamic __import__() with non-literal -- potential injection vector"),
    (r"\bpickle\.loads?\s*\(", "pickle deserialization -- arbitrary code execution risk"),
    (r"\byaml\.load\s*\((?!.*Loader)", "yaml.load without SafeLoader -- code execution risk"),
)

_SECURITY_JS_PATTERNS: tuple[tuple[str, str], ...] = (
    (r"\beval\s*\(", "eval() usage -- potential code injection"),
    (r"\bnew\s+Function\s*\(", "new Function() -- dynamic code execution"),
    (r"innerHTML\s*=", "innerHTML assignment -- XSS risk"),
    (r"document\.write\s*\(", "document.write -- XSS risk"),
    (r"dangerouslySetInnerHTML", "React dangerouslySetInnerHTML -- XSS risk"),
)

# SQL-clause structure: must look like an actual SQL statement (keyword + target
# identifier + structural follow-on), not a verb in prose. Checked against the
# literal template of an f-string / .format() / %-format string, *not* a raw line.
_SQL_STRUCTURE_RE = __import__("re").compile(
    r"(?i)\b("
    r"SELECT\s+[\w*,\s()]+\s+FROM\s+\w"
    r"|INSERT\s+INTO\s+\w+"
    r"|UPDATE\s+\w+\s+SET\s+\w"
    r"|DELETE\s+FROM\s+\w"
    r"|DROP\s+TABLE\s+\w"
    r"|CREATE\s+(?:TABLE|INDEX|VIEW)\s+\w"
    r"|ALTER\s+TABLE\s+\w"
    r")",
)

# Minimum literal length to plausibly contain a real query (keyword + target + clause).
_MIN_SQL_QUERY_LEN = 20

# DB-call attribute names: literal must be inside one of these calls on a
# Python AST for the SQL-injection rule to fire.
_DB_CALL_ATTRS: frozenset[str] = frozenset({
    "execute", "executemany", "executescript", "query", "raw",
})


def _py_fstring_template(node: ast.JoinedStr) -> tuple[str, bool]:
    """Extract the literal template of an f-string and whether it has interpolations."""
    parts: list[str] = []
    has_interp = False
    for value in node.values:
        if isinstance(value, ast.FormattedValue):
            has_interp = True
            parts.append(" {} ")  # placeholder to preserve spacing
        elif isinstance(value, ast.Constant) and isinstance(value.value, str):
            parts.append(value.value)
    return "".join(parts), has_interp


def _py_fstring_is_sql(node: ast.JoinedStr) -> bool:
    template, has_interp = _py_fstring_template(node)
    if not has_interp:
        return False
    if len(template) < _MIN_SQL_QUERY_LEN:
        return False
    return bool(_SQL_STRUCTURE_RE.search(template))


def _py_format_call_is_sql(node: ast.Call) -> bool:
    """True if ``"<literal>".format(...)`` with SQL-clause structure in the literal."""
    if not isinstance(node.func, ast.Attribute) or node.func.attr != "format":
        return False
    tmpl = node.func.value
    if not (isinstance(tmpl, ast.Constant) and isinstance(tmpl.value, str)):
        return False
    literal = tmpl.value
    if len(literal) < _MIN_SQL_QUERY_LEN:
        return False
    return bool(_SQL_STRUCTURE_RE.search(literal))


def _py_pct_format_is_sql(node: ast.BinOp) -> bool:
    """True if ``"<literal with %s>" % (...)`` with SQL-clause structure."""
    if not isinstance(node.op, ast.Mod):
        return False
    left = node.left
    if not (isinstance(left, ast.Constant) and isinstance(left.value, str)):
        return False
    literal = left.value
    if "%s" not in literal and "%(" not in literal:
        return False
    if len(literal) < _MIN_SQL_QUERY_LEN:
        return False
    return bool(_SQL_STRUCTURE_RE.search(literal))


def _flatten_add_chain(node: ast.AST) -> list[ast.AST]:
    """Flatten a left-associative ``a + b + c`` chain into ``[a, b, c]``.

    Only ``+`` (``ast.Add``) is unrolled; any other node is returned as a single
    leaf. Used to inspect every operand of a string-concatenation query.
    """
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        return _flatten_add_chain(node.left) + _flatten_add_chain(node.right)
    return [node]


def _py_concat_is_sql(node: ast.BinOp) -> bool:
    """True if ``"<sql literal>" + <var> [+ ...]`` builds a query with a variable.

    SQL-injection via string concatenation. Fires only when the ``+`` chain
    BOTH (a) contains a string literal with real SQL-clause structure and
    (b) has at least one NON-literal operand (a variable / call / attribute the
    caller interpolates in). A constant ``"SELECT ... " + "WHERE ..."`` (all
    literals) is a static query and must NOT fire — no injection vector.
    """
    if not isinstance(node.op, ast.Add):
        return False
    operands = _flatten_add_chain(node)
    literal_parts: list[str] = []
    has_non_literal = False
    for operand in operands:
        if isinstance(operand, ast.Constant) and isinstance(operand.value, str):
            literal_parts.append(operand.value)
        else:
            has_non_literal = True
    if not has_non_literal:
        return False  # constant string concatenation — not dynamic
    combined = "".join(literal_parts)
    if len(combined) < _MIN_SQL_QUERY_LEN:
        return False
    return bool(_SQL_STRUCTURE_RE.search(combined))


def _detect_python_sql_injection(tree: ast.AST) -> list[tuple[int, str]]:
    """Return ``(lineno, description)`` for dynamic SQL passed to DB-call sites.

    AST-level: only fires when a dynamically-built literal is the first argument
    of ``.execute / .executemany / .executescript / .query / .raw`` AND the
    literal template has real SQL-clause structure (not just a keyword). Covers
    f-string, ``.format()``, ``%``-format, and ``+`` string concatenation with
    an interpolated variable.
    """
    hits: list[tuple[int, str]] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        if not isinstance(node.func, ast.Attribute):
            continue
        if node.func.attr not in _DB_CALL_ATTRS:
            continue
        if not node.args:
            continue
        first = node.args[0]
        lineno = getattr(node, "lineno", 1) or 1
        if isinstance(first, ast.JoinedStr) and _py_fstring_is_sql(first):
            hits.append((lineno, "f-string SQL query -- SQL injection risk"))
        elif isinstance(first, ast.Call) and _py_format_call_is_sql(first):
            hits.append((lineno, ".format() SQL query -- SQL injection risk"))
        elif isinstance(first, ast.BinOp) and _py_pct_format_is_sql(first):
            hits.append((lineno, "%-format SQL query -- use parameterized queries"))
        elif isinstance(first, ast.BinOp) and _py_concat_is_sql(first):
            hits.append((lineno, "concatenated SQL query -- SQL injection risk"))
    return hits


# Callables whose ``shell=True`` keyword really is a subprocess invocation.
_SUBPROCESS_SHELL_CALLEES: frozenset[str] = frozenset({
    "run", "Popen", "call", "check_call", "check_output", "getoutput",
    "getstatusoutput", "spawn", "system",
})

# Map of Python dangerous-call signatures -> description. AST-based: fires only
# on genuine Call nodes, not on pattern strings inside our own source.
_PY_DANGEROUS_CALLS: dict[tuple[str, ...], str] = {
    ("eval",):                         "eval() usage -- potential code injection",
    ("exec",):                         "exec() usage -- potential code injection",
    ("os", "system"):                  "os.system() -- prefer subprocess with shell=False",
    ("pickle", "load"):                "pickle deserialization -- arbitrary code execution risk",
    ("pickle", "loads"):               "pickle deserialization -- arbitrary code execution risk",
}


def _call_attr_chain(node: ast.AST) -> tuple[str, ...] | None:
    """Return the attribute chain for a Call's func (e.g. ``pickle.loads`` -> ('pickle','loads')).

    Returns None if the callee isn't a simple Name or a ``<Name>.<attr>`` chain.
    """
    if isinstance(node, ast.Name):
        return (node.id,)
    if isinstance(node, ast.Attribute):
        head = node.value
        parts: list[str] = [node.attr]
        while isinstance(head, ast.Attribute):
            parts.append(head.attr)
            head = head.value
        if isinstance(head, ast.Name):
            parts.append(head.id)
            return tuple(reversed(parts))
    return None


def _detect_python_dangerous_calls(tree: ast.AST) -> list[tuple[int, str]]:
    """Return ``(lineno, description)`` for AST Call nodes matching dangerous signatures.

    Suppresses FP hits on docstrings, regex pattern constants, and prose that
    mentions ``eval(`` / ``exec(`` / etc. textually but never calls them.
    """
    hits: list[tuple[int, str]] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        chain = _call_attr_chain(node.func)
        if chain is None:
            continue
        for sig, desc in _PY_DANGEROUS_CALLS.items():
            # Match exact chain OR suffix (`pickle.loads` matches `m.pickle.loads`).
            if len(chain) >= len(sig) and chain[-len(sig):] == sig:
                lineno = getattr(node, "lineno", 1) or 1
                hits.append((lineno, desc))
                break
        # yaml.load without Loader= kwarg.
        if len(chain) >= 2 and chain[-2:] == ("yaml", "load"):
            has_loader = any(kw.arg == "Loader" for kw in node.keywords)
            if not has_loader:
                lineno = getattr(node, "lineno", 1) or 1
                hits.append((lineno, "yaml.load without SafeLoader -- code execution risk"))
        # __import__ with non-literal first arg.
        if chain == ("__import__",) and node.args:
            first = node.args[0]
            if not (isinstance(first, ast.Constant) and isinstance(first.value, str)):
                lineno = getattr(node, "lineno", 1) or 1
                hits.append((
                    lineno,
                    "dynamic __import__() with non-literal -- potential injection vector",
                ))
    return hits


def _detect_python_shell_true(tree: ast.AST) -> list[tuple[int, str]]:
    """Return ``(lineno, description)`` for real ``subprocess.*(shell=True, ...)`` calls.

    AST-level: suppresses FP hits on docstrings, regex string constants, and
    prose describing the pattern. Fires only when a Call node has a genuine
    ``shell=True`` keyword AND the callee name looks like a subprocess launcher.
    """
    hits: list[tuple[int, str]] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        callee_name: str | None = None
        if isinstance(node.func, ast.Attribute):
            callee_name = node.func.attr
        elif isinstance(node.func, ast.Name):
            callee_name = node.func.id
        if callee_name is None or callee_name not in _SUBPROCESS_SHELL_CALLEES:
            continue
        for kw in node.keywords:
            if kw.arg == "shell" and isinstance(kw.value, ast.Constant) and kw.value.value is True:
                lineno = getattr(node, "lineno", 1) or 1
                hits.append((
                    lineno,
                    "subprocess with shell=True -- command injection risk",
                ))
                break
    return hits


def assess_security_patterns(
    file_path: str,
    content: str,
) -> list[GateFinding]:
    """Cluster 12: Scan for dangerous code patterns in any language.

    For Python, SQL-injection detection is AST-based: a literal is flagged only
    when it is passed to a database-call site (``.execute``, ``.query``, ...)
    AND the template has real SQL-clause structure (``SELECT ... FROM``,
    ``UPDATE ... SET``, ``DELETE FROM``, etc.), not just a keyword appearing in
    prose (error messages, log lines, prompts, HTML).
    """
    import re
    if not content.strip():
        return []  # NOT_APPLICABLE

    lang = detect_language(file_path)
    findings: list[GateFinding] = []

    # --- AST-based detection for Python (SQL injection + shell=True) --------
    py_tree: ast.AST | None = None
    if lang == "python":
        try:
            py_tree = ast.parse(content)
        except SyntaxError:
            py_tree = None
        if py_tree is not None:
            for lineno, desc in _detect_python_sql_injection(py_tree):
                findings.append(build_finding(
                    check_id="security_scan",
                    category=GateCategory.CONTRACT,
                    title=f"[security_patterns] {file_path}:{lineno}",
                    severity=GateSeverity.HIGH,
                    impact=GateImpact.REVISE,
                    summary=desc,
                    recommendation=f"Use parameterized queries at {file_path}:{lineno}: {desc}",
                    evidence=(EvidenceReference(kind="probe", path=file_path, detail=desc, ok=False),),
                    repair_kind=RepairKind.REPLACE_WITH_FAIL_LOUD.value,
                    executor_action=f"Fix SQL injection at {file_path}:{lineno}",
                ))
            for lineno, desc in _detect_python_shell_true(py_tree):
                findings.append(build_finding(
                    check_id="security_scan",
                    category=GateCategory.CONTRACT,
                    title=f"[security_patterns] {file_path}:{lineno}",
                    severity=GateSeverity.HIGH,
                    impact=GateImpact.REVISE,
                    summary=desc,
                    recommendation=f"Avoid shell=True at {file_path}:{lineno}: pass argv list instead.",
                    evidence=(EvidenceReference(kind="probe", path=file_path, detail=desc, ok=False),),
                    repair_kind=RepairKind.REPLACE_WITH_FAIL_LOUD.value,
                    executor_action=f"Replace shell=True with argv list at {file_path}:{lineno}",
                ))
            for lineno, desc in _detect_python_dangerous_calls(py_tree):
                findings.append(build_finding(
                    check_id="security_scan",
                    category=GateCategory.CONTRACT,
                    title=f"[security_patterns] {file_path}:{lineno}",
                    severity=GateSeverity.HIGH,
                    impact=GateImpact.REVISE,
                    summary=desc,
                    recommendation=f"Remove dangerous pattern at {file_path}:{lineno}: {desc}",
                    evidence=(EvidenceReference(kind="probe", path=file_path, detail=desc, ok=False),),
                    repair_kind=RepairKind.REPLACE_WITH_FAIL_LOUD.value,
                    executor_action=f"Fix security issue at {file_path}:{lineno}",
                ))

    # --- Dangerous-pattern detection (regex, language-aware) -----------------
    # For Python we covered shell=True + eval/exec/... via AST; for non-Python
    # keep the regex fallback.
    if lang == "python":
        dangerous_patterns: list[tuple[str, str]] = []  # all handled via AST above
    elif lang in ("javascript", "typescript"):
        dangerous_patterns = list(_SECURITY_JS_PATTERNS)
    else:
        dangerous_patterns = [
            p for p in _SECURITY_DANGEROUS_PATTERNS
            if "eval" in p[0] or "shell" in p[0]
        ]

    for pattern, description in dangerous_patterns:
        for i, line in enumerate(content.splitlines(), 1):
            stripped = line.lstrip()
            if stripped.startswith("#") or stripped.startswith("//") or stripped.startswith("*"):
                continue
            if re.search(pattern, line, re.IGNORECASE):
                findings.append(build_finding(
                    check_id="security_scan",
                    category=GateCategory.CONTRACT,
                    title=f"[security_patterns] {file_path}:{i}",
                    severity=GateSeverity.HIGH,
                    impact=GateImpact.REVISE,
                    summary=description,
                    recommendation=f"Remove dangerous pattern at {file_path}:{i}: {description}",
                    evidence=(EvidenceReference(kind="probe", path=file_path, detail=description, ok=False),),
                    repair_kind=RepairKind.REPLACE_WITH_FAIL_LOUD.value,
                    executor_action=f"Fix security issue at {file_path}:{i}",
                ))
        if len(findings) >= 20:
            break
    return findings[:20]


# ---------------------------------------------------------------------------
# Cluster 13: Test Quality
# ---------------------------------------------------------------------------


def assess_test_quality(
    file_path: str,
    content: str,
) -> list[GateFinding]:
    """Cluster 13: Detect weak or empty tests in any test file."""
    import re

    lang = detect_language(file_path)
    if lang != "python":
        return []  # NOT_APPLICABLE

    if not file_path.replace("\\", "/").split("/")[-1].startswith("test_"):
        return []  # NOT_APPLICABLE

    test_funcs = list(re.finditer(r"(?:^|\n)([ \t]*)def (test_\w+)\s*\(", content))
    if not test_funcs:
        return []  # NOT_APPLICABLE

    # F14a: skip test-function matches whose `def test_...` is inside a
    # string literal (test fixtures that embed Python source as a string).
    string_literal_lines = collect_string_constant_line_ranges(content)

    findings: list[GateFinding] = []
    for match in test_funcs:
        # Line number of the `def test_...` (1-based). The leading `(?:^|\n)`
        # group may put match.start() on the preceding newline; using
        # match.end()-len(matched_def) is fragile, so count newlines up to
        # the actual "def " position via a substring search within the match.
        match_text = match.group(0)
        def_offset_in_match = match_text.find("def ")
        def_abs_offset = match.start() + (def_offset_in_match if def_offset_in_match >= 0 else 0)
        def_line_no = content[:def_abs_offset].count("\n") + 1
        if def_line_no in string_literal_lines:
            continue

        indent = match.group(1)
        func_name = match.group(2)
        start = match.end()
        body_pattern = rf"\n{indent}def \w+\s*\(" if indent else r"\ndef \w+\s*\("
        # F14a: walk next-function candidates until we find one that is
        # NOT inside a string literal (else the body would be cut short at
        # a fake `def foo` inside a triple-quoted fixture, dropping real
        # asserts from the body text).
        body_end_rel: int | None = None
        search_pos = 0
        rest = content[start:]
        while True:
            nxt = re.search(body_pattern, rest[search_pos:])
            if nxt is None:
                break
            abs_match_start = start + search_pos + nxt.start()
            def_offset = rest[search_pos + nxt.start():search_pos + nxt.end()].find("def ")
            def_abs = abs_match_start + (def_offset if def_offset >= 0 else 0)
            cand_line = content[:def_abs].count("\n") + 1
            if cand_line not in string_literal_lines:
                body_end_rel = search_pos + nxt.start()
                break
            # Candidate is inside a string literal — skip past it and continue.
            search_pos += nxt.end()
        body = rest[:body_end_rel] if body_end_rel is not None else rest

        body_stripped = body.strip()
        detail = None
        if not body_stripped or body_stripped == "pass" or body_stripped.startswith("..."):
            detail = "Empty test body (pass/ellipsis only)"
        elif re.search(r"\bassert\s+True\b", body) and not re.search(r"\bassert\s+\w+\s*(==|!=|>|<|in|not)", body):
            detail = "Only assert True -- meaningless assertion"
        elif not bool(re.search(r"\bassert\b|\bAssert\w+\(|\.assert_\w+\(|pytest\.raises", body)):
            detail = "No assertions found in test body"

        if detail:
            findings.append(build_finding(
                check_id="test_quality_scan",
                category=GateCategory.TESTING,
                title=f"[test_quality] {file_path}:{func_name}",
                severity=GateSeverity.MEDIUM,
                impact=GateImpact.REVISE,
                summary=detail,
                recommendation=f"Add meaningful assertions to {func_name}.",
                evidence=(EvidenceReference(kind="probe", path=file_path, detail=detail, ok=False),),
                repair_kind=RepairKind.ADD_TEST.value,
                executor_action=f"Add assertions to {func_name} in {file_path}",
            ))
        if len(findings) >= 20:
            break
    return findings


# ---------------------------------------------------------------------------
# Cluster 14: Import Cycles
# ---------------------------------------------------------------------------


def assess_import_cycles(
    module_imports: dict[str, list[str]],
) -> list[GateFinding]:
    """Cluster 14: Detect circular import dependencies.

    module_imports: {"module_a": ["module_b", "module_c"], "module_b": ["module_a"], ...}
    """
    if not module_imports:
        return []  # NOT_APPLICABLE

    # DFS cycle detection
    cycles: list[tuple[str, ...]] = []
    visited: set[str] = set()
    path: list[str] = []
    path_set: set[str] = set()

    def _dfs(node: str) -> None:
        if node in path_set:
            cycle_start = path.index(node)
            cycle = tuple(path[cycle_start:] + [node])
            min_idx = cycle.index(min(cycle[:-1]))
            normalized = cycle[min_idx:-1] + cycle[min_idx:]
            if normalized not in [tuple(c) for c in cycles]:
                cycles.append(normalized)
            return
        if node in visited:
            return
        visited.add(node)
        path.append(node)
        path_set.add(node)
        for dep in module_imports.get(node, []):
            if dep in module_imports:
                _dfs(dep)
        path.pop()
        path_set.discard(node)

    for mod in module_imports:
        if mod not in visited:
            _dfs(mod)

    findings: list[GateFinding] = []
    for cycle in cycles[:20]:
        chain = " -> ".join(cycle)
        findings.append(build_finding(
            check_id="import_cycle_scan",
            category=GateCategory.CONTRACT,
            title=f"[import_cycles] {chain[:80]}",
            severity=GateSeverity.HIGH,
            impact=GateImpact.REVISE,
            summary=f"Circular dependency: {chain}",
            recommendation="Break the import cycle by extracting shared code to a third module.",
            evidence=(EvidenceReference(kind="probe", detail=f"Circular dependency: {chain}", ok=False),),
            repair_kind=RepairKind.EXTRACT_SHARED.value,
            executor_action=f"Break import cycle: {chain}",
        ))
    return findings


# ---------------------------------------------------------------------------
# Cluster 15: Roundtrip Consistency
# ---------------------------------------------------------------------------


def assess_roundtrip_consistency(
    class_name: str,
    original_dict: dict[str, object],
    roundtripped_dict: dict[str, object],
) -> list[GateFinding]:
    """Cluster 15: Verify serialize/deserialize roundtrip preserves all fields."""
    if not original_dict:
        return []  # NOT_APPLICABLE

    findings: list[GateFinding] = []
    all_keys = set(original_dict.keys()) | set(roundtripped_dict.keys())

    for key in sorted(all_keys):
        orig = original_dict.get(key)
        rt = roundtripped_dict.get(key)
        if key not in original_dict:
            detail = f"Key appeared after roundtrip (not in original)"
        elif key not in roundtripped_dict:
            detail = f"Key lost during roundtrip"
        elif orig != rt:
            detail = f"Value changed: {str(orig)[:50]} -> {str(rt)[:50]}"
        else:
            continue
        findings.append(build_finding(
            check_id="roundtrip_check",
            category=GateCategory.DRIFT,
            title=f"[roundtrip_consistency] {class_name}.{key}",
            severity=GateSeverity.MEDIUM,
            impact=GateImpact.REVISE,
            summary=detail,
            recommendation=f"Fix roundtrip serialization for {class_name}.{key}.",
            evidence=(EvidenceReference(kind="probe", detail=detail, ok=False),),
            repair_kind=RepairKind.FIX_CONTRACT.value,
            executor_action=f"Fix roundtrip for {class_name}.{key}",
        ))
    return findings


# ---------------------------------------------------------------------------
# Cluster 16: Shared Mutable State
# ---------------------------------------------------------------------------


def assess_shared_mutable_state(
    file_path: str,
    content: str,
) -> list[GateFinding]:
    """Cluster 16: Detect module-level mutable state without synchronization."""
    import re

    if not content.strip():
        return []  # NOT_APPLICABLE

    uses_threading = bool(re.search(r"\bimport\s+threading\b|\bfrom\s+threading\b|\bThread\s*\(", content))

    mutable_pattern = re.compile(
        r"^([A-Z_][A-Z_0-9]*)\s*(?::.*?)?\s*=\s*("
        r"\{[^}]*\}|"
        r"\[[^\]]*\]|"
        r"set\s*\(|"
        r"dict\s*\(|"
        r"list\s*\(|"
        r"defaultdict\s*\("
        r")",
        re.MULTILINE,
    )

    mutables = list(mutable_pattern.finditer(content))
    if not mutables:
        return []  # PASS — no module-level mutables

    findings: list[GateFinding] = []
    for match in mutables:
        var_name = match.group(1)
        line_num = content[:match.start()].count("\n") + 1

        mutation_patterns = [
            rf"\b{re.escape(var_name)}\s*\[",
            rf"\b{re.escape(var_name)}\.append\b",
            rf"\b{re.escape(var_name)}\.add\b",
            rf"\b{re.escape(var_name)}\.update\b",
            rf"\b{re.escape(var_name)}\.pop\b",
            rf"\b{re.escape(var_name)}\.remove\b",
            rf"\b{re.escape(var_name)}\.extend\b",
            rf"\b{re.escape(var_name)}\.clear\b",
            rf"\b{re.escape(var_name)}\.discard\b",
        ]
        is_mutated = any(re.search(p, content) for p in mutation_patterns)

        if is_mutated and uses_threading:
            findings.append(build_finding(
                check_id="mutable_state_scan",
                category=GateCategory.RUNTIME_BEHAVIOR,
                title=f"[shared_mutable_state] {file_path}:{line_num}:{var_name}",
                severity=GateSeverity.HIGH,
                impact=GateImpact.REVISE,
                summary=f"Module-level mutable '{var_name}' mutated in threaded context without lock",
                recommendation="Add a threading.Lock() to protect all mutations of this variable.",
                evidence=(EvidenceReference(kind="probe", path=file_path, detail=f"Module-level mutable '{var_name}' mutated in threaded context without lock", ok=False),),
                repair_kind=RepairKind.FIX_CONTRACT.value,
                executor_action=f"Add lock for '{var_name}' in {file_path}",
            ))
    return findings


# ---------------------------------------------------------------------------
# Cluster 17: Dependency Vulnerabilities
# ---------------------------------------------------------------------------


def assess_dependency_vulnerabilities(
    audit_output: str,
    package_manager: str = "pip",
) -> list[GateFinding]:
    """Cluster 17: Detect known CVEs in project dependencies."""
    import json as _json

    if not audit_output.strip():
        return []  # NOT_APPLICABLE

    try:
        data = _json.loads(audit_output)
    except _json.JSONDecodeError:
        return [_insufficient_evidence_finding(
            check_id="dependency_cve_scan",
            category=GateCategory.CONTRACT,
            cluster="dependency_vulnerabilities",
            explanation=f"Could not parse {package_manager} audit output as JSON",
        )]

    findings: list[GateFinding] = []

    if package_manager == "pip":
        vulns = data if isinstance(data, list) else data.get("vulnerabilities", [])
        for vuln in vulns:
            name = vuln.get("name") or vuln.get("package_name") or "unknown"
            vuln_id = vuln.get("id") or vuln.get("vulnerability_id") or (vuln.get("aliases") or [""])[0] or "CVE-unknown"
            version = vuln.get("version") or vuln.get("installed_version") or "?"
            fix = vuln.get("fix_versions") or vuln.get("fixed_in") or []
            findings.append(build_finding(
                check_id="dependency_cve_scan",
                category=GateCategory.CONTRACT,
                title=f"[dependency_vulnerabilities] {name}=={version}",
                severity=GateSeverity.HIGH,
                impact=GateImpact.REVISE,
                summary=f"{vuln_id}: {name}=={version} (fix: {fix})",
                recommendation=f"Upgrade {name} to a fixed version: {fix}",
                evidence=(EvidenceReference(kind="probe", detail=f"{vuln_id}: {name}=={version} (fix: {fix})", ok=False),),
                repair_kind=RepairKind.FIX_CONTRACT.value,
                executor_action=f"Upgrade {name} to fix {vuln_id}",
            ))
    elif package_manager == "npm":
        vulns = data.get("vulnerabilities", {})
        for pkg_name, info in vulns.items():
            severity = info.get("severity", "unknown")
            findings.append(build_finding(
                check_id="dependency_cve_scan",
                category=GateCategory.CONTRACT,
                title=f"[dependency_vulnerabilities] {pkg_name}",
                severity=GateSeverity.HIGH,
                impact=GateImpact.REVISE,
                summary=f"{pkg_name}: severity={severity}",
                recommendation=f"Upgrade or patch {pkg_name}.",
                evidence=(EvidenceReference(kind="probe", detail=f"{pkg_name}: severity={severity}", ok=False),),
                repair_kind=RepairKind.FIX_CONTRACT.value,
                executor_action=f"Upgrade {pkg_name}",
            ))

    return findings
