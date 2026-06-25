"""Static code analysis: unreachable code, shadowed builtins, mutable defaults,
resource leaks, docstring drift. Clusters 34-38.

Clusters:
  34 - Unreachable Code
  35 - Shadowed Builtins
  36 - Mutable Default Arguments
  37 - Resource Leaks
  38 - Docstring/Signature Parameter Drift
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
from ..common import build_finding
from .._ast_helpers import collect_string_constant_line_ranges
import logging
_log = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Cluster 34: Unreachable Code
# ---------------------------------------------------------------------------

# Terminator keywords per language
_TERMINATORS = {
    "python": {"return", "raise", "break", "continue"},
    "javascript": {"return", "throw", "break", "continue"},
    "typescript": {"return", "throw", "break", "continue"},
    "go": {"return", "panic", "break", "continue"},
    "rust": {"return", "panic!", "break", "continue"},
    "java": {"return", "throw", "break", "continue"},
    "csharp": {"return", "throw", "break", "continue"},
    "kotlin": {"return", "throw", "break", "continue"},
    "ruby": {"return", "raise", "break", "next"},
    "swift": {"return", "throw", "break", "continue"},
    "php": {"return", "throw", "break", "continue"},
}

# Lines that legitimately follow a terminator at the same/less indent
_POST_TERMINATOR_OK = {
    "except", "except:", "elif", "else", "else:", "finally", "finally:",
    "catch", "case", "default", "default:", "}", "end", "rescue", "ensure",
    "elif:", "elseif", "elsif",
}


def assess_unreachable_code(
    file_path: str,
    content: str,
) -> list[GateFinding]:
    """Cluster 34: Detect code after return/raise/throw/break in same block."""
    if not content.strip():
        return []

    lang = detect_language(file_path)
    terminators = _TERMINATORS.get(lang)
    if not terminators:
        return []

    lines = content.splitlines()
    findings: list[GateFinding] = []

    # F14a: for Python, skip lines that live inside a string constant
    # (test fixtures containing `return x\n    dead_line()` etc.). For
    # non-Python languages this helper returns an empty set (ast.parse
    # fails), preserving prior behavior.
    string_literal_lines: frozenset[int] = (
        collect_string_constant_line_ranges(content) if lang == "python" else frozenset()
    )

    def _indent(line: str) -> int:
        return len(line) - len(line.lstrip())

    i = 0
    while i < len(lines) - 1:
        # F14a: skip terminator candidate lines that are inside a string literal.
        if (i + 1) in string_literal_lines:
            i += 1
            continue

        stripped = lines[i].strip()

        first_word = stripped.split("(")[0].split(" ")[0].rstrip(";")
        if first_word in terminators and not stripped.startswith("#") and not stripped.startswith("//"):
            term_indent = _indent(lines[i])
            for j in range(i + 1, min(i + 5, len(lines))):
                next_line = lines[j]
                if not next_line.strip():
                    continue
                # F14a: also skip the follow-up line if it's inside a string literal.
                if (j + 1) in string_literal_lines:
                    continue
                next_stripped = next_line.strip()
                next_indent = _indent(next_line)
                if next_indent > term_indent:
                    break
                if next_indent == term_indent:
                    first_next = next_stripped.split("(")[0].split(" ")[0].rstrip(":;")
                    if first_next.lower() not in _POST_TERMINATOR_OK and not next_stripped.startswith(("#", "//", "/*", "*", "@")):
                        detail = f"Unreachable code after '{first_word}' at line {i + 1}: {next_stripped[:60]}"
                        findings.append(build_finding(
                            check_id="unreachable_scan",
                            category=GateCategory.DRIFT,
                            title=f"[unreachable_code] {file_path}:{j + 1}",
                            severity=GateSeverity.MEDIUM,
                            impact=GateImpact.REVISE,
                            summary=detail,
                            recommendation="Remove or restructure the unreachable code block.",
                            evidence=(EvidenceReference(kind="probe", path=file_path, detail=detail, ok=False),),
                            repair_kind=RepairKind.REMOVE_DUPLICATE.value,
                            executor_action=f"Remove unreachable code at {file_path}:{j + 1}",
                        ))
                break
        i += 1
        if len(findings) >= 10:
            break

    return findings


# ---------------------------------------------------------------------------
# Cluster 35: Shadowed Builtins
# ---------------------------------------------------------------------------

_BUILTINS_BY_LANG: dict[str, set[str]] = {
    "python": {
        "list", "dict", "set", "tuple", "str", "int", "float", "bool",
        "type", "id", "input", "print", "len", "range", "map", "filter",
        "open", "hash", "any", "all", "min", "max", "sum", "sorted",
        "next", "iter", "super", "format", "zip", "enumerate", "abs",
        "round", "bytes", "object", "dir", "vars", "chr", "ord", "hex",
        "oct", "bin", "pow", "repr", "callable", "isinstance", "issubclass",
        "getattr", "setattr", "hasattr", "property", "classmethod",
        "staticmethod", "frozenset", "compile", "eval", "exec", "globals",
        "locals", "breakpoint", "complex", "file",
    },
    "javascript": {
        "Array", "Object", "String", "Number", "Boolean", "Function",
        "Symbol", "Map", "Set", "Promise", "Error", "Date", "RegExp",
        "JSON", "Math", "parseInt", "parseFloat", "isNaN", "Infinity",
        "NaN", "undefined", "console", "window", "document", "fetch",
        "setTimeout", "setInterval", "eval", "alert",
    },
    "go": {
        "error", "string", "int", "float64", "bool", "byte", "rune",
        "append", "cap", "close", "copy", "delete", "len", "make",
        "new", "panic", "recover", "print", "println", "true", "false",
        "nil", "iota", "complex64", "complex128",
    },
}
_BUILTINS_BY_LANG["typescript"] = _BUILTINS_BY_LANG["javascript"]


def _ast_shadowed_builtins_python(
    content: str,
    builtins: set[str],
) -> list[tuple[int, str]] | None:
    """Use AST to find Python names that genuinely shadow builtins.

    Returns a list of (lineno, name) tuples, or ``None`` when the content
    cannot be parsed (SyntaxError) so the caller can fall back to regex.

    Skipped (not real shadowing):
    - ``ast.AnnAssign`` inside a class body (dataclass/Pydantic field annotation)
    - Function parameter names (``def f(id: str)`` — legit API surface)
    - Names suppressed with ``# noqa: shadowed_builtin`` on the same line

    Flagged (real shadowing):
    - Module-level plain assignment: ``id = foo()``
    - Function-local plain assignment: ``def f(): id = 42``
    - ``for`` loop target at any scope: ``for list in items``
    - Import alias: ``from x import list``
    - Function definition whose name shadows a builtin: ``def list():``
    """
    import ast

    try:
        tree = ast.parse(content)
    except SyntaxError:
        return None  # caller falls back to regex

    source_lines = content.splitlines()

    def _noqa(lineno: int) -> bool:
        """Return True if the line carries # noqa: shadowed_builtin."""
        if lineno < 1 or lineno > len(source_lines):
            return False
        line = source_lines[lineno - 1]
        return "noqa: shadowed_builtin" in line

    hits: list[tuple[int, str]] = []

    # Collect the set of class body node-ids so we can skip AnnAssign inside them.
    class_body_ids: set[int] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.ClassDef):
            for child in node.body:
                class_body_ids.add(id(child))

    # Collect function arg names to skip (parameter annotations are not shadowing).
    param_names_by_funcdef: dict[int, set[str]] = {}
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            args = node.args
            all_args = (
                args.args
                + args.posonlyargs
                + args.kwonlyargs
                + ([args.vararg] if args.vararg else [])
                + ([args.kwarg] if args.kwarg else [])
            )
            param_names_by_funcdef[id(node)] = {a.arg for a in all_args}

    for node in ast.walk(tree):
        # --- AnnAssign: skip if it's inside a class body ---
        if isinstance(node, ast.AnnAssign):
            if id(node) in class_body_ids:
                continue  # dataclass / Pydantic field — not real shadowing
            if isinstance(node.target, ast.Name):
                name = node.target.id
                lineno = node.lineno
                if name in builtins and not _noqa(lineno):
                    hits.append((lineno, name))
            continue

        # --- Plain assignment (Assign / AugAssign / NamedExpr) ---
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name):
                    name = target.id
                    lineno = node.lineno
                    if name in builtins and not _noqa(lineno):
                        hits.append((lineno, name))
            continue

        if isinstance(node, ast.AugAssign):
            if isinstance(node.target, ast.Name):
                name = node.target.id
                lineno = node.lineno
                if name in builtins and not _noqa(lineno):
                    hits.append((lineno, name))
            continue

        if isinstance(node, ast.NamedExpr):
            if isinstance(node.target, ast.Name):
                name = node.target.id
                lineno = node.lineno
                if name in builtins and not _noqa(lineno):
                    hits.append((lineno, name))
            continue

        # --- For-loop target ---
        if isinstance(node, (ast.For, ast.AsyncFor)):
            if isinstance(node.target, ast.Name):
                name = node.target.id
                lineno = node.lineno
                if name in builtins and not _noqa(lineno):
                    hits.append((lineno, name))
            continue

        # --- Import alias ---
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            for alias in node.names:
                bound = alias.asname if alias.asname else alias.name
                lineno = node.lineno
                if bound in builtins and not _noqa(lineno):
                    hits.append((lineno, bound))
            continue

        # --- Function / class definition name ---
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            name = node.name
            lineno = node.lineno
            if name in builtins and not _noqa(lineno):
                hits.append((lineno, name))
            # Note: we do NOT flag the parameter names — those are legit API surface.
            continue

    # Deduplicate and sort by line number (ast.walk may visit some nodes twice
    # in edge cases with nested comprehensions).
    seen: set[tuple[int, str]] = set()
    result: list[tuple[int, str]] = []
    for item in sorted(hits, key=lambda x: x[0]):
        if item not in seen:
            seen.add(item)
            result.append(item)
    return result


def assess_shadowed_builtins(
    file_path: str,
    content: str,
) -> list[GateFinding]:
    """Cluster 35: Detect variable names that shadow language builtins."""
    import re

    if not content.strip():
        return []

    lang = detect_language(file_path)
    builtins = _BUILTINS_BY_LANG.get(lang)
    if not builtins:
        return []

    basename = file_path.replace("\\", "/").rsplit("/", 1)[-1] if "/" in file_path.replace("\\", "/") else file_path
    if basename.startswith("test_") or basename.startswith("conftest"):
        return []

    findings: list[GateFinding] = []

    if lang == "python":
        # Prefer AST-based detection — precise, no FPs on dataclass fields /
        # function parameters.  Returns None on SyntaxError → regex fallback.
        ast_hits = _ast_shadowed_builtins_python(content, builtins)
        if ast_hits is not None:
            # AST parse succeeded; ast_hits is the authoritative list (may be empty).
            for lineno, name in ast_hits:
                detail = f"Variable '{name}' shadows Python builtin (line {lineno})"
                findings.append(build_finding(
                    check_id="shadowed_builtin_scan",
                    category=GateCategory.RUNTIME_BEHAVIOR,
                    title=f"[shadowed_builtins] {file_path}:{lineno}",
                    severity=GateSeverity.LOW,
                    impact=GateImpact.WARN,
                    summary=detail,
                    recommendation=f"Rename '{name}' to avoid shadowing the Python builtin.",
                    evidence=(EvidenceReference(kind="probe", path=file_path, detail=detail, ok=False),),
                    repair_kind=RepairKind.FIX_CONTRACT.value,
                    executor_action=f"Rename shadowed builtin '{name}' at {file_path}:{lineno}",
                ))
                if len(findings) >= 10:
                    break
        else:
            # SyntaxError in file — best-effort regex fallback.
            source_lines = content.splitlines()
            for i, line in enumerate(source_lines, 1):
                if line.strip().startswith("#"):
                    continue
                if "noqa: shadowed_builtin" in line:
                    continue
                name = None
                m = re.match(r'^\s*(\w+)\s*=\s*(?!=)', line)
                if m:
                    name = m.group(1)
                if not name:
                    m = re.match(r'^\s*for\s+(\w+)\s+in\b', line)
                    if m:
                        name = m.group(1)
                if not name:
                    m = re.match(r'^\s*def\s+(\w+)\s*\(', line)
                    if m:
                        name = m.group(1)
                if name and name in builtins:
                    detail = f"Variable '{name}' shadows Python builtin (line {i})"
                    findings.append(build_finding(
                        check_id="shadowed_builtin_scan",
                        category=GateCategory.RUNTIME_BEHAVIOR,
                        title=f"[shadowed_builtins] {file_path}:{i}",
                        severity=GateSeverity.LOW,
                        impact=GateImpact.WARN,
                        summary=detail,
                        recommendation=f"Rename '{name}' to avoid shadowing the Python builtin.",
                        evidence=(EvidenceReference(kind="probe", path=file_path, detail=detail, ok=False),),
                        repair_kind=RepairKind.FIX_CONTRACT.value,
                        executor_action=f"Rename shadowed builtin '{name}' at {file_path}:{i}",
                    ))
                if len(findings) >= 10:
                    break

    elif lang in ("javascript", "typescript"):
        js_re = re.compile(r'^\s*(?:var|let|const)\s+(\w+)\s*=')
        fn_re = re.compile(r'^\s*function\s+(\w+)\s*\(')

        for i, line in enumerate(content.splitlines(), 1):
            if line.strip().startswith("//"):
                continue
            for m in [js_re.match(line), fn_re.match(line)]:
                if m:
                    name = m.group(1)
                    if name in builtins:
                        detail = f"Variable '{name}' shadows JS/TS builtin (line {i})"
                        findings.append(build_finding(
                            check_id="shadowed_builtin_scan",
                            category=GateCategory.RUNTIME_BEHAVIOR,
                            title=f"[shadowed_builtins] {file_path}:{i}",
                            severity=GateSeverity.LOW,
                            impact=GateImpact.WARN,
                            summary=detail,
                            recommendation=f"Rename '{name}' to avoid shadowing the JS/TS builtin.",
                            evidence=(EvidenceReference(kind="probe", path=file_path, detail=detail, ok=False),),
                            repair_kind=RepairKind.FIX_CONTRACT.value,
                            executor_action=f"Rename shadowed builtin '{name}' at {file_path}:{i}",
                        ))
                        break
            if len(findings) >= 10:
                break

    elif lang == "go":
        go_re = re.compile(r'^\s*(?:var\s+)?(\w+)\s*:?=')
        for i, line in enumerate(content.splitlines(), 1):
            if line.strip().startswith("//"):
                continue
            m = go_re.match(line)
            if m and m.group(1) in builtins:
                detail = f"Variable '{m.group(1)}' shadows Go builtin (line {i})"
                findings.append(build_finding(
                    check_id="shadowed_builtin_scan",
                    category=GateCategory.RUNTIME_BEHAVIOR,
                    title=f"[shadowed_builtins] {file_path}:{i}",
                    severity=GateSeverity.LOW,
                    impact=GateImpact.WARN,
                    summary=detail,
                    recommendation=f"Rename '{m.group(1)}' to avoid shadowing the Go builtin.",
                    evidence=(EvidenceReference(kind="probe", path=file_path, detail=detail, ok=False),),
                    repair_kind=RepairKind.FIX_CONTRACT.value,
                    executor_action=f"Rename shadowed builtin '{m.group(1)}' at {file_path}:{i}",
                ))
            if len(findings) >= 10:
                break

    return findings


# ---------------------------------------------------------------------------
# Cluster 36: Mutable Default Arguments
# ---------------------------------------------------------------------------


def assess_mutable_defaults(
    file_path: str,
    content: str,
) -> list[GateFinding]:
    """Cluster 36: Detect mutable default arguments in function signatures."""
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

    if lang == "python":
        mutable_re = re.compile(
            r'(\w+)\s*(?::\s*\w[^=]*)?\s*=\s*(\[\]|\{\}|set\(\)|list\(\)|dict\(\)|bytearray\(\))'
        )
        for i, line in enumerate(content.splitlines(), 1):
            if not line.strip().startswith("def "):
                continue
            sig = line
            j = i
            all_lines = content.splitlines()
            while sig.count("(") > sig.count(")") and j < min(i + 10, len(all_lines)):
                j += 1
                sig += " " + all_lines[j - 1]
            for m in mutable_re.finditer(sig):
                detail = f"Mutable default argument '{m.group(1)}={m.group(2)}' (line {i})"
                findings.append(build_finding(
                    check_id="mutable_default_scan",
                    category=GateCategory.RUNTIME_BEHAVIOR,
                    title=f"[mutable_defaults] {file_path}:{i}",
                    severity=GateSeverity.MEDIUM,
                    impact=GateImpact.REVISE,
                    summary=detail,
                    recommendation=f"Use None as default and initialize inside the function: `if {m.group(1)} is None: {m.group(1)} = {m.group(2)}`",
                    evidence=(EvidenceReference(kind="probe", path=file_path, detail=detail, ok=False),),
                    repair_kind=RepairKind.FIX_CONTRACT.value,
                    executor_action=f"Fix mutable default at {file_path}:{i}",
                ))
            if len(findings) >= 10:
                break

    elif lang in ("javascript", "typescript"):
        js_mutable_re = re.compile(r'(\w+)\s*=\s*(\[\]|\{\})')
        for i, line in enumerate(content.splitlines(), 1):
            stripped = line.strip()
            if "function" in stripped or "=>" in stripped or stripped.startswith("("):
                for m in js_mutable_re.finditer(line):
                    detail = f"Mutable default argument '{m.group(1)} = {m.group(2)}' (line {i})"
                    findings.append(build_finding(
                        check_id="mutable_default_scan",
                        category=GateCategory.RUNTIME_BEHAVIOR,
                        title=f"[mutable_defaults] {file_path}:{i}",
                        severity=GateSeverity.MEDIUM,
                        impact=GateImpact.REVISE,
                        summary=detail,
                        recommendation="Use null/undefined as default and initialize inside the function.",
                        evidence=(EvidenceReference(kind="probe", path=file_path, detail=detail, ok=False),),
                        repair_kind=RepairKind.FIX_CONTRACT.value,
                        executor_action=f"Fix mutable default at {file_path}:{i}",
                    ))
            if len(findings) >= 10:
                break

    return findings


# ---------------------------------------------------------------------------
# Cluster 37: Resource Leaks
# ---------------------------------------------------------------------------


def assess_resource_leaks(
    file_path: str,
    content: str,
) -> list[GateFinding]:
    """Cluster 37: Detect unclosed resources (file handles, connections)."""
    import re

    if not content.strip():
        return []

    lang = detect_language(file_path)
    if lang not in ("python", "go", "java"):
        return []

    basename = file_path.replace("\\", "/").rsplit("/", 1)[-1] if "/" in file_path.replace("\\", "/") else file_path
    if basename.startswith("test_") or basename.startswith("conftest"):
        return []

    findings: list[GateFinding] = []

    if lang == "python":
        for i, line in enumerate(content.splitlines(), 1):
            stripped = line.strip()
            if stripped.startswith("#"):
                continue
            if re.search(r'\w+\s*=\s*open\s*\(', stripped) and not stripped.startswith("with "):
                detail = f"open() without `with` statement (line {i}): use `with open(...) as f:` instead"
                findings.append(build_finding(
                    check_id="resource_leak_scan",
                    category=GateCategory.RUNTIME_BEHAVIOR,
                    title=f"[resource_leaks] {file_path}:{i}",
                    severity=GateSeverity.MEDIUM,
                    impact=GateImpact.REVISE,
                    summary=detail,
                    recommendation="Use `with open(...) as f:` to ensure the file is closed.",
                    evidence=(EvidenceReference(kind="probe", path=file_path, detail=detail, ok=False),),
                    repair_kind=RepairKind.FIX_CONTRACT.value,
                    executor_action=f"Fix resource leak at {file_path}:{i}",
                ))
            if re.search(r'\w+\s*=\s*(?:sqlite3\.connect|socket\.socket|urllib\.\w+\.urlopen)\s*\(', stripped) and not stripped.startswith("with "):
                detail = f"Resource opened without `with` statement (line {i})"
                findings.append(build_finding(
                    check_id="resource_leak_scan",
                    category=GateCategory.RUNTIME_BEHAVIOR,
                    title=f"[resource_leaks] {file_path}:{i}",
                    severity=GateSeverity.MEDIUM,
                    impact=GateImpact.REVISE,
                    summary=detail,
                    recommendation="Use a context manager (`with` statement) to ensure the resource is closed.",
                    evidence=(EvidenceReference(kind="probe", path=file_path, detail=detail, ok=False),),
                    repair_kind=RepairKind.FIX_CONTRACT.value,
                    executor_action=f"Fix resource leak at {file_path}:{i}",
                ))
            if len(findings) >= 10:
                break

    elif lang == "go":
        lines = content.splitlines()
        for i, line in enumerate(lines, 1):
            m = re.search(r'(\w+)\s*,\s*\w+\s*:?=\s*os\.(Open|Create|OpenFile)\s*\(', line)
            if m:
                var_name = m.group(1)
                has_defer = False
                for j in range(i, min(i + 5, len(lines))):
                    if f"defer {var_name}.Close()" in lines[j]:
                        has_defer = True
                        break
                if not has_defer:
                    detail = f"os.{m.group(2)}() without `defer {var_name}.Close()` (line {i})"
                    findings.append(build_finding(
                        check_id="resource_leak_scan",
                        category=GateCategory.RUNTIME_BEHAVIOR,
                        title=f"[resource_leaks] {file_path}:{i}",
                        severity=GateSeverity.MEDIUM,
                        impact=GateImpact.REVISE,
                        summary=detail,
                        recommendation=f"Add `defer {var_name}.Close()` immediately after opening.",
                        evidence=(EvidenceReference(kind="probe", path=file_path, detail=detail, ok=False),),
                        repair_kind=RepairKind.FIX_CONTRACT.value,
                        executor_action=f"Fix resource leak at {file_path}:{i}",
                    ))
            if len(findings) >= 10:
                break

    elif lang == "java":
        for i, line in enumerate(content.splitlines(), 1):
            stripped = line.strip()
            if re.search(r'new\s+(?:FileInputStream|FileOutputStream|BufferedReader|FileReader|FileWriter|Socket)\s*\(', stripped):
                if "try" not in stripped:
                    detail = f"Resource created without try-with-resources (line {i})"
                    findings.append(build_finding(
                        check_id="resource_leak_scan",
                        category=GateCategory.RUNTIME_BEHAVIOR,
                        title=f"[resource_leaks] {file_path}:{i}",
                        severity=GateSeverity.MEDIUM,
                        impact=GateImpact.REVISE,
                        summary=detail,
                        recommendation="Use try-with-resources to ensure the resource is closed.",
                        evidence=(EvidenceReference(kind="probe", path=file_path, detail=detail, ok=False),),
                        repair_kind=RepairKind.FIX_CONTRACT.value,
                        executor_action=f"Fix resource leak at {file_path}:{i}",
                    ))
            if len(findings) >= 10:
                break

    return findings


# ---------------------------------------------------------------------------
# Cluster 38: Docstring/Signature Parameter Drift
# ---------------------------------------------------------------------------


def assess_docstring_params(
    file_path: str,
    content: str,
) -> list[GateFinding]:
    """Cluster 38: Detect mismatch between function parameters and docstring."""
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

    if lang == "python":
        func_re = re.compile(r'^(\s*)def\s+(\w+)\s*\(([^)]*)\)\s*(?:->.*)?:', re.MULTILINE)
        for m in func_re.finditer(content):
            func_name = m.group(2)
            params_str = m.group(3)
            raw_params = [p.strip().split(":")[0].split("=")[0].strip()
                          for p in params_str.split(",") if p.strip()]
            actual_params = [p for p in raw_params
                            if p and p not in ("self", "cls") and not p.startswith("*")]
            if not actual_params:
                continue

            end_pos = m.end()
            rest = content[end_pos:end_pos + 2000]
            doc_match = re.match(r'\s*(?:"""(.*?)"""|\'\'\'(.*?)\'\'\')', rest, re.DOTALL)
            if not doc_match:
                continue
            docstring = doc_match.group(1) or doc_match.group(2) or ""
            doc_params = re.findall(r':param\s+(\w+)', docstring)
            if not doc_params:
                args_match = re.search(r'Args:\s*\n((?:\s+\w+.*\n)*)', docstring)
                if args_match:
                    doc_params = re.findall(r'^\s+(\w+)\s*(?:\(|:)', args_match.group(1), re.MULTILINE)
            if not doc_params:
                continue

            line_num = content[:m.start()].count("\n") + 1
            if set(doc_params) != set(actual_params):
                missing_in_doc = set(actual_params) - set(doc_params)
                extra_in_doc = set(doc_params) - set(actual_params)
                parts = []
                if missing_in_doc:
                    parts.append(f"missing from docs: {', '.join(sorted(missing_in_doc))}")
                if extra_in_doc:
                    parts.append(f"extra in docs: {', '.join(sorted(extra_in_doc))}")
                detail = f"Docstring/signature mismatch in {func_name}(): {'; '.join(parts)}"
                findings.append(build_finding(
                    check_id="docstring_param_scan",
                    category=GateCategory.REPORTING,
                    title=f"[docstring_drift] {file_path}:{line_num}:{func_name}",
                    severity=GateSeverity.LOW,
                    impact=GateImpact.WARN,
                    summary=detail,
                    recommendation=f"Update docstring for {func_name}() to match actual parameters.",
                    evidence=(EvidenceReference(kind="probe", path=file_path, detail=detail, ok=False),),
                    repair_kind=RepairKind.ADD_PROOF.value,
                    executor_action=f"Fix docstring drift in {func_name}() at {file_path}:{line_num}",
                ))
            if len(findings) >= 10:
                break

    elif lang in ("javascript", "typescript"):
        blocks = re.finditer(r'/\*\*(.*?)\*/\s*(?:(?:async\s+)?function\s+(\w+)\s*\(([^)]*)\)|(?:const|let|var)\s+(\w+)\s*=\s*(?:async\s+)?\(([^)]*)\))', content, re.DOTALL)
        for m in blocks:
            jsdoc = m.group(1)
            func_name = m.group(2) or m.group(4) or "anonymous"
            params_str = m.group(3) or m.group(5) or ""
            doc_params = re.findall(r'@param\s+(?:\{[^}]*\}\s+)?(\w+)', jsdoc)
            actual_params = [p.strip().split("=")[0].split(":")[0].strip()
                            for p in params_str.split(",") if p.strip()]
            actual_params = [p for p in actual_params if p and not p.startswith("...")]
            if not doc_params or not actual_params:
                continue

            line_num = content[:m.start()].count("\n") + 1
            if set(doc_params) != set(actual_params):
                detail = f"JSDoc/signature mismatch in {func_name}()"
                findings.append(build_finding(
                    check_id="docstring_param_scan",
                    category=GateCategory.REPORTING,
                    title=f"[docstring_drift] {file_path}:{line_num}:{func_name}",
                    severity=GateSeverity.LOW,
                    impact=GateImpact.WARN,
                    summary=detail,
                    recommendation=f"Update JSDoc for {func_name}() to match actual parameters.",
                    evidence=(EvidenceReference(kind="probe", path=file_path, detail=detail, ok=False),),
                    repair_kind=RepairKind.ADD_PROOF.value,
                    executor_action=f"Fix JSDoc drift in {func_name}() at {file_path}:{line_num}",
                ))
            if len(findings) >= 10:
                break

    return findings
