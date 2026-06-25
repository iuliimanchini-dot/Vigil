"""Security gate: command_injection and path_traversal_hint detection.

security.command_injection:
  subprocess.* called with shell=True AND first positional arg is a
  string-building expression (BinOp Add, JoinedStr f-string, or .format()).

security.path_traversal_hint:
  os.path.join(base, user_input) or Path(base) / user_input where user_input
  is a function parameter and no sanitizer (.resolve() + is_relative_to or
  explicit ".." check) is visible in the function body.
"""
from __future__ import annotations

import ast
import logging
import re

from cortex_forensic._shared import (
    EvidenceReference,
    GateCategory,
    GateImpact,
    GateSeverity,
    RepairKind,
)
from cortex_forensic.gate_models import PostExecGateContext
from ..source_analysis import is_source_file
from .common import build_check_result, build_finding, normalize_path
from ._ast_helpers import parse_python_source_or_emit_finding

_log = logging.getLogger(__name__)

# subprocess function names considered dangerous with shell=True
_SUBPROCESS_FUNCS = frozenset({"run", "Popen", "call", "check_call", "check_output"})

# Taint hint: parameter names that suggest user-supplied / external input.
# Only path parameters matching this regex (or annotated with `# taint: user-supplied`)
# are flagged as path traversal hints.
_TAINT_PARAM_RE = re.compile(
    r"(?i)^(user_|untrusted_|input_|request_|body_|form_|query_|param_|upload_|client_|external_)"
    r"|(_input|_upload|_param|_arg|_from_user)$"
)


# ---------------------------------------------------------------------------
# Helpers — command_injection
# ---------------------------------------------------------------------------

def _is_shell_true(call: ast.Call) -> bool:
    for kw in call.keywords:
        if kw.arg == "shell" and isinstance(kw.value, ast.Constant) and kw.value.value is True:
            return True
    return False


def _is_string_building(node: ast.expr) -> bool:
    """Return True if node is string concatenation, f-string, or .format() call."""
    # BinOp with Add (e.g. "cmd " + arg)
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        return True
    # JoinedStr = f-string
    if isinstance(node, ast.JoinedStr):
        return True
    # <expr>.format(...)
    if isinstance(node, ast.Call):
        if isinstance(node.func, ast.Attribute) and node.func.attr == "format":
            return True
    return False


def _get_func_name(call: ast.Call) -> tuple[str, str] | None:
    """Return (module, func) for subprocess.X calls, or None."""
    func = call.func
    if isinstance(func, ast.Attribute) and isinstance(func.value, ast.Name):
        return func.value.id, func.attr
    return None


def _find_command_injections(tree: ast.AST, file_path: str) -> list[dict]:
    """B4 (2026-04-23): accepts a pre-parsed tree so the meta-syntax-error
    path emits once per file in the caller."""
    hits: list[dict] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        parts = _get_func_name(node)
        if parts is None:
            continue
        module, func = parts
        if module != "subprocess" or func not in _SUBPROCESS_FUNCS:
            continue
        if not _is_shell_true(node):
            continue
        # Check first positional arg
        if node.args and _is_string_building(node.args[0]):
            hits.append({
                "call": f"subprocess.{func}",
                "line": getattr(node, "lineno", 0),
                "file": file_path,
            })
    return hits


# ---------------------------------------------------------------------------
# Helpers — path_traversal_hint
# ---------------------------------------------------------------------------

def _get_function_params(func_node: ast.FunctionDef | ast.AsyncFunctionDef) -> set[str]:
    params: set[str] = set()
    for arg in func_node.args.args + func_node.args.posonlyargs + func_node.args.kwonlyargs:
        params.add(arg.arg)
    if func_node.args.vararg:
        params.add(func_node.args.vararg.arg)
    if func_node.args.kwarg:
        params.add(func_node.args.kwarg.arg)
    return params


def _has_sanitizer(func_node: ast.FunctionDef | ast.AsyncFunctionDef) -> bool:
    """Return True if the function body contains resolve() + is_relative_to or '..' check."""
    for node in ast.walk(func_node):
        # .resolve() call
        if isinstance(node, ast.Call):
            if isinstance(node.func, ast.Attribute) and node.func.attr in {"resolve", "is_relative_to"}:
                return True
        # string literal ".." check — any Constant with ".." indicates manual validation
        if isinstance(node, ast.Constant) and isinstance(node.value, str) and ".." in node.value:
            return True
    return False


def _find_path_traversal_hints(tree: ast.AST, file_path: str) -> list[dict]:
    """B4 (2026-04-23): accepts a pre-parsed tree so the meta-syntax-error
    path emits once per file in the caller."""
    hits: list[dict] = []

    for func_node in ast.walk(tree):
        if not isinstance(func_node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        params = _get_function_params(func_node)
        if not params:
            continue
        if _has_sanitizer(func_node):
            continue

        for node in ast.walk(func_node):
            if not isinstance(node, ast.Call):
                continue
            lineno = getattr(node, "lineno", 0)

            # os.path.join(base, user_input) where user_input is a param
            parts = _get_func_name(node)
            if parts:
                module, func = parts
                # os.path.join: the node.func is Attribute(value=Attribute(value=Name('os'), attr='path'), attr='join')
                # We handle that pattern separately below.

            # Check os.path.join pattern
            func_node_call = node.func
            if isinstance(func_node_call, ast.Attribute) and func_node_call.attr == "join":
                val = func_node_call.value
                if isinstance(val, ast.Attribute) and val.attr == "path":
                    if isinstance(val.value, ast.Name) and val.value.id == "os":
                        # Check if any arg (beyond first) is a tainted function parameter
                        for arg in node.args[1:]:
                            if isinstance(arg, ast.Name) and arg.id in params:
                                if _TAINT_PARAM_RE.search(arg.id):
                                    hits.append({
                                        "call": "os.path.join",
                                        "line": lineno,
                                        "file": file_path,
                                        "param": arg.id,
                                    })

            # Check Path(base) / user_input pattern — BinOp Div
            # This appears as BinOp(left=Call(func=Name('Path')|Attribute(...Path), op=Div, right=Name(param))
            if isinstance(node, ast.BinOp):
                # ast.walk visits all nodes; skip — we handle BinOp separately below
                pass

        # Walk for BinOp Div with Path on left and tainted param on right
        for node in ast.walk(func_node):
            if not isinstance(node, ast.BinOp):
                continue
            if not isinstance(node.op, ast.Div):
                continue
            right = node.right
            if isinstance(right, ast.Name) and right.id in params:
                if not _TAINT_PARAM_RE.search(right.id):
                    continue
                # Check left involves Path
                left = node.left
                left_src = ast.unparse(left) if hasattr(ast, "unparse") else ""
                if "Path" in left_src or _involves_path_call(left):
                    lineno = getattr(node, "lineno", 0)
                    hits.append({
                        "call": "Path(...) / param",
                        "line": lineno,
                        "file": file_path,
                        "param": right.id,
                    })

    return hits


def _involves_path_call(node: ast.expr) -> bool:
    """Return True if the node tree contains a call to Path or pathlib.Path."""
    for n in ast.walk(node):
        if isinstance(n, ast.Call):
            if isinstance(n.func, ast.Name) and n.func.id == "Path":
                return True
            if isinstance(n.func, ast.Attribute) and n.func.attr == "Path":
                return True
    return False


# ---------------------------------------------------------------------------
# Gate entry-point
# ---------------------------------------------------------------------------

def run_security_injection_checks(ctx: PostExecGateContext):
    """Detect command injection and path traversal hints in changed Python files."""
    findings = []

    for raw_path in ctx.changed_files_observed:
        normalized = normalize_path(raw_path)
        if not is_source_file(normalized):
            continue

        abs_path = ctx.project_dir / normalized
        try:
            src = abs_path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError) as exc:
            _log.debug("security_injection_checks: cannot read %s: %s", normalized, exc)
            continue

        # B4 (2026-04-23): parse once so SyntaxError emits a single
        # meta.syntax_parse_error for this file.
        tree = parse_python_source_or_emit_finding(
            src,
            rel_path=normalized,
            emit_finding=findings.append,
            emitting_gate="security_injection",
        )
        if tree is None:
            continue

        # --- security.command_injection ---
        for hit in _find_command_injections(tree, normalized):
            lineno = hit["line"]
            call_name = hit["call"]
            findings.append(
                build_finding(
                    check_id="security.command_injection",
                    category=GateCategory.CONTRACT,
                    title=f"Command injection risk: {call_name}(shell=True, <string-build>) at {normalized}:{lineno}",
                    severity=GateSeverity.CRITICAL,
                    impact=GateImpact.BLOCK,
                    summary=(
                        f"{normalized} line {lineno}: {call_name}() called with shell=True "
                        "and a dynamically-built string (concatenation / f-string / .format). "
                        "An attacker controlling any part of the string can inject arbitrary shell commands."
                    ),
                    recommendation=(
                        "Pass a list of arguments instead of a shell string. "
                        "Use subprocess.run([cmd, arg1, arg2], shell=False). "
                        "Never build shell commands from untrusted input."
                    ),
                    evidence=[
                        EvidenceReference(
                            kind="file",
                            path=normalized,
                            detail=f"line:{lineno}",
                        )
                    ],
                    repair_kind=RepairKind.REPLACE_WITH_FAIL_LOUD.value,
                    executor_action=(
                        "Pass list of args instead of shell string. "
                        "Use subprocess.run([cmd, arg1, arg2], shell=False)"
                    ),
                    proof_required=(
                        "no subprocess call with shell=True + string concatenation/f-string/format remains"
                    ),
                    allowlist_allowed=False,
                )
            )

        # --- security.path_traversal_hint ---
        for hit in _find_path_traversal_hints(tree, normalized):
            lineno = hit["line"]
            call_name = hit["call"]
            param = hit.get("param", "?")
            findings.append(
                build_finding(
                    check_id="security.path_traversal_hint",
                    category=GateCategory.CONTRACT,
                    title=f"Path traversal hint: {call_name} with unvalidated param '{param}' at {normalized}:{lineno}",
                    severity=GateSeverity.HIGH,
                    impact=GateImpact.REVISE,
                    summary=(
                        f"{normalized} line {lineno}: {call_name} receives function parameter '{param}' "
                        "without visible '..' check or resolve()+is_relative_to() guard. "
                        "User-controlled path components can escape the intended base directory."
                    ),
                    recommendation=(
                        "Validate user-supplied path components: call .resolve() and verify "
                        ".is_relative_to(base_dir), or explicitly reject paths containing '..'."
                    ),
                    evidence=[
                        EvidenceReference(
                            kind="file",
                            path=normalized,
                            detail=f"line:{lineno} param={param}",
                        )
                    ],
                    repair_kind=RepairKind.VALIDATE_BOUNDARY.value,
                    executor_action=(
                        f"Add path sanitization before {call_name}: "
                        "resolved = Path(base, {param}).resolve(); "
                        "assert resolved.is_relative_to(base_dir)"
                    ),
                    proof_required=(
                        f"every {call_name} call with user-supplied '{param}' has resolve()+is_relative_to guard"
                    ),
                    allowlist_allowed=True,
                )
            )

    return build_check_result(
        check_id="security_injection",
        category=GateCategory.CONTRACT,
        findings=findings,
    )
