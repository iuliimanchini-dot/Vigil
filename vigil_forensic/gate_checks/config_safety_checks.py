"""Config safety gate: dangerous_default, missing_env_var_check, hardcoded_path.

config.dangerous_default:
  Dataclass field or function parameter default with a security-risky value:
  allow_unsafe=True, verify_ssl=False, check_certs=False, debug=True,
  trust_env=True, unsafe_*=True.

config.missing_env_var_check:
  os.environ["VAR"] subscript access without surrounding try/except KeyError
  or a prior `if "VAR" in os.environ:` guard in the same function body.

config.unguarded_env_access.hardcoded_path (Sprint F-4):
  String constants embedded as launch/runtime dependencies that pin the code
  to a specific machine's filesystem layout — the natural extension of the
  unguarded_env_access concern. These show up most often as:
    * /usr/bin/pythonN — hardcoded interpreter path in subprocess argv
    * C:\\Python311\\python.exe — same, Windows variant
    * C:\\Users\\<user>\\... or /home/<user>/... — hardcoded home dir
    * .venv/bin/<exe> or venv/Scripts/<exe> — pinned virtualenv layout
  Detection is AST-based; the constant must appear as the first element of
  subprocess argv, the path argument of os.execv/os.execve, the argument
  to pathlib.Path(), or the right-hand side of os.environ["PATH"] / etc.
  Severity adjusts by deployment_target context (linux-only project +
  windows-only path = HIGH; cross-platform = MEDIUM).
"""
from __future__ import annotations

import ast
import logging
import re
from pathlib import Path

from vigil_forensic._shared import (
    EvidenceReference,
    GateCategory,
    GateImpact,
    GateSeverity,
    RepairKind,
)
from vigil_forensic.gate_models import PostExecGateContext
from ..source_analysis import is_source_file
from ._deployment_detector import resolve_deployment
from .common import build_check_result, build_finding, has_allowlist_for, normalize_path

_log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Dangerous defaults: (param_name_pattern, dangerous_value)
# dangerous_value=True means the flag True is risky; False means False is risky
# ---------------------------------------------------------------------------
_DANGEROUS_DEFAULTS: list[tuple[re.Pattern[str], bool]] = [
    (re.compile(r"^allow_unsafe$"), True),
    (re.compile(r"^verify_ssl$"), False),
    (re.compile(r"^check_certs$"), False),
    (re.compile(r"^debug$"), True),
    (re.compile(r"^trust_env$"), True),
    (re.compile(r"^unsafe_"), True),   # any name starting with unsafe_
]


def _is_dangerous_constant(name: str, value: object) -> bool:
    """Return True if name+value matches a dangerous-default pattern."""
    for pattern, risky_value in _DANGEROUS_DEFAULTS:
        if pattern.match(name) and value is risky_value:
            return True
    return False


# ---------------------------------------------------------------------------
# Helpers — dangerous_default
# ---------------------------------------------------------------------------

def _find_dangerous_defaults(src: str, file_path: str) -> list[dict]:
    try:
        tree = ast.parse(src)
    except SyntaxError:
        return []

    hits: list[dict] = []

    for node in ast.walk(tree):
        # Function parameter defaults
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            defaults = node.args.defaults + node.args.kw_defaults
            kw_args = node.args.kwonlyargs
            pos_args = node.args.args
            # positional defaults are right-aligned
            all_args = pos_args + kw_args
            for i, default in enumerate(defaults):
                if default is None:
                    continue
                # map defaults back to arg names (right-aligned for positional)
                offset = len(pos_args) - len(node.args.defaults)
                if i < len(node.args.defaults):
                    arg_idx = offset + i
                    if 0 <= arg_idx < len(pos_args):
                        arg_name = pos_args[arg_idx].arg
                    else:
                        continue
                else:
                    kw_idx = i - len(node.args.defaults)
                    if kw_idx < len(kw_args):
                        arg_name = kw_args[kw_idx].arg
                    else:
                        continue
                if isinstance(default, ast.Constant) and isinstance(default.value, bool):
                    if _is_dangerous_constant(arg_name, default.value):
                        hits.append({
                            "kind": "func_param",
                            "name": arg_name,
                            "value": default.value,
                            "line": getattr(default, "lineno", getattr(node, "lineno", 0)),
                            "file": file_path,
                        })

        # Dataclass / class body Assign (e.g. field defaults)
        if isinstance(node, ast.ClassDef):
            for stmt in node.body:
                if isinstance(stmt, ast.AnnAssign) and stmt.value is not None:
                    target = stmt.target
                    val = stmt.value
                    if isinstance(target, ast.Name) and isinstance(val, ast.Constant):
                        if isinstance(val.value, bool) and _is_dangerous_constant(target.id, val.value):
                            hits.append({
                                "kind": "class_field",
                                "name": target.id,
                                "value": val.value,
                                "line": getattr(stmt, "lineno", 0),
                                "file": file_path,
                            })
                if isinstance(stmt, ast.Assign):
                    for target in stmt.targets:
                        if isinstance(target, ast.Name) and isinstance(stmt.value, ast.Constant):
                            if isinstance(stmt.value.value, bool) and _is_dangerous_constant(target.id, stmt.value.value):
                                hits.append({
                                    "kind": "class_field",
                                    "name": target.id,
                                    "value": stmt.value.value,
                                    "line": getattr(stmt, "lineno", 0),
                                    "file": file_path,
                                })

    return hits


# ---------------------------------------------------------------------------
# Helpers — missing_env_var_check
# ---------------------------------------------------------------------------

def _extract_environ_subscript_accesses(func_node: ast.FunctionDef | ast.AsyncFunctionDef) -> list[dict]:
    """Collect os.environ["VAR"] subscript accesses in a function body."""
    results: list[dict] = []
    for node in ast.walk(func_node):
        if isinstance(node, ast.Subscript):
            val = node.value
            if not isinstance(val, ast.Attribute):
                continue
            if val.attr != "environ":
                continue
            if not isinstance(val.value, ast.Name):
                continue
            if val.value.id != "os":
                continue
            # Extract the key
            key_node = node.slice
            # Python 3.9+: slice is direct; 3.8: wrapped in Index
            if isinstance(key_node, ast.Index):
                key_node = key_node.value  # type: ignore[attr-defined]
            if isinstance(key_node, ast.Constant) and isinstance(key_node.value, str):
                results.append({
                    "varname": key_node.value,
                    "line": getattr(node, "lineno", 0),
                })
    return results


def _has_environ_guard(func_node: ast.FunctionDef | ast.AsyncFunctionDef, varname: str) -> bool:
    """Return True if the function body contains a guard for the given env var name.

    Guards recognised:
      1. `if "VAR" in os.environ:` — Compare with In operator
      2. try/except KeyError (or bare except) wrapping body
    """
    for node in ast.walk(func_node):
        # Pattern 1: "VAR" in os.environ  OR  "VAR" not in os.environ
        if isinstance(node, ast.Compare):
            if node.ops and isinstance(node.ops[0], (ast.In, ast.NotIn)):
                left = node.left
                if isinstance(left, ast.Constant) and left.value == varname:
                    return True
        # Pattern 2: try/except KeyError
        if isinstance(node, ast.Try):
            for handler in node.handlers:
                if handler.type is None:
                    return True  # bare except
                if isinstance(handler.type, ast.Name) and handler.type.id == "KeyError":
                    return True
                if isinstance(handler.type, ast.Attribute) and handler.type.attr == "KeyError":
                    return True
    return False


def _find_missing_env_var_checks(src: str, file_path: str) -> list[dict]:
    try:
        tree = ast.parse(src)
    except SyntaxError:
        return []

    hits: list[dict] = []

    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        for access in _extract_environ_subscript_accesses(node):
            varname = access["varname"]
            if not _has_environ_guard(node, varname):
                hits.append({
                    "varname": varname,
                    "line": access["line"],
                    "file": file_path,
                })

    # Also check module-level os.environ["VAR"] (outside any function).
    # ast.walk visits the entire tree including nested function bodies, so we
    # cannot use it here.  Instead walk only the direct children of Module.body
    # — these are guaranteed to be top-level statements.
    module_guarded_vars: set[str] = set()
    for stmt in tree.body:
        # Collect module-level guards: `if "VAR" in os.environ:` or try/except KeyError
        if isinstance(stmt, ast.If):
            test = stmt.test
            if isinstance(test, ast.Compare) and test.ops and isinstance(test.ops[0], (ast.In, ast.NotIn)):
                if isinstance(test.left, ast.Constant) and isinstance(test.left.value, str):
                    module_guarded_vars.add(test.left.value)
        if isinstance(stmt, ast.Try):
            for handler in stmt.handlers:
                if handler.type is None:
                    # bare except at module level — treat all vars as guarded is too broad;
                    # we record the vars accessed inside the try body specifically
                    for sub in ast.walk(stmt):
                        if isinstance(sub, ast.Subscript):
                            val = sub.value
                            if isinstance(val, ast.Attribute) and val.attr == "environ":
                                if isinstance(val.value, ast.Name) and val.value.id == "os":
                                    key_node = sub.slice
                                    if isinstance(key_node, ast.Index):
                                        key_node = key_node.value  # type: ignore[attr-defined]
                                    if isinstance(key_node, ast.Constant) and isinstance(key_node.value, str):
                                        module_guarded_vars.add(key_node.value)
                    break
                if isinstance(handler.type, ast.Name) and handler.type.id == "KeyError":
                    for sub in ast.walk(stmt):
                        if isinstance(sub, ast.Subscript):
                            val = sub.value
                            if isinstance(val, ast.Attribute) and val.attr == "environ":
                                if isinstance(val.value, ast.Name) and val.value.id == "os":
                                    key_node = sub.slice
                                    if isinstance(key_node, ast.Index):
                                        key_node = key_node.value  # type: ignore[attr-defined]
                                    if isinstance(key_node, ast.Constant) and isinstance(key_node.value, str):
                                        module_guarded_vars.add(key_node.value)
                    break

    # Now find unguarded subscript accesses in top-level Assign / AnnAssign / Expr
    for stmt in tree.body:
        if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.If, ast.Try)):
            continue  # skip function defs (already handled) and guarded blocks
        for sub in ast.walk(stmt):
            if isinstance(sub, ast.Subscript):
                val = sub.value
                if not isinstance(val, ast.Attribute):
                    continue
                if val.attr != "environ":
                    continue
                if not isinstance(val.value, ast.Name):
                    continue
                if val.value.id != "os":
                    continue
                key_node = sub.slice
                if isinstance(key_node, ast.Index):
                    key_node = key_node.value  # type: ignore[attr-defined]
                if isinstance(key_node, ast.Constant) and isinstance(key_node.value, str):
                    varname = key_node.value
                    if varname not in module_guarded_vars:
                        hits.append({
                            "varname": varname,
                            "line": getattr(sub, "lineno", 0),
                            "file": file_path,
                        })

    return hits


# ---------------------------------------------------------------------------
# Helpers — hardcoded_path  (Sprint F-4)
# ---------------------------------------------------------------------------
#
# Hardcoded interpreter / user / venv paths embedded as launch dependencies.
# These are the second face of the "unguarded environment access" concern:
# the code reaches outside its sandbox without going through a configurable
# channel (env var, sys.executable, expanduser, importlib.resources). When
# the host moves, the code breaks.
#
# Patterns are anchored — partial substring matches only fire on real path
# shapes ("/usr/bin/python3", not the unrelated string "python3" in a docstring).
# The variant categorisation is exposed in the finding so reviewers can
# distinguish a Windows-pinned path on a Linux deployment (HIGH severity)
# from a portable cross-platform pin (MEDIUM).

_HARDCODED_PATH_PATTERNS: tuple[tuple[re.Pattern[str], str], ...] = (
    # Hardcoded Python interpreter, POSIX layout.
    # /usr/bin/python, /usr/bin/python3, /usr/bin/python3.11, /usr/local/bin/python
    (re.compile(r"^/usr(?:/local)?/bin/python\d*(?:\.\d+)?$"), "hardcoded_interpreter"),
    # Hardcoded Python interpreter, Windows layout.
    # C:\Python311\python.exe, D:\Python39\python.exe, etc.
    (re.compile(r"^[A-Za-z]:[\\\/]+Python\d+[\\\/]+python\.exe$", re.IGNORECASE), "hardcoded_interpreter"),
    # Hardcoded user paths — Windows.
    # C:\Users\foo\..., D:\Users\bar\... — only flag when the path includes a
    # directory after the user folder (otherwise C:\Users\Public\ etc. would
    # be too broad). The trailing \ ensures a real subdirectory.
    (re.compile(r"^[A-Za-z]:[\\\/]+Users[\\\/]+[A-Za-z0-9._-]+[\\\/]+", re.IGNORECASE), "hardcoded_user_path"),
    # Hardcoded user paths — POSIX.
    # /home/foo/... — must include a subpath after the user folder.
    (re.compile(r"^/home/[A-Za-z0-9._-]+/"), "hardcoded_user_path"),
    # macOS user paths.
    (re.compile(r"^/Users/[A-Za-z0-9._-]+/"), "hardcoded_user_path"),
    # Hardcoded venv paths — Unix.
    (re.compile(r"^[\./]*\.?venv/bin/[A-Za-z0-9._-]+$"), "hardcoded_venv_path"),
    # Hardcoded venv paths — Windows.
    (re.compile(r"^[\./]*\.?venv[\\\/]+Scripts[\\\/]+[A-Za-z0-9._-]+(?:\.exe)?$", re.IGNORECASE), "hardcoded_venv_path"),
)


def _classify_hardcoded_path(value: str) -> str | None:
    """Return the variant tag if *value* matches a hardcoded-path pattern.

    Returns None when the string is a normal data value (URL, relative path,
    plain filename, etc.). Anchors guarantee no spurious match on bare
    substrings like ``"python"`` or ``"home"``.
    """
    if not value or len(value) < 5:
        return None
    # Normalise once. We test the original string against patterns that
    # already accept both / and \ where relevant — no double-normalisation.
    for pattern, variant in _HARDCODED_PATH_PATTERNS:
        if pattern.match(value):
            return variant
    return None


# AST call-site signatures we treat as "this string IS a launch/runtime path".
# A hardcoded path appearing inside an unrelated string-formatting context
# (e.g. a docstring describing how to install) is not a launch dependency.
#
# Format: ((module_or_class, leaf_attr_or_None), arg_index_or_keyword)
#   * (("subprocess", "run"),       0)  — first positional argument of subprocess.run
#   * (("subprocess", "Popen"),     0)
#   * (("os",         "execv"),     0)  — first positional argument of os.execv
#   * (("os",         "execve"),    0)
#   * ((None,         "Path"),      0)  — Path(...) bare call (after `from pathlib import Path`)
#   * (("pathlib",    "Path"),      0)
#
# When the matching argument is a list/tuple literal (subprocess argv), we
# inspect its first element rather than the literal itself.

_LAUNCH_CALL_SIGNATURES: tuple[tuple[tuple[str | None, str], int], ...] = (
    (("subprocess", "run"), 0),
    (("subprocess", "Popen"), 0),
    (("subprocess", "call"), 0),
    (("subprocess", "check_call"), 0),
    (("subprocess", "check_output"), 0),
    (("os", "execv"), 0),
    (("os", "execve"), 0),
    (("os", "execvp"), 0),
    (("os", "execvpe"), 0),
    (("os", "spawnv"), 1),  # spawnv(mode, path, args)
    (("os", "spawnve"), 1),
    ((None, "Path"), 0),
    (("pathlib", "Path"), 0),
)


def _resolve_simple_call_target(call: ast.Call) -> tuple[str | None, str] | None:
    """Identify a Call as ``module.func(...)`` / ``Class(...)`` / ``func(...)``.

    Returns (module_or_None, leaf_attr_or_func_name). Used by the launch-call
    signature matcher.
    """
    func = call.func
    if isinstance(func, ast.Attribute):
        if isinstance(func.value, ast.Name):
            return func.value.id, func.attr
    elif isinstance(func, ast.Name):
        return None, func.id
    return None


def _argv_first_arg(call: ast.Call, arg_index: int) -> ast.AST | None:
    """Return the AST node at the given positional argument index, descending
    one level into a list/tuple literal so subprocess([X, ...]) yields X.

    Returns None if the index is out of range or the slot is unsupported.
    """
    if arg_index >= len(call.args):
        return None
    arg = call.args[arg_index]
    if isinstance(arg, (ast.List, ast.Tuple)) and arg.elts:
        return arg.elts[0]
    return arg


def _is_safe_dynamic_path_call(node: ast.AST) -> bool:
    """Recognise common safe alternatives that produce a path at runtime.

    These must NOT trigger a hardcoded-path finding even when wrapped in a
    Path(...) / subprocess argv slot:

      * sys.executable
      * os.path.expanduser(...) / os.path.expandvars(...)
      * Path.home() / Path.cwd()
      * shutil.which(...)
      * importlib.resources.files(...) / .joinpath(...)
      * os.environ.get(...) — already runtime-driven
      * pathlib.Path(__file__).parent / ...
      * Path(...) /  ... (anything)  — composed result
    """
    if isinstance(node, ast.Attribute):
        # sys.executable
        if isinstance(node.value, ast.Name) and node.value.id == "sys" and node.attr == "executable":
            return True
        # __file__ etc. — safe identifiers used to derive paths.
        if isinstance(node.value, ast.Name) and node.attr in {"parent", "parents", "stem", "name"}:
            return True
    if isinstance(node, ast.Name):
        if node.id in {"__file__", "__path__"}:
            return True
    if isinstance(node, ast.Call):
        target = _resolve_simple_call_target(node)
        if target is None:
            return False
        module, fname = target
        # os.path.expanduser/expandvars
        if module == "os" and fname in {"expanduser", "expandvars"}:
            return True
        if module == "shutil" and fname == "which":
            return True
        # Path.home() / Path.cwd() — the function attr will be on Name "Path".
        if module == "Path" and fname in {"home", "cwd"}:
            return True
        # Anything wrapping os.environ.get(...) is environment-driven.
        if module == "environ" and fname == "get":
            return True
    return False


def _find_hardcoded_paths(
    src: str,
    file_path: str,
    *,
    project_dir: Path,
) -> list[dict]:
    """Detect hardcoded interpreter / user / venv paths in launch / runtime
    code. Returns list of hit dicts: ``{value, variant, line, file, severity}``.
    """
    try:
        tree = ast.parse(src)
    except SyntaxError:
        return []

    # Resolve deployment target once per file. Severity escalates when the
    # detected path platform conflicts with the deployment target.
    try:
        deployment = resolve_deployment(project_dir, file_content=src)
    except Exception:  # noqa: BLE001 -- detector must never crash gate
        deployment = "unknown"

    hits: list[dict] = []

    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        target = _resolve_simple_call_target(node)
        if target is None:
            continue

        # Match against known launch-call signatures.
        signature = None
        for sig, arg_index in _LAUNCH_CALL_SIGNATURES:
            if sig == target:
                signature = (sig, arg_index)
                break
        if signature is None:
            continue
        _, arg_index = signature

        path_node = _argv_first_arg(node, arg_index)
        if path_node is None:
            continue

        # Whitelist: safe dynamic alternatives.
        if _is_safe_dynamic_path_call(path_node):
            continue

        # Only string Constants are subject to hardcoded-path classification.
        if not (isinstance(path_node, ast.Constant) and isinstance(path_node.value, str)):
            continue

        variant = _classify_hardcoded_path(path_node.value)
        if variant is None:
            continue

        # Severity escalation — windows path on linux-only or vice versa.
        is_windows_path = bool(re.match(r"^[A-Za-z]:[\\\/]", path_node.value))
        is_linux_path = path_node.value.startswith(("/usr/", "/home/", "/Users/"))
        severity = GateSeverity.MEDIUM
        if deployment == "linux-only" and is_windows_path:
            severity = GateSeverity.HIGH
        elif deployment == "windows-only" and is_linux_path:
            severity = GateSeverity.HIGH

        hits.append({
            "value": path_node.value,
            "variant": variant,
            "line": getattr(path_node, "lineno", getattr(node, "lineno", 0)),
            "file": file_path,
            "severity": severity,
            "deployment": deployment,
        })

    return hits


# ---------------------------------------------------------------------------
# Gate entry-point
# ---------------------------------------------------------------------------

def run_config_safety_checks(ctx: PostExecGateContext):
    """Detect dangerous defaults and missing env-var guards in changed Python files."""
    findings = []

    for raw_path in ctx.changed_files_observed:
        normalized = normalize_path(raw_path)
        if not is_source_file(normalized):
            continue

        abs_path = ctx.project_dir / normalized
        try:
            src = abs_path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError) as exc:
            _log.debug("config_safety_checks: cannot read %s: %s", normalized, exc)
            continue

        # --- config.dangerous_default ---
        for hit in _find_dangerous_defaults(src, normalized):
            name = hit["name"]
            value = hit["value"]
            lineno = hit["line"]
            if has_allowlist_for(src, "config.dangerous_default", lineno):
                continue
            safe_value = not value  # flip the bool to the safe direction
            findings.append(
                build_finding(
                    check_id="config.dangerous_default",
                    category=GateCategory.CONFIG_SSOT,
                    title=f"Dangerous default: {name}={value!r} at {normalized}:{lineno}",
                    severity=GateSeverity.HIGH,
                    impact=GateImpact.REVISE,
                    summary=(
                        f"{normalized} line {lineno}: parameter/field '{name}' defaults to "
                        f"{value!r} which is a security-unsafe value. "
                        "This opt-in to unsafe behaviour is invisible to callers who rely on defaults."
                    ),
                    recommendation=(
                        f"Change default to {name}={safe_value!r} (the safe value). "
                        "Require explicit opt-in via keyword argument for unsafe behaviour."
                    ),
                    evidence=[
                        EvidenceReference(
                            kind="file",
                            path=normalized,
                            detail=f"line:{lineno}",
                        )
                    ],
                    repair_kind=RepairKind.FIX_CONTRACT.value,
                    executor_action=(
                        f"Flip default to safe value; require explicit opt-in via kwarg. "
                        f"Change {name}={value!r} → {name}={safe_value!r}"
                    ),
                    proof_required=(
                        f"No {name}={value!r} default in codebase; unsafe behaviour requires explicit kwarg"
                    ),
                    allowlist_allowed=True,
                )
            )

        # --- config.missing_env_var_check ---
        for hit in _find_missing_env_var_checks(src, normalized):
            varname = hit["varname"]
            lineno = hit["line"]
            if has_allowlist_for(src, "config.missing_env_var_check", lineno):
                continue
            findings.append(
                build_finding(
                    check_id="config.missing_env_var_check",
                    category=GateCategory.CONFIG_SSOT,
                    title=f"Unguarded os.environ[\"{varname}\"] at {normalized}:{lineno}",
                    severity=GateSeverity.MEDIUM,
                    impact=GateImpact.REVISE,
                    summary=(
                        f"{normalized} line {lineno}: os.environ[\"{varname}\"] raises KeyError "
                        "if the variable is absent. No try/except KeyError or "
                        f"'if \"{varname}\" in os.environ:' guard is present in the enclosing function."
                    ),
                    recommendation=(
                        f"Replace os.environ[\"{varname}\"] with "
                        f"os.environ.get(\"{varname}\", DEFAULT) "
                        f"or add an explicit presence check: "
                        f"if \"{varname}\" not in os.environ: raise RuntimeError(...)."
                    ),
                    evidence=[
                        EvidenceReference(
                            kind="file",
                            path=normalized,
                            detail=f"line:{lineno}",
                        )
                    ],
                    repair_kind=RepairKind.VALIDATE_BOUNDARY.value,
                    executor_action=(
                        f"Replace os.environ[\"{varname}\"] with "
                        f"os.environ.get(\"{varname}\", DEFAULT) or explicit missing check"
                    ),
                    proof_required=(
                        f"No unguarded os.environ[\"{varname}\"] subscript access remains"
                    ),
                    allowlist_allowed=True,
                )
            )

        # --- config.unguarded_env_access.hardcoded_path (Sprint F-4) ---
        for hit in _find_hardcoded_paths(src, normalized, project_dir=ctx.project_dir):
            value = hit["value"]
            variant = hit["variant"]
            lineno = hit["line"]
            severity = hit["severity"]
            deployment = hit["deployment"]
            if has_allowlist_for(src, "config.unguarded_env_access.hardcoded_path", lineno):
                continue
            if has_allowlist_for(src, "config.unguarded_env_access", lineno):
                # Parent id allowlist also suppresses the variant.
                continue
            findings.append(
                build_finding(
                    check_id="config.unguarded_env_access.hardcoded_path",
                    category=GateCategory.CONFIG_SSOT,
                    title=(
                        f"Hardcoded {variant.replace('_', ' ')}: {value!r} "
                        f"at {normalized}:{lineno}"
                    ),
                    severity=severity,
                    impact=GateImpact.REVISE,
                    summary=(
                        f"{normalized} line {lineno}: launch/runtime path is the "
                        f"hardcoded literal {value!r} (variant: {variant}). "
                        "This pins execution to a specific machine's filesystem "
                        "layout; the code breaks on any host that does not "
                        f"match. Detected deployment_target: {deployment}."
                    ),
                    recommendation=(
                        "Replace with a portable alternative: "
                        "sys.executable for Python interpreter, "
                        "os.path.expanduser('~/...') or pathlib.Path.home() for "
                        "user paths, importlib.resources for bundled assets, "
                        "or os.environ.get('VAR') for site-specific values."
                    ),
                    evidence=[
                        EvidenceReference(
                            kind="file",
                            path=normalized,
                            detail=f"line:{lineno}",
                        )
                    ],
                    repair_kind=RepairKind.VALIDATE_BOUNDARY.value,
                    executor_action=(
                        f"Replace literal {value!r} with portable equivalent "
                        f"(sys.executable / os.path.expanduser / Path.home / "
                        "importlib.resources / os.environ)."
                    ),
                    proof_required=(
                        "grep shows no remaining hardcoded interpreter / user / "
                        "venv path literals at file launch boundary"
                    ),
                    allowlist_allowed=True,
                    confidence=0.85,
                    applicability="applicable",
                    analysis_mode="ast",
                    applicability_reason=f"deployment_target={deployment}",
                )
            )

    return build_check_result(
        check_id="config_safety",
        category=GateCategory.CONFIG_SSOT,
        findings=findings,
    )
