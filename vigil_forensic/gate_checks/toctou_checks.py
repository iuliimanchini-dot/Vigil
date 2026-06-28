"""TOCTOU check-then-act detector (Finding G.1 plan v7).

Detects Time-Of-Check-To-Time-Of-Use patterns where a resource-existence
check (exists, is_port_in_use, etc.) is immediately followed by a mutation
(write_text, unlink, socket.bind, etc.) without an atomic guard (with-block
or explicit acquire_atomic call) in between.
"""
from __future__ import annotations

import ast
import logging

from vigil_forensic._shared import EvidenceReference, GateCategory, GateImpact, GateSeverity, RepairKind
from vigil_forensic.gate_models import PostExecGateContext
from ..source_analysis import is_source_file
from .common import build_check_result, build_finding, normalize_path

_log = logging.getLogger(__name__)

# Functions whose presence indicates a resource-existence check
CHECK_FUNCS = frozenset({
    "exists",
    "is_file",
    "is_dir",
    "is_port_in_use",
    "is_running",
    "is_pid_alive",
    "is_alive",
})

# Functions whose presence indicates a mutation on the resource
MUTATION_FUNCS = frozenset({
    "write_text",
    "write_bytes",
    "unlink",
    "rename",
    "replace",
    "mkdir",
    "rmdir",
    "rmtree",
    "copy",
    "copy2",
    "move",
    "bind",
})

# Calls that indicate the pattern is guarded atomically
ATOMIC_HINTS = frozenset({
    "acquire_atomic",
    "acquire_atomic_with_atexit",
    "acquire",
})

# Leftmost receiver names recognised as path-handling modules.  When a call
# looks like ``<module>.func('/path', ...)`` we treat the first positional
# string arg as the resource path.  Keep this list conservative to avoid
# mis-extracting payloads from method calls on user objects.
_MODULE_NAMES = frozenset({
    "os",
    "path",
    "pathlib",
    "shutil",
    "io",
})

# How many subsequent statements to inspect after a check-call
_LOOKAHEAD = 10


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

from .atomic_write_checks import _get_call_name


def _get_receiver_var(node: ast.Call) -> str | None:
    """Return the variable name of the method receiver, if any."""
    if isinstance(node.func, ast.Attribute):
        if isinstance(node.func.value, ast.Name):
            return node.func.value.id
    return None


def _extract_literal_path(call_node: ast.Call) -> str | None:
    """Return a string literal that identifies the resource being operated on.

    Two patterns are handled, in this order of priority:

    1. Method-on-constructor — ``Path('/tmp/x').exists()``,
       ``Path('/tmp/x').write_text('data')``:
       The call is an attribute access whose receiver is itself a ``Call``
       (e.g. ``Path('...')``) with a string-literal first positional argument.
       We extract the literal from the *receiver*, because the outer call's
       first positional arg is typically payload data (e.g. ``'data'`` for
       ``write_text``), not a path.

    2. Direct string arg — ``os.path.exists('/tmp/x')`` or
       ``open('/tmp/x', 'w')``:
       The call is a free function (``ast.Name``) or a non-constructor
       attribute chain (e.g. ``os.path.exists``) whose first positional
       argument is a string constant representing the resource path.

    We explicitly gate pattern 2 on the call *not* being a method call whose
    receiver looks like a path-constructor call, to avoid misinterpreting
    ``Path('/tmp/x').write_text('data')`` as the resource being ``'data'``.
    """
    # Pattern 1: method call on a constructor-style receiver
    # e.g.  Path('/tmp/x').exists()  →  func = Attribute(value=Call(args=['/tmp/x']), attr='exists')
    # The receiver itself carries the path literal; the outer call's first
    # positional arg (if any) is typically payload, not a path.
    if isinstance(call_node.func, ast.Attribute):
        receiver = call_node.func.value
        if isinstance(receiver, ast.Call):
            if receiver.args:
                inner_arg = receiver.args[0]
                if isinstance(inner_arg, ast.Constant) and isinstance(inner_arg.value, str):
                    return inner_arg.value
            # Receiver is a Call but no literal arg → unknown, do not fall
            # through to outer args (they are payload for the method).
            return None
        # Receiver is a Name / Attribute (e.g. ``p.write_text('data')`` or
        # ``os.path.exists('/tmp/x')``).  For free-function-style attribute
        # chains like ``os.path.exists``, the first positional arg IS a path;
        # for bound method calls like ``p.write_text``, the first positional
        # arg is payload.  We cannot distinguish these at pure-AST level
        # without a whitelist, so we only extract the literal when the
        # attribute chain's leftmost receiver is a Name that looks like a
        # module (os, path, pathlib, shutil).  This keeps the check precise
        # for free functions while avoiding payload-as-path FPs on methods.
        if isinstance(receiver, ast.Name) and receiver.id in _MODULE_NAMES:
            if call_node.args:
                arg = call_node.args[0]
                if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
                    return arg.value
        # Otherwise (bound method on a plain variable) → no literal
        return None

    # Pattern 2: plain free function (``exists('/tmp/x')``, ``open('/tmp/x', 'w')``):
    # func is an ``ast.Name``.  First positional string arg is the path.
    if isinstance(call_node.func, ast.Name) and call_node.args:
        arg = call_node.args[0]
        if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
            return arg.value

    return None


def _collect_alias_assignments(
    func_node: ast.FunctionDef | ast.AsyncFunctionDef,
) -> dict[str, int]:
    """Return mapping of assigned variable name → statement index in func body.

    Only considers top-level Assign statements (not augmented, not annotated)
    with a single Name target.  Used to detect simple aliasing:
        lock_file = base / "lock"
    where both the check and the mutation reference ``lock_file``.
    """
    result: dict[str, int] = {}
    for idx, stmt in enumerate(func_node.body):
        if isinstance(stmt, ast.Assign):
            for target in stmt.targets:
                if isinstance(target, ast.Name):
                    result[target.id] = idx
    return result


def _find_check_call(stmt: ast.stmt) -> dict | None:
    """Return {func, var, literal, line} if *stmt* contains a CHECK_FUNCS call; else None."""
    for node in ast.walk(stmt):
        if isinstance(node, ast.Call):
            name = _get_call_name(node)
            if name in CHECK_FUNCS:
                return {
                    "func": name,
                    "var": _get_receiver_var(node),
                    "literal": _extract_literal_path(node),
                    "line": node.lineno,
                    "call_node": node,
                }
    return None


def _find_mutation_call(stmt: ast.stmt) -> dict | None:
    """Return {func, var, literal, line} if *stmt* contains a MUTATION_FUNCS call; else None."""
    for node in ast.walk(stmt):
        if isinstance(node, ast.Call):
            name = _get_call_name(node)
            if name in MUTATION_FUNCS:
                return {
                    "func": name,
                    "var": _get_receiver_var(node),
                    "literal": _extract_literal_path(node),
                    "line": node.lineno,
                    "call_node": node,
                }
    return None


def _has_atomic_call(stmt: ast.stmt) -> bool:
    """Return True if *stmt* contains any ATOMIC_HINTS call."""
    for node in ast.walk(stmt):
        if isinstance(node, ast.Call):
            if _get_call_name(node) in ATOMIC_HINTS:
                return True
    return False


def _same_resource(
    check: dict,
    mutation: dict,
    alias_assignments: dict[str, int] | None = None,
) -> bool:
    """Return True when check and mutation operate on the same resource.

    Three matching strategies (in priority order):

    1. Literal string match — both calls pass an identical string constant as
       their first positional argument, e.g.::

           Path("/tmp/x").exists()   →  Path("/tmp/x").write_text(...)

    2. Same receiver variable — both calls are method calls on the same Name
       node, e.g.::

           p.exists()   →  p.write_text(...)

    3. Alias match — both receiver variables were assigned in the same function
       scope (via a simple ``Name = <expr>`` assignment), indicating they are
       aliases for a common underlying resource, e.g.::

           lock_file = base / "lock"
           lock_file.exists()   →  lock_file.write_text(...)

       Note: strategy 3 only fires when both calls reference the *same*
       variable name that appears in ``alias_assignments``.  It does NOT fire
       when two *different* aliased variables are used (different-aliases case),
       because that would require value-equality analysis beyond AST scope.
    """
    # Strategy 1: literal string comparison
    lit_c = check.get("literal")
    lit_m = mutation.get("literal")
    if lit_c is not None and lit_m is not None and lit_c == lit_m:
        return True

    # Strategy 2: same receiver variable name
    var_c = check.get("var")
    var_m = mutation.get("var")
    if var_c and var_m:
        if var_c == var_m:
            return True
        # Strategy 3: alias — different variable names that were both assigned
        # in the same scope.  We only flag when they share the *same* name
        # (strategy 2 already covers that), so reaching here means var_c !=
        # var_m → skip to avoid false positives on truly different aliases.

    # Cannot confirm same resource → conservative, do not flag
    return False


def _detect_toctou_in_function(
    func_node: ast.FunctionDef | ast.AsyncFunctionDef,
    file_path: str,
) -> list[dict]:
    """Walk top-level statements of a function and return raw finding dicts."""
    raw: list[dict] = []
    body = func_node.body
    alias_assignments = _collect_alias_assignments(func_node)
    for i, stmt in enumerate(body):
        check_info = _find_check_call(stmt)
        if not check_info:
            continue
        for look_ahead in body[i + 1: i + 1 + _LOOKAHEAD]:
            # A with-block implies context manager / lock → safe
            if isinstance(look_ahead, ast.With):
                break
            # An explicit atomic-hint call → safe
            if _has_atomic_call(look_ahead):
                break
            mut_info = _find_mutation_call(look_ahead)
            if mut_info and _same_resource(check_info, mut_info, alias_assignments):
                raw.append({
                    "file": file_path,
                    "check_func": check_info["func"],
                    "check_line": check_info["line"],
                    "mut_func": mut_info["func"],
                    "mut_line": mut_info["line"],
                })
                break
    return raw


# ---------------------------------------------------------------------------
# Public gate entry-point
# ---------------------------------------------------------------------------

def run_toctou_check_then_act(ctx: PostExecGateContext):
    """Detect TOCTOU check-then-act races in changed Python files.

    For each .py file in ctx.changed_files_observed:
    1. Parse the AST.
    2. Walk all function defs (including nested ones).
    3. Within each function body, detect a check-call immediately followed
       (within _LOOKAHEAD statements) by a mutation on the same resource,
       with no intervening with-block or atomic-hint call.

    Fail-open: parse errors / missing files -> DEBUG log, skip, never raise.
    """
    findings = []

    for raw_path in ctx.changed_files_observed:
        normalized = normalize_path(raw_path)
        if not is_source_file(normalized):
            continue

        abs_path = ctx.project_dir / normalized
        try:
            src = abs_path.read_text(encoding="utf-8")
            tree = ast.parse(src)
        except (OSError, SyntaxError, UnicodeDecodeError) as exc:
            _log.debug("toctou_check: failed to parse %s: %s", normalized, exc)
            continue

        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                raw_hits = _detect_toctou_in_function(node, normalized)
                for hit in raw_hits:
                    findings.append(
                        build_finding(
                            check_id="toctou_check_then_act.race_window",
                            category=GateCategory.RUNTIME_BEHAVIOR,
                            title="TOCTOU race: non-atomic check-then-act on shared resource",
                            severity=GateSeverity.MEDIUM,
                            impact=GateImpact.REVISE,
                            summary=(
                                f"{hit['file']}: {hit['check_func']}() at line "
                                f"{hit['check_line']} followed by {hit['mut_func']}() "
                                f"at line {hit['mut_line']} without atomic guard -- "
                                "another process may alter the resource between check and act."
                            ),
                            recommendation=(
                                "Wrap the check+act sequence in a context manager or use an "
                                "atomic operation (e.g. open(..., 'x'), os.replace, "
                                "acquire_atomic) to eliminate the race window."
                            ),
                            evidence=[
                                EvidenceReference(
                                    kind="file",
                                    path=hit["file"],
                                    detail=(
                                        f"check={hit['check_func']}:L{hit['check_line']} "
                                        f"mutation={hit['mut_func']}:L{hit['mut_line']}"
                                    ),
                                )
                            ],
                            repair_kind=RepairKind.ADD_BOUNDARY_CHECK.value,
                            executor_action="Add check-then-act guard",
                            proof_required="TOCTOU pattern fixed",
                            allowlist_allowed=False,
                        )
                    )

    return build_check_result(
        check_id="toctou_check_then_act",
        category=GateCategory.RUNTIME_BEHAVIOR,
        findings=findings,
    )
