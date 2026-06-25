"""Atomic-write safety detector (Finding G.2 plan v7; FP reduction F.9b, F.10, F.16a).

Detects write_text / write_bytes / open(..., "w"|"wb"|"a"|"ab") calls in a
function body that lack a surrounding tmpfile+rename atomic pattern.

A write is considered safe when the same function body contains:
  - a Path.replace or os.replace / os.rename call, AND
  - at least one reference to a .tmp suffix path (name ending in ".tmp" or
    variable name containing "tmp").

Sprint B3 (2026-04-23) — ArtifactRoleMap migration (non-destructive):

  When ``ctx.project_context.artifact_roles`` is available, each write site
  receives a role classification from ``SYSTEM.shared_helpers.artifact_role``
  and the gate derives tri-state applicability via ``_applicability_for_role``:

    shared_state / config / manifest → applicable      (atomicity matters)
    per_run_output / temp / log       → not_applicable (structurally irrelevant)
    cache / unknown                   → unknown        (reviewer judges)

  Confidence is adjusted by risk signals that do NOT gate applicability:
    * cross-file read-back        → +0.10 (real race window)
    * same-file-only read-back    → -0.10 (single-process round-trip)
    * enclosing function is init  → -0.15 (one-time execution)

  When ``artifact_roles`` is None (pre-Sprint-B3 callers), the legacy
  classification path is preserved — same behaviour as F.9b/F.10/F.16a.

Legacy heuristics (read-back manifest, state-file variable names, per-call
unique markers, init-path downgrade) are preserved INSIDE ArtifactRoleMap
(where appropriate) AND as the legacy fallback path. Risk signals
(read-back, init-path) stay visible in the gate as confidence adjusters —
never collapsed into applicability.

Fail-open: parse errors / missing files -> DEBUG log, skip, never raise.
"""
from __future__ import annotations

import ast
import logging
from pathlib import Path
from typing import Iterable

from cortex_forensic._shared import EvidenceReference, GateCategory, GateImpact, GateSeverity, RepairKind
from cortex_forensic.gate_models import PostExecGateContext
from ..source_analysis import is_source_file
from .common import build_check_result, build_finding, normalize_path
from ._ast_helpers import parse_python_source_or_emit_finding

_log = logging.getLogger(__name__)

# Method names that represent a direct write without explicit tmpfile routing
WRITE_METHODS = frozenset({
    "write_text",
    "write_bytes",
})

# open() mode strings that indicate a write (not read-only)
WRITE_MODES = frozenset({"w", "wb", "a", "ab", "w+", "wb+", "a+", "ab+"})

# open() mode strings that indicate a read (used by read-manifest builder)
READ_MODES = frozenset({"r", "rb", "rt", "r+", "rb+"})

# Method / function names that indicate an atomic rename/replace finalisation
REPLACE_FUNCS = frozenset({
    "replace",
    "rename",
})

# os-module names that expose rename/replace as free functions
OS_REPLACE_NAMES = frozenset({
    "os.replace",
    "os.rename",
    "os.renames",
    "shutil.move",
})

# Path-method names that indicate a file read (used by read-manifest builder)
READ_METHODS = frozenset({
    "read_text",
    "read_bytes",
})

# Function-name patterns that identify single-writer init/bootstrap paths
# (Part 3: downgrade MEDIUM → LOW because there's only one writer).
_INIT_PATH_PREFIXES = ("_init_", "configure_", "setup_", "ensure_")
_INIT_PATH_EXACT = frozenset({"_bootstrap", "bootstrap", "_configure", "_setup"})

# F9b-tighten (2026-04-23): persistence-naming prefixes — when a non-literal
# write occurs inside a function whose name starts with one of these, we treat
# it as a probable persistence site (manual review needed rather than silent
# drop). See Fix A in task tracker 2026-04-23.
_PERSISTENCE_PREFIXES = (
    "save_", "persist_", "write_", "dump_", "flush_", "store_",
    "commit_", "sync_",
)

# F.16a (2026-04-23): Names / call-targets that prove the write-target path is
# per-call-unique. When any of these appears in the path-derivation AST, the
# finding is suppressed (no race possible — every invocation writes to a
# distinct filename).
#
# Two detection sources:
#   * _UNIQUE_CALL_NAMES: dotted/bare call names like ``time.time``, ``uuid4``.
#   * _UNIQUE_VAR_NAMES : variable names that hold a per-call-unique token,
#                         typically substituted into an f-string/format.

_UNIQUE_CALL_NAMES = frozenset({
    # time-based
    "time",             # time.time() → Attribute call; attr == "time"
    "time_ns",
    "monotonic",
    "monotonic_ns",
    "perf_counter",
    "perf_counter_ns",
    "now",              # datetime.now / datetime.utcnow consumer
    "utcnow",
    "today",
    # uuid-based
    "uuid1",
    "uuid3",
    "uuid4",
    "uuid5",
    "token_hex",        # secrets.token_hex
    "token_urlsafe",
    "token_bytes",
    # random/sequence
    "randbits",
    "getrandbits",
    "next",             # next(counter) — iterator sequence
})

_UNIQUE_VAR_NAMES = frozenset({
    "session_num",
    "session_number",
    "attempt_id",
    "attempt_num",
    "attempt",
    "iteration",
    "iter_num",
    "timestamp",
    "ts",
    "ts_ms",
    "ts_ns",
    "now",
    "now_ts",
    "nonce",
    "request_id",
    "run_id",
    "correlation_id",
    "trace_id",
    "pid",
})

# F.16a (2026-04-23): Variable-name hints that suggest a state file (canonical
# write target with a fixed path). When a non-literal write target binds to a
# variable matching these, we keep the finding at MEDIUM even without a
# persistence-named enclosing function.

_STATE_FILE_NAME_FRAGMENTS = (
    "state_path",
    "_state_path",
    "state_file",
    "_state_file",
    "config_path",
    "_config_path",
    "config_file",
    "_config_file",
    "cache_path",
    "_cache_path",
    "cache_file",
    "_cache_file",
    "lock_path",
    "_lock_path",
    "lock_file",
    "_lock_file",
    "ledger_path",
    "ledger_file",
    "session_store",
    "db_path",
    "manifest_path",
    "manifest_file",
    "status_path",
    "status_file",
    "active_path",
    "active_file",
    "answer_file",
    "heartbeat_path",
    "heartbeat_file",
    "sidecar",
)


# ---------------------------------------------------------------------------
# Path classifiers (Part 1)
# ---------------------------------------------------------------------------

def _is_test_or_libs_path(path: str, ctx: object = None) -> bool:
    """True if *path* should be skipped as a test-fixture or vendored-libs file.

    Sprint C2 (2026-04-23): prefers ``ctx.project_context.test_topology.
    is_test_path(rel_path)`` when a ``PostExecGateContext`` is threaded
    through. Legacy path-fragment check preserved as fallback so callers
    that don't have a ctx (older tests, direct invocations) continue to
    work exactly as before.

    Matches (legacy fallback):
      - anything under SYSTEM/dev/tests/
      - anything containing /tests/ as a path component
      - anything under SYSTEM/libs/ (vendored deps)
    """
    p = (path or "").replace("\\", "/")
    # SYSTEM/libs is always skipped regardless of topology — vendored deps
    # are never inside the project's test surface but also never inside the
    # code surface the gate cares about.
    if p.startswith("SYSTEM/libs/") or "/SYSTEM/libs/" in p:
        return True
    topology = getattr(getattr(ctx, "project_context", None), "test_topology", None)
    if topology is not None:
        if topology.is_test_path(p):
            return True
        # Topology says "not a test" — trust it. Don't fall back to the
        # basename check because that would re-introduce the false positive
        # topology is designed to eliminate.
        return False
    # Legacy fallback: no ctx / no topology available.
    if p.startswith("SYSTEM/dev/tests/"):
        return True
    if "/tests/" in p or p.startswith("tests/"):
        return True
    return False


# ---------------------------------------------------------------------------
# AST helpers
# ---------------------------------------------------------------------------

def _get_call_name(node: ast.Call) -> str | None:
    """Return the bare method/function name from a Call node."""
    if isinstance(node.func, ast.Attribute):
        return node.func.attr
    if isinstance(node.func, ast.Name):
        return node.func.id
    return None


def _get_dotted_name(node: ast.Call) -> str | None:
    """Return 'module.attr' for calls like os.replace(...)."""
    if isinstance(node.func, ast.Attribute):
        if isinstance(node.func.value, ast.Name):
            return f"{node.func.value.id}.{node.func.attr}"
    return None


def _get_literal_path_arg(node: ast.Call) -> str | None:
    """Return the string literal that names the file path, or None.

    Dispatch by call form:
      - ``open(path, mode)``      → literal path is ``node.args[0]``
      - ``x.write_text(content)`` → literal path is the **receiver** (node.func.value)
      - ``x.write_bytes(content)`` / ``x.read_text()`` / ``x.read_bytes()`` → same
      - ``Path("lit").write_text(...)`` → receiver is a Call; unwrap Path(...)
    """
    name = _get_call_name(node)

    # open(path, mode) — literal path is args[0]
    if name == "open":
        if node.args:
            first = node.args[0]
            if isinstance(first, ast.Constant) and isinstance(first.value, str):
                return first.value
        return None

    # Method-style path ops: write_text / write_bytes / read_text / read_bytes
    # The path is the receiver, not args[0] (which is content / encoding / etc).
    if isinstance(node.func, ast.Attribute):
        receiver = node.func.value
        # Case 1: receiver itself is a literal string, e.g. "path/to/file".read_text()
        # (rare in practice but handle defensively)
        if isinstance(receiver, ast.Constant) and isinstance(receiver.value, str):
            return receiver.value
        # Case 2: Path("lit").write_text(...) / Path("lit").read_text()
        if isinstance(receiver, ast.Call):
            callee = _get_call_name(receiver)
            if callee == "Path" and receiver.args:
                inner = receiver.args[0]
                if isinstance(inner, ast.Constant) and isinstance(inner.value, str):
                    return inner.value
    return None


def _is_write_call(node: ast.Call) -> tuple[bool, int]:
    """Return (True, lineno) if the call is a bare write_text/write_bytes."""
    name = _get_call_name(node)
    if name in WRITE_METHODS:
        return True, node.lineno
    return False, 0


def _is_open_write(node: ast.Call) -> tuple[bool, int]:
    """Return (True, lineno) if open() is called with a write mode.

    Handles positional mode arg and keyword mode= arg.
    """
    name = _get_call_name(node)
    if name != "open":
        return False, 0

    # positional: open(path, "w")
    if len(node.args) >= 2:
        mode_arg = node.args[1]
        if isinstance(mode_arg, ast.Constant) and mode_arg.value in WRITE_MODES:
            return True, node.lineno

    # keyword: open(path, mode="w")
    for kw in node.keywords:
        if kw.arg == "mode" and isinstance(kw.value, ast.Constant):
            if kw.value.value in WRITE_MODES:
                return True, node.lineno

    return False, 0


def _has_atomic_pattern(func_node: ast.FunctionDef | ast.AsyncFunctionDef) -> bool:
    """Return True if the function body contains a replace/rename call AND
    a reference to a '.tmp'-suffix string or 'tmp'-containing variable name.
    """
    has_replace = False
    has_tmp_ref = False

    for node in ast.walk(func_node):
        if isinstance(node, ast.Call):
            # Method-style: x.replace(...) / x.rename(...)
            if _get_call_name(node) in REPLACE_FUNCS:
                has_replace = True
            # Free-function style: os.replace(...) / os.rename(...)
            dotted = _get_dotted_name(node)
            if dotted and dotted in OS_REPLACE_NAMES:
                has_replace = True

        # String literal containing ".tmp"
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            if ".tmp" in node.value:
                has_tmp_ref = True

        # Variable / attribute name containing "tmp"
        if isinstance(node, ast.Name) and "tmp" in node.id.lower():
            has_tmp_ref = True
        if isinstance(node, ast.Attribute) and "tmp" in node.attr.lower():
            has_tmp_ref = True

    return has_replace and has_tmp_ref


# ---------------------------------------------------------------------------
# Read-source manifest (Part 2)
# ---------------------------------------------------------------------------

def _collect_read_literals(tree: ast.AST) -> set[str]:
    """Return the set of string literals that appear as read-source targets.

    Recognised patterns (each yields the literal string argument):
      - open("lit")                         # default mode → read
      - open("lit", "r" / "rb" / ...)
      - open("lit", mode="r")
      - Path("lit").read_text() / .read_bytes()
      - json.load(open("lit"))              # indirect, handled by open() above
      - json.loads(Path("lit").read_text()) # handled by read_text above
      - x.read_text() / .read_bytes() where receiver is Path("lit")
    """
    literals: set[str] = set()

    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue

        name = _get_call_name(node)

        # open(path, mode) — classify mode
        if name == "open" and node.args:
            first = node.args[0]
            if not (isinstance(first, ast.Constant) and isinstance(first.value, str)):
                continue
            mode: str | None = None
            if len(node.args) >= 2:
                mode_arg = node.args[1]
                if isinstance(mode_arg, ast.Constant) and isinstance(mode_arg.value, str):
                    mode = mode_arg.value
            for kw in node.keywords:
                if kw.arg == "mode" and isinstance(kw.value, ast.Constant):
                    if isinstance(kw.value.value, str):
                        mode = kw.value.value
            # No mode → default "r" (read). Explicit read mode → read.
            if mode is None or mode in READ_MODES:
                literals.add(first.value)
            continue

        # *.read_text() / *.read_bytes()
        if name in READ_METHODS:
            lit = _get_literal_path_arg(node)
            if lit is not None:
                literals.add(lit)

    return literals


def _build_read_manifest(
    project_dir: Path,
    changed_files: Iterable[str],
    file_snapshots: dict,
) -> dict[str, set[str]]:
    """Build a dict: literal_path_string -> set of file paths that read it.

    Sources:
      - ``file_snapshots`` when available (already-loaded text).
      - Falls back to reading the file from disk.

    Fail-open: per-file parse/IO errors logged DEBUG, skipped.
    """
    manifest: dict[str, set[str]] = {}

    for raw_path in changed_files:
        normalized = normalize_path(raw_path)
        if not is_source_file(normalized):
            continue

        src: str | None = None
        snap = file_snapshots.get(normalized) if file_snapshots else None
        if snap is not None and getattr(snap, "text", None):
            src = snap.text
        else:
            try:
                src = (project_dir / normalized).read_text(encoding="utf-8")
            except (OSError, UnicodeDecodeError) as exc:
                _log.debug("atomic_write: read-manifest IO for %s: %s", normalized, exc)
                continue

        try:
            tree = ast.parse(src)
        except SyntaxError as exc:
            _log.debug("atomic_write: read-manifest parse %s: %s", normalized, exc)
            continue

        for lit in _collect_read_literals(tree):
            manifest.setdefault(lit, set()).add(normalized)

    return manifest


# ---------------------------------------------------------------------------
# Write collection
# ---------------------------------------------------------------------------

def _is_init_path_function(func_name: str) -> bool:
    """True if *func_name* matches the single-writer init/bootstrap heuristic."""
    if not func_name:
        return False
    if func_name in _INIT_PATH_EXACT:
        return True
    return any(func_name.startswith(prefix) for prefix in _INIT_PATH_PREFIXES)


def _is_persistence_named_function(func_name: str) -> bool:
    """F9b-tighten: True if *func_name* looks like a persistence sink.

    Non-literal writes inside such functions are NOT silently dropped — we
    emit a MEDIUM finding with "manual review needed" note. This catches
    blind-spot A: variable write targets (e.g. `artifact_path.write_text(...)`)
    that previously bypassed the read-back manifest check entirely.
    """
    if not func_name:
        return False
    return any(func_name.startswith(prefix) for prefix in _PERSISTENCE_PREFIXES)


def _collect_unsafe_writes(
    func_node: ast.FunctionDef | ast.AsyncFunctionDef,
    file_path: str,
) -> list[dict]:
    """Return raw finding dicts for each unguarded write in the function.

    Each dict includes:
      - file, write_func, line (as before)
      - func_name: enclosing function name (for Part 3 init-path heuristic)
      - write_literal: the string literal written to, if any (for Part 2)
      - target_expr: AST node for the write-target expression (F.16a path-hint)
      - target_var_name: bare variable/attribute name bound to the target
        (F.16a state-file-name heuristic)
      - func_node: reference to the enclosing function (F.16a assignment walk)
    """
    raw: list[dict] = []

    # If the function already has the atomic pattern, none of its writes are flagged
    if _has_atomic_pattern(func_node):
        return raw

    func_name = getattr(func_node, "name", "") or ""

    for node in ast.walk(func_node):
        if not isinstance(node, ast.Call):
            continue

        flagged, lineno = _is_write_call(node)
        if flagged:
            target_expr = _extract_write_target_expr(node)
            raw.append({
                "file": file_path,
                "write_func": _get_call_name(node),
                "line": lineno,
                "func_name": func_name,
                "write_literal": _get_literal_path_arg(node),
                "target_expr": target_expr,
                "target_var_name": _extract_target_var_name(target_expr),
                "func_node": func_node,
            })
            continue

        flagged, lineno = _is_open_write(node)
        if flagged:
            # Determine the mode string for the finding message
            mode = "w"
            if len(node.args) >= 2 and isinstance(node.args[1], ast.Constant):
                mode = node.args[1].value
            for kw in node.keywords:
                if kw.arg == "mode" and isinstance(kw.value, ast.Constant):
                    mode = kw.value.value
            target_expr = _extract_write_target_expr(node)
            raw.append({
                "file": file_path,
                "write_func": f'open(..., "{mode}")',
                "line": lineno,
                "func_name": func_name,
                "write_literal": _get_literal_path_arg(node),
                "target_expr": target_expr,
                "target_var_name": _extract_target_var_name(target_expr),
                "func_node": func_node,
            })

    return raw


# ---------------------------------------------------------------------------
# F.16a: per-call-unique path detection (path-hint heuristic)
# ---------------------------------------------------------------------------

def _expr_contains_unique_marker(expr: ast.AST | None) -> bool:
    """Return True if *expr* (or any subtree) contains a per-call-unique marker.

    Recognised markers:
      * Call to a function whose bare or dotted name ends in one of
        ``_UNIQUE_CALL_NAMES`` (``time.time``, ``uuid.uuid4``,
        ``datetime.now`` …).
      * Reference to a Name whose id is in ``_UNIQUE_VAR_NAMES``
        (``session_num``, ``attempt_id``, ``timestamp`` …). This catches
        f-strings like ``f"audit_{timestamp}.json"`` and format args like
        ``f"session_{session_num:03d}.json"``.

    Safe for any expression node; returns False on None.
    """
    if expr is None:
        return False
    for node in ast.walk(expr):
        if isinstance(node, ast.Call):
            name = _get_call_name(node)
            if name and name in _UNIQUE_CALL_NAMES:
                return True
        elif isinstance(node, ast.Name):
            if node.id in _UNIQUE_VAR_NAMES:
                return True
        elif isinstance(node, ast.Attribute):
            # e.g. self.session_num — treat attribute suffix as a name hint.
            if node.attr in _UNIQUE_VAR_NAMES:
                return True
    return False


def _var_name_suggests_state_file(var_name: str | None) -> bool:
    """True if *var_name* suggests a canonical state-file path.

    Matches whole-name or suffix fragments in ``_STATE_FILE_NAME_FRAGMENTS``.
    """
    if not var_name:
        return False
    lowered = var_name.lower()
    for frag in _STATE_FILE_NAME_FRAGMENTS:
        if lowered == frag or lowered.endswith("_" + frag) or lowered.endswith(frag):
            return True
    return False


def _extract_write_target_expr(call_node: ast.Call) -> ast.AST | None:
    """Return the AST expression that evaluates to the write target path.

    For ``path.write_text(...)`` / ``path.write_bytes(...)``: the *receiver*
    (``call_node.func.value``) — e.g. a Name ``path``, a BinOp
    ``gates_dir / "status.json"``, or a Call ``Path("...")``.

    For ``open(path, "w")``: the first positional arg.

    Returns None when the target shape is unexpected.
    """
    name = _get_call_name(call_node)
    if name == "open":
        if call_node.args:
            return call_node.args[0]
        return None
    if isinstance(call_node.func, ast.Attribute) and name in WRITE_METHODS:
        return call_node.func.value
    return None


def _extract_target_var_name(target_expr: ast.AST | None) -> str | None:
    """Return the binding variable name for a write-target expression, or None.

    Handles:
      * Name                          → id
      * Attribute (self.foo_path)     → attr
      * BinOp / Call (inline)         → None (no single binding name)
    """
    if isinstance(target_expr, ast.Name):
        return target_expr.id
    if isinstance(target_expr, ast.Attribute):
        return target_expr.attr
    return None


def _find_assignment_rhs(
    func_node: ast.FunctionDef | ast.AsyncFunctionDef,
    var_name: str,
    before_lineno: int,
) -> ast.AST | None:
    """Return the RHS of the most recent assignment to *var_name* before *before_lineno*.

    Walks the function body in source order. Handles:
      * ``x = expr``              (ast.Assign with Name target)
      * ``x: T = expr``           (ast.AnnAssign)
      * ``self.x = expr``         (Attribute target, matched by attr name)

    Returns the last-before-lineno matching RHS AST node, or None if no
    assignment found. Used by the per-call-unique heuristic to analyse how
    the write-target variable was derived.
    """
    last_rhs: ast.AST | None = None
    for node in ast.walk(func_node):
        if isinstance(node, ast.Assign):
            if node.lineno >= before_lineno:
                continue
            for tgt in node.targets:
                if isinstance(tgt, ast.Name) and tgt.id == var_name:
                    last_rhs = node.value
                    break
                if isinstance(tgt, ast.Attribute) and tgt.attr == var_name:
                    last_rhs = node.value
                    break
        elif isinstance(node, ast.AnnAssign):
            if node.lineno >= before_lineno or node.value is None:
                continue
            tgt = node.target
            if isinstance(tgt, ast.Name) and tgt.id == var_name:
                last_rhs = node.value
            elif isinstance(tgt, ast.Attribute) and tgt.attr == var_name:
                last_rhs = node.value
    return last_rhs


def _collect_tempdir_bindings(
    func_node: ast.FunctionDef | ast.AsyncFunctionDef,
) -> set[str]:
    """Return the set of variable names bound to tempfile.* results in the function.

    Captures:
      * ``x = tempfile.mkdtemp(...)`` / ``tempfile.mkstemp(...)``
      * ``with tempfile.TemporaryDirectory(...) as x:``
      * ``x = Path(tempfile.mkdtemp(...))`` — Path() wrapper unwrapped

    These bindings hold filesystem paths whose leaf component is guaranteed
    unique by the OS, so any write derived from them is per-call-unique and
    concurrency-safe (no concurrent process can guess the name).
    """
    tempdir_names: set[str] = set()

    def _call_is_tempfile(call: ast.Call) -> bool:
        # tempfile.mkdtemp / tempfile.mkstemp / tempfile.TemporaryDirectory
        if isinstance(call.func, ast.Attribute) and isinstance(call.func.value, ast.Name):
            if call.func.value.id == "tempfile" and call.func.attr in {
                "mkdtemp", "mkstemp", "TemporaryDirectory", "NamedTemporaryFile",
            }:
                return True
        # Bare imports: mkdtemp(...), TemporaryDirectory(...)
        if isinstance(call.func, ast.Name) and call.func.id in {
            "mkdtemp", "mkstemp", "TemporaryDirectory", "NamedTemporaryFile",
        }:
            return True
        # Path(tempfile.mkdtemp(...)) — unwrap
        if isinstance(call.func, ast.Name) and call.func.id == "Path" and call.args:
            inner = call.args[0]
            if isinstance(inner, ast.Call) and _call_is_tempfile(inner):
                return True
        return False

    for node in ast.walk(func_node):
        if isinstance(node, ast.Assign):
            if isinstance(node.value, ast.Call) and _call_is_tempfile(node.value):
                for tgt in node.targets:
                    if isinstance(tgt, ast.Name):
                        tempdir_names.add(tgt.id)
        elif isinstance(node, ast.AnnAssign):
            if (
                node.value is not None
                and isinstance(node.value, ast.Call)
                and _call_is_tempfile(node.value)
                and isinstance(node.target, ast.Name)
            ):
                tempdir_names.add(node.target.id)
        elif isinstance(node, (ast.With, ast.AsyncWith)):
            for item in node.items:
                if (
                    isinstance(item.context_expr, ast.Call)
                    and _call_is_tempfile(item.context_expr)
                    and isinstance(item.optional_vars, ast.Name)
                ):
                    tempdir_names.add(item.optional_vars.id)

    # Transitive closure: pick up re-bindings whose RHS references a tempdir
    # name already in the set, e.g. ``temp_root = Path(temp_dir)`` or
    # ``tmp_proj = Path(td)``. We iterate to a fixed point (bounded: the
    # graph is finite and strictly growing).
    for _ in range(8):  # defensive cap; realistic chains are depth 1-2.
        grew = False
        for node in ast.walk(func_node):
            if isinstance(node, ast.Assign):
                if _expr_references_any_name(node.value, tempdir_names):
                    for tgt in node.targets:
                        if isinstance(tgt, ast.Name) and tgt.id not in tempdir_names:
                            tempdir_names.add(tgt.id)
                            grew = True
            elif isinstance(node, ast.AnnAssign) and node.value is not None:
                if (
                    _expr_references_any_name(node.value, tempdir_names)
                    and isinstance(node.target, ast.Name)
                    and node.target.id not in tempdir_names
                ):
                    tempdir_names.add(node.target.id)
                    grew = True
        if not grew:
            break
    return tempdir_names


def _expr_references_any_name(expr: ast.AST | None, names: set[str]) -> bool:
    """True if *expr* (or any subtree) contains a Name reference in *names*."""
    if expr is None or not names:
        return False
    for node in ast.walk(expr):
        if isinstance(node, ast.Name) and node.id in names:
            return True
    return False


def _path_is_per_call_unique(
    target_expr: ast.AST | None,
    func_node: ast.FunctionDef | ast.AsyncFunctionDef | None,
) -> bool:
    """Return True if the write-target path is provably per-call-unique.

    Strategy:
      1. Inspect *target_expr* itself (e.g. inline
         ``(gates_dir / f"audit_{time.time()}.json")``).
      2. If the target is a bare variable binding, walk back to its most
         recent assignment RHS and inspect that.
      3. Tempdir chain: if the write-target expression references any
         variable bound to a ``tempfile.*`` result (``mkdtemp``,
         ``TemporaryDirectory`` …), the path is OS-guaranteed unique and
         single-writer — suppress.

    A positive hit means every invocation of the enclosing function writes to
    a distinct filename, which makes a crash-torn partial write unobservable
    by any reader (the reader needs the exact same filename and the writer
    never reuses one). The finding is suppressed.
    """
    if target_expr is None:
        return False

    # Step 1 — check the expression itself.
    if _expr_contains_unique_marker(target_expr):
        return True

    # Step 2 — if the expression is a Name / Attribute, walk back to the
    # binding's assignment RHS and check there.
    var_name = _extract_target_var_name(target_expr)
    if var_name and func_node is not None:
        rhs = _find_assignment_rhs(
            func_node,
            var_name,
            before_lineno=getattr(target_expr, "lineno", 10 ** 9),
        )
        if _expr_contains_unique_marker(rhs):
            return True
        # Also check if the RHS itself references a tempdir binding — e.g.
        # ``schema_path = temp_root / "schema.json"`` where ``temp_root``
        # came from ``with TemporaryDirectory() as temp_dir``.
        if func_node is not None:
            tempdir_names = _collect_tempdir_bindings(func_node)
            if _expr_references_any_name(rhs, tempdir_names):
                return True

    # Step 3 — inline expression referencing a tempdir binding, e.g.
    # ``(clean_config_dir / "settings.json").write_text(...)`` where
    # ``clean_config_dir = Path(tempfile.mkdtemp(...))``.
    if func_node is not None:
        tempdir_names = _collect_tempdir_bindings(func_node)
        if _expr_references_any_name(target_expr, tempdir_names):
            return True

    return False


# ---------------------------------------------------------------------------
# Severity / skip classification
# ---------------------------------------------------------------------------

def _classify_severity(
    hit: dict,
    read_manifest: dict[str, set[str]],
) -> tuple[GateSeverity | None, str | None]:
    """Return (severity, extra_note) for the hit, or (None, None) to skip.

    Applies Parts 2, 3, and F9b-tighten:
      * Part 2 (literal target):
          - not read anywhere        → skip
          - read only in same file   → LOW
          - read across files        → MEDIUM (keep)
      * F9b-tighten (non-literal target):
          - func name matches _PERSISTENCE_PREFIXES → MEDIUM with note
          - otherwise                              → LOW with note
      * Part 3 (init/bootstrap): downgrade MEDIUM → LOW (applies after).

    Previously a non-literal write slipped past Part 2 and Part 3 left it at
    its default MEDIUM silently. The new path ALWAYS emits at least a LOW
    finding (blind-spot A) so the artefact is visible to reviewers.
    """
    write_file = hit.get("file") or ""
    write_literal = hit.get("write_literal")
    func_name = hit.get("func_name") or ""

    base_severity: GateSeverity = GateSeverity.MEDIUM
    extra_note: str | None = None

    if write_literal is not None:
        # Part 2 (literal target + read-back analysis).
        readers = read_manifest.get(write_literal, set())
        if not readers:
            # write-only artefact: log output, temp file — no race risk.
            return None, None
        cross_file_readers = readers - {write_file}
        if not cross_file_readers:
            # Same-file reader only: single-writer single-reader, downgrade.
            base_severity = GateSeverity.LOW
    else:
        # Non-literal write target. Apply F.16a path-hint heuristic first:
        #   1. If the path is per-call-unique (timestamp, uuid, session_num
        #      marker in its derivation) → SUPPRESS (no race possible).
        #   2. Else if the binding variable name suggests a state file
        #      (``state_path``, ``status_path``, ``lock_file`` …) → MEDIUM.
        #   3. Else fall back to F.10 function-name heuristic:
        #        - persistence-named function → MEDIUM+note
        #        - otherwise                  → LOW+note
        target_expr = hit.get("target_expr")
        func_node = hit.get("func_node")
        target_var_name = hit.get("target_var_name")

        if _path_is_per_call_unique(target_expr, func_node):
            # F.16a: per-call-unique filename → no race possible, suppress.
            return None, None

        if _var_name_suggests_state_file(target_var_name):
            base_severity = GateSeverity.MEDIUM
            extra_note = (
                f"non-literal target, variable name '{target_var_name}' "
                "suggests state file, manual review needed"
            )
        elif _is_persistence_named_function(func_name):
            base_severity = GateSeverity.MEDIUM
            extra_note = (
                "non-literal target, function name suggests persistence, "
                "manual review needed"
            )
        else:
            base_severity = GateSeverity.LOW
            extra_note = "non-literal write target, read-back unknown"

    # Part 3 (init/bootstrap path downgrade) applies to both branches.
    if _is_init_path_function(func_name):
        if base_severity == GateSeverity.MEDIUM:
            base_severity = GateSeverity.LOW

    return base_severity, extra_note


# ---------------------------------------------------------------------------
# Sprint B3 (2026-04-23) — ArtifactRoleMap applicability mapping
# ---------------------------------------------------------------------------

# Role → (applicability, reason-template) map. per Sprint B3 P1 rule, this
# derives ONLY from structural role — risk signals (read-back, init-path)
# influence confidence, not applicability.
_APPLICABILITY_BY_ROLE = {
    "shared_state": ("applicable", ""),
    "config":       ("applicable", ""),
    "manifest":     ("applicable", ""),
    "per_run_output": ("not_applicable", "role: per_run_output"),
    "temp":         ("not_applicable", "role: temp"),
    "log":          ("not_applicable", "role: log"),
    "cache":        ("unknown", "role: cache"),
    "unknown":      ("unknown", "role: unknown"),
}


def _applicability_for_role(role: str) -> tuple[str, str]:
    """Return (applicability, applicability_reason) for a role.

    Unknown roles fall back to ``unknown`` applicability so the reviewer
    sees the finding flagged rather than silently suppressed.
    """
    return _APPLICABILITY_BY_ROLE.get(role, ("unknown", "role classification failed"))


def _severity_for_applicability(applicability: str) -> "GateSeverity":
    """Role-driven default severity (legacy path keeps its own tuning)."""
    if applicability == "applicable":
        return GateSeverity.MEDIUM
    return GateSeverity.LOW


def _confidence_with_risk_signals(wtc) -> float:
    """Adjust detector confidence by risk signals — never gates applicability.

    * cross-file read-back    → +0.10 (real race window)
    * same-file-only read-back → -0.10 (single-process round-trip)
    * enclosing init path     → -0.15 (one-time execution)
    """
    conf = float(wtc.confidence)
    if wtc.has_read_back_cross_file:
        conf = min(conf + 0.10, 1.0)
    elif wtc.has_read_back_same_file:
        conf = max(conf - 0.10, 0.0)
    if wtc.is_in_init_path:
        conf = max(conf - 0.15, 0.0)
    return conf


# ---------------------------------------------------------------------------
# Public gate entry-point
# ---------------------------------------------------------------------------

def run_atomic_write_safety_checks(ctx: PostExecGateContext):
    """Detect write calls without an atomic tmpfile+rename pattern.

    For each .py file in ctx.changed_files_observed:
    1. Skip if the path lives under tests or vendored libs.
    2. Parse the AST.
    3. Walk all function defs (including nested ones).
    4. For each function lacking a replace/rename + .tmp reference, collect
       candidate unsafe writes.
    5. Classify each hit:
         * if ``ctx.project_context.artifact_roles`` is available, derive
           applicability from the ArtifactRole and adjust confidence with
           read-back + init-path signals (Sprint B3).
         * otherwise fall back to legacy heuristic path (F.9b/F.10/F.16a).

    Fail-open: parse errors / missing files -> DEBUG log, skip, never raise.
    """
    findings = []

    # Sprint B3: prefer role map from ProjectContext when available.
    artifact_map = getattr(getattr(ctx, "project_context", None), "artifact_roles", None)

    # Legacy prerequisite: build the read-source manifest once up front. Still
    # needed for the fallback path and for non-literal heuristics that the
    # ArtifactRoleMap may not attempt at the gate-evidence granularity.
    read_manifest = _build_read_manifest(
        project_dir=ctx.project_dir,
        changed_files=ctx.changed_files_observed,
        file_snapshots=getattr(ctx, "file_snapshots", {}) or {},
    )

    for raw_path in ctx.changed_files_observed:
        normalized = normalize_path(raw_path)
        if not is_source_file(normalized):
            continue

        # Skip tests and vendored libs — these paths don't warrant
        # atomic-write enforcement. Sprint C2: ctx threaded through so the
        # helper can consult ProjectContext.test_topology when present.
        if _is_test_or_libs_path(normalized, ctx):
            continue

        abs_path = ctx.project_dir / normalized
        try:
            src = abs_path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError) as exc:
            _log.debug("atomic_write: failed to read %s: %s", normalized, exc)
            continue

        # B4 (2026-04-23): replaces silent `except SyntaxError` — now emits
        # meta.syntax_parse_error so broken Python is not invisible.
        tree = parse_python_source_or_emit_finding(
            src,
            rel_path=normalized,
            emit_finding=findings.append,
            emitting_gate="atomic_write_safety",
        )
        if tree is None:
            continue

        for node in ast.walk(tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            raw_hits = _collect_unsafe_writes(node, normalized)
            for hit in raw_hits:
                if artifact_map is not None:
                    finding = _build_finding_from_role_map(
                        hit=hit,
                        artifact_map=artifact_map,
                        rel_path=normalized,
                    )
                    if finding is None:
                        continue  # no classification → fall back below
                    findings.append(finding)
                    continue

                # Legacy fallback path (pre-Sprint-B3 callers, no project_context).
                severity, extra_note = _classify_severity(hit, read_manifest)
                if severity is None:
                    continue  # legacy: write-only suppression
                findings.append(_build_legacy_finding(hit, severity, extra_note))

    return build_check_result(
        check_id="atomic_write_safety",
        category=GateCategory.DRIFT,
        findings=findings,
    )


def _build_finding_from_role_map(
    *,
    hit: dict,
    artifact_map,
    rel_path: str,
):
    """Sprint B3 path: apply ArtifactRoleMap to a single write hit.

    Returns a GateFinding with tri-state applicability derived from the role,
    and confidence adjusted by the (preserved) risk signals. Returns ``None``
    when the role map has no classification for this site (signals the
    caller to use the legacy fallback).
    """
    wtc = artifact_map.classify_site(rel_path, hit["line"])
    if wtc is None:
        return None

    applicability, app_reason = _applicability_for_role(wtc.role)
    severity = _severity_for_applicability(applicability)
    confidence = _confidence_with_risk_signals(wtc)

    # Risk-signal suffix for human summaries — visible to the reviewer.
    tags: list[str] = [f"role={wtc.role}"]
    if wtc.has_read_back_cross_file:
        tags.append("cross-file read-back")
    elif wtc.has_read_back_same_file:
        tags.append("same-file read-back")
    if wtc.is_in_init_path:
        tags.append("init path")

    summary = (
        f"{hit['file']}: {hit['write_func']}() at line {hit['line']} writes "
        "directly without a tmpfile+rename guard -- partial writes or "
        f"corruption on crash are possible. ({', '.join(tags)})"
    )

    return build_finding(
        check_id="atomic_write_safety.missing_tmpfile_rename",
        category=GateCategory.DRIFT,
        title="Non-atomic write: missing tmpfile+rename pattern",
        severity=severity,
        impact=GateImpact.REVISE,
        summary=summary,
        recommendation=(
            "Write to a .tmp sibling file first, then atomically rename "
            "it to the target (Path.replace / os.replace). This prevents "
            "readers from observing a partially-written file."
        ),
        evidence=[
            EvidenceReference(
                kind="file",
                path=hit["file"],
                detail=f"write={hit['write_func']}:L{hit['line']}",
            )
        ],
        repair_kind=RepairKind.REFACTOR.value,
        executor_action="Use atomic write pattern",
        proof_required="Atomic writes verified",
        allowlist_allowed=False,
        confidence=confidence,
        applicability=applicability,
        applicability_reason=app_reason,
        analysis_mode="ast",
    )


def _build_legacy_finding(hit: dict, severity: "GateSeverity", extra_note):
    """Legacy finding builder (pre-Sprint-B3 path)."""
    summary = (
        f"{hit['file']}: {hit['write_func']}() at line "
        f"{hit['line']} writes directly without a tmpfile+rename "
        "guard -- partial writes or corruption on crash are possible."
    )
    if extra_note:
        summary = f"{summary} ({extra_note})"
    return build_finding(
        check_id="atomic_write_safety.missing_tmpfile_rename",
        category=GateCategory.DRIFT,
        title="Non-atomic write: missing tmpfile+rename pattern",
        severity=severity,
        impact=GateImpact.REVISE,
        summary=summary,
        recommendation=(
            "Write to a .tmp sibling file first, then atomically rename "
            "it to the target (Path.replace / os.replace). This prevents "
            "readers from observing a partially-written file."
        ),
        evidence=[
            EvidenceReference(
                kind="file",
                path=hit["file"],
                detail=f"write={hit['write_func']}:L{hit['line']}",
            )
        ],
        repair_kind=RepairKind.REFACTOR.value,
        executor_action="Use atomic write pattern",
        proof_required="Atomic writes verified",
        allowlist_allowed=False,
    )
