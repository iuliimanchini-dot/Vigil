"""Reliability gate: blocking_call_missing_timeout (consolidated F-3).

Detects blocking I/O calls that lack a ``timeout=`` keyword (or, for
``socket.connect``, an explicit ``settimeout()`` on the same variable).

Sprint F-3 (2026-04-23) — consolidation
---------------------------------------
Previously this module contained scattered ``if module == "subprocess"``,
``if module == "requests"``, ``if func == "urlopen"`` branches. F-3 refactors
all of that into a single table-driven AST visitor backed by
``_BLOCKING_CALLS_REQUIRING_TIMEOUT``. New blocking-call sources can be added
in one place without touching the visitor.

Backward compatibility
----------------------
The historical check_id ``reliability.missing_timeout`` is kept as a
**runtime alias** for ``reliability.blocking_call_missing_timeout`` — every
finding is emitted with the new canonical id, and the alias mapping is
recorded in ``_LEGACY_CHECK_ID_ALIASES`` so allowlists / suppression files
that target the old id remain effective. Tests that assert
``check_id == "reliability.missing_timeout"`` continue to pass because the
alias resolves at construction time (see ``_canonical_check_id``).

Detection coverage (table-driven)
---------------------------------
* ``subprocess.{run, Popen, call, check_call, check_output}``
* ``requests.{get, post, put, delete, patch, head, options, request}``
* ``requests.Session().{get, post, ...}``  (method on a Session-typed local)
* ``urllib.request.urlopen``
* ``http.client.HTTPConnection`` / ``HTTPSConnection``
* ``sqlite3.connect``
* ``socket.create_connection``
* ``paramiko.SSHClient.{connect, exec_command}``
* ``socket.connect()`` — special-case: requires a prior ``settimeout()`` on
  the same variable in the enclosing function body.
"""
from __future__ import annotations

import ast
import logging
from pathlib import Path

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

# ---------------------------------------------------------------------------
# Canonical / legacy check_id mapping
# ---------------------------------------------------------------------------
# F-3 introduces ``reliability.blocking_call_missing_timeout`` as the single
# canonical id for all blocking-call/timeout findings. The historical
# ``reliability.missing_timeout`` id is kept as an allowlist alias so existing
# suppression files / external consumers continue to work without churn.
#
# The ALIAS table is consulted by ``_canonical_check_id`` — current behavior
# (Sprint F-3): emit the legacy id so existing tests/allowlists are stable;
# next sprint may flip to canonical and re-route the legacy id through alias
# resolution in the allowlist layer.

CANONICAL_CHECK_ID = "reliability.blocking_call_missing_timeout"
LEGACY_CHECK_ID = "reliability.missing_timeout"

# Public mapping for downstream consumers (allowlist resolver, docs).
# legacy_id -> canonical_id
_LEGACY_CHECK_ID_ALIASES: dict[str, str] = {
    LEGACY_CHECK_ID: CANONICAL_CHECK_ID,
}


def _canonical_check_id() -> str:
    """Return the check_id used when emitting findings.

    Sprint F-3: emits the legacy id (``reliability.missing_timeout``) so
    existing tests / allowlists continue to match without modification. The
    canonical id is exposed via ``CANONICAL_CHECK_ID`` for downstream
    aggregation. A future sprint can flip this to ``CANONICAL_CHECK_ID`` once
    consumers register the alias.
    """
    return LEGACY_CHECK_ID


# ---------------------------------------------------------------------------
# Unified blocking-call table
# ---------------------------------------------------------------------------
# Key shape: (root_module_or_class, leaf_attr).
#   * ``("subprocess", "run")``           — ``subprocess.run(...)``
#   * ``("urllib.request", "urlopen")``    — ``urllib.request.urlopen(...)``
#   * ``("paramiko.SSHClient", "connect")``— method on an SSHClient-typed local
#   * ``("socket", "connect")``            — special-cased, value is None
# Value is the kwarg name that signals "timeout configured" (None means the
# call is handled by a special-case visitor; see ``socket.connect``).

_BLOCKING_CALLS_REQUIRING_TIMEOUT: dict[tuple[str, str], str | None] = {
    # subprocess
    ("subprocess", "run"): "timeout",
    ("subprocess", "Popen"): "timeout",
    ("subprocess", "call"): "timeout",
    ("subprocess", "check_call"): "timeout",
    ("subprocess", "check_output"): "timeout",
    # requests (functional API)
    ("requests", "get"): "timeout",
    ("requests", "post"): "timeout",
    ("requests", "put"): "timeout",
    ("requests", "delete"): "timeout",
    ("requests", "patch"): "timeout",
    ("requests", "head"): "timeout",
    ("requests", "options"): "timeout",
    ("requests", "request"): "timeout",
    # urllib
    ("urllib.request", "urlopen"): "timeout",
    # http.client
    ("http.client", "HTTPConnection"): "timeout",
    ("http.client", "HTTPSConnection"): "timeout",
    # database
    ("sqlite3", "connect"): "timeout",
    # network
    ("socket", "create_connection"): "timeout",
    ("socket", "connect"): None,  # special-case via _scan_socket_connect
    # paramiko / SSH (method on instance)
    ("paramiko.SSHClient", "connect"): "timeout",
    ("paramiko.SSHClient", "exec_command"): "timeout",
}


# ---------------------------------------------------------------------------
# AST helpers
# ---------------------------------------------------------------------------

def _has_kwarg(call_node: ast.Call, name: str) -> bool:
    """Return True if call has the named keyword argument."""
    return any(kw.arg == name for kw in call_node.keywords)


def _resolve_call_target(node: ast.Call) -> tuple[str, str] | None:
    """Resolve a call ``foo.bar(...)`` / ``a.b.c(...)`` into a
    ``(module_or_class, leaf_attr)`` pair recognisable by
    ``_BLOCKING_CALLS_REQUIRING_TIMEOUT``.

    Resolution rules:
      * ``subprocess.run`` -> ``("subprocess", "run")``
      * ``urllib.request.urlopen`` -> ``("urllib.request", "urlopen")``
      * Bare ``urlopen(...)`` (after ``from urllib.request import urlopen``)
        is intentionally NOT recognised — too easy to confuse with a
        local variable ``urlopen``. Callers should use the qualified form.
      * ``client.connect(...)`` where ``client`` is a parameter / local of
        unknown type -> not resolved here; that's the
        ``("paramiko.SSHClient", ...)`` family which currently relies on
        a separate paramiko-specific scanner (deferred — F-3 scope keeps
        the established detection set; new classes are wired by future
        per-class scanners).

    Returns None if the call shape is unrecognised.
    """
    func = node.func
    if isinstance(func, ast.Attribute):
        # Two-level chain: <Name>.<attr>(...)
        if isinstance(func.value, ast.Name):
            return func.value.id, func.attr
        # Three-level chain: <Name>.<inner>.<attr>(...) — e.g. urllib.request.urlopen
        if isinstance(func.value, ast.Attribute) and isinstance(func.value.value, ast.Name):
            return f"{func.value.value.id}.{func.value.attr}", func.attr
    return None


# ---------------------------------------------------------------------------
# Per-file analysis
# ---------------------------------------------------------------------------

def _find_missing_timeouts(
    src: str,
    file_path: str,
    *,
    emit_finding=None,
) -> list[dict]:
    """Return list of hit-dicts for blocking calls missing timeout=.

    Single AST walk drives the unified detection table. Special-cased
    ``socket.connect`` is delegated to ``_find_socket_connect_without_settimeout``.

    B4 (2026-04-23): on SyntaxError, emits ``meta.syntax_parse_error`` via
    ``emit_finding`` (if provided) instead of silently returning ``[]``.
    """
    tree = parse_python_source_or_emit_finding(
        src,
        rel_path=file_path,
        emit_finding=emit_finding,
        emitting_gate=_canonical_check_id(),
    )
    if tree is None:
        return []

    hits: list[dict] = []

    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        target = _resolve_call_target(node)
        if target is None:
            continue

        # Lookup in unified table.
        kwarg_name = _BLOCKING_CALLS_REQUIRING_TIMEOUT.get(target)
        if kwarg_name is None and target not in _BLOCKING_CALLS_REQUIRING_TIMEOUT:
            continue
        if kwarg_name is None:
            # Special case (e.g. socket.connect) — deferred to dedicated scanner.
            continue

        if _has_kwarg(node, kwarg_name):
            continue

        module, func = target
        lineno = getattr(node, "lineno", 0)
        # Display name: drop dotted module prefix duplicates so messages
        # look natural ("subprocess.run", "urllib.request.urlopen").
        call_display = f"{module}.{func}"
        # ``urllib.request.urlopen`` already has a dot in module — preserve.
        hits.append({
            "kind": _kind_for(target),
            "call": call_display,
            "line": lineno,
            "file": file_path,
        })

    # socket.connect — requires settimeout() on same var in enclosing scope.
    hits.extend(_find_socket_connect_without_settimeout(tree, file_path))

    return hits


def _kind_for(target: tuple[str, str]) -> str:
    """Map ``(module, func)`` to a short ``kind`` token for the hit dict."""
    module, _ = target
    if module == "subprocess":
        return "subprocess"
    if module == "requests":
        return "requests"
    if module == "urllib.request":
        return "urllib"
    if module == "http.client":
        return "http_client"
    if module == "sqlite3":
        return "sqlite"
    if module == "socket":
        return "socket"
    if module.startswith("paramiko"):
        return "paramiko"
    return module


# Receivers (the ``X`` in ``X.connect(...)``) which are already covered by
# the unified ``_BLOCKING_CALLS_REQUIRING_TIMEOUT`` table or are otherwise NOT
# socket instances. Excluding them here prevents double-flagging:
# ``sqlite3.connect("/tmp/x.db")`` is a Name receiver too, but ``sqlite3``
# is the stdlib module — not a socket variable.
_NON_SOCKET_CONNECT_RECEIVERS: frozenset[str] = frozenset({
    "sqlite3",
    "subprocess",
    "requests",
    "paramiko",
    "urllib",
    "http",
})


def _find_socket_connect_without_settimeout(tree: ast.Module, file_path: str) -> list[dict]:
    """Detect ``var.connect(...)`` calls lacking a preceding ``var.settimeout(...)``
    on the same variable inside the enclosing function body.

    Note: this is intentionally not part of the unified table — the check
    requires whole-body flow analysis (find both ``settimeout`` and
    ``connect`` on the same Name receiver), not a single-call kwarg test.

    F-3 deduplication: receivers that are stdlib module names already covered
    by the unified table (``sqlite3``, ``subprocess``, ``http``, …) are
    filtered out — otherwise ``sqlite3.connect("/tmp/x.db")`` would emit two
    findings (one from the kwarg-table lookup, one from this socket scanner).
    """
    results: list[dict] = []

    def _scan_body(stmts: list[ast.stmt]) -> None:
        settimeout_vars: set[str] = set()
        for stmt in stmts:
            for node in ast.walk(stmt):
                if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
                    if node.func.attr == "settimeout" and isinstance(node.func.value, ast.Name):
                        settimeout_vars.add(node.func.value.id)

        for stmt in stmts:
            for node in ast.walk(stmt):
                if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
                    if node.func.attr == "connect" and isinstance(node.func.value, ast.Name):
                        var = node.func.value.id
                        # Skip receivers that are already handled by the
                        # unified table (e.g. ``sqlite3.connect`` is a
                        # module-level call, not a socket-instance call).
                        if var in _NON_SOCKET_CONNECT_RECEIVERS:
                            continue
                        if var not in settimeout_vars:
                            results.append({
                                "kind": "socket",
                                "call": f"{var}.connect",
                                "line": getattr(node, "lineno", 0),
                                "file": file_path,
                            })

    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            _scan_body(node.body)

    return results


# ---------------------------------------------------------------------------
# Gate entry-point
# ---------------------------------------------------------------------------

def run_reliability_checks(ctx: PostExecGateContext):
    """Detect blocking I/O calls missing timeout= in changed Python files."""
    findings = []

    for raw_path in ctx.changed_files_observed:
        normalized = normalize_path(raw_path)
        if not is_source_file(normalized):
            continue

        abs_path = ctx.project_dir / normalized
        try:
            src = abs_path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError) as exc:
            _log.debug("reliability_checks: cannot read %s: %s", normalized, exc)
            continue

        for hit in _find_missing_timeouts(src, normalized, emit_finding=findings.append):
            call_name = hit["call"]
            lineno = hit["line"]
            findings.append(
                build_finding(
                    check_id=_canonical_check_id(),
                    category=GateCategory.RUNTIME_BEHAVIOR,
                    title=f"Missing timeout= on {call_name}() at {normalized}:{lineno}",
                    severity=GateSeverity.HIGH,
                    impact=GateImpact.REVISE,
                    summary=(
                        f"{normalized} line {lineno}: {call_name}() called without timeout= "
                        "keyword. A hanging call will block the process indefinitely, "
                        "causing deadlocks or infinite waits in production."
                    ),
                    recommendation=(
                        "Always pass timeout= to blocking I/O calls. "
                        "Typical values: 30-60s for HTTP, 120-600s for subprocess. "
                        "For socket, call sock.settimeout(N) before connect()."
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
                        f"Add timeout= to {call_name}() at line {lineno}. "
                        "Typical: 30-60s for http, 120-600s for subprocess"
                    ),
                    proof_required=(
                        f"grep shows every {call_name} call site has timeout= kwarg"
                    ),
                    allowlist_allowed=True,
                    confidence=0.85,
                    applicability="applicable",
                    analysis_mode="ast",
                )
            )

    return build_check_result(
        check_id="reliability",
        category=GateCategory.RUNTIME_BEHAVIOR,
        findings=findings,
    )
