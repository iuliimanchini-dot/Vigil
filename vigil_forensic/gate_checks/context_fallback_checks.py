"""Context-fallback fail-open detector (Finding G.3 plan v7 + F7 enhancement).

Two detection criteria (each emits a distinct ``check_id`` subtype):

1. **two_branch_sentinel** — historical F6 pattern:
   ``if X is None: <action> else: <action>`` where both branches contain
   actionable statements AND share at least one common assignment target.
   This is the F-004 / F-EMERGENCY sentinel-fallback.

2. **fallback_without_else** (F7, 2026-04-23) — actionable None-guard with no
   else.  Covers the common fail-loud-alternative / actionable fallback shape
   where the ``else`` is elided because the None-branch explicitly diverts
   control flow or assigns a default to module/self state.  Triggers when the
   ``if X is None:`` body contains:
       * ``return <non-trivial>`` -- sentinel Name, Call, Attribute, BinOp,
         non-empty literal, etc.  NOT flagged: bare ``return``, ``return None``,
         ``return True/False``, ``return 0/""``, ``return []/{}/()/set()``.
         These trivial-literal returns are pure-classifier / defensive-input
         patterns, not sentinel-fallbacks (FP tightening 2026-04-23).
       * ``Assign`` to module/self state (``self.X = ...`` / ``cls.X = ...``)

   **NOT flagged: ``raise ...``** -- a defensive ``raise`` is fail-LOUD (explicit
   error signaling), which is the OPPOSITE of a silent fallback.  The gate's
   purpose is to find silent/implicit fallbacks; a raise can never be one.
   Removed from emission 2026-04-23 (F15-A) after triage showed 15/15 action=raise
   findings were genuine fail-loud defensive patterns (~100% FP rate).

Priority: if both criteria would match (body has actionable stmt AND there is
an else branch), criterion 1 wins -- we do not double-flag the same ``if``.

Flagged (two-branch):
    if cache is None:
        result = default_value
    else:
        result = cache.compute()

Flagged (fallback-without-else):
    if cfg is None:
        return DEFAULT_CONFIG
    if handler is None:
        self._handler = _NULL_HANDLER

Not flagged:
    if cfg is not None and cfg.enabled:     # short-circuit guard
    if x is None: return                    # bare bail-out
    if x is None: return None               # explicit bare bail-out
    if x is None: return False              # pure classifier (FP tightening)
    if x is None: return True               # pure classifier (FP tightening)
    if x is None: return []                 # empty-collection defensive return
    if x is None: return {}                 # empty-dict defensive return
    if x is None: return ()                 # empty-tuple defensive return
    if x is None: return 0                  # empty-scalar defensive return
    if x is None: return ""                 # empty-scalar defensive return
    if x is None: raise ValueError("...")   # F15-A: fail-loud, not a fallback
    if x is None: log.warning("x"); return  # pure logging + bare bail-out
    if env is None: env = os.environ        # F14b: same-var rebinding
                                            #       (idiomatic default param)
    if counter is None: counter += 1        # F14b: AugAssign to same var

Allowlist: ``# noqa: context_fallback_save`` on the finding line (or the
preceding line) suppresses both criteria.

Fail-open: parse errors, missing files -> DEBUG log + skip, never raise.
"""
from __future__ import annotations

import ast
import logging
import re
from pathlib import Path
from typing import Iterable

from vigil_forensic._shared import EvidenceReference, GateCategory, GateImpact, GateSeverity, RepairKind
from vigil_forensic.gate_models import PostExecGateContext
from vigil_forensic.source_analysis import is_source_file
from .common import build_check_result, build_finding, has_allowlist_for, normalize_path

_log = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _extract_is_none_var(test: ast.expr) -> str | None:
    """Return var name from ``X is None`` (Compare, Is, None), else None."""
    if not isinstance(test, ast.Compare):
        return None
    if len(test.ops) != 1 or not isinstance(test.ops[0], ast.Is):
        return None
    if len(test.comparators) != 1:
        return None
    comp = test.comparators[0]
    if not isinstance(comp, ast.Constant) or comp.value is not None:
        return None
    if isinstance(test.left, ast.Name):
        return test.left.id
    return None


def _assigned_names(stmts: list[ast.stmt]) -> set[str]:
    """Return all Names that appear as Assign targets in *stmts* (top-level only)."""
    names: set[str] = set()
    for stmt in stmts:
        if isinstance(stmt, ast.Assign):
            for target in stmt.targets:
                if isinstance(target, ast.Name):
                    names.add(target.id)
        elif isinstance(stmt, (ast.AugAssign,)):
            if isinstance(stmt.target, ast.Name):
                names.add(stmt.target.id)
    return names


def _is_default_rebinding(if_node: ast.If, guarded_var: str) -> bool:
    """Return True if ``if <guarded_var> is None:`` body rebinds *guarded_var*
    itself to a non-None value -- the idiomatic default-parameter pattern.

    This shape is NOT a fail-open: after the body runs the variable is
    guaranteed to hold a usable non-None value and the function proceeds
    with normal logic.

    Matched (returns True -- SKIP, not a fail-open)::

        if env is None:
            env = os.environ           # same-var, non-None rebinding

        if counter is None:
            counter += 1               # AugAssign to same var (rare but valid)

        if config is None:
            config: Config = build_default_config()   # AnnAssign to same var

    NOT matched (returns False -- still potential fail-open)::

        if result is None:
            logger.warning("missing")  # no rebinding at all

        if env is None:
            source = os.environ        # rebinding DIFFERENT var, not guarded_var

        if x is None:
            x = None                   # rebinding to None (no-op, suspicious)

    Scans only direct children of ``if_node.body`` (no nested walks) so
    rebinds hidden inside an inner block do not count.
    """
    for stmt in if_node.body:
        # Plain assignment: ``env = <value>`` (including tuple-target variants
        # that happen to include guarded_var).
        if isinstance(stmt, ast.Assign):
            for target in stmt.targets:
                if isinstance(target, ast.Name) and target.id == guarded_var:
                    if not (
                        isinstance(stmt.value, ast.Constant)
                        and stmt.value.value is None
                    ):
                        return True
        # Annotated assignment: ``env: Mapping[str, str] = os.environ``.
        elif isinstance(stmt, ast.AnnAssign):
            if (
                isinstance(stmt.target, ast.Name)
                and stmt.target.id == guarded_var
                and stmt.value is not None
                and not (
                    isinstance(stmt.value, ast.Constant)
                    and stmt.value.value is None
                )
            ):
                return True
        # Augmented assignment: ``counter += 1`` to same var.  Value is not
        # a plain None here (AugAssign requires an rvalue expression); still
        # counts as a rebinding to a non-None value.
        elif isinstance(stmt, ast.AugAssign):
            if isinstance(stmt.target, ast.Name) and stmt.target.id == guarded_var:
                return True
    return False


def _has_actionable_stmt(stmts: list[ast.stmt]) -> bool:
    """Return True if stmts contain at least one Assign/AugAssign/Return/Raise/Expr(Call)."""
    for stmt in stmts:
        if isinstance(stmt, (ast.Assign, ast.AugAssign, ast.Return, ast.Raise)):
            return True
        if isinstance(stmt, ast.Expr) and isinstance(stmt.value, ast.Call):
            return True
    return False


def _is_trivial_rhs(value: ast.expr | None) -> bool:
    """Return True if *value* is a TRIVIAL RHS (None / empty collection /
    empty scalar / bare empty-collection constructor call).

    Trivial shapes:
      - ``Constant(value=None|True|False|0|"")``
      - ``List([])`` / ``Tuple(())`` / ``Set()`` / ``Dict({})`` (no elements)
      - ``tuple()`` / ``list()`` / ``dict()`` / ``set()`` / ``frozenset()`` --
        bare calls with no args / keywords
      - ``None`` (missing rvalue, defensive)
    """
    if value is None:
        return True
    if isinstance(value, ast.Constant):
        v = value.value
        if v is None:
            return True
        if isinstance(v, bool):
            # bool is subclass of int; handle before int
            return True
        if v == "" or v == 0:
            return True
        return False
    if isinstance(value, ast.List) and not value.elts:
        return True
    if isinstance(value, ast.Tuple) and not value.elts:
        return True
    if isinstance(value, ast.Set) and not value.elts:
        return True
    if isinstance(value, ast.Dict) and not value.keys:
        return True
    if (
        isinstance(value, ast.Call)
        and isinstance(value.func, ast.Name)
        and value.func.id in {"tuple", "list", "dict", "set", "frozenset"}
        and not value.args
        and not value.keywords
    ):
        return True
    return False


def _none_branch_rhs_is_trivial(stmt: ast.If, shared_var: str) -> bool:
    """True if the None-branch (``if X is None:``) assigns a TRIVIAL value
    (None / empty collection / empty scalar) to ``shared_var``.

    Trivial values make the branch explicit Optional-style handling, NOT a
    silent fallback -- the caller can distinguish None/empty from real data.

    Returns True for these RHS shapes (on ANY assignment to ``shared_var``
    in the direct children of ``stmt.body``):

      - ``ast.Constant(value=None|True|False|0|"")``
      - ``ast.Tuple/List/Dict/Set`` with zero elements
      - ``ast.Call`` to ``tuple()`` / ``list()`` / ``dict()`` / ``set()`` /
        ``frozenset()`` with no args

    This is the F17-B FP-tightening (2026-04-23).  If ANY assignment to
    ``shared_var`` in the None-branch uses a trivial RHS the pattern is
    classified as Optional-coercion and the two-branch criterion is
    skipped.  If NO assignment to ``shared_var`` uses a trivial RHS we
    assume the None-branch holds a real sentinel (DEFAULT_CONFIG, loader
    call, non-empty literal, etc.) and keep flagging.
    """
    for node in stmt.body:
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name) and target.id == shared_var:
                    if _is_trivial_rhs(node.value):
                        return True
        elif isinstance(node, ast.AnnAssign):
            if (
                isinstance(node.target, ast.Name)
                and node.target.id == shared_var
                and _is_trivial_rhs(node.value)
            ):
                return True
        elif isinstance(node, ast.AugAssign):
            if isinstance(node.target, ast.Name) and node.target.id == shared_var:
                if _is_trivial_rhs(node.value):
                    return True
    return False


_STRUCTURED_RESULT_NAME_RE = re.compile(
    r"^(?:"
    r"build_[A-Za-z_][A-Za-z0-9_]*_result"     # build_check_result, build_gate_result, ...
    r"|build_check_result"                      # explicit match (covered above, kept for clarity)
    r"|make_[A-Za-z_][A-Za-z0-9_]*"             # make_empty_map, make_default_ctx, ...
    r"|create_[A-Za-z_][A-Za-z0-9_]*"           # create_empty_report, create_default_result, ...
    r"|empty_[A-Za-z_][A-Za-z0-9_]*"            # empty_map, empty_result, ...
    r"|[A-Za-z_][A-Za-z0-9_]*_result"           # gate_check_result, fallback_result, ...
    r"|GateCheckResult"                         # explicit well-known result class
    r"|[A-Z][A-Za-z0-9_]*Result"                # PascalCase *Result classes (VerificationResult, CheckResult, ...)
    r")$"
)


def _is_structured_result_call(value: ast.expr) -> bool:
    """Return True if *value* is a call / attribute access that propagates a
    structured result object (error-propagation, not silent fallback).

    Recognised shapes:

    * ``build_check_result(...)`` / ``build_gate_result(...)`` -- builder funcs
    * ``make_empty_map()`` / ``make_default_ctx(...)`` -- constructor helpers
    * ``create_empty_report(...)`` / ``create_default_result()`` -- creators
    * ``empty_map()`` / ``empty_result(...)`` -- empty-result factories
    * ``fallback_result(...)`` / ``gate_check_result(...)`` -- *_result funcs
    * ``GateCheckResult(check_id=..., findings=[])`` -- dataclass/class call
    * ``VerificationResult(...)`` -- any PascalCase ``*Result`` class call
    * ``obj.empty()`` / ``Klass.empty_for_X(...)`` -- ``.empty*`` methods
    * ``self.empty_result`` / ``obj.default_result`` -- attribute propagating
      an already-constructed structured-result (``Attribute`` access, not Call)

    All of these are explicit structured-error propagation: the function is
    saying "here's a well-typed empty/default result for this no-op branch"
    rather than silently substituting a sentinel.  The result is actionable
    for the caller (they can inspect ``findings``, ``errors``, ``notes``) --
    it is NOT a silent fallback.

    This is the F16b whitelist (2026-04-23) and runs BEFORE the generic
    "Call/Attribute is non-trivial" check inside ``_is_trivial_return_value``.
    """
    # Shape 1: direct call to named function / class -- ``f(...)``
    if isinstance(value, ast.Call):
        func = value.func
        # ``name(...)``
        if isinstance(func, ast.Name):
            return bool(_STRUCTURED_RESULT_NAME_RE.match(func.id))
        # ``obj.name(...)`` / ``Klass.name(...)``
        if isinstance(func, ast.Attribute):
            attr = func.attr
            if _STRUCTURED_RESULT_NAME_RE.match(attr):
                return True
            # ``.empty()`` / ``.empty_for_X()`` / ``.default()`` family
            if attr == "empty" or attr.startswith("empty_") or attr.startswith("default_for_"):
                return True
            return False
        return False
    # Shape 2: bare attribute propagating an already-built structured result --
    # ``return self.empty_result`` / ``return obj.default_result``.  Only match
    # attribute NAMES that look like structured results to avoid leaking the
    # whitelist to arbitrary ``return self.value`` returns (which may well be
    # real silent fallbacks).
    if isinstance(value, ast.Attribute):
        attr = value.attr
        if _STRUCTURED_RESULT_NAME_RE.match(attr):
            return True
        if attr.startswith("empty_") or attr == "empty":
            return True
        return False
    return False


def _is_trivial_return_value(value: ast.expr) -> bool:
    """Return True if *value* is a trivial literal that does NOT qualify as an
    actionable fallback.

    Trivial literals (excluded from the ``fallback_without_else`` criterion to
    reduce FPs from pure classifier / defensive-input-handling functions):

    * ``Constant(value=True)`` / ``Constant(value=False)`` -- boolean literals
      (pure classifier ``return False``)
    * ``Constant(value=None)`` -- explicit None bail-out
    * ``Constant(value="")`` / ``Constant(value=0)`` -- empty-scalar bail-outs
    * ``List([])`` / ``Dict({})`` / ``Tuple(())`` / ``Set()`` -- empty-collection
      bail-outs (``return []`` is defensive, not a sentinel-fallback)

    F16b (2026-04-23): structured-result constructors (``build_check_result(...)``
    / ``make_empty_map()`` / ``GateCheckResult(...)`` / ``self.empty_result``)
    are ALSO treated as trivial for the purpose of this gate -- they are
    explicit error-propagation, not silent fallback.  See
    ``_is_structured_result_call``.

    Non-trivial (still flagged): ``Name``, non-whitelisted ``Call``,
    non-whitelisted ``Attribute``, ``BinOp``, non-empty collection literals,
    non-empty/non-zero scalars.
    """
    if isinstance(value, ast.Constant):
        v = value.value
        if v is None:
            return True
        if isinstance(v, bool):
            # bool is subclass of int; check before int
            return True
        if v == "" or v == 0:
            # empty string / zero
            return True
        return False
    if isinstance(value, ast.List) and not value.elts:
        return True
    if isinstance(value, ast.Tuple) and not value.elts:
        return True
    if isinstance(value, ast.Set) and not value.elts:
        return True
    if isinstance(value, ast.Dict) and not value.keys:
        return True
    # Empty built-in collection constructors: ``return set()`` / ``return list()``
    # / ``return dict()`` / ``return tuple()`` / ``return frozenset()`` with no
    # args are semantically identical to their literal form and equally trivial.
    if (
        isinstance(value, ast.Call)
        and isinstance(value.func, ast.Name)
        and value.func.id in {"set", "list", "dict", "tuple", "frozenset"}
        and not value.args
        and not value.keywords
    ):
        return True
    # F16b (2026-04-23): structured-result constructor calls / attribute
    # propagation of pre-built structured results are explicit error propagation,
    # not silent fallback.  Treat as trivial -> not flagged.
    if _is_structured_result_call(value):
        return True
    return False


def _is_nontrivial_return(stmt: ast.stmt) -> bool:
    """Return True if *stmt* is ``return <expr>`` where expr is non-trivial.

    Bare ``return`` (value is None) and trivial literal returns (``return None``,
    ``return False``, ``return []``, etc.) are considered trivial bail-outs and
    deliberately excluded so we don't inflate finding count with benign
    defensive guards / pure-classifier returns.  See ``_is_trivial_return_value``
    for the full exclusion list.
    """
    if not isinstance(stmt, ast.Return):
        return False
    value = stmt.value
    if value is None:
        return False
    if _is_trivial_return_value(value):
        return False
    return True


def _is_module_or_self_assign(stmt: ast.stmt) -> bool:
    """Return True if *stmt* assigns to ``self.X`` / ``cls.X`` / module-level attribute.

    We treat attribute-style assignments as "module/self state" because inside
    a function body they signal mutation of persistent state (object field,
    class attribute) rather than a pure local fallback.  This is the 3rd
    actionable shape for the ``fallback_without_else`` criterion.
    """
    if not isinstance(stmt, (ast.Assign, ast.AugAssign)):
        return False
    targets: list[ast.expr]
    if isinstance(stmt, ast.Assign):
        targets = list(stmt.targets)
    else:  # AugAssign
        targets = [stmt.target]
    for target in targets:
        if isinstance(target, ast.Attribute):
            return True
    return False


def _actionable_without_else_kind(body: list[ast.stmt]) -> str | None:
    """Classify an if-body as an actionable fallback without-else.

    Returns the finding subtype label (``"return_value"`` / ``"state_assign"``)
    or None if the body is not actionable under this criterion.  A body may
    contain any number of statements -- we scan for the first matching shape.
    Pure ``return`` / ``return None`` / logging calls followed by bare return
    do NOT match.

    **``raise`` is NOT an actionable fallback** (F15-A, 2026-04-23): a raise
    is fail-LOUD (explicit error), the OPPOSITE of a silent fallback.  The
    gate's purpose is to find silent/implicit fallbacks; a raise can never be
    one.  Before this change 15/15 ``action=raise`` findings were genuine
    fail-loud defensive patterns (~100% FP rate) -- emission removed.
    """
    for stmt in body:
        if _is_nontrivial_return(stmt):
            return "return_value"
        if _is_module_or_self_assign(stmt):
            return "state_assign"
    return None


def _detect_context_fallback_in_function(
    func_node: ast.FunctionDef | ast.AsyncFunctionDef,
    file_path: str,
) -> list[dict]:
    """Walk top-level statements of a function; return raw finding dicts.

    Each hit dict carries a ``subtype`` key:

    * ``"two_branch"`` -- ``if X is None: <action> else: <action>`` where both
      branches contain actionable statements AND share at least one common
      assignment target (sentinel fallback, F6 criterion).
    * ``"fallback_without_else"`` -- ``if X is None:`` with no else, where the
      body contains an actionable fallback shape (non-trivial return /
      module-or-self assignment) (F7 criterion, 2026-04-23).  ``raise`` is
      explicitly EXCLUDED as of F15-A (2026-04-23) -- fail-loud is not a
      silent fallback and has no place in this gate.

    Priority: if an ``if`` node has an else branch, only the two-branch
    criterion is considered -- we never double-flag the same node.

    Short-circuit guards (``if X is not None and X.attr ...``) are NOT flagged.
    Bare ``return`` / ``return None`` bail-outs are NOT flagged.
    """
    raw: list[dict] = []
    body = func_node.body
    for stmt in body:
        if not isinstance(stmt, ast.If):
            continue

        # Require test to be exactly ``X is None``
        var = _extract_is_none_var(stmt.test)
        if var is None:
            continue

        # --- FP tightening 2026-04-23 (F14b): default-parameter-rebinding ---
        # ``if X is None: X = default`` (same-var rebinding to non-None) is the
        # idiomatic default-argument pattern, NOT a fail-open.  Skip both
        # two-branch and fallback_without_else criteria for this shape.
        if _is_default_rebinding(stmt, var):
            continue

        if stmt.orelse:
            # --- Criterion 1: two-branch sentinel fallback ---
            # Both branches must contain at least one actionable statement
            if not _has_actionable_stmt(stmt.body):
                continue
            if not _has_actionable_stmt(stmt.orelse):
                continue

            # Both branches must assign to at least one common target name
            body_targets = _assigned_names(stmt.body)
            else_targets = _assigned_names(stmt.orelse)
            shared_targets = body_targets & else_targets
            if not shared_targets:
                continue

            # --- FP tightening 2026-04-23 (F17-B): Optional-coercion skip ---
            # When the None-branch assigns a TRIVIAL value (None, empty
            # collection, empty scalar) to every shared target, the pattern
            # is explicit Optional handling (caller can distinguish None /
            # empty from real data) rather than a silent sentinel fallback.
            # Only skip if ALL shared targets are trivial; if at least one
            # target binds a real sentinel (DEFAULT_CONFIG, loader call,
            # non-empty literal) we still flag the real silent fallback.
            trivial_shared = {
                var_name for var_name in shared_targets
                if _none_branch_rhs_is_trivial(stmt, var_name)
            }
            if trivial_shared == shared_targets:
                continue  # ALL shared targets use trivial None-branch → Optional idiom

            raw.append({
                "file": file_path,
                "var": var,
                "line": stmt.lineno,
                "func": func_node.name,
                "subtype": "two_branch",
                "action_kind": "shared_assign",
            })
        else:
            # --- Criterion 2: actionable body without else ---
            kind = _actionable_without_else_kind(stmt.body)
            if kind is None:
                continue
            raw.append({
                "file": file_path,
                "var": var,
                "line": stmt.lineno,
                "func": func_node.name,
                "subtype": "fallback_without_else",
                "action_kind": kind,
            })
    return raw


# ---------------------------------------------------------------------------
# Public gate entry-point
# ---------------------------------------------------------------------------

_TWO_BRANCH_CHECK_ID = "context_fallback_save.fail_open_none_guard"
_WITHOUT_ELSE_CHECK_ID = "context_fallback_save.fallback_without_else"


def _build_two_branch_finding(hit: dict):
    return build_finding(
        check_id=_TWO_BRANCH_CHECK_ID,
        category=GateCategory.CONTRACT,
        title="Fail-open None guard: X is not None and X.attr short-circuits to wrong branch",
        severity=GateSeverity.MEDIUM,
        impact=GateImpact.REVISE,
        summary=(
            f"{hit['file']}:{hit['line']} in {hit['func']}(): "
            f"``if {hit['var']} is None: <fallback> else: <main>`` -- "
            f"both branches assign to a shared target; when {hit['var']} is None "
            "the sentinel silently replaces real data (F-004 pattern)."
        ),
        recommendation=(
            f"Add an explicit guard before the compound condition: "
            f"``if {hit['var']} is None: raise ValueError(...)`` or "
            f"``if {hit['var']} is None: return``.  "
            "Do not rely on short-circuit evaluation to handle None silently."
        ),
        evidence=[
            EvidenceReference(
                kind="file",
                path=hit["file"],
                detail=(
                    f"func={hit['func']} var={hit['var']} "
                    f"line={hit['line']} subtype=two_branch"
                ),
            )
        ],
        repair_kind="remove_fallback",
        executor_action="Remove/narrow fallback pattern",
        proof_required="No fallback in file",
        allowlist_allowed=False,
    )


def _build_without_else_finding(hit: dict):
    kind = hit.get("action_kind", "unknown")
    # Note: ``raise`` is NOT emitted (F15-A, 2026-04-23) -- fail-loud is not
    # a silent fallback.  Only ``return_value`` and ``state_assign`` reach here.
    kind_desc = {
        "return_value": "returns a non-trivial value",
        "state_assign": "assigns to module/self state",
    }.get(kind, "performs an actionable fallback")
    return build_finding(
        check_id=_WITHOUT_ELSE_CHECK_ID,
        category=GateCategory.CONTRACT,
        title="Actionable None-guard without else: fallback side-effect without paired main branch",
        severity=GateSeverity.MEDIUM,
        impact=GateImpact.REVISE,
        summary=(
            f"{hit['file']}:{hit['line']} in {hit['func']}(): "
            f"``if {hit['var']} is None:`` body {kind_desc} (no else branch). "
            "This is an actionable fallback decision -- a reviewer must confirm "
            "the chosen alternative (raise / default return / state mutation) is "
            "intentional, not an accidental silent-swallow."
        ),
        recommendation=(
            "Confirm the fallback is intentional and documented.  If it is, add "
            "``# noqa: context_fallback_save`` on the if-line.  If it is not, "
            "either remove the guard (let the caller handle None) or replace the "
            "sentinel with an explicit ``raise`` so the failure is loud."
        ),
        evidence=[
            EvidenceReference(
                kind="file",
                path=hit["file"],
                detail=(
                    f"func={hit['func']} var={hit['var']} "
                    f"line={hit['line']} subtype=fallback_without_else "
                    f"action={kind}"
                ),
            )
        ],
        repair_kind="remove_fallback",
        executor_action="Confirm intentional or remove fallback pattern",
        proof_required="Allowlist comment or no fallback in file",
        allowlist_allowed=True,
    )


def run_context_fallback_save_checks(ctx: PostExecGateContext):
    """Detect fail-open None-guard patterns in changed Python files.

    For each .py file in ctx.changed_files_observed:
      1. Parse AST.
      2. Walk all function defs (including nested).
      3. Apply two detection criteria (see module docstring):
         - two-branch sentinel fallback
         - actionable fallback without else
      4. Suppress per-line via ``# noqa: context_fallback_save``.

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
            _log.debug("context_fallback: failed to parse %s: %s", normalized, exc)
            continue

        for node in ast.walk(tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            raw_hits = _detect_context_fallback_in_function(node, normalized)
            for hit in raw_hits:
                # Allowlist: respect per-line ``# noqa: context_fallback_save``.
                if has_allowlist_for(src, "context_fallback_save", hit["line"]):
                    continue
                if hit.get("subtype") == "fallback_without_else":
                    findings.append(_build_without_else_finding(hit))
                else:
                    findings.append(_build_two_branch_finding(hit))

    return build_check_result(
        check_id="context_fallback_save",
        category=GateCategory.CONTRACT,
        findings=findings,
    )
