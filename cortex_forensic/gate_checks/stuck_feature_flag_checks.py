"""Stuck feature flag forensic gate.

Detects module-level UPPER_SNAKE_CASE constants assigned to ``False`` that:
    1. are referenced inside an ``if`` test somewhere in the touched files,
    2. are never reassigned to a non-False value anywhere in the touched files,
    3. are not part of a re-export chain (only False-default literals count).

The result is a "stuck flag": code is permanently gated off and forgotten.
Real-world example from this codebase: ``plan_review_ran = False`` hardcoded
with the actual review code never running.

Project-agnostic — works for any Python codebase. Operates strictly on
``ctx.touched_files`` (only ``.py``); files outside ``ctx.project_dir`` are
skipped.

Algorithm:
    Pass 1: collect module-level ``Assign(target=Name(UPPER), value=Constant(False))``
            (excluding TypeVar-style and dunder names).
    Pass 2: across ALL touched .py files, locate any other assignment to the
            same name whose RHS is NOT ``Constant(False)`` — anything else
            (True, function call, attribute, name reference) marks the name as
            "dynamic" and disqualifies it.
    Pass 3: across ALL touched .py files, scan ``If.test`` for usage of the
            candidate name (as bare ``Name``, ``not NAME``, inside ``BoolOp``,
            or as left side of ``Compare``).

A finding is emitted for each name with at least one If usage AND no dynamic
assignment.
"""
from __future__ import annotations

import ast
import logging
import re
from pathlib import Path
from typing import Iterable

from cortex_forensic.gate_models import PostExecGateContext
from cortex_forensic.meta_findings import emit_meta_finding
from cortex_forensic._shared import (
    EvidenceReference,
    GateCategory,
    GateCheckResult,
    GateImpact,
    GateSeverity,
    RepairKind,
)

from .common import build_check_result, build_finding, normalize_path

_log = logging.getLogger(__name__)

_CATEGORY = GateCategory.DRIFT
_CHECK_ID = "stuck_feature_flag"

# UPPER_SNAKE_CASE: leading underscore allowed (private module constants).
# At least one alpha char and one underscore-or-alphanum to avoid lone-letter
# matches like ``X = False`` (which is almost never a feature flag).
_UPPER_SNAKE_RE = re.compile(r"^_?[A-Z][A-Z0-9_]*[A-Z0-9]$")


def _is_false_constant(node: ast.AST) -> bool:
    return (
        isinstance(node, ast.Constant)
        and isinstance(node.value, bool)
        and node.value is False
    )


def _module_level_false_assign_target(node: ast.AST) -> str | None:
    """Return the constant name iff *node* is ``NAME = False`` at module top.

    Caller is responsible for ensuring *node* is a direct child of the module
    (not inside a function/class body).
    """
    if not isinstance(node, ast.Assign):
        return None
    if len(node.targets) != 1:
        return None
    target = node.targets[0]
    if not isinstance(target, ast.Name):
        return None
    name = target.id
    if not _UPPER_SNAKE_RE.match(name):
        return None
    if name.startswith("__") and name.endswith("__"):
        return None
    if not _is_false_constant(node.value):
        return None
    return name


def _module_level_assign_targets(node: ast.AST) -> list[tuple[str, ast.AST]]:
    """Return (name, value) pairs for any module-level ``NAME = <expr>``
    assignment whose target is a single Name. Used by the dynamic-assignment
    pass to detect "assigned to non-False elsewhere".
    """
    out: list[tuple[str, ast.AST]] = []
    if isinstance(node, ast.Assign):
        if len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
            out.append((node.targets[0].id, node.value))
    elif isinstance(node, ast.AugAssign) and isinstance(node.target, ast.Name):
        # ``X |= True`` etc. — counts as dynamic.
        out.append((node.target.id, node.value))
    elif isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
        if node.value is not None:
            out.append((node.target.id, node.value))
    return out


def _walk_assigns_anywhere(tree: ast.AST) -> Iterable[tuple[str, ast.AST]]:
    """Yield (name, value) for every ``Name = <expr>`` assignment found
    anywhere in the tree (module-level OR inside functions/classes). Used
    to detect cross-scope dynamic reassignment of a candidate flag.
    """
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign):
            for tgt in node.targets:
                if isinstance(tgt, ast.Name):
                    yield (tgt.id, node.value)
                elif isinstance(tgt, (ast.Tuple, ast.List)):
                    for elt in tgt.elts:
                        if isinstance(elt, ast.Name):
                            yield (elt.id, node.value)
        elif isinstance(node, ast.AugAssign) and isinstance(node.target, ast.Name):
            yield (node.target.id, node.value)
        elif isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
            if node.value is not None:
                yield (node.target.id, node.value)


def _name_is_used_in_if_test(test: ast.AST, name: str) -> bool:
    """Return True if *test* references *name* in any of the supported forms.

    Supported:
      * ``Name(id=NAME)`` — bare reference
      * ``UnaryOp(op=Not, operand=Name(id=NAME))`` — ``if not NAME``
      * ``BoolOp(values=[..., Name(id=NAME), ...])`` — ``if NAME and X``
      * ``Compare(left=Name(id=NAME), ...)`` — ``if NAME == X``
    """
    if isinstance(test, ast.Name) and test.id == name:
        return True
    if (
        isinstance(test, ast.UnaryOp)
        and isinstance(test.op, ast.Not)
        and isinstance(test.operand, ast.Name)
        and test.operand.id == name
    ):
        return True
    if isinstance(test, ast.BoolOp):
        for v in test.values:
            if _name_is_used_in_if_test(v, name):
                return True
    if isinstance(test, ast.Compare):
        if isinstance(test.left, ast.Name) and test.left.id == name:
            return True
        for cmp_node in test.comparators:
            if isinstance(cmp_node, ast.Name) and cmp_node.id == name:
                return True
    return False


def _collect_if_usage_sites(tree: ast.AST, name: str) -> list[int]:
    """Return 1-based line numbers of every ``If`` whose test references *name*."""
    lines: list[int] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.If) and _name_is_used_in_if_test(node.test, name):
            line = getattr(node, "lineno", 0) or 0
            if line:
                lines.append(int(line))
    return lines


def _resolve_target_path(project_dir: Path, raw_path: str) -> Path | None:
    """Resolve *raw_path* to an absolute Path inside *project_dir*. Return
    ``None`` for files outside the project, missing files, or non-``.py``
    files.
    """
    rel = normalize_path(raw_path)
    if not rel.lower().endswith(".py"):
        return None
    candidate = (project_dir / rel).resolve()
    try:
        project_resolved = project_dir.resolve()
    except OSError:
        return None
    try:
        candidate.relative_to(project_resolved)
    except ValueError:
        return None
    if not candidate.exists() or not candidate.is_file():
        return None
    return candidate


def run_stuck_feature_flag_checks(ctx: PostExecGateContext) -> GateCheckResult:
    """Detect stuck feature flags in ``ctx.touched_files`` (Python only).

    Returns a GateCheckResult with one finding per stuck flag (advisory WARN).
    """
    project_dir = ctx.project_dir
    touched = tuple(ctx.touched_files or ())
    if not touched:
        return build_check_result(
            check_id=_CHECK_ID,
            category=_CATEGORY,
            notes=[f"{_CHECK_ID}: no touched files"],
        )

    # Maps name -> (rel_path, line). Uses first-seen False assignment;
    # subsequent False assignments to the same name are tolerated (they are
    # still "False" — not dynamic). The recorded site is the canonical
    # evidence pointer in the finding.
    false_assignments: dict[str, tuple[str, int]] = {}
    # Maps name -> list of (rel_path, line) where it is reassigned to non-False
    # (anywhere — module level, function body, class body). Presence
    # disqualifies the name.
    dynamic_assignments: dict[str, list[tuple[str, int]]] = {}
    # Maps name -> list of (rel_path, line) for if-test usage sites.
    if_usage_sites: dict[str, list[tuple[str, int]]] = {}

    for raw_path in touched:
        abs_path = _resolve_target_path(project_dir, raw_path)
        if abs_path is None:
            continue
        rel_path = normalize_path(raw_path)
        try:
            source = abs_path.read_text(encoding="utf-8", errors="replace")
        except OSError as exc:
            emit_meta_finding(
                "meta.file_unreadable",
                path=rel_path,
                detail=f"{type(exc).__name__}: {exc}",
            )
            continue
        try:
            tree = ast.parse(source, filename=str(abs_path))
        except SyntaxError as exc:
            emit_meta_finding(
                "meta.syntax_parse_error",
                path=rel_path,
                detail=f"line {exc.lineno}: {exc.msg}",
            )
            continue

        # Pass 1 — module-level NAME = False
        for node in ast.iter_child_nodes(tree):
            name = _module_level_false_assign_target(node)
            if name is None:
                continue
            line = int(getattr(node, "lineno", 0) or 0)
            false_assignments.setdefault(name, (rel_path, line))

        # Pass 2 — any assignment anywhere whose RHS is NOT Constant(False)
        for name, value in _walk_assigns_anywhere(tree):
            if not _UPPER_SNAKE_RE.match(name):
                continue
            if name.startswith("__") and name.endswith("__"):
                continue
            if _is_false_constant(value):
                continue
            line = int(getattr(value, "lineno", 0) or 0)
            dynamic_assignments.setdefault(name, []).append((rel_path, line))

    # Pass 3 — if-test usage scan. Only do this for names that survived
    # pass 1 + pass 2 (cheap optimisation; correctness is unchanged).
    candidates = {
        name for name in false_assignments if name not in dynamic_assignments
    }
    if not candidates:
        return build_check_result(
            check_id=_CHECK_ID,
            category=_CATEGORY,
            notes=[f"{_CHECK_ID}: no candidate False-default constants found"],
        )

    for raw_path in touched:
        abs_path = _resolve_target_path(project_dir, raw_path)
        if abs_path is None:
            continue
        rel_path = normalize_path(raw_path)
        try:
            source = abs_path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        try:
            tree = ast.parse(source, filename=str(abs_path))
        except SyntaxError:
            continue

        for name in candidates:
            for line in _collect_if_usage_sites(tree, name):
                if_usage_sites.setdefault(name, []).append((rel_path, line))

    # Emit findings.
    findings = []
    for name in sorted(candidates):
        usages = if_usage_sites.get(name, [])
        if not usages:
            continue
        decl_path, decl_line = false_assignments[name]
        evidence: list[EvidenceReference] = [
            EvidenceReference(
                kind="false_default_assignment",
                path=decl_path,
                detail=f"{decl_path}:{decl_line}: {name} = False",
            )
        ]
        for use_path, use_line in usages:
            evidence.append(
                EvidenceReference(
                    kind="if_test_usage",
                    path=use_path,
                    detail=f"{use_path}:{use_line}: if-test references {name}",
                )
            )
        findings.append(
            build_finding(
                check_id=_CHECK_ID,
                category=_CATEGORY,
                title=f"Stuck feature flag: {name}",
                severity=GateSeverity.MEDIUM,
                impact=GateImpact.WARN,
                summary=(
                    f"Module constant {name}=False at {decl_path}:{decl_line} "
                    f"is used in {len(usages)} conditional(s) but never "
                    f"reassigned anywhere in the project. Likely dead/disabled "
                    f"feature."
                ),
                recommendation=(
                    "Either remove the flag and the gated code, or wire up a "
                    "path that sets it to True."
                ),
                evidence=evidence,
                repair_kind=RepairKind.REMOVE_DEAD_SURFACE.value,
                executor_action="Resolve stuck feature flag (remove or wire)",
                proof_required="Flag is either deleted (with its gated code) or set to True via a real code path.",
                allowlist_allowed=True,
                preferred_fix_shape="delete the flag + the dead branch, OR add the missing assignment path",
            )
        )

    notes: list[str] = []
    if not findings:
        notes.append(
            f"{_CHECK_ID}: {len(candidates)} False-default candidate(s) "
            f"found, none with if-test usage"
        )
    return build_check_result(
        check_id=_CHECK_ID,
        category=_CATEGORY,
        findings=findings,
        notes=notes,
    )
