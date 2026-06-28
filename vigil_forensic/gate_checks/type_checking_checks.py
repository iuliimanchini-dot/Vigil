from __future__ import annotations

"""Gate checks for type annotation coverage and `Any` erosion.

Sub-checks:
    type_checking.missing_hints_public_api — public functions lacking param/return annotations
    type_checking.any_erosion              — excessive `Any` annotations in public API
"""

import ast
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
from ..source_analysis import is_source_file, is_test_file, get_language_id
from .common import build_check_result, build_finding, iter_touched_snapshots, normalize_path
from ._ast_helpers import parse_python_source_or_emit_finding
import logging
_log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_ANY_EROSION_THRESHOLD = 8  # findings emitted when Any count per-file exceeds this

# File basenames that are skipped for any_erosion: re-export / fixture files
# use Any for compatibility and that is intentional.
_ANY_EROSION_SKIP_BASENAMES = frozenset({"__init__.py", "conftest.py"})
_ANY_TS_RE = re.compile(r":\s*any\b", re.IGNORECASE)  # JS/TS `: any` annotation pattern

# ---------------------------------------------------------------------------
# AST helpers
# ---------------------------------------------------------------------------

_SKIP_NAMES = frozenset({"__init__", "__new__"})


def _is_public_function(node: ast.FunctionDef | ast.AsyncFunctionDef) -> bool:
    """Return True when the function is part of the public API (name not prefixed with `_`)."""
    return not node.name.startswith("_") and node.name not in _SKIP_NAMES


def _missing_hints(node: ast.FunctionDef | ast.AsyncFunctionDef) -> list[str]:
    """Return a list of missing-annotation descriptions for *node*.

    Checks:
      - Each non-`self`/`cls` parameter must have an `annotation`.
      - The function must have a `returns` annotation.
    """
    issues: list[str] = []

    # Parameters — skip implicit self/cls (first arg of methods that have no annotation)
    args = node.args
    all_params = (
        args.posonlyargs
        + args.args
        + ([] if args.vararg is None else [args.vararg])
        + args.kwonlyargs
        + ([] if args.kwarg is None else [args.kwarg])
    )
    for param in all_params:
        if param.arg in ("self", "cls"):
            continue
        if param.annotation is None:
            issues.append(f"param '{param.arg}' missing annotation")

    if node.returns is None:
        issues.append("return type missing")

    return issues


def _count_any_in_annotations(tree: ast.Module) -> int:
    """Count `Any` usages in function signatures and class-level field annotations."""
    count = 0
    for node in ast.walk(tree):
        # Function argument and return annotations
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            if _is_any_node(node.returns):
                count += 1
            args = node.args
            all_params = (
                args.posonlyargs
                + args.args
                + ([] if args.vararg is None else [args.vararg])
                + args.kwonlyargs
                + ([] if args.kwarg is None else [args.kwarg])
            )
            for param in all_params:
                if _is_any_node(param.annotation):
                    count += 1
        # Dataclass / class-level annotated assignments
        elif isinstance(node, ast.AnnAssign):
            if _is_any_node(node.annotation):
                count += 1
    return count


def _is_any_node(annotation: ast.expr | None) -> bool:
    """True when annotation is the bare Name `Any`."""
    return isinstance(annotation, ast.Name) and annotation.id == "Any"


# ---------------------------------------------------------------------------
# JS/TS helper
# ---------------------------------------------------------------------------

def _count_any_ts(text: str) -> int:
    """Count `: any` occurrences in JS/TS source text (case-insensitive)."""
    return len(_ANY_TS_RE.findall(text))


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------

def run_type_checking_checks(ctx: PostExecGateContext):
    """Run both type-checking sub-checks and return a single GateCheckResult.

    Emits two sub-check kinds of findings (``type_checking.missing_hints_public_api``
    and ``type_checking.any_erosion``) aggregated under one ``type_checking`` gate
    result, matching the contract expected by :func:`post_exec_gate._normalize_check_results`.
    """
    hints_findings: list = []
    erosion_findings: list = []

    for snapshot in iter_touched_snapshots(ctx):
        if not snapshot.exists or not is_source_file(snapshot.path):
            continue

        path = snapshot.path
        text = snapshot.text
        lang = get_language_id(path)

        # ------------------------------------------------------------------
        # Python: AST-based checks
        # ------------------------------------------------------------------
        if lang == "python":
            # B4 (2026-04-23): fail-loud parse via shared helper; meta
            # finding rides along with hints_findings for reporting.
            tree = parse_python_source_or_emit_finding(
                text,
                rel_path=normalize_path(path),
                emit_finding=hints_findings.append,
                emitting_gate="type_checking",
            )
            if tree is None:
                continue

            # Sub-check 1: missing_hints_public_api
            if not is_test_file(path):
                for node in ast.walk(tree):
                    if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                        continue
                    if not _is_public_function(node):
                        continue
                    issues = _missing_hints(node)
                    if not issues:
                        continue
                    line_no = getattr(node, "lineno", 0)
                    issue_str = ", ".join(issues)
                    hints_findings.append(
                        build_finding(
                            check_id="type_checking.missing_hints_public_api",
                            category=GateCategory.CONTRACT,
                            title=(
                                f"Public function '{node.name}' in {path}:{line_no} "
                                f"missing annotations ({issue_str})"
                            ),
                            severity=GateSeverity.MEDIUM,
                            impact=GateImpact.REVISE,
                            summary=(
                                f"Function '{node.name}' at {path}:{line_no} is part of the "
                                "public API but has incomplete type annotations: "
                                f"{issue_str}. "
                                "Missing annotations impede static analysis, IDE completion, "
                                "and reviewer understanding of the contract."
                            ),
                            recommendation=(
                                "Add type annotations to all parameters and the return type. "
                                "Use `from __future__ import annotations` for forward references. "
                                "If types are injected by a decorator, add `allowlist: true` to "
                                "suppress this finding."
                            ),
                            evidence=[
                                EvidenceReference(
                                    kind="file",
                                    path=path,
                                    detail=f"line:{line_no}",
                                )
                            ],
                            repair_kind=RepairKind.FIX_CONTRACT.value,
                            executor_action=(
                                f"Add type hints to public function {node.name}: "
                                "params + return"
                            ),
                            proof_required=(
                                "function signature has typed params + return; "
                                "mypy/pyright clean"
                            ),
                            allowlist_allowed=True,
                            preferred_fix_shape=(
                                f"def {node.name}(arg: Type) -> ReturnType:"
                            ),
                        )
                    )

            # Sub-check 2: any_erosion (Python)
            # Skip re-export hubs and fixture files — Any is intentional there.
            if Path(path).name in _ANY_EROSION_SKIP_BASENAMES:
                continue
            any_count = _count_any_in_annotations(tree)
            if any_count > _ANY_EROSION_THRESHOLD:
                erosion_findings.append(
                    build_finding(
                        check_id="type_checking.any_erosion",
                        category=GateCategory.CONTRACT,
                        title=(
                            f"Excessive `Any` annotations ({any_count}) in {path}"
                        ),
                        severity=GateSeverity.LOW,
                        impact=GateImpact.WARN,
                        summary=(
                            f"File {path} contains {any_count} `Any` annotations in "
                            "function signatures or dataclass fields. "
                            "High `Any` density erodes static-analysis guarantees and "
                            "hides type mismatches that mypy/pyright would otherwise catch."
                        ),
                        recommendation=(
                            "Replace `Any` with concrete types (TypedDict, Protocol, or "
                            "a concrete class). If a wide type is genuinely needed, use "
                            "`object` for contravariant positions or define a narrow Protocol."
                        ),
                        evidence=[
                            EvidenceReference(
                                kind="file",
                                path=path,
                                detail=f"any_count:{any_count}",
                            )
                        ],
                        repair_kind=RepairKind.FIX_CONTRACT.value,
                        executor_action=(
                            f"Replace {any_count} `Any` annotations with concrete types "
                            "(TypedDict, Protocol, or concrete class). "
                            "Reference audit in STORAGE/docs/2026-04-22-any_type_audit_*.md"
                        ),
                        proof_required=(
                            f"grep 'Any' in file returns ≤ {_ANY_EROSION_THRESHOLD} occurrences "
                            f"where {_ANY_EROSION_THRESHOLD} is new threshold; "
                            "ensure no `# type: ignore` added to bypass"
                        ),
                        allowlist_allowed=True,
                    )
                )

        # ------------------------------------------------------------------
        # JS / TS: regex-based `any` erosion only (no AST missing-hints check)
        # ------------------------------------------------------------------
        elif lang in ("javascript", "typescript"):
            any_count = _count_any_ts(text)
            if any_count > _ANY_EROSION_THRESHOLD:
                erosion_findings.append(
                    build_finding(
                        check_id="type_checking.any_erosion",
                        category=GateCategory.CONTRACT,
                        title=(
                            f"Excessive `: any` annotations ({any_count}) in {path}"
                        ),
                        severity=GateSeverity.LOW,
                        impact=GateImpact.WARN,
                        summary=(
                            f"File {path} contains {any_count} `: any` type annotations. "
                            "Excessive `any` defeats TypeScript's type system."
                        ),
                        recommendation=(
                            "Replace `: any` with concrete types or `unknown` where the "
                            "type is genuinely unknown."
                        ),
                        evidence=[
                            EvidenceReference(
                                kind="file",
                                path=path,
                                detail=f"any_count:{any_count}",
                            )
                        ],
                        repair_kind=RepairKind.FIX_CONTRACT.value,
                        executor_action=(
                            f"Replace {any_count} `: any` annotations with concrete types "
                            "or `unknown`. "
                            "Reference audit in STORAGE/docs/2026-04-22-any_type_audit_*.md"
                        ),
                        proof_required=(
                            f"grep ': any' in file returns ≤ {_ANY_EROSION_THRESHOLD} occurrences; "
                            "ensure no eslint-disable added to bypass"
                        ),
                        allowlist_allowed=True,
                    )
                )

        # Go and other languages: stub — skip without raising
        # else: pass

    all_findings = hints_findings + erosion_findings
    return build_check_result(
        check_id="type_checking",
        category=GateCategory.CONTRACT,
        findings=all_findings,
    )
