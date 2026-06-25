from __future__ import annotations

import ast
import logging
from pathlib import Path

from cortex_forensic._shared import EvidenceReference, GateCategory, GateImpact, GateSeverity, RepairKind
from cortex_forensic.gate_models import PostExecGateContext
from cortex_forensic.gate_checks.common import build_check_result, build_finding, normalize_path

_log = logging.getLogger(__name__)


def _extract_all_names(tree: ast.Module) -> list[str] | None:
    """Return the list of names declared in a top-level ``__all__`` assignment.

    Handles ``__all__ = [...]`` and ``__all__ = (...)``.
    Returns None if no ``__all__`` assignment is found at module level.
    Returns an empty list if ``__all__`` is found but contains no string constants.
    """
    for node in tree.body:
        if not isinstance(node, ast.Assign):
            continue
        for target in node.targets:
            if not (isinstance(target, ast.Name) and target.id == "__all__"):
                continue
            # Found an __all__ assignment — extract string elements
            names: list[str] = []
            value = node.value
            if isinstance(value, (ast.List, ast.Tuple)):
                for elt in value.elts:
                    if isinstance(elt, ast.Constant) and isinstance(elt.value, str):
                        names.append(elt.value)
            return names
    return None


def _extract_defined_names(tree: ast.Module) -> set[str]:
    """Return all names defined or imported at the top level of a module.

    Covers:
    - Top-level ``def`` and ``class`` declarations
    - Top-level simple assignments: ``Name = ...`` (catches re-assignments like
      ``MyClass = _impl.MyClass``)
    - ``import X`` → ``X``
    - ``import X as Z`` → ``Z``
    - ``from X import Y`` → ``Y``
    - ``from X import Y as Z`` → ``Z``
    """
    defined: set[str] = set()
    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            defined.add(node.name)
        elif isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name):
                    defined.add(target.id)
        elif isinstance(node, ast.AnnAssign):
            if isinstance(node.target, ast.Name):
                defined.add(node.target.id)
        elif isinstance(node, ast.Import):
            for alias in node.names:
                # ``import X.Y`` → top-level name is ``X``
                # ``import X.Y as Z`` → name is ``Z``
                name = alias.asname if alias.asname else alias.name.split(".")[0]
                defined.add(name)
        elif isinstance(node, ast.ImportFrom):
            for alias in node.names:
                name = alias.asname if alias.asname else alias.name
                # Wildcard imports: skip (cannot statically determine what they add)
                if name != "*":
                    defined.add(name)
    return defined


def run_export_completeness_checks(ctx: PostExecGateContext):
    """Detect symbols in ``__all__`` that are not defined or imported in the same file.

    Catches the "class extracted to new file but re-export not added" pattern
    where a developer moves a class/function to a new module and forgets to
    add ``from <new_module> import <symbol>`` back to the original file.
    """
    findings = []

    for raw_path in ctx.changed_files_reported:
        normalized = normalize_path(raw_path)

        # Skip non-Python files and vendor/libs directory
        if not normalized.endswith(".py"):
            continue
        if "SYSTEM/libs/" in normalized or normalized.startswith("SYSTEM/libs"):
            continue

        abs_path = ctx.project_dir / normalized
        if not abs_path.exists():
            continue

        try:
            source = abs_path.read_text(encoding="utf-8", errors="replace")
        except OSError as exc:
            _log.debug("export_completeness: cannot read %s: %s", normalized, exc)
            continue

        # Fail-open: skip unparseable files without crashing
        try:
            tree = ast.parse(source, filename=normalized)
        except Exception as exc:  # noqa: BLE001 — FX-V6-EC1 / intentional fail-open
            _log.debug("export_completeness: cannot parse %s: %s", normalized, exc)
            continue

        all_names = _extract_all_names(tree)
        if all_names is None:
            # No __all__ in this file — nothing to check
            continue

        defined_names = _extract_defined_names(tree)
        rel_path = normalized

        for name in all_names:
            if name in defined_names:
                continue
            findings.append(
                build_finding(
                    check_id="export_completeness.missing_symbol",
                    category=GateCategory.CONTRACT,
                    title=f"__all__ declares '{name}' but it is not defined or imported",
                    severity=GateSeverity.HIGH,
                    impact=GateImpact.BLOCK,
                    summary=(
                        f"Module {rel_path!r} has __all__ = [..., {name!r}, ...] but "
                        f"'{name}' is neither defined nor imported in this file. "
                        "Likely a class/function was extracted to a new module and "
                        "the re-export was forgotten."
                    ),
                    recommendation=(
                        f"Add 'from <new_module> import {name}' to {rel_path}, "
                        f"or remove '{name}' from __all__"
                    ),
                    evidence=[
                        EvidenceReference(
                            kind="file",
                            path=rel_path,
                            detail=f"__all__ declares '{name}' but symbol absent",
                        )
                    ],
                    repair_kind=RepairKind.FIX_CONTRACT.value,
                    executor_action="Add missing re-export or remove from __all__",
                    proof_required="ImportError resolved; __all__ consistent with module contents",
                    allowlist_allowed=True,
                )
            )

    return build_check_result(
        check_id="export_completeness",
        category=GateCategory.CONTRACT,
        findings=findings,
    )
