"""Gate check: detect AI-hallucinated symbols in modified Python files.

Two sub-checks:
  A. hallucination.import_not_found  -- imported name doesn't exist in the source module
  B. hallucination.undefined_call    -- function called without import or local definition

Both checks are WARN-severity (not blocking) to build confidence before escalating.
Files with `from X import *` skip check B (star imports make scope unknowable).
TYPE_CHECKING blocks are skipped in both checks.

Sprint B1 (2026-04-23): check A migrated to the tri-state ``PythonModuleIndex``
resolver. When the module layout is uncertain (src-layout, PEP 420 namespace,
custom PYTHONPATH) findings are emitted with ``applicability="unknown"``
instead of being silently skipped — the reviewer sees the detector's
uncertainty rather than losing signal.
"""
from __future__ import annotations

import ast
from pathlib import Path
from typing import Optional

from cortex_forensic._shared import (
    EvidenceReference,
    GateCategory,
    GateImpact,
    GateSeverity,
)
# standalone: code-hash stamping unavailable
PythonModuleIndex = None  # type: ignore[assignment,misc]
ResolveOutcome = None  # type: ignore[assignment,misc]
from cortex_forensic.gate_models import PostExecGateContext
from cortex_forensic.gate_checks.common import build_check_result, build_finding, iter_touched_snapshots
from cortex_forensic.source_analysis import is_source_file
import logging
_log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Built-in names that are always in scope without any import
# ---------------------------------------------------------------------------

PYTHON_BUILTINS: frozenset[str] = frozenset({
    # Built-in functions
    "abs", "all", "any", "ascii", "bin", "breakpoint", "callable",
    "chr", "compile", "delattr", "dir", "divmod", "enumerate", "eval",
    "exec", "filter", "format", "frozenset", "getattr", "globals",
    "hasattr", "hash", "help", "hex", "id", "input", "isinstance",
    "issubclass", "iter", "len", "list", "locals", "map", "max",
    "memoryview", "min", "next", "object", "oct", "open", "ord",
    "pow", "print", "property", "range", "repr", "reversed", "round",
    "set", "setattr", "slice", "sorted", "staticmethod", "str", "sum",
    "super", "tuple", "type", "vars", "zip",
    # Built-in types
    "bool", "bytearray", "bytes", "classmethod", "complex", "dict", "float", "int",
    # Exceptions
    "ArithmeticError", "AssertionError", "AttributeError", "BaseException",
    "BlockingIOError", "BrokenPipeError", "BufferError",
    "ChildProcessError", "ConnectionAbortedError", "ConnectionError",
    "ConnectionRefusedError", "ConnectionResetError", "DeprecationWarning",
    "EOFError", "EnvironmentError", "Exception", "FileExistsError",
    "FileNotFoundError", "FloatingPointError", "FutureWarning",
    "GeneratorExit", "IOError", "ImportError", "ImportWarning",
    "IndentationError", "IndexError", "InterruptedError", "IsADirectoryError",
    "KeyError", "KeyboardInterrupt", "LookupError", "MemoryError",
    "ModuleNotFoundError", "NameError", "NotADirectoryError",
    "NotImplementedError", "OSError", "OverflowError", "PermissionError",
    "ProcessLookupError", "RecursionError", "ReferenceError",
    "ResourceWarning", "RuntimeError", "RuntimeWarning", "StopAsyncIteration",
    "StopIteration", "SyntaxError", "SyntaxWarning", "SystemError", "SystemExit",
    "TabError", "TimeoutError", "TypeError", "UnboundLocalError",
    "UnicodeDecodeError", "UnicodeEncodeError", "UnicodeError",
    "UnicodeTranslateError", "UnicodeWarning", "UserWarning",
    "ValueError", "Warning", "ZeroDivisionError",
    # Special constants
    "None", "True", "False", "NotImplemented", "Ellipsis",
    # Module-level dunders always present
    "__name__", "__file__", "__doc__", "__package__", "__spec__",
    "__all__", "__annotations__", "__builtins__",
})

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _is_project_module(module: str, roots: tuple[str, ...]) -> bool:
    return any(module.startswith(r) for r in roots)


def _resolve_module_path(module: str, project_dir: Path) -> Path | None:
    """Legacy filesystem-only resolver (kept as fallback for callers without ctx).

    Convert 'SYSTEM.runtime.foo' -> absolute path to foo.py (or package
    __init__.py). Handles cluster topology: SYSTEM, BRAIN, INTERFACE,
    STORAGE, and any roots in ctx.source_package_roots.

    Sprint B1: the primary path is now ``_resolve_module_with_context``
    which returns a tri-state ``ResolveOutcome`` via ``PythonModuleIndex``.
    This function is only used when ``ctx.project_context`` is None (older
    callers that have not yet plumbed the context through).
    """
    rel = module.replace(".", "/")
    candidate = project_dir / (rel + ".py")
    if candidate.exists():
        return candidate
    init = project_dir / rel / "__init__.py"
    if init.exists():
        return init
    return None


def _resolve_module_with_context(
    module: str, ctx: PostExecGateContext
) -> ResolveOutcome:
    """Tri-state module resolution using ctx.project_context when available.

    Returns a ``ResolveOutcome`` with strict tri-state semantics:
      * ``resolved``            — no finding emitted downstream.
      * ``missing_confident``   — applicable finding with confidence >= 0.85.
      * ``resolver_uncertain``  — applicability="unknown" finding with
                                  confidence 0.4-0.7 and a human reason.

    Fallback path (no project_context or no python_module_index): legacy
    filesystem check wrapped into the same ``ResolveOutcome`` vocabulary
    so the caller does not branch on context presence. When fallback finds
    nothing we return ``missing_confident`` only if the module starts with
    a known project source package root — otherwise uncertain (preserves
    FN discipline for older callers).
    """
    # When PythonModuleIndex/ResolveOutcome are unavailable (standalone mode),
    # fall back to filesystem check with a stub result object.
    if PythonModuleIndex is None or ResolveOutcome is None:
        path = _resolve_module_path(module, ctx.project_dir)
        # Return a simple namespace that callers test for .status attribute
        class _StubOutcome:
            def __init__(self, status: str, path: object, confidence: float, reason: str) -> None:
                self.status = status; self.path = path; self.confidence = confidence; self.reason = reason
        if path is not None:
            return _StubOutcome("resolved", path, 0.9, reason="")  # type: ignore[return-value]
        return _StubOutcome("resolver_uncertain", None, 0.4, reason="module index unavailable in standalone mode")  # type: ignore[return-value]

    project_ctx = getattr(ctx, "project_context", None)
    module_index: Optional[PythonModuleIndex] = None
    if project_ctx is not None:
        candidate_index = getattr(project_ctx, "python_module_index", None)
        if isinstance(candidate_index, PythonModuleIndex):
            module_index = candidate_index

    if module_index is not None:
        return module_index.resolve(module)

    # Legacy fallback — older callers without a full ProjectContext.
    path = _resolve_module_path(module, ctx.project_dir)
    if path is not None:
        return ResolveOutcome("resolved", path, 0.9, reason="")
    # Without a module index we cannot distinguish "hallucinated" from
    # "resolver incomplete" — stay uncertain to avoid false positives.
    return ResolveOutcome(
        "resolver_uncertain",
        None,
        0.4,
        reason=(
            f"module index unavailable; {module!r} not found under "
            f"project_dir via direct fs check"
        ),
    )


def _extract_defined_names(source_text: str) -> frozenset[str]:
    """Return all names exported by a module (top-level defs, assignments, __all__)."""
    try:
        tree = ast.parse(source_text)
    except SyntaxError:
        return frozenset()

    names: set[str] = set()
    all_list: list[str] | None = None

    for node in ast.iter_child_nodes(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            names.add(node.name)
        elif isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name):
                    names.add(target.id)
                    if target.id == "__all__" and isinstance(node.value, (ast.List, ast.Tuple)):
                        all_list = [
                            elt.value
                            for elt in node.value.elts
                            if isinstance(elt, ast.Constant) and isinstance(elt.value, str)
                        ]
        elif isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
            names.add(node.target.id)
        elif isinstance(node, ast.Import):
            for alias in node.names:
                names.add(alias.asname or alias.name.split(".")[0])
        elif isinstance(node, ast.ImportFrom) and node.names:
            for alias in node.names:
                if alias.name != "*":
                    names.add(alias.asname or alias.name)

    if all_list is not None:
        return frozenset(all_list) | names
    return frozenset(names)


def _type_checking_lines(tree: ast.Module) -> frozenset[int]:
    """Return line numbers that live inside `if TYPE_CHECKING:` blocks."""
    lines: set[int] = set()
    for node in ast.iter_child_nodes(tree):
        if not isinstance(node, ast.If):
            continue
        test = node.test
        is_tc = (
            (isinstance(test, ast.Name) and test.id == "TYPE_CHECKING")
            or (isinstance(test, ast.Attribute) and test.attr == "TYPE_CHECKING")
        )
        if is_tc:
            for child in ast.walk(node):
                ln = getattr(child, "lineno", None)
                if ln is not None:
                    lines.add(ln)
    return frozenset(lines)


def _collect_known_names(tree: ast.Module) -> frozenset[str]:
    """Names in scope for this file: builtins + imports + local defs + params."""
    names: set[str] = set(PYTHON_BUILTINS)
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            names.add(node.name)
        elif isinstance(node, ast.Import):
            for alias in node.names:
                names.add(alias.asname or alias.name.split(".")[0])
        elif isinstance(node, ast.ImportFrom):
            for alias in node.names:
                if alias.name != "*":
                    names.add(alias.asname or alias.name)
        # Function / method parameters (cls, self, fn, probe_fn, …)
        elif isinstance(node, ast.arg):
            names.add(node.arg)
        # Local assignments: _error = ctx["error"], esc = html.escape, …
        elif isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name):
                    names.add(target.id)
                elif isinstance(target, (ast.Tuple, ast.List)):
                    for elt in target.elts:
                        if isinstance(elt, ast.Name):
                            names.add(elt.id)
        elif isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
            names.add(node.target.id)
        # for x in …  /  async for x in …
        elif isinstance(node, (ast.For, ast.AsyncFor)):
            if isinstance(node.target, ast.Name):
                names.add(node.target.id)
            elif isinstance(node.target, (ast.Tuple, ast.List)):
                for elt in node.target.elts:
                    if isinstance(elt, ast.Name):
                        names.add(elt.id)
        # with … as x:
        elif isinstance(node, ast.withitem):
            if node.optional_vars and isinstance(node.optional_vars, ast.Name):
                names.add(node.optional_vars.id)
        # except Exc as e:
        elif isinstance(node, ast.ExceptHandler) and node.name:
            names.add(node.name)
        # walrus operator  x := expr
        elif isinstance(node, ast.NamedExpr):
            names.add(node.target.id)
    return frozenset(names)


def _has_star_import(tree: ast.Module) -> bool:
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom):
            for alias in node.names:
                if alias.name == "*":
                    return True
    return False


# ---------------------------------------------------------------------------
# Check A: imported name doesn't exist in source module
# ---------------------------------------------------------------------------


def _check_imports(
    snapshot, ctx: PostExecGateContext, tree: ast.Module
) -> list:
    """Sprint B1: tri-state import resolution via PythonModuleIndex.

    Three outcomes per ``from <module> import <name>`` statement:
      * module.resolve(module) == ``resolved``            → compare name
        against module's defined symbols (legacy behaviour — confident
        finding when name is missing).
      * module.resolve(module) == ``missing_confident``   → emit
        ``hallucination.module_not_found`` at ``applicability="applicable"``.
      * module.resolve(module) == ``resolver_uncertain``  → emit
        ``hallucination.import_not_found`` at ``applicability="unknown"``
        so the reviewer keeps visibility on a potential hallucination
        without us pretending to be sure.
    """
    findings = []
    tc_lines = _type_checking_lines(tree)

    for node in ast.walk(tree):
        if not isinstance(node, ast.ImportFrom) or not node.module:
            continue
        lineno = getattr(node, "lineno", 0)
        if lineno in tc_lines:
            continue
        if not _is_project_module(node.module, ctx.source_package_roots):
            continue

        outcome = _resolve_module_with_context(node.module, ctx)

        if outcome.status == "resolver_uncertain":
            # Layout uncertainty — emit one finding per (module, name) pair
            # flagged as unknown so the reviewer sees the uncertainty. We
            # cannot say the name is missing (module may provide it at
            # runtime via custom PYTHONPATH), but we can say "we don't
            # know" rather than silently dropping the signal.
            for alias in node.names:
                if alias.name in ("*", "_"):
                    continue
                findings.append(
                    build_finding(
                        check_id="hallucination.import_not_found",
                        category=GateCategory.CONTRACT,
                        title=f"Unresolved import '{alias.name}' from {node.module}",
                        severity=GateSeverity.LOW,
                        impact=GateImpact.WARN,
                        summary=(
                            f"{snapshot.path} line {lineno}: imports "
                            f"'{alias.name}' from '{node.module}'. Resolver "
                            f"cannot determine whether this module resolves "
                            f"at runtime (uncertain layout: "
                            f"{outcome.reason})."
                        ),
                        recommendation=(
                            f"Inspect manually: does '{node.module}' resolve "
                            f"at runtime and does it export '{alias.name}'? "
                            f"If yes, consider marking the module index "
                            f"aware of this path."
                        ),
                        evidence=[
                            EvidenceReference(
                                kind="file",
                                path=snapshot.path,
                                detail=f"line {lineno}: from {node.module} import {alias.name}",
                            )
                        ],
                        repair_kind='validate_boundary',
                        executor_action='Address finding details',
                        proof_required='No hallucination',
                        allowlist_allowed=True,
                        confidence=outcome.confidence,
                        applicability="unknown",
                        analysis_mode="ast",
                        applicability_reason=(
                            outcome.reason
                            or "resolver incomplete for this project layout"
                        ),
                    )
                )
            continue

        if outcome.status == "missing_confident":
            # Module itself doesn't exist in the project. One finding per
            # imported name so reviewers see which symbols are affected.
            for alias in node.names:
                if alias.name in ("*", "_"):
                    continue
                findings.append(
                    build_finding(
                        check_id="hallucination.import_not_found",
                        category=GateCategory.CONTRACT,
                        title=f"Module '{node.module}' not found for import '{alias.name}'",
                        severity=GateSeverity.MEDIUM,
                        impact=GateImpact.REVISE,
                        summary=(
                            f"{snapshot.path} line {lineno}: imports "
                            f"'{alias.name}' from '{node.module}' but the "
                            f"module is not present in the project tree. "
                            f"{outcome.reason}"
                        ),
                        recommendation=(
                            f"Verify '{node.module}' exists. If renamed, "
                            f"update the import; if missing, create the "
                            f"module or remove the stale import."
                        ),
                        evidence=[
                            EvidenceReference(
                                kind="file",
                                path=snapshot.path,
                                detail=f"line {lineno}: from {node.module} import {alias.name}",
                            )
                        ],
                        repair_kind='validate_boundary',
                        executor_action='Address finding details',
                        proof_required='No hallucination',
                        allowlist_allowed=False,
                        confidence=outcome.confidence,
                        applicability="applicable",
                        analysis_mode="ast",
                    )
                )
            continue

        # outcome.status == "resolved" — verify the imported name exists
        # inside the resolved module using the legacy file-based detector.
        source_path = outcome.path
        if source_path is None:
            # Defensive — resolved outcome must carry a path; if not, skip.
            continue

        try:
            source_text = source_path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue

        defined = _extract_defined_names(source_text)

        # Package dir for submodule existence checks. Use the resolved
        # file's parent so src-layout resolutions see the correct dir.
        if source_path.name == "__init__.py":
            pkg_dir = source_path.parent
        else:
            pkg_dir = source_path.parent / source_path.stem
            if not pkg_dir.is_dir():
                pkg_dir = source_path.parent

        for alias in node.names:
            if alias.name in ("*", "_"):
                continue
            # Valid submodule import: from pkg import submod where pkg/submod.py
            # or pkg/submod/__init__.py exists. Python resolves these without
            # the name appearing in __init__.py, so skip — not a hallucination.
            if (pkg_dir / (alias.name + ".py")).exists() or (pkg_dir / alias.name / "__init__.py").exists():
                continue
            if alias.name not in defined:
                findings.append(
                    build_finding(
                        check_id="hallucination.import_not_found",
                        category=GateCategory.CONTRACT,
                        title=f"Imported '{alias.name}' not found in {node.module}",
                        severity=GateSeverity.MEDIUM,
                        impact=GateImpact.REVISE,
                        summary=(
                            f"{snapshot.path} line {lineno}: imports '{alias.name}' "
                            f"from '{node.module}' but that name is not defined there. "
                            f"Likely an AI hallucination -- the symbol was invented."
                        ),
                        recommendation=(
                            f"Check that '{alias.name}' exists in {node.module}. "
                            f"If added in this edit, ensure the definition is also present."
                        ),
                        evidence=[
                            EvidenceReference(
                                kind="file",
                                path=snapshot.path,
                                detail=f"line {lineno}: from {node.module} import {alias.name}",
                            )
                        ],
                        repair_kind='validate_boundary',
                        executor_action='Address finding details',
                        proof_required='No hallucination',
                        allowlist_allowed=False,
                        confidence=0.9,
                        applicability="applicable",
                        analysis_mode="ast",
                    )
                )
    return findings


# ---------------------------------------------------------------------------
# Check B: function called without being imported or locally defined
# ---------------------------------------------------------------------------


def _check_undefined_calls(
    snapshot, tree: ast.Module
) -> list:
    # Star imports make scope unknowable — skip conservatively
    if _has_star_import(tree):
        return []

    findings = []
    known = _collect_known_names(tree)
    tc_lines = _type_checking_lines(tree)

    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        if not isinstance(node.func, ast.Name):
            continue  # skip obj.method() -- needs type inference

        name = node.func.id
        lineno = getattr(node, "lineno", 0)

        if lineno in tc_lines:
            continue
        if name.startswith("__"):
            continue  # dunder names are always special
        if name in known:
            continue

        findings.append(
            build_finding(
                check_id="hallucination.undefined_call",
                category=GateCategory.CONTRACT,
                title=f"Call to undefined '{name}' in {snapshot.path}",
                severity=GateSeverity.MEDIUM,
                impact=GateImpact.REVISE,
                summary=(
                    f"{snapshot.path} line {lineno}: calls '{name}()' "
                    f"but this name is not imported or defined in the file. "
                    f"Likely an AI hallucination -- the function was invented."
                ),
                recommendation=(
                    f"Add an import for '{name}' or define it before use. "
                    f"If it should come from another module, add the import statement."
                ),
                evidence=[
                    EvidenceReference(
                        kind="file",
                        path=snapshot.path,
                        detail=f"line {lineno}: {name}(...)",
                    )
                ],
            
                repair_kind='validate_boundary',
                executor_action='Address finding details',
                proof_required='No hallucination',
                allowlist_allowed=False,
            )
        )
    return findings


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def run_hallucination_checks(ctx: PostExecGateContext):
    """Detect AI-hallucinated symbols in touched Python files."""
    findings = []
    for snapshot in iter_touched_snapshots(ctx):
        if not snapshot.exists or not is_source_file(snapshot.path):
            continue
        if not snapshot.text.strip():
            continue
        try:
            tree = ast.parse(snapshot.text, filename=snapshot.path)
        except SyntaxError:
            continue  # handled by syntax_validity_checks
        findings.extend(_check_imports(snapshot, ctx, tree))
        findings.extend(_check_undefined_calls(snapshot, tree))
    return build_check_result(
        check_id="hallucination",
        category=GateCategory.CONTRACT,
        findings=findings,
    )
