"""Detect imports inside function bodies — should be at module top.

Pattern caught:

    def foo():
        import json  # <-- module-level import buried inside a function
        return json.dumps(...)

Move stdlib imports to module top unless a legitimate reason (circular import,
deferred load of an optional heavy dep) is documented inline via a recognized
comment marker.
"""
from __future__ import annotations

import ast
import json as _json
import logging
import time

from cortex_forensic._shared import (
    EvidenceReference,
    GateCategory,
    GateImpact,
    GateSeverity,
    RepairKind,
)
from cortex_forensic.gate_models import PostExecGateContext
from cortex_forensic.gate_checks.common import (
    build_check_result,
    build_finding,
    normalize_path,
)

_log = logging.getLogger(__name__)


# W4.BQ: relative path (under project_dir) where this gate persists its
# findings each run. Downstream MEDIUM-executor repair flow reads this file
# via the path stored on adapter._imports_lift_findings_path.
PERSISTED_FINDINGS_RELPATH = ".cortex/forensics/imports_in_function_findings.json"


# Stdlib modules: local-inside-function imports of these are almost always smell.
# (We deliberately stay conservative — narrow set of standard, lightweight
#  modules. Third-party / heavyweight modules are commonly lazy-loaded and
#  would produce noisy findings if listed.)
_STDLIB_LOCAL_IMPORT_SMELLS: frozenset[str] = frozenset({
    "json",
    "os",
    "sys",
    "re",
    "logging",
    "hashlib",
    "uuid",
    "time",
    "datetime",
    "pathlib",
    "subprocess",
    "threading",
    "collections",
    "itertools",
    "functools",
    "typing",
    "math",
    "io",
    "string",
    "enum",
})


# Inline comment markers that legitimize a local import. Matched
# case-insensitively as substrings of the import line's trailing comment.
_LEGITIMATE_REASON_MARKERS: tuple[str, ...] = (
    "# circular",
    "# lazy",
    "# defer",
    "# type_checking",
    "# noqa: imports_in_function",
    "# autoforensics-skip: imports_in_function",
)


def _is_legitimate(line_text: str) -> bool:
    """Return True if the import line carries a recognized legitimacy marker."""
    lowered = line_text.lower()
    return any(marker in lowered for marker in _LEGITIMATE_REASON_MARKERS)


def _iter_imports_within(func: ast.FunctionDef | ast.AsyncFunctionDef):
    """Yield (Import|ImportFrom, enclosing_function_name) for nodes inside *func*.

    A nested function definition gets its own enclosing scope reported; the
    walker descends into the nested def so the user sees the closest function.
    """
    stack: list[tuple[ast.AST, str]] = [(func, func.name)]
    while stack:
        node, enclosing_name = stack.pop()
        for child in ast.iter_child_nodes(node):
            if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)):
                # Descend into nested function with updated enclosing name.
                stack.append((child, child.name))
                continue
            if isinstance(child, (ast.Import, ast.ImportFrom)):
                yield child, enclosing_name
            else:
                # Descend into other constructs (If/Try/For/With/...) keeping
                # the same enclosing function name.
                stack.append((child, enclosing_name))


def _module_names(node: ast.Import | ast.ImportFrom) -> list[str]:
    if isinstance(node, ast.Import):
        return [alias.name for alias in node.names]
    # ImportFrom: report the source module (or "" for relative-only imports).
    return [node.module or ""]


def run_imports_in_function_checks(ctx: PostExecGateContext):
    """Scan changed Python files for stdlib imports inside function bodies."""
    findings: list = []
    # W4.BQ: parallel structured records — same data as the GateFinding
    # tuples above, but in a flat shape the MEDIUM-tier repair executor can
    # consume without de-serializing GateFinding dataclasses from JSON. The
    # shape is the public contract for the brief-mutation step.
    persisted_records: list[dict] = []

    for raw_path in ctx.changed_files_reported or ctx.touched_files:
        normalized = normalize_path(raw_path)

        if not normalized.endswith(".py"):
            continue
        # Skip vendor / libs tree — third-party code, not ours to police.
        if "SYSTEM/libs/" in normalized or normalized.startswith("SYSTEM/libs"):
            continue

        abs_path = ctx.project_dir / normalized
        if not abs_path.exists() or not abs_path.is_file():
            continue

        try:
            source = abs_path.read_text(encoding="utf-8", errors="replace")
        except OSError as exc:
            _log.debug("imports_in_function: cannot read %s: %s", normalized, exc)
            continue

        try:
            tree = ast.parse(source, filename=normalized)
        except SyntaxError as exc:
            _log.debug("imports_in_function: cannot parse %s: %s", normalized, exc)
            continue

        source_lines = source.splitlines()

        # Collect entry-point function definitions: any FunctionDef/AsyncFunctionDef
        # that is NOT lexically inside another function. Methods of classes count
        # as entry points (a class body is not a function). The recursive walker
        # below descends into nested functions itself, so we must not double-walk.
        entry_funcs: list[ast.FunctionDef | ast.AsyncFunctionDef] = []

        def _collect(node: ast.AST, inside_func: bool) -> None:
            for child in ast.iter_child_nodes(node):
                if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    if not inside_func:
                        entry_funcs.append(child)
                    _collect(child, True)
                else:
                    _collect(child, inside_func)

        _collect(tree, False)

        for top_node in entry_funcs:
            for import_node, enclosing_name in _iter_imports_within(top_node):
                names = _module_names(import_node)
                if not names:
                    continue

                # Only flag imports whose first dotted component matches our
                # stdlib smell set. Stays conservative — heavyweight / 3rd-party
                # lazy imports are intentionally NOT flagged.
                top_levels = [n.split(".")[0] for n in names if n]
                if not any(t in _STDLIB_LOCAL_IMPORT_SMELLS for t in top_levels):
                    continue

                lineno = int(getattr(import_node, "lineno", 0) or 0)
                line_text = (
                    source_lines[lineno - 1] if 1 <= lineno <= len(source_lines) else ""
                )

                if _is_legitimate(line_text):
                    continue

                joined = ", ".join(n for n in names if n)
                # W4.BQ: capture per-finding structured record for disk
                # persistence. abs_path is resolved against ctx.project_dir
                # so MEDIUM executor can directly Edit the file.
                persisted_records.append({
                    "file": str(abs_path),
                    "file_relpath": normalized,
                    "line": lineno,
                    "function": enclosing_name,
                    "imported": [n for n in names if n],
                    "line_text": line_text,
                    "suggestion": (
                        f"Move 'import {joined}' from function "
                        f"{enclosing_name}() to module top."
                    ),
                })
                findings.append(
                    build_finding(
                        check_id="imports_in_function.stdlib",
                        category=GateCategory.DRIFT,
                        title=(
                            f"Stdlib import inside function '{enclosing_name}' in "
                            f"{normalized}:{lineno}"
                        ),
                        severity=GateSeverity.MEDIUM,
                        impact=GateImpact.REVISE,
                        summary=(
                            f"Function {enclosing_name}() in {normalized} imports "
                            f"'{joined}' inside its body. Stdlib imports belong at "
                            "module top so the dependency is visible to readers, "
                            "static analysis, and import graph tools."
                        ),
                        recommendation=(
                            f"Move 'import {joined}' from {enclosing_name}() to the "
                            "module top. If the local import is intentional "
                            "(circular import, lazy load), add a trailing comment "
                            "such as '# lazy: ...', '# circular: ...', or "
                            "'# noqa: imports_in_function' on the import line."
                        ),
                        evidence=[
                            EvidenceReference(
                                kind="file",
                                path=normalized,
                                detail=f"line:{lineno} function:{enclosing_name}",
                            )
                        ],
                        repair_kind=RepairKind.FIX_CONTRACT.value,
                        executor_action=(
                            "Hoist the import to module top, or add a legitimacy "
                            "marker comment on the import line."
                        ),
                        proof_required=(
                            "Import is at module top OR import line carries a "
                            "recognized legitimacy marker."
                        ),
                        allowlist_allowed=True,
                    )
                )

    # W4.BQ: persist structured findings to disk so the downstream MEDIUM
    # repair executor can consume them. Best-effort — never fail the gate
    # because we couldn't write the artifact. The file is overwritten on
    # every run (atomic full rewrite; no append) so stale entries from
    # prior sessions do not contaminate the current repair brief.
    if persisted_records:
        try:
            findings_path = ctx.project_dir / PERSISTED_FINDINGS_RELPATH
            findings_path.parent.mkdir(parents=True, exist_ok=True)
            payload = {
                "schema_version": "1.0",
                "generated_at": time.time(),
                "count": len(persisted_records),
                "findings": persisted_records,
            }
            findings_path.write_text(
                _json.dumps(payload, indent=2, ensure_ascii=False),
                encoding="utf-8",
            )
            _log.info(
                "imports_in_function: persisted %d findings to %s",
                len(persisted_records), findings_path,
            )
        except OSError as exc:
            _log.warning(
                "imports_in_function: failed to persist findings: %s", exc,
            )

    return build_check_result(
        check_id="imports_in_function",
        category=GateCategory.DRIFT,
        findings=findings,
    )
