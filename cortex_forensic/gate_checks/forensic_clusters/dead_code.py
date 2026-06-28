"""Dead code and unused import clusters 20, 23.

Clusters:
  20 - Dead Code
  23 - Unused Imports
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from .core import detect_language, _insufficient_evidence_finding
from ...gate_models import (
    EvidenceReference,
    GateCategory,
    GateFinding,
    GateImpact,
    GateSeverity,
    RepairKind,
)
from ..common import build_finding
import logging
_log = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Cluster 20: Dead Code
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class DeadCodeItem:
    """A potentially dead code item with classification."""
    name: str
    file_path: str
    line: int
    kind: str  # "function" | "class" | "import"
    classification: str  # "dead_code" | "likely_forgotten_wiring" | "standalone_utility"
    reason: str


_STANDALONE_MARKERS = frozenset({
    "main", "cli", "entry", "handler", "hook", "callback", "plugin",
    "fixture", "setup", "teardown", "conftest", "register", "migrate",
    "command", "task", "worker", "job", "cron", "schedule",
})

_STANDALONE_DECORATORS = (
    "@app.", "@click.", "@pytest.fixture", "@staticmethod",
    "@classmethod", "@property", "@abstractmethod", "@override",
    "@register", "@task", "@celery",
)


def assess_dead_code(
    items: list[DeadCodeItem],
) -> list[GateFinding]:
    """Cluster 20: Classify dead code as truly dead, forgotten wiring, or standalone."""
    if not items:
        return []  # NOT_APPLICABLE

    findings: list[GateFinding] = []
    for item in items:
        if item.classification == "standalone_utility":
            continue

        is_fail = item.classification in ("dead_code", "likely_forgotten_wiring")
        if not is_fail:
            continue

        severity_hint = "FORGOTTEN WIRING" if item.classification == "likely_forgotten_wiring" else "DEAD CODE"
        detail = f"[{severity_hint}] {item.kind} '{item.name}': {item.reason}"
        findings.append(build_finding(
            check_id="dead_code_scan",
            category=GateCategory.DRIFT,
            title=f"[dead_code] {item.file_path}:{item.line}:{item.name}",
            severity=GateSeverity.MEDIUM,
            impact=GateImpact.REVISE,
            summary=detail,
            recommendation=f"Remove or wire up dead code: '{item.name}' in {item.file_path}",
            evidence=(EvidenceReference(kind="probe", path=item.file_path, detail=detail, ok=False),),
            repair_kind=RepairKind.REMOVE_DUPLICATE.value,
            executor_action=f"Remove or wire up '{item.name}' at {item.file_path}:{item.line}",
        ))
    return findings


def classify_dead_code_item(
    name: str,
    file_path: str,
    line: int,
    kind: str,
    is_referenced_anywhere: bool,
    is_in_all: bool,
    is_recent_commit: bool,
    has_adjacent_caller_file: bool,
    decorator_line: str = "",
) -> DeadCodeItem:
    """Classify a potentially unused code item into one of 3 categories."""
    name_lower = name.lower()
    if any(marker in name_lower for marker in _STANDALONE_MARKERS):
        return DeadCodeItem(name=name, file_path=file_path, line=line, kind=kind,
            classification="standalone_utility", reason="Name contains standalone marker")

    if is_in_all:
        return DeadCodeItem(name=name, file_path=file_path, line=line, kind=kind,
            classification="standalone_utility", reason="Listed in __all__ -- public API")

    if any(decorator_line.strip().startswith(d) for d in _STANDALONE_DECORATORS):
        return DeadCodeItem(name=name, file_path=file_path, line=line, kind=kind,
            classification="standalone_utility", reason=f"Has framework decorator: {decorator_line.strip()[:40]}")

    if is_referenced_anywhere:
        return DeadCodeItem(name=name, file_path=file_path, line=line, kind=kind,
            classification="standalone_utility", reason="Referenced elsewhere in project")

    if is_recent_commit and has_adjacent_caller_file:
        return DeadCodeItem(name=name, file_path=file_path, line=line, kind=kind,
            classification="likely_forgotten_wiring",
            reason="Added recently with adjacent caller file that doesn't use it")

    if is_recent_commit:
        return DeadCodeItem(name=name, file_path=file_path, line=line, kind=kind,
            classification="likely_forgotten_wiring",
            reason="Added recently but not referenced anywhere")

    # Precision guard (oracle FP fix): a PUBLIC (non-underscore) symbol that is
    # merely unreferenced WITHIN the scanned set is NOT reliably dead -- it may
    # be library / public API consumed by callers outside the scan scope. Only
    # PRIVATE (underscore-prefixed) unreferenced symbols are treated as dead.
    # Keeps recall on truly-private dead code (e.g. ``_never_called``) while
    # eliminating false positives on public functions in partial/library scans.
    if not name.startswith("_"):
        return DeadCodeItem(name=name, file_path=file_path, line=line, kind=kind,
            classification="standalone_utility",
            reason="Public symbol unreferenced in scan -- may be external API")

    return DeadCodeItem(name=name, file_path=file_path, line=line, kind=kind,
        classification="dead_code",
        reason="Not referenced anywhere in the project")


# ---------------------------------------------------------------------------
# Cluster 23: Unused Imports
# ---------------------------------------------------------------------------


def _collect_type_checking_import_line_nums(tree: "ast.Module") -> set[int]:
    """Return line numbers of every Import / ImportFrom node that appears inside
    the BODY of an `if TYPE_CHECKING:` (or `if typing.TYPE_CHECKING:`) block.

    Only the ``if`` body is scanned, NOT the ``else`` branch.  Imports in the
    ``else:`` branch of a TYPE_CHECKING guard are RUNTIME imports (the common
    ``if TYPE_CHECKING: <type-import> else: <runtime-import-or-fallback>``
    idiom); tagging them as TYPE_CHECKING imports produced false positives on
    real projects (e.g. filelock ``__init__.py`` else-branch imports). Fix
    2026-06-28 (FP-round2-A).

    AST walk only — no regex on source text.
    """
    import ast

    tc_import_lines: set[int] = set()
    for node in ast.walk(tree):
        if not isinstance(node, ast.If):
            continue
        test = node.test
        is_tc_guard = (
            (isinstance(test, ast.Name) and test.id == "TYPE_CHECKING")
            or (isinstance(test, ast.Attribute) and test.attr == "TYPE_CHECKING")
        )
        if not is_tc_guard:
            continue
        # Walk ONLY the body statements (not node.orelse). Nested If/imports
        # inside the body are still collected via ast.walk over each stmt.
        for stmt in node.body:
            for child in ast.walk(stmt):
                if isinstance(child, (ast.Import, ast.ImportFrom)):
                    tc_import_lines.add(child.lineno)
    return tc_import_lines


def _collect_runtime_referenced_names(tree: "ast.Module") -> set[str]:
    """Collect every bare identifier referenced as a runtime VALUE.

    This covers usages a TYPE_CHECKING import legitimately satisfies that are
    NOT type annotations, and which ``_collect_forward_ref_strings`` misses:

      * ``Name`` loads anywhere (``TypeVar(...)`` call name, ``X`` value use).
      * ``Attribute`` base names (``te.ParamSpec`` -> ``te``, ``sys.version_info``
        -> ``sys``).
      * ``__all__`` string members (a TYPE_CHECKING import re-exported via
        ``__all__`` is a public re-export, not a dead import).

    Fix 2026-06-28 (FP-round2-A): TYPE_CHECKING imports are treated as USED if
    the name appears in this set, because such imports exist precisely to back
    type-only references — which include runtime ``TypeVar(...)`` construction,
    ``sys.version_info`` version-gating, and ``__all__`` re-exports.

    AST walk only.
    """
    import ast

    names: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Name):
            names.add(node.id)
        elif isinstance(node, ast.Attribute):
            # Walk down to the root Name of an attribute chain (a.b.c -> a).
            base = node.value
            while isinstance(base, ast.Attribute):
                base = base.value
            if isinstance(base, ast.Name):
                names.add(base.id)
        elif isinstance(node, ast.Assign):
            # __all__ = ["Foo", "Bar"] — string members are re-exports.
            for target in node.targets:
                if isinstance(target, ast.Name) and target.id == "__all__":
                    for elt in ast.walk(node.value):
                        if isinstance(elt, ast.Constant) and isinstance(elt.value, str):
                            names.add(elt.value)
    return names


def _collect_forward_ref_strings(tree: "ast.Module") -> set[str]:
    """Collect all bare identifiers referenced as type-expressions.

    Sources (F9c + F9c-tighten 2026-04-23):
      * AnnAssign annotations (``x: Foo``).
      * Function argument / return annotations.
      * String-quoted forward references inside the above.
      * First argument of ``cast(...)`` / ``typing.cast(...)`` — blind-spot
        C. The cast's first arg is a type expression that MUST keep its
        TYPE_CHECKING import alive. Supports ``cast(Foo, v)`` and
        ``cast("Foo", v)``.
      * Second argument of ``isinstance(v, X)`` / ``issubclass(c, X)`` —
        parity case for string-quoted runtime type refs.
    """
    import ast

    names: set[str] = set()

    def _extract_from_annotation(ann: ast.AST | None) -> None:
        if ann is None:
            return
        for sub in ast.walk(ann):
            if isinstance(sub, ast.Name):
                names.add(sub.id)
            elif isinstance(sub, ast.Constant) and isinstance(sub.value, str):
                # Forward ref: "ForensicReport" | "Foo[Bar]" | "list[Foo]"
                try:
                    inner = ast.parse(sub.value, mode="eval")
                except SyntaxError:
                    # Add any identifier-like token to be safe
                    for tok in sub.value.replace("[", " ").replace("]", " ").replace(",", " ").split():
                        tok = tok.strip().strip("'\"")
                        if tok.isidentifier():
                            names.add(tok)
                    continue
                for n in ast.walk(inner):
                    if isinstance(n, ast.Name):
                        names.add(n.id)

    def _is_cast_call(call: ast.Call) -> bool:
        """True if *call* is ``cast(...)`` or ``<anything>.cast(...)``."""
        f = call.func
        if isinstance(f, ast.Name) and f.id == "cast":
            return True
        if isinstance(f, ast.Attribute) and f.attr == "cast":
            return True
        return False

    def _is_isinstance_call(call: ast.Call) -> bool:
        f = call.func
        return isinstance(f, ast.Name) and f.id in ("isinstance", "issubclass")

    for node in ast.walk(tree):
        if isinstance(node, ast.AnnAssign):
            _extract_from_annotation(node.annotation)
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            _extract_from_annotation(node.returns)
            for arg in (
                list(node.args.args)
                + list(node.args.kwonlyargs)
                + list(node.args.posonlyargs)
                + ([node.args.vararg] if node.args.vararg else [])
                + ([node.args.kwarg] if node.args.kwarg else [])
            ):
                if arg is not None:
                    _extract_from_annotation(arg.annotation)
        elif isinstance(node, ast.arg):
            _extract_from_annotation(node.annotation)
        # F9c-tighten: cast(TypeName, v) / cast("TypeName", v).
        elif isinstance(node, ast.Call) and _is_cast_call(node) and node.args:
            _extract_from_annotation(node.args[0])
        # F9c-tighten parity: isinstance(v, TypeName) — second-arg type ref.
        elif isinstance(node, ast.Call) and _is_isinstance_call(node) and len(node.args) >= 2:
            _extract_from_annotation(node.args[1])
    return names


def assess_unused_imports(
    file_path: str,
    content: str,
    project_files_content: dict[str, str] | None = None,
) -> list[GateFinding]:
    """Cluster 23: Detect unused imports.

    TYPE_CHECKING honoring (F9c): imports inside `if TYPE_CHECKING:` blocks are
    treated as forward-reference imports. They are flagged ONLY if the imported
    symbol is never referenced as a type annotation (direct Name, string
    forward-ref, or AnnAssign target). Truly dead TYPE_CHECKING imports still
    raise a finding.
    """
    import ast
    import re

    lang = detect_language(file_path)
    if lang != "python":
        return []  # NOT_APPLICABLE

    if not content.strip():
        return []  # NOT_APPLICABLE

    # --- AST pre-pass for TYPE_CHECKING detection (F9c) ------------------
    tc_import_line_nums: set[int] = set()
    forward_ref_names: set[str] = set()
    runtime_ref_names: set[str] = set()
    try:
        tree = ast.parse(content)
    except SyntaxError:
        tree = None
    if tree is not None:
        tc_import_line_nums = _collect_type_checking_import_line_nums(tree)
        forward_ref_names = _collect_forward_ref_strings(tree)
        # FP-round2-A (2026-06-28): names referenced as runtime values
        # (TypeVar(...) call, te.ParamSpec attribute base, sys.version_info,
        # __all__ re-export). A TYPE_CHECKING import satisfying any of these is
        # USED, not dead.
        runtime_ref_names = _collect_runtime_referenced_names(tree)

    lines = content.splitlines()

    imports: list[tuple[int, str, str]] = []  # (line_num, imported_name, full_line)
    for i, line in enumerate(lines, 1):
        stripped = line.strip()
        if stripped.startswith("#"):
            continue

        m = re.match(r"from\s+[\w.]+\s+import\s+(.+?)(?:\s+#.*)?$", stripped)
        if m:
            names_str = m.group(1)
            if "(" in names_str:
                continued = names_str
                j = i
                while ")" not in continued and j < len(lines):
                    j += 1
                    continued += " " + lines[j - 1].strip()
                names_str = continued.replace("(", "").replace(")", "")

            for part in names_str.split(","):
                part = part.strip()
                if not part:
                    continue
                if " as " in part:
                    alias = part.split(" as ")[1].strip()
                    imports.append((i, alias, stripped))
                else:
                    name = part.split(".")[0].strip()
                    if name and name.isidentifier():
                        imports.append((i, name, stripped))
            continue

        m = re.match(r"import\s+([\w.]+)(?:\s+as\s+(\w+))?", stripped)
        if m:
            name = m.group(2) or m.group(1).split(".")[-1]
            imports.append((i, name, stripped))

    if not imports:
        return []  # NOT_APPLICABLE

    body_lines = []
    import_line_nums = {line_num for line_num, _, _ in imports}
    for i, line in enumerate(lines, 1):
        if i not in import_line_nums:
            body_lines.append(line)
    body = "\n".join(body_lines)

    findings: list[GateFinding] = []
    for line_num, name, full_line in imports:
        if name == "annotations" and "future" in full_line:
            continue
        # Bare `TYPE_CHECKING` import is always skipped (it's the guard itself).
        if name == "TYPE_CHECKING":
            continue
        if name.startswith("_"):
            continue

        # --- F9c: TYPE_CHECKING-guarded forward-ref import handling ---------
        is_in_tc_block = line_num in tc_import_line_nums
        if is_in_tc_block:
            # The import is inside `if TYPE_CHECKING:`. Treat it as used if the
            # name appears anywhere as an annotation (direct Name or string
            # forward-ref). Otherwise flag it as a dead TYPE_CHECKING import.
            if name in forward_ref_names:
                continue
            # FP-round2-A (2026-06-28): also treat as used if the name is
            # referenced as a runtime value inside (or outside) the block —
            # TypeVar(...) construction, `te.ParamSpec`/`sys.version_info`
            # attribute base, or an `__all__` re-export. These are the
            # legitimate non-annotation uses a TYPE_CHECKING import backs.
            if name in runtime_ref_names:
                continue
            # Not referenced anywhere in annotations → still flag below with
            # specialized wording.
            findings.append(build_finding(
                check_id="unused_import_scan",
                category=GateCategory.DRIFT,
                title=f"[unused_imports] {file_path}:{line_num}:{name}",
                severity=GateSeverity.LOW,
                impact=GateImpact.WARN,
                summary=(
                    f"Import '{name}' at line {line_num} is inside `if TYPE_CHECKING:` "
                    f"but is never used as a type annotation"
                ),
                recommendation=f"Remove unused TYPE_CHECKING import '{name}' from {file_path}.",
                evidence=(EvidenceReference(
                    kind="probe",
                    path=file_path,
                    detail=(
                        f"Import '{name}' inside TYPE_CHECKING block at line {line_num} "
                        f"is not referenced by any annotation"
                    ),
                    ok=False,
                ),),
                repair_kind=RepairKind.REMOVE_DUPLICATE.value,
                executor_action=f"Remove unused TYPE_CHECKING import '{name}' at line {line_num}",
            ))
            if len(findings) >= 20:
                break
            continue

        if " as " in full_line:
            parts = full_line.split(" as ")
            if len(parts) >= 2:
                original = parts[-2].strip().split()[-1].strip().rstrip(",")
                alias = parts[-1].strip().split(",")[0].split("#")[0].strip()
                if original == alias:
                    continue

        all_match = re.search(r"__all__\s*=\s*[\[\(](.*?)[\]\)]", content, re.DOTALL)
        if all_match and f'"{name}"' in all_match.group(1) or all_match and f"'{name}'" in all_match.group(1):
            continue

        pattern = rf"\b{re.escape(name)}\b"
        used_in_body = bool(re.search(pattern, body))

        if not used_in_body:
            type_patterns = [
                rf"(?::\s*|->\s*){re.escape(name)}\b",
                rf"\b{re.escape(name)}\[",
                rf",\s*{re.escape(name)}\]",
            ]
            if any(re.search(tp, body) for tp in type_patterns):
                continue

            findings.append(build_finding(
                check_id="unused_import_scan",
                category=GateCategory.DRIFT,
                title=f"[unused_imports] {file_path}:{line_num}:{name}",
                severity=GateSeverity.LOW,
                impact=GateImpact.WARN,
                summary=f"Import '{name}' at line {line_num} is not used in file body",
                recommendation=f"Remove unused import '{name}' from {file_path}.",
                evidence=(EvidenceReference(kind="probe", path=file_path, detail=f"Import '{name}' at line {line_num} is not used in file body", ok=False),),
                repair_kind=RepairKind.REMOVE_DUPLICATE.value,
                executor_action=f"Remove unused import '{name}' at line {line_num}",
            ))
        if len(findings) >= 20:
            break
    return findings
