"""C53: Legacy Compatibility Debt.

Detects obsolete compatibility/shim layers via structure-based analysis
(not relying on naming conventions like "legacy/shim/compat").

Sub-checks:
  forwarding_wrapper         -- module is >70% re-export lines, no domain logic
  unused_shim_module         -- module exports have zero non-test callers in repo
  stale_migration_marker     -- comment contains stale migration TODO/DEPRECATED marker
  shape_adapter_without_producer -- dict key transform with no active producer
"""
from __future__ import annotations

import re
from pathlib import Path

from ...gate_models import (
    EvidenceReference,
    GateCategory,
    GateFinding,
    GateImpact,
    GateSeverity,
    RepairKind,
)
from ..common import (
    build_finding,
    collect_constant_container_literal_lines,
    is_section_header_comment,
)
from .._ast_helpers import collect_string_constant_line_ranges
import logging
_log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_REEXPORT_PATTERN = re.compile(
    r"^\s*(?:from\s+[\w.]+\s+import\s+\S|(\w+)\s*=\s*[\w.]+\.\w+)",
    re.MULTILINE,
)

_FUNCTION_DEF_PATTERN = re.compile(
    r"^\s*(?:async\s+)?def\s+\w+\s*\(",
    re.MULTILINE,
)

_MIGRATION_COMMENT_PATTERN = re.compile(
    r"#.*?(?:TODO\s*:\s*migrate|legacy|old\s+path|DEPRECATED)",
    re.IGNORECASE,
)

_SHAPE_ADAPTER_PATTERN = re.compile(
    r"""if\s+["'](\w+)["']\s+in\s+\w+\s*:\s*\n\s*\w+\[["']\w+["']\]\s*=\s*\w+\.pop\(["'](\w+)["']\)""",
    re.MULTILINE,
)

# ---------------------------------------------------------------------------
# Sanctioned forwarding hubs (per CLAUDE.md — do NOT flag these)
# ---------------------------------------------------------------------------

_SANCTIONED_FORWARDING_HUBS: frozenset[str] = frozenset({
    "INTERFACE/cli/cli.py",
    "SYSTEM/runtime/app.py",
    "SYSTEM/runtime/pocketcoder_adapter.py",
    "INTERFACE/operator/operator_assets.py",
    "SYSTEM/execution/pocketcoder_executor.py",
    "BRAIN/autoforensics/gate_checks/forensic_clusters/__init__.py",
    "BRAIN/autoforensics/gate_models.py",
})

_NOQA_LEGACY_COMPAT_PATTERN = re.compile(
    r"#\s*noqa:\s*legacy-compat",
    re.IGNORECASE,
)


def _is_sanctioned_hub(file_path: str) -> bool:
    """Return True if file_path is a CLAUDE.md-sanctioned re-export hub."""
    normalized = file_path.replace("\\", "/")
    # Strip leading drive / absolute prefix to match the relative hub paths
    for hub in _SANCTIONED_FORWARDING_HUBS:
        if normalized == hub or normalized.endswith("/" + hub):
            return True
    return False


def _has_noqa_legacy_compat(content: str) -> bool:
    """Return True if file contains '# noqa: legacy-compat' near the top (first 30 lines)."""
    head = "\n".join(content.splitlines()[:30])
    return bool(_NOQA_LEGACY_COMPAT_PATTERN.search(head))


# Threshold: if >=70% of non-blank, non-comment lines are re-export lines
_REEXPORT_RATIO_THRESHOLD = 0.70
# Maximum real function bodies (>5 body lines) to still qualify as a pure wrapper
_MAX_REAL_FUNCTIONS = 2
# Maximum total code lines for a forwarding wrapper
_MAX_TOTAL_CODE_LINES = 30


def _count_reexport_lines(content: str) -> tuple[int, int]:
    """Return (reexport_line_count, total_code_line_count)."""
    lines = content.splitlines()
    code_lines = [
        line for line in lines
        if line.strip() and not line.strip().startswith("#")
        and not line.strip().startswith('"""')
        and not line.strip().startswith("'''")
        and not line.strip() in ("from __future__ import annotations", "")
    ]
    reexport_lines = [
        line for line in code_lines
        if re.match(r"^\s*from\s+[\w.]+\s+import\s+", line)
        or re.match(r"^\s*\w+\s*=\s*[\w.]+\.\w+\s*$", line)
    ]
    return len(reexport_lines), len(code_lines)


def _count_substantial_functions(content: str) -> int:
    """Count function defs with body > 5 lines (excluding docstring-only)."""
    try:
        import ast
        tree = ast.parse(content)
    except SyntaxError:
        return 0

    count = 0
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        body_lines = getattr(node, "end_lineno", 0) - getattr(node, "lineno", 0)
        if body_lines > 5:
            # Exclude pure docstring functions
            body = node.body
            if len(body) == 1 and isinstance(body[0], ast.Expr) and isinstance(body[0].value, ast.Constant):
                continue
            count += 1
    return count


# ---------------------------------------------------------------------------
# Sub-check 1: forwarding_wrapper
# ---------------------------------------------------------------------------


def check_forwarding_wrapper(
    file_path: str,
    content: str,
) -> list[GateFinding]:
    """Detect modules that are >70% re-export lines with no domain logic."""
    if not content.strip():
        return []

    # Skip CLAUDE.md-sanctioned re-export hubs.
    if _is_sanctioned_hub(file_path):
        return []

    # Skip files that opt-out with an inline noqa comment.
    if _has_noqa_legacy_compat(content):
        return []

    reexport_count, total_code_lines = _count_reexport_lines(content)
    if total_code_lines == 0:
        return []

    ratio = reexport_count / total_code_lines
    if ratio < _REEXPORT_RATIO_THRESHOLD:
        return []

    substantial_funcs = _count_substantial_functions(content)
    if substantial_funcs > _MAX_REAL_FUNCTIONS:
        return []

    if total_code_lines > _MAX_TOTAL_CODE_LINES:
        return []

    detail = (
        f"{reexport_count}/{total_code_lines} code lines are re-exports "
        f"({ratio:.0%}); {substantial_funcs} substantial function bodies found"
    )
    return [build_finding(
        check_id="legacy_compat_debt.forwarding_wrapper",
        category=GateCategory.DRIFT,
        title=f"[legacy_compat_debt.forwarding_wrapper] {file_path}",
        severity=GateSeverity.MEDIUM,
        impact=GateImpact.REVISE,
        summary=(
            f"{file_path} is a forwarding wrapper: {detail}. "
            "Callers should import directly from the canonical module."
        ),
        recommendation=(
            "Remove the forwarding wrapper. Update all callers to import "
            "from the canonical module directly."
        ),
        evidence=(EvidenceReference(kind="probe", path=file_path, detail=detail, ok=False),),
        repair_kind=RepairKind.REMOVE_DEAD_SURFACE.value,
        executor_action=(
            "Remove forwarding wrapper and update callers to import from canonical module"
        ),
        proof_required="no callers reference the wrapper after fix; grep confirms",
        allowlist_allowed=True,
        preferred_fix_shape="delete file; update all importers to point to canonical module",
    )]


# ---------------------------------------------------------------------------
# Sub-check 2: unused_shim_module
# ---------------------------------------------------------------------------


def _module_is_pure_reexport_shim(content: str) -> bool:
    """F9e: return True IFF the module has *no* substantive AST content at
    module level. A canonical owner is any module containing at least one of:

      - FunctionDef / AsyncFunctionDef
      - ClassDef
      - If / While / Try / With (domain logic control flow)

    Permitted pure-reexport nodes (shim-only):
      - Import / ImportFrom
      - Assign(targets=[Name], value=Name)   -- plain re-export alias
      - Assign targeting __all__             -- list/tuple of names
      - Expr(Constant(str))                  -- docstring
      - AnnAssign for __all__ (rare)
    """
    import ast

    try:
        tree = ast.parse(content)
    except SyntaxError:
        return False

    for node in ast.iter_child_nodes(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            return False
        if isinstance(node, (ast.If, ast.While, ast.Try, ast.With, ast.For, ast.AsyncFor, ast.AsyncWith)):
            return False
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            continue
        if isinstance(node, ast.Expr) and isinstance(node.value, ast.Constant):
            # Module docstring (or other bare constant) — non-substantive.
            continue
        if isinstance(node, ast.Assign):
            # Shape permitted: targets are Name(s); value is a simple Name /
            # Attribute / List/Tuple of string constants (for __all__).
            is_all_assignment = (
                len(node.targets) == 1
                and isinstance(node.targets[0], ast.Name)
                and node.targets[0].id == "__all__"
            )
            if is_all_assignment:
                continue
            # Plain alias: `Foo = SomeName` or `Foo = other.attr`
            if (
                all(isinstance(t, ast.Name) for t in node.targets)
                and isinstance(node.value, (ast.Name, ast.Attribute))
            ):
                continue
            # Any other Assign (call, complex expression, dict, etc.) is
            # substantive.
            return False
        if isinstance(node, ast.AnnAssign):
            # Permit only __all__ annotation
            if isinstance(node.target, ast.Name) and node.target.id == "__all__":
                continue
            return False
        # Any other node type (e.g., Raise, Global, Nonlocal, Delete) is
        # substantive — real logic.
        return False
    return True


def check_unused_shim_module(
    file_path: str,
    content: str,
    all_project_files_content: dict[str, str] | None = None,
) -> list[GateFinding]:
    """Detect modules whose exports have zero non-test callers in the repo.

    F9e: a module is considered a shim ONLY if its top-level AST is limited
    to imports, re-export assignments, `__all__`, and a docstring. Modules
    containing `def`, `class`, `if`/`while`/`try`/`with`/`for` blocks are
    canonical owners and skipped regardless of caller count.
    """
    if not content.strip():
        return []
    if all_project_files_content is None:
        return []

    # F9e: skip canonical owners (anything with real module-level logic).
    if not _module_is_pure_reexport_shim(content):
        return []

    # Extract module stem for import detection
    stem = Path(file_path).stem
    # Convert file path to importable dotted form candidates
    module_path = file_path.replace("\\", "/").replace("/", ".").removesuffix(".py")

    # Find symbols exported from this file (top-level defs and imports)
    exported_names: list[str] = []
    try:
        import ast
        tree = ast.parse(content)
        for node in ast.iter_child_nodes(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                exported_names.append(node.name)
            elif isinstance(node, ast.ImportFrom):
                for alias in node.names:
                    exported_names.append(alias.asname or alias.name)
    except SyntaxError:
        return []

    if not exported_names:
        return []

    # Check if any non-test file imports from this module
    caller_count = 0
    for other_path, other_content in all_project_files_content.items():
        norm_other = other_path.replace("\\", "/")
        if norm_other == file_path.replace("\\", "/"):
            continue
        # Skip test files
        if "/test" in norm_other or "\\test" in norm_other or norm_other.startswith("test"):
            continue
        # Check for import of this module by stem or dotted path
        if stem in other_content and (
            f"from {stem}" in other_content
            or f"import {stem}" in other_content
            or module_path in other_content
        ):
            caller_count += 1

    if caller_count > 0:
        return []

    detail = (
        f"Module {file_path!r} (stem={stem!r}) has {len(exported_names)} exports "
        f"but 0 non-test callers found in repo"
    )
    return [build_finding(
        check_id="legacy_compat_debt.unused_shim_module",
        category=GateCategory.DRIFT,
        title=f"[legacy_compat_debt.unused_shim_module] {file_path}",
        severity=GateSeverity.MEDIUM,
        impact=GateImpact.REVISE,
        summary=(
            f"{detail}. The module may be a dead shim that was never cleaned up."
        ),
        recommendation=(
            "Verify no dynamic imports exist, then remove the module. "
            "If still needed, add a caller or document why it exists."
        ),
        evidence=(EvidenceReference(kind="probe", path=file_path, detail=detail, ok=False),),
        repair_kind=RepairKind.REMOVE_DEAD_SURFACE.value,
        executor_action=(
            "Delete unused shim module after verifying no dynamic import callers"
        ),
        proof_required="grep confirms 0 import references to this module; module deleted",
        allowlist_allowed=True,
        preferred_fix_shape="delete module; confirm with grep",
    )]


# ---------------------------------------------------------------------------
# Sub-check 3: stale_migration_marker
# ---------------------------------------------------------------------------


def check_stale_migration_marker(
    file_path: str,
    content: str,
) -> list[GateFinding]:
    """Detect stale migration markers (TODO: migrate, legacy, DEPRECATED, etc.)."""
    if not content.strip():
        return []

    # F14c sub-fix 1: skip string literals inside UPPER_CASE module-level
    # container assignments (e.g. the regex-literal inside
    # ``_MIGRATION_COMMENT_PATTERN = re.compile(r"...legacy...")`` won't
    # appear as a Name target here, but for regex-based scans we also skip
    # lines that belong to such containers in case future refactor moves
    # markers into a list).
    skip_lines = set(collect_constant_container_literal_lines(content))
    # F14c extra: also skip interior lines of multi-line string constants
    # (docstrings that talk about migration/legacy patterns).
    skip_lines |= set(collect_string_constant_line_ranges(content))

    findings: list[GateFinding] = []
    lines = content.splitlines()
    for line_num, line in enumerate(lines, 1):
        if line_num in skip_lines:
            continue
        # F14c sub-fix 2: skip visual section-header separator comments such
        # as ``# -- legacy_debt (C53) --`` so the gate doesn't flag its own
        # section markers.
        if is_section_header_comment(line):
            continue
        if not re.search(_MIGRATION_COMMENT_PATTERN, line):
            continue
        # Extract the matched comment snippet
        snippet = line.strip()[:120]
        detail = f"Stale migration marker at line {line_num}: {snippet!r}"
        findings.append(build_finding(
            check_id="legacy_compat_debt.stale_migration_marker",
            category=GateCategory.DRIFT,
            title=f"[legacy_compat_debt.stale_migration_marker] {file_path}:{line_num}",
            severity=GateSeverity.MEDIUM,
            impact=GateImpact.REVISE,
            summary=(
                f"{file_path}:{line_num} contains a stale migration marker. {detail}. "
                "Either complete the migration or remove the obsolete marker."
            ),
            recommendation=(
                "Complete the migration referenced by this comment, or remove the stale marker "
                "if the migration was already done."
            ),
            evidence=(EvidenceReference(
                kind="probe", path=file_path, detail=detail, ok=False,
            ),),
            repair_kind=RepairKind.REMOVE_DEAD_SURFACE.value,
            executor_action=(
                "Either complete the migration or remove the stale marker"
            ),
            proof_required="marker removed or migration completed; grep confirms no reference to old path",
            allowlist_allowed=True,
            preferred_fix_shape="remove comment and complete or discard the migration",
        ))
        if len(findings) >= 10:
            break
    return findings


# ---------------------------------------------------------------------------
# Sub-check 4: shape_adapter_without_producer
# ---------------------------------------------------------------------------


def check_shape_adapter_without_producer(
    file_path: str,
    content: str,
    all_project_files_content: dict[str, str] | None = None,
) -> list[GateFinding]:
    """Detect dict-shape adapters whose old-shape key has no active producer."""
    if not content.strip():
        return []

    matches = list(_SHAPE_ADAPTER_PATTERN.finditer(content))
    if not matches:
        return []

    findings: list[GateFinding] = []
    for m in matches:
        old_key = m.group(1)
        line_num = content[: m.start()].count("\n") + 1

        # Check if the old key has any producer outside this file
        producer_count = 0
        if all_project_files_content is not None:
            for other_path, other_content in all_project_files_content.items():
                norm_other = other_path.replace("\\", "/")
                if norm_other == file_path.replace("\\", "/"):
                    continue
                # Look for writes of old_key as dict key
                if f'"{old_key}"' in other_content or f"'{old_key}'" in other_content:
                    producer_count += 1

        if producer_count > 0:
            continue

        detail = (
            f"Shape adapter at line {line_num} converts key {old_key!r} to new form, "
            f"but grep finds 0 producers of {old_key!r} outside this file"
        )
        findings.append(build_finding(
            check_id="legacy_compat_debt.shape_adapter_without_producer",
            category=GateCategory.DRIFT,
            title=f"[legacy_compat_debt.shape_adapter_without_producer] {file_path}:{line_num}",
            severity=GateSeverity.MEDIUM,
            impact=GateImpact.REVISE,
            summary=(
                f"{detail}. The adapter is dead code: nothing produces the old shape it handles."
            ),
            recommendation=(
                f"Remove the shape adapter for key {old_key!r}. "
                "If the old shape is still produced by a dynamic path, document it explicitly."
            ),
            evidence=(EvidenceReference(
                kind="probe", path=file_path, detail=detail, ok=False,
            ),),
            repair_kind=RepairKind.REMOVE_DEAD_SURFACE.value,
            executor_action=(
                f"Remove shape adapter for old key {old_key!r}; verify no producer exists with grep"
            ),
            proof_required="grep confirms no producer of old shape; adapter code removed",
            allowlist_allowed=True,
            preferred_fix_shape="delete adapter block; confirm with grep",
        ))
    return findings
