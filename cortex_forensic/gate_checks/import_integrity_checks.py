from __future__ import annotations

import logging
import re
from pathlib import Path

from cortex_forensic._shared import EvidenceReference, GateCategory, GateImpact, GateSeverity, RepairKind
from cortex_forensic.gate_models import PostExecGateContext
from cortex_forensic.source_analysis import is_source_file
from .common import build_check_result, build_finding, normalize_path
from cortex_forensic._git_utils import git_show as _git_show_init

_log = logging.getLogger(__name__)

# Matches top-level import statements (both `import X` and `from X import Y`)
IMPORT_LINE_RE = re.compile(r"^(?:from\s+\S+\s+)?import\s+\S.*$", re.MULTILINE)

_MAX_DELETED_FILES = 5
_MAX_FILES_PER_ROOT = 500


def _derive_module_path(file_path: str) -> str:
    """Convert 'SYSTEM/runtime/foo.py' to 'SYSTEM.runtime.foo'.

    Handles new cluster topology: SYSTEM, BRAIN, INTERFACE, TESTS prefixes."""
    normalized = normalize_path(file_path)
    if is_source_file(normalized):
        normalized = normalized[:-3]
    return normalized.replace("/", ".")


def _find_deleted_py_files(ctx: PostExecGateContext) -> list[str]:
    """Return .py files in changed_files_reported that don't exist on disk."""
    deleted = []
    for raw_path in ctx.changed_files_reported:
        normalized = normalize_path(raw_path)
        if not is_source_file(normalized):
            continue
        abs_path = ctx.project_dir / normalized
        if not abs_path.exists():
            deleted.append(normalized)
            if len(deleted) >= _MAX_DELETED_FILES:
                break
    return deleted


def run_import_integrity_checks(ctx: PostExecGateContext):
    findings = []
    deleted_files = _find_deleted_py_files(ctx)
    if not deleted_files:
        return build_check_result(check_id="import_integrity", category=GateCategory.CONTRACT)

    # Build search patterns for each deleted module
    module_paths = [(f, _derive_module_path(f)) for f in deleted_files]

    # Use auto-detected source roots; fall back to scanning project_dir directly
    scan_roots = [ctx.project_dir / r for r in ctx.source_package_roots if (ctx.project_dir / r).is_dir()]
    if not scan_roots:
        scan_roots = [ctx.project_dir]
    for root_dir in scan_roots:
        file_count = 0
        for py_file in root_dir.rglob("*.py"):
            file_count += 1
            if file_count > _MAX_FILES_PER_ROOT:
                break
            try:
                text = py_file.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            rel_importer = str(py_file.relative_to(ctx.project_dir)).replace("\\", "/")
            for deleted_path, module_dotpath in module_paths:
                if rel_importer == deleted_path:
                    continue  # Don't flag the deleted file itself
                # Check for: from SYSTEM.runtime.foo import ... OR import SYSTEM.runtime.foo
                if f"from {module_dotpath}" in text or f"import {module_dotpath}" in text:
                    findings.append(
                        build_finding(
                            check_id="import_integrity.broken_import",
                            category=GateCategory.CONTRACT,
                            title=f"Broken import: {rel_importer} imports deleted {deleted_path}",
                            severity=GateSeverity.HIGH,
                            impact=GateImpact.REVISE,
                            summary=(
                                f"File {rel_importer} imports from module '{module_dotpath}' "
                                f"but {deleted_path} was deleted in this session. "
                                "This will cause an ImportError at runtime."
                            ),
                            recommendation=(
                                "Update the import in the affected file to use the new module "
                                "path, or delete the orphaned file if it is no longer needed."
                            ),
                            evidence=[
                                EvidenceReference(kind="file", path=deleted_path, detail="deleted"),
                                EvidenceReference(kind="file", path=rel_importer, detail=f"imports:{module_dotpath}"),
                            ],
                        
                            repair_kind='fix_contract',
                            executor_action='Fix import',
                            proof_required='Import resolved',
                            allowlist_allowed=False,
                        )
                    )

    return build_check_result(check_id="import_integrity", category=GateCategory.CONTRACT, findings=findings)


# ---------------------------------------------------------------------------
# Finding 6.3: init_order_regression
# ---------------------------------------------------------------------------


def _extract_import_order(content: str) -> list[str]:
    """Return top-level import statements in source order.

    Uses regex scan -- captures `import X` and `from X import Y` lines at any
    indentation level (intentional: mirrors the task spec regex).  Only
    distinct lines are preserved in order of first appearance so that
    duplicate import lines do not cause false positives.
    """
    seen: set[str] = set()
    ordered: list[str] = []
    for stmt in IMPORT_LINE_RE.findall(content):
        stripped = stmt.strip()
        if stripped and stripped not in seen:
            seen.add(stripped)
            ordered.append(stripped)
    return ordered


def _compare_import_order(before: list[str], after: list[str]) -> tuple[int, int]:
    """Return (reordered_count, removed_count).

    - removed_count: imports present in `before` but absent in `after`.
    - reordered_count: imports present in both but their relative order changed.
      Additive-only changes (new imports in `after`) are NOT flagged.
    """
    before_set = set(before)
    after_set = set(after)

    removed = [s for s in before if s not in after_set]
    removed_count = len(removed)

    # Common imports in the order they appear in each sequence
    common_before = [s for s in before if s in after_set]
    common_after = [s for s in after if s in before_set]

    reordered_count = 0 if common_before == common_after else len(common_before)

    return reordered_count, removed_count


def run_init_order_regression_checks(ctx: PostExecGateContext):
    """Emit findings when `__init__.py` files have import order changed or imports removed.

    Reordering top-level imports can alter module side effects and circular
    import resolution -- this gate surfaces such regressions before they merge.

    Rules:
    - Only inspects `__init__.py` files present in changed_files_observed.
    - Skips files with no prior version (newly added -- not a regression).
    - Fails open: any git/I-O error is logged at DEBUG and the file is skipped.
    - New imports added are OK (additive changes pass).
    """
    findings = []

    for raw_path in ctx.changed_files_observed:
        normalized = normalize_path(raw_path)
        if not normalized.endswith("__init__.py"):
            continue

        prior_content = _git_show_init(normalized)
        if prior_content is None:
            # New file or git unavailable — not a regression
            continue

        abs_path = ctx.project_dir / normalized
        try:
            current_content = abs_path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError) as exc:
            _log.debug("init_order_regression: cannot read current file %s: %s", normalized, exc)
            continue

        before_order = _extract_import_order(prior_content)
        after_order = _extract_import_order(current_content)

        reordered_count, removed_count = _compare_import_order(before_order, after_order)

        if reordered_count > 0 or removed_count > 0:
            parts = []
            if reordered_count > 0:
                parts.append(f"{reordered_count} import(s) reordered")
            if removed_count > 0:
                parts.append(f"{removed_count} import(s) removed")
            detail_str = ", ".join(parts)

            findings.append(
                build_finding(
                    check_id="init_order_regression.import_order_changed",
                    category=GateCategory.CONTRACT,
                    title=f"Import order regression in {normalized}",
                    severity=GateSeverity.MEDIUM,
                    impact=GateImpact.REVISE,
                    summary=(
                        f"{normalized} has {detail_str} compared to HEAD~1. "
                        "Reordering or removing top-level imports in __init__.py "
                        "can alter module initialization side effects and change "
                        "circular import resolution order."
                    ),
                    recommendation=(
                        "Restore the original import order in __init__.py unless "
                        "the change is intentional and the circular-import / "
                        "side-effect impact has been verified. "
                        "If intentional, document the reason in the commit message."
                    ),
                    evidence=[
                        EvidenceReference(
                            kind="file",
                            path=normalized,
                            detail=detail_str,
                        )
                    ],
                
                    repair_kind='refactor',
                    executor_action='Fix import order',
                    proof_required='Import order stable',
                    allowlist_allowed=False,
                )
            )

    return build_check_result(
        check_id="init_order_regression",
        category=GateCategory.CONTRACT,
        findings=findings,
    )
