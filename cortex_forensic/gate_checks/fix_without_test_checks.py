from __future__ import annotations

from cortex_forensic._shared import SOURCE_EXTENSIONS as _SOURCE_EXTENSIONS
from cortex_forensic._shared import EvidenceReference, GateCategory, GateImpact, GateSeverity, RepairKind
from cortex_forensic.gate_models import PostExecGateContext
from .common import build_check_result, build_finding, normalize_path
import logging
_log = logging.getLogger(__name__)

_FIX_KEYWORDS = frozenset({"fix", "repair", "bug", "patch", "hotfix", "bugfix"})
# Sprint C3 (2026-04-23): _SOURCE_EXTENSIONS imported above from
# SYSTEM.shared_helpers.file_extensions. Keep the private alias so existing
# call sites resolve without having to rewrite the suffix lookup.


def _intent_has_fix_keyword(task_intent: str) -> bool:
    """Check if task_intent contains a fix-related keyword as a word token."""
    tokens = set(task_intent.lower().replace("-", "_").split("_"))
    # Also split on spaces for natural language intents
    for word in task_intent.lower().split():
        tokens.update(word.replace("-", "_").split("_"))
    return bool(tokens & _FIX_KEYWORDS)


def run_fix_without_test_checks(ctx: PostExecGateContext):
    findings = []
    if ctx.task_intent == "metadata_only":
        return build_check_result(check_id="fix_without_test", category=GateCategory.TESTING)
    if not _intent_has_fix_keyword(ctx.task_intent):
        return build_check_result(check_id="fix_without_test", category=GateCategory.TESTING)

    has_source_changes = False
    source_files = []
    for raw_path in ctx.changed_files_observed:
        normalized = normalize_path(raw_path)
        suffix = "." + normalized.rsplit(".", 1)[-1] if "." in normalized else ""
        if suffix.lower() in _SOURCE_EXTENSIONS:
            has_source_changes = True
            source_files.append(normalized)

    if not has_source_changes:
        return build_check_result(check_id="fix_without_test", category=GateCategory.TESTING)

    if not ctx.tests_touched:
        findings.append(
            build_finding(
                check_id="fix_without_test.no_tests",
                category=GateCategory.TESTING,
                title="Fix/repair task changed source files but no tests",
                severity=GateSeverity.MEDIUM,
                impact=GateImpact.REVISE,
                summary=(
                    f"Task intent '{ctx.task_intent}' indicates a fix/repair, and "
                    f"{len(source_files)} source file(s) were changed, but no test files "
                    "were touched. Consider adding a regression test."
                ),
                recommendation="Add a test that reproduces the bug and verifies the fix.",
                evidence=[
                    EvidenceReference(kind="file", path=source_files[0], detail="source_changed_no_test")
                ],
            
                repair_kind='add_regression_test',
                executor_action='Add tests for coverage',
                proof_required='Tests added/passing',
                allowlist_allowed=True,
            )
        )

    return build_check_result(check_id="fix_without_test", category=GateCategory.TESTING, findings=findings)
