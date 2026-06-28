"""Authority-related forensic checks (Finding 6.1).

illegal_authority_writer: flag new writer functions appearing in modules that
previously had none -- signals unauthorized authority expansion.
"""
from __future__ import annotations

import logging

from vigil_forensic._shared import EvidenceReference, GateCategory, GateImpact, GateSeverity, RepairKind
from vigil_forensic.gate_models import PostExecGateContext
from ..source_analysis import is_source_file
from .common import build_check_result, build_finding, normalize_path
from vigil_forensic._git_utils import git_show as _git_show

_log = logging.getLogger(__name__)

WRITER_PREFIXES = ("def write_", "def save_", "def commit_", "def delete_", "def persist_")


def _count_writers(content: str) -> int:
    """Count writer-named function definitions in source content."""
    return sum(content.count(prefix) for prefix in WRITER_PREFIXES)


def run_authority_checks(ctx: PostExecGateContext):
    """Emit findings for NEW writer functions in previously-read-only modules.

    For each changed .py file observed in the gate context:
    - If prior content (HEAD~1) has ZERO writer-named defs
    - And current content has >=1 writer-named def
    - Then emit a warning finding.

    Missing files (newly added) are NOT flagged -- new files are new authority
    by definition and should be reviewed separately.

    Fails open: git unavailable or any I/O error -> skip that file, never crash.
    """
    findings = []

    for raw_path in ctx.changed_files_observed:
        normalized = normalize_path(raw_path)
        if not is_source_file(normalized):
            continue

        prior = _git_show(normalized)
        if prior is None:
            # File didn't exist before OR git unavailable — skip, not a violation
            continue

        abs_path = ctx.project_dir / normalized
        try:
            current = abs_path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError) as exc:
            _log.debug("authority_checks: cannot read current file %s: %s", normalized, exc)
            continue

        if _count_writers(prior) == 0 and _count_writers(current) > 0:
            findings.append(
                build_finding(
                    check_id="illegal_authority_writer.new_writer_in_readonly_module",
                    category=GateCategory.CONTRACT,
                    title="Illegal authority expansion: new writer function in previously read-only module",
                    severity=GateSeverity.MEDIUM,
                    impact=GateImpact.REVISE,
                    summary=(
                        f"{normalized} introduced new writer function(s) "
                        f"(write_/save_/commit_/delete_/persist_) where none existed "
                        f"previously. Verify authority expansion is intentional and "
                        f"covered by authority map."
                    ),
                    recommendation=(
                        "If the writer function is intentional, update the project authority map "
                        "to document the new write authority. "
                        "If unintentional, remove or relocate the function."
                    ),
                    evidence=[
                        EvidenceReference(
                            kind="file",
                            path=normalized,
                            detail="new_writer_in_previously_readonly_module",
                        )
                    ],
                    repair_kind=RepairKind.VALIDATE_BOUNDARY.value,
                    executor_action="Validate authority boundaries",
                    proof_required="Authority respected",
                    allowlist_allowed=False,
                )
            )

    return build_check_result(
        check_id="authority_checks",
        category=GateCategory.CONTRACT,
        findings=findings,
    )
