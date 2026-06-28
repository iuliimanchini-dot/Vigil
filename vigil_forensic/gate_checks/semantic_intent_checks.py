from __future__ import annotations

import re

from vigil_forensic._shared import EvidenceReference, GateCategory, GateImpact, GateSeverity
from vigil_forensic.gate_models import PostExecGateContext
from .common import build_check_result, build_finding
import logging
_log = logging.getLogger(__name__)


_STOPWORDS: frozenset[str] = frozenset({
    "the", "and", "for", "with", "that", "this", "from", "into", "only", "must",
    "should", "would", "could", "без", "для", "или", "что", "как", "это", "если",
    "надо", "нужно", "задача", "task", "run", "verify", "verification",
})

_NO_EDIT_MARKERS: tuple[str, ...] = (
    # English
    "do not edit",
    "no project file changes",
    "do not change project files",
    "without editing project files",
    "discussion only",
    "plan only",
    "do not execute",
    # Russian
    "не редакт",
    "не редактируй",
    "не менять файлы",
    "не меняй файлы",
    "без изменений файлов",
    "только обсуди",
    "только план",
    "не запускай исполнение",
)


def run_semantic_intent_checks(ctx: PostExecGateContext):
    findings = []
    report = ctx.structured_handoff.report if ctx.structured_handoff is not None else None
    if report is None:
        return build_check_result(check_id="semantic_intent", category=GateCategory.SEMANTIC_INTENT)

    request_text = ctx.original_user_request.strip()
    handoff_text = " ".join((
        report.task_understanding,
        " ".join(report.actions_taken),
        " ".join(report.verification_performed),
    )).lower()
    request_keywords = _keywords(request_text)
    matched_keywords = tuple(keyword for keyword in request_keywords if keyword in handoff_text)

    if report.result_claim == "success" and len(request_keywords) >= 3 and not matched_keywords:
        findings.append(
            build_finding(
                check_id="semantic.intent_not_reflected",
                category=GateCategory.SEMANTIC_INTENT,
                title="Successful handoff does not reflect task intent keywords",
                severity=GateSeverity.HIGH,
                impact=GateImpact.REVISE,
                summary=(
                    "The executor claims success, but its handoff does not mention any high-signal "
                    "keywords from the original operator request."
                ),
                recommendation="Revise the handoff or implementation so the result explicitly addresses the requested objective.",
                evidence=[
                    EvidenceReference(
                        kind="handoff",
                        detail=", ".join(request_keywords[:8]),
                    )
                ],
            
                repair_kind='validate_boundary',
                executor_action='Address finding details',
                proof_required='Intent preserved',
                allowlist_allowed=False,
            )
        )

    lower_request = request_text.lower()
    forbids_project_edits = any(marker in lower_request for marker in _NO_EDIT_MARKERS)
    non_metadata_changes = tuple(
        path for path in ctx.changed_files_observed
        if not path.replace("\\", "/").startswith((".a1/", ".cortex/", ".claude/", ".prompt-engineer/"))
    )
    if forbids_project_edits and non_metadata_changes:
        findings.append(
            build_finding(
                check_id="semantic.forbidden_edit_violation",
                category=GateCategory.SEMANTIC_INTENT,
                title="Executor changed files despite a no-edit task constraint",
                severity=GateSeverity.CRITICAL,
                impact=GateImpact.BLOCK,
                summary="The original request prohibited project-file edits, but observed changed-file evidence includes project files.",
                recommendation="Revert or explain the unauthorized project-file changes and rerun through the control plane.",
                evidence=[EvidenceReference(kind="changed_file", path=path) for path in non_metadata_changes[:5]],
            
                repair_kind='validate_boundary',
                executor_action='Address finding details',
                proof_required='Intent preserved',
                allowlist_allowed=False,
            )
        )

    if report.result_claim == "success" and (report.blockers or report.uncertainties):
        findings.append(
            build_finding(
                check_id="semantic.success_with_unresolved_blockers",
                category=GateCategory.SEMANTIC_INTENT,
                title="Handoff claims success while listing blockers or uncertainties",
                severity=GateSeverity.HIGH,
                impact=GateImpact.REVISE,
                summary="The executor result_claim is success, but the handoff still contains blockers or uncertainties.",
                recommendation="Downgrade the claim to partial/failed or resolve the listed blockers before success.",
            
                repair_kind='validate_boundary',
                executor_action='Address finding details',
                proof_required='Intent preserved',
                allowlist_allowed=False,
            )
        )

    return build_check_result(
        check_id="semantic_intent",
        category=GateCategory.SEMANTIC_INTENT,
        findings=findings,
    )


def _keywords(text: str) -> tuple[str, ...]:
    words = re.findall(r"[A-Za-zА-Яа-я0-9_]{4,}", text.lower())
    result: list[str] = []
    for word in words:
        if word in _STOPWORDS:
            continue
        if word not in result:
            result.append(word)
    return tuple(result[:12])
