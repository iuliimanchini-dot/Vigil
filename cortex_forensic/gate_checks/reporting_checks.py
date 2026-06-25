from __future__ import annotations

from pathlib import Path

from cortex_forensic._shared import EvidenceReference, GateCategory, GateImpact, GateSeverity, RepairKind
from cortex_forensic.gate_models import PostExecGateContext
from .common import build_check_result, build_finding
import logging
_log = logging.getLogger(__name__)


def run_reporting_checks(ctx: PostExecGateContext):
    findings = []
    profile = ctx.repo_profile
    required = profile.reporting_required_artifacts if profile is not None else ()
    for required_name in required:
        artifact_path = ctx.artifact_refs.get(required_name, "")
        if artifact_path and Path(artifact_path).exists():
            continue
        findings.append(
            build_finding(
                check_id="reporting.artifact_missing",
                category=GateCategory.REPORTING,
                title="Referenced artifact is missing",
                severity=GateSeverity.HIGH,
                impact=GateImpact.BLOCK if required_name == "executor_handoff" else GateImpact.REVISE,
                summary=f"Required artifact '{required_name}' is missing from the post-exec evidence set.",
                recommendation="Persist the artifact before stronger verification wording is used.",
                evidence=[EvidenceReference(kind="artifact", path=artifact_path, detail=required_name)],
            
                repair_kind='fix_contract',
                executor_action='Fix reporting',
                proof_required='Report accurate',
                allowlist_allowed=False,
            )
        )
    summary = (ctx.verification_summary.summary or "").lower()
    if "accepted" in summary and ctx.verification_summary.blocking_issues:
        findings.append(
            build_finding(
                check_id="reporting.accepted_vs_blocking",
                category=GateCategory.REPORTING,
                title="Acceptance wording is unsupported by raw blocking evidence",
                severity=GateSeverity.MEDIUM,
                impact=GateImpact.REVISE,
                summary="Verification summary contains accepted wording while blocking issues are still present.",
                recommendation="Tone down summary wording until raw evidence supports it.",
            
                repair_kind='fix_contract',
                executor_action='Fix reporting',
                proof_required='Report accurate',
                allowlist_allowed=False,
            )
        )
    return build_check_result(check_id="reporting", category=GateCategory.REPORTING, findings=findings)
