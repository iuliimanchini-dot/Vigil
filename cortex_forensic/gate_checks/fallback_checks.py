from __future__ import annotations

from cortex_forensic._shared import EvidenceReference, GateCategory, GateImpact, GateSeverity, RepairKind
from cortex_forensic.gate_models import PostExecGateContext
from .common import build_check_result, build_finding, iter_touched_snapshots
import logging
_log = logging.getLogger(__name__)


def run_fallback_checks(ctx: PostExecGateContext):
    findings = []
    profile = ctx.repo_profile
    if profile is None:
        return build_check_result(check_id="fallback", category=GateCategory.FALLBACK)
    for snapshot in iter_touched_snapshots(ctx):
        if not snapshot.exists or profile.is_generated_or_vendored(snapshot.path):
            continue
        text_lower = snapshot.text.lower()
        for pattern, impact in profile.forbidden_fallback_patterns.items():
            if pattern.lower() not in text_lower:
                continue
            severity = GateSeverity.CRITICAL if impact is GateImpact.BLOCK else GateSeverity.MEDIUM
            if profile.is_critical(snapshot.path) and impact is GateImpact.REVISE:
                severity = GateSeverity.HIGH
            findings.append(
                build_finding(
                    check_id="fallback.pattern",
                    category=GateCategory.FALLBACK,
                    title=f"Forbidden fallback or workaround marker in touched code: {pattern}",
                    severity=severity,
                    impact=impact,
                    summary=f"Touched file {snapshot.path} contains '{pattern}', which is disallowed or suspicious in this repo profile.",
                    recommendation="Remove the fallback/workaround or document and relocate it under an explicit owned policy path.",
                    evidence=[EvidenceReference(kind="file", path=snapshot.path, detail=pattern)],
                    repair_kind=RepairKind.REMOVE_FALLBACK.value,
                    executor_action="Remove/narrow fallback pattern",
                    proof_required="No fallback in file",
                    allowlist_allowed=False,
                )
            )
    return build_check_result(check_id="fallback", category=GateCategory.FALLBACK, findings=findings)
