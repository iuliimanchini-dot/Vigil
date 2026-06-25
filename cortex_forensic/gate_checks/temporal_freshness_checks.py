from __future__ import annotations

from pathlib import Path

from cortex_forensic._shared import EvidenceReference, GateCategory, GateImpact, GateSeverity, RepairKind
from cortex_forensic.gate_models import PostExecGateContext
from .common import build_check_result, build_finding
import logging
_log = logging.getLogger(__name__)


def run_temporal_freshness_checks(ctx: PostExecGateContext):
    findings = []
    handoff_path = ctx.artifact_refs.get("executor_handoff", "")
    prompt_path = ctx.session_artifacts.get("system_prompt", "")
    forensic_path = ctx.artifact_refs.get("forensic", "")

    handoff_ts = _mtime(handoff_path)
    prompt_ts = _mtime(prompt_path)
    forensic_ts = _mtime(forensic_path)

    if prompt_ts > 0.0 and handoff_ts > 0.0 and handoff_ts + 0.001 < prompt_ts:
        findings.append(
            build_finding(
                check_id="temporal.handoff_before_prompt",
                category=GateCategory.TEMPORAL_FRESHNESS,
                title="Executor handoff is older than the Claude prompt",
                severity=GateSeverity.CRITICAL,
                impact=GateImpact.BLOCK,
                summary="The handoff artifact timestamp predates the prompt artifact for the same session.",
                recommendation="Verify artifact selection by current session/attempt; do not reuse stale handoff files.",
                evidence=[
                    EvidenceReference(kind="artifact", path=prompt_path, detail=f"prompt_mtime={prompt_ts}"),
                    EvidenceReference(kind="artifact", path=handoff_path, detail=f"handoff_mtime={handoff_ts}"),
                ],
            
                repair_kind='refactor',
                executor_action='Address finding details',
                proof_required='Freshness acceptable',
                allowlist_allowed=False,
            )
        )

    if handoff_ts > 0.0 and forensic_ts > 0.0 and forensic_ts + 0.001 < handoff_ts:
        findings.append(
            build_finding(
                check_id="temporal.forensic_before_handoff",
                category=GateCategory.TEMPORAL_FRESHNESS,
                title="Forensic evidence is older than the executor handoff",
                severity=GateSeverity.HIGH,
                impact=GateImpact.REVISE,
                summary="The forensic artifact appears older than the handoff it is supposed to validate.",
                recommendation="Rerun forensic validation after the executor handoff and persist fresh evidence.",
                evidence=[
                    EvidenceReference(kind="artifact", path=handoff_path, detail=f"handoff_mtime={handoff_ts}"),
                    EvidenceReference(kind="artifact", path=forensic_path, detail=f"forensic_mtime={forensic_ts}"),
                ],
            
                repair_kind='refactor',
                executor_action='Address finding details',
                proof_required='Freshness acceptable',
                allowlist_allowed=False,
            )
        )

    return build_check_result(
        check_id="temporal_freshness",
        category=GateCategory.TEMPORAL_FRESHNESS,
        findings=findings,
    )


def _mtime(path_text: str) -> float:
    if not path_text:
        return 0.0
    path = Path(path_text)
    if not path.exists() or not path.is_file():
        return 0.0
    return path.stat().st_mtime
