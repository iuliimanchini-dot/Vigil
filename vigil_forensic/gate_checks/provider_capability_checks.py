"""Provider capability gate check.

Detects executor provider capability mismatches before gate-monitored runs.
Registered in gate_registry.py before tool_hook_coverage_checks.
"""
from __future__ import annotations

from vigil_forensic._shared import GateCategory, GateCheckResult, GateImpact, GateSeverity
from vigil_forensic.gate_models import PostExecGateContext
from .common import build_check_result, build_finding
import logging
_log = logging.getLogger(__name__)

__all__ = ["check_provider_capabilities"]


def check_provider_capabilities(ctx: PostExecGateContext) -> GateCheckResult:
    """Check executor provider capabilities against gate requirements.

    - PC01: Gemini executor uses trace-file hooks (not stream) -- WARN so that
      tool_hook_coverage gate does not BLOCK on zero hook-event count.
    - PC02: executor_provider missing from metadata -- soft WARN.
    """
    findings = []

    executor_provider = str(
        ctx.control_task_metadata.get("executor_provider") or ""
    ).strip()

    if executor_provider == "gemini":
        findings.append(
            build_finding(
                check_id="PC01_gemini_hook_events_in_trace",
                category=GateCategory.CONTRACT,
                title="Gemini executor: hook events go to trace file, not JSON stream",
                severity=GateSeverity.LOW,
                impact=GateImpact.REVISE,
                summary=(
                    "Gemini executor writes hook events to the trace file, not the "
                    "JSON stream. tool_hook_coverage gate counts will be 0 -- expected."
                ),
                recommendation="No action needed. tool_hook_coverage gate should not BLOCK on Gemini runs.",
            
                repair_kind='refactor',
                executor_action='Address finding details',
                proof_required='Issue fixed',
                allowlist_allowed=False,
            )
        )

    if not executor_provider:
        findings.append(
            build_finding(
                check_id="PC02_executor_provider_unknown",
                category=GateCategory.CONTRACT,
                title="executor_provider metadata missing -- cannot validate capabilities",
                severity=GateSeverity.LOW,
                impact=GateImpact.REVISE,
                summary="executor_provider key absent from control task metadata.",
                recommendation="Ensure pocketcoder_executor.py writes executor_provider to control task metadata.",
            
                repair_kind='refactor',
                executor_action='Address finding details',
                proof_required='Issue fixed',
                allowlist_allowed=False,
            )
        )

    return build_check_result(
        check_id="provider_capability",
        category=GateCategory.CONTRACT,
        findings=findings,
    )
