"""Integrity cluster wrappers -- universal (project-agnostic) clusters.

Covers: success proof, proxy-as-truth, config applied, state divergence,
fallback transparency.
"""
from __future__ import annotations

from ...gate_models import GateFinding, PostExecGateContext
from ..common import normalize_path
from ..forensic_clusters import (
    ProofRequirement,
    assess_config_applied,
    assess_fallback_transparency,
    assess_source_truthfulness,
    assess_state_consistency,
    assess_success_proof,
)
import logging
_log = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Cluster 2: Success Without Proof
# ---------------------------------------------------------------------------


def _check_success_proof(ctx: PostExecGateContext) -> list[GateFinding]:
    """Cluster 2: Success Without Proof."""
    if not ctx.session_number:
        return []

    status = {
        "phase": "completed" if ctx.verification_summary.passed else "incomplete",
        "ok": ctx.verification_summary.passed and not ctx.verification_summary.blocking_issues,
        "proof_path": ctx.artifact_refs.get("final_report", ""),
        "forensic_path": ctx.artifact_refs.get("forensic", ""),
    }
    proof_reqs: list[ProofRequirement] = [
        ProofRequirement(name="final_report", field_path="proof_path", required=True),
    ]
    if ctx.task_intent == "code_change":
        proof_reqs.append(
            ProofRequirement(name="forensic_report", field_path="forensic_path", required=True),
        )
    return assess_success_proof(status, proof_reqs)


# ---------------------------------------------------------------------------
# Cluster 4: Config Accepted But Ignored (proof requirements)
# ---------------------------------------------------------------------------

# Maps abstract required_proof names → artifact_refs keys that carry their evidence.
# Proof names in validation contracts are conceptual (e.g. "verification_commands"),
# while artifact_refs keys are physical files (e.g. "executor_handoff"). Without this
# map, every proof name that doesn't literally appear as an artifact key is a structural
# false positive — the names will never match file-path strings.
_PROOF_ARTIFACT_MAP: dict[str, tuple[str, ...]] = {
    "structured_handoff":    ("executor_handoff",),
    "verification_commands": ("executor_handoff",),
    "truth_surface_proof":   ("executor_handoff", "forensic"),
    "commit_proof":          ("executor_handoff",),
    "remote_file_truth":     ("executor_handoff",),
    "hook_compatibility":    ("stream_trace", "executor_handoff"),
    "forensic_summary":      ("forensic",),
}


def _proof_is_consumed(proof_name: str, refs: dict[str, str]) -> bool:
    """Return True if a required proof is satisfied by available artifacts.

    Check order:
    1. Direct key match in artifact_refs.
    2. Known proof→artifact mapping (_PROOF_ARTIFACT_MAP).
    3. Partial string matching (legacy fallback for unlisted proof names).
    """
    if proof_name in refs:
        return True
    artifact_keys = _PROOF_ARTIFACT_MAP.get(proof_name)
    if artifact_keys:
        return any(bool(refs.get(k)) for k in artifact_keys)
    return any(
        proof_name.startswith(k) or k.startswith(proof_name.replace("_report", ""))
        for k in refs
    ) or any(proof_name in str(v) for v in refs.values())


def _check_config_applied(ctx: PostExecGateContext) -> list[GateFinding]:
    """Cluster 4: Config Accepted But Ignored (proof requirements)."""
    findings: list[GateFinding] = []
    contract = ctx.validation_contract
    required_proofs = getattr(contract, "required_proofs", None)
    if not required_proofs:
        return findings

    has_session = bool(ctx.session_number) and bool(ctx.artifact_refs)
    if not has_session:
        return findings

    refs = ctx.artifact_refs or {}
    for proof_name in required_proofs:
        persisted = bool(proof_name)
        consumed = _proof_is_consumed(proof_name, refs)
        findings.extend(assess_config_applied(proof_name, proof_name, persisted, consumed))
    return findings


# ---------------------------------------------------------------------------
# Cluster 6: State Divergence
# ---------------------------------------------------------------------------


def _check_state_divergence(ctx: PostExecGateContext) -> list[GateFinding]:
    """Cluster 6: State Divergence."""
    if not ctx.changed_files_reported or not ctx.changed_files_observed:
        return []
    reported_set = frozenset(normalize_path(f) for f in ctx.changed_files_reported)
    observed_set = frozenset(normalize_path(f) for f in ctx.changed_files_observed)
    return assess_state_consistency(
        representations={"reported": reported_set, "observed": observed_set},
        expected_equal_keys=[("reported", "observed")],
    )


# ---------------------------------------------------------------------------
# Cluster 7: Fallback Hides Truth
# ---------------------------------------------------------------------------


def _check_fallback_transparency(ctx: PostExecGateContext) -> list[GateFinding]:
    """Cluster 7: Fallback Hides Truth."""
    remote_mode = "remote_authoritative" in ctx.transport_mode
    if not remote_mode:
        return []
    has_remote_proof = bool(ctx.artifact_refs.get("remote_commit_proof"))
    return assess_fallback_transparency(
        primary_available=True,
        fallback_used=not has_remote_proof,
        degradation_labeled=False,
    )


# ---------------------------------------------------------------------------
# Cluster 3: Proxy as Truth
# ---------------------------------------------------------------------------


def _check_proxy_as_truth(ctx: PostExecGateContext) -> list[GateFinding]:
    """Cluster 3: Check truth-source labeling honesty."""
    remote_mode = "remote_authoritative" in ctx.transport_mode
    if not remote_mode:
        return []

    has_remote_proof = bool(ctx.artifact_refs.get("remote_commit_proof"))
    has_local_only = not has_remote_proof and bool(ctx.artifact_refs.get("final_report"))

    if has_remote_proof:
        return assess_source_truthfulness(
            stated_source="authoritative",
            actual_source="authoritative",
            label_shown="remote commit verified",
        )
    elif has_local_only:
        return assess_source_truthfulness(
            stated_source="authoritative",
            actual_source="proxy",
            label_shown="local artifacts only in remote-authoritative mode",
        )
    else:
        return []


# ---------------------------------------------------------------------------
# Cluster 4 expansion: Config beyond proof-only
# ---------------------------------------------------------------------------


def _check_config_general(ctx: PostExecGateContext) -> list[GateFinding]:
    """Cluster 4 expanded: Check broader config acceptance patterns."""
    findings: list[GateFinding] = []

    transport = ctx.transport_mode or ""
    project_mode = getattr(ctx, "project_mode", "") or ""
    if transport and project_mode:
        consistent = transport == project_mode or project_mode in transport
        findings.extend(assess_config_applied(
            config_key="transport_mode",
            config_value=transport,
            persisted=True,
            consumed_by_runtime=consistent,
        ))

    contract = ctx.validation_contract
    contract_class = getattr(contract, "task_classification", "") or ""
    if contract_class and ctx.task_intent:
        consistent = contract_class == ctx.task_intent or ctx.task_intent in contract_class
        findings.extend(assess_config_applied(
            config_key="task_classification",
            config_value=contract_class,
            persisted=True,
            consumed_by_runtime=consistent,
        ))

    return findings
