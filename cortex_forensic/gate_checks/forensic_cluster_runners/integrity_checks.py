"""Integrity cluster wrappers -- clusters 1-9.

Covers: declared capabilities, success proof, proxy-as-truth, config applied,
rendered vs live, state divergence, fallback transparency, dead surfaces,
phantom handlers.
"""
from __future__ import annotations

import importlib
import re
from pathlib import Path

from ...gate_models import GateFinding, PostExecGateContext
from ..common import normalize_path
from ..forensic_clusters import (
    CapabilityDeclaration,
    ProbeResult,
    ProofRequirement,
    assess_config_applied,
    assess_declared_capabilities,
    assess_fallback_transparency,
    assess_phantom_capability,
    assess_rendered_vs_live,
    assess_source_truthfulness,
    assess_state_consistency,
    assess_success_proof,
    assess_surface_reachability,
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
# Cluster 9: Phantom Capability
# ---------------------------------------------------------------------------


def _check_phantom_handlers(ctx: PostExecGateContext) -> list[GateFinding]:
    """Cluster 9: Phantom Capability on critical operator handlers."""
    critical_handlers = [
        ("handle_export_analyze", "INTERFACE.operator.operator_api_infra", "handle_export_analyze", ["handler"]),
        ("handle_switch_project", "INTERFACE.operator.operator_api_infra", "handle_switch_project", ["handler"]),
    ]
    findings: list[GateFinding] = []
    for name, mod, attr, sig in critical_handlers:
        findings.extend(assess_phantom_capability(name, mod, attr, expected_signature=sig))
    return findings


# ---------------------------------------------------------------------------
# Cluster 1: Declared Capability != Actual Capability
# ---------------------------------------------------------------------------


def _check_declared_capabilities(ctx: PostExecGateContext) -> list[GateFinding]:
    """Cluster 1: Verify declared operator handler capabilities actually exist."""
    try:
        mod = importlib.import_module("INTERFACE.operator.operator_api")
    except ImportError:
        from ..gate_checks.common import build_finding
        from ...gate_models import (
            EvidenceReference, GateCategory, GateImpact, GateSeverity, RepairKind,
        )
        from ..common import build_finding as _bf
        detail = "Cannot import operator_api -- unable to check declared capabilities"
        return [_bf(
            check_id="declared_vs_actual",
            category=GateCategory.CONTRACT,
            title="[declared_capability] import_failure",
            severity=GateSeverity.HIGH,
            impact=GateImpact.REVISE,
            summary=detail,
            recommendation="Fix the import error in operator_api.",
            evidence=(EvidenceReference(kind="probe", detail=detail, ok=False),),
            repair_kind=RepairKind.ADD_PROOF.value,
            executor_action="Fix operator_api import error",
        )]

    all_names = getattr(mod, "__all__", None)
    if not all_names:
        return []

    declarations = [
        CapabilityDeclaration(name=name, declared_in="__all__", target=name)
        for name in all_names
        if name.startswith("handle_")
    ]

    def _probe(decl: CapabilityDeclaration) -> ProbeResult:
        obj = getattr(mod, decl.target, None)
        if obj is None:
            return ProbeResult(
                target=decl.target, applicable=True, evidence_found=True, ok=False,
                detail="Declared in __all__ but does not exist on module",
            )
        if not callable(obj):
            return ProbeResult(
                target=decl.target, applicable=True, evidence_found=True, ok=False,
                detail="Exists but is not callable",
            )
        return ProbeResult(
            target=decl.target, applicable=True, evidence_found=True, ok=True,
            detail="Exists and is callable",
        )

    return assess_declared_capabilities(declarations, _probe)


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
# Cluster 5: Rendered Contract != Live Contract
# ---------------------------------------------------------------------------


def _check_rendered_vs_live(ctx: PostExecGateContext) -> list[GateFinding]:
    """Cluster 5: Verify that route handlers referenced by dashboard dispatch exist."""
    try:
        ext_src = Path("INTERFACE/UI/dashboard_extension.py").read_text(encoding="utf-8")
    except OSError:
        return []

    handler_refs = set(re.findall(r"operator_api\.(\w+)\(", ext_src))
    if not handler_refs:
        return []

    # Let ImportError propagate -- _safe_run() in _helpers.py wraps each
    # cluster runner and converts uncaught exceptions into a structured
    # `internal_failure.cluster5_rendered_vs_live` GateFinding. Returning []
    # here would silently mask "operator_api is unimportable" as "no findings"
    # which is indistinguishable from "no handlers referenced" -- exactly the
    # ambiguity the gate framework is meant to surface.
    mod = importlib.import_module("INTERFACE.operator.operator_api")

    def _probe(endpoint: str) -> ProbeResult:
        obj = getattr(mod, endpoint, None)
        if obj is None:
            return ProbeResult(
                target=endpoint, applicable=True, evidence_found=True, ok=False,
                detail=f"Route dispatches to operator_api.{endpoint} but it does not exist",
            )
        if not callable(obj):
            return ProbeResult(
                target=endpoint, applicable=True, evidence_found=True, ok=False,
                detail=f"operator_api.{endpoint} exists but is not callable",
            )
        return ProbeResult(
            target=endpoint, applicable=True, evidence_found=True, ok=True,
            detail=f"operator_api.{endpoint} exists and is callable",
        )

    return assess_rendered_vs_live(list(handler_refs), _probe)


# ---------------------------------------------------------------------------
# Cluster 8: Dead Surface Drift
# ---------------------------------------------------------------------------


def _check_dead_surfaces(ctx: PostExecGateContext) -> list[GateFinding]:
    """Cluster 8: Verify that operator render functions are reachable via routes."""
    try:
        views_mod = importlib.import_module("INTERFACE.UI.views.operator_pages")
        combined_src = ""
        for f in [
            "INTERFACE/operator/operator_api.py",
            "INTERFACE/UI/dashboard_extension.py",
            "INTERFACE/UI/views/operator_status.py",
            "INTERFACE/UI/views/operator_pages.py",
        ]:
            p = Path(f)
            if p.exists():
                combined_src += p.read_text(encoding="utf-8")
    except (ImportError, OSError):
        return []

    render_funcs = [
        name for name in dir(views_mod)
        if name.startswith("render_operator") and callable(getattr(views_mod, name))
    ]

    if not render_funcs:
        return []

    def _probe(surface: str) -> ProbeResult:
        referenced = surface in combined_src
        return ProbeResult(
            target=surface, applicable=True, evidence_found=True, ok=referenced,
            detail=f"{'Referenced' if referenced else 'ORPHANED'} in handler/dispatch code",
        )

    return assess_surface_reachability(render_funcs, _probe)


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
