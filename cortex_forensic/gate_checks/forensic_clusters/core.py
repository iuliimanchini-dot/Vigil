"""Core types, adapter, language detection, and integrity clusters 1-9.

Clusters:
  1 - Declared Capability != Actual Capability
  2 - Success Without Proof
  3 - Non-Authoritative Proxy Mistaken as Truth
  4 - Config Accepted But Ignored
  5 - Rendered Contract != Live Contract
  6 - State Divergence
  7 - Fallback Hides Truth
  8 - Dead Surface Drift
  9 - Phantom Capability (LLM-specific)
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, Optional, Sequence

from ...gate_models import (
    EvidenceReference,
    GateCategory,
    GateFinding,
    GateImpact,
    GateSeverity,
    RepairKind,
)
from ..common import build_finding
import logging
_log = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Language detection
# ---------------------------------------------------------------------------


def detect_language(file_path: str) -> str:
    """Detect programming language from file extension."""
    ext = file_path.rsplit(".", 1)[-1].lower() if "." in file_path else ""
    return {
        "py": "python", "pyw": "python",
        "js": "javascript", "mjs": "javascript", "cjs": "javascript",
        "ts": "typescript", "tsx": "typescript", "jsx": "javascript",
        "rb": "ruby", "go": "go", "rs": "rust",
        "java": "java", "kt": "kotlin", "scala": "scala",
        "cs": "csharp", "cpp": "cpp", "c": "c", "h": "c",
        "swift": "swift", "php": "php", "lua": "lua",
        "sh": "shell", "bash": "shell", "zsh": "shell",
        "html": "html", "css": "css", "scss": "scss",
        "json": "json", "yaml": "yaml", "yml": "yaml", "toml": "toml",
        "md": "markdown", "rst": "restructuredtext",
        "sql": "sql",
    }.get(ext, "unknown")


# ---------------------------------------------------------------------------
# Helper: build an insufficient-evidence finding
# ---------------------------------------------------------------------------


def _insufficient_evidence_finding(
    check_id: str,
    category: GateCategory,
    cluster: str,
    explanation: str,
) -> GateFinding:
    return build_finding(
        check_id=check_id,
        category=category,
        title=f"[{cluster}] insufficient evidence",
        severity=GateSeverity.INFO,
        impact=GateImpact.WARN,
        summary=explanation,
        recommendation="Gather more evidence before re-running this check.",
        repair_kind=RepairKind.ADD_PROOF.value,
        executor_action="Gather more evidence before re-running",
        proof_required="",
        allowlist_allowed=True,
    )


# ---------------------------------------------------------------------------
# Cluster 2: Success Without Proof
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ProofRequirement:
    """A field/artifact that must be present for success to be truthful."""
    name: str
    field_path: str
    required: bool = True


def assess_success_proof(
    status: dict[str, object],
    proof_requirements: Sequence[ProofRequirement],
    success_field: str = "ok",
    completion_field: str = "phase",
    completion_value: str = "completed",
) -> list[GateFinding]:
    """Cluster 2: Verify success claims have required proof."""
    phase = str(status.get(completion_field) or "")
    if phase != completion_value:
        return []  # not a success claim

    ok = status.get(success_field)
    if ok is False:
        return []  # explicit failure, not a false success claim

    findings: list[GateFinding] = []
    for req in proof_requirements:
        if not req.required:
            continue
        value = status.get(req.field_path)
        has_value = bool(value) if isinstance(value, str) else value is not None
        if not has_value:
            findings.append(build_finding(
                check_id="success_proof",
                category=GateCategory.REPORTING,
                title=f"[success_without_proof] missing: {req.name}",
                severity=GateSeverity.MEDIUM,
                impact=GateImpact.REVISE,
                summary=f"Success claimed but missing proof: {req.field_path}",
                recommendation="Provide required proof artifacts before claiming success.",
                evidence=(EvidenceReference(kind="probe", detail=f"MISSING: {req.name}", ok=False),),
                repair_kind=RepairKind.ADD_MISSING_PROOF.value,
                executor_action=f"Add missing proof: {req.name}",
            ))
    return findings


# ---------------------------------------------------------------------------
# Cluster 3: Non-Authoritative Proxy Mistaken as Truth
# ---------------------------------------------------------------------------


def assess_source_truthfulness(
    stated_source: str,
    actual_source: str,
    label_shown: str = "",
) -> list[GateFinding]:
    """Cluster 3: Verify source labeling is honest.

    stated_source/actual_source: "authoritative"|"proxy"|"cache"|"preview"|"stale"|"unknown"
    """
    valid_sources = {"authoritative", "proxy", "cache", "preview", "stale", "unknown"}
    if actual_source not in valid_sources:
        return [_insufficient_evidence_finding(
            check_id="source_truthfulness",
            category=GateCategory.TRUTH_BOUNDARY,
            cluster="proxy_as_truth",
            explanation=f"Unknown actual source type: {actual_source}",
        )]

    if actual_source == "unknown":
        return [_insufficient_evidence_finding(
            check_id="source_truthfulness",
            category=GateCategory.TRUTH_BOUNDARY,
            cluster="proxy_as_truth",
            explanation="Actual source is unknown -- cannot assess truthfulness",
        )]

    if actual_source != "authoritative" and stated_source == "authoritative":
        return [build_finding(
            check_id="source_truthfulness",
            category=GateCategory.TRUTH_BOUNDARY,
            title=f"[proxy_as_truth] {label_shown or 'source_label'}",
            severity=GateSeverity.MEDIUM,
            impact=GateImpact.REVISE,
            summary=f"Stated '{stated_source}' but actual is '{actual_source}'",
            recommendation=f"Non-authoritative source ({actual_source}) presented as authoritative",
            evidence=(EvidenceReference(kind="probe", detail=f"Stated '{stated_source}' but actual is '{actual_source}'", ok=False),),
            repair_kind=RepairKind.FIX_CONTRACT.value,
            executor_action="Correct source labeling to reflect actual data provenance",
        )]

    return []


# ---------------------------------------------------------------------------
# Cluster 4: Config Accepted But Ignored
# ---------------------------------------------------------------------------


def assess_config_applied(
    config_key: str,
    config_value: object,
    persisted: bool,
    consumed_by_runtime: bool,
) -> list[GateFinding]:
    """Cluster 4: Verify config is not just accepted but applied."""
    if config_key == "" or config_value is None:
        return []  # not applicable

    findings: list[GateFinding] = []
    if not persisted:
        findings.append(build_finding(
            check_id="config_applied",
            category=GateCategory.CONFIG_SSOT,
            title=f"[config_accepted_ignored] {config_key}.persisted",
            severity=GateSeverity.MEDIUM,
            impact=GateImpact.REVISE,
            summary=f"Config '{config_key}' accepted but not persisted",
            recommendation="Persist config value before returning success.",
            evidence=(EvidenceReference(kind="probe", detail="Config NOT persisted", ok=False),),
            repair_kind=RepairKind.FIX_CONTRACT.value,
            executor_action=f"Persist config '{config_key}'",
        ))
    elif not consumed_by_runtime:
        findings.append(build_finding(
            check_id="config_applied",
            category=GateCategory.CONFIG_SSOT,
            title=f"[config_accepted_ignored] {config_key}.consumed",
            severity=GateSeverity.MEDIUM,
            impact=GateImpact.REVISE,
            summary=f"Config '{config_key}' accepted and persisted but not consumed by runtime",
            recommendation="Ensure runtime actually reads and applies the persisted config.",
            evidence=(EvidenceReference(kind="probe", detail="Config NOT consumed by runtime", ok=False),),
            repair_kind=RepairKind.FIX_CONTRACT.value,
            executor_action=f"Wire config '{config_key}' into runtime consumption path",
        ))
    return findings


# ---------------------------------------------------------------------------
# Cluster 6: State Divergence
# ---------------------------------------------------------------------------


def assess_state_consistency(
    representations: dict[str, object],
    expected_equal_keys: Sequence[tuple[str, str]],
    normalizer: Optional[Callable[[object], object]] = None,
) -> list[GateFinding]:
    """Cluster 6: Multiple representations of the same state must agree.

    representations: {"model": value, "persisted": value, "displayed": value}
    expected_equal_keys: [("model", "persisted"), ("model", "displayed")]
    """
    if len(representations) < 2:
        return []  # not applicable

    norm = normalizer or (lambda x: x)
    findings: list[GateFinding] = []

    for key_a, key_b in expected_equal_keys:
        val_a = representations.get(key_a)
        val_b = representations.get(key_b)
        if val_a is None or val_b is None:
            missing = key_a if val_a is None else key_b
            findings.append(build_finding(
                check_id="state_consistency",
                category=GateCategory.DRIFT,
                title=f"[state_divergence] {key_a}=={key_b}",
                severity=GateSeverity.MEDIUM,
                impact=GateImpact.REVISE,
                summary=f"Missing representation: {missing}",
                recommendation=f"State divergence: {key_a}=={key_b}. Ensure all representations are consistent.",
                evidence=(EvidenceReference(kind="probe", detail=f"Missing representation: {missing}", ok=False),),
                repair_kind=RepairKind.FIX_CONTRACT.value,
                executor_action=f"Provide missing representation: {missing}",
            ))
            continue
        if norm(val_a) != norm(val_b):
            findings.append(build_finding(
                check_id="state_consistency",
                category=GateCategory.DRIFT,
                title=f"[state_divergence] {key_a}=={key_b}",
                severity=GateSeverity.MEDIUM,
                impact=GateImpact.REVISE,
                summary=f"State divergence: {key_a} vs {key_b}",
                recommendation=f"State divergence detected: {key_a}=={key_b}. Synchronize representations.",
                evidence=(EvidenceReference(kind="probe", detail=f"DIVERGENT: {key_a} vs {key_b}", ok=False),),
                repair_kind=RepairKind.FIX_CONTRACT.value,
                executor_action=f"Synchronize {key_a} and {key_b}",
            ))
    return findings


# ---------------------------------------------------------------------------
# Cluster 7: Fallback Hides Truth
# ---------------------------------------------------------------------------


def assess_fallback_transparency(
    primary_available: bool,
    fallback_used: bool,
    degradation_labeled: bool,
) -> list[GateFinding]:
    """Cluster 7: Hidden fallback = fail; labeled degradation = pass."""
    if primary_available and not fallback_used:
        return []  # PASS

    if not primary_available and not fallback_used:
        return [_insufficient_evidence_finding(
            check_id="fallback_transparency",
            category=GateCategory.FALLBACK,
            cluster="fallback_hides_truth",
            explanation="Primary unavailable, no fallback used -- state unclear",
        )]

    if fallback_used and not degradation_labeled:
        return [build_finding(
            check_id="fallback_transparency",
            category=GateCategory.FALLBACK,
            title=f"[fallback_hides_truth] fallback_label",
            severity=GateSeverity.MEDIUM,
            impact=GateImpact.REVISE,
            summary="Hidden fallback: failure masked as normal operation",
            recommendation="Label degraded mode explicitly so callers know they are not getting primary behavior.",
            evidence=(EvidenceReference(kind="probe", detail="Fallback active but not labeled as degraded mode", ok=False),),
            repair_kind=RepairKind.REMOVE_FALLBACK.value,
            executor_action="Add explicit degradation label when fallback is active",
        )]

    return []  # fallback used AND degradation labeled = PASS


