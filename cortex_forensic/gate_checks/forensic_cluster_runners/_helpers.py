"""Shared helpers for forensic cluster runner sub-modules."""
from __future__ import annotations

import logging
from typing import List

from ...gate_models import (
    EvidenceReference,
    GateCategory,
    GateFinding,
    GateImpact,
    GateSeverity,
    RepairKind,
)
from ..common import build_finding

_log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Global cap: each per-file scanner returns at most this many findings total
# ---------------------------------------------------------------------------

_MAX_FINDINGS_PER_CLUSTER = 30


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _safe_run(label: str, fn, findings: List[GateFinding], notes: List[str]) -> None:
    """Run *fn*, extending *findings* with results; on error append error finding + note."""
    try:
        result = fn()
        if isinstance(result, list):
            if result:
                findings.extend(result)
            else:
                notes.append(f"[forensic_clusters] {label}: not applicable")
        elif result is not None:
            # Fail-loud: unexpected return type is a runner bug, not a skip
            _log.error("forensic_clusters: %s returned unexpected type %s", label, type(result).__name__)
            findings.append(build_finding(
                check_id=f"internal_failure.{label}",
                category=GateCategory.CONTRACT,
                title=f"[internal_failure] {label} — unexpected return type",
                severity=GateSeverity.HIGH,
                impact=GateImpact.REVISE,
                summary=f"Cluster runner {label!r} returned {type(result).__name__} instead of list[GateFinding]",
                recommendation="Fix the cluster runner to return list[GateFinding] or empty list.",
                evidence=(EvidenceReference(kind="probe", detail=f"Unexpected return: {type(result)}", ok=False),),
                repair_kind=RepairKind.INVESTIGATE_GATE_FAILURE.value,
                executor_action=f"Fix return type in cluster runner {label!r}",
            ))
            notes.append(f"[forensic_clusters] {label} unexpected return type: {type(result).__name__}")
    except Exception as exc:  # noqa: BLE001
        _log.error("forensic_clusters: %s internal error: %s", label, exc, exc_info=True)
        detail = f"Cluster runner {label!r} raised {type(exc).__name__}: {exc}"
        findings.append(build_finding(
            check_id=f"internal_failure.{label}",
            category=GateCategory.CONTRACT,
            title=f"[internal_failure] {label}",
            severity=GateSeverity.HIGH,
            impact=GateImpact.REVISE,
            summary=detail,
            recommendation="Fix the internal error in the forensic cluster runner.",
            evidence=(EvidenceReference(kind="probe", detail=detail, ok=False),),
            repair_kind=RepairKind.INVESTIGATE_GATE_FAILURE.value,
            executor_action=f"Fix internal failure in cluster runner {label!r}",
        ))
        notes.append(f"[forensic_clusters] {label} internal error: {exc}")
