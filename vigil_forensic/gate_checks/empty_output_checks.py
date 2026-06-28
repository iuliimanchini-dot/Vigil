from __future__ import annotations

from pathlib import Path

from vigil_forensic._shared import BINARY_EXTENSIONS as _BINARY_EXTENSIONS
from vigil_forensic._shared import EvidenceReference, GateCategory, GateImpact, GateSeverity, RepairKind
from vigil_forensic.gate_models import PostExecGateContext
from .common import build_check_result, build_finding, normalize_path
import logging
_log = logging.getLogger(__name__)

_EMPTY_ALLOWLIST = {"__init__.py", ".gitkeep"}
# Sprint C3 (2026-04-23): _BINARY_EXTENSIONS imported above from
# SYSTEM.shared_helpers.file_extensions. Keep the private alias so existing
# call sites (abs_path.suffix.lower() in _BINARY_EXTENSIONS) resolve.


def run_empty_output_checks(ctx: PostExecGateContext):
    findings = []
    if not ctx.changed_files_observed or ctx.task_intent == "metadata_only":
        return build_check_result(check_id="empty_output", category=GateCategory.REPORTING)
    for raw_path in ctx.changed_files_observed:
        normalized = normalize_path(raw_path)
        abs_path = ctx.project_dir / normalized

        # Probe existence first. A PermissionError on stat() (raised inside
        # pathlib.Path.exists) must NOT be masked as a missing or empty
        # file: that would silently hide a real issue. Surface it via
        # meta.file_unreadable and move on.
        try:
            present = abs_path.exists()
        except (PermissionError, OSError) as exc:
            from vigil_forensic.meta_findings import emit_meta_finding
            emit_meta_finding(
                "meta.file_unreadable",
                path=normalized,
                detail=f"{type(exc).__name__}: {exc}",
            )
            continue

        if not present:
            continue  # drift_checks handles missing files
        try:
            is_file = abs_path.is_file()
        except (PermissionError, OSError) as exc:
            from vigil_forensic.meta_findings import emit_meta_finding
            emit_meta_finding(
                "meta.file_unreadable",
                path=normalized,
                detail=f"{type(exc).__name__}: {exc}",
            )
            continue
        if not is_file:
            continue
        basename = abs_path.name
        if basename in _EMPTY_ALLOWLIST:
            continue
        if abs_path.suffix.lower() in _BINARY_EXTENSIONS:
            continue
        try:
            size = abs_path.stat().st_size
        except (PermissionError, OSError) as exc:
            from vigil_forensic.meta_findings import emit_meta_finding
            emit_meta_finding(
                "meta.file_unreadable",
                path=normalized,
                detail=f"{type(exc).__name__}: {exc}",
            )
            continue
        if size == 0:
            findings.append(
                build_finding(
                    check_id="empty_output.zero_bytes",
                    category=GateCategory.REPORTING,
                    title=f"Changed file is empty (0 bytes): {normalized}",
                    severity=GateSeverity.MEDIUM,
                    impact=GateImpact.REVISE,
                    summary=f"Executor reported {normalized} as changed but the file is 0 bytes. This may indicate a false-success or truncated write.",
                    recommendation="Verify the file was written correctly. If intentionally empty, document why.",
                    evidence=[EvidenceReference(kind="file", path=normalized, detail="0 bytes")],
                
                    repair_kind='fix_contract',
                    executor_action='Fix empty output',
                    proof_required='Non-empty output',
                    allowlist_allowed=False,
                )
            )
    return build_check_result(check_id="empty_output", category=GateCategory.REPORTING, findings=findings)
