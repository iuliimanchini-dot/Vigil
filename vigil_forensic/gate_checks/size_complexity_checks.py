from __future__ import annotations

import logging

from vigil_forensic._shared import EvidenceReference, GateCategory, GateImpact, GateSeverity, RepairKind
from vigil_forensic.gate_models import PostExecGateContext
from ..source_analysis import extract_functions, get_language_id, is_source_file
from .common import build_check_result, build_finding, is_generated_file, iter_touched_snapshots, max_nesting_depth, normalize_path

_log = logging.getLogger(__name__)


def _suppress_for_data_module(
    snapshot,
    file_warn: int,
    file_revise: int,
    fn_warn: int,
    fn_revise: int,
    nest_warn: int,
    nest_revise: int,
) -> bool:
    """Return True iff legacy thresholds would emit ANY size_complexity finding.

    Used by the Sprint B4 data_module branch to decide whether a single
    ``applicability=not_applicable`` summary finding should be surfaced.
    If legacy thresholds would not flag the file anyway, skip silently
    (no NA finding inflation).
    """
    if snapshot.line_count >= file_warn:
        return True
    if is_source_file(snapshot.path):
        try:
            for fi in extract_functions(snapshot.path, snapshot.text):
                if fi.line_count >= fn_warn:
                    return True
        except Exception:  # pragma: no cover -- fail-open
            return False
        if get_language_id(snapshot.path) == "python":
            if max_nesting_depth(snapshot.text) >= nest_warn:
                return True
    return False

# NOTE: the size_complexity.zone_overload sub-check was REMOVED (FP fix).
# It inferred "responsibility zones" from function-name prefixes — the exact
# same name-prefix heuristic as god_object_zones — and double-reported every
# file that god_object_zones already flagged (e.g. 7 + 5 findings on the same
# filelock files). The zone heuristic now has a single home in the opt-in
# god_object_zones gate (see self_audit._NOISY_OPT_IN_GATES). size_complexity
# keeps only its objective size / function-length / nesting budget checks.


def run_size_complexity_checks(ctx: PostExecGateContext):
    findings = []
    profile = ctx.repo_profile
    thresholds = (profile.size_thresholds if profile is not None else {}) or {}
    file_warn = int(thresholds.get("file_warn", 600))
    file_revise = int(thresholds.get("file_revise", 800))
    fn_warn = int(thresholds.get("function_warn", 80))
    fn_revise = int(thresholds.get("function_revise", 120))
    nest_warn = int(thresholds.get("nesting_warn", 4))
    nest_revise = int(thresholds.get("nesting_revise", 6))
    # Sprint B4: optional per-file role map (ProjectContext.file_roles).
    # None when ctx.project_context is absent (legacy path) or when the
    # light-tier build is in use. Gate behavior degrades gracefully: when
    # file_roles is None or role.kind is in {"code_module", "generated",
    # "unknown", "test_module"}, legacy threshold + F16d marker + allowlist
    # logic applies unchanged. Only role.kind == "data_module" takes the
    # new suppression branch.
    file_roles = getattr(getattr(ctx, "project_context", None), "file_roles", None)

    # Sprint C2 (2026-04-23): prefer TestTopology.is_test_path for test-path
    # skip. Legacy basename check preserved as fallback.
    topology = getattr(getattr(ctx, "project_context", None), "test_topology", None)

    for snapshot in iter_touched_snapshots(ctx):
        if not snapshot.exists:
            continue
        norm_path = snapshot.path.replace("\\", "/")
        if topology is not None:
            if topology.is_test_path(norm_path):
                continue
        elif norm_path.split("/")[-1].startswith("test_"):
            continue
        if profile and snapshot.path in profile.allowlisted_large_files:
            continue
        # F16d: skip auto-generated files and sanctioned asset bundles.
        if is_generated_file(snapshot.text):
            _log.debug(
                "size_complexity: skipping generated/sanctioned file %s",
                snapshot.path,
            )
            continue

        # Sprint B4: density-based suppression for data-dominant modules.
        # Catalog/registry files (e.g. GATE_SPECS = (...)) are measured by
        # thresholds designed for code; surface a single not_applicable
        # finding when legacy thresholds would have flagged, then skip the
        # rest of the per-file checks.
        if file_roles is not None:
            role = file_roles.role(snapshot.path)
            if role.kind == "data_module":
                if _suppress_for_data_module(
                    snapshot,
                    file_warn,
                    file_revise,
                    fn_warn,
                    fn_revise,
                    nest_warn,
                    nest_revise,
                ):
                    pct = int(round(role.metrics.data_density_ratio * 100))
                    findings.append(
                        build_finding(
                            check_id="size.applicability_suppressed",
                            category=GateCategory.SIZE_COMPLEXITY,
                            title="Size/complexity thresholds not applicable to data module",
                            severity=GateSeverity.LOW,
                            impact=GateImpact.WARN,
                            summary=(
                                f"{snapshot.path} is a data-dominant module "
                                f"({pct}% literal content); size thresholds "
                                f"designed for code modules do not apply."
                            ),
                            recommendation=(
                                "Treat catalog/registry files as data, not "
                                "code: exempt from LOC/function/nesting "
                                "budgets."
                            ),
                            evidence=[EvidenceReference(kind="file", path=snapshot.path)],
                            repair_kind="",
                            executor_action="",
                            proof_required="",
                            allowlist_allowed=True,
                            applicability="not_applicable",
                            applicability_reason=role.reason,
                            analysis_mode="role_map",
                            confidence=0.9,
                        )
                    )
                _log.debug(
                    "size_complexity: skipping data_module %s (data_density=%.2f code_density=%.2f)",
                    snapshot.path,
                    role.metrics.data_density_ratio,
                    role.metrics.code_density_ratio,
                )
                continue
            # Other role kinds fall through to legacy path.
        if snapshot.line_count >= file_revise:
            findings.append(
                build_finding(
                    check_id="size.file_too_large",
                    category=GateCategory.SIZE_COMPLEXITY,
                    title="Touched file exceeds the revise threshold",
                    severity=GateSeverity.HIGH,
                    impact=GateImpact.REVISE,
                    summary=f"{snapshot.path} is {snapshot.line_count} lines; profile revise threshold is {file_revise}.",
                    recommendation="Split responsibilities or move new logic into smaller modules.",
                    evidence=[EvidenceReference(kind="file", path=snapshot.path)],
                    repair_kind=RepairKind.SPLIT_MODULE.value,
                    executor_action=f"Split {snapshot.path} — {snapshot.line_count} lines exceeds {file_revise}-line threshold; extract each responsibility into a focused module",
                    proof_required="file below threshold after split; grep confirms no logic removed",
                    allowlist_allowed=False,
                )
            )
        elif snapshot.line_count >= file_warn:
            findings.append(
                build_finding(
                    check_id="size.file_warn",
                    category=GateCategory.SIZE_COMPLEXITY,
                    title="Touched file exceeds the warning threshold",
                    severity=GateSeverity.MEDIUM,
                    impact=GateImpact.REVISE,
                    summary=f"{snapshot.path} is {snapshot.line_count} lines; profile warning threshold is {file_warn}.",
                    recommendation="Keep the file from becoming a new god-file.",
                    evidence=[EvidenceReference(kind="file", path=snapshot.path)],
                    repair_kind=RepairKind.SPLIT_MODULE.value,
                    executor_action=f"Watch {snapshot.path} — {snapshot.line_count} lines approaching {file_revise}-line revise threshold",
                )
            )
        if is_source_file(snapshot.path):
            for fi in extract_functions(snapshot.path, snapshot.text):
                if fi.line_count >= fn_revise:
                    findings.append(
                        build_finding(
                            check_id="size.function_too_large",
                            category=GateCategory.SIZE_COMPLEXITY,
                            title="Touched function exceeds the revise threshold",
                            severity=GateSeverity.HIGH,
                            impact=GateImpact.REVISE,
                            summary=f"{snapshot.path}::{fi.name} is {fi.line_count} lines; profile revise threshold is {fn_revise}.",
                            recommendation="Split orchestration, logic, and rendering into smaller helpers.",
                            evidence=[EvidenceReference(kind="file", path=snapshot.path, detail=fi.name)],
                            repair_kind=RepairKind.REFACTOR.value,
                            executor_action=f"Refactor {snapshot.path}::{fi.name} — {fi.line_count} lines; extract sub-steps into named helpers",
                            proof_required="function below threshold; tests still pass",
                            allowlist_allowed=False,
                        )
                    )
                    break
                if fi.line_count >= fn_warn:
                    findings.append(
                        build_finding(
                            check_id="size.function_warn",
                            category=GateCategory.SIZE_COMPLEXITY,
                            title="Touched function exceeds the warning threshold",
                            severity=GateSeverity.MEDIUM,
                            impact=GateImpact.REVISE,
                            summary=f"{snapshot.path}::{fi.name} is {fi.line_count} lines; profile warning threshold is {fn_warn}.",
                            recommendation="Watch for mixed responsibility growth.",
                            evidence=[EvidenceReference(kind="file", path=snapshot.path, detail=fi.name)],
                            repair_kind=RepairKind.REFACTOR.value,
                            executor_action=f"Watch {snapshot.path}::{fi.name} — {fi.line_count} lines approaching revise threshold",
                        )
                    )
                    break
            if get_language_id(snapshot.path) == "python":
                nesting = max_nesting_depth(snapshot.text)
                if nesting >= nest_revise:
                    findings.append(
                        build_finding(
                            check_id="size.nesting_too_high",
                            category=GateCategory.SIZE_COMPLEXITY,
                            title="Touched code exceeds nesting threshold",
                            severity=GateSeverity.HIGH,
                            impact=GateImpact.REVISE,
                            summary=f"{snapshot.path} reaches nesting depth {nesting}; profile revise threshold is {nest_revise}.",
                            recommendation="Flatten control flow or extract helpers.",
                            evidence=[EvidenceReference(kind="file", path=snapshot.path)],
                            repair_kind=RepairKind.REFACTOR.value,
                            executor_action=f"Flatten {snapshot.path} — nesting depth {nesting} exceeds {nest_revise}; use early returns",
                            proof_required="nesting depth below threshold; tests still pass",
                            allowlist_allowed=False,
                        )
                    )
                elif nesting >= nest_warn:
                    findings.append(
                        build_finding(
                            check_id="size.nesting_warn",
                            category=GateCategory.SIZE_COMPLEXITY,
                            title="Touched code exceeds warning nesting threshold",
                            severity=GateSeverity.MEDIUM,
                            impact=GateImpact.REVISE,
                            summary=f"{snapshot.path} reaches nesting depth {nesting}; profile warning threshold is {nest_warn}.",
                            recommendation="Prefer early exits and smaller helpers.",
                            evidence=[EvidenceReference(kind="file", path=snapshot.path)],
                            repair_kind=RepairKind.REFACTOR.value,
                            executor_action=f"Watch {snapshot.path} — nesting depth {nesting} approaching {nest_revise} revise threshold",
                        )
                    )
        # size_complexity.zone_overload removed (FP fix): name-prefix zone
        # inference now lives only in the opt-in god_object_zones gate.
    return build_check_result(check_id="size_complexity", category=GateCategory.SIZE_COMPLEXITY, findings=findings)


# ---------------------------------------------------------------------------
# hotspot_inflation gate
# ---------------------------------------------------------------------------

_MODE_DO_NOT_TOUCH = "do_not_touch_without_runtime_trace"
_MODE_FORENSIC_FIRST = "forensic_first"


def run_hotspot_inflation_checks(ctx: PostExecGateContext):
    """Emit a finding for every touched file that is a high-risk hotspot in ctx.maps.

    Modes that trigger findings:
      - do_not_touch_without_runtime_trace -> HIGH severity
      - forensic_first                     -> MEDIUM severity

    No file-fallback: hotspot data is only available via ctx.maps.
    When ctx.maps is absent or missing, return empty findings (fail-open).
    """
    if ctx.maps is None or getattr(ctx.maps, "missing", False):
        _log.debug("hotspot_inflation: ctx.maps not available -- skipping")
        return build_check_result(
            check_id="hotspot_inflation",
            category=GateCategory.SIZE_COMPLEXITY,
            notes=("maps not available -- skipping",),
        )

    hotspots = getattr(ctx.maps, "hotspot", ()) or ()
    hotspot_by_target: dict[str, object] = {
        normalize_path(h.target): h for h in hotspots
    }

    findings = []
    for raw_path in (ctx.touched_files or ()):
        normalized = normalize_path(raw_path)
        h = hotspot_by_target.get(normalized)
        if h is None:
            continue
        mode = (getattr(h, "recommended_mode", "") or "").lower()
        if mode == _MODE_DO_NOT_TOUCH:
            severity = GateSeverity.HIGH
            impact = GateImpact.REVISE
            recommendation = (
                "Capture startup trace + regression tests before merging. "
                "This file must not be modified without a runtime trace per map_builder policy."
            )
        elif mode == _MODE_FORENSIC_FIRST:
            severity = GateSeverity.MEDIUM
            impact = GateImpact.REVISE
            recommendation = (
                "Run forensic gates + authority check before refactoring. "
                "This file is flagged forensic_first in the hotspot map."
            )
        else:
            _log.debug("hotspot_inflation: %s mode=%r -- not actionable, skipping", normalized, mode)
            continue

        hotspot_score = getattr(h, "hotspot_score", 0)
        findings.append(
            build_finding(
                check_id="hotspot_inflation",
                category=GateCategory.SIZE_COMPLEXITY,
                title=f"Touched high-risk hotspot ({mode})",
                severity=severity,
                impact=impact,
                summary=(
                    f"{normalized}: hotspot_score={hotspot_score}, mode={mode}. "
                    f"Modifying this file requires pre-change forensic trace per map_builder policy."
                ),
                recommendation=recommendation,
                evidence=(EvidenceReference(kind="file", path=normalized),),
                repair_kind=RepairKind.REFACTOR.value,
                executor_action="Address finding details",
                proof_required="Performance acceptable",
                allowlist_allowed=False,
            )
        )

    return build_check_result(
        check_id="hotspot_inflation",
        category=GateCategory.SIZE_COMPLEXITY,
        findings=findings,
    )
