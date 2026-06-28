"""Context health gate (B3 wave, 2026-04-23).

The autoforensics system previously had a silent failure mode: when the
``PostExecGateContext`` was assembled with empty fields (e.g. ``file_snapshots
== {}`` because snapshot collection failed upstream, or ``touched_files == ()``
because the changed-files list was lost), every write-safety gate would
trivially return "no findings". The report would read PASS even though no
meaningful audit actually happened.

This gate closes that gap. It runs FIRST in the dispatch order (conceptually
— ordering is enforced by GATE_SPECS position) and emits meta-level findings
describing exactly which context slots were unpopulated and why that matters.

Design rules
------------
* Runs in BOTH static (sessionless) and full-audit modes. It is the single
  gate whose job is to tell you whether the OTHER gates had enough context
  to produce meaningful results.
* Uses ``attempt_id`` to detect static mode — the static CLI sets
  ``attempt_id="forensic_audit_static"`` / ``self_audit`` (see
  ``cli_forensic_audit._build_static_context`` and
  ``self_audit.build_synthetic_context``). In static mode we deliberately
  suppress findings that are expected to be empty (e.g. empty
  ``file_snapshots`` is the normal case for the CLI static runner).
* Emits findings via the shared ``build_finding`` helper so they flow through
  the same allowlist / severity override machinery as the other gates. It
  does NOT use ``meta_findings.emit_meta_finding`` because this gate runs
  in-band (it's a real gate runner, not an out-of-band emitter).
"""
from __future__ import annotations

import logging

from vigil_forensic._shared import (
    EvidenceReference,
    GateCategory,
    GateCheckResult,
    GateFinding,
    GateImpact,
    GateSeverity,
)
from vigil_forensic.gate_models import PostExecGateContext

from .common import build_check_result, build_finding

_log = logging.getLogger(__name__)

# Static-mode attempt_id sentinel values. Kept here rather than imported from
# cli_forensic_audit to avoid a circular import between gate_checks/* and
# BRAIN/autoforensics/cli_forensic_audit.py.
_STATIC_MODE_ATTEMPT_IDS: frozenset[str] = frozenset({
    "forensic_audit_static",
    "self_audit",
})


def _is_static_mode(ctx: PostExecGateContext) -> bool:
    """Return True if the context was assembled by the static CLI runners.

    Static-mode contexts legitimately have empty ``file_snapshots`` (self_audit
    populates them, but cli_forensic_audit builds them lazily on access),
    empty ``session_artifacts``, missing git state, etc. Suppressing findings
    in that mode avoids drowning the report in meta-noise when the user is
    intentionally running a sessionless scan.
    """
    return ctx.attempt_id in _STATIC_MODE_ATTEMPT_IDS


def _has_git_state(ctx: PostExecGateContext) -> bool:
    """Detect whether the context carries git-derived state.

    ``PostExecGateContext`` does not have a dedicated ``git_state`` attribute
    in the current data model — git-dependent information is scattered across
    ``runtime_state.extras``, ``forensic_report``, and per-gate git_show
    probes. We treat "git state available" as any of:

    * ``ctx.runtime_state.extras`` carries a key containing "git";
    * ``ctx.artifact_refs`` references a git artifact;
    * ``ctx.forensic_report`` has a non-empty ``current_task_id`` (implies
      a live session with git history reachable).

    This heuristic is intentionally generous: we only want to emit a finding
    when NO path to git state is available, not every time a particular
    optional field is empty.
    """
    # Runtime-state extras often carry git_hash, git_branch, etc.
    try:
        for key, _val in ctx.runtime_state.extras:
            if "git" in str(key).lower():
                return True
    except AttributeError:
        pass

    # Artifact references — e.g., git_blame_<file>.txt
    for key in ctx.artifact_refs.keys():
        if "git" in str(key).lower():
            return True

    # Live session with current_task_id implies git history reachable
    current_task = getattr(ctx.forensic_report, "current_task_id", None)
    if current_task:
        return True

    return False


def _session_dir_exists(ctx: PostExecGateContext) -> bool:
    """Return True if the expected session artifact directory exists on disk.

    Only meaningful when ``session_number > 0`` (i.e. we're in an active
    session, not a static scan). Layout follows the project convention of
    ``<project_dir>/.cortex/sessions/<session_number>/``.
    """
    if ctx.session_number <= 0:
        return True  # no session → no directory expected
    session_dir = ctx.project_dir / ".cortex" / "sessions" / str(ctx.session_number)
    try:
        return session_dir.is_dir()
    except OSError as exc:
        _log.warning(
            "context_health: OSError probing session dir %s: %s", session_dir, exc,
        )
        # If we can't even probe the directory, downstream gates will also
        # struggle — surface it as "missing" to be safe.
        return False


def run_context_health_checks(ctx: PostExecGateContext) -> GateCheckResult:
    """Emit meta-level findings describing gaps in the audit context itself.

    Runs in BOTH static and full-audit modes. Findings that would be
    expected in static mode (empty snapshots, no git state, no session dir)
    are suppressed when ``_is_static_mode(ctx)`` is True so the noise floor
    stays meaningful.
    """
    findings: list[GateFinding] = []
    static = _is_static_mode(ctx)

    # 1. Empty file_snapshots outside static mode -----------------------------
    #    This is the original motivating failure: write-safety gates silently
    #    pass when they have no snapshots to inspect. In static mode,
    #    cli_forensic_audit intentionally leaves snapshots empty (gates read
    #    files on demand from disk), so we only fire outside that mode.
    if not static and not ctx.file_snapshots:
        findings.append(
            build_finding(
                check_id="context_health.empty_file_snapshots",
                category=GateCategory.META,
                title="Audit context has no file snapshots",
                severity=GateSeverity.HIGH,
                impact=GateImpact.WARN,
                summary=(
                    "ctx.file_snapshots is empty outside static-scan mode. "
                    "Write-safety gates (atomic_write, empty_output, "
                    "contract_shape_drift, etc.) use snapshots to reason "
                    "about file content and will silently produce 0 findings "
                    "when the map is empty. A PASS verdict in that state is "
                    "meaningless."
                ),
                recommendation=(
                    "Populate ctx.file_snapshots in the upstream gate "
                    "pipeline before dispatch, OR treat this finding as a "
                    "hard failure of the gate infrastructure (not of the "
                    "project under audit)."
                ),
                evidence=[
                    EvidenceReference(
                        kind="context_slot",
                        path="ctx.file_snapshots",
                        detail=f"attempt_id={ctx.attempt_id!r} task_id={ctx.task_id!r}",
                        ok=False,
                    )
                ],
                allowlist_allowed=False,
            )
        )

    # 2. Missing git state ----------------------------------------------------
    #    Gates that rely on diff/blame/authorship (authority_checks,
    #    contract_shape_drift) will be inconclusive. Emit MEDIUM so operators
    #    know findings from those gates may be incomplete.
    if not static and not _has_git_state(ctx):
        findings.append(
            build_finding(
                check_id="context_health.git_state_unavailable",
                category=GateCategory.META,
                title="Audit context is missing git state",
                severity=GateSeverity.MEDIUM,
                impact=GateImpact.WARN,
                summary=(
                    "No git-derived state attached to context (no git keys "
                    "in runtime_state.extras, no git artifact refs, no "
                    "current_task_id). Gates depending on diff / blame / "
                    "authorship are inconclusive."
                ),
                recommendation=(
                    "Ensure the gate pipeline captures git state upstream "
                    "(git rev-parse / git show) when a git repo is "
                    "available. If the project is intentionally not a git "
                    "repo, disable git-dependent gates explicitly."
                ),
                evidence=[
                    EvidenceReference(
                        kind="context_slot",
                        path="ctx.runtime_state/artifact_refs/forensic_report",
                        detail="no git-prefixed key found",
                        ok=False,
                    )
                ],
                allowlist_allowed=True,
            )
        )

    # 3. Session artifacts missing -------------------------------------------
    #    session_number is set but the expected artifact directory is absent.
    #    This typically means an interrupted session or out-of-band cleanup.
    if ctx.session_number > 0 and not _session_dir_exists(ctx):
        session_dir = ctx.project_dir / ".cortex" / "sessions" / str(ctx.session_number)
        findings.append(
            build_finding(
                check_id="context_health.session_artifacts_missing",
                category=GateCategory.META,
                title="Session artifacts directory is missing",
                severity=GateSeverity.MEDIUM,
                impact=GateImpact.WARN,
                summary=(
                    f"Expected session artifact dir {session_dir} does not "
                    f"exist, yet session_number={ctx.session_number} is set "
                    f"on the gate context."
                ),
                recommendation=(
                    "Investigate why the session produced no artifact "
                    "directory (interrupted session, cleanup race, wrong "
                    "project_dir). Artifact-completeness gates cannot "
                    "produce meaningful output without it."
                ),
                evidence=[
                    EvidenceReference(
                        kind="session_artifact_dir",
                        path=str(session_dir),
                        detail=f"session_number={ctx.session_number}",
                        ok=False,
                    )
                ],
                allowlist_allowed=True,
            )
        )

    # 4. Empty touched_files outside static mode ------------------------------
    #    This is a soft signal — a genuine no-op audit can produce empty
    #    touched_files legitimately. Surface it as LOW so it's visible but
    #    doesn't block.
    if not static and not ctx.touched_files:
        findings.append(
            build_finding(
                check_id="context_health.touched_files_empty",
                category=GateCategory.META,
                title="Audit context reports zero touched files",
                severity=GateSeverity.LOW,
                impact=GateImpact.WARN,
                summary=(
                    "ctx.touched_files is empty outside static-scan mode. "
                    "May be a legitimate no-op audit (metadata-only) but "
                    "can also mean the upstream changed-files collector "
                    "lost its input."
                ),
                recommendation=(
                    "Confirm the audit input is what you expect. If this "
                    "audit is genuinely no-op, suppress this finding via "
                    "allowlist; otherwise investigate the upstream "
                    "changed-files collector."
                ),
                evidence=[
                    EvidenceReference(
                        kind="context_slot",
                        path="ctx.touched_files",
                        detail=f"attempt_id={ctx.attempt_id!r}",
                        ok=False,
                    )
                ],
                allowlist_allowed=True,
            )
        )

    return build_check_result(
        check_id="context_health",
        category=GateCategory.META,
        findings=findings,
    )
