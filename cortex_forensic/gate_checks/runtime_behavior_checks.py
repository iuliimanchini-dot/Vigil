"""Runtime behavior forensic checks.

Includes:
  - runtime.claim_contradiction: verification passes but runtime health is unhealthy.
  - runtime.identity_mismatch: foreground runtime claims it survives console exit.
  - runtime_duplicate_side_effect (Finding 6.2): same side-effect call pattern appears
    >=2 times in a changed file, suggesting a duplicate startup hook or double
    registration.

Detection approach for Finding 6.2: AST-based call counting.
Ignores strings, comments, and docstrings — no false positives from those sources.
"""
from __future__ import annotations

import ast
import logging
from pathlib import Path

from cortex_forensic._shared import EvidenceReference, GateCategory, GateImpact, GateSeverity, RepairKind
from cortex_forensic.gate_models import PostExecGateContext
from cortex_forensic.source_analysis import is_source_file
from .common import build_check_result, build_finding, normalize_path
from ._ast_helpers import parse_python_source_or_emit_finding

_log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Finding 6.2 — duplicate side-effect registration
# ---------------------------------------------------------------------------

DUPLICATE_SIDE_EFFECT_PATTERNS: tuple[tuple[str, ...], ...] = (
    ("atexit", "register"),
    ("signal", "signal"),
    ("scheduler", "add"),
    ("scheduler", "add_job"),
    ("schedule", "every"),
    ("EventEmitter", "on"),
    ("subscribe",),
    ("add_listener",),
)


def _count_ast_calls(
    content: str,
    call_pattern: tuple[str, ...],
    *,
    emit_finding=None,
    rel_path: str = "",
) -> int:
    """Count ast.Call nodes matching pattern. AST ignores strings/comments/docstrings.

    Pattern examples:
    - ('atexit', 'register') -> matches atexit.register(...)
    - ('signal', 'signal') -> matches signal.signal(...)
    - ('subscribe',) -> matches subscribe(...)

    B4 (2026-04-23): replaces silent `except SyntaxError: return 0` — on
    SyntaxError emits ``meta.syntax_parse_error`` via the supplied
    ``emit_finding`` (if any) and returns 0. If no ``emit_finding`` is
    supplied (unit-test surface) the helper stays silent — matches the prior
    behavior so legacy unit tests keep working.
    """
    tree = parse_python_source_or_emit_finding(
        content,
        rel_path=rel_path,
        emit_finding=emit_finding,
        emitting_gate="runtime_duplicate_side_effect",
    )
    if tree is None:
        return 0
    count = 0
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        func = node.func
        if len(call_pattern) == 2 and isinstance(func, ast.Attribute) and isinstance(func.value, ast.Name):
            if (func.value.id, func.attr) == call_pattern:
                count += 1
        elif len(call_pattern) == 1 and isinstance(func, ast.Name):
            if func.id == call_pattern[0]:
                count += 1
    return count


def run_runtime_behavior_checks(ctx: PostExecGateContext):
    """Original runtime-behavior checks: claim contradiction + identity mismatch.

    Split from combined implementation per F-001 (plan v7 Phase A). The
    duplicate-side-effect detection moved to run_runtime_duplicate_side_effect_checks.

    Checks performed
    ----------------
    1. runtime.claim_contradiction -- verification passes while runtime health is bad.
    2. runtime.identity_mismatch  -- foreground runtime claims persistence.
    """
    findings = []

    # --- existing checks ---------------------------------------------------
    runtime = ctx.runtime_state
    verification = ctx.verification_summary
    health = runtime.health
    if verification.passed and str(health).lower() in {"stale_lock", "no_lock", "unhealthy"}:
        findings.append(
            build_finding(
                check_id="runtime.claim_contradiction",
                category=GateCategory.RUNTIME_BEHAVIOR,
                title="Runtime health contradicts verification success",
                severity=GateSeverity.HIGH,
                impact=GateImpact.REVISE,
                summary=f"Verification is marked passed while runtime health is '{health}'.",
                recommendation="Reconcile runtime truth surfaces before acceptance wording is strengthened.",
            
                repair_kind='refactor',
                executor_action='Address finding details',
                proof_required='Runtime behavior acceptable',
                allowlist_allowed=False,
            )
        )
    if runtime.runtime_model == "attached_foreground_runtime" and runtime.survives_console_exit is True:
        findings.append(
            build_finding(
                check_id="runtime.identity_mismatch",
                category=GateCategory.RUNTIME_BEHAVIOR,
                title="Runtime persistence claim contradicts attached foreground model",
                severity=GateSeverity.HIGH,
                impact=GateImpact.REVISE,
                summary="Attached foreground runtime cannot truthfully claim it survives console exit.",
                recommendation="Keep runtime identity and persistence wording aligned.",
            
                repair_kind='refactor',
                executor_action='Address finding details',
                proof_required='Runtime behavior acceptable',
                allowlist_allowed=False,
            )
        )

    return build_check_result(
        check_id="runtime_behavior",
        category=GateCategory.RUNTIME_BEHAVIOR,
        findings=findings,
    )


def run_runtime_duplicate_side_effect_checks(ctx: PostExecGateContext):
    """Detects duplicate side-effect registrations (plan v6 E.2).

    Flags files where the same side-effect registration pattern
    (atexit.register, signal.signal, scheduler.add, etc.) appears >=2 times.

    Fails open: any I/O error on a changed file is logged at DEBUG and skipped.
    """
    findings = []

    # --- Finding 6.2: duplicate side-effect registration -------------------
    for raw_path in ctx.changed_files_observed:
        normalized = normalize_path(raw_path)
        if not is_source_file(normalized):
            continue

        abs_path = ctx.project_dir / normalized
        try:
            content = abs_path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError) as exc:
            _log.debug("runtime_behavior_checks: cannot read %s: %s", normalized, exc)
            continue

        # B4 (2026-04-23): emit meta finding exactly once per file (on
        # the first pattern iteration) by handing the sink to _count_ast_calls
        # for the first call; subsequent pattern iterations pass no sink to
        # avoid duplicate meta findings.
        meta_sink = findings.append
        for pattern in DUPLICATE_SIDE_EFFECT_PATTERNS:
            count = _count_ast_calls(
                content, pattern,
                emit_finding=meta_sink,
                rel_path=normalized,
            )
            meta_sink = None
            pattern_str = ".".join(pattern)
            if count >= 2:
                findings.append(
                    build_finding(
                        check_id="runtime_duplicate_side_effect.double_registration",
                        category=GateCategory.RUNTIME_BEHAVIOR,
                        title="Potential duplicate side-effect registration",
                        severity=GateSeverity.MEDIUM,
                        impact=GateImpact.REVISE,
                        summary=(
                            f"{normalized} calls '{pattern_str}' {count} time(s). "
                            f"Multiple registrations of the same side-effect hook "
                            f"(atexit, signal, scheduler, event subscription) in one "
                            f"module suggest accidental double-registration or a "
                            f"duplicate startup path."
                        ),
                        recommendation=(
                            "Verify that each side-effect hook is registered exactly "
                            "once per process lifetime. Extract registration into a "
                            "dedicated setup function guarded by an idempotency flag, "
                            "or assert the handler is not already registered before "
                            "calling register/subscribe."
                        ),
                        evidence=[
                            EvidenceReference(
                                kind="file",
                                path=normalized,
                                detail=f"pattern='{pattern_str}' count={count}",
                            )
                        ],
                    
                        repair_kind='refactor',
                        executor_action='Address finding details',
                        proof_required='Runtime behavior acceptable',
                        allowlist_allowed=False,
                    )
                )

    return build_check_result(
        check_id="runtime_duplicate_side_effect",
        category=GateCategory.RUNTIME_BEHAVIOR,
        findings=findings,
    )
