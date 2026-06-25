"""Core orchestrator: run_forensic_cluster_checks.

Imports all _check_* wrappers from sibling modules and runs them via
_safe_run(), merging results into a single GateCheckResult.
"""
from __future__ import annotations

import concurrent.futures
import logging
import time
from typing import List

from ...gate_models import GateCategory, GateCheckResult, GateFinding, PostExecGateContext
from ..common import build_check_result

from ._helpers import _safe_run
from .integrity_checks import (
    _check_config_applied,
    _check_config_general,
    _check_fallback_transparency,
    _check_proxy_as_truth,
    _check_state_divergence,
    _check_success_proof,
)
from .quality_checks import (
    _check_dead_code,
    _check_dependency_vulnerabilities,
    _check_edit_consistency,
    _check_embedded_code_syntax,
    _check_encoding_consistency,
    _check_error_message_quality,
    _check_exception_swallowing,
    _check_http_method_consistency,
    _check_import_cycles,
    _check_js_surface_coverage,
    _check_log_level_quality,
    _check_magic_numbers,
    _check_mutation_verified,
    _check_naming_consistency,
    _check_response_shape_drift,
    _check_roundtrip_consistency,
    _check_secrets_in_code,
    _check_security_patterns,
    _check_shared_mutable_state,
    _check_test_quality,
    _check_todo_debt,
    _check_unused_imports,
)
from .advanced_checks import (
    _check_boundary_validation,
    _check_broad_catch_no_reraise,
    _check_commented_code,
    _check_debug_prints,
    _check_docstring_params,
    _check_hardcoded_paths,
    _check_legacy_compat_debt,
    _check_log_without_context,
    _check_missing_await,
    _check_missing_null_check,
    _check_mutable_defaults,
    _check_naive_timezone,
    _check_near_duplicate_code,
    _check_path_concatenation,
    _check_resource_leaks,
    _check_shadowed_builtins,
    _check_shared_logic_fragmentation,
    _check_test_secrets,
    _check_unchecked_response,
    _check_unpinned_dependencies,
    _check_unreachable_code,
)
_log = logging.getLogger(__name__)

_FORENSIC_CLUSTERS_TIMEOUT = 90


def run_forensic_cluster_checks(ctx: PostExecGateContext) -> GateCheckResult:
    """Run universal forensic cluster checks against the real gate context.

    Universal (project-agnostic) integrity clusters:
    - C2: Success Without Proof (artifact_refs check)
    - C3: Proxy as Truth (remote truth labeling)
    - C4: Config Accepted Ignored (proofs + transport + classification)
    - C6: State Divergence (reported vs observed files)
    - C7: Fallback Hides Truth (remote mode without proof)

    (C1 declared/C5 rendered/C8 dead-surface/C9 phantom were Vigil-specific and
    removed -- they depended on INTERFACE.operator / INTERFACE.UI modules.)
    """
    all_findings: List[GateFinding] = []
    error_notes: List[str] = []

    def _run_all_checks() -> tuple[List[GateFinding], List[str]]:
        _results: List[GateFinding] = []
        _notes: List[str] = []
        _start = time.monotonic()

        _checks = [
            # Phase 1 runners (existing)
            ("cluster2_success_without_proof", lambda: _check_success_proof(ctx)),
            ("cluster4_config_accepted_ignored_proofs", lambda: _check_config_applied(ctx)),
            ("cluster6_state_divergence", lambda: _check_state_divergence(ctx)),
            ("cluster7_fallback_hides_truth", lambda: _check_fallback_transparency(ctx)),
            # clusters 1/5/8/9 (declared_capability, rendered_vs_live, dead_surface,
            # phantom_capability) were REMOVED: they hardcoded Vigil's INTERFACE.operator
            # / INTERFACE.UI modules and only ever produced false findings (ImportError /
            # empty) on any non-Vigil project. Gone for a clean standalone package.
            # Phase 3 runners (new)
            ("cluster3_proxy_as_truth", lambda: _check_proxy_as_truth(ctx)),
            ("cluster4_config_accepted_ignored_general", lambda: _check_config_general(ctx)),
            # Phase 4 runners
            ("cluster10_edit_consistency", lambda: _check_edit_consistency(ctx)),
            ("cluster11_mutation_verified", lambda: _check_mutation_verified(ctx)),
            # Phase 5 runners (universal clusters)
            ("cluster12_security", lambda: _check_security_patterns(ctx)),
            ("cluster13_test_quality", lambda: _check_test_quality(ctx)),
            ("cluster14_import_cycles", lambda: _check_import_cycles(ctx)),
            ("cluster15_roundtrip", lambda: _check_roundtrip_consistency(ctx)),
            ("cluster16_mutable_state", lambda: _check_shared_mutable_state(ctx)),
            # Phase 6 runners (security + code quality)
            ("cluster17_dependency_cves", lambda: _check_dependency_vulnerabilities(ctx)),
            ("cluster20_dead_code", lambda: _check_dead_code(ctx)),
            ("cluster23_unused_imports", lambda: _check_unused_imports(ctx)),
            ("cluster25_secrets", lambda: _check_secrets_in_code(ctx)),
            # Phase 7 runners (code style + encoding)
            ("cluster21_magic_numbers", lambda: _check_magic_numbers(ctx)),
            ("cluster22_error_messages", lambda: _check_error_message_quality(ctx)),
            ("cluster24_naming", lambda: _check_naming_consistency(ctx)),
            ("cluster26_todo_debt", lambda: _check_todo_debt(ctx)),
            ("cluster28_log_levels", lambda: _check_log_level_quality(ctx)),
            ("cluster29_encoding", lambda: _check_encoding_consistency(ctx)),
            # Phase 8 runners (JS/API contract drift)
            ("cluster27_embedded_syntax", lambda: _check_embedded_code_syntax(ctx)),
            ("cluster28b_response_shape", lambda: _check_response_shape_drift(ctx)),
            ("cluster29b_method_consistency", lambda: _check_http_method_consistency(ctx)),
            ("cluster30_js_coverage", lambda: _check_js_surface_coverage(ctx)),
            # Phase 9 runners (fail-loud, portability, security boundaries)
            ("cluster31_exception_swallowing", lambda: _check_exception_swallowing(ctx)),
            ("cluster32_hardcoded_paths", lambda: _check_hardcoded_paths(ctx)),
            ("cluster33_boundary_validation", lambda: _check_boundary_validation(ctx)),
            # Phase 10 runners (deep code quality + language-agnostic)
            ("cluster34_unreachable_code", lambda: _check_unreachable_code(ctx)),
            ("cluster35_shadowed_builtins", lambda: _check_shadowed_builtins(ctx)),
            ("cluster36_mutable_defaults", lambda: _check_mutable_defaults(ctx)),
            ("cluster37_resource_leaks", lambda: _check_resource_leaks(ctx)),
            ("cluster38_docstring_drift", lambda: _check_docstring_params(ctx)),
            ("cluster39_broad_catch", lambda: _check_broad_catch_no_reraise(ctx)),
            ("cluster40_debug_prints", lambda: _check_debug_prints(ctx)),
            ("cluster41_commented_code", lambda: _check_commented_code(ctx)),
            # Phase 11 runners (async, API safety, dependencies)
            ("cluster42_missing_await", lambda: _check_missing_await(ctx)),
            ("cluster43_unchecked_response", lambda: _check_unchecked_response(ctx)),
            ("cluster44_naive_timezone", lambda: _check_naive_timezone(ctx)),
            ("cluster45_near_duplicate", lambda: _check_near_duplicate_code(ctx)),
            ("cluster46_null_check", lambda: _check_missing_null_check(ctx)),
            ("cluster47_path_concat", lambda: _check_path_concatenation(ctx)),
            ("cluster48_log_context", lambda: _check_log_without_context(ctx)),
            ("cluster49_test_secrets", lambda: _check_test_secrets(ctx)),
            ("cluster50_unpinned_deps", lambda: _check_unpinned_dependencies(ctx)),
            # Phase 12 runners (C52: structural quality)
            ("cluster52_shared_logic_fragmentation", lambda: _check_shared_logic_fragmentation(ctx)),
            # Phase 13 runners (C53: legacy compatibility debt)
            ("cluster53_legacy_compat_debt", lambda: _check_legacy_compat_debt(ctx)),
        ]

        from cortex_forensic.self_audit import get_cancel_event
        for label, fn in _checks:
            _cancel = get_cancel_event()
            if _cancel is not None and _cancel.is_set():
                _log.info("forensic_clusters: cancel_event set, stopping at %s", label)
                break
            _elapsed = time.monotonic() - _start
            if _elapsed > _FORENSIC_CLUSTERS_TIMEOUT - 10:  # 10s safety margin
                _log.warning(
                    "post_exec_gate: forensic_clusters timeout threshold approaching "
                    "(%.1fs / %ds), stopping early",
                    _elapsed, _FORENSIC_CLUSTERS_TIMEOUT,
                )
                break
            _safe_run(label, fn, _results, _notes)

        return _results, _notes

    executor = concurrent.futures.ThreadPoolExecutor(max_workers=1)
    try:
        all_findings, error_notes = executor.submit(_run_all_checks).result(
            timeout=_FORENSIC_CLUSTERS_TIMEOUT
        )
    except concurrent.futures.TimeoutError:
        _log.error(
            "post_exec_gate: forensic_clusters total execution timeout (%ds reached)",
            _FORENSIC_CLUSTERS_TIMEOUT,
        )
        all_findings = []
        error_notes = []
    finally:
        executor.shutdown(wait=False)

    # Apply false positive allowlist with revalidation
    from ..forensic_clusters import load_allowlist, filter_by_allowlist
    try:
        allowlist = load_allowlist(ctx.project_dir)
        if allowlist:
            all_findings, filtered, revalidation_notes = filter_by_allowlist(
                all_findings, allowlist, project_dir=ctx.project_dir,
            )
            error_notes.extend(revalidation_notes)
            if filtered:
                error_notes.append(
                    f"[allowlist] Filtered {len(filtered)} finding(s) via false_positive_allowlist.json "
                    f"({sum(1 for e in allowlist if e.is_valid())} valid entries)"
                )
    except (OSError, KeyError, ValueError, TypeError):
        pass  # allowlist failure must not block forensics

    return build_check_result(
        check_id="forensic_clusters",
        category=GateCategory.CONTRACT,
        findings=all_findings,
        notes=error_notes,
    )
