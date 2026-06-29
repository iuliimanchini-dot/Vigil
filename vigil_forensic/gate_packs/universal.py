"""Universal gate specifications for vigil_forensic.

Adapted from the Vigil autoforensics gate_packs.universal.
FOC gates (foc_observability_coverage, foc_secret_logging, foc_duplicate_log) are DROPPED.
All cluster imports rewritten to vigil_forensic.*.
"""
from __future__ import annotations

from typing import Any

from vigil_forensic.gate_checks.broad_except_checks import run_broad_except_checks
from vigil_forensic.gate_checks.embedded_string_checks import run_embedded_string_checks
from vigil_forensic.gate_checks.duplication_checks import run_duplication_checks
from vigil_forensic.gate_checks.file_proliferation_checks import run_file_proliferation_checks
from vigil_forensic.gate_checks.fix_without_test_checks import run_fix_without_test_checks
from vigil_forensic.gate_checks.empty_output_checks import run_empty_output_checks
from vigil_forensic.gate_checks.semantic_intent_checks import run_semantic_intent_checks
from vigil_forensic.gate_checks.temporal_freshness_checks import run_temporal_freshness_checks
from vigil_forensic.gate_checks.hallucination_checks import run_hallucination_checks
from vigil_forensic.gate_checks.encoding_checks import run_encoding_checks, run_subprocess_encoding_checks
from vigil_forensic.gate_checks.authority_checks import run_authority_checks
from vigil_forensic.gate_checks.runtime_behavior_checks import run_runtime_duplicate_side_effect_checks
from vigil_forensic.gate_checks.contract_shape_drift_checks import run_contract_shape_drift_checks
from vigil_forensic.gate_checks.toctou_checks import run_toctou_check_then_act
from vigil_forensic.gate_checks.atomic_write_checks import run_atomic_write_safety_checks
from vigil_forensic.gate_checks.swift_safety_checks import run_swift_force_unwrap_checks, run_swift_iuo_checks
from vigil_forensic.gate_checks.context_fallback_checks import run_context_fallback_save_checks
from vigil_forensic.gate_checks.broad_except_hidden_sentinel_checks import run_broad_except_hidden_sentinel_checks
from vigil_forensic.gate_checks.god_object_zones_checks import run_god_object_zones_checks
from vigil_forensic.gate_checks.forensic_cluster_runners import run_forensic_cluster_checks
from vigil_forensic.gate_checks.project_specific_runner import run_project_specific_checks
from vigil_forensic.gate_checks.fallback_checks import run_fallback_checks
from vigil_forensic.gate_checks.config_ssot_checks import run_config_ssot_checks
from vigil_forensic.gate_checks.performance_checks import run_performance_checks
from vigil_forensic.gate_checks.size_complexity_checks import run_size_complexity_checks, run_hotspot_inflation_checks
from vigil_forensic.gate_checks.testing_checks import run_testing_checks
from vigil_forensic.gate_checks.test_quality_checks import (
    run_empty_test_module_checks,
    run_simulated_test_checks,
    run_test_quality_checks,
    run_test_suite_masking_checks,
)
from vigil_forensic.gate_checks.reporting_checks import run_reporting_checks
from vigil_forensic.gate_checks.syntax_validity_checks import run_syntax_validity_checks
from vigil_forensic.gate_checks.provider_capability_checks import check_provider_capabilities
from vigil_forensic.gate_checks.import_integrity_checks import run_import_integrity_checks, run_init_order_regression_checks
from vigil_forensic.gate_checks.boundary_breach_checks import run_boundary_breach_checks
from vigil_forensic.gate_checks.conflict_checks import run_conflict_touch_checks
from vigil_forensic.gate_checks.refactor_completeness_checks import run_refactor_completeness_checks
from vigil_forensic.gate_checks.type_checking_checks import run_type_checking_checks
from vigil_forensic.gate_checks.reliability_checks import run_reliability_checks
from vigil_forensic.gate_checks.security_injection_checks import run_security_injection_checks
from vigil_forensic.gate_checks.config_safety_checks import run_config_safety_checks
from vigil_forensic.gate_checks.implementation_overfit_checks import run_implementation_overfit_checks
from vigil_forensic.gate_checks.stuck_feature_flag_checks import run_stuck_feature_flag_checks
from vigil_forensic.gate_checks.hunter_artifact_completeness_check import run_hunter_artifact_completeness_checks
from vigil_forensic.gate_checks.export_completeness_checks import run_export_completeness_checks
from vigil_forensic.gate_checks.imports_in_function_checks import run_imports_in_function_checks
from vigil_forensic.gate_checks.ml_checks import run_ml_checks
from vigil_forensic.meta_findings import meta_runner_stub
from vigil_forensic._shared import GateCategory

# Gate metadata flags — single source of truth for gate classification.
# FOC gates DROPPED (foc.observability_coverage, foc.secret_logging, foc.duplicate_log).
GATE_FLAGS: dict[str, frozenset[str]] = {
    "handoff":              frozenset({"skip_in_static"}),
    "artifact_completeness": frozenset({"skip_in_static"}),
    "semantic_intent":      frozenset({"skip_in_static"}),
    # forensic_clusters is NOT skip_in_static: the pack runs in static mode but
    # filters out its runtime-only sub-checks (see
    # forensic_cluster_runners.core._RUNTIME_ONLY_CLUSTERS / _is_static_mode), so
    # the static-safe checks (security, secrets, mutable defaults, resource
    # leaks, dead code, hardcoded paths, …) still fire without runtime FPs.
    "forensic_clusters":    frozenset(),
    "pipeline_chain":       frozenset({"skip_in_static"}),
    "testing":              frozenset({"skip_in_static"}),
    "fix_without_test":     frozenset({"skip_in_static"}),
    "truth_boundary":       frozenset({"skip_in_static"}),
    "pe_health":            frozenset({"skip_in_static"}),
    "hallucination":        frozenset({"skip_in_static"}),
    "empty_output":         frozenset({"skip_in_static"}),
    "reporting":            frozenset({"skip_in_static"}),
    "temporal_freshness":   frozenset({"skip_in_static"}),
    "provider_capability":  frozenset({"skip_in_static"}),
    "tool_hook_coverage":   frozenset({"skip_in_static"}),
    "policy_boundary":      frozenset({"skip_in_static"}),
    "draft_boundary":       frozenset({"skip_in_static"}),
    "authority_checks":       frozenset({"requires_git"}),
    "contract_shape_drift":   frozenset({"requires_git"}),
    "init_order_regression":  frozenset({"requires_git"}),
    "stuck_feature_flag":     frozenset(),
    "hunter_artifact_completeness": frozenset({"skip_in_static"}),
    "size_complexity":   frozenset({"agnostic"}),
    "duplication":       frozenset({"agnostic"}),
    "file_proliferation": frozenset({"agnostic"}),
    "syntax_validity":   frozenset({"agnostic"}),
}

GATE_SPECS: tuple[tuple[str, GateCategory, Any], ...] = (
    # broad_except family
    ("broad_except", GateCategory.FALLBACK, run_broad_except_checks),
    ("broad_except.bare", GateCategory.FALLBACK, run_broad_except_checks),
    ("broad_except.base_exception", GateCategory.FALLBACK, run_broad_except_checks),
    ("broad_except.return_none", GateCategory.FALLBACK, run_broad_except_checks),
    ("broad_except.log_swallow", GateCategory.FALLBACK, run_broad_except_checks),
    ("broad_except.hidden_sentinel", GateCategory.CONTRACT, run_broad_except_hidden_sentinel_checks),
    # embedded string
    ("embedded_string", GateCategory.FALLBACK, run_embedded_string_checks),
    # duplication
    ("duplication", GateCategory.DUPLICATION, run_duplication_checks),
    ("file_proliferation", GateCategory.DUPLICATION, run_file_proliferation_checks),
    # testing
    ("fix_without_test", GateCategory.TESTING, run_fix_without_test_checks),
    # reporting
    ("empty_output", GateCategory.REPORTING, run_empty_output_checks),
    # semantic / temporal
    ("semantic_intent", GateCategory.SEMANTIC_INTENT, run_semantic_intent_checks),
    ("temporal_freshness", GateCategory.TEMPORAL_FRESHNESS, run_temporal_freshness_checks),
    # contract
    ("hallucination", GateCategory.CONTRACT, run_hallucination_checks),
    # runtime behavior
    ("encoding_safety", GateCategory.RUNTIME_BEHAVIOR, run_encoding_checks),
    ("subprocess_encoding", GateCategory.RUNTIME_BEHAVIOR, run_subprocess_encoding_checks),
    ("authority_checks", GateCategory.CONTRACT, run_authority_checks),
    ("runtime_duplicate_side_effect", GateCategory.RUNTIME_BEHAVIOR, run_runtime_duplicate_side_effect_checks),
    ("toctou_check_then_act", GateCategory.RUNTIME_BEHAVIOR, run_toctou_check_then_act),
    ("atomic_write_safety", GateCategory.DRIFT, run_atomic_write_safety_checks),
    # Swift safety (AST-precise; runs only on .swift files)
    ("swift.force_unwrap", GateCategory.RUNTIME_BEHAVIOR, run_swift_force_unwrap_checks),
    ("swift.implicitly_unwrapped_optional", GateCategory.RUNTIME_BEHAVIOR, run_swift_iuo_checks),
    ("context_fallback_save", GateCategory.CONTRACT, run_context_fallback_save_checks),
    # drift
    ("contract_shape_drift", GateCategory.DRIFT, run_contract_shape_drift_checks),
    # object zones
    ("god_object_zones", GateCategory.DRIFT, run_god_object_zones_checks),
    # cluster framework runner
    ("forensic_clusters", GateCategory.CONTRACT, run_forensic_cluster_checks),
    # dynamic gate loader
    ("project_specific", GateCategory.CONTRACT, run_project_specific_checks),
    # profile-driven gates
    ("fallback", GateCategory.FALLBACK, run_fallback_checks),
    ("config_ssot", GateCategory.CONFIG_SSOT, run_config_ssot_checks),
    ("performance", GateCategory.PERFORMANCE, run_performance_checks),
    ("size_complexity", GateCategory.SIZE_COMPLEXITY, run_size_complexity_checks),
    ("testing", GateCategory.TESTING, run_testing_checks),
    ("test_quality", GateCategory.TESTING, run_test_quality_checks),
    ("test_suite_masking", GateCategory.TESTING, run_test_suite_masking_checks),
    ("empty_test_module", GateCategory.TESTING, run_empty_test_module_checks),
    ("simulated_instead_of_executed_test", GateCategory.TESTING, run_simulated_test_checks),
    ("reporting", GateCategory.REPORTING, run_reporting_checks),
    ("syntax_validity", GateCategory.REPORTING, run_syntax_validity_checks),
    ("provider_capability", GateCategory.CONTRACT, check_provider_capabilities),
    ("import_integrity", GateCategory.CONTRACT, run_import_integrity_checks),
    ("init_order_regression", GateCategory.CONTRACT, run_init_order_regression_checks),
    ("boundary_breach", GateCategory.CONTRACT, run_boundary_breach_checks),
    ("conflict_touch", GateCategory.CONTRACT, run_conflict_touch_checks),
    ("hotspot_inflation", GateCategory.SIZE_COMPLEXITY, run_hotspot_inflation_checks),
    ("refactor_completeness", GateCategory.DRIFT, run_refactor_completeness_checks),
    ("type_checking", GateCategory.CONTRACT, run_type_checking_checks),
    ("reliability", GateCategory.RUNTIME_BEHAVIOR, run_reliability_checks),
    ("security_injection", GateCategory.CONTRACT, run_security_injection_checks),
    ("config_safety", GateCategory.CONFIG_SSOT, run_config_safety_checks),
    ("implementation_overfit", GateCategory.DRIFT, run_implementation_overfit_checks),
    ("stuck_feature_flag", GateCategory.DRIFT, run_stuck_feature_flag_checks),
    ("hunter_artifact_completeness", GateCategory.META, run_hunter_artifact_completeness_checks),
    ("export_completeness", GateCategory.CONTRACT, run_export_completeness_checks),
    ("imports_in_function", GateCategory.DRIFT, run_imports_in_function_checks),
    ("imports_in_function.stdlib", GateCategory.DRIFT, run_imports_in_function_checks),
    # ML/NN correctness pack (static AST; look-ahead, leakage, seed)
    ("ml_checks", GateCategory.ML, run_ml_checks),
    ("ml.lookahead_negative_shift", GateCategory.ML, run_ml_checks),
    ("ml.nondeterministic_split", GateCategory.ML, run_ml_checks),
    ("ml.scaler_fit_on_test", GateCategory.ML, run_ml_checks),
    ("ml.missing_random_seed", GateCategory.ML, run_ml_checks),
    # meta stubs (FOC gates removed)
    ("meta.syntax_parse_error", GateCategory.META, meta_runner_stub),
    ("meta.profile_load_failed", GateCategory.META, meta_runner_stub),
    ("meta.git_unavailable", GateCategory.META, meta_runner_stub),
    ("meta.artifact_corrupted", GateCategory.META, meta_runner_stub),
    ("meta.artifact_unreadable", GateCategory.META, meta_runner_stub),
    ("meta.file_unreadable", GateCategory.META, meta_runner_stub),
    ("meta.allowlist_corrupted", GateCategory.META, meta_runner_stub),
)
