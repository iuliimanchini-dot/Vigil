"""forensic_clusters package -- public API.

Sub-modules:
  core              -- types, language detection, clusters 1-9
  edit_mutation     -- clusters 10-17
  dead_code         -- clusters 20, 23
  code_style        -- clusters 21, 22, 24, 25, 26, 28, 29 + allowlist
  api_protocol      -- clusters 27, 28b, 29b, 30
  exception_boundary -- clusters 31, 32, 33
  static_analysis   -- clusters 34-38
  async_quality     -- clusters 39-43
  data_quality      -- clusters 44-50
  legacy_debt       -- cluster 53: legacy compatibility debt
"""
from __future__ import annotations

# -- core --
from .core import (
    CapabilityDeclaration,
    ProofRequirement,
    ProbeResult,
    detect_language,
    assess_declared_capabilities,
    assess_success_proof,
    assess_source_truthfulness,
    assess_config_applied,
    assess_rendered_vs_live,
    assess_state_consistency,
    assess_fallback_transparency,
    assess_surface_reachability,
    assess_phantom_capability,
)

# -- edit_mutation --
from .edit_mutation import (
    assess_edit_consistency,
    assess_mutation_verified,
    assess_security_patterns,
    assess_test_quality,
    assess_import_cycles,
    assess_roundtrip_consistency,
    assess_shared_mutable_state,
    assess_dependency_vulnerabilities,
)

# -- dead_code --
from .dead_code import (
    DeadCodeItem,
    assess_dead_code,
    classify_dead_code_item,
    assess_unused_imports,
)

# -- code_style --
from .code_style import (
    assess_secrets_in_code,
    assess_magic_numbers,
    assess_error_message_quality,
    assess_naming_consistency,
    assess_todo_debt,
    assess_log_level_quality,
    assess_encoding_consistency,
)

# -- allowlist --
from .allowlist import (
    AllowlistEntry,
    load_allowlist,
    revalidate_allowlist,
    save_allowlist,
    filter_by_allowlist,
)

# -- api_protocol --
from .api_protocol import (
    assess_embedded_code_syntax,
    assess_response_shape_drift,
    assess_http_method_consistency,
    assess_js_surface_coverage,
)

# -- exception_boundary --
from .exception_boundary import (
    assess_exception_swallowing,
    assess_hardcoded_paths,
    assess_boundary_validation,
)

# -- static_analysis --
from .static_analysis import (
    assess_unreachable_code,
    assess_shadowed_builtins,
    assess_mutable_defaults,
    assess_resource_leaks,
    assess_docstring_params,
)

# -- async_quality --
from .async_quality import (
    assess_broad_catch_no_reraise,
    assess_debug_prints,
    assess_commented_code,
    assess_missing_await,
    assess_unchecked_response,
)

# -- data_quality --
from .data_quality import (
    assess_naive_timezone,
    assess_near_duplicate_code,
    assess_missing_null_check,
    assess_path_concatenation,
    assess_log_without_context,
    assess_test_secrets,
    assess_unpinned_dependencies,
)

# -- legacy_debt (C53) --
from .legacy_debt import (
    check_forwarding_wrapper,
    check_unused_shim_module,
    check_stale_migration_marker,
    check_shape_adapter_without_producer,
)

__all__ = [
    # core types
    "CapabilityDeclaration",
    "ProofRequirement",
    "ProbeResult",
    "DeadCodeItem",
    "AllowlistEntry",
    # utility
    "detect_language",
    # allowlist
    "load_allowlist",
    "revalidate_allowlist",
    "save_allowlist",
    "filter_by_allowlist",
    # assess functions — integrity clusters 1-9
    "assess_declared_capabilities",
    "assess_success_proof",
    "assess_source_truthfulness",
    "assess_config_applied",
    "assess_rendered_vs_live",
    "assess_state_consistency",
    "assess_fallback_transparency",
    "assess_surface_reachability",
    "assess_phantom_capability",
    # assess functions — edit/mutation/static clusters 10-17
    "assess_edit_consistency",
    "assess_mutation_verified",
    "assess_security_patterns",
    "assess_test_quality",
    "assess_import_cycles",
    "assess_roundtrip_consistency",
    "assess_shared_mutable_state",
    "assess_dependency_vulnerabilities",
    # assess functions — dead code / unused imports 20, 23
    "assess_dead_code",
    "classify_dead_code_item",
    "assess_unused_imports",
    # assess functions — code style 21, 22, 24, 25, 26, 28, 29
    "assess_secrets_in_code",
    "assess_magic_numbers",
    "assess_error_message_quality",
    "assess_naming_consistency",
    "assess_todo_debt",
    "assess_log_level_quality",
    "assess_encoding_consistency",
    # assess functions — api protocol 27, 28b, 29b, 30
    "assess_embedded_code_syntax",
    "assess_response_shape_drift",
    "assess_http_method_consistency",
    "assess_js_surface_coverage",
    # assess functions — exception/boundary 31-33
    "assess_exception_swallowing",
    "assess_hardcoded_paths",
    "assess_boundary_validation",
    # assess functions — static analysis 34-38
    "assess_unreachable_code",
    "assess_shadowed_builtins",
    "assess_mutable_defaults",
    "assess_resource_leaks",
    "assess_docstring_params",
    # assess functions — async quality 39-43
    "assess_broad_catch_no_reraise",
    "assess_debug_prints",
    "assess_commented_code",
    "assess_missing_await",
    "assess_unchecked_response",
    # assess functions — data quality 44-50
    "assess_naive_timezone",
    "assess_near_duplicate_code",
    "assess_missing_null_check",
    "assess_path_concatenation",
    "assess_log_without_context",
    "assess_test_secrets",
    "assess_unpinned_dependencies",
    # assess functions — legacy compatibility debt C53
    "check_forwarding_wrapper",
    "check_unused_shim_module",
    "check_stale_migration_marker",
    "check_shape_adapter_without_producer",
]
