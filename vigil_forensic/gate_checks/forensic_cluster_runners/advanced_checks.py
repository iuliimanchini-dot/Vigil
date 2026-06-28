"""Advanced cluster wrappers -- clusters 32-50, 53.

Covers: hardcoded paths, boundary validation, unreachable code, shadowed
builtins, mutable defaults, resource leaks, docstring drift, broad catch,
debug prints, commented code, missing await, unchecked response, naive
timezone, near-duplicate code, missing null check, path concatenation,
log without context, test secrets, unpinned dependencies,
legacy compatibility debt (C53).
"""
from __future__ import annotations

from ...source_analysis import is_source_file, is_test_file, get_language_id
from ...gate_models import GateFinding, PostExecGateContext
from ..forensic_clusters import (
    assess_boundary_validation,
    assess_broad_catch_no_reraise,
    assess_commented_code,
    assess_debug_prints,
    assess_docstring_params,
    assess_hardcoded_paths,
    assess_log_without_context,
    assess_missing_await,
    assess_missing_null_check,
    assess_mutable_defaults,
    assess_naive_timezone,
    assess_near_duplicate_code,
    assess_path_concatenation,
    assess_resource_leaks,
    assess_shadowed_builtins,
    assess_test_secrets,
    assess_unchecked_response,
    assess_unpinned_dependencies,
    assess_unreachable_code,
)
from ._helpers import _MAX_FINDINGS_PER_CLUSTER
import logging
_log = logging.getLogger(__name__)


def _check_hardcoded_paths(ctx) -> list[GateFinding]:
    snapshots = ctx.file_snapshots or {}
    findings: list[GateFinding] = []
    for path, snap in snapshots.items():
        if not hasattr(snap, "text") or not snap.text:
            continue
        findings.extend(assess_hardcoded_paths(path, snap.text))
        if len(findings) >= _MAX_FINDINGS_PER_CLUSTER:
            break
    return findings


def _check_boundary_validation(ctx) -> list[GateFinding]:
    snapshots = ctx.file_snapshots or {}
    findings: list[GateFinding] = []
    for path, snap in snapshots.items():
        if not is_source_file(path) or not hasattr(snap, "text") or not snap.text:
            continue
        findings.extend(assess_boundary_validation(path, snap.text))
        if len(findings) >= _MAX_FINDINGS_PER_CLUSTER:
            break
    return findings


def _check_unreachable_code(ctx) -> list[GateFinding]:
    snapshots = ctx.file_snapshots or {}
    findings: list[GateFinding] = []
    for path, snap in snapshots.items():
        if not hasattr(snap, "text") or not snap.text:
            continue
        findings.extend(assess_unreachable_code(path, snap.text))
        if len(findings) >= _MAX_FINDINGS_PER_CLUSTER:
            break
    return findings


def _check_shadowed_builtins(ctx) -> list[GateFinding]:
    snapshots = ctx.file_snapshots or {}
    findings: list[GateFinding] = []
    for path, snap in snapshots.items():
        if not hasattr(snap, "text") or not snap.text:
            continue
        findings.extend(assess_shadowed_builtins(path, snap.text))
        if len(findings) >= _MAX_FINDINGS_PER_CLUSTER:
            break
    return findings


def _check_mutable_defaults(ctx) -> list[GateFinding]:
    snapshots = ctx.file_snapshots or {}
    findings: list[GateFinding] = []
    for path, snap in snapshots.items():
        if not hasattr(snap, "text") or not snap.text:
            continue
        findings.extend(assess_mutable_defaults(path, snap.text))
        if len(findings) >= _MAX_FINDINGS_PER_CLUSTER:
            break
    return findings


def _check_resource_leaks(ctx) -> list[GateFinding]:
    snapshots = ctx.file_snapshots or {}
    findings: list[GateFinding] = []
    for path, snap in snapshots.items():
        if not hasattr(snap, "text") or not snap.text:
            continue
        findings.extend(assess_resource_leaks(path, snap.text))
        if len(findings) >= _MAX_FINDINGS_PER_CLUSTER:
            break
    return findings


def _check_docstring_params(ctx) -> list[GateFinding]:
    snapshots = ctx.file_snapshots or {}
    findings: list[GateFinding] = []
    for path, snap in snapshots.items():
        if not hasattr(snap, "text") or not snap.text:
            continue
        findings.extend(assess_docstring_params(path, snap.text))
        if len(findings) >= _MAX_FINDINGS_PER_CLUSTER:
            break
    return findings


def _check_broad_catch_no_reraise(ctx) -> list[GateFinding]:
    snapshots = ctx.file_snapshots or {}
    findings: list[GateFinding] = []
    for path, snap in snapshots.items():
        if not is_source_file(path) or not hasattr(snap, "text") or not snap.text:
            continue
        findings.extend(assess_broad_catch_no_reraise(path, snap.text))
        if len(findings) >= _MAX_FINDINGS_PER_CLUSTER:
            break
    return findings


def _check_debug_prints(ctx) -> list[GateFinding]:
    snapshots = ctx.file_snapshots or {}
    findings: list[GateFinding] = []
    for path, snap in snapshots.items():
        if not hasattr(snap, "text") or not snap.text:
            continue
        findings.extend(assess_debug_prints(path, snap.text))
        if len(findings) >= _MAX_FINDINGS_PER_CLUSTER:
            break
    return findings


def _check_commented_code(ctx) -> list[GateFinding]:
    snapshots = ctx.file_snapshots or {}
    findings: list[GateFinding] = []
    for path, snap in snapshots.items():
        if not hasattr(snap, "text") or not snap.text:
            continue
        findings.extend(assess_commented_code(path, snap.text))
        if len(findings) >= _MAX_FINDINGS_PER_CLUSTER:
            break
    return findings


def _check_missing_await(ctx) -> list[GateFinding]:
    snapshots = ctx.file_snapshots or {}
    findings: list[GateFinding] = []
    for path, snap in snapshots.items():
        if not hasattr(snap, "text") or not snap.text:
            continue
        findings.extend(assess_missing_await(path, snap.text))
        if len(findings) >= _MAX_FINDINGS_PER_CLUSTER:
            break
    return findings


def _check_unchecked_response(ctx) -> list[GateFinding]:
    snapshots = ctx.file_snapshots or {}
    findings: list[GateFinding] = []
    for path, snap in snapshots.items():
        if not hasattr(snap, "text") or not snap.text:
            continue
        findings.extend(assess_unchecked_response(path, snap.text))
        if len(findings) >= _MAX_FINDINGS_PER_CLUSTER:
            break
    return findings


def _check_naive_timezone(ctx) -> list[GateFinding]:
    snapshots = ctx.file_snapshots or {}
    findings: list[GateFinding] = []
    for path, snap in snapshots.items():
        if not hasattr(snap, "text") or not snap.text:
            continue
        findings.extend(assess_naive_timezone(path, snap.text))
        if len(findings) >= _MAX_FINDINGS_PER_CLUSTER:
            break
    return findings


def _check_near_duplicate_code(ctx) -> list[GateFinding]:
    snapshots = ctx.file_snapshots or {}
    findings: list[GateFinding] = []
    for path, snap in snapshots.items():
        if not hasattr(snap, "text") or not snap.text:
            continue
        findings.extend(assess_near_duplicate_code(path, snap.text))
        if len(findings) >= _MAX_FINDINGS_PER_CLUSTER:
            break
    return findings


def _check_missing_null_check(ctx) -> list[GateFinding]:
    snapshots = ctx.file_snapshots or {}
    findings: list[GateFinding] = []
    for path, snap in snapshots.items():
        if not hasattr(snap, "text") or not snap.text:
            continue
        findings.extend(assess_missing_null_check(path, snap.text))
        if len(findings) >= _MAX_FINDINGS_PER_CLUSTER:
            break
    return findings


def _check_path_concatenation(ctx) -> list[GateFinding]:
    snapshots = ctx.file_snapshots or {}
    findings: list[GateFinding] = []
    for path, snap in snapshots.items():
        if not hasattr(snap, "text") or not snap.text:
            continue
        findings.extend(assess_path_concatenation(path, snap.text))
        if len(findings) >= _MAX_FINDINGS_PER_CLUSTER:
            break
    return findings


def _check_log_without_context(ctx) -> list[GateFinding]:
    snapshots = ctx.file_snapshots or {}
    findings: list[GateFinding] = []
    for path, snap in snapshots.items():
        if not hasattr(snap, "text") or not snap.text:
            continue
        findings.extend(assess_log_without_context(path, snap.text))
        if len(findings) >= _MAX_FINDINGS_PER_CLUSTER:
            break
    return findings


def _check_test_secrets(ctx) -> list[GateFinding]:
    snapshots = ctx.file_snapshots or {}
    findings: list[GateFinding] = []
    for path, snap in snapshots.items():
        if not hasattr(snap, "text") or not snap.text:
            continue
        findings.extend(assess_test_secrets(path, snap.text))
        if len(findings) >= _MAX_FINDINGS_PER_CLUSTER:
            break
    return findings


def _check_unpinned_dependencies(ctx) -> list[GateFinding]:
    snapshots = ctx.file_snapshots or {}
    findings: list[GateFinding] = []
    for path, snap in snapshots.items():
        if not hasattr(snap, "text") or not snap.text:
            continue
        findings.extend(assess_unpinned_dependencies(path, snap.text))
        if len(findings) >= _MAX_FINDINGS_PER_CLUSTER:
            break
    return findings


# ---------------------------------------------------------------------------
# Cluster 53: Legacy Compatibility Debt
# ---------------------------------------------------------------------------


def _check_legacy_compat_debt(ctx) -> list[GateFinding]:
    """C53: Detect forwarding wrappers, unused shims, stale markers, dead adapters."""
    snapshots = ctx.file_snapshots or {}
    if not snapshots:
        return []
    from ...gate_checks.forensic_clusters.legacy_debt import (
        check_forwarding_wrapper,
        check_unused_shim_module,
        check_stale_migration_marker,
        check_shape_adapter_without_producer,
    )
    all_content = {
        path: snap.text
        for path, snap in snapshots.items()
        if hasattr(snap, "text") and snap.text
    }
    findings: list[GateFinding] = []
    for path, content in all_content.items():
        findings.extend(check_forwarding_wrapper(path, content))
        findings.extend(check_unused_shim_module(path, content, all_content))
        findings.extend(check_stale_migration_marker(path, content))
        findings.extend(check_shape_adapter_without_producer(path, content, all_content))
        if len(findings) >= _MAX_FINDINGS_PER_CLUSTER:
            break
    return findings


# ---------------------------------------------------------------------------
# Cluster 52: Shared Logic Fragmentation
# ---------------------------------------------------------------------------


def _check_shared_logic_fragmentation(ctx) -> list[GateFinding]:
    """C52: Detect duplicate module proliferation and abstraction bypass."""
    snapshots = ctx.file_snapshots or {}
    if not snapshots:
        return []
    from ...gate_checks.forensic_clusters.structural_quality import assess_shared_logic_fragmentation
    return assess_shared_logic_fragmentation(
        snapshots,
        project_dir=ctx.project_dir,
        source_package_roots=ctx.source_package_roots,
    )
