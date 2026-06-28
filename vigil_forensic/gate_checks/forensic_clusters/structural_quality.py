"""C52: Shared Logic Fragmentation / Duplicate Module Proliferation.

Four patterns detected on the touched-file set:
  P1 — Abstraction Bypass: new shared-family file that doesn't import the canonical
  P2 — Provider Parallel Flow: 2+ provider files share flow markers without a common base
  P3 — Responsibility Family Proliferation: 3+ touched files share (dir, responsibility_suffix)
  P4 — Generic Shared Fork: new generic-stem file has a same-stem sibling it ignores
"""
from __future__ import annotations

import os
import re
from pathlib import Path

from ...gate_models import EvidenceReference, GateCategory, GateImpact, GateSeverity, GateFileSnapshot, RepairKind
from ..common import build_finding, normalize_path
import logging
_log = logging.getLogger(__name__)

# Suffixes suggesting "provider-like" roles
_PROVIDER_SUFFIXES = frozenset({
    "_provider", "_adapter", "_service", "_client", "_backend", "_engine",
})

# Responsibility suffixes that should stay consolidated, not proliferated
_RESPONSIBILITY_SUFFIXES = frozenset({
    "_checks", "_check", "_utils", "_helpers", "_handlers",
    "_runners", "_providers", "_adapters", "_validators",
})


def _stem(path: str) -> str:
    """Filename without extension, lowercased."""
    basename = os.path.basename(path)
    return basename.rsplit(".", 1)[0].lower() if "." in basename else basename.lower()


def _parent_dir(path: str) -> str:
    return os.path.dirname(normalize_path(path))


def _has_import_from(text: str, module_stem: str) -> bool:
    """True if *text* contains an import statement referencing *module_stem*."""
    pattern = re.compile(
        r"(?:from|import)\s+[\w.]*\b" + re.escape(module_stem) + r"\b",
        re.MULTILINE,
    )
    return bool(pattern.search(text))


def _flow_markers_found(text: str, patterns: tuple[str, ...]) -> frozenset[str]:
    """Return the subset of flow marker regex patterns that match *text*."""
    found: set[str] = set()
    for pat in patterns:
        try:
            if re.search(pat, text, re.MULTILINE):
                found.add(pat)
        except re.error:
            pass
    return frozenset(found)


def assess_shared_logic_fragmentation(
    snapshots: dict[str, GateFileSnapshot],
    *,
    project_dir: Path,
    source_package_roots: tuple[str, ...],
) -> list:
    findings: list = []
    findings.extend(_pattern1_abstraction_bypass(snapshots, project_dir, source_package_roots))
    findings.extend(_pattern2_provider_parallel_flow(snapshots))
    findings.extend(_pattern3_responsibility_proliferation(snapshots))
    findings.extend(_pattern4_generic_shared_fork(snapshots, project_dir, source_package_roots))
    return findings


# ---------------------------------------------------------------------------
# P1 — Abstraction Bypass
# ---------------------------------------------------------------------------

def _pattern1_abstraction_bypass(
    snapshots: dict[str, GateFileSnapshot],
    project_dir: Path,
    source_package_roots: tuple[str, ...],
) -> list:
    from ...source_analysis import get_shared_families
    findings = []
    for path, snap in snapshots.items():
        if not snap.exists or not snap.text.strip():
            continue
        file_stem = _stem(path)
        families = get_shared_families(path)
        if file_stem not in families:
            continue
        # Look for a canonical file with the same stem in any package root
        canonical_candidates: list[str] = []
        for root_name in source_package_roots:
            root = project_dir / root_name
            if not root.is_dir():
                continue
            for existing in root.rglob(f"*{file_stem}*"):
                if not existing.is_file():
                    continue
                rel = str(existing.relative_to(project_dir)).replace("\\", "/")
                if normalize_path(rel) == normalize_path(path):
                    continue
                if _stem(rel) == file_stem:
                    canonical_candidates.append(rel)
        if not canonical_candidates:
            continue
        canonical = canonical_candidates[0]
        if not _has_import_from(snap.text, file_stem):
            findings.append(build_finding(
                check_id="c52.abstraction_bypass",
                category=GateCategory.DUPLICATION,
                title=f"Shared-family file {path!r} ignores canonical {canonical!r}",
                severity=GateSeverity.MEDIUM,
                impact=GateImpact.REVISE,
                summary=(
                    f"{path} has stem {file_stem!r} (shared family) but does not import "
                    f"from the existing canonical {canonical}. "
                    "Logic likely duplicated rather than extended."
                ),
                recommendation=f"Import from {canonical} and extend it instead of creating a parallel copy.",
                evidence=[
                    EvidenceReference(kind="file", path=path, detail="new"),
                    EvidenceReference(kind="file", path=canonical, detail="canonical"),
                ],
                repair_kind=RepairKind.EDIT_CANONICAL.value,
                executor_action=f"Import from {canonical} in {path}; merge any new logic there instead",
                proof_required="new file imports canonical; no duplicate logic",
                allowlist_allowed=False,
            ))
    return findings


# ---------------------------------------------------------------------------
# P2 — Provider Parallel Flow
# ---------------------------------------------------------------------------

def _pattern2_provider_parallel_flow(snapshots: dict[str, GateFileSnapshot]) -> list:
    from ...source_analysis import get_flow_markers
    findings = []
    provider_files = [
        (path, snap)
        for path, snap in snapshots.items()
        if snap.exists and any(path.replace("\\", "/").endswith(suf + ext)
                               for suf in _PROVIDER_SUFFIXES
                               for ext in (".py", ".ts", ".js"))
    ]
    if len(provider_files) < 2:
        return findings
    # Compare each pair
    seen: set[tuple[str, str]] = set()
    for i, (path_a, snap_a) in enumerate(provider_files):
        markers_a = get_flow_markers(path_a)
        found_a = _flow_markers_found(snap_a.text, markers_a)
        for path_b, snap_b in provider_files[i + 1:]:
            pair = (min(path_a, path_b), max(path_a, path_b))
            if pair in seen:
                continue
            seen.add(pair)
            markers_b = get_flow_markers(path_b)
            found_b = _flow_markers_found(snap_b.text, markers_b)
            shared = found_a & found_b
            if len(shared) < 3:
                continue
            if _has_import_from(snap_a.text, _stem(path_b)) or _has_import_from(snap_b.text, _stem(path_a)):
                continue  # already connected
            findings.append(build_finding(
                check_id="c52.provider_parallel_flow",
                category=GateCategory.DUPLICATION,
                title=f"Provider files share {len(shared)} flow steps without a common base",
                severity=GateSeverity.MEDIUM,
                impact=GateImpact.REVISE,
                summary=(
                    f"{path_a} and {path_b} both implement {len(shared)} shared flow steps "
                    f"with no common imported base. Extract the shared flow into a base class or mixin."
                ),
                recommendation=(
                    "Extract the shared flow steps into a common base module. "
                    "Both providers should import from it."
                ),
                evidence=[
                    EvidenceReference(kind="file", path=path_a),
                    EvidenceReference(kind="file", path=path_b),
                ],
                repair_kind=RepairKind.EXTRACT_SHARED.value,
                executor_action=f"Extract shared flow steps from {path_a} and {path_b} into a common base; both import it",
                proof_required="shared base exists; both providers import it; tests pass",
            ))
    return findings


# ---------------------------------------------------------------------------
# P3 — Responsibility Family Proliferation
# ---------------------------------------------------------------------------

def _pattern3_responsibility_proliferation(snapshots: dict[str, GateFileSnapshot]) -> list:
    findings = []
    groups: dict[tuple[str, str], list[str]] = {}
    for path in snapshots:
        if not snapshots[path].exists:
            continue
        file_stem = _stem(path)
        parent = _parent_dir(path)
        for suf in _RESPONSIBILITY_SUFFIXES:
            if file_stem.endswith(suf):
                groups.setdefault((parent, suf), []).append(path)
                break
    for (parent, suf), paths in groups.items():
        if len(paths) < 3:
            continue
        findings.append(build_finding(
            check_id="c52.responsibility_proliferation",
            category=GateCategory.DUPLICATION,
            title=f"{len(paths)} {suf!r}-suffixed files in {parent or '.'!r}",
            severity=GateSeverity.MEDIUM,
            impact=GateImpact.REVISE,
            summary=(
                f"{len(paths)} files with suffix {suf!r} in {parent or '.'!r}: "
                f"{', '.join(sorted(paths)[:5])}. "
                "This many responsibility-scoped files in one directory suggests fragmentation."
            ),
            recommendation=(
                f"Consider consolidating {suf}-suffixed logic into fewer modules. "
                "If the separation is intentional, document the boundary clearly."
            ),
            evidence=[EvidenceReference(kind="file", path=p) for p in sorted(paths)[:5]],
            repair_kind=RepairKind.CONSOLIDATE.value,
            executor_action=f"Consolidate {len(paths)} {suf!r} files in {parent or '.'}; merge related logic into fewer modules",
        ))
    return findings


# ---------------------------------------------------------------------------
# P4 — Generic Shared Fork
# ---------------------------------------------------------------------------

def _pattern4_generic_shared_fork(
    snapshots: dict[str, GateFileSnapshot],
    project_dir: Path,
    source_package_roots: tuple[str, ...],
) -> list:
    from ...source_analysis import get_generic_stems
    findings = []
    for path, snap in snapshots.items():
        if not snap.exists or not snap.text.strip():
            continue
        file_stem = _stem(path)
        stems = get_generic_stems(path)
        if file_stem not in stems:
            continue
        # Look for siblings with the same stem in different dirs
        siblings: list[str] = []
        for root_name in source_package_roots:
            root = project_dir / root_name
            if not root.is_dir():
                continue
            for existing in root.rglob(f"{file_stem}.*"):
                if not existing.is_file():
                    continue
                rel = str(existing.relative_to(project_dir)).replace("\\", "/")
                if normalize_path(rel) == normalize_path(path):
                    continue
                if _stem(rel) == file_stem and _parent_dir(rel) != _parent_dir(path):
                    siblings.append(rel)
        if not siblings:
            continue
        # Check for non-trivial code overlap via length comparison (heuristic)
        try:
            sib_text = (project_dir / siblings[0]).read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        min_len = min(len(snap.text), len(sib_text))
        if min_len < 200:
            continue  # too small to flag
        findings.append(build_finding(
            check_id="c52.generic_shared_fork",
            category=GateCategory.DUPLICATION,
            title=f"Generic-stem file {path!r} forks {siblings[0]!r}",
            severity=GateSeverity.MEDIUM,
            impact=GateImpact.REVISE,
            summary=(
                f"Touched file {path} has generic stem {file_stem!r} and a same-stem sibling "
                f"at {siblings[0]}. If they serve the same purpose, merge into one canonical module."
            ),
            recommendation=f"Verify {path} vs {siblings[0]}. If same purpose — consolidate; if different purpose — rename to be semantically distinct.",
            evidence=[
                EvidenceReference(kind="file", path=path, detail="new"),
                EvidenceReference(kind="file", path=siblings[0], detail="sibling"),
            ],
            repair_kind=RepairKind.EDIT_CANONICAL.value,
            executor_action=f"Merge {path} into {siblings[0]} or rename {path} with a specific semantic name",
            proof_required="single canonical generic module; or both have distinct semantic names",
            allowlist_allowed=False,
        ))
    return findings
