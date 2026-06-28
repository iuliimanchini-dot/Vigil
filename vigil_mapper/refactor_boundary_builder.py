"""Generic refactor boundary loader -- reads from <project_dir>/.cortex/maps/70_refactor_boundaries.json.

ARCHITECTURE NOTE: Refactor boundaries are generated/loaded in two phases:

1. AUTO-INFERRED BOUNDARIES (computed during map build):
   - source: `.cortex/maps/70_refactor_boundaries.json`
   - phase: "planning"
   - recomputed on every build (Phase 4 will add auto-inference logic)
   - include: SCC clusters, hotspot-scored files, canonical owners

2. MANUAL SEED BOUNDARIES (user-authored, override auto-inferred):
   - source: `.cortex/map_seeds/refactor_boundaries.json`
   - phase: "seed" or higher (user-defined)
   - override auto-inferred entries for same allowed_files/forbidden_files
   - auto-inferred entries for files without seed are still included

LOADER BEHAVIOR:
- This module loads GENERATED boundaries from maps/70_refactor_boundaries.json
- Seed loading handled separately by main builder orchestrator
- merge strategy: seed entries + auto-inferred entries (seed wins on conflicts)
- If file missing: return empty list (not an error)

Design: generic, works on any project via project_dir parameter.
"""
from __future__ import annotations

import json
import logging
from pathlib import Path

from .map_errors import MapIntegrityError
from .map_models_ext import RefactorBoundary

__all__ = [
    "load_refactor_seeds",
    "infer_refactor_boundaries",
]

_log = logging.getLogger(__name__)


def infer_refactor_boundaries(repo_maps) -> list[RefactorBoundary]:
    """Auto-infer refactor boundaries from conflict/hotspot/authority maps.

    Algorithm:
    1. Group conflicts by SCC cluster → boundary candidates
    2. Hotspot scores: safe_refactor (score < 30), caution (30-60), do_not_touch (>= 60)
    3. Authority: canonical_owner matching domain
    4. Union-find: merge clusters with overlapping files
    5. Emit RefactorBoundary per cluster
    """
    import hashlib

    boundaries: list[RefactorBoundary] = []

    # Build hotspot index: file -> score + recommended_mode
    hotspot_by_file: dict[str, dict] = {}
    for h in repo_maps.hotspot:
        target = getattr(h, "target", "")
        score = getattr(h, "hotspot_score", 0)
        mode = "do_not_touch" if score >= 60 else ("caution" if score >= 30 else "safe_refactor")
        hotspot_by_file[target] = {
            "score": score,
            "mode": mode,
        }

    # Build authority index: domain -> canonical_owner
    authority_by_domain: dict[str, str] = {}
    for auth in repo_maps.authority:
        domain = getattr(auth, "authority_domain", "")
        owner = getattr(auth, "canonical_owner", "")
        if domain:
            authority_by_domain[domain] = owner

    # Cluster candidates from conflict map (SCC clusters)
    clusters: list[dict] = []
    seen_files: set[str] = set()

    for conflict in repo_maps.conflict:
        domain = getattr(conflict, "domain", "")
        if domain != "structural_cycles":
            continue

        # Parse sources to collect SCC member files
        sources_parsed: list[dict] = []
        sources_raw = getattr(conflict, "sources", [])
        for src_raw in sources_raw:
            try:
                src = json.loads(src_raw) if isinstance(src_raw, str) else src_raw
                if isinstance(src, dict):
                    sources_parsed.append(src)
            except (json.JSONDecodeError, TypeError):
                pass

        scc_files = [s.get("file", "") for s in sources_parsed if s.get("file")]

        # Skip if already clustered
        if any(f in seen_files for f in scc_files):
            continue

        # Add new cluster
        if scc_files:
            clusters.append({
                "files": scc_files,
                "conflict": conflict,
                "sources": sources_parsed,
            })
            seen_files.update(scc_files)

    # Classify files by hotspot mode
    def classify_file(f: str) -> str:
        hs = hotspot_by_file.get(f, {})
        return hs.get("mode", "unknown")

    # Build boundaries
    for cluster in clusters:
        scc_files = cluster["files"]
        conflict = cluster["conflict"]
        sources = cluster["sources"]

        # Partition by hotspot mode
        safe_files = [f for f in scc_files if classify_file(f) == "safe_refactor"]
        caution_files = [f for f in scc_files if classify_file(f) == "caution"]
        forbidden_files = [f for f in scc_files if classify_file(f) == "do_not_touch"]

        # Extract canonical owners (entrypoints) from authority
        entrypoints: set[str] = set()
        conflict_domain = getattr(conflict, "domain", "")
        # Remove "structural_cycles" suffix if present to get domain name
        domain_name = conflict_domain.replace("_cycles", "") if conflict_domain.endswith("_cycles") else conflict_domain

        if domain_name in authority_by_domain:
            owner = authority_by_domain[domain_name]
            if owner:
                entrypoints.add(owner)

        # Generate stable ID
        cluster_id = hashlib.sha256(
            ",".join(sorted(scc_files)).encode("utf-8")
        ).hexdigest()[:8]

        max_fan_in = max((s.get("cluster_max_fan_in", 0) for s in sources), default=0)
        boundary = RefactorBoundary(
            boundary_id=f"auto_{cluster_id}",
            goal=f"Decouple import cycle in cluster ({len(scc_files)} files, max fan_in={max_fan_in})",
            phase="planning",
            allowed_files=tuple(safe_files + caution_files),  # Safe + caution can be refactored
            watch_files=(),
            forbidden_files=tuple(forbidden_files),            # Do-not-touch files
            entrypoints=tuple(entrypoints),
            must_hold_invariants=(),
            source="auto_inferred",
            evidence=(),
            confidence=0.75,
            freshness="inferred",
            status="inferred",
        )
        boundaries.append(boundary)

    _log.info(
        "infer_refactor_boundaries: inferred %d boundaries from %d SCC clusters",
        len(boundaries), len(clusters),
    )
    return boundaries


def load_refactor_seeds(project_dir: Path) -> list[RefactorBoundary]:
    """Load USER-AUTHORED manual seed boundaries from <project_dir>/.cortex/map_seeds/refactor_boundaries.json.

    Manual seeds are persistent, user-authored refactor boundaries that override
    auto-inferred boundaries for the same file sets. This function reads from the
    seed directory (persistent, under version control). Auto-inferred boundaries
    are computed separately and merged afterward.

    IMPORTANT: This loads SEEDS only, not generated output. For generated output,
    use infer_refactor_boundaries() which computes boundaries at build time.

    Args:
        project_dir: Absolute path to the target project root.

    Returns:
        list[RefactorBoundary]: Boundaries from the seed file, or [] if missing.

    Raises:
        MapIntegrityError: If JSON is corrupt, schema is invalid, or major version mismatch.
    """
    project_dir = Path(project_dir).resolve()
    seeds_dir = project_dir / ".cortex" / "map_seeds"
    boundaries_path = seeds_dir / "refactor_boundaries.json"

    # Missing file — log and return empty
    if not boundaries_path.exists():
        _log.info(
            "load_refactor_boundaries: no boundaries file at %s -- returning empty",
            boundaries_path,
        )
        return []

    # Read JSON
    try:
        import json
        content = boundaries_path.read_text(encoding="utf-8")
        payload = json.loads(content)
    except (OSError, json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise MapIntegrityError(
            f"Failed to read/parse {boundaries_path}: {exc}"
        ) from exc

    # Validate structure
    if not isinstance(payload, dict):
        raise MapIntegrityError(
            f"Expected JSON object at root, got {type(payload).__name__}"
        )

    # Check schema_version
    schema_version_raw = payload.get("schema_version")
    if schema_version_raw is None:
        raise MapIntegrityError("Missing required field: schema_version")

    schema_version_str = str(schema_version_raw)
    major_version_str = schema_version_str.split(".")[0] if "." in schema_version_str else schema_version_str
    try:
        major_version = int(major_version_str)
    except ValueError:
        raise MapIntegrityError(
            f"Invalid schema_version format: {schema_version_str}"
        ) from None

    if major_version > 1:
        raise MapIntegrityError(
            f"Major version {major_version} > 1 -- incompatible schema"
        )

    # Parse entries
    entries_raw = payload.get("entries", [])
    if not isinstance(entries_raw, list):
        raise MapIntegrityError(
            f"Expected 'entries' to be a list, got {type(entries_raw).__name__}"
        )

    boundaries: list[RefactorBoundary] = []
    for i, raw_entry in enumerate(entries_raw):
        if not isinstance(raw_entry, dict):
            _log.warning(
                "load_refactor_boundaries: skipping entry %d (not a dict, got %s)",
                i, type(raw_entry).__name__,
            )
            continue
        try:
            boundary = RefactorBoundary.from_dict(raw_entry)
            boundaries.append(boundary)
        except (KeyError, TypeError, ValueError) as exc:
            _log.warning(
                "load_refactor_boundaries: skipping entry %d: %s",
                i, exc,
            )

    _log.info(
        "load_refactor_seeds: loaded %d boundaries from %s",
        len(boundaries), boundaries_path,
    )
    return boundaries


# Backward compatibility alias (deprecated, use load_refactor_seeds)
load_refactor_boundaries = load_refactor_seeds
