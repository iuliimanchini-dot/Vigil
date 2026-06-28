"""Conflict map builder -- Map 5.

Performs pairwise diff between authority, runtime, structural and contract maps
from an existing RepoMaps container to detect inter-map conflicts.

Generic: operates on any RepoMaps, does not assume Vigil project layout.

Public API:
    build_conflict_map(repo_maps, previous_conflicts=()) -> list[ConflictEntry]
"""
from __future__ import annotations

import json
import logging
from collections.abc import Sequence
from datetime import datetime, timezone

from .fingerprint import make_conflict_id
from .map_common import classify_file_role
from .map_errors import MapBuildConflictBudgetExceeded
from .map_models import AuthorityDomain, DataContractEntry, RepoMaps, StructuralEntry
from .map_models_ext import ConflictEntry

__all__ = ["build_conflict_map"]

_log = logging.getLogger(__name__)

# Maximum number of open conflicts allowed before budget raise.
_CONFLICT_BUDGET = 500

# Metadata constants for all generated entries.
_SOURCE = "inter_map_diff"
_CONFIDENCE = 0.9


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _normalize_writer(raw: "str | dict") -> dict:
    """Normalise a writer entry to a dict with a populated 'file' key.

    Handles:
      - dict passed directly (already parsed)
      - JSON-serialised string (from AuthorityDomain.writers_detected storage)
      - plain string (treated as a file path)

    Field resolution order for the file path:
        1. ``file``      -- canonical key after Wave A1 fix
        2. ``location``  -- alternate key used by some authority_builder versions
        3. ``target``    -- fallback for older entries
    """
    if isinstance(raw, dict):
        obj: dict = raw
    else:
        try:
            parsed = json.loads(raw)
            obj = parsed if isinstance(parsed, dict) else {}
        except (json.JSONDecodeError, TypeError):
            # Treat the raw value itself as a file path.
            return {"file": str(raw), "kind": "unknown"}

    # Resolve file path from the first non-empty key.
    file_path = (
        obj.get("file", "")
        or obj.get("location", "")
        or obj.get("target", "")
    )
    if file_path and "file" not in obj:
        # Return a normalised copy so downstream code always uses "file".
        obj = dict(obj, file=str(file_path))
    return obj


def _group_files_by_scc(
    entries: dict[str, "StructuralEntry"],
) -> list[frozenset[str]]:
    """Group files into strongly connected components via union-find.

    Args:
        entries: dict mapping file path to StructuralEntry.

    Returns:
        List of frozensets, each representing one SCC (set of files in cycle).
        Files not in any cycle are omitted.
    """
    # Collect all files mentioned in any cycle.
    cycle_files: set[str] = set()
    for entry in entries.values():
        if entry.cycles:
            cycle_files.add(entry.file)
            cycle_files.update(entry.cycles)

    parent: dict[str, str] = {f: f for f in cycle_files}

    def find(f: str) -> str:
        if parent[f] != f:
            parent[f] = find(parent[f])
        return parent[f]

    def union(a: str, b: str) -> None:
        if a not in parent:
            parent[a] = a
        if b not in parent:
            parent[b] = b
        pa, pb = find(a), find(b)
        if pa != pb:
            parent[pa] = pb

    # Union files that are in the same cycle.
    for f, entry in entries.items():
        if not entry.cycles:
            continue
        for cycle_member in entry.cycles:
            union(f, cycle_member)

    # Group by root.
    groups: dict[str, set[str]] = {}
    for f in parent:
        root = find(f)
        groups.setdefault(root, set()).add(f)

    return [frozenset(group) for group in groups.values()]


# ---------------------------------------------------------------------------
# Pairwise checks
# ---------------------------------------------------------------------------

def _check_authority_vs_runtime(
    authority_map: tuple,
    runtime_map: tuple,
) -> list[tuple]:
    """Authority vs runtime: illegal writers detected in authority -> conflict.

    Each tuple: (domain, subject, sources, severity, action).
    """
    conflicts: list[tuple] = []

    # Index runtime nodes by defined_in file for quick lookup.
    runtime_by_file: dict[str, list] = {}
    for node in runtime_map:
        f = getattr(node, "defined_in", "")
        runtime_by_file.setdefault(f, []).append(node)

    for domain in authority_map:
        if not isinstance(domain, AuthorityDomain):
            continue
        for writer_raw in domain.writers_detected:
            writer = _normalize_writer(writer_raw)
            writer_file = writer.get("file", "")
            writer_kind = writer.get("kind", "unknown")
            if writer_kind != "illegal_write":
                continue

            sources = [
                {
                    "map": "authority_map",
                    "claim": "illegal_write_detected",
                    "file": writer_file,
                    "domain": domain.authority_domain,
                },
            ]

            # Enrich with runtime evidence if the writer file has a node there.
            if writer_file in runtime_by_file:
                sources.append({
                    "map": "runtime_map",
                    "claim": "writes_observed",
                    "file": writer_file,
                })

            cid = make_conflict_id(
                domain=domain.authority_domain,
                subject=writer_file,
                sources=sources,
            )
            conflicts.append((
                cid,
                domain.authority_domain,
                writer_file,
                sources,
                "high",
                "investigate_illegal_write",
            ))

    _log.debug("_check_authority_vs_runtime: %d conflicts found", len(conflicts))
    return conflicts


def _check_authority_vs_structural(
    authority_map: tuple,
    structural_map: tuple,
) -> list[tuple]:
    """Authority vs structural: illegal writer also appears as an importer
    of the canonical_owner -> structural confirms downstream coupling.
    """
    conflicts: list[tuple] = []

    # Index structural entries by file for fast lookup.
    structural_by_file: dict[str, StructuralEntry] = {}
    for entry in structural_map:
        if isinstance(entry, StructuralEntry):
            structural_by_file[entry.file] = entry

    for domain in authority_map:
        if not isinstance(domain, AuthorityDomain):
            continue
        canonical = domain.canonical_owner

        for writer_raw in domain.writers_detected:
            writer = _normalize_writer(writer_raw)
            writer_file = writer.get("file", "")
            writer_kind = writer.get("kind", "unknown")
            if writer_kind != "illegal_write":
                continue

            # Check if writer appears in imports_in of canonical owner's
            # structural entry, suggesting a downstream reader that writes back.
            entry = structural_by_file.get(canonical)
            if entry is None:
                continue
            if writer_file not in entry.imports_in:
                continue

            sources = [
                {
                    "map": "authority_map",
                    "claim": "illegal_write_detected",
                    "file": writer_file,
                    "domain": domain.authority_domain,
                },
                {
                    "map": "structural_map",
                    "claim": "downstream_reader_writes_back",
                    "canonical": canonical,
                    "writer": writer_file,
                },
            ]
            cid = make_conflict_id(
                domain=domain.authority_domain + ":structural",
                subject=writer_file,
                sources=sources,
            )
            conflicts.append((
                cid,
                domain.authority_domain + ":structural",
                writer_file,
                sources,
                "medium",
                "review_coupling",
            ))

    _log.debug("_check_authority_vs_structural: %d conflicts found", len(conflicts))
    return conflicts


def _check_contract_vs_structural(
    contract_map: tuple,
    structural_map: tuple,
) -> list[tuple]:
    """Contract vs structural: a variant file does not import the canonical_schema
    -> variant is evolving independently.
    """
    conflicts: list[tuple] = []

    # Index structural entries by file for fast lookup.
    structural_by_file: dict[str, StructuralEntry] = {}
    for entry in structural_map:
        if isinstance(entry, StructuralEntry):
            structural_by_file[entry.file] = entry

    for contract in contract_map:
        if not isinstance(contract, DataContractEntry):
            continue
        canonical_schema = contract.canonical_schema
        if not canonical_schema:
            continue

        for variant_raw in contract.variants:
            # Variants are stored as JSON-serialised dicts or plain strings.
            try:
                variant_obj = json.loads(variant_raw) if isinstance(variant_raw, str) else variant_raw
            except (json.JSONDecodeError, TypeError):
                variant_obj = {}

            variant_file = variant_obj.get("file", "") if isinstance(variant_obj, dict) else str(variant_raw)
            if not variant_file:
                continue

            # Check if variant file imports canonical_schema.
            entry = structural_by_file.get(variant_file)
            if entry is None:
                # Variant file not in structural map — not a conflict here.
                continue

            if canonical_schema in entry.imports_out:
                # Correctly imports canonical → no conflict.
                continue

            sources = [
                {
                    "map": "contract_map",
                    "claim": "variant_location",
                    "entity": contract.entity,
                    "variant_file": variant_file,
                    "canonical_schema": canonical_schema,
                },
                {
                    "map": "structural_map",
                    "claim": "missing_canonical_import",
                    "file": variant_file,
                },
            ]
            cid = make_conflict_id(
                domain=contract.entity,
                subject=variant_file,
                sources=sources,
            )
            conflicts.append((
                cid,
                contract.entity,
                variant_file,
                sources,
                "medium",
                "add_canonical_import_or_merge",
            ))

    _log.debug("_check_contract_vs_structural: %d conflicts found", len(conflicts))
    return conflicts


def _check_authority_shared_writes(
    authority_map: tuple,
) -> list[tuple]:
    """Authority shared writes: auto-discovered domains with multiple writers
    from different modules writing to the same target file.

    Returns raw tuples for ConflictEntry construction:
        (cid, domain, subject, sources, severity, action)
    Test-only shared writes (all writers are test/fixture) get "low" severity.
    """
    raw: list[tuple] = []

    for domain in authority_map:
        if not isinstance(domain, AuthorityDomain):
            continue
        # Only process auto-discovered inferred domains
        if domain.status != "inferred":
            continue

        # Group writers by target, collecting file_role
        target_to_writers_with_roles: dict[str, list[tuple[str, str]]] = {}
        for writer_raw in domain.writers_detected:
            writer = _normalize_writer(writer_raw)
            kind = writer.get("kind", "unknown")
            if kind != "shared_write":
                continue
            target = writer.get("target", "")
            location = writer.get("file", "") or writer.get("location", "")
            file_role = writer.get("file_role", "production")
            if target and location:
                target_to_writers_with_roles.setdefault(target, []).append((location, file_role))

        for target, writers_with_roles in sorted(target_to_writers_with_roles.items()):
            if len(writers_with_roles) < 2:
                continue
            writers = [w[0] for w in writers_with_roles]
            roles = {w[1] for w in writers_with_roles}
            # Check if all writers are test/fixture (no production)
            is_test_only = "production" not in roles
            sources = [
                {
                    "map": "authority_map",
                    "claim": "shared_write_detected",
                    "file": w,
                    "domain": domain.authority_domain,
                    "target": target,
                }
                for w in sorted(writers)
            ]
            cid = make_conflict_id(
                domain=domain.authority_domain,
                subject=target,
                sources=sources,
            )
            severity = "low" if is_test_only else "medium"
            raw.append((cid, domain.authority_domain, target, sources, severity, "investigate_shared_write"))

    _log.debug("_check_authority_shared_writes: %d conflicts found", len(raw))
    return raw


def _check_structural_cycles(
    structural_map: tuple,
) -> list[tuple]:
    """Structural cycles: per-SCC (strongly connected component) grouping.

    Groups files that share import cycles into SCCs via union-find, then
    emits one conflict per SCC instead of one per file. This avoids N
    duplicate findings for an N-node cycle.

    Filtering criteria (all must hold):
        1. SCC has >= 2 files.
        2. Max fan-in across all SCC files with known StructuralEntry >= 3.

    Severity:
        "high"   – all SCC files with entries are production.
        "medium" – mixed production + test/fixture.
        "low"    – all SCC files with entries are test/fixture.

    Returns raw tuples for ConflictEntry construction:
        (cid, domain, subject, sources, severity, action)
    """
    # Build lookup: file path -> StructuralEntry (only files that have one).
    entries: dict[str, StructuralEntry] = {}
    for entry in structural_map:
        if isinstance(entry, StructuralEntry):
            entries[entry.file] = entry

    # Group files into SCCs using union-find over cycle membership.
    scc_list = _group_files_by_scc(entries)

    raw: list[tuple] = []

    for scc in scc_list:
        # Filter 1: must have >= 2 files in the cycle cluster (includes ghost members).
        if len(scc) < 2:
            continue

        # Gather metadata only for SCC files that have a StructuralEntry.
        # Files referenced in cycles but absent from the structural map are
        # still part of the SCC geometrically, but carry no fan-in data.
        known_entries = [entries[f] for f in scc if f in entries]

        # Filter 2: max fan-in across known entries must be >= 3.
        if not known_entries:
            continue
        max_fan_in = max(len(e.imports_in) for e in known_entries)
        if max_fan_in < 3:
            continue

        # Compute file roles for known entries.
        roles = {e.file: classify_file_role(e.file) for e in known_entries}

        # Determine severity based on role composition of known entries.
        has_production = any(r == "production" for r in roles.values())
        all_production = all(r == "production" for r in roles.values())

        if all_production:
            cluster_severity = "high"
        elif has_production:
            cluster_severity = "medium"
        else:
            cluster_severity = "low"

        # Representative subject: lexicographically first file in SCC (stable).
        subject = sorted(scc)[0]

        # Build sources list: one entry per SCC file, tagged with what's known.
        sources: list[dict] = []
        for f in sorted(scc):
            entry = entries.get(f)
            source_item: dict = {
                "map": "structural_map",
                "claim": "import_cycle",
                "file": f,
                "cluster_size": len(scc),
                "cluster_max_fan_in": max_fan_in,
            }
            if entry is not None:
                source_item["file_role"] = roles[f]
                source_item["fan_in"] = len(entry.imports_in)
                source_item["cycle_members"] = list(entry.cycles)
            sources.append(source_item)

        cid = make_conflict_id(domain="structural_cycles", subject=subject, sources=sources)
        raw.append((cid, "structural_cycles", subject, sources, cluster_severity, "break_cycle"))

    _log.debug(
        "_check_structural_cycles: %d SCC clusters -> %d conflicts",
        len(scc_list), len(raw),
    )
    return raw


def _check_contract_drift(
    contract_map: tuple,
) -> list[tuple]:
    """Data contract drift: schema inconsistencies.

    Returns raw tuples for ConflictEntry construction:
        (cid, domain, subject, sources, severity, action)
    """
    raw: list[tuple] = []
    from .map_models import DataContractEntry

    for contract in contract_map:
        if not isinstance(contract, DataContractEntry):
            continue
        drift_flags = getattr(contract, "drift_flags", ())
        if not drift_flags:
            continue
        sources = [{
            "map": "data_contract_map",
            "claim": flag,
            "entity": contract.entity,
        } for flag in drift_flags]
        cid = make_conflict_id(domain="contract_drift", subject=contract.entity, sources=sources)
        raw.append((cid, "contract_drift", contract.entity, sources, "medium", "investigate_contract_drift"))

    _log.debug("_check_contract_drift: %d conflicts found", len(raw))
    return raw


def _check_runtime_env_coupling(
    runtime_map: tuple,
) -> list[tuple]:
    """Runtime environment coupling: nodes with unvalidated env var dependencies.

    Downgrade severity for test nodes (less critical in production).
    Returns raw tuples for ConflictEntry construction:
        (cid, domain, subject, sources, severity, action)
    """
    raw: list[tuple] = []
    from .map_models import RuntimeNode

    for node in runtime_map:
        if not isinstance(node, RuntimeNode):
            continue
        depends_on_env = getattr(node, "depends_on_env", ())
        if not depends_on_env:
            continue
        # Check file role from defined_in field
        file_role = classify_file_role(node.defined_in) if hasattr(node, "defined_in") else "production"
        # Test/fixture nodes are less critical (skip entirely or downgrade)
        if file_role != "production":
            continue  # Skip test/fixture env coupling
        sources = [{
            "map": "runtime_map",
            "claim": "env_var_dependency",
            "node": node.node,
            "defined_in": node.defined_in,
            "file_role": file_role,
            "env_vars": list(depends_on_env),
        }]
        cid = make_conflict_id(domain="runtime_env_coupling", subject=node.node, sources=sources)
        raw.append((cid, "runtime_env_coupling", node.node, sources, "low", "document_env_contract"))

    _log.debug("_check_runtime_env_coupling: %d conflicts found", len(raw))
    return raw


# ---------------------------------------------------------------------------
# Lifecycle resolution
# ---------------------------------------------------------------------------

def _populate_conflict_evidence(
    domain: str,
    subject: str,
    sources: list[dict],
) -> tuple[str, ...]:
    """Build evidence tuples from conflict sources.

    Evidence strategy:
      1. For source_location: each file in sources with claim markers
      2. For write_conflicts domain: target_path evidence from subject
      3. Representative list (max 10 items) to avoid bloat

    Returns:
        Tuple of JSON-serialized EvidenceItem strings.
    """
    from .map_models_findings import EvidenceItem

    evidence_items: list[EvidenceItem] = []

    # Add source files from sources list (representative sample)
    added_files = set()
    for src in sources[:5]:  # Limit to first 5 sources to avoid bloat
        if not isinstance(src, dict):
            continue
        file = src.get("file", "")
        if file and file not in added_files:
            evidence_items.append(EvidenceItem(
                kind="source_location",
                file=file,
                line=src.get("line"),
                map="structural" if "cycle" in src.get("claim", "") else "authority",
            ))
            added_files.add(file)

    # For write_conflicts or shared_write domains, add target as target_path evidence
    if domain in ("write_conflicts", "shared_write") or "write" in domain:
        evidence_items.append(EvidenceItem(
            kind="target_path",
            path=subject,
        ))

    # For structural_cycles, add cycle member files as source locations
    if domain == "structural_cycles":
        cycle_members = set()
        for src in sources:
            if isinstance(src, dict):
                members = src.get("cycle_members", [])
                if isinstance(members, list):
                    cycle_members.update(m for m in members if m not in added_files)
        # Add top 3 cycle members (representative)
        for member in sorted(cycle_members)[:3]:
            evidence_items.append(EvidenceItem(
                kind="source_location",
                file=member,
                map="structural",
            ))
            added_files.add(member)

    # Serialize to JSON strings
    result: list[str] = []
    for item in evidence_items[:10]:  # Cap at 10 items total
        result.append(json.dumps(item.to_dict(), sort_keys=True))

    return tuple(result)


def _apply_lifecycle(
    raw_conflicts: list[tuple],
    previous_by_id: dict[str, ConflictEntry],
    freshness: str,
) -> tuple[list[ConflictEntry], set[str]]:
    """Build ConflictEntry objects applying previous-status inheritance.

    Returns:
        (entries, seen_ids) where seen_ids is the set of conflict IDs
        present in the new build.
    """
    result: list[ConflictEntry] = []
    seen_ids: set[str] = set()

    for cid, domain, subject, sources, severity, action in raw_conflicts:
        seen_ids.add(cid)
        prev = previous_by_id.get(cid)

        # Lifecycle: preserve resolved status from previous build.
        # validated status from previous is also preserved (manual triage result).
        # Default for new (unseen) conflicts is "open".
        if prev is not None and prev.conflict_status == "resolved":
            conflict_status = "resolved"
            metadata_status = prev.status  # carry "validated" or whatever it was
        elif prev is not None and prev.conflict_status == "validated":
            conflict_status = "validated"
            metadata_status = prev.status
        else:
            conflict_status = "open"
            metadata_status = "open"

        # Populate evidence from sources
        evidence = _populate_conflict_evidence(domain, subject, sources)

        result.append(ConflictEntry(
            conflict_id=cid,
            domain=domain,
            subject=subject,
            sources=tuple(json.dumps(s, sort_keys=True) for s in sources),
            severity=severity,
            conflict_status=conflict_status,
            action=action,
            source=_SOURCE,
            evidence=evidence,
            confidence=_CONFIDENCE,
            freshness=freshness,
            status=metadata_status,
        ))

    return result, seen_ids


def _carry_resolved(
    previous_by_id: dict[str, ConflictEntry],
    seen_ids: set[str],
    freshness: str,
) -> list[ConflictEntry]:
    """Return previously present conflicts that have disappeared -> mark resolved."""
    carried: list[ConflictEntry] = []
    for cid, prev in previous_by_id.items():
        if cid in seen_ids:
            continue
        if prev.conflict_status == "resolved":
            # Already resolved, carry as-is but update freshness.
            carried.append(ConflictEntry(
                conflict_id=prev.conflict_id,
                domain=prev.domain,
                subject=prev.subject,
                sources=prev.sources,
                severity=prev.severity,
                conflict_status="resolved",
                action=prev.action,
                source=prev.source,
                evidence=prev.evidence,
                confidence=prev.confidence,
                freshness=freshness,
                status=prev.status,
            ))
        else:
            # Was open/in_progress, now gone → mark resolved.
            carried.append(ConflictEntry(
                conflict_id=prev.conflict_id,
                domain=prev.domain,
                subject=prev.subject,
                sources=prev.sources,
                severity=prev.severity,
                conflict_status="resolved",
                action=prev.action,
                source=prev.source,
                evidence=prev.evidence,
                confidence=prev.confidence,
                freshness=freshness,
                status=prev.status,
            ))
    return carried


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def build_conflict_map(
    repo_maps: RepoMaps,
    previous_conflicts: Sequence[ConflictEntry] = (),
) -> list[ConflictEntry]:
    """Build a conflict map from pairwise inter-map diffs.

    Checks performed:
        1. authority vs runtime  -- illegal writers seen in authority but
           also observed as writing at runtime.
        2. authority vs structural -- illegal writer appears as downstream
           reader (imports_in) of the canonical owner.
        3. contract vs structural -- variant file does not import canonical_schema.

    Conflict lifecycle:
        - New conflict (not in previous): status = "open".
        - Conflict matching previous by ID where previous was "resolved":
          preserve "resolved".
        - Conflict in previous but absent from new build: marked "resolved",
          included in output.

    Args:
        repo_maps: Container with all available maps.
        previous_conflicts: Sequence of ConflictEntry from prior build for
            lifecycle/status preservation.

    Returns:
        Sorted list of ConflictEntry (by conflict_id).

    Raises:
        MapBuildConflictBudgetExceeded: If open conflict count exceeds 500.
    """
    _log.info(
        "build_conflict_map: starting pairwise diff -- structural=%d runtime=%d "
        "contract=%d authority=%d previous=%d",
        len(repo_maps.structural),
        len(repo_maps.runtime),
        len(repo_maps.data_contract),
        len(repo_maps.authority),
        len(previous_conflicts),
    )

    freshness = _utc_now()

    # Index previous conflicts by ID for O(1) lookups.
    previous_by_id: dict[str, ConflictEntry] = {
        c.conflict_id: c for c in previous_conflicts
    }

    # Collect raw conflict tuples from all checks.
    raw: list[tuple] = []
    raw.extend(_check_authority_vs_runtime(repo_maps.authority, repo_maps.runtime))
    raw.extend(_check_authority_vs_structural(repo_maps.authority, repo_maps.structural))
    raw.extend(_check_authority_shared_writes(repo_maps.authority))
    raw.extend(_check_contract_vs_structural(repo_maps.data_contract, repo_maps.structural))
    raw.extend(_check_structural_cycles(repo_maps.structural))
    raw.extend(_check_contract_drift(repo_maps.data_contract))
    raw.extend(_check_runtime_env_coupling(repo_maps.runtime))

    # Deduplicate by conflict_id (keep first occurrence).
    seen_raw: set[str] = set()
    deduped: list[tuple] = []
    for item in raw:
        cid = item[0]
        if cid not in seen_raw:
            seen_raw.add(cid)
            deduped.append(item)

    # Apply lifecycle.
    new_entries, seen_ids = _apply_lifecycle(deduped, previous_by_id, freshness)

    # Carry resolved conflicts that have disappeared.
    carried = _carry_resolved(previous_by_id, seen_ids, freshness)

    result = new_entries + carried

    # Sort for deterministic output.
    result.sort(key=lambda c: c.conflict_id)

    # Budget check.
    open_count = sum(1 for c in result if c.conflict_status == "open")
    _log.info(
        "build_conflict_map: total=%d open=%d resolved=%d",
        len(result), open_count, len(result) - open_count,
    )
    if open_count > _CONFLICT_BUDGET:
        raise MapBuildConflictBudgetExceeded(
            "Open conflict count %d exceeds budget %d" % (open_count, _CONFLICT_BUDGET)
        )

    return result
