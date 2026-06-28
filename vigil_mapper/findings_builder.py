"""Findings builder -- synthesizes map entries into diagnostic findings.

Map 8: Findings synthesizes from all 7 maps (structural, data_contract, authority,
runtime, conflict, hotspot, refactor_boundary) and produces actionable findings
for operators.

Patterns:
- architecture_cycle: SCC cluster + fan_in >= 5 + hotspot score >= 60
- state_ownership_conflict: shared_write conflict + runtime node + 2+ production modules
- schema_drift_risk: contract_drift + multiple readers >= 2
- runtime_config_risk: env_coupling conflict + env_var not in contract
- write_authority_violation: illegal_write + verified target (path_constructor provenance)

Lifecycle:
- new: first time seeing this finding_id
- existing: same finding_id, same severity
- worsened: same finding_id, severity increased
- resolved: previous finding_id not in current output
"""
from __future__ import annotations

import hashlib
import json
import logging
from pathlib import Path
from typing import Any

from .map_models import RepoMaps
from .map_models_findings import Finding, EvidenceItem
from .map_storage import maps_dir

__all__ = ["build_findings_map"]

_log = logging.getLogger(__name__)


def build_findings_map(
    project_dir: Path,
    repo_maps: RepoMaps,
    maps_dir_override: Path | None = None,
) -> list[Finding]:
    """Build findings map from all 7 maps.

    Args:
        project_dir: Absolute path to the target project root.
        repo_maps: RepoMaps object containing all built maps.
        maps_dir_override: Optional override for maps directory (for --output-dir).

    Returns:
        list[Finding]: Synthesized findings with lifecycle states.
    """
    project_dir = Path(project_dir).resolve()
    _log.info("build_findings_map: starting for %s", project_dir)

    # Load previous findings for lifecycle tracking
    prev_findings = _load_previous_findings(project_dir, maps_dir_override)
    prev_by_id = {f.finding_id: f for f in prev_findings}

    # Synthesize new findings
    current_findings: list[Finding] = []

    # Pattern 1: architecture_cycle
    current_findings.extend(_find_architecture_cycles(repo_maps, prev_by_id))

    # Pattern 2: state_ownership_conflict
    current_findings.extend(_find_state_ownership_conflicts(repo_maps, prev_by_id))

    # Pattern 3: schema_drift_risk
    current_findings.extend(_find_schema_drift_risks(repo_maps, prev_by_id))

    # Pattern 4: runtime_config_risk
    current_findings.extend(_find_runtime_config_risks(repo_maps, prev_by_id))

    # Pattern 5: write_authority_violation
    current_findings.extend(_find_write_authority_violations(repo_maps, prev_by_id))

    # Add resolved findings for lifecycle
    current_by_id = {f.finding_id: f for f in current_findings}
    for prev_id, prev_finding in prev_by_id.items():
        if prev_id not in current_by_id:
            current_findings.append(_mark_resolved(prev_finding))

    _log.info(
        "build_findings_map: synthesized %d findings (%d new, %d existing, %d resolved)",
        len(current_findings),
        sum(1 for f in current_findings if f.finding_status == "new"),
        sum(1 for f in current_findings if f.finding_status == "existing"),
        sum(1 for f in current_findings if f.finding_status == "resolved"),
    )

    return current_findings


def _load_previous_findings(project_dir: Path, maps_dir_override: Path | None = None) -> list[Finding]:
    """Load previous findings map if exists.

    Args:
        project_dir: Absolute path to the target project root.
        maps_dir_override: Optional override for maps directory (for --output-dir).
    """
    if maps_dir_override is not None:
        mdir = maps_dir_override.resolve()
    else:
        mdir = maps_dir(project_dir)
    findings_path = mdir / "80_findings_map.json"

    if not findings_path.exists():
        return []

    try:
        import json
        content = findings_path.read_text(encoding="utf-8")
        payload = json.loads(content)
    except (OSError, json.JSONDecodeError, UnicodeDecodeError) as exc:
        _log.warning("_load_previous_findings: failed to read %s: %s", findings_path, exc)
        return []

    entries_raw = payload.get("entries", [])
    findings: list[Finding] = []
    for i, raw_entry in enumerate(entries_raw):
        try:
            finding = Finding.from_dict(raw_entry)
            findings.append(finding)
        except (KeyError, TypeError, ValueError) as exc:
            _log.debug("_load_previous_findings: skipping entry %d: %s", i, exc)

    _log.debug("_load_previous_findings: loaded %d previous findings", len(findings))
    return findings


def _make_finding_id(category: str, subject: str, details: str) -> str:
    """Generate stable finding_id from category, subject, and details."""
    content = f"{category}:{subject}:{details}"
    hash_val = hashlib.sha256(content.encode("utf-8")).hexdigest()[:16]
    return f"{category}_{hash_val}"


def _mark_resolved(finding: Finding) -> Finding:
    """Mark a previous finding as resolved."""
    return Finding(
        finding_id=finding.finding_id,
        category=finding.category,
        title=finding.title,
        severity=finding.severity,
        confidence=finding.confidence,
        why_it_matters=finding.why_it_matters,
        suggested_fix=finding.suggested_fix,
        affected_files=finding.affected_files,
        evidence=finding.evidence,
        source_maps=finding.source_maps,
        finding_status="resolved",
        source=finding.source,
        freshness=finding.freshness,
        status=finding.status,
    )


def _get_lifecycle_status(
    finding_id: str,
    severity: str,
    prev_by_id: dict[str, Finding],
) -> str:
    """Determine lifecycle status (new/existing/worsened)."""
    if finding_id not in prev_by_id:
        return "new"
    prev = prev_by_id[finding_id]
    if prev.severity == severity:
        return "existing"
    # Check if severity worsened (critical > high > medium > low)
    _severity_level = {"critical": 4, "high": 3, "medium": 2, "low": 1}
    curr_level = _severity_level.get(severity, 0)
    prev_level = _severity_level.get(prev.severity, 0)
    return "worsened" if curr_level > prev_level else "existing"


def _find_architecture_cycles(
    repo_maps: RepoMaps,
    prev_by_id: dict[str, Finding],
) -> list[Finding]:
    """Find architecture_cycle findings: SCC + fan_in >= 5 + hotspot score >= 60.

    Trigger: ConflictEntry with domain == "structural_cycles"
             AND cluster_max_fan_in >= 5 in any source entry
             AND a HotspotEntry for any SCC member with hotspot_score >= 60.
    """
    findings: list[Finding] = []

    # Build hotspot index: file -> HotspotEntry
    hotspot_by_file: dict[str, Any] = {}
    for h in repo_maps.hotspot:
        hotspot_by_file[getattr(h, "target", "")] = h

    for conflict in repo_maps.conflict:
        if getattr(conflict, "domain", "") != "structural_cycles":
            continue

        # Parse sources to collect SCC member files and cluster_max_fan_in
        sources_parsed: list[dict] = []
        for src_raw in conflict.sources:
            try:
                src = json.loads(src_raw) if isinstance(src_raw, str) else src_raw
                if isinstance(src, dict):
                    sources_parsed.append(src)
            except (json.JSONDecodeError, TypeError):
                pass

        # Check fan_in threshold across all sources
        max_fan_in = max(
            (s.get("cluster_max_fan_in", 0) for s in sources_parsed),
            default=0,
        )
        if max_fan_in < 5:
            continue

        # Collect SCC member files from sources
        scc_files = [s.get("file", "") for s in sources_parsed if s.get("file")]

        # Find hotspot entries for any SCC member with score >= 60
        hot_entries = [
            hotspot_by_file[f]
            for f in scc_files
            if f in hotspot_by_file and getattr(hotspot_by_file[f], "hotspot_score", 0) >= 60
        ]
        if not hot_entries:
            continue

        # Construct evidence
        evidence_items: list[str] = []
        for src in sources_parsed:
            ev = EvidenceItem(
                kind="map_entry",
                map="conflict_map",
                entry_id=getattr(conflict, "conflict_id", ""),
                file=src.get("file", ""),
            )
            evidence_items.append(json.dumps(ev.to_dict(), sort_keys=True))

        for h in hot_entries:
            ev = EvidenceItem(
                kind="map_entry",
                map="hotspot_map",
                entry_id=getattr(h, "target", ""),
                file=getattr(h, "target", ""),
            )
            evidence_items.append(json.dumps(ev.to_dict(), sort_keys=True))

        # Representative subject for stable ID
        subject = conflict.subject
        details = f"fan_in={max_fan_in}"
        finding_id = _make_finding_id("architecture_cycle", subject, details)

        # Severity: critical if cluster is all-production (conflict severity == "high"),
        # otherwise high
        severity = "critical" if conflict.severity == "high" else "high"
        lifecycle = _get_lifecycle_status(finding_id, severity, prev_by_id)

        # Build a deduplication-stable strategy hint from SCC size
        scc_size = len(scc_files)
        suggested_fix = (
            f"Decouple cycle by introducing an abstraction layer or moving shared "
            f"symbols to a common base module (cycle cluster size: {scc_size} files)"
        )

        finding = Finding(
            finding_id=finding_id,
            category="architecture_cycle",
            title=f"Import cycle cluster with high fan-in ({max_fan_in}) and hotspot overlap",
            severity=severity,
            confidence=min(conflict.confidence, 0.9),
            why_it_matters=(
                "Circular imports with high fan-in create tight coupling that blocks "
                "independent testing, deployment, and refactoring of affected modules."
            ),
            suggested_fix=suggested_fix,
            affected_files=tuple(sorted(set(scc_files))),
            evidence=tuple(evidence_items),
            source_maps=("structural_map", "conflict_map", "hotspot_map"),
            finding_status=lifecycle,
            source="synthesis",
            freshness="",
            status="validated",
        )
        findings.append(finding)

    _log.debug("_find_architecture_cycles: %d findings", len(findings))
    return findings


def _find_state_ownership_conflicts(
    repo_maps: RepoMaps,
    prev_by_id: dict[str, Finding],
) -> list[Finding]:
    """Find state_ownership_conflict: shared_write + runtime node + 2+ production writers.

    Trigger: ConflictEntry with action == "investigate_shared_write"
             AND at least 2 source entries with file_role == "production"
             AND a RuntimeNode with defined_in matching the conflict subject (target file).
    """
    findings: list[Finding] = []

    # Index runtime nodes by defined_in file
    runtime_by_file: dict[str, Any] = {}
    for node in repo_maps.runtime:
        f = getattr(node, "defined_in", "")
        if f:
            runtime_by_file[f] = node

    for conflict in repo_maps.conflict:
        if getattr(conflict, "action", "") != "investigate_shared_write":
            continue

        # Parse sources to collect writer files and roles
        sources_parsed: list[dict] = []
        for src_raw in conflict.sources:
            try:
                src = json.loads(src_raw) if isinstance(src_raw, str) else src_raw
                if isinstance(src, dict):
                    sources_parsed.append(src)
            except (json.JSONDecodeError, TypeError):
                pass

        # Count production writers
        production_writers = [
            s.get("file", "")
            for s in sources_parsed
            if s.get("file_role", "production") == "production" and s.get("file")
        ]
        if len(production_writers) < 2:
            continue

        # Target file is the conflict subject
        target_file = conflict.subject

        # Check that a RuntimeNode exists for the target file
        runtime_node = runtime_by_file.get(target_file)
        if runtime_node is None:
            continue

        # Build evidence
        evidence_items: list[str] = []
        for writer_file in sorted(set(production_writers)):
            ev = EvidenceItem(
                kind="source_location",
                file=writer_file,
                map="authority_map",
            )
            evidence_items.append(json.dumps(ev.to_dict(), sort_keys=True))

        ev_conflict = EvidenceItem(
            kind="map_entry",
            map="conflict_map",
            entry_id=getattr(conflict, "conflict_id", ""),
            file=target_file,
        )
        evidence_items.append(json.dumps(ev_conflict.to_dict(), sort_keys=True))

        ev_runtime = EvidenceItem(
            kind="map_entry",
            map="runtime_map",
            entry_id=getattr(runtime_node, "node", ""),
            file=getattr(runtime_node, "defined_in", ""),
        )
        evidence_items.append(json.dumps(ev_runtime.to_dict(), sort_keys=True))

        details = f"writers={len(production_writers)}"
        finding_id = _make_finding_id("state_ownership_conflict", target_file, details)
        severity = "high"
        lifecycle = _get_lifecycle_status(finding_id, severity, prev_by_id)

        finding = Finding(
            finding_id=finding_id,
            category="state_ownership_conflict",
            title=f"Multiple production modules write to shared target: {target_file}",
            severity=severity,
            confidence=min(conflict.confidence, 0.85),
            why_it_matters=(
                "Shared write access without a single owner leads to race conditions, "
                "inconsistent state, and undefined ordering of writes at runtime."
            ),
            suggested_fix=(
                f"Designate single owner for {target_file} and route all writes "
                "through that module; demote remaining writers to readers."
            ),
            affected_files=tuple(sorted(set(production_writers) | {target_file})),
            evidence=tuple(evidence_items),
            source_maps=("authority_map", "conflict_map", "runtime_map"),
            finding_status=lifecycle,
            source="synthesis",
            freshness="",
            status="validated",
        )
        findings.append(finding)

    _log.debug("_find_state_ownership_conflicts: %d findings", len(findings))
    return findings


def _find_schema_drift_risks(
    repo_maps: RepoMaps,
    prev_by_id: dict[str, Finding],
) -> list[Finding]:
    """Find schema_drift_risk: contract_drift conflict + 2+ readers in data_contract map.

    Trigger: ConflictEntry with domain == "contract_drift"
             AND corresponding DataContractEntry with len(readers) >= 2.
    """
    findings: list[Finding] = []

    # Index data_contract entries by entity name
    contract_by_entity: dict[str, Any] = {}
    for contract in repo_maps.data_contract:
        entity = getattr(contract, "entity", "")
        if entity:
            contract_by_entity[entity] = contract

    for conflict in repo_maps.conflict:
        if getattr(conflict, "domain", "") != "contract_drift":
            continue

        entity = conflict.subject
        contract = contract_by_entity.get(entity)
        if contract is None:
            continue

        readers = getattr(contract, "readers", ())
        if len(readers) < 2:
            continue

        # Build evidence
        evidence_items: list[str] = []

        ev_conflict = EvidenceItem(
            kind="map_entry",
            map="conflict_map",
            entry_id=getattr(conflict, "conflict_id", ""),
            path=entity,
        )
        evidence_items.append(json.dumps(ev_conflict.to_dict(), sort_keys=True))

        for reader_file in sorted(readers):
            ev = EvidenceItem(
                kind="source_location",
                file=reader_file,
                map="data_contract_map",
            )
            evidence_items.append(json.dumps(ev.to_dict(), sort_keys=True))

        details = f"readers={len(readers)}"
        finding_id = _make_finding_id("schema_drift_risk", entity, details)
        severity = "medium"
        lifecycle = _get_lifecycle_status(finding_id, severity, prev_by_id)

        # Collect drift_flags from contract for context
        drift_flags = list(getattr(contract, "drift_flags", ()))
        drift_summary = ", ".join(drift_flags[:3]) if drift_flags else "schema inconsistency"

        finding = Finding(
            finding_id=finding_id,
            category="schema_drift_risk",
            title=f"Schema drift risk in entity '{entity}' with {len(readers)} readers",
            severity=severity,
            confidence=min(conflict.confidence, 0.8),
            why_it_matters=(
                f"Schema drift ({drift_summary}) with multiple readers means "
                "consumers may silently receive stale or incompatible data shapes."
            ),
            suggested_fix=(
                "Align schema variants or add a migration step; pin all readers "
                "to the canonical schema and remove divergent variants."
            ),
            affected_files=tuple(sorted(readers)),
            evidence=tuple(evidence_items),
            source_maps=("data_contract_map", "conflict_map"),
            finding_status=lifecycle,
            source="synthesis",
            freshness="",
            status="validated",
        )
        findings.append(finding)

    _log.debug("_find_schema_drift_risks: %d findings", len(findings))
    return findings


def _find_runtime_config_risks(
    repo_maps: RepoMaps,
    prev_by_id: dict[str, Finding],
) -> list[Finding]:
    """Find runtime_config_risk: env_coupling conflict + env_var absent from contracts.

    Trigger: ConflictEntry with domain == "runtime_env_coupling"
             AND none of the env_vars from the conflict sources appear as an
             entity name in any DataContractEntry.
    """
    findings: list[Finding] = []

    # Collect all entity names from data_contract map (treat as documented env vars)
    contract_entities: set[str] = {
        getattr(c, "entity", "") for c in repo_maps.data_contract
    }
    contract_entities.discard("")

    for conflict in repo_maps.conflict:
        if getattr(conflict, "domain", "") != "runtime_env_coupling":
            continue

        # Parse sources to find env_vars list
        env_vars: list[str] = []
        node_name: str = conflict.subject
        defined_in: str = ""
        for src_raw in conflict.sources:
            try:
                src = json.loads(src_raw) if isinstance(src_raw, str) else src_raw
                if isinstance(src, dict):
                    env_vars.extend(src.get("env_vars", []))
                    defined_in = defined_in or src.get("defined_in", "")
                    node_name = node_name or src.get("node", "")
            except (json.JSONDecodeError, TypeError):
                pass

        if not env_vars:
            continue

        # Find env vars not present in any contract entity
        undocumented = [v for v in env_vars if v not in contract_entities]
        if not undocumented:
            continue

        # Build evidence — one finding per undocumented env var to keep IDs stable
        for env_var in sorted(set(undocumented)):
            evidence_items: list[str] = []

            ev_conflict = EvidenceItem(
                kind="map_entry",
                map="conflict_map",
                entry_id=getattr(conflict, "conflict_id", ""),
                path=env_var,
            )
            evidence_items.append(json.dumps(ev_conflict.to_dict(), sort_keys=True))

            if defined_in:
                ev_location = EvidenceItem(
                    kind="source_location",
                    file=defined_in,
                    map="runtime_map",
                )
                evidence_items.append(json.dumps(ev_location.to_dict(), sort_keys=True))

            details = f"env_var={env_var}"
            finding_id = _make_finding_id("runtime_config_risk", node_name, details)

            # Severity: medium if env var name looks like a critical secret,
            # otherwise low — keep it simple, use medium to be conservative
            severity = (
                "medium"
                if any(kw in env_var.upper() for kw in ("KEY", "SECRET", "TOKEN", "PASSWORD", "PASS"))
                else "low"
            )
            lifecycle = _get_lifecycle_status(finding_id, severity, prev_by_id)

            affected: list[str] = [defined_in] if defined_in else []

            finding = Finding(
                finding_id=finding_id,
                category="runtime_config_risk",
                title=f"Undocumented env var '{env_var}' coupled to runtime node '{node_name}'",
                severity=severity,
                confidence=min(conflict.confidence, 0.75),
                why_it_matters=(
                    f"Env var '{env_var}' is consumed at runtime but absent from "
                    "any data contract, making its presence, type, and defaults invisible "
                    "to operators and static analysis."
                ),
                suggested_fix=(
                    f"Document env var '{env_var}' in a data contract entity "
                    "or remove the runtime coupling if the var is no longer needed."
                ),
                affected_files=tuple(affected),
                evidence=tuple(evidence_items),
                source_maps=("runtime_map", "conflict_map", "data_contract_map"),
                finding_status=lifecycle,
                source="synthesis",
                freshness="",
                status="validated",
            )
            findings.append(finding)

    _log.debug("_find_runtime_config_risks: %d findings", len(findings))
    return findings


def _find_write_authority_violations(
    repo_maps: RepoMaps,
    prev_by_id: dict[str, Finding],
) -> list[Finding]:
    """Find write_authority_violation: illegal_write + path_constructor provenance.

    Trigger: ConflictEntry with action == "investigate_illegal_write" (domain in authority map)
             AND in the corresponding AuthorityDomain, the illegal writer's detected entry
             has provenance == "path_constructor", meaning the write target is statically
             verifiable (not a dynamic parameter).
    """
    findings: list[Finding] = []

    # Build authority domain index: authority_domain name -> AuthorityDomain
    authority_by_domain: dict[str, Any] = {}
    for domain in repo_maps.authority:
        name = getattr(domain, "authority_domain", "")
        if name:
            authority_by_domain[name] = domain

    for conflict in repo_maps.conflict:
        if getattr(conflict, "action", "") != "investigate_illegal_write":
            continue

        # The conflict subject is the illegal writer file; domain is the authority domain name
        # (may have ":structural" suffix from _check_authority_vs_structural — strip it)
        raw_domain = getattr(conflict, "domain", "")
        authority_domain_name = raw_domain.removesuffix(":structural")
        writer_file = conflict.subject

        auth_domain = authority_by_domain.get(authority_domain_name)
        if auth_domain is None:
            continue

        # Find the writer entry in writers_detected that matches writer_file
        # and has provenance == "path_constructor"
        path_constructor_target: str = ""
        for writer_raw in auth_domain.writers_detected:
            try:
                writer = json.loads(writer_raw) if isinstance(writer_raw, str) else writer_raw
            except (json.JSONDecodeError, TypeError):
                continue
            if not isinstance(writer, dict):
                continue

            # Match by file, location, or target key (normalise as in conflict_builder)
            wfile = (
                writer.get("file", "")
                or writer.get("location", "")
                or writer.get("target", "")
            )
            if wfile != writer_file:
                continue
            if writer.get("kind") != "illegal_write":
                continue
            if writer.get("provenance") == "path_constructor":
                path_constructor_target = writer.get("target", writer_file)
                break

        if not path_constructor_target:
            continue

        # Build evidence
        evidence_items: list[str] = []

        ev_writer = EvidenceItem(
            kind="source_location",
            file=writer_file,
            map="authority_map",
        )
        evidence_items.append(json.dumps(ev_writer.to_dict(), sort_keys=True))

        ev_target = EvidenceItem(
            kind="target_path",
            path=path_constructor_target,
            map="authority_map",
        )
        evidence_items.append(json.dumps(ev_target.to_dict(), sort_keys=True))

        ev_conflict = EvidenceItem(
            kind="map_entry",
            map="conflict_map",
            entry_id=getattr(conflict, "conflict_id", ""),
            file=writer_file,
        )
        evidence_items.append(json.dumps(ev_conflict.to_dict(), sort_keys=True))

        details = f"target={path_constructor_target}"
        finding_id = _make_finding_id("write_authority_violation", writer_file, details)
        severity = "high"
        lifecycle = _get_lifecycle_status(finding_id, severity, prev_by_id)

        canonical_owner = getattr(auth_domain, "canonical_owner", authority_domain_name)

        finding = Finding(
            finding_id=finding_id,
            category="write_authority_violation",
            title=(
                f"Illegal write by '{writer_file}' to path_constructor target "
                f"in domain '{authority_domain_name}'"
            ),
            severity=severity,
            confidence=min(conflict.confidence, 0.9),
            why_it_matters=(
                f"The file writes to a statically-verifiable path ({path_constructor_target}) "
                f"that belongs to domain '{authority_domain_name}' (canonical owner: "
                f"{canonical_owner}), bypassing authority controls."
            ),
            suggested_fix=(
                f"Add '{writer_file}' to allowed_writers for domain "
                f"'{authority_domain_name}', or refactor writes through the canonical "
                f"owner ({canonical_owner})."
            ),
            affected_files=tuple(sorted({writer_file, path_constructor_target})),
            evidence=tuple(evidence_items),
            source_maps=("authority_map", "conflict_map"),
            finding_status=lifecycle,
            source="synthesis",
            freshness="",
            status="validated",
        )
        findings.append(finding)

    _log.debug("_find_write_authority_violations: %d findings", len(findings))
    return findings
