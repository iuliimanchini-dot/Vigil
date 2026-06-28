"""Fingerprint utilities for the map builder subsystem.

Provides stable, deterministic identifiers for conflict entries and schema hashes.
"""
from __future__ import annotations

import hashlib
import json
import logging

__all__ = [
    "make_conflict_id",
    "map_schema_hash",
]

_log = logging.getLogger(__name__)


def make_conflict_id(domain: str, subject: str, sources: list[dict]) -> str:
    """Compute a stable conflict identifier from domain, subject and sources.

    Sources are sorted by (map, claim) before hashing so that insertion
    order does not affect the result.

    Returns: ``"conf_" + first 12 hex digits of SHA-256``.
    """
    canonical = json.dumps(
        {
            "domain": domain,
            "subject": subject,
            "sources": sorted(sources, key=lambda s: (s.get("map", ""), s.get("claim", ""))),
        },
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    )
    digest = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
    conflict_id = "conf_" + digest[:12]
    _log.debug("make_conflict_id: domain=%s subject=%s -> %s", domain, subject, conflict_id)
    return conflict_id


def map_schema_hash(entries: list[dict]) -> str:
    """Compute a 16-hex-char hash over the union of field names across all entries.

    This detects schema drift (field additions/removals) between builds
    without comparing values.
    """
    all_fields = sorted({f for e in entries for f in e.keys()})
    digest = hashlib.sha256(json.dumps(all_fields).encode("utf-8")).hexdigest()
    schema_hash = digest[:16]
    _log.debug("map_schema_hash: %d entries, %d distinct fields -> %s", len(entries), len(all_fields), schema_hash)
    return schema_hash
