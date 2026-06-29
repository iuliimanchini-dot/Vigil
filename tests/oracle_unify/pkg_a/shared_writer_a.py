"""Shared-target writer A (module prefix pkg_a).

Writes to shared/state.json -- the SAME resolved target as pkg_b/shared_writer_b.
This pins the seed-free shared-write auto-discovery cluster path
(_auto_discover_domains: 2+ writers from different module prefixes).
"""
from __future__ import annotations

from pathlib import Path


def persist_a(payload: str) -> None:
    p = Path("shared/state.json")
    p.write_text(payload)
