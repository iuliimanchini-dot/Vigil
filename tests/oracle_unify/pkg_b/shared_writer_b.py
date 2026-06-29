"""Shared-target writer B (module prefix pkg_b).

Writes to shared/state.json -- the SAME resolved target as pkg_a/shared_writer_a,
from a DIFFERENT module prefix, triggering shared-write auto-discovery.
"""
from __future__ import annotations

from pathlib import Path


def persist_b(payload: str) -> None:
    target = Path("shared/state.json")
    target.write_text(payload)
