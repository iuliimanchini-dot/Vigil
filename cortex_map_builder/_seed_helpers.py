"""Shared helpers for seed bootstrap and adoption modules.

Extracted to avoid circular imports between seed_bootstrapper <-> seed_adoption.
Not a public API -- consumers are seed_bootstrapper.py and seed_adoption.py only.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .map_storage import _atomic_write_json
import logging
_log = logging.getLogger(__name__)

# Required top-level key per seed type (in addition to schema_version)
SEED_REQUIRED_KEY: dict[str, str] = {
    "authority_domains": "domains",
    "sanctioned_assets": "patterns",
    "data_contract_priorities": "priority_entities",
}


def validate_seed_schema(seed_name: str, data: Any) -> bool:
    """Minimal validation: schema_version present + required top-level key."""
    if not isinstance(data, dict):
        return False
    if "schema_version" not in data:
        return False
    required_key = SEED_REQUIRED_KEY.get(seed_name)
    if required_key and required_key not in data:
        return False
    return True


def gather_minimal_context(project_dir: Path) -> dict[str, str]:
    """Lightweight 2-level directory tree + pyproject.toml snippet."""
    tree_lines: list[str] = []
    try:
        skip_names = {"__pycache__", "node_modules", "venv", ".venv", ".git"}
        for entry in sorted(project_dir.iterdir()):
            if entry.name.startswith(".") or entry.name in skip_names:
                continue
            tree_lines.append(entry.name + ("/" if entry.is_dir() else ""))
            if entry.is_dir():
                try:
                    for sub in sorted(entry.iterdir())[:20]:
                        if sub.name.startswith(".") or sub.name in skip_names:
                            continue
                        tree_lines.append(
                            "  " + sub.name + ("/" if sub.is_dir() else "")
                        )
                except (OSError, PermissionError):
                    continue
    except (OSError, PermissionError):
        pass

    pyproj_path = project_dir / "pyproject.toml"
    pyproj = (
        pyproj_path.read_text(encoding="utf-8")[:2000]
        if pyproj_path.exists()
        else ""
    )
    return {"tree": "\n".join(tree_lines), "pyproject": pyproj}


def load_seed_state(state_path: Path) -> dict[str, Any]:
    """Load .bootstrap_state.json; return empty scaffold if missing or corrupt."""
    if not state_path.exists():
        return {"schema_version": "1.0.0", "seeds": {}}
    try:
        data = json.loads(state_path.read_text(encoding="utf-8"))
        if not isinstance(data, dict):
            return {"schema_version": "1.0.0", "seeds": {}}
        return data
    except (json.JSONDecodeError, OSError):
        return {"schema_version": "1.0.0", "seeds": {}}


def save_seed_state(state_path: Path, state: dict[str, Any]) -> None:
    """Persist bootstrap/adoption state atomically."""
    _atomic_write_json(state_path, state)
