"""Public API for the map builder subsystem.

Deferred (lazy) imports only -- avoids circular import chains during
early startup before map_models/map_storage are fully initialised.

Public surface:
    build_all_maps(project_dir)  -- stub, implemented in Phase 7 (cli_entry.py)
    load_repo_maps(project_dir)  -- load all 7 maps from disk
    maps_dir(project_dir)        -- default output dir: <project_dir>/.cortex/maps/
    seeds_dir(project_dir)       -- default seeds dir: <project_dir>/.cortex/map_seeds/
    RepoMaps                     -- container dataclass
"""
from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .map_models import RepoMaps as _RepoMaps

__all__ = [
    "build_all_maps",
    "load_repo_maps",
    "maps_dir",
    "run_map_build",
    "seeds_dir",
    "RepoMaps",
]


def load_repo_maps(project_dir: Path):
    """Load all 7 maps from <project_dir>/.cortex/maps/. Deferred import."""
    from .map_storage import load_repo_maps as _load  # noqa: PLC0415
    return _load(project_dir)


def maps_dir(project_dir: Path) -> Path:
    """Default output location: <project_dir>/.cortex/maps/. Deferred import."""
    from .map_storage import maps_dir as _maps_dir  # noqa: PLC0415
    return _maps_dir(project_dir)


def seeds_dir(project_dir: Path) -> Path:
    """Default seed config location: <project_dir>/.cortex/map_seeds/. Deferred import."""
    from .map_storage import seeds_dir as _seeds_dir  # noqa: PLC0415
    return _seeds_dir(project_dir)


def build_all_maps(project_dir: Path) -> None:
    """Build all maps (stub -- full implementation in Phase 7 cli_entry.py).

    Currently raises NotImplementedError so callers discover the gap early.
    """
    raise NotImplementedError(
        "build_all_maps is not implemented yet. "
        "Use 'python -m SYSTEM.runtime.app map-build' after Phase 7."
    )


def run_map_build(
    project_dir,
    *,
    map: str = "all",
    dry_run: bool = False,
    strict: bool = False,
    timeout_s: int = 300,
    output_dir=None,
) -> int:
    """Programmatic API for the map build pipeline. Deferred import.

    See ``BRAIN.autoforensics.map_builder.cli_entry.run_map_build`` for full docs.
    """
    from .cli_entry import run_map_build as _run  # noqa: PLC0415
    return _run(
        project_dir,
        map=map,
        dry_run=dry_run,
        strict=strict,
        timeout_s=timeout_s,
        output_dir=output_dir,
    )


def __getattr__(name: str):
    if name == "RepoMaps":
        from .map_models import RepoMaps  # noqa: PLC0415
        return RepoMaps
    raise AttributeError("module %r has no attribute %r" % (__name__, name))
