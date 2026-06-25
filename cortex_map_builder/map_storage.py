"""Atomic read/write, filelock-wrapped map storage for the map builder subsystem.

Generic design: all output goes to <project_dir>/.cortex/maps/ by default.
This works for any target project (user project, or Vigil self-diag via
`--project ./`).

Atomic write pattern (tempfile.mkstemp + os.replace):
    fd, tmp_path = tempfile.mkstemp(dir=..., prefix=..., suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(payload, fh, ...) ; fh.write("\\n")
        os.replace(tmp_path, target)
    except BaseException:
        try: os.unlink(tmp_path)
        except OSError: pass
        raise
"""
from __future__ import annotations

import json
import logging
import os
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

from .map_common import MAPS_SUBDIR, SEEDS_SUBDIR
from .map_errors import MapConcurrencyError, MapSecurityError
from .map_models import (
    AuthorityDomain,
    BuildMeta,
    DataContractEntry,
    RepoMaps,
    RuntimeNode,
    StructuralEntry,
)
from .map_models_ext import ConflictEntry, HotspotEntry, RefactorBoundary
from .map_models_findings import Finding

__all__ = [
    "BuildMeta",
    "load_repo_maps",
    "write_map",
    "regenerate_index",
    "maps_dir",
    "seeds_dir",
]

_log = logging.getLogger(__name__)

# Map filenames (relative to maps_dir(project_dir))
_MAP_FILES: dict[str, str] = {
    "structural": "10_structural_map.json",
    "runtime": "20_runtime_map.json",
    "data_contract": "30_data_contract_map.json",
    "authority": "40_authority_map.json",
    "conflict": "50_conflict_map.json",
    "hotspot": "60_hotspot_map.json",
    "findings": "80_findings_map.json",
    "refactor_boundary": "70_refactor_boundaries.json",
}

_INDEX_FILE = "00_map_index.json"


# ---------------------------------------------------------------------------
# Path helpers (public — exposed in __all__ and __init__.py)
# ---------------------------------------------------------------------------

def maps_dir(project_dir: Path) -> Path:
    """Default output location: <project_dir>/.cortex/maps/"""
    return project_dir.resolve() / MAPS_SUBDIR


def seeds_dir(project_dir: Path) -> Path:
    """Default seed config location: <project_dir>/.cortex/map_seeds/"""
    return project_dir.resolve() / SEEDS_SUBDIR


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _check_path_security(project_dir: Path, target: Path) -> None:
    """Verify target is inside project_dir. Raises MapSecurityError otherwise."""
    project_dir_resolved = project_dir.resolve(strict=False)
    target_resolved = target.resolve(strict=False)
    try:
        target_resolved.relative_to(project_dir_resolved)
    except ValueError:
        raise MapSecurityError(
            "Path escape attempt: %s is not inside %s" % (target, project_dir)
        )


def _atomic_write_json(path: Path, payload: dict) -> None:
    """Write payload to path atomically via tempfile + os.replace.

    Pattern mirrors SYSTEM/runtime/runtime_lock.py::acquire().
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_path = tempfile.mkstemp(
        dir=str(path.parent),
        prefix=".map_",
        suffix=".tmp",
    )
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(json.dumps(payload, indent=2, ensure_ascii=False, sort_keys=True))
            fh.write("\n")
        os.replace(tmp_path, str(path))
    except BaseException:
        try:
            os.unlink(tmp_path)
        except OSError as exc:
            _log.error("map_storage: cleanup failed for %s: %s", tmp_path, exc)
        raise
    _log.debug("_atomic_write_json: wrote %s", path)


def _read_json(path: Path) -> Optional[dict]:
    """Read JSON from path.

    Returns:
        dict  -- file exists and parses cleanly.
        None  -- file does not exist (legitimate absent state).

    Raises:
        OSError / UnicodeDecodeError -- I/O failure reading an existing file.
        ValueError                  -- file exists but contains invalid JSON or
                                      a non-dict top-level value (corrupt map).
    """
    if not path.exists():
        _log.debug("_read_json: file not found: %s", path)
        return None
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        _log.error("_read_json: I/O error reading %s: %s", path, exc)
        raise
    try:
        data = json.loads(text)
    except json.JSONDecodeError as exc:
        _log.error("_read_json: corrupt JSON in %s: %s", path, exc)
        raise ValueError("%s is corrupt: %s" % (path, exc)) from exc
    if not isinstance(data, dict):
        msg = "_read_json: expected dict, got %s in %s" % (type(data).__name__, path)
        _log.error(msg)
        raise ValueError(msg)
    return data


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def load_repo_maps(project_dir: Path) -> RepoMaps:
    """Load all 8 maps from <project_dir>/.cortex/maps/.

    Returns RepoMaps(missing=True) if the maps directory is absent.
    """
    mdir = maps_dir(project_dir)
    if not mdir.is_dir():
        _log.info("load_repo_maps: maps directory absent at %s -- returning missing=True", mdir)
        return RepoMaps(missing=True)

    def _load_entries(name: str, from_dict_fn):
        filename = _MAP_FILES[name]
        path = mdir / filename
        payload = _read_json(path)
        if payload is None:
            _log.warning("load_repo_maps: map file absent or corrupt: %s", filename)
            return ()
        entries_raw = payload.get("entries", [])
        result = []
        for raw in entries_raw:
            try:
                result.append(from_dict_fn(raw))
            except (KeyError, TypeError, ValueError) as exc:
                _log.warning("load_repo_maps: skipping corrupt entry in %s: %s", filename, exc)
        return tuple(result)

    structural = _load_entries("structural", StructuralEntry.from_dict)
    runtime = _load_entries("runtime", RuntimeNode.from_dict)
    data_contract = _load_entries("data_contract", DataContractEntry.from_dict)
    authority = _load_entries("authority", AuthorityDomain.from_dict)
    conflict = _load_entries("conflict", ConflictEntry.from_dict)
    hotspot = _load_entries("hotspot", HotspotEntry.from_dict)
    refactor_boundary = _load_entries("refactor_boundary", RefactorBoundary.from_dict)

    # Load findings (Map 8)
    findings_list: list[Finding] = []
    findings_path = mdir / _MAP_FILES["findings"]
    if findings_path.exists():
        try:
            payload = json.loads(findings_path.read_text(encoding="utf-8"))
            for raw_entry in payload.get("entries", []):
                try:
                    findings_list.append(Finding.from_dict(raw_entry))
                except (KeyError, TypeError, ValueError) as exc:
                    _log.warning("load_repo_maps: skipping corrupt finding entry: %s", exc)
        except (OSError, json.JSONDecodeError, ValueError, KeyError) as exc:
            _log.warning("load_repo_maps: failed to load findings from %s: %s", findings_path, exc)

    _log.info(
        "load_repo_maps: loaded structural=%d runtime=%d data_contract=%d "
        "authority=%d conflict=%d hotspot=%d boundary=%d findings=%d",
        len(structural), len(runtime), len(data_contract),
        len(authority), len(conflict), len(hotspot), len(refactor_boundary),
        len(findings_list),
    )
    return RepoMaps(
        structural=structural,
        runtime=runtime,
        data_contract=data_contract,
        authority=authority,
        conflict=conflict,
        hotspot=hotspot,
        refactor_boundary=refactor_boundary,
        findings=tuple(findings_list),
        missing=False,
    )


def write_map(
    project_dir: Path,
    name: str,
    entries: list,
    metadata: dict,
    *,
    build_meta: BuildMeta | None = None,
    maps_dir_override: Path | None = None,
) -> None:
    """Atomically write a named map with filelock protection.

    Output path: <maps_dir>/<filename>.json (maps_dir defaults to
        <project_dir>/.cortex/maps/ or maps_dir_override if given).
    Lock path:   <maps_dir>/.<name>.lock

    Args:
        project_dir: Absolute path to the target project root. Used for the
            default maps directory and security checks when no override given.
        name: Map name key (e.g. "structural"). Must be in _MAP_FILES.
        entries: List of entry dicts to write under the "entries" key.
        metadata: Additional top-level keys merged into the payload
                  (e.g. schema_version, produced_by, trace_status).
        build_meta: Optional BuildMeta instance. When provided, adds a
            top-level "build_meta" key and sets schema_version to "2.0.0".
            When None, schema_version remains "1.0.0" (backward compat).
        maps_dir_override: If given, writes to this directory instead of
            <project_dir>/.cortex/maps/. The directory is created if absent.
            Security check is performed against this directory's own resolved
            path (not project_dir) so temp dirs are allowed.

    Raises:
        MapConcurrencyError: If filelock timeout exceeded.
        MapSecurityError: If computed path escapes the target dir.
        KeyError: If name is not a known map name.
    """
    try:
        from filelock import FileLock, Timeout as FileLockTimeout
    except ImportError as exc:
        raise ImportError("filelock is required: %s" % exc) from exc

    if name not in _MAP_FILES:
        raise KeyError("Unknown map name: %s. Known names: %s" % (name, list(_MAP_FILES)))

    if maps_dir_override is not None:
        mdir = maps_dir_override.resolve()
        target_path = mdir / _MAP_FILES[name]
        lock_path = mdir / (".%s.lock" % name)
        # Security check: target must stay inside the override dir
        try:
            target_path.relative_to(mdir)
        except ValueError:
            from .map_errors import MapSecurityError
            raise MapSecurityError(
                "Path escape attempt: %s is not inside override dir %s" % (target_path, mdir)
            )
    else:
        mdir = maps_dir(project_dir)
        target_path = mdir / _MAP_FILES[name]
        lock_path = mdir / (".%s.lock" % name)
        # Security check before acquiring lock
        _check_path_security(project_dir, target_path)
        _check_path_security(project_dir, lock_path)

    mdir.mkdir(parents=True, exist_ok=True)

    payload: dict[str, Any] = {
        "schema_version": "1.0.0",
        "produced_by": "cortex_map_builder.v1",
    }
    payload.update(metadata)
    payload["entries"] = entries

    # Embed build_meta if provided.  The payload schema_version stays at
    # "1.0.0" for backward-compat with validators (e.g. refactor_boundary_builder
    # enforces major ≤ 1).  The PRESENCE of "build_meta" is the v2.0.0 signal;
    # regenerate_index reads it to populate the index and emits schema_version
    # "2.0.0" in the per-map index entry when build_meta is present.
    if build_meta is not None:
        payload["build_meta"] = build_meta.to_dict()

    _log.debug("write_map: acquiring lock for %s", name)
    try:
        with FileLock(str(lock_path), timeout=10):
            _log.debug("write_map: lock acquired for %s", name)
            _atomic_write_json(target_path, payload)
    except FileLockTimeout as exc:
        _log.error("write_map: filelock timeout for map %s: %s", name, exc)
        raise MapConcurrencyError(
            "Filelock timeout (10s) for map %s -- another writer may be running" % name
        ) from exc

    _log.info("write_map: wrote %s (%d entries)", name, len(entries))


def regenerate_index(
    project_dir: Path,
    *,
    maps_dir_override: Path | None = None,
) -> None:
    """Rebuild 00_map_index.json from existing map files on disk.

    Structure per plan sec.9 Observability Contract.
    Output: <maps_dir>/00_map_index.json (default: <project_dir>/.cortex/maps/).

    Args:
        project_dir: Absolute path to the target project root.
        maps_dir_override: If given, reads maps from and writes index to this
            directory instead of <project_dir>/.cortex/maps/.
    """
    if maps_dir_override is not None:
        mdir = maps_dir_override.resolve()
    else:
        mdir = maps_dir(project_dir)
    mdir.mkdir(parents=True, exist_ok=True)

    from .fingerprint import map_schema_hash

    built_at = (
        datetime.now(timezone.utc)
        .isoformat()
        .replace("+00:00", "Z")
    )

    maps_section: dict[str, Any] = {}
    total_entries = 0
    warnings_count = 0
    errors_count = 0
    all_schema_versions: list[str] = []
    # Accumulate language -> {map_name: bool} across all maps for the matrix.
    # Key: language string. Value: dict mapping each map name to True/False.
    _lang_support: dict[str, dict[str, bool]] = {}

    for name, filename in _MAP_FILES.items():
        path = mdir / filename
        payload = _read_json(path)
        if payload is None:
            warnings_count += 1
            maps_section[name] = {"status": "missing"}
            continue

        entries = payload.get("entries", [])
        entry_count = len(entries)
        total_entries += entry_count
        schema_ver = payload.get("schema_version", "0.0.0")
        all_schema_versions.append(schema_ver)

        schema_hash_val = map_schema_hash(entries) if entries else ""
        file_bytes = path.stat().st_size if path.exists() else 0

        # Derive per-map index entry from build_meta if present (v2.0.0),
        # otherwise emit a legacy sentinel (v1.0.0 payloads without build_meta).
        raw_build_meta = payload.get("build_meta")
        if raw_build_meta is not None:
            bm = BuildMeta.from_dict(raw_build_meta)
            supported_langs: list[str] = bm.coverage.get("supported_languages", [])

            # Accumulate into the cross-map language support matrix.
            all_langs = set(bm.coverage.get("files_scanned_by_lang", {}).keys()) | set(supported_langs)
            for lang in all_langs:
                if lang not in _lang_support:
                    _lang_support[lang] = {}
                _lang_support[lang][name] = lang in supported_langs

            map_entry: dict[str, Any] = {
                "analysis_mode": bm.analysis_mode,
                # build_duration_s and built_at are in semantic_diff._IGNORED_FIELDS,
                # so they are stripped during I2 determinism checks.
                "build_duration_s": bm.duration_s,
                "built_at": bm.built_at,
                "confidence_avg": bm.confidence_avg,
                "coverage_ratio": bm.coverage.get("coverage_ratio", 0.0),
                "entry_count": entry_count,
                # file_bytes is in _IGNORED_FIELDS (size jitters with duration precision).
                "file_bytes": file_bytes,
                "languages_detected": bm.coverage.get("files_scanned_by_lang", {}),
                "producer": bm.producer,
                "reason": bm.reason,
                "schema_hash": schema_hash_val,
                "schema_version": "2.0.0",  # build_meta presence signals v2
                "supported_languages": supported_langs,
                "status": bm.status,
            }
            # 5.3: surface unsupported_files_sample when the build_meta contains it.
            if bm.unsupported_files_sample:
                map_entry["unsupported_files_sample"] = list(bm.unsupported_files_sample)
            maps_section[name] = map_entry
        else:
            # Legacy v1.0.0 payload — no build_meta present.
            maps_section[name] = {
                "entry_count": entry_count,
                "file_bytes": file_bytes,
                "schema_hash": schema_hash_val,
                "schema_version": "1.0.0",
                "status": "legacy",
            }

    schema_versions_all_equal = len(set(all_schema_versions)) <= 1

    # 5.1: Build per-language support matrix across all 7 maps.
    # For each language seen in any map, record True/False per map name.
    # Maps absent from a language's accumulator are filled with False.
    all_map_names = list(_MAP_FILES.keys())
    language_support: dict[str, dict[str, bool]] = {
        lang: {mn: _lang_support[lang].get(mn, False) for mn in all_map_names}
        for lang in sorted(_lang_support)
    }

    index_payload: dict[str, Any] = {
        "schema_version": "1.0.0",
        "produced_by": "cortex_map_builder.v1",
        "built_at": built_at,
        "pipeline_success": errors_count == 0,
        "maps": maps_section,
        "global": {
            "total_entries": total_entries,
            "schema_versions_all_equal": schema_versions_all_equal,
            "warnings_count": warnings_count,
            "errors_count": errors_count,
            "language_support": language_support,
        },
    }

    index_path = mdir / _INDEX_FILE
    if maps_dir_override is None:
        _check_path_security(project_dir, index_path)
    _atomic_write_json(index_path, index_payload)
    _log.info(
        "regenerate_index: total_entries=%d warnings=%d errors=%d",
        total_entries, warnings_count, errors_count,
    )
