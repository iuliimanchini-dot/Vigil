"""CLI entry point for the map builder subsystem.

cmd_map_build(args) is called from the Vigil app dispatcher.
Returns an integer exit code (never calls sys.exit directly).

Exit codes:
    0   -- success, pipeline_success=true
    1   -- application error (exception in builder or subprocess)
    2   -- validation error (bad args, path issues)
    3   -- strict mode: warnings detected
    4   -- strict mode: new conflicts detected
    124 -- (reserved) timeout; tracer timeout uses --timeout-s

Design note: conflict and hotspot builders depend on prior maps (structural,
runtime, authority, data_contract). When building all maps in sequence the
pipeline keeps an in-memory accumulator (RepoMaps) so conflict/hotspot do not
need to re-read from disk. This also makes --dry-run work correctly: no files
are written, but downstream builders still receive the freshly built entries.
"""
from __future__ import annotations

import argparse
import json
import logging
import re
import sys
import time
from pathlib import Path
from typing import Any

_log = logging.getLogger(__name__)

# Map names in dependency order:
# - conflict+hotspot depend on structural/runtime/authority/data_contract
# - findings depends on all 7 maps (includes hotspot)
# - refactor_boundary may depend on findings (auto-inferred boundaries use SCC + hotspot)
_ALL_MAPS_ORDERED = [
    "structural",
    "data_contract",
    "authority",
    "runtime",
    "conflict",
    "hotspot",
    "findings",
    "refactor_boundary",
]

_ANSI_RE = re.compile(r"\033\[[0-9;]*m")


def _strip_ansi(text: str) -> str:
    return _ANSI_RE.sub("", text)


def _print_line(msg: str, no_color: bool = False, file=None) -> None:
    """Print to stdout (or file). Strips ANSI if --no-color."""
    if no_color:
        msg = _strip_ansi(msg)
    if file is not None:
        print(msg, file=file)
    else:
        print(msg)


def _build_metadata(map_name: str, duration_s: float) -> dict[str, Any]:
    """Build standard metadata dict for write_map."""
    from datetime import datetime, timezone
    built_at = (
        datetime.now(timezone.utc)
        .isoformat()
        .replace("+00:00", "Z")
    )
    return {
        "built_at": built_at,
        "build_duration_s": round(duration_s, 2),
        "map_name": map_name,
    }


def _scan_project_files_by_lang(project_dir: Path) -> dict[str, int]:
    """Scan project_dir once and return {language: file_count} via ADAPTERS.

    Called ONCE per full build in cmd_map_build to ensure all maps in the
    same build share a consistent file-count snapshot (determinism for I2).
    """
    from .map_common import iter_source_files
    from .source_adapters import ADAPTERS

    files_by_lang: dict[str, int] = {}
    for f in iter_source_files(project_dir):
        ext = f.suffix.lower()
        if ext in ADAPTERS:
            lang = ADAPTERS[ext].language
            files_by_lang[lang] = files_by_lang.get(lang, 0) + 1
    return files_by_lang


def _authority_conflict_build_meta_kwargs(
    map_name: str,
    files_by_lang: dict[str, int],
) -> dict:
    """Return keyword overrides for _build_build_meta when coverage is partial.

    Computes coverage_ratio from files_by_lang. If ratio < 1.0, emits
    analysis_mode / status / reason reflecting honest partial coverage.

    Returns an empty dict when coverage is 1.0 (pure Python project) so the
    defaults in _build_build_meta remain unchanged.
    """
    py_count = files_by_lang.get("python", 0)
    total = sum(files_by_lang.values())
    if total == 0 or py_count == total:
        return {}  # full coverage or empty project -- no override needed

    non_py = total - py_count
    ratio = py_count / total  # coverage_ratio (same formula as _build_build_meta)

    if map_name == "authority":
        return {
            "analysis_mode": "python_ast+seed_only",
            "status": "partial",
            "reason": (
                f"Authority writer detection covers {py_count} Python file(s) via AST; "
                f"{non_py} non-Python file(s) covered by seed only "
                f"(writer detectors arrive in Phase L7a). "
                f"coverage_ratio={ratio:.2f}"
            ),
        }
    if map_name == "conflict":
        return {
            "analysis_mode": "python_ast+seed_only",
            "status": "partial",
            "reason": (
                f"partial_upstream_limited: authority coverage_ratio={ratio:.2f}; "
                f"{non_py} non-Python file(s) not analysed for write conflicts."
            ),
        }
    return {}


def _build_build_meta(
    map_name: str,
    duration_s: float,
    project_dir: Path,
    producer_module: str,
    files_by_lang: dict[str, int],
    *,
    analysis_mode: str = "python_ast",
    status: str = "ok",
    reason: str = "",
    confidence_avg: float = 1.0,
) -> "Any":
    """Construct a BuildMeta for a given map.

    Args:
        files_by_lang: Pre-computed {language: count} from _scan_project_files_by_lang.
            Passed in rather than re-computed per map to ensure all maps in a
            single build share a consistent file-count snapshot (I2 determinism).
    """
    from datetime import datetime, timezone

    from .map_common import get_coverage_metadata
    from .map_models import BuildMeta

    built_at = (
        datetime.now(timezone.utc)
        .isoformat()
        .replace("+00:00", "Z")
    )

    coverage_meta = get_coverage_metadata(map_name)
    supported_languages = coverage_meta.get("supported_languages", [])
    files_supported: dict[str, int] = {
        lang: files_by_lang.get(lang, 0)
        for lang in supported_languages
    }
    total_scanned = sum(files_by_lang.values())
    total_supported = sum(files_supported.values())
    coverage_ratio = (total_supported / total_scanned) if total_scanned > 0 else 0.0

    return BuildMeta(
        analysis_mode=analysis_mode,
        status=status,
        reason=reason,
        confidence_avg=confidence_avg,
        coverage={
            "files_scanned_by_lang": files_by_lang,
            "files_supported_by_lang": files_supported,
            "coverage_ratio": coverage_ratio,
            "supported_languages": supported_languages,
        },
        producer=producer_module,
        built_at=built_at,
        duration_s=round(duration_s, 3),
    )


def _make_repo_maps_from_accumulator(acc: dict[str, list]) -> Any:
    """Build a RepoMaps from accumulated in-memory entry objects.

    acc keys: structural, runtime, data_contract, authority, conflict, hotspot, refactor_boundary.
    Values are lists of *entry objects* (dataclass instances), not dicts.
    """
    from .map_models import RepoMaps
    return RepoMaps(
        structural=tuple(acc.get("structural", ())),
        runtime=tuple(acc.get("runtime", ())),
        data_contract=tuple(acc.get("data_contract", ())),
        authority=tuple(acc.get("authority", ())),
        conflict=tuple(acc.get("conflict", ())),
        hotspot=tuple(acc.get("hotspot", ())),
        refactor_boundary=tuple(acc.get("refactor_boundary", ())),
        missing=False,
    )


def _build_single_map(
    map_name: str,
    project_dir: Path,
    timeout_s: int,
    runtime_target: str | None,
    in_memory_acc: dict[str, list],
    parse_cache: "Any | None" = None,
    maps_dir_override: Path | None = None,
    cancel_event: "Any | None" = None,
) -> tuple[list, list, dict, bool]:
    """Build one named map. Returns (entry_objects, entry_dicts, metadata, had_warning).

    entry_objects -- raw dataclass instances (for in-memory accumulator).
    entry_dicts   -- serialised dicts ready for write_map / dry-run logging.
    metadata      -- metadata dict for write_map.
    had_warning   -- True if the builder emitted a degraded-mode warning.
    parse_cache   -- optional ParseCacheL1 instance; passed through to builders
                     that support it (structural, runtime, data_contract, authority).
    maps_dir_override -- optional override for maps directory (for --output-dir).
    cancel_event  -- optional threading.Event; builder stops early when set.
    """
    t0 = time.perf_counter()
    had_warning = False

    if map_name == "structural":
        from .structural_builder import build_structural_map
        entries_obj = build_structural_map(
            project_dir, parse_cache=parse_cache, cancel_event=cancel_event
        )

    elif map_name == "data_contract":
        from .data_contract_builder import build_data_contract_map
        entries_obj = build_data_contract_map(project_dir, parse_cache=parse_cache)

    elif map_name == "authority":
        from .authority_builder import build_authority_map
        entries_obj = build_authority_map(project_dir, parse_cache=parse_cache)

    elif map_name == "runtime":
        if runtime_target:
            from .runtime_builder import build_runtime_map_full
            entries_obj, _extra = build_runtime_map_full(
                project_dir,
                target_module=runtime_target,
                timeout_s=float(min(timeout_s, 90)),
            )
        else:
            from .runtime_builder import build_runtime_map_static
            entries_obj = build_runtime_map_static(project_dir, parse_cache=parse_cache)

    elif map_name == "refactor_boundary":
        from .refactor_boundary_builder import load_refactor_seeds, infer_refactor_boundaries

        # Step 1: Load manual seeds (user-authored, persistent)
        seed_boundaries = load_refactor_seeds(project_dir)

        # Step 2: ALWAYS infer auto-boundaries (deterministic from repo maps)
        if in_memory_acc:
            repo_maps = _make_repo_maps_from_accumulator(in_memory_acc)
            auto_boundaries = infer_refactor_boundaries(repo_maps)
        else:
            from .map_storage import load_repo_maps
            repo_maps = load_repo_maps(project_dir)
            auto_boundaries = infer_refactor_boundaries(repo_maps) if not repo_maps.missing else []

        # Step 3: Merge: seed entries override auto-inferred for same files
        # Seeds have higher priority and appear first
        entries_obj = []

        # Collect auto-inferred boundary file sets
        auto_file_sets: set[tuple[str, ...]] = set()
        for auto_b in auto_boundaries:
            # Use allowed_files + forbidden_files as the identity
            file_set = tuple(sorted(set(auto_b.allowed_files) | set(auto_b.forbidden_files)))
            auto_file_sets.add(file_set)

        # Add seed entries first (they have priority)
        entries_obj.extend(seed_boundaries)

        # Track which file sets are already covered by seeds
        seed_file_sets: set[tuple[str, ...]] = set()
        for seed_b in seed_boundaries:
            file_set = tuple(sorted(set(seed_b.allowed_files) | set(seed_b.forbidden_files)))
            seed_file_sets.add(file_set)

        # Add auto-inferred entries that don't conflict with seeds
        for auto_b in auto_boundaries:
            file_set = tuple(sorted(set(auto_b.allowed_files) | set(auto_b.forbidden_files)))
            if file_set not in seed_file_sets:
                entries_obj.append(auto_b)

    elif map_name == "conflict":
        # Prefer in-memory accumulator; fall back to disk if running single-map mode
        if in_memory_acc:
            repo_maps = _make_repo_maps_from_accumulator(in_memory_acc)
        else:
            from .map_storage import load_repo_maps
            repo_maps = load_repo_maps(project_dir)
            if repo_maps.missing:
                _log.warning(
                    "conflict builder: no maps found at %s/.cortex/maps/ "
                    "-- building with empty inputs",
                    project_dir,
                )
                had_warning = True
        from .conflict_builder import build_conflict_map
        entries_obj = build_conflict_map(repo_maps)

    elif map_name == "hotspot":
        # Prefer in-memory accumulator; fall back to disk if running single-map mode
        if in_memory_acc:
            repo_maps = _make_repo_maps_from_accumulator(in_memory_acc)
        else:
            from .map_storage import load_repo_maps
            repo_maps = load_repo_maps(project_dir)
            if repo_maps.missing:
                _log.warning(
                    "hotspot builder: no maps found at %s/.cortex/maps/ "
                    "-- building with empty inputs",
                    project_dir,
                )
                had_warning = True
        from .hotspot_builder import build_hotspot_map, compute_hotspot_churn_metadata
        _churn_data, _churn_meta = compute_hotspot_churn_metadata(project_dir)
        entries_obj = build_hotspot_map(repo_maps, churn_data=_churn_data)

    elif map_name == "findings":
        # Prefer in-memory accumulator; fall back to disk if running single-map mode
        if in_memory_acc:
            repo_maps = _make_repo_maps_from_accumulator(in_memory_acc)
        else:
            from .map_storage import load_repo_maps
            repo_maps = load_repo_maps(project_dir)
            if repo_maps.missing:
                _log.warning(
                    "findings builder: no maps found at %s/.cortex/maps/ "
                    "-- building with empty inputs",
                    project_dir,
                )
                had_warning = True
        from .findings_builder import build_findings_map
        entries_obj = build_findings_map(project_dir, repo_maps, maps_dir_override=maps_dir_override)

    else:
        raise ValueError("Unknown map name: %s" % map_name)

    duration = time.perf_counter() - t0
    metadata = _build_metadata(map_name, duration)
    # For hotspot: embed churn audit fields so cmd_map_build can write them to index.
    if map_name == "hotspot":
        metadata.update(_churn_meta)  # type: ignore[possibly-undefined]
    entry_dicts = [e.to_dict() for e in entries_obj]
    return entries_obj, entry_dicts, metadata, had_warning


def _maybe_materialize_remote_tree(project_dir: Path) -> Path:
    """Remote tree materialization not available in standalone mode."""
    return project_dir


def cmd_map_build(args: argparse.Namespace) -> int:
    """Entry point called from dispatch. Returns exit code (never sys.exit)."""

    # 1. Validate --project
    project_str = getattr(args, "project", None)
    if not project_str:
        _log.error("--project is required")
        print("[ERR] --project is required", file=sys.stderr)
        return 2

    project_dir = Path(project_str).resolve()
    if not project_dir.exists():
        _log.error("--project path does not exist: %s", project_dir)
        print("[ERR] --project path does not exist: %s" % project_dir, file=sys.stderr)
        return 2
    if not project_dir.is_dir():
        _log.error("--project path is not a directory: %s", project_dir)
        print("[ERR] --project path is not a directory: %s" % project_dir, file=sys.stderr)
        return 2

    # X2.1: when transport_mode=remote_authoritative, materialize a
    # tarball of the SERVER tree into a local cache and run builders
    # against that. Local copy is a thin client and would yield stale
    # maps. ``sync_fallback`` and missing-contract paths use the local
    # copy as before (it IS the truth in those modes).
    real_project_dir = project_dir  # save original before possible materialize
    project_dir = _maybe_materialize_remote_tree(project_dir)

    # 2. Configure logging
    verbose = bool(getattr(args, "verbose", False))
    if verbose:
        logging.getLogger().setLevel(logging.DEBUG)
        _log.debug("Verbose mode enabled")

    # 3. Determine map set
    map_arg = getattr(args, "map", "all")
    if map_arg == "all":
        map_set = list(_ALL_MAPS_ORDERED)
    else:
        map_set = [map_arg]

    dry_run = bool(getattr(args, "dry_run", False))
    no_color = bool(getattr(args, "no_color", False))
    strict = bool(getattr(args, "strict", False))
    timeout_s = int(getattr(args, "timeout_s", 300))
    output_dir = getattr(args, "output_dir", None)
    runtime_target = getattr(args, "runtime_target", None)
    json_mode = bool(getattr(args, "json", False))
    max_file_mb = float(getattr(args, "max_file_mb", 5.0))
    cancel_event = getattr(args, "cancel_event", None)

    target_maps_dir: Path | None = None
    if output_dir:
        target_maps_dir = Path(output_dir).resolve()
        target_maps_dir.mkdir(parents=True, exist_ok=True)
        _log.info("map-build: using output_dir override: %s", target_maps_dir)

    # Phase 2: If materialization happened and user didn't specify --output-dir,
    # force maps to real project dir (not _remote_cache), so supervisor reads
    # materialized maps from the canonical location, not stale local copies.
    if project_dir != real_project_dir and target_maps_dir is None:
        target_maps_dir = real_project_dir / ".cortex" / "maps"
        target_maps_dir.mkdir(parents=True, exist_ok=True)
        _log.info(
            "map-build: remote_authoritative — forcing maps output to %s",
            target_maps_dir,
        )

    _log.info(
        "map-build start: project=%s map=%s dry_run=%s strict=%s",
        project_dir, map_arg, dry_run, strict,
    )

    # 4. Build each map — keep in-memory accumulator for conflict/hotspot
    from .map_storage import write_map, regenerate_index

    total = len(map_set)
    total_warnings = 0
    new_conflicts = 0
    # When --json is active, progress lines go to stderr so stdout stays clean JSON
    _progress_file = sys.stderr if json_mode else None

    # in_memory_acc holds dataclass instances for downstream builders
    in_memory_acc: dict[str, list] = {}
    # churn metadata captured during hotspot build for index audit (E2)
    _hotspot_churn_meta: dict | None = None

    # Pre-compute file scan once per build (shared by all _build_build_meta calls)
    # so that all maps in this build share a consistent file-count snapshot.
    # This ensures I2 (build determinism) passes: the index coverage fields
    # are identical between two back-to-back builds of the same project.
    _files_by_lang: dict[str, int] = _scan_project_files_by_lang(project_dir)

    # Initialise two-level parse cache.  L2 uses real_project_dir so the on-disk
    # cache survives across builds even in remote_authoritative mode where
    # project_dir may be a _remote_cache subdirectory.
    from .parse_cache import ParseCacheL1, ParseCacheL2  # noqa: PLC0415
    _parse_l2 = ParseCacheL2(real_project_dir)
    _parse_l1 = ParseCacheL1(_parse_l2, max_file_mb=max_file_mb)
    _log.debug(
        "map-build: parse cache initialised (L2 at %s, max_file_mb=%.1f)",
        real_project_dir, max_file_mb,
    )

    # Maps whose acc entry is no longer needed once a later map has been built.
    # refactor_boundary is the last consumer of everything, so we free all entries
    # after building it.  findings is the last consumer of structural/runtime/etc.
    # We clear the entire acc after refactor_boundary (or findings if that's last).
    _LAST_CONSUMERS: dict[str, str] = {
        "structural":        "refactor_boundary",
        "data_contract":     "refactor_boundary",
        "authority":         "refactor_boundary",
        "runtime":           "refactor_boundary",
        "conflict":          "refactor_boundary",
        "hotspot":           "refactor_boundary",
        "findings":          "refactor_boundary",
        "refactor_boundary": "refactor_boundary",  # drop immediately
    }

    for idx, map_name in enumerate(map_set, start=1):
        # Honour cancel before starting each map
        if cancel_event is not None and cancel_event.is_set():
            _log.info("map-build: cancelled before building %s", map_name)
            break

        _log.info("[%d/%d] Building map: %s", idx, total, map_name)
        try:
            entries_obj, entry_dicts, metadata, had_warning = _build_single_map(
                map_name,
                project_dir,
                timeout_s,
                runtime_target,
                in_memory_acc,
                parse_cache=_parse_l1,
                maps_dir_override=target_maps_dir,
                cancel_event=cancel_event,
            )
        except Exception as exc:  # noqa: BLE001
            _log.error("[%d/%d] %s: FAILED -- %s", idx, total, map_name, exc)
            _print_line("[%d/%d] %s: ERROR -- %s" % (idx, total, map_name, exc), no_color)
            return 1

        # Accumulate in memory for downstream builders
        in_memory_acc[map_name] = entries_obj

        # Capture churn metadata from hotspot build for index audit (E2)
        if map_name == "hotspot":
            _hotspot_churn_meta = {
                k: metadata.get(k)
                for k in ("churn_source", "git_head_sha", "since_window")
            }

        if had_warning:
            total_warnings += 1

        # Count new conflicts for --strict
        if map_name == "conflict":
            new_conflicts = sum(
                1 for e in entry_dicts
                if isinstance(e, dict) and e.get("lifecycle_status") == "new"
            )

        duration_s = metadata.get("build_duration_s", 0.0)

        if dry_run:
            _log.info(
                "[%d/%d] %s: would write (%d entries) [dry-run]",
                idx, total, map_name, len(entry_dicts),
            )
            _print_line(
                "[%d/%d] %s: would write (%d entries) [dry-run]"
                % (idx, total, map_name, len(entry_dicts)),
                no_color,
                file=_progress_file,
            )
        else:
            _producer = "BRAIN.autoforensics.map_builder.%s_builder" % map_name
            _extra_kwargs = _authority_conflict_build_meta_kwargs(map_name, _files_by_lang)
            _bm = _build_build_meta(
                map_name,
                duration_s,
                project_dir,
                _producer,
                _files_by_lang,
                **_extra_kwargs,
            )
            write_map(
                project_dir,
                map_name,
                entry_dicts,
                metadata,
                build_meta=_bm,
                maps_dir_override=target_maps_dir,
            )
            # Log coverage metadata for this builder
            from .map_common import get_coverage_metadata  # noqa: PLC0415
            coverage = get_coverage_metadata(map_name)
            _log.debug(
                "[%d/%d] %s coverage: supported_languages=%s",
                idx, total, map_name, coverage["supported_languages"],
            )
            _print_line(
                "[%d/%d] %s: %d entries, %.1fs, %s"
                % (idx, total, map_name, len(entry_dicts), duration_s, _bm.status),
                no_color,
                file=_progress_file,
            )

        # Release in-memory entries for maps whose last downstream consumer
        # is the map we just built.  This bounds peak RSS during the pipeline.
        # entry_dicts (serialised dicts) are retained on the stack until
        # write_map returns; entries_obj (dataclass instances) can be dropped
        # once no future builder will call _make_repo_maps_from_accumulator.
        maps_to_free = [
            k for k, last in _LAST_CONSUMERS.items()
            if last == map_name and k in in_memory_acc
        ]
        for _k in maps_to_free:
            del in_memory_acc[_k]
            _log.debug("map-build: freed in_memory_acc[%s] after %s", _k, map_name)

    # 4b. Log parse cache stats (debug summary)
    _parse_l1.log_stats()
    _parse_l2.flush()

    # 5. Regenerate index
    if not dry_run:
        try:
            regenerate_index(project_dir, maps_dir_override=target_maps_dir)
            _log.info("map-build: index regenerated")
        except Exception as exc:  # noqa: BLE001
            _log.error("map-build: failed to regenerate index: %s", exc)
            return 1

        # 5a. Patch churn audit fields into maps.hotspot section of index (E2)
        if _hotspot_churn_meta is not None:
            from .map_storage import maps_dir as _maps_dir
            _index_dir = target_maps_dir if target_maps_dir is not None else _maps_dir(project_dir)
            _index_path = _index_dir / "00_map_index.json"
            try:
                _index_payload = json.loads(_index_path.read_text(encoding="utf-8"))
                _hotspot_section = _index_payload.get("maps", {}).get("hotspot", {})
                _hotspot_section.update(_hotspot_churn_meta)
                _index_payload.setdefault("maps", {})["hotspot"] = _hotspot_section
                _index_path.write_text(
                    json.dumps(_index_payload, indent=2, ensure_ascii=False),
                    encoding="utf-8",
                )
                _log.info(
                    "map-build: hotspot churn metadata patched into index "
                    "(churn_source=%s)",
                    _hotspot_churn_meta.get("churn_source"),
                )
            except (OSError, json.JSONDecodeError) as exc:
                _log.warning("map-build: failed to patch churn metadata into index: %s", exc)

    # 6. --json output: print 00_map_index.json to stdout
    if json_mode and not dry_run:
        from .map_storage import maps_dir
        _json_maps_dir = target_maps_dir if target_maps_dir is not None else maps_dir(project_dir)
        index_path = _json_maps_dir / "00_map_index.json"
        if index_path.exists():
            try:
                payload = json.loads(index_path.read_text(encoding="utf-8"))
                text = json.dumps(payload, indent=2, ensure_ascii=False)
                _print_line(text, no_color)
            except (json.JSONDecodeError, OSError) as exc:
                _log.error("map-build: failed to read index: %s", exc)
                return 1
        else:
            _log.warning("map-build: index not found after build")
    elif json_mode and dry_run:
        _log.info("map-build: --json with --dry-run: no index written, skipping JSON output")

    # 7. --strict exit code logic
    if strict:
        if new_conflicts > 0:
            _log.warning("map-build: strict mode -- %d new conflicts detected", new_conflicts)
            return 4
        if total_warnings > 0:
            _log.warning("map-build: strict mode -- %d warnings", total_warnings)
            return 3

    # 8. Publish maps to server (remote_authoritative optional feature — not available in standalone)
    # _maybe_materialize_remote_tree is a no-op in standalone, so project_dir == real_project_dir
    # always. This block is preserved as a stub so the original logic is readable.
    _log.debug("map-build: standalone mode — remote publish skipped")

    _log.info("map-build complete: exit 0")
    return 0


# ---------------------------------------------------------------------------
# Programmatic API (E0 — A6)
# ---------------------------------------------------------------------------

def run_map_build(
    project_dir: Path,
    *,
    map: str = "all",
    dry_run: bool = False,
    strict: bool = False,
    timeout_s: int = 300,
    output_dir: Path | None = None,
    max_file_mb: float = 5.0,
    cancel_event: "Any | None" = None,
) -> int:
    """Programmatic entry point for the map build pipeline.

    Functional params only -- CLI-shaped params (json, no_color, verbose) are
    NOT exposed here.  Returns an integer exit code (0 = success), same
    semantics as cmd_map_build.

    Args:
        project_dir: Absolute (or resolvable) path to the target project root.
        map: Map name to build, or "all" for the full pipeline.
        dry_run: If True, build all maps in memory but do not write to disk.
        strict: If True, return exit code 3 on warnings, 4 on new conflicts.
        timeout_s: Timeout in seconds for the tracer (runtime map only).
        output_dir: If given, writes maps to this directory instead of
            <project_dir>/.cortex/maps/.  The directory is created if absent.
            This is the sanctioned way for background workers to write to a
            temp directory before applying a semantic diff filter (see E1).
        max_file_mb: Files larger than this threshold (MiB) are skipped during
            the build.  Skipped files are listed in the result meta under
            ``oversized_files``.  Default: 5.0 MiB.  Pass float('inf') to
            disable the guard entirely.
        cancel_event: Optional threading.Event.  When set, the build stops
            after the current map finishes and returns exit code 0 with
            partial results.

    Returns:
        Integer exit code:
            0  -- success
            1  -- application error
            2  -- validation error (bad args or path)
            3  -- strict mode: warnings
            4  -- strict mode: new conflicts
    """
    import argparse
    ns = argparse.Namespace(
        project=str(project_dir),
        map=map,
        dry_run=dry_run,
        strict=strict,
        timeout_s=timeout_s,
        output_dir=str(output_dir) if output_dir is not None else None,
        verbose=False,
        json=False,
        no_color=True,
        runtime_target=None,
        max_file_mb=max_file_mb,
        cancel_event=cancel_event,
    )
    return cmd_map_build(ns)
