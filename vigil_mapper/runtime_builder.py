"""Generic runtime map builder -- Map 2.

Static AST scanner for runtime-relevant patterns in any target project.

Detects (via _runtime_ast.py):
  - Module-level call statements (import_time_side_effects)
  - Route/dispatch decorators (@app.route, @bp.route, @router.get, etc.)
  - Background task spawns in __init__ / bootstrap / setup functions
    (threading.Thread, asyncio.create_task, subprocess.Popen)
  - Environment variable reads (os.environ.get, os.getenv, os.environ[])

Optionally merges with a seed from <project>/.cortex/map_seeds/runtime_seed.json.
Seed nodes are marked status="canonical" and win on name conflicts.
Auto-discovered nodes are marked status="inferred".

Generic design: no hardcoded application-specific node names.
Self-diagnosis: pass project_dir=Path(".") to run against Vigil itself.

Public API:
    build_runtime_map_static(project_dir, include_roots) -> list[RuntimeNode]
    build_runtime_map_full(project_dir, target_module, target_argv, timeout_s,
                           include_roots) -> tuple[list[RuntimeNode], dict]
"""
from __future__ import annotations

import ast
import json
import logging
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Sequence

from .map_common import iter_py_files
from .map_errors import MapIntegrityError
from .map_models import RuntimeNode
from .map_storage import seeds_dir
from .source_adapters import get_adapter_for_file

__all__ = ["build_runtime_map_static", "build_runtime_map_full", "build_python_runtime_nodes"]

_log = logging.getLogger(__name__)

# Seed schema version this builder supports.
_SUPPORTED_SEED_SCHEMA = "1.0.0"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _freshness_now() -> str:
    return (
        datetime.now(timezone.utc)
        .isoformat()
        .replace("+00:00", "Z")
    )


def _rel_posix(path: Path, project_dir: Path) -> str:
    try:
        return path.relative_to(project_dir).as_posix()
    except ValueError:
        return path.as_posix()


# ---------------------------------------------------------------------------
# Seed loading
# ---------------------------------------------------------------------------

def _load_seed(project_dir: Path) -> list[RuntimeNode]:
    """Load optional runtime seed from <project_dir>/.cortex/map_seeds/runtime_seed.json.

    Returns:
        List of RuntimeNode with status="canonical" on success.
        Empty list if seed file is absent (info-logged, not an error).

    Raises:
        MapIntegrityError: If the seed file exists but is corrupt or missing
            schema_version.
    """
    seed_path = seeds_dir(project_dir) / "runtime_seed.json"

    if not seed_path.exists():
        _log.info("build_runtime_map_static: no runtime seed, using auto-discovery only")
        return []

    try:
        raw = seed_path.read_text(encoding="utf-8")
        payload = json.loads(raw)
    except (OSError, json.JSONDecodeError) as exc:
        raise MapIntegrityError(
            "runtime_seed.json is unreadable or not valid JSON: %s" % exc
        ) from exc

    if not isinstance(payload, dict):
        raise MapIntegrityError(
            "runtime_seed.json: expected a JSON object at top level"
        )

    schema_version = payload.get("schema_version")
    if not schema_version:
        raise MapIntegrityError(
            "runtime_seed.json: missing required field 'schema_version'"
        )
    if schema_version != _SUPPORTED_SEED_SCHEMA:
        raise MapIntegrityError(
            "runtime_seed.json: unsupported schema_version %r (expected %r)"
            % (schema_version, _SUPPORTED_SEED_SCHEMA)
        )

    raw_nodes = payload.get("nodes", [])
    if not isinstance(raw_nodes, list):
        raise MapIntegrityError("runtime_seed.json: 'nodes' must be a list")

    freshness = _freshness_now()
    nodes: list[RuntimeNode] = []
    for i, raw_node in enumerate(raw_nodes):
        if not isinstance(raw_node, dict):
            raise MapIntegrityError("runtime_seed.json: node[%d] is not a dict" % i)
        node_name = raw_node.get("node")
        if not node_name:
            raise MapIntegrityError("runtime_seed.json: node[%d] missing 'node' field" % i)
        nodes.append(RuntimeNode(
            node=str(node_name),
            defined_in=str(raw_node.get("defined_in", "")),
            kind=str(raw_node.get("kind", "unknown")),
            calls=tuple(raw_node.get("calls", [])),
            side_effects=tuple(raw_node.get("side_effects", [])),
            depends_on_env=tuple(raw_node.get("depends_on_env", [])),
            order_constraints=tuple(raw_node.get("order_constraints", [])),
            hidden_runtime_dependencies=tuple(raw_node.get("hidden_runtime_dependencies", [])),
            tags=tuple(raw_node.get("tags", [])),
            source="seed",
            evidence=(str(seed_path),),
            confidence=1.0,
            freshness=freshness,
            status="canonical",
        ))

    _log.info(
        "build_runtime_map_static: loaded %d canonical nodes from runtime seed",
        len(nodes),
    )
    return nodes


# ---------------------------------------------------------------------------
# Python node-build path (unified source-adapter route)
# ---------------------------------------------------------------------------

def build_python_runtime_nodes(
    project_dir: Path,
    include_roots: Sequence[str] | None = None,
    seed_node_names: "frozenset[str]" = frozenset(),
    parse_cache: "Any | None" = None,
    freshness: str | None = None,
) -> list[RuntimeNode]:
    """Build the inferred Python runtime nodes via the PythonAdapter path.

    Routes Python runtime extraction through ``PythonAdapter.extract_runtime_results``
    (the unified source-adapter path) and applies the SAME byte-identical
    cross-result merge + seed-conflict skip + global sort the runtime builder
    historically applied inline.  Returns inferred RuntimeNode objects (seed
    names skipped), globally sorted by node name -- identical to the
    dedicated-builder output.

    This is the "Python-specific node-build path" (option b) invoked from
    ``_runtime_dispatch.collect_adapter_runtime_nodes`` after the
    ``language != "python"`` guard was removed; Go/Java/TS keep their separate
    ``_signal_to_node`` conversion.
    """
    project_dir = project_dir.resolve()
    if freshness is None:
        freshness = _freshness_now()

    try:
        py_files = list(iter_py_files(project_dir, include_roots))
    except Exception as exc:
        from .map_errors import MapBuilderError  # noqa: PLC0415
        raise MapBuilderError(
            "build_python_runtime_nodes: iter_py_files failed: %s" % exc
        ) from exc

    _log.debug("build_python_runtime_nodes: scanning %d files", len(py_files))

    # auto_raw: node_name → merged accumulator dict
    auto_raw: dict[str, dict] = {}

    for abs_path in py_files:
        rel = _rel_posix(abs_path, project_dir)

        # Use parse_cache if available to avoid re-reading + re-parsing.
        # Cache gives us is_parseable; the ast.parse below is the SyntaxError
        # gate that decides whether the file is handed to the adapter (it keeps
        # the historical "skip unparseable" file-selection byte-identical).
        if parse_cache is not None:
            cached = parse_cache.get_or_parse(abs_path, project_dir)
            if not cached.is_parseable:
                _log.debug("build_python_runtime_nodes: skipping unparseable (cache): %s", rel)
                continue
            # Reuse cached source if available (avoid re-reading disk)
            source = parse_cache.get_cached_source(abs_path)
            if source is None:
                # Fallback: cache miss on source (should be rare)
                try:
                    source = abs_path.read_text(encoding="utf-8", errors="replace")
                except OSError as exc:
                    from .map_errors import MapBuilderError  # noqa: PLC0415
                    raise MapBuilderError(
                        "build_python_runtime_nodes: cannot read %s: %s" % (abs_path, exc)
                    ) from exc
            try:
                ast.parse(source, filename=rel)
            except SyntaxError:
                _log.debug("build_python_runtime_nodes: skipping unparseable file: %s", rel)
                continue
        else:
            # Backward-compat: no cache
            try:
                source = abs_path.read_text(encoding="utf-8", errors="replace")
            except OSError as exc:
                from .map_errors import MapBuilderError  # noqa: PLC0415
                raise MapBuilderError(
                    "build_python_runtime_nodes: cannot read %s: %s" % (abs_path, exc)
                ) from exc

            try:
                ast.parse(source, filename=rel)
            except SyntaxError:
                _log.debug("build_python_runtime_nodes: skipping unparseable file: %s", rel)
                continue

        # Route Python runtime extraction through the source adapter (unified
        # path). PythonAdapter.extract_runtime_results runs the SAME
        # _RuntimeVisitor and returns its raw per-file results; the cross-result
        # merge + seed-conflict resolution below are unchanged.
        py_adapter = get_adapter_for_file(abs_path)
        if py_adapter is None or getattr(py_adapter, "language", "") != "python":
            continue
        visitor_results = py_adapter.extract_runtime_results(source, rel)

        for raw in visitor_results:
            name = raw["node"]
            if name in auto_raw:
                existing = auto_raw[name]
                existing["tags"] = list(set(existing["tags"]) | set(raw["tags"]))
                existing["env_vars"] = list(set(existing["env_vars"]) | set(raw["env_vars"]))
                existing["side_effects"] = list(
                    set(existing["side_effects"]) | set(raw["side_effects"])
                )
                # Preserve entry-function call targets (order-stable union).
                for c in raw.get("calls", ()):
                    if c not in existing["calls"]:
                        existing["calls"].append(c)
            else:
                auto_raw[name] = {
                    "node": name,
                    "kind": raw["kind"],
                    "tags": list(raw["tags"]),
                    "env_vars": list(raw["env_vars"]),
                    "side_effects": list(raw["side_effects"]),
                    "calls": list(raw.get("calls", ())),
                    "evidence": raw["evidence"],
                    "defined_in": name.split(":")[0] if ":" in name else name,
                }

    _log.debug("build_python_runtime_nodes: auto-discovered %d raw nodes", len(auto_raw))

    # Build inferred RuntimeNode objects, skipping seed conflicts (global sort).
    auto_nodes: list[RuntimeNode] = []
    for name, raw in sorted(auto_raw.items()):
        if name in seed_node_names:
            _log.debug("build_python_runtime_nodes: seed canonical wins for node %r", name)
            continue
        auto_nodes.append(RuntimeNode(
            node=name,
            defined_in=raw["defined_in"],
            kind=raw["kind"],
            calls=tuple(raw.get("calls", ())),
            side_effects=tuple(sorted(set(raw["side_effects"]))),
            depends_on_env=tuple(sorted(set(raw["env_vars"]))),
            order_constraints=(),
            hidden_runtime_dependencies=(),
            tags=tuple(sorted(set(raw["tags"]))),
            source="static_scan",
            evidence=raw["evidence"],
            confidence=0.75,
            freshness=freshness,
            status="inferred",
        ))
    return auto_nodes


# ---------------------------------------------------------------------------
# Main builder
# ---------------------------------------------------------------------------

def build_runtime_map_static(
    project_dir: Path,
    include_roots: Sequence[str] | None = None,
    parse_cache: "Any | None" = None,
) -> list[RuntimeNode]:
    """Build Map 2 (runtime) via static AST analysis.

    Loads an optional seed from <project_dir>/.cortex/map_seeds/runtime_seed.json.
    Seed nodes are marked canonical and win on node-name conflicts.
    Auto-discovered nodes are marked inferred.

    Map metadata note: trace_status="static_only" should be set by the caller
    when writing the map payload (e.g. via write_map metadata arg).

    Args:
        project_dir: Root of the target project to scan.
        include_roots: Optional list of subdirectory names to restrict scan.
            None = whole project (minus excluded dirs).

    Returns:
        Merged list[RuntimeNode], canonical seed nodes first, then inferred.

    Raises:
        MapIntegrityError: If runtime_seed.json exists but is corrupt.
    """
    project_dir = project_dir.resolve()
    _log.info(
        "build_runtime_map_static: start project_dir=%s include_roots=%s",
        project_dir,
        include_roots,
    )
    t_start = time.monotonic()

    # 1. Load optional seed
    seed_nodes = _load_seed(project_dir)
    seed_index: dict[str, RuntimeNode] = {n.node: n for n in seed_nodes}

    # 2. Auto-discover via the unified adapter dispatch.
    # collect_adapter_runtime_nodes builds the FULL auto node set for ALL
    # languages: Python via build_python_runtime_nodes (rich _RuntimeVisitor +
    # merge + seed skip + global sort -- routed through PythonAdapter), then
    # Go/Java/TS/JS via _signal_to_node (unchanged). Python's seed-conflict
    # skip needs the seed names, so they are passed through.
    seed_node_names = frozenset(seed_index)
    auto_nodes: list[RuntimeNode] = []
    try:
        from ._runtime_dispatch import collect_adapter_runtime_nodes  # noqa: PLC0415
        auto_nodes = collect_adapter_runtime_nodes(
            project_dir,
            _freshness_now,
            include_roots=list(include_roots) if include_roots is not None else None,
            seed_node_names=seed_node_names,
            parse_cache=parse_cache,
        )
        _log.debug(
            "build_runtime_map_static: adapter dispatch produced %d auto nodes",
            len(auto_nodes),
        )
    except Exception as exc:  # noqa: BLE001
        _log.error(
            "build_runtime_map_static: adapter runtime dispatch failed: %s -- continuing",
            exc,
        )

    # 3. Merge: canonical seed first, inferred auto second
    merged: list[RuntimeNode] = list(seed_nodes) + auto_nodes

    elapsed = time.monotonic() - t_start
    _SLA_SECONDS = 20.0
    if elapsed > _SLA_SECONDS:
        _log.warning(
            "build_runtime_map_static: SLA exceeded -- %.2fs > %.1fs (%d nodes)",
            elapsed, _SLA_SECONDS, len(merged),
        )
    else:
        _log.info(
            "build_runtime_map_static: done in %.2fs -- seed=%d auto=%d total=%d",
            elapsed, len(seed_nodes), len(auto_nodes), len(merged),
        )

    return merged


# ---------------------------------------------------------------------------
# Full builder: static + subprocess trace merge
# ---------------------------------------------------------------------------

def build_runtime_map_full(
    project_dir: Path,
    target_module: str | None = None,
    target_argv: Sequence[str] = (),
    timeout_s: float = 30.0,
    include_roots: Sequence[str] | None = None,
) -> tuple[list[RuntimeNode], dict]:
    """Build Map 2 (runtime) combining static analysis with live startup tracing.

    If target_module is None, degrades gracefully to static-only (same as
    calling build_runtime_map_static directly).

    Merge rule (per plan sec.4b):
        canonical (seed)  >  observed (trace-confirmed)  >  inferred (static auto)

    A static node's status is upgraded from "inferred" to "observed" when a
    matching trace call event is found. "canonical" nodes are never downgraded.

    Args:
        project_dir: Root of the target project to scan.
        target_module: Dotted Python module name to trace (e.g. "json").
            None -> static only, no subprocess spawned.
        target_argv: Forwarded to the subprocess as target's sys.argv.
        timeout_s: Subprocess time budget in seconds.
        include_roots: Optional subdirectory restrict list for static scan.

    Returns:
        Tuple of (nodes, metadata):
            nodes    - merged list[RuntimeNode]
            metadata - dict with trace_status and trace metrics

    Raises:
        RuntimeTracerTimeoutError: If subprocess times out.
        (MapBuilderError subtypes from static scan propagate unchanged.)
    """
    from .map_errors import RuntimeTracerError, RuntimeTracerTimeoutError  # noqa: PLC0415

    project_dir = project_dir.resolve()

    # Step 1: always build static map first.
    static_nodes = build_runtime_map_static(project_dir, include_roots)

    # Step 2: if no target specified, return static-only.
    if target_module is None:
        _log.info("build_runtime_map_full: no target_module -- returning static_only map")
        return static_nodes, {"trace_status": "static_only"}

    # Step 3: attempt subprocess trace.
    from .runtime_tracer import capture_startup_trace  # noqa: PLC0415

    trace_result: dict | None = None
    trace_exit_code: int = -1
    trace_duration: float = 0.0

    try:
        trace_result = capture_startup_trace(
            target_module=target_module,
            target_argv=target_argv,
            project_dir=project_dir,
            timeout_s=timeout_s,
        )
        trace_exit_code = trace_result.get("exit_code", -1)
        trace_duration = trace_result.get("duration_s", 0.0)
    except RuntimeTracerTimeoutError:
        _log.warning(
            "build_runtime_map_full: trace timed out for target=%r -- degrading to static",
            target_module,
        )
        return static_nodes, {
            "trace_status": "degraded",
            "trace_exit_code": -1,
            "trace_events_captured": 0,
            "trace_duration_s": 0.0,
            "trace_error": "timeout",
        }
    except RuntimeTracerError as exc:
        _log.warning(
            "build_runtime_map_full: trace failed for target=%r: %s -- degrading to static",
            target_module,
            exc,
        )
        return static_nodes, {
            "trace_status": "degraded",
            "trace_exit_code": -1,
            "trace_events_captured": 0,
            "trace_duration_s": 0.0,
            "trace_error": str(exc),
        }

    # Step 4: if subprocess returned non-zero, degrade.
    if trace_exit_code != 0:
        _log.warning(
            "build_runtime_map_full: trace exited with code %d for target=%r -- degrading",
            trace_exit_code,
            target_module,
        )
        return static_nodes, {
            "trace_status": "degraded",
            "trace_exit_code": trace_exit_code,
            "trace_events_captured": len(trace_result.get("events", [])) if trace_result else 0,
            "trace_duration_s": trace_duration,
        }

    # Step 5: merge — upgrade inferred nodes to observed where trace confirms them.
    events: list[dict] = trace_result.get("events", []) if trace_result else []
    import_events: list[dict] = trace_result.get("import_events", []) if trace_result else []

    # Build a set of observed qualnames from trace events (call events only).
    observed_qualnames: set[str] = {
        ev["qualname"]
        for ev in events
        if ev.get("event") == "call" and ev.get("qualname")
    }
    # Also collect imported module names.
    observed_imports: set[str] = {
        ev["module"]
        for ev in import_events
        if ev.get("module")
    }

    freshness = _freshness_now()
    merged_nodes: list[RuntimeNode] = []

    for node in static_nodes:
        # canonical nodes are never downgraded.
        if node.status == "canonical":
            merged_nodes.append(node)
            continue

        # Check if this node's qualname or node name appears in trace events.
        node_name = node.node
        # Match by qualname suffix (node may be "module:Class.method" format).
        short_name = node_name.split(":")[-1] if ":" in node_name else node_name
        module_part = node_name.split(":")[0] if ":" in node_name else ""

        matched = (
            short_name in observed_qualnames
            or node_name in observed_qualnames
            or module_part in observed_imports
        )

        if matched and node.status == "inferred":
            # Upgrade: inferred → observed.
            # RuntimeNode is frozen — create a new instance with updated fields.
            existing_evidence = list(node.evidence)
            new_evidence = tuple(existing_evidence + ["trace:call"])
            upgraded = RuntimeNode(
                node=node.node,
                defined_in=node.defined_in,
                kind=node.kind,
                calls=node.calls,
                side_effects=node.side_effects,
                depends_on_env=node.depends_on_env,
                order_constraints=node.order_constraints,
                hidden_runtime_dependencies=node.hidden_runtime_dependencies,
                tags=node.tags,
                source=node.source,
                evidence=new_evidence,
                confidence=min(node.confidence + 0.1, 1.0),
                freshness=freshness,
                status="observed",
            )
            merged_nodes.append(upgraded)
            _log.debug(
                "build_runtime_map_full: upgraded node %r inferred->observed",
                node.node,
            )
        else:
            merged_nodes.append(node)

    events_captured = len(events)
    _log.info(
        "build_runtime_map_full: full trace done -- events=%d imports=%d "
        "upgraded=%d total=%d duration=%.2fs",
        events_captured,
        len(import_events),
        sum(1 for n in merged_nodes if n.status == "observed"),
        len(merged_nodes),
        trace_duration,
    )

    metadata = {
        "trace_status": "full",
        "trace_events_captured": events_captured,
        "trace_duration_s": trace_duration,
        "trace_exit_code": trace_exit_code,
    }
    return merged_nodes, metadata
