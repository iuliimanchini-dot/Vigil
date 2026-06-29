"""Adapter runtime node dispatch -- Map 2 helper.

Builds the auto-discovered RuntimeNode set for ALL languages with
supports_runtime_signals=True. Python uses the rich node-build path
(runtime_builder.build_python_runtime_nodes, via PythonAdapter); Go/Java/TS/JS
use the TSRuntimeSignal -> RuntimeNode conversion (_signal_to_node).
Called by runtime_builder.build_runtime_map_static.
"""
from __future__ import annotations

import logging
from pathlib import Path
from typing import Callable

from .map_models import RuntimeNode

_log = logging.getLogger(__name__)

_KIND_MAP: dict[str, dict] = {
    "framework_route": {"node_kind": "api_route",  "side_effects": ("http_handler",),     "tags": ("nextjs", "framework_route")},
    "middleware":      {"node_kind": "middleware",  "side_effects": ("request_intercept",), "tags": ("nextjs",)},
    "module_init":     {"node_kind": "init",        "side_effects": (),                     "tags": ("module_init",)},
    "background_job":  {"node_kind": "worker",      "side_effects": (),                     "tags": ("background_job",)},
    "env_access":      {"node_kind": "env_access",  "side_effects": (),                     "tags": ("env",)},
    # Go runtime kinds
    "init_function":   {"node_kind": "init",        "side_effects": ("import_time",),       "tags": ("go", "init")},
    "goroutine_spawn": {"node_kind": "worker",      "side_effects": ("concurrency",),       "tags": ("go", "goroutine")},
    "package_init":    {"node_kind": "init",        "side_effects": ("import_time",),       "tags": ("go", "package_var")},
    # Java runtime kinds
    "static_block":     {"node_kind": "init",       "side_effects": ("import_time",),       "tags": ("java", "static_block")},
    "spring_component": {"node_kind": "init",       "side_effects": ("di_registration",),   "tags": ("java", "spring")},
    "thread_spawn":     {"node_kind": "worker",     "side_effects": ("concurrency",),       "tags": ("java", "thread")},
    # JavaScript runtime kinds
    "timer":            {"node_kind": "worker",     "side_effects": ("scheduled",),         "tags": ("js", "timer")},
    "event_listener":   {"node_kind": "init",       "side_effects": ("event_binding",),     "tags": ("js", "event")},
    "top_level_effect": {"node_kind": "init",       "side_effects": ("import_time",),       "tags": ("js", "top_level")},
    # Swift runtime kinds
    "entrypoint":       {"node_kind": "init",       "side_effects": ("import_time",),       "tags": ("swift", "entrypoint")},
}


def _signal_to_node(signal: object, freshness_fn: Callable[[], str]) -> RuntimeNode | None:
    """Convert one TSRuntimeSignal to a RuntimeNode. Returns None for unknown kinds."""
    kind = getattr(signal, "kind", "")
    file_posix = getattr(signal, "file", "")
    line = getattr(signal, "line", 0)
    confidence = getattr(signal, "confidence", 0.7)
    payload = getattr(signal, "payload", {})

    mapping = _KIND_MAP.get(kind)
    if mapping is None:
        _log.debug("_signal_to_node: unknown kind %r -- skipping", kind)
        return None

    if kind == "framework_route":
        methods = "|".join(payload.get("http_methods", ["*"]))
        node_id = payload.get("route_path", file_posix) + ":" + methods
        depends_on_env: tuple[str, ...] = ()
    elif kind == "middleware":
        node_id = file_posix + ":middleware"
        depends_on_env = ()
    elif kind == "module_init":
        node_id = file_posix + ":server_init"
        depends_on_env = ()
    elif kind == "background_job":
        node_id = file_posix + ":" + payload.get("call", "job")
        depends_on_env = ()
    elif kind == "env_access":
        env_var = payload.get("env_var", "")
        node_id = "env:" + env_var
        depends_on_env = (env_var,) if env_var else ()
    else:
        # Generic fallback for _KIND_MAP entries not handled by specific branches above
        # (e.g. Go kinds: init_function, goroutine_spawn, package_init).
        # node_id uses payload["call"] when present, falling back to kind.
        call = payload.get("call", kind)
        node_id = file_posix + ":" + call
        depends_on_env = ()

    return RuntimeNode(
        node=node_id,
        defined_in=file_posix,
        kind=mapping["node_kind"],
        calls=(),
        side_effects=mapping["side_effects"],
        depends_on_env=depends_on_env,
        order_constraints=(),
        hidden_runtime_dependencies=(),
        tags=mapping["tags"],
        source="ts_regex_adapter",
        evidence=(f"{kind}:line{line}",),
        confidence=confidence,
        freshness=freshness_fn(),
        status="inferred",
    )


def collect_adapter_runtime_nodes(
    project_dir: Path,
    freshness_fn: Callable[[], str],
    include_roots: "list[str] | None" = None,
    seed_node_names: "frozenset[str] | None" = None,
    parse_cache: object | None = None,
) -> list[RuntimeNode]:
    """Collect RuntimeNode objects from ALL runtime adapters (Python included).

    The historical ``language != "python"`` guard is gone: this function now
    builds the full auto-discovered runtime node set for every adapter with
    ``supports_runtime_signals=True``.  Two node-build paths coexist (the
    Python-specific path is option (b) from the unify plan -- Go/Java/TS keep
    their exact ``_signal_to_node`` conversion, unchanged):

      * Python  -> ``build_python_runtime_nodes`` runs the rich
        ``_RuntimeVisitor`` (via PythonAdapter) + the same cross-result merge +
        seed-conflict skip + global sort the runtime builder always applied, so
        the emitted nodes are byte-identical to the dedicated-builder era.
      * Others  -> ``extract_runtime`` (TSRuntimeSignal) -> ``_signal_to_node``
        (UNCHANGED -- Go/Java/TS conversion is not touched).

    Ordering matches the legacy build: Python nodes first (globally sorted),
    then TS/JS/Go/Java nodes in source-file order.
    """
    from .map_common import iter_source_files  # noqa: PLC0415
    from .source_adapters import ADAPTERS      # noqa: PLC0415

    nodes: list[RuntimeNode] = []

    # --- Python node-build path (rich): merge + cross-ref + seed skip + sort ---
    from .runtime_builder import build_python_runtime_nodes  # noqa: PLC0415
    nodes.extend(build_python_runtime_nodes(
        project_dir,
        include_roots=include_roots,
        seed_node_names=seed_node_names or frozenset(),
        parse_cache=parse_cache,
        freshness=freshness_fn(),
    ))

    # --- Non-Python node-build path (TS/JS/Go/Java): _signal_to_node UNCHANGED ---
    # NOTE: this `!= "python"` is NOT the removed blocking guard -- it merely
    # routes Python AWAY from the thin TSRuntimeSignal->_signal_to_node path
    # (Python is already fully handled above by build_python_runtime_nodes).
    # Without it, .py files would be re-scanned here and dropped (their thin
    # RuntimeSignal lacks the `.kind` _signal_to_node reads), which is wasteful
    # and confusing. The guard that BLOCKED Python from this function entirely
    # is gone -- Python now flows through it via the rich path.
    runtime_adapters = {
        ext: adapter
        for ext, adapter in ADAPTERS.items()
        if getattr(adapter, "supports_runtime_signals", False)
        and getattr(adapter, "language", "") != "python"
    }
    if runtime_adapters:
        languages = list({adapter.language for adapter in runtime_adapters.values()})
        _log.debug("collect_adapter_runtime_nodes: non-python languages=%r", languages)

        for src_file in iter_source_files(
            project_dir, languages=languages, include_roots=include_roots
        ):
            adapter = ADAPTERS.get(src_file.suffix.lower())
            if adapter is None or not getattr(adapter, "supports_runtime_signals", False):
                continue
            try:
                content = src_file.read_text(encoding="utf-8", errors="replace")
                signals = adapter.extract_runtime(content, src_file)
            except Exception as exc:  # noqa: BLE001
                _log.error("collect_adapter_runtime_nodes: failed for %s: %s", src_file, exc)
                continue

            for sig in signals:
                node = _signal_to_node(sig, freshness_fn)
                if node is not None:
                    nodes.append(node)

    _log.debug("collect_adapter_runtime_nodes: collected %d nodes", len(nodes))
    return nodes
