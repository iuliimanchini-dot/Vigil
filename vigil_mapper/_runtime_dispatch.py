"""TS/JS adapter runtime signal dispatch -- Map 2 helper.

Converts TSRuntimeSignal -> RuntimeNode for all adapters with
supports_runtime_signals=True (excluding Python which uses the AST path).
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
) -> list[RuntimeNode]:
    """Collect RuntimeNode objects from TS/JS adapter runtime signals.

    Iterates source files for adapters with supports_runtime_signals=True
    (non-Python), calls extract_runtime(), and converts signals to RuntimeNodes.
    """
    from .map_common import iter_source_files  # noqa: PLC0415
    from .source_adapters import ADAPTERS      # noqa: PLC0415

    nodes: list[RuntimeNode] = []

    runtime_adapters = {
        ext: adapter
        for ext, adapter in ADAPTERS.items()
        if getattr(adapter, "supports_runtime_signals", False)
        and getattr(adapter, "language", "") != "python"
    }
    if not runtime_adapters:
        return nodes

    languages = list({adapter.language for adapter in runtime_adapters.values()})
    _log.debug("collect_adapter_runtime_nodes: languages=%r", languages)

    for src_file in iter_source_files(project_dir, languages=languages):
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
