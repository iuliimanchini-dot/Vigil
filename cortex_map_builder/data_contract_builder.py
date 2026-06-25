"""Data contract map builder -- scans target project for entity types.

Detects: @dataclass, NamedTuple, TypedDict, pydantic.BaseModel classes.
Builds DataContractEntry per entity with shape, writers, readers, drift flags.
Generic design: operates on any target project_dir via iter_py_files.
No exec/eval/compile/importlib.import_module of scanned files. AST only.
"""
from __future__ import annotations

import ast
import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Sequence

from .map_common import iter_py_files, iter_source_files
from .map_errors import MapBuilderError
from .map_models import DataContractEntry
from .map_storage import seeds_dir
from ._ast_helpers_minimal import parse_python_source_or_emit_finding

__all__ = ["build_data_contract_map"]

_log = logging.getLogger(__name__)

_SOURCE = "static_scan"
_CONFIDENCE = 0.85

_DATACLASS_DECORATORS = frozenset({"dataclass", "dataclasses.dataclass"})
_NAMEDTUPLE_BASES = frozenset({"NamedTuple", "typing.NamedTuple"})
_TYPEDDICT_BASES = frozenset({"TypedDict", "typing.TypedDict"})
_PYDANTIC_BASES = frozenset({"BaseModel", "pydantic.BaseModel"})
_SERIALIZER_METHODS = frozenset({"to_dict", "to_json", "dict", "model_dump"})


# ---------------------------------------------------------------------------
# AST helpers
# ---------------------------------------------------------------------------

def _node_name(node: ast.expr) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return "%s.%s" % (_node_name(node.value), node.attr)
    if isinstance(node, ast.Call):
        return _node_name(node.func)
    return ""


def _is_entity(cls: ast.ClassDef) -> bool:
    if any(_node_name(d) in _DATACLASS_DECORATORS for d in cls.decorator_list):
        return True
    bases = {_node_name(b) for b in cls.bases}
    return bool(bases & (_NAMEDTUPLE_BASES | _TYPEDDICT_BASES | _PYDANTIC_BASES))


def _entity_kind(cls: ast.ClassDef) -> str:
    if any(_node_name(d) in _DATACLASS_DECORATORS for d in cls.decorator_list):
        return "dataclass"
    bases = {_node_name(b) for b in cls.bases}
    if bases & _NAMEDTUPLE_BASES:
        return "namedtuple"
    if bases & _TYPEDDICT_BASES:
        return "typeddict"
    return "pydantic"


def _extract_shape(cls: ast.ClassDef) -> dict[str, str]:
    """Extract top-level annotated fields from class body only.

    Iterates cls.body directly (not ast.walk) so that local AnnAssign
    statements inside method bodies are never mistaken for class fields.
    """
    shape: dict[str, str] = {}
    for stmt in cls.body:
        if isinstance(stmt, ast.AnnAssign) and isinstance(stmt.target, ast.Name):
            try:
                ann = ast.unparse(stmt.annotation)
            except Exception:
                ann = "<unknown>"
            shape[stmt.target.id] = ann
    return shape


def _extract_serializer_shapes(cls: ast.ClassDef) -> dict[str, list[str]]:
    result: dict[str, list[str]] = {}
    for stmt in cls.body:
        if not isinstance(stmt, ast.FunctionDef) or stmt.name not in _SERIALIZER_METHODS:
            continue
        keys = [
            k.value
            for node in ast.walk(stmt)
            if isinstance(node, ast.Dict)
            for k in node.keys
            if isinstance(k, ast.Constant) and isinstance(k.value, str)
        ]
        result[stmt.name] = keys
    return result


# ---------------------------------------------------------------------------
# Drift detection
# ---------------------------------------------------------------------------

def _drift_flags(
    canonical_shape: dict[str, str],
    canonical_path: str,
    variants: list[dict],
    serializer_shapes: dict[str, list[str]],
) -> list[str]:
    flags: list[str] = []
    cfields = set(canonical_shape)

    for v in variants:
        vpath = v.get("path", "")
        if vpath == canonical_path:
            continue
        vfields = set(v.get("shape", {}))
        added = vfields - cfields
        removed = cfields - vfields
        semantic = [f for f in cfields & vfields if canonical_shape[f] != v["shape"][f]]
        if added:
            flags.append("representational:extra_fields:%s:%s" % (vpath, ",".join(sorted(added))))
        if removed:
            flags.append("representational:missing_fields:%s:%s" % (vpath, ",".join(sorted(removed))))
        for f in semantic:
            flags.append("semantic:annotation_diff:%s:%s" % (vpath, f))

    for method, keys in serializer_shapes.items():
        if not keys:
            continue
        kset = set(keys)
        extra = kset - cfields
        missing = cfields - kset
        if extra:
            flags.append("serialization:%s:extra_keys:%s" % (method, ",".join(sorted(extra))))
        if missing:
            flags.append("serialization:%s:missing_keys:%s" % (method, ",".join(sorted(missing))))

    return flags


# ---------------------------------------------------------------------------
# Cross-module scan
# ---------------------------------------------------------------------------

def _collect_writers_readers(
    py_files: list[Path],
    entity_names: frozenset[str],
    rel_base: Path,
    *,
    syntax_error_sink=None,
) -> tuple[dict[str, list[str]], dict[str, list[str]]]:
    writers: dict[str, list[str]] = {n: [] for n in entity_names}
    readers: dict[str, list[str]] = {n: [] for n in entity_names}

    for py_file in py_files:
        try:
            source = py_file.read_text(encoding="utf-8", errors="replace")
        except OSError as exc:
            _log.warning("_collect_writers_readers: cannot read %s: %s", py_file, exc)
            continue

        try:
            rel_path_for_meta = py_file.relative_to(rel_base).as_posix()
        except ValueError:
            rel_path_for_meta = py_file.as_posix()

        # B4 (2026-04-23): replaces silent `except SyntaxError: continue` —
        # emits meta.syntax_parse_error via the supplied sink (if any) so
        # broken .py files surface in downstream audits.
        tree = parse_python_source_or_emit_finding(
            source,
            rel_path=rel_path_for_meta,
            emit_finding=syntax_error_sink,
            emitting_gate="data_contract_builder.writers_readers",
            filename=str(py_file),
        )
        if tree is None:
            continue

        try:
            rel_path = py_file.relative_to(rel_base).as_posix()
        except ValueError:
            rel_path = py_file.as_posix()

        imported: set[str] = set()
        for node in ast.walk(tree):
            if isinstance(node, (ast.ImportFrom, ast.Import)):
                for alias in node.names:  # type: ignore[union-attr]
                    name = alias.asname or alias.name
                    if name in entity_names:
                        imported.add(name)

        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                fname = _node_name(node.func)
                # bare name or attr.name — strip prefix
                short = fname.split(".")[-1] if "." in fname else fname
                if short in entity_names and rel_path not in writers[short]:
                    writers[short].append(rel_path)

        for name in imported:
            if rel_path not in readers[name]:
                readers[name].append(rel_path)

    return writers, readers


# ---------------------------------------------------------------------------
# Priorities
# ---------------------------------------------------------------------------

def _load_priorities(project_dir: Path) -> frozenset[str]:
    pfile = seeds_dir(project_dir) / "data_contract_priorities.json"
    if not pfile.exists():
        _log.debug("_load_priorities: no priorities file at %s", pfile)
        return frozenset()
    try:
        raw = json.loads(pfile.read_text(encoding="utf-8"))
        names = raw.get("priority_entities", [])
        if not isinstance(names, list):
            _log.warning("_load_priorities: priority_entities not a list in %s", pfile)
            return frozenset()
        result = frozenset(str(n) for n in names)
        _log.info("_load_priorities: loaded %d priority entities", len(result))
        return result
    except (json.JSONDecodeError, OSError) as exc:
        _log.warning("_load_priorities: failed to read %s: %s", pfile, exc)
        return frozenset()


# ---------------------------------------------------------------------------
# Per-file scan
# ---------------------------------------------------------------------------

def _scan_file(py_file: Path, project_dir: Path, *, syntax_error_sink=None, source: str | None = None) -> list[dict]:
    if source is None:
        try:
            source = py_file.read_text(encoding="utf-8", errors="replace")
        except OSError as exc:
            raise MapBuilderError("Cannot read %s: %s" % (py_file, exc)) from exc

    try:
        rel_path_for_meta = py_file.relative_to(project_dir).as_posix()
    except ValueError:
        rel_path_for_meta = py_file.as_posix()

    # B4 (2026-04-23): replaces silent `except SyntaxError: return []`.
    tree = parse_python_source_or_emit_finding(
        source,
        rel_path=rel_path_for_meta,
        emit_finding=syntax_error_sink,
        emitting_gate="data_contract_builder.scan_file",
        filename=str(py_file),
    )
    if tree is None:
        return []

    try:
        rel = py_file.relative_to(project_dir).as_posix()
    except ValueError:
        rel = py_file.as_posix()

    result = []
    for node in ast.walk(tree):
        if isinstance(node, ast.ClassDef) and _is_entity(node):
            result.append({
                "name": node.name,
                "kind": _entity_kind(node),
                "path": rel,
                "shape": _extract_shape(node),
                "serializer_shapes": _extract_serializer_shapes(node),
            })
    return result


# ---------------------------------------------------------------------------
# Adapter dispatch (TS/JS and other non-Python languages)
# ---------------------------------------------------------------------------

def _collect_adapter_contract_entries(
    project_dir: Path,
    freshness: str,
    include_roots: Sequence[str] | None = None,
) -> list[DataContractEntry]:
    """Collect DataContractEntry objects from non-Python adapters with supports_contracts=True."""
    from .source_adapters import ADAPTERS  # noqa: PLC0415

    contract_exts: frozenset[str] = frozenset(
        ext for ext, ad in ADAPTERS.items()
        if ad.supports_contracts and ad.language != "python"
    )
    if not contract_exts:
        return []

    entries: list[DataContractEntry] = []
    for src_file in iter_source_files(project_dir, include_roots=include_roots):
        if src_file.suffix.lower() not in contract_exts:
            continue
        adapter = ADAPTERS.get(src_file.suffix.lower())
        if adapter is None or not adapter.supports_contracts:
            continue
        try:
            content = src_file.read_text(encoding="utf-8", errors="replace")
            candidates = adapter.extract_contracts(content, src_file)
        except OSError as exc:
            _log.warning("_collect_adapter_contract_entries: cannot read %s: %s", src_file, exc)
            continue
        except Exception as exc:  # noqa: BLE001
            _log.error("_collect_adapter_contract_entries: %s failed: %s", src_file, exc)
            continue

        try:
            file_posix = src_file.relative_to(project_dir).as_posix()
        except ValueError:
            file_posix = src_file.as_posix()

        for candidate in candidates:
            entries.append(DataContractEntry(
                entity=candidate.name,
                canonical_schema=file_posix,
                variants=(), transformations=(),
                writers=(), readers=(), drift_flags=(),
                source="ts_regex_adapter",
                evidence=("file:%s" % file_posix,),
                confidence=candidate.confidence,
                freshness=freshness,
                status="inferred",
            ))

    _log.debug("_collect_adapter_contract_entries: %d entries", len(entries))
    return entries


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def build_data_contract_map(
    project_dir: Path,
    include_roots: Sequence[str] | None = None,
    *,
    syntax_error_sink=None,
    parse_cache: Any | None = None,
) -> list[DataContractEntry]:
    """Scan target project and return DataContractEntry list.

    Priority entities from <project>/.cortex/map_seeds/data_contract_priorities.json
    receive status="canonical"; others get status="inferred".

    B4 (2026-04-23): ``syntax_error_sink`` (optional callable that accepts a
    ``GateFinding``) receives ``meta.syntax_parse_error`` findings for any
    broken .py file encountered during the scan. If ``None``, per-file counts
    are logged at WARNING once the scan completes.
    """
    project_dir = project_dir.resolve()
    _log.info("build_data_contract_map: scanning %s", project_dir)

    freshness = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    priority_entities = _load_priorities(project_dir)
    py_files: list[Path] = list(iter_py_files(project_dir, include_roots=include_roots))
    _log.info("build_data_contract_map: %d py files", len(py_files))

    # B4 (2026-04-23): meta sink wiring — if no external sink provided, fall
    # back to a local counter + WARNING log so broken files are not silent.
    local_syntax_findings: list = []
    effective_sink = syntax_error_sink if syntax_error_sink is not None else local_syntax_findings.append

    raw: dict[str, list[dict]] = {}
    for py_file in py_files:
        # Use parse_cache to skip unparseable files cheaply (avoid re-read + parse).
        cached_source = None
        if parse_cache is not None:
            cached = parse_cache.get_or_parse(py_file, project_dir)
            if not cached.is_parseable:
                _log.debug("build_data_contract_map: skipping unparseable (cache): %s", py_file.name)
                continue
            # Reuse cached source if available (avoids re-reading disk)
            cached_source = parse_cache.get_cached_source(py_file)
        for entity in _scan_file(py_file, project_dir, syntax_error_sink=effective_sink, source=cached_source):
            raw.setdefault(entity["name"], []).append(entity)

    _log.info("build_data_contract_map: %d unique entities", len(raw))

    all_names = frozenset(raw)
    writers_map, readers_map = _collect_writers_readers(
        py_files, all_names, project_dir, syntax_error_sink=effective_sink
    )

    if syntax_error_sink is None and local_syntax_findings:
        _log.warning(
            "build_data_contract_map: %d .py files failed to parse (meta.syntax_parse_error)",
            len(local_syntax_findings),
        )

    entries: list[DataContractEntry] = []
    for entity_name, locs in raw.items():
        locs_sorted = sorted(locs, key=lambda e: e["path"])
        canon = locs_sorted[0]
        canon_path = canon["path"]
        canon_shape: dict[str, str] = canon["shape"]

        variants_dicts = [{"path": l["path"], "kind": l["kind"], "shape": l["shape"]} for l in locs_sorted]
        flags = _drift_flags(canon_shape, canon_path, variants_dicts, canon["serializer_shapes"])
        transformations = [
            {"kind": "serializer", "method": m, "output_keys": sorted(k)}
            for m, k in canon["serializer_shapes"].items()
        ]

        entries.append(DataContractEntry(
            entity=entity_name,
            canonical_schema=canon_path,
            variants=tuple(json.dumps(v, sort_keys=True) for v in variants_dicts),
            transformations=tuple(json.dumps(t, sort_keys=True) for t in transformations),
            writers=tuple(sorted(set(writers_map.get(entity_name, [])))),
            readers=tuple(sorted(set(readers_map.get(entity_name, [])))),
            drift_flags=tuple(flags),
            source=_SOURCE,
            evidence=("file:%s" % canon_path,),
            confidence=_CONFIDENCE,
            freshness=freshness,
            status="canonical" if entity_name in priority_entities else "inferred",
        ))

    # Collect contracts from TS/JS and other non-Python adapters
    try:
        adapter_entries = _collect_adapter_contract_entries(
            project_dir, freshness, include_roots=include_roots
        )
        entries.extend(adapter_entries)
        if adapter_entries:
            _log.info(
                "build_data_contract_map: +%d entries from non-Python adapters",
                len(adapter_entries),
            )
    except Exception as exc:  # noqa: BLE001
        _log.error("build_data_contract_map: adapter contract scan failed: %s", exc)

    entries.sort(key=lambda e: e.entity)
    _log.info(
        "build_data_contract_map: %d entries (%d with drift)",
        len(entries), sum(1 for e in entries if e.drift_flags),
    )
    return entries
