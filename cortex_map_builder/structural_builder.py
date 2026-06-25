"""Generic structural map builder -- Map 1.

Scans any target project directory and builds a dependency graph:
  - imports_out / imports_in per file
  - cycle detection (iterative Tarjan SCC)
  - auto-tags: large_file, high_fan_in, high_fan_out, cycle_member, unparseable
  - symbols_defined (class / function names)

Multi-language: Python files are parsed via AST (Pass 1); all other languages
registered in source_adapters.ADAPTERS (TypeScript, JavaScript, Go, Java) are
processed via regex-based adapters in Pass 1b (_collect_non_python_raw_data).
Both passes contribute StructuralEntry records to the same result list.

Remaining gap: contracts/authority/runtime maps (Maps 2-4) are Python-AST-only
today; non-Python adapters return [] stubs for those passes.

Generic design: operates on any project_dir, no Vigil-specific assumptions.
Self-diagnosis: pass project_dir=Path(".") to run against Vigil itself.

Public API:
    build_structural_map(project_dir, include_roots, time_budget_s) -> list[StructuralEntry]
"""
from __future__ import annotations

import ast
import logging
import time
from collections.abc import Mapping

from pathlib import Path
from typing import Any, Sequence

from .map_common import STRUCTURAL_THRESHOLDS, iter_py_files, iter_source_files
from .map_errors import MapBuilderError
from .map_models import StructuralEntry
from .source_adapters import get_adapter_for_file
from ._extract_imports_impl import _extract_imports  # noqa: PLC2701

__all__ = ["build_structural_map"]

_log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

from .runtime_builder import _freshness_now


def _rel_posix(path: Path, project_dir: Path) -> str:
    """Return path relative to project_dir as forward-slash string."""
    try:
        return path.relative_to(project_dir).as_posix()
    except ValueError:
        # Fallback: shouldn't happen since iter_py_files already resolves
        return path.as_posix()


def _is_parseable(source: str) -> bool:
    """Return False if source has a SyntaxError, True otherwise."""
    try:
        ast.parse(source)
        return True
    except SyntaxError:
        return False


def _extract_symbols_defined(source: str) -> list[str]:
    """Return class and function names defined in source (all scopes).

    Returns empty list on SyntaxError (caller already tagged unparseable).
    """
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return []
    names: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, (ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)):
            names.append(node.name)
    return names


def _collect_from_import_candidates(source: str) -> list[str]:
    """Collect additional dotted candidates from 'from X import Y' statements.

    _extract_imports adds only the module X for 'from X import Y'.
    Here we also produce 'X.Y' as a candidate, so that sub-module imports
    like 'from pkg import submod' resolve to 'pkg/submod.py'.

    Returns list of dotted strings (may contain duplicates -- dedup is done by caller).
    Silently returns empty list on SyntaxError.
    """
    candidates: list[str] = []
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return candidates
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
            for alias in node.names:
                if alias.name != "*":
                    candidates.append(f"{node.module}.{alias.name}")
    return candidates


_TS_EXTS = (".ts", ".tsx", ".js", ".jsx")


def _collect_non_python_raw_data(
    project_dir: Path,
    include_roots: "Sequence[str] | None",
    max_file_bytes: float = float("inf"),
    oversized_files: "list[dict] | None" = None,
    cancel_event: "Any | None" = None,
) -> "dict[str, dict]":
    result: dict[str, dict] = {}
    for src_file in iter_source_files(project_dir, include_roots=include_roots):
        if cancel_event is not None and cancel_event.is_set():
            _log.info("_collect_non_python_raw_data: cancelled, stopping early")
            break
        adapter = get_adapter_for_file(src_file)
        if adapter is None or adapter.language == "python" or not adapter.supports_structural:
            continue
        rel = _rel_posix(src_file, project_dir)
        # File-size guard — skip oversized non-Python files
        try:
            file_bytes = src_file.stat().st_size
        except OSError:
            file_bytes = 0
        if file_bytes > max_file_bytes:
            size_mb = file_bytes / (1024 * 1024)
            _log.warning(
                "_collect_non_python_raw_data: skipping oversized file %s (%.1f MiB)",
                src_file, size_mb,
            )
            if oversized_files is not None:
                oversized_files.append({"path": str(src_file), "size_mb": round(size_mb, 3)})
            continue
        try:
            content = src_file.read_text(encoding="utf-8", errors="replace")
        except OSError as exc:
            _log.warning("_collect_non_python_raw_data: cannot read %s: %s", src_file, exc)
            continue
        size_lines = content.count("\n") + (1 if content and not content.endswith("\n") else 0)
        try:
            import_edges = adapter.extract_imports(content, src_file)
            symbol_defs = adapter.extract_symbols(content, src_file)
            unparseable = False
        except Exception as exc:
            _log.warning("_collect_non_python_raw_data: adapter error on %s: %s", rel, exc)
            import_edges, symbol_defs, unparseable = [], [], True
        result[rel] = {
            "imports_out": list(dict.fromkeys(e.to_module for e in import_edges if e.to_module)),
            "symbols_defined": [s.name for s in symbol_defs],
            "size_lines": size_lines,
            "unparseable": unparseable,
            "language": adapter.language,
        }
    _log.debug("_collect_non_python_raw_data: %d non-Python files", len(result))
    return result


def _resolve_ts_import_to_rel(import_str: str, importer_rel: str, known_files: Mapping[str, object]) -> str | None:
    """Resolve TS/JS import specifier to known relative file key; returns None for packages."""
    if not import_str:
        return None

    def _probe(base: str) -> "str | None":
        for ext in _TS_EXTS:
            if base.endswith(ext):
                base = base[: -len(ext)]
                break
        for ext in _TS_EXTS:
            if (base + ext) in known_files:
                return base + ext
            if (base + "/index" + ext) in known_files:
                return base + "/index" + ext
        return None

    if import_str.startswith("./") or import_str.startswith("../"):
        importer_dir = "/".join(importer_rel.split("/")[:-1])
        raw = (importer_dir + "/" + import_str) if importer_dir else import_str
        parts: list[str] = []
        for p in raw.split("/"):
            if p == "..":
                if parts: parts.pop()
            elif p and p != ".":
                parts.append(p)
        return _probe("/".join(parts))
    if import_str.startswith("@/"):
        return _probe(import_str[2:])
    return None  # bare package import -- external


def _resolve_any_import(import_str: str, importer_rel: str, known_files: Mapping[str, object]) -> str | None:
    if importer_rel.endswith(".py"):
        return _resolve_import_to_rel(import_str, importer_rel, known_files)
    return _resolve_ts_import_to_rel(import_str, importer_rel, known_files)


# ---------------------------------------------------------------------------
# Tarjan SCC (iterative) — cycle detection
# ---------------------------------------------------------------------------

def _tarjan_sccs(graph: dict[str, list[str]]) -> list[list[str]]:
    """Compute all SCCs using iterative Tarjan algorithm.

    Returns list of SCCs where len > 1 (i.e., cycles only).
    Single-node SCCs without self-loops are excluded.
    """
    index_counter = [0]
    stack: list[str] = []
    lowlink: dict[str, int] = {}
    index: dict[str, int] = {}
    on_stack: dict[str, bool] = {}
    sccs: list[list[str]] = []

    nodes = list(graph.keys())

    for start in nodes:
        if start in index:
            continue
        # Iterative DFS with explicit call stack
        # Each frame: (node, iterator-over-neighbours, was-just-pushed)
        call_stack: list[tuple[str, list[str], int]] = []
        call_stack.append((start, list(graph.get(start, [])), 0))
        index[start] = lowlink[start] = index_counter[0]
        index_counter[0] += 1
        stack.append(start)
        on_stack[start] = True

        while call_stack:
            node, neighbours, ni = call_stack[-1]

            if ni < len(neighbours):
                # Advance to next neighbour
                call_stack[-1] = (node, neighbours, ni + 1)
                w = neighbours[ni]
                if w not in index:
                    # Tree edge — recurse
                    index[w] = lowlink[w] = index_counter[0]
                    index_counter[0] += 1
                    stack.append(w)
                    on_stack[w] = True
                    call_stack.append((w, list(graph.get(w, [])), 0))
                elif on_stack.get(w, False):
                    # Back edge
                    if lowlink[node] > index[w]:
                        lowlink[node] = index[w]
            else:
                # Done with all neighbours — pop frame
                call_stack.pop()
                if call_stack:
                    parent, _, _ = call_stack[-1]
                    if lowlink[parent] > lowlink[node]:
                        lowlink[parent] = lowlink[node]

                # Check if node is root of an SCC
                if lowlink[node] == index[node]:
                    scc: list[str] = []
                    while True:
                        w = stack.pop()
                        on_stack[w] = False
                        scc.append(w)
                        if w == node:
                            break
                    # Only keep SCCs with actual cycles
                    if len(scc) > 1:
                        sccs.append(scc)
                    elif scc and scc[0] in graph and scc[0] in graph.get(scc[0], []):
                        # Self-loop
                        sccs.append(scc)

    return sccs


# ---------------------------------------------------------------------------
# Main builder
# ---------------------------------------------------------------------------

def build_structural_map(
    project_dir: Path,
    include_roots: Sequence[str] | None = None,
    time_budget_s: float = 30.0,
    parse_cache: "Any | None" = None,
    cancel_event: "Any | None" = None,
) -> list[StructuralEntry]:
    """Build Map 1 (structural) for a target project directory.

    Args:
        project_dir: Root of the target project to scan.
        include_roots: Optional list of subdirectory names (relative to
            project_dir) to restrict the scan. None = whole project.
        time_budget_s: Soft time limit in seconds. Emits a warning if
            exceeded but does NOT truncate results.

    Returns:
        Sorted list of StructuralEntry, one per source file found.  Includes
        Python (.py), TypeScript (.ts/.tsx), JavaScript (.js/.jsx), Go (.go),
        and Java (.java) — all languages registered in source_adapters.ADAPTERS.

        Coverage note: the structural map (imports_out, symbols_defined) is
        multi-language.  The contracts, authority, and runtime maps are
        Python-AST-only today; non-Python adapters return empty stubs for
        those passes.

    Raises:
        MapBuilderError: On unexpected errors during scan (not SyntaxError --
            those are caught and tagged as unparseable).
    """
    project_dir = project_dir.resolve()
    _log.info(
        "build_structural_map: scanning project_dir=%s include_roots=%s",
        project_dir,
        include_roots,
    )
    t_start = time.monotonic()

    # ------------------------------------------------------------------
    # Pass 1: parse each file → collect raw data
    # ------------------------------------------------------------------
    # raw_data[rel_posix] = {imports_out, symbols_defined, size_lines, unparseable}
    raw_data: dict[str, dict] = {}

    try:
        py_files = list(iter_py_files(project_dir, include_roots))
    except Exception as exc:
        raise MapBuilderError(
            "build_structural_map: iter_py_files failed: %s" % exc
        ) from exc

    # Derive max_file_bytes from parse_cache if available (keeps the limit consistent)
    _max_file_bytes: float = getattr(parse_cache, "_max_file_bytes", float("inf"))
    _oversized: list[dict] = getattr(parse_cache, "oversized_files", [])

    for abs_path in py_files:
        if cancel_event is not None and cancel_event.is_set():
            _log.info("build_structural_map: cancelled, stopping py_files loop early")
            break
        rel = _rel_posix(abs_path, project_dir)

        # --- Fast path: use parse_cache if available ---
        if parse_cache is not None:
            parsed = parse_cache.get_or_parse(abs_path, project_dir)
            raw_data[rel] = {
                "imports_out": parsed.imports_out,
                "symbols_defined": parsed.symbols_defined,
                "size_lines": parsed.size_lines,
                "unparseable": not parsed.is_parseable,
                "language": "python",
            }
            continue

        # --- Slow path: direct read + parse (backward-compat, parse_cache=None) ---
        unparseable = False
        imports_out: list[str] = []
        symbols_defined: list[str] = []
        size_lines = 0

        try:
            source = abs_path.read_text(encoding="utf-8", errors="replace")
        except OSError as exc:
            raise MapBuilderError(
                "build_structural_map: cannot read %s: %s" % (abs_path, exc)
            ) from exc

        size_lines = source.count("\n") + (1 if source and not source.endswith("\n") else 0)

        # Check parseability first (ast.parse directly, before _extract_imports
        # which silently swallows SyntaxError and returns an empty ModuleNode)
        if not _is_parseable(source):
            unparseable = True
        else:
            # AST donor: _extract_imports returns ModuleNode
            try:
                module_node = _extract_imports(source, rel)
            except Exception as exc:
                raise MapBuilderError(
                    "build_structural_map: unexpected error parsing %s: %s" % (rel, exc)
                ) from exc

            # Combine top-level + lazy + dynamic imports — deduplicated
            seen: set[str] = set()
            for imp in (
                module_node.imports
                + module_node.lazy_imports
                + module_node.dynamic_imports
            ):
                if imp and imp not in seen:
                    seen.add(imp)
                    imports_out.append(imp)

            # Also add "module.name" candidates from "from module import name"
            # so that sub-module imports resolve correctly (e.g. from pkg import sub
            # → candidate "pkg.sub" → resolves to "pkg/sub.py")
            for candidate in _collect_from_import_candidates(source):
                if candidate and candidate not in seen:
                    seen.add(candidate)
                    imports_out.append(candidate)

            # symbols_defined: class/function names
            symbols_defined = _extract_symbols_defined(source)

        raw_data[rel] = {
            "imports_out": imports_out,
            "symbols_defined": symbols_defined,
            "size_lines": size_lines,
            "unparseable": unparseable,
            "language": "python",
        }

    # Pass 1b: non-Python structural extraction via registered adapters
    non_py_raw = _collect_non_python_raw_data(
        project_dir,
        include_roots,
        max_file_bytes=_max_file_bytes,
        oversized_files=_oversized,
        cancel_event=cancel_event,
    )
    raw_data.update(non_py_raw)

    _log.debug("build_structural_map: pass 1 done, %d files", len(raw_data))

    # ------------------------------------------------------------------
    # Pass 2: build reverse index (imports_in)
    # ------------------------------------------------------------------
    # imports_in[file] = set of files that import it
    imports_in: dict[str, set[str]] = {rel: set() for rel in raw_data}

    for rel, data in raw_data.items():
        for imp in data["imports_out"]:
            # Match against known relative keys by module-path heuristic
            # imports_out are module dotted names (e.g. "BRAIN.foo.bar" or ".bar")
            # We try to resolve them to a known rel path
            target_rel = _resolve_any_import(imp, rel, raw_data)
            if target_rel is not None and target_rel in imports_in:
                imports_in[target_rel].add(rel)

    _log.debug("build_structural_map: pass 2 done (reverse index built)")

    # ------------------------------------------------------------------
    # Cycle detection (Tarjan SCC)
    # ------------------------------------------------------------------
    graph: dict[str, list[str]] = {}
    for rel, data in raw_data.items():
        resolved_targets: list[str] = []
        for imp in data["imports_out"]:
            t = _resolve_any_import(imp, rel, raw_data)
            if t is not None:
                resolved_targets.append(t)
        graph[rel] = resolved_targets

    try:
        sccs = _tarjan_sccs(graph)
    except Exception as exc:
        raise MapBuilderError(
            "build_structural_map: cycle detection failed: %s" % exc
        ) from exc

    # Map each file to its cycle members (excluding itself)
    cycle_map: dict[str, list[str]] = {}
    for scc in sccs:
        scc_set = set(scc)
        for member in scc:
            cycle_map[member] = sorted(scc_set - {member})

    _log.debug(
        "build_structural_map: cycle detection done, %d SCCs with cycles",
        len(sccs),
    )

    # ------------------------------------------------------------------
    # Build StructuralEntry list
    # ------------------------------------------------------------------
    large_file_threshold = STRUCTURAL_THRESHOLDS["large_file_lines"]
    high_fan_in_threshold = STRUCTURAL_THRESHOLDS["high_fan_in"]
    high_fan_out_threshold = STRUCTURAL_THRESHOLDS["high_fan_out"]

    freshness = _freshness_now()
    entries: list[StructuralEntry] = []

    for rel in sorted(raw_data.keys()):
        data = raw_data[rel]
        size_lines = data["size_lines"]
        imports_out_list = data["imports_out"]
        symbols_defined = data["symbols_defined"]
        unparseable = data["unparseable"]
        imports_in_list = sorted(imports_in.get(rel, set()))
        cycles_list = cycle_map.get(rel, [])

        tags: list[str] = []
        if unparseable:
            tags.append("unparseable")
        if size_lines > large_file_threshold:
            tags.append("large_file")
        if len(imports_in_list) > high_fan_in_threshold:
            tags.append("high_fan_in")
        if len(imports_out_list) > high_fan_out_threshold:
            tags.append("high_fan_out")
        if cycles_list:
            tags.append("cycle_member")

        entry = StructuralEntry(
            file=rel,
            language=data.get("language", "unknown"),
            size_lines=size_lines,
            imports_out=tuple(imports_out_list),
            imports_in=tuple(imports_in_list),
            symbols_defined=tuple(symbols_defined),
            symbols_used_external=(),
            cycles=tuple(cycles_list),
            tags=tuple(sorted(tags)),
            source="static_scan",
            evidence=(rel,),
            confidence=0.95,
            freshness=freshness,
            status="inferred",
        )
        entries.append(entry)

    elapsed = time.monotonic() - t_start
    if elapsed > time_budget_s:
        _log.warning(
            "build_structural_map: SLA exceeded -- %.1fs > %.1fs budget (%d files)",
            elapsed,
            time_budget_s,
            len(entries),
        )
    else:
        _log.info(
            "build_structural_map: done in %.2fs, %d entries",
            elapsed,
            len(entries),
        )

    return entries


# ---------------------------------------------------------------------------
# Import resolution helper
# ---------------------------------------------------------------------------

def _resolve_import_to_rel(
    import_name: str,
    importer_rel: str,
    known_files: Mapping[str, object],
) -> str | None:
    """Try to map a dotted import name to a known relative file path.

    Handles:
    - Absolute dotted names: "foo.bar.baz" -> "foo/bar/baz.py" or "foo/bar/baz/__init__.py"
    - Relative imports: ".foo" or "..foo" (resolved relative to importer's package)

    Returns the matching key from known_files or None if unresolvable.
    """
    if not import_name:
        return None

    # Resolve relative imports
    if import_name.startswith("."):
        dots = len(import_name) - len(import_name.lstrip("."))
        rest = import_name.lstrip(".")
        # Importer's package dir (strip filename, go up `dots-1` levels)
        parts = importer_rel.split("/")
        pkg_parts = parts[:-dots] if dots <= len(parts) else []
        if rest:
            pkg_parts = pkg_parts + rest.split(".")
        candidate_module = "/".join(pkg_parts)
    else:
        candidate_module = "/".join(import_name.split("."))

    if not candidate_module:
        return None

    # Try direct .py file
    candidate_py = candidate_module + ".py"
    if candidate_py in known_files:
        return candidate_py

    # Try package __init__.py
    candidate_init = candidate_module + "/__init__.py"
    if candidate_init in known_files:
        return candidate_init

    return None
