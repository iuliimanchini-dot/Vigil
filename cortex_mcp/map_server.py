"""FastMCP stdio server: code-map

Wraps cortex_map_builder.run_map_build + load_repo_maps behind a
background-job poll API. Resource constraints:
- At most 2 concurrent jobs (enforced by _jobs.JobRegistry).
- One thread per job (no pool).
- Output truncated/paginated to OUTPUT_CHAR_LIMIT chars to stay within
  MCP token limits (~25 k tokens ≈ ~100 k chars; we use 80 k to be safe).
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from mcp.server.fastmcp import FastMCP

from cortex_mcp import _jobs
from cortex_mcp import _paths
from cortex_map_builder import run_map_build, load_repo_maps

_INSTRUCTIONS = """\
code-map - builds structural maps of a codebase across Python/Go/Java/JS/TS:
imports/dependencies, defined symbols, runtime entry points, data contracts,
authority/write sites, risk hotspots, and refactor boundaries. Static analysis
(tree-sitter/AST) - it never runs the project.

WHEN TO USE: when the user wants to understand an unfamiliar codebase's architecture,
find what imports/depends on what, locate runtime entry points or risk hotspots, or
scope a refactor. Not a code-quality auditor (use forensic-audit for bugs/smells).

WORKFLOW (background job + poll):
  1. start_code_map(path="", map="all") -> leave path empty to auto-detect the project
     root from the current directory; returns {job_id, resolved_path}.
  2. get_code_map_status(job_id)         -> poll until status == "done".
  3. get_code_map_results(job_id)        -> COMPACT SUMMARY by default (per-map-type
     counts + top entries). Read this FIRST; it fits the context budget.
  4. Drill in: get_code_map_results(job_id, map="structural") for one full map type,
     or view="full" for every map (both paginated via page=).
  Also: load_code_map_by_path(path) re-reads maps built in an earlier session (no job).

SEEDS (optional refinement): 6 maps need no config. Three can be refined by a JSON
seed under <project>/.cortex/map_seeds/:
  - authority_domains.json: group write sites into named domains (without it, each
    writer is auto-surfaced on its own).
  - runtime_seed.json: declare extra runtime nodes beyond auto-discovered entrypoints.
  - refactor_boundaries.json: define the refactor goal/boundaries (refactor_boundary
    is seed-driven and needs a goal).
See docs/usage/code-map.* (section "Seeds") for the JSON format and templates.

NOTE: output is summary-first to stay within the context budget; maps are cached on
disk under <project>/.cortex/ so re-runs are cheap.
"""

mcp = FastMCP("code-map", instructions=_INSTRUCTIONS)

# ~80 k chars keeps well under the 25 k token MCP output limit.
OUTPUT_CHAR_LIMIT = 80_000

# Map list keys present in the serialisable maps dict.
_MAP_TYPES = (
    "structural",
    "runtime",
    "data_contract",
    "authority",
    "conflict",
    "hotspot",
    "refactor_boundary",
    "findings",
)

# Per-map-type cap for entries shown in the compact summary view.
_TOP_ENTRIES_CAP = 10


# ---------------------------------------------------------------------------
# Serialisation helpers
# ---------------------------------------------------------------------------

def _entry_to_dict(entry: Any) -> Any:
    """Convert a dataclass entry to a plain dict via to_dict() if available."""
    if hasattr(entry, "to_dict"):
        return entry.to_dict()
    if hasattr(entry, "__dict__"):
        return vars(entry)
    return str(entry)


def _repo_maps_to_serialisable(repo_maps: Any) -> dict:
    """Flatten a RepoMaps instance into a plain dict of lists."""
    if repo_maps is None:
        return {"missing": True}
    if getattr(repo_maps, "missing", False):
        return {
            "missing": True,
            "note": "maps directory not found - run start_code_map first",
        }
    return {
        "missing": False,
        "schema_version": getattr(repo_maps, "schema_version", "unknown"),
        "structural": [_entry_to_dict(e) for e in (repo_maps.structural or ())],
        "runtime": [_entry_to_dict(e) for e in (repo_maps.runtime or ())],
        "data_contract": [_entry_to_dict(e) for e in (repo_maps.data_contract or ())],
        "authority": [_entry_to_dict(e) for e in (repo_maps.authority or ())],
        "conflict": [_entry_to_dict(e) for e in (repo_maps.conflict or ())],
        "hotspot": [_entry_to_dict(e) for e in (repo_maps.hotspot or ())],
        "refactor_boundary": [
            _entry_to_dict(e) for e in (repo_maps.refactor_boundary or ())
        ],
        "findings": [_entry_to_dict(e) for e in (repo_maps.findings or ())],
    }


def _paginate_json(data: Any, page: int, page_size_chars: int) -> dict:
    """Serialise *data* to JSON and return a page slice with metadata."""
    full_json = json.dumps(data, default=str, indent=2)
    total = len(full_json)
    start_char = page * page_size_chars
    end_char = start_char + page_size_chars
    return {
        "payload": full_json[start_char:end_char],
        "truncated": end_char < total,
        "total_chars": total,
        "page": page,
        "total_pages": (total + page_size_chars - 1) // page_size_chars,
    }


# ---------------------------------------------------------------------------
# Summary builder (Feature 2 - summary-first map results)
# ---------------------------------------------------------------------------

def _compact_map_entry(entry: Any) -> dict:
    """Project a map entry down to a few compact fields for the summary.

    Map types use different field names for an entry's identity:
    structural->file, data_contract->entity, hotspot->target, runtime->node,
    conflict->subject, findings->title, refactor_boundary->boundary_id. Pull the
    first present so the summary is MEANINGFUL for every map (not all-null).
    """
    if not isinstance(entry, dict):
        return {"value": str(entry)}
    name = (
        entry.get("name") or entry.get("entity") or entry.get("target")
        or entry.get("node") or entry.get("subject") or entry.get("title")
        or entry.get("boundary_id") or entry.get("conflict_id")
        or entry.get("finding_id") or entry.get("authority_domain")
    )
    file = (
        entry.get("file") or entry.get("defined_in")
        or entry.get("canonical_schema") or entry.get("canonical_owner")
        or entry.get("path")
    )
    compact: dict[str, Any] = {"name": name, "file": file}
    if entry.get("line") is not None:
        compact["line"] = entry.get("line")
    # One signal metric if present (varies by map type).
    for metric in ("hotspot_score", "severity", "size", "complexity", "score", "count"):
        if entry.get(metric) is not None:
            compact[metric] = entry[metric]
            break
    return compact


def _build_map_summary(maps_data: dict) -> dict:
    """Build a compact summary of serialised repo maps.

    Args:
        maps_data: Output of ``_repo_maps_to_serialisable`` (a dict with one
                   list per map type).

    Returns:
        A dict with ``by_map_type`` (per-type counts), ``top_entries``
        (up to ``_TOP_ENTRIES_CAP`` compact entries per non-empty type),
        ``schema_version``, ``missing`` and a ``hint``.
    """
    by_map_type: dict[str, int] = {}
    top_entries: dict[str, list[dict]] = {}
    for map_type in _MAP_TYPES:
        entries = maps_data.get(map_type) or []
        by_map_type[map_type] = len(entries)
        if entries:
            top_entries[map_type] = [
                _compact_map_entry(e) for e in entries[:_TOP_ENTRIES_CAP]
            ]

    hint = (
        "Compact map summary. For all entries of one map call "
        "get_code_map_results with map='<type>' (e.g. 'structural'), or "
        "view='full' for every map. Paging via page=."
    )

    return {
        "missing": bool(maps_data.get("missing", False)),
        "schema_version": maps_data.get("schema_version", "unknown"),
        "by_map_type": by_map_type,
        "top_entries": top_entries,
        "hint": hint,
    }


# ---------------------------------------------------------------------------
# Internal: path-preserving wrapper around run_map_build
# ---------------------------------------------------------------------------

def _run_map_build_with_path(path: str, map: str = "all") -> dict:
    """Run the map build and bundle the project path into the return value
    so that get_code_map_results can call load_repo_maps without extra args.
    """
    exit_code = run_map_build(Path(path), map=map, timeout_s=300)
    return {"exit_code": exit_code, "_path": path}


# ---------------------------------------------------------------------------
# MCP tools
# ---------------------------------------------------------------------------

@mcp.tool()
def start_code_map(path: str = "", map: str = "all") -> dict:
    """Start a background code-map build job for the given project path.

    Args:
        path: Absolute path to the project root directory.  When empty/omitted
              the project root is auto-detected by walking up from the current
              working directory for a ``.git`` / ``pyproject.toml`` /
              ``package.json`` marker (falling back to cwd).  The chosen
              directory is returned as ``resolved_path``.
        map:  Map type to build - "all" (default) or a specific map name
              recognised by cortex_map_builder (e.g. "structural").

    Returns:
        {"job_id": str | None, "status": "running" | "busy",
         "resolved_path": str, ...}
        When status is "busy" the server is at max concurrent jobs; retry later.
    """
    # Auto-target: resolve only when no explicit path was given.
    if path:
        resolved_path = path
    else:
        resolved_path = _paths._resolve_project_root(None)

    # project_dir enables disk-backed persistence so results survive a server
    # restart; get_code_map_status/results then resolve by job_id from disk.
    started = _jobs.start(
        _run_map_build_with_path, resolved_path, map=map, project_dir=resolved_path
    )
    started["resolved_path"] = resolved_path
    return started


@mcp.tool()
def get_code_map_status(job_id: str) -> dict:
    """Poll the status of a code-map build job.

    Args:
        job_id: Job ID returned by start_code_map.

    Returns:
        {"job_id": str, "status": "running" | "done" | "error" | "cancelled" | "not_found"}
    """
    return _jobs.status(job_id)


@mcp.tool()
def get_code_map_results(
    job_id: str,
    view: str = "summary",
    map: str = "",
    page: int = 0,
    page_size_chars: int = OUTPUT_CHAR_LIMIT,
) -> dict:
    """Retrieve results of a completed code-map build.

    Three modes (loads maps written to disk by run_map_build):
      * ``view='summary'`` (default) - per-map-type counts + the top entries
        per map.  Compact; fits the MCP context budget.  Use this first.
      * ``map='<type>'`` - every entry of a single map (e.g. 'structural'),
        paginated.  Takes precedence over ``view``.
      * ``view='full'`` - every entry of every map, paginated.

    Args:
        job_id:          Job ID returned by start_code_map.
        view:            "summary" (default) or "full".
        map:             A single map type to return in full (e.g.
                         "structural").  Empty = honour ``view``.
        page:            Zero-based page index (each page ≈ page_size_chars chars).
        page_size_chars: Max chars per page (default 80 000 ≈ 25 k tokens).

    Returns:
        dict with "job_id", "status", "view", "exit_code", "payload"
        (JSON string), "truncated" (bool), "total_chars", "page", "total_pages".
    """
    r = _jobs.result(job_id)
    status = r.get("status")

    if status in ("running", "not_found"):
        return {
            "job_id": job_id, "status": status,
            "payload": None, "truncated": False, "total_chars": 0,
        }
    if status == "cancelled":
        return {
            "job_id": job_id, "status": "cancelled",
            "payload": None, "truncated": False, "total_chars": 0,
        }
    if status == "error":
        return {
            "job_id": job_id, "status": "error", "error": r.get("error"),
            "payload": None, "truncated": False, "total_chars": 0,
        }

    # status == "done"
    inner = r.get("result") or {}
    exit_code = inner.get("exit_code") if isinstance(inner, dict) else inner
    path_str = inner.get("_path") if isinstance(inner, dict) else None

    if path_str:
        try:
            repo_maps = load_repo_maps(Path(path_str))
            maps_data = _repo_maps_to_serialisable(repo_maps)
        except Exception as exc:
            maps_data = {"error": str(exc)}
    else:
        # _repo_maps_to_serialisable is monkeypatchable; call it so tests that
        # patch it can inject fake maps even when no path is available.
        maps_data = _repo_maps_to_serialisable(None)

    # Decide the projection of maps_data based on map / view.
    effective_view = "summary"
    if map and map != "all":
        # Single-map view: only the requested map type's entries.
        rendered_maps: dict = {map: maps_data.get(map, [])}
        effective_view = f"map:{map}"
    elif view == "full":
        rendered_maps = maps_data
        effective_view = "full"
    else:
        rendered_maps = _build_map_summary(maps_data)
        effective_view = "summary"

    full_data = {"exit_code": exit_code, "maps": rendered_maps}
    page_data = _paginate_json(full_data, page=page, page_size_chars=page_size_chars)

    return {
        "job_id": job_id, "status": "done", "view": effective_view,
        "exit_code": exit_code, **page_data,
    }


@mcp.tool()
def load_code_map_by_path(
    path: str,
    page: int = 0,
    page_size_chars: int = OUTPUT_CHAR_LIMIT,
) -> dict:
    """Load previously built maps from disk for a given project path (no job needed).

    Useful when maps were built in a prior session, or to re-read results.

    Args:
        path:            Absolute path to the project root.
        page:            Zero-based page index.
        page_size_chars: Max chars per page.
    """
    try:
        repo_maps = load_repo_maps(Path(path))
        maps_data = _repo_maps_to_serialisable(repo_maps)
    except Exception as exc:
        return {"status": "error", "error": str(exc)}

    page_data = _paginate_json(maps_data, page=page, page_size_chars=page_size_chars)
    return {"status": "ok", **page_data}


@mcp.tool()
def cancel_code_map(job_id: str) -> dict:
    """Cancel a running code-map build job.

    Args:
        job_id: Job ID returned by start_code_map.

    Returns:
        {"job_id": str, "cancelled": bool, ...}
    """
    return _jobs.cancel(job_id)


def main() -> None:
    mcp.run()


if __name__ == "__main__":
    main()
