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
from cortex_map_builder import run_map_build, load_repo_maps

mcp = FastMCP("code-map")

# ~80 k chars keeps well under the 25 k token MCP output limit.
OUTPUT_CHAR_LIMIT = 80_000


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
            "note": "maps directory not found — run start_code_map first",
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
def start_code_map(path: str, map: str = "all") -> dict:
    """Start a background code-map build job for the given project path.

    Args:
        path: Absolute path to the project root directory.
        map:  Map type to build — "all" (default) or a specific map name
              recognised by cortex_map_builder (e.g. "structural").

    Returns:
        {"job_id": str | None, "status": "running" | "busy", ...}
        When status is "busy" the server is at max concurrent jobs; retry later.
    """
    return _jobs.start(_run_map_build_with_path, path, map=map)


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
    page: int = 0,
    page_size_chars: int = OUTPUT_CHAR_LIMIT,
) -> dict:
    """Retrieve results of a completed code-map build (paginated).

    Loads maps written to disk by run_map_build and returns them as
    structured data. Large payloads are paginated to stay within MCP limits.

    Args:
        job_id:          Job ID returned by start_code_map.
        page:            Zero-based page index (each page ≈ page_size_chars chars).
        page_size_chars: Max chars per page (default 80 000 ≈ 25 k tokens).

    Returns:
        dict with "job_id", "status", "exit_code", "payload" (JSON string),
        "truncated" (bool), "total_chars", "page", "total_pages".
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
        maps_data = {"note": "path unavailable; use load_code_map_by_path"}

    full_data = {"exit_code": exit_code, "maps": maps_data}
    page_data = _paginate_json(full_data, page=page, page_size_chars=page_size_chars)

    return {"job_id": job_id, "status": "done", "exit_code": exit_code, **page_data}


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
