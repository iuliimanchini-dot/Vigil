"""End-to-end MCP protocol tests for the two cortex FastMCP stdio servers.

Unlike ``test_mcp_smoke.py`` (which imports and calls the tool *functions*
directly, bypassing the wire protocol), these tests launch each server as a
**real subprocess** and drive it with the genuine MCP Python client
(``mcp.ClientSession`` over ``mcp.client.stdio.stdio_client``).  They exercise
the actual JSON-RPC stdio transport: ``initialize`` -> ``list_tools`` ->
``call_tool`` (start) -> poll ``get_*_status`` -> ``call_tool`` (results).

Why this matters: the in-process smoke tests can pass even if the server
cannot start over stdio, a tool errors when invoked through the protocol, or a
result fails to JSON-serialise across the wire.  This file proves the servers
work as MCP servers, not just as Python modules.

Design notes
------------
* The servers are launched via ``<python> -m cortex_mcp.<server>`` — both
  modules expose ``if __name__ == "__main__": main()`` which calls
  ``mcp.run()`` (stdio transport by default).  Verified to launch this way.
* These tools are annotated ``-> dict`` (a *bare* ``dict``).  FastMCP does not
  build an output schema for a bare ``dict`` (only ``dict[str, X]`` / TypedDict
  / BaseModel get one), so ``CallToolResult.structuredContent`` is ``None`` and
  the dict is returned as JSON text in ``content[0].text``.  ``_tool_payload``
  handles both shapes (prefers ``structuredContent`` if a future change adds a
  schema, else parses the text block).
* pytest-asyncio is **not** installed in this venv, and the existing suite is
  fully synchronous.  Each test is therefore a plain sync test that drives the
  async client via ``asyncio.run(...)``.
* Resource-light: a 2-file tmp project, a bounded (<=60 s) poll loop, and the
  ``stdio_client`` async context manager — which performs the MCP shutdown
  sequence (close stdin -> wait -> SIGTERM -> SIGKILL, via a Windows Job
  Object) — guarantees the subprocess is reaped, leaving no orphan.
"""
from __future__ import annotations

import asyncio
import json
import sys
import textwrap
import time
from pathlib import Path
from typing import Any

import pytest

from mcp import ClientSession
from mcp.client.stdio import StdioServerParameters, stdio_client

# Bounded wall-clock budget for a single job to reach a terminal state.
_POLL_TIMEOUT_S = 60.0
_POLL_INTERVAL_S = 0.4

# A "small" summary payload should comfortably fit the MCP context budget.
# The default summary view caps findings/entries hard; on a tiny project it is
# a few KB.  We assert it stays well under the server's 80 000-char page size.
_SMALL_PAYLOAD_CHARS = 80_000


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_tiny_project(root: Path) -> Path:
    """Create a minimal 2-file Python project for the auditors to scan."""
    proj = root / "tiny_e2e_proj"
    proj.mkdir()
    (proj / "alpha.py").write_text(
        textwrap.dedent("""\
            def add(a, b):
                return a + b
        """),
        encoding="utf-8",
    )
    (proj / "beta.py").write_text(
        textwrap.dedent("""\
            import os

            def cwd() -> str:
                return os.getcwd()
        """),
        encoding="utf-8",
    )
    return proj


def _tool_payload(result: Any) -> dict:
    """Extract the structured dict a tool returned, over the wire.

    Prefers ``structuredContent`` (populated when a tool has an output schema);
    falls back to JSON-parsing the first text content block (the case for these
    bare-``dict`` tools).  Asserts the call did not error at the protocol level.
    """
    assert result.isError is False, f"tool returned isError=True: {result.content!r}"
    if result.structuredContent is not None:
        return result.structuredContent
    assert result.content, "tool returned no content blocks"
    block = result.content[0]
    assert getattr(block, "type", None) == "text", f"unexpected content block: {block!r}"
    return json.loads(block.text)


def _server_params(module: str, cwd: Path) -> StdioServerParameters:
    """Launch params for ``<python> -m <module>`` rooted at *cwd*."""
    return StdioServerParameters(
        command=sys.executable,
        args=["-m", module],
        cwd=str(cwd),
    )


async def _poll_until_terminal(
    session: ClientSession, status_tool: str, job_id: str
) -> str:
    """Poll *status_tool* via the protocol until status != 'running' (bounded)."""
    deadline = time.monotonic() + _POLL_TIMEOUT_S
    last = "running"
    while time.monotonic() < deadline:
        status = _tool_payload(await session.call_tool(status_tool, {"job_id": job_id}))
        last = status.get("status", "unknown")
        if last != "running":
            return last
        await asyncio.sleep(_POLL_INTERVAL_S)
    return "timeout(" + last + ")"


# ---------------------------------------------------------------------------
# Forensic server — real stdio protocol
# ---------------------------------------------------------------------------

async def _forensic_e2e(tmp_path: Path) -> None:
    proj = _make_tiny_project(tmp_path)
    params = _server_params("cortex_mcp.forensic_server", cwd=proj)

    async with stdio_client(params) as (read, write):
        async with ClientSession(read, write) as session:
            # 1. initialize
            init = await session.initialize()
            assert init.serverInfo.name == "forensic-audit", init.serverInfo

            # 2. list_tools — expected tool set present
            listed = await session.list_tools()
            names = {t.name for t in listed.tools}
            expected = {
                "start_forensic_audit",
                "get_forensic_status",
                "get_forensic_results",
                "cancel_forensic_audit",
            }
            assert expected <= names, f"missing tools: {expected - names}"

            # 3. start with explicit path -> job_id
            start = _tool_payload(
                await session.call_tool(
                    "start_forensic_audit", {"path": str(proj), "severity": "LOW"}
                )
            )
            assert start["status"] == "running", f"unexpected start: {start}"
            job_id = start["job_id"]
            assert job_id

            # 4. poll until terminal (bounded)
            final = await _poll_until_terminal(session, "get_forensic_status", job_id)
            assert final == "done", f"forensic audit did not finish cleanly: {final}"

            # 5. get results (default summary view) — assert summary shape + size
            results = _tool_payload(
                await session.call_tool("get_forensic_results", {"job_id": job_id})
            )
            assert results["status"] == "done"
            assert results["view"] == "summary"
            assert results["exit_code"] in (0, 1)
            assert results.get("total_chars", 1 << 30) <= _SMALL_PAYLOAD_CHARS

            summary = json.loads(results["payload"])
            # forensic summary contract: total + by_severity buckets.
            assert "total" in summary
            assert isinstance(summary["total"], int)
            assert "by_severity" in summary
            assert set(summary["by_severity"]) == {"high", "medium", "low"}
            assert all(isinstance(v, int) for v in summary["by_severity"].values())

            # 6. auto-path: empty path resolves to a project root (returned).
            auto = _tool_payload(
                await session.call_tool("start_forensic_audit", {"path": ""})
            )
            assert auto.get("resolved_path"), f"no resolved_path: {auto}"
            # Auto-target resolves to the cwd we launched under (the tiny proj),
            # since it carries no VCS marker and the walk falls back to start.
            assert Path(auto["resolved_path"]) == proj
            if auto.get("job_id"):  # cancel so it never runs to completion
                await session.call_tool(
                    "cancel_forensic_audit", {"job_id": auto["job_id"]}
                )


def test_forensic_server_stdio_e2e(tmp_path):
    asyncio.run(_forensic_e2e(tmp_path))


# ---------------------------------------------------------------------------
# Map server — real stdio protocol
# ---------------------------------------------------------------------------

async def _map_e2e(tmp_path: Path) -> None:
    proj = _make_tiny_project(tmp_path)
    params = _server_params("cortex_mcp.map_server", cwd=proj)

    async with stdio_client(params) as (read, write):
        async with ClientSession(read, write) as session:
            # 1. initialize
            init = await session.initialize()
            assert init.serverInfo.name == "code-map", init.serverInfo

            # 2. list_tools — expected tool set present
            listed = await session.list_tools()
            names = {t.name for t in listed.tools}
            expected = {
                "start_code_map",
                "get_code_map_status",
                "get_code_map_results",
                "load_code_map_by_path",
                "cancel_code_map",
            }
            assert expected <= names, f"missing tools: {expected - names}"

            # 3. start with explicit path -> job_id
            start = _tool_payload(
                await session.call_tool("start_code_map", {"path": str(proj)})
            )
            assert start["status"] == "running", f"unexpected start: {start}"
            job_id = start["job_id"]
            assert job_id

            # 4. poll until terminal (bounded)
            final = await _poll_until_terminal(session, "get_code_map_status", job_id)
            assert final == "done", f"map build did not finish cleanly: {final}"

            # 5. get results (default summary view) — assert summary shape + size
            results = _tool_payload(
                await session.call_tool("get_code_map_results", {"job_id": job_id})
            )
            assert results["status"] == "done"
            assert results["view"] == "summary"
            assert results["exit_code"] == 0
            assert results.get("total_chars", 1 << 30) <= _SMALL_PAYLOAD_CHARS

            payload = json.loads(results["payload"])
            maps = payload["maps"]
            # map summary contract: per-map-type counts.
            assert "by_map_type" in maps
            by_type = maps["by_map_type"]
            assert isinstance(by_type, dict)
            assert "structural" in by_type
            # The tiny project has 2 top-level defs -> 2 structural entries.
            assert by_type["structural"] >= 1
            assert all(isinstance(v, int) for v in by_type.values())

            # 6. auto-path: empty path resolves to a project root (returned).
            auto = _tool_payload(await session.call_tool("start_code_map", {"path": ""}))
            assert auto.get("resolved_path"), f"no resolved_path: {auto}"
            assert Path(auto["resolved_path"]) == proj
            if auto.get("job_id"):  # cancel so it never runs to completion
                await session.call_tool("cancel_code_map", {"job_id": auto["job_id"]})


def test_map_server_stdio_e2e(tmp_path):
    asyncio.run(_map_e2e(tmp_path))
