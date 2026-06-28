"""agent-brief: synthesise an agent-facing briefing from repo maps.

Verified at TWO levels (lesson: ML gates were DEAD despite green unit tests because
only the builder was tested, not the tool path):
  1. _build_agent_brief() directly  (unit)
  2. get_code_map_results(view="brief")  (the actual MCP tool path)
"""
from __future__ import annotations

import json

import vigil_mcp.map_server as ms
from vigil_mcp.map_server import _build_agent_brief


_FAKE_MAPS = {
    "runtime": [{"node": "main", "file": "app.py"}],
    "authority": [{"canonical_owner": "store.py", "name": "store.py"}],
    "hotspot": [
        {"target": "big.py", "file": "big.py", "hotspot_score": 23},
        {"target": "mid.py", "file": "mid.py", "hotspot_score": 9},
    ],
    "conflict": [{"subject": "duplicate config loader"}],
    "schema_version": "1.0",
}


# --- unit: builder -------------------------------------------------------

def test_brief_synthesises_all_sections():
    b = _build_agent_brief(_FAKE_MAPS)
    brief = b["brief"]
    assert "Entry points" in brief and "main" in brief
    assert "write-sites" in brief and "store.py" in brief
    assert "Riskiest" in brief and "big.py" in brief
    assert "Watch-outs" in brief and "duplicate config loader" in brief
    assert "Suggested read order" in brief


def test_brief_read_order_entrypoints_before_hotspots():
    sig = _build_agent_brief(_FAKE_MAPS)["signals"]
    ro = sig["suggested_read_order"]
    assert ro and ro[0] == "app.py"          # entry point first
    assert "big.py" in ro and "mid.py" in ro  # hotspots follow
    # hotspots sorted by score desc
    assert ro.index("big.py") < ro.index("mid.py")


def test_brief_empty_maps_is_graceful():
    b = _build_agent_brief({})
    assert "No structural signals" in b["brief"]
    assert b["signals"]["suggested_read_order"] == []


# --- e2e: the real MCP tool path ----------------------------------------

def test_brief_via_get_code_map_results(monkeypatch):
    monkeypatch.setattr(
        ms._jobs, "result",
        lambda jid: {"status": "done", "result": {"exit_code": 0}},
    )
    monkeypatch.setattr(ms, "_repo_maps_to_serialisable", lambda _x: _FAKE_MAPS)

    out = ms.get_code_map_results("job-1", view="brief")
    assert out["status"] == "done"
    assert out["view"] == "brief"
    payload = json.loads(out["payload"])
    brief = payload["maps"]["brief"]
    assert "Agent briefing" in brief
    assert "app.py" in brief and "store.py" in brief
