"""Smoke tests for cortex_mcp.

Resource-light: uses a tiny tmp project, no xdist, single-threaded poll loops.
Tests drive the Python functions directly (no MCP wire protocol needed).
"""
from __future__ import annotations

import time
import textwrap
from pathlib import Path

import pytest

from cortex_mcp._jobs import JobRegistry


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _poll(status_fn, job_id: str, max_wait: float = 60.0, interval: float = 0.25) -> str:
    """Poll status_fn(job_id) until status is not 'running', return final status."""
    deadline = time.monotonic() + max_wait
    while time.monotonic() < deadline:
        s = status_fn(job_id)
        if s.get("status") != "running":
            return s.get("status", "unknown")
        time.sleep(interval)
    return "timeout"


def _make_tiny_project(tmp_path: Path) -> Path:
    """Create a minimal Python project for the auditors to scan."""
    proj = tmp_path / "tiny_proj"
    proj.mkdir()
    (proj / "hello.py").write_text(
        textwrap.dedent("""\
            def greet(name: str) -> str:
                return f"Hello, {name}!"
        """),
        encoding="utf-8",
    )
    (proj / "README.md").write_text("# Tiny project\n", encoding="utf-8")
    return proj


# ---------------------------------------------------------------------------
# _jobs unit tests
# ---------------------------------------------------------------------------

class TestJobRegistry:
    def test_start_and_done(self):
        reg = JobRegistry(max_concurrent=2)
        r = reg.start(lambda: 42)
        assert r["status"] == "running"
        jid = r["job_id"]
        assert jid is not None

        final = _poll(reg.status, jid, max_wait=10.0)
        assert final == "done"

        result = reg.result(jid)
        assert result["status"] == "done"
        assert result["result"] == 42

    def test_error_captured(self):
        reg = JobRegistry(max_concurrent=2)

        def _boom():
            raise RuntimeError("intentional test error")

        r = reg.start(_boom)
        jid = r["job_id"]
        final = _poll(reg.status, jid, max_wait=10.0)
        assert final == "error"
        result = reg.result(jid)
        assert "intentional test error" in (result.get("error") or "")

    def test_concurrent_cap(self):
        """With cap=1, second start while first is running returns busy."""
        import threading

        reg = JobRegistry(max_concurrent=1)
        gate = threading.Event()

        def _slow():
            gate.wait(timeout=15.0)
            return "done"

        r1 = reg.start(_slow)
        assert r1["status"] == "running"

        # Second job should be refused.
        r2 = reg.start(lambda: "quick")
        assert r2["status"] == "busy"
        assert r2["job_id"] is None

        # Release the first job.
        gate.set()
        _poll(reg.status, r1["job_id"], max_wait=10.0)

        # Now a new job should be accepted.
        r3 = reg.start(lambda: "after")
        assert r3["status"] == "running"
        _poll(reg.status, r3["job_id"], max_wait=10.0)

    def test_cancel(self):
        import threading

        reg = JobRegistry(max_concurrent=2)
        gate = threading.Event()

        def _slow():
            gate.wait(timeout=15.0)
            return "finished"

        r = reg.start(_slow)
        jid = r["job_id"]

        cancel_result = reg.cancel(jid)
        assert cancel_result["cancelled"] is True

        # status should be cancelled
        s = reg.status(jid)
        assert s["status"] == "cancelled"

        # Cancelling again should return cancelled=False (already terminal)
        cancel_again = reg.cancel(jid)
        assert cancel_again["cancelled"] is False

        gate.set()  # release thread

    def test_not_found(self):
        reg = JobRegistry()
        s = reg.status("nonexistent-id")
        assert s["status"] == "not_found"
        r = reg.result("nonexistent-id")
        assert r["status"] == "not_found"
        c = reg.cancel("nonexistent-id")
        assert c["cancelled"] is False


# ---------------------------------------------------------------------------
# Forensic audit smoke test
# ---------------------------------------------------------------------------

class TestForensicMCP:
    def test_start_poll_results(self, tmp_path):
        from cortex_mcp.forensic_server import (
            start_forensic_audit,
            get_forensic_status,
            get_forensic_results,
        )

        proj = _make_tiny_project(tmp_path)
        start = start_forensic_audit(str(proj), gates="", severity="LOW")
        assert start["status"] == "running", f"unexpected: {start}"
        jid = start["job_id"]

        final_status = _poll(get_forensic_status, jid, max_wait=120.0, interval=0.5)
        assert final_status == "done", f"forensic audit did not finish: {final_status}"

        results = get_forensic_results(jid)
        assert results["status"] == "done"
        assert results["exit_code"] in (0, 1)
        # payload must be a non-empty JSON string
        assert results["payload"] is not None
        assert len(results["payload"]) > 0

        import json
        data = json.loads(results["payload"])
        assert "findings" in data, f"'findings' key missing from result: {list(data.keys())}"
        assert isinstance(data["findings"], list)

        # Confirm truncation metadata always present
        assert "truncated" in results
        assert "total_chars" in results

    def test_cancel_forensic(self, tmp_path):
        from cortex_mcp.forensic_server import (
            start_forensic_audit,
            get_forensic_status,
            cancel_forensic_audit,
        )

        proj = _make_tiny_project(tmp_path)
        r = start_forensic_audit(str(proj))
        jid = r["job_id"]

        # Cancel immediately (may already be done on tiny proj — that's fine)
        c = cancel_forensic_audit(jid)
        assert isinstance(c.get("cancelled"), bool)


# ---------------------------------------------------------------------------
# Map build smoke test
# ---------------------------------------------------------------------------

class TestMapMCP:
    def test_start_poll_results(self, tmp_path):
        from cortex_mcp.map_server import (
            start_code_map,
            get_code_map_status,
            get_code_map_results,
        )

        proj = _make_tiny_project(tmp_path)
        start = start_code_map(str(proj))
        assert start["status"] == "running", f"unexpected: {start}"
        jid = start["job_id"]

        final_status = _poll(get_code_map_status, jid, max_wait=120.0, interval=0.5)
        assert final_status in ("done", "error"), (
            f"map build did not finish: {final_status}"
        )

        results = get_code_map_results(jid)
        assert results["status"] in ("done", "error")
        assert "truncated" in results
        assert "total_chars" in results

        if results["status"] == "done":
            assert results["payload"] is not None
            import json
            data = json.loads(results["payload"])
            assert "maps" in data or "exit_code" in data

    def test_load_by_path_missing(self, tmp_path):
        """load_code_map_by_path on a path with no built maps returns missing flag."""
        from cortex_mcp.map_server import load_code_map_by_path

        result = load_code_map_by_path(str(tmp_path))
        assert result["status"] == "ok"
        import json
        maps = json.loads(result["payload"])
        assert maps.get("missing") is True

    def test_cancel_map(self, tmp_path):
        from cortex_mcp.map_server import start_code_map, cancel_code_map

        proj = _make_tiny_project(tmp_path)
        r = start_code_map(str(proj))
        jid = r["job_id"]

        c = cancel_code_map(jid)
        assert isinstance(c.get("cancelled"), bool)
