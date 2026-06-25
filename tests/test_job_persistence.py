"""Disk-backed persistence for cortex_mcp._jobs.JobRegistry (G2.3).

Contract under test
-------------------
When a job is started with a ``project_dir``, the registry persists the job's
terminal record + result to ``<project_dir>/.cortex/cortex_jobs/<job_id>.json``
via an atomic tempfile+os.replace write under a per-job FileLock.  A *fresh*
registry instance (simulating an MCP server restart) can resolve that job's
status/result from disk even though its in-memory dict is empty.

Key semantics asserted here:
  * restart survival   — a completed job's result is readable from a new
                          registry instance pointed at the same project.
  * running→interrupted — a record left on disk in the ``running`` state (the
                          process died mid-flight) loads as ``interrupted``,
                          never ``done``.  The dead thread cannot be resumed.
  * corruption-tolerant — a partial/corrupt JSON file on disk is skipped
                          gracefully (no exception escapes the load path).
  * cross-project rule  — job files live under their own project's
                          ``.cortex/cortex_jobs/``; resolving under a *different*
                          project does not surface another project's job.

Resource-light: tiny payloads, no xdist, short poll loops.
"""
from __future__ import annotations

import json
import time
from pathlib import Path

from cortex_mcp._jobs import (
    JobRegistry,
    STATUS_DONE,
    STATUS_ERROR,
    STATUS_INTERRUPTED,
    jobs_dir,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _poll(reg: JobRegistry, job_id: str, max_wait: float = 10.0, interval: float = 0.05) -> str:
    """Poll reg.status(job_id) until not 'running'; return the final status."""
    deadline = time.monotonic() + max_wait
    while time.monotonic() < deadline:
        s = reg.status(job_id)
        if s.get("status") != "running":
            return s.get("status", "unknown")
        time.sleep(interval)
    return "timeout"


# ---------------------------------------------------------------------------
# 1. Restart survival
# ---------------------------------------------------------------------------

def test_completed_result_survives_restart(tmp_path):
    """Registry A completes a job; a fresh registry B at the same project
    can read the identical result (the in-memory dict is gone — it came
    from disk)."""
    proj = tmp_path / "projA"
    proj.mkdir()

    reg_a = JobRegistry(max_concurrent=2)
    started = reg_a.start(lambda: {"answer": 42, "items": [1, 2, 3]}, project_dir=str(proj))
    assert started["status"] == "running"
    jid = started["job_id"]
    assert _poll(reg_a, jid) == STATUS_DONE

    # A file must exist on disk under the project's cortex_jobs dir.
    on_disk = jobs_dir(proj) / f"{jid}.json"
    assert on_disk.exists(), f"expected persisted job file at {on_disk}"

    # Simulated restart: brand-new registry instance, empty memory.
    reg_b = JobRegistry(max_concurrent=2)
    status_b = reg_b.status(jid)
    assert status_b["status"] == STATUS_DONE, f"restart lost status: {status_b}"

    result_b = reg_b.result(jid)
    assert result_b["status"] == STATUS_DONE
    assert result_b["result"] == {"answer": 42, "items": [1, 2, 3]}, (
        f"restart lost/changed result: {result_b}"
    )


def test_error_result_survives_restart(tmp_path):
    """A failed job's terminal status + error survive a restart too."""
    proj = tmp_path / "projErr"
    proj.mkdir()

    def _boom():
        raise RuntimeError("intentional persist test error")

    reg_a = JobRegistry(max_concurrent=2)
    jid = reg_a.start(_boom, project_dir=str(proj))["job_id"]
    assert _poll(reg_a, jid) == STATUS_ERROR

    reg_b = JobRegistry(max_concurrent=2)
    r = reg_b.result(jid)
    assert r["status"] == STATUS_ERROR
    assert "intentional persist test error" in (r.get("error") or "")


# ---------------------------------------------------------------------------
# 2. running → interrupted on load
# ---------------------------------------------------------------------------

def test_running_on_disk_loads_as_interrupted(tmp_path):
    """A job persisted while still 'running' (its process died) must load as
    'interrupted' on a fresh registry — never 'done'. The thread is gone and
    cannot be resumed."""
    proj = tmp_path / "projRun"
    proj.mkdir()

    # Persist a record in the RUNNING state directly (this is what a job that
    # had begun executing but whose process was then killed leaves behind).
    reg_a = JobRegistry(max_concurrent=2)
    jid = reg_a._persist_running_record_for_test(str(proj))  # test seam

    raw = json.loads((jobs_dir(proj) / f"{jid}.json").read_text(encoding="utf-8"))
    assert raw["status"] == "running", "fixture must persist a RUNNING record"

    # Fresh registry = restart. The dead 'running' job surfaces as interrupted.
    reg_b = JobRegistry(max_concurrent=2)
    status_b = reg_b.status(jid)
    assert status_b["status"] == STATUS_INTERRUPTED, (
        f"running job after restart must be interrupted, got {status_b}"
    )

    result_b = reg_b.result(jid)
    assert result_b["status"] == STATUS_INTERRUPTED
    assert result_b["status"] != STATUS_DONE


# ---------------------------------------------------------------------------
# 3. Corruption tolerance
# ---------------------------------------------------------------------------

def test_corrupt_json_skipped_gracefully(tmp_path):
    """A partial/corrupt JSON file on disk must not crash a lookup — it is
    treated as 'not_found'."""
    proj = tmp_path / "projCorrupt"
    proj.mkdir()
    d = jobs_dir(proj)
    d.mkdir(parents=True, exist_ok=True)

    bad_id = "deadbeefdeadbeef"
    # Truncated / invalid JSON (an interrupted atomic write could look like this
    # only if os.replace were non-atomic; we still defend against it).
    (d / f"{bad_id}.json").write_text('{"job_id": "deadbeef", "stat', encoding="utf-8")

    reg = JobRegistry(max_concurrent=2)
    status = reg.status(bad_id)  # must not raise
    assert status["status"] == "not_found", f"corrupt file should be not_found, got {status}"

    result = reg.result(bad_id)  # must not raise
    assert result["status"] == "not_found"


def test_empty_file_skipped_gracefully(tmp_path):
    """A zero-byte job file is also tolerated as not_found."""
    proj = tmp_path / "projEmpty"
    proj.mkdir()
    d = jobs_dir(proj)
    d.mkdir(parents=True, exist_ok=True)

    empty_id = "0000000000000000"
    (d / f"{empty_id}.json").write_text("", encoding="utf-8")

    reg = JobRegistry(max_concurrent=2)
    assert reg.status(empty_id)["status"] == "not_found"
    assert reg.result(empty_id)["status"] == "not_found"


# ---------------------------------------------------------------------------
# 4. Cross-project isolation
# ---------------------------------------------------------------------------

def test_cross_project_isolation(tmp_path):
    """A job completed under project X writes its file under X's own
    .cortex/cortex_jobs/.  Resolving that job_id against project Y (which never
    ran it) must NOT surface project X's result — project Y has no such file."""
    proj_x = tmp_path / "projX"
    proj_y = tmp_path / "projY"
    proj_x.mkdir()
    proj_y.mkdir()

    reg_a = JobRegistry(max_concurrent=2)
    jid = reg_a.start(lambda: "secret-from-X", project_dir=str(proj_x))["job_id"]
    assert _poll(reg_a, jid) == STATUS_DONE

    # The file is under X, not Y.
    assert (jobs_dir(proj_x) / f"{jid}.json").exists()
    assert not (jobs_dir(proj_y) / f"{jid}.json").exists()

    # A fresh registry resolving the job *scoped to Y* must not find it.
    reg_b = JobRegistry(max_concurrent=2)
    scoped_to_y = reg_b.result(jid, project_dir=str(proj_y))
    assert scoped_to_y["status"] == "not_found", (
        f"project Y must not see project X's job, got {scoped_to_y}"
    )

    # ...but scoped to X (the owning project) it resolves fine.
    scoped_to_x = reg_b.result(jid, project_dir=str(proj_x))
    assert scoped_to_x["status"] == STATUS_DONE
    assert scoped_to_x["result"] == "secret-from-X"
