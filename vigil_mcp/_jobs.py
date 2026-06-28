"""Background job registry for vigil_mcp servers.

Design constraints (the user's machine hangs under heavy parallel runs):
- At most MAX_CONCURRENT jobs running at any time (hard cap = 2).
- Each job runs in exactly ONE threading.Thread — no thread pools.
- Jobs are cancellable via a threading.Event that the worker can poll.
- A per-job wall-clock timeout (default 600 s) caps runaway jobs automatically.
- Results are stored in-process AND, when a job carries a ``project_dir``,
  persisted to disk so a completed/failed/cancelled job's result survives an
  MCP server restart.

Disk-backed persistence (G2.3)
------------------------------
When ``start(...)`` is given a ``project_dir`` (the path passed to the
``start_*`` MCP tools), the job's *terminal* record + result is written to::

    <project_dir>/.cortex/cortex_jobs/<job_id>.json

via an atomic ``tempfile.mkstemp`` + ``os.replace`` under a per-job
``filelock.FileLock`` — exactly the pattern vigil_mapper uses in
``map_storage._atomic_write_json``.  A *fresh* ``JobRegistry`` instance (a new
process = simulated restart) resolves a prior run's job from disk on lookup,
because its in-memory dict is empty.

Restart / interrupted semantics
-------------------------------
* Terminal records (``done`` / ``error`` / ``cancelled``) load back verbatim,
  so ``status`` / ``result`` return the prior run's outcome after a restart.
* A record left on disk in the ``running`` state means the owning process died
  mid-flight.  The worker thread is gone and CANNOT be resumed, so on load such
  a record is surfaced as ``interrupted`` — it is never reported as ``done``.

Resolution & cross-project rule
--------------------------------
* ``status(job_id)`` / ``result(job_id)`` first check memory.  On a miss they
  read the job file lazily *by id* (bounded: one ``Path.exists`` + one read,
  never a full directory scan).
* Job files live under their OWN project's ``cortex_jobs`` dir.  A small global
  index (``job_id -> project_dir``, under the user state dir) lets the servers —
  which only pass a ``job_id`` — locate the owning project after a restart.
* Passing an explicit ``project_dir=`` to ``status`` / ``result`` SCOPES the
  lookup to that project only (the global index is ignored).  Hence a job that
  ran under project X is *not* visible when resolved scoped to project Y — its
  file simply is not under Y.  Resolving scoped to X (or by id via the index)
  finds it.
"""
from __future__ import annotations

import json
import os
import tempfile
import threading
import time
import traceback
import uuid
from pathlib import Path
from typing import Any, Callable

MAX_CONCURRENT = 2   # Hard cap; callers get "busy" status when exceeded.

# Default wall-clock timeout for a single job (seconds).
DEFAULT_TIMEOUT_S: int = 600

# Job status values
STATUS_RUNNING     = "running"
STATUS_DONE        = "done"
STATUS_ERROR       = "error"
STATUS_CANCELLED   = "cancelled"
STATUS_TIMEOUT     = "timeout"
# Loaded from disk for a job whose process died while it was still running.
STATUS_INTERRUPTED = "interrupted"

# Statuses that are final and worth persisting to disk.  ``running`` is also
# persisted (so a death mid-flight is detectable as ``interrupted`` on reload)
# but is NOT terminal.
_TERMINAL_STATUSES = frozenset(
    {STATUS_DONE, STATUS_ERROR, STATUS_CANCELLED, STATUS_TIMEOUT}
)

# On-disk layout (mirrors vigil_mapper's <project>/.cortex/maps/).
_JOBS_SUBDIR = (".cortex", "cortex_jobs")

# Schema marker for forward-compat.
_SCHEMA_VERSION = "1.0.0"

# FileLock acquire timeout (seconds) — matches map_storage's 10 s.
_LOCK_TIMEOUT_S = 10


# ---------------------------------------------------------------------------
# Disk path helpers
# ---------------------------------------------------------------------------

def jobs_dir(project_dir: Path | str) -> Path:
    """Per-project job directory: ``<project_dir>/.cortex/cortex_jobs/``."""
    return Path(project_dir).joinpath(*_JOBS_SUBDIR)


def _job_file(project_dir: Path | str, job_id: str) -> Path:
    return jobs_dir(project_dir) / f"{job_id}.json"


def _index_dir() -> Path:
    """Global ``job_id -> project_dir`` index root (survives restart).

    Lives under the user state dir so the MCP servers, which look a job up by
    ``job_id`` alone, can find the owning project after a process restart.
    Falls back to the OS temp dir if the home directory is unavailable.
    """
    try:
        root = Path.home()
    except (OSError, RuntimeError):
        root = Path(tempfile.gettempdir())
    return root / ".cortex" / "cortex_jobs_index"


def _index_file(job_id: str) -> Path:
    return _index_dir() / f"{job_id}.json"


# ---------------------------------------------------------------------------
# Atomic JSON write (mirrors vigil_mapper.map_storage._atomic_write_json)
# ---------------------------------------------------------------------------

def _atomic_write_json(path: Path, payload: dict) -> None:
    """Write *payload* to *path* atomically via tempfile + os.replace.

    Cross-platform: ``os.replace`` is atomic on POSIX and Windows.  A partial
    write can only ever land in the temp file, which is removed on error, so a
    reader never observes a half-written target.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_path = tempfile.mkstemp(dir=str(path.parent), prefix=".job_", suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(json.dumps(payload, indent=2, ensure_ascii=False, sort_keys=True))
            fh.write("\n")
        os.replace(tmp_path, str(path))
    except BaseException:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass
        raise


def _write_with_lock(path: Path, payload: dict) -> None:
    """Atomic write under a per-file FileLock (best-effort if filelock absent)."""
    path.parent.mkdir(parents=True, exist_ok=True)
    lock_path = path.with_suffix(".lock")
    try:
        from filelock import FileLock, Timeout as FileLockTimeout
    except ImportError:
        # filelock is a declared dependency; if somehow missing, the tmp+replace
        # write is still atomic per-writer — degrade rather than crash the job.
        _atomic_write_json(path, payload)
        return
    try:
        with FileLock(str(lock_path), timeout=_LOCK_TIMEOUT_S):
            _atomic_write_json(path, payload)
    except FileLockTimeout:
        # Another writer holds the lock; fall back to a direct atomic write
        # rather than losing the result entirely. os.replace is still atomic.
        _atomic_write_json(path, payload)


def _read_json_quiet(path: Path) -> dict | None:
    """Read a JSON object from *path*; return None on absent / corrupt / empty.

    Never raises for a bad file — a truncated or partially-written record is
    treated as "no usable record here" so a lookup degrades to ``not_found``.
    """
    try:
        if not path.exists():
            return None
        raw = path.read_text(encoding="utf-8")
    except OSError:
        return None
    if not raw.strip():
        return None
    try:
        data = json.loads(raw)
    except (json.JSONDecodeError, ValueError):
        return None
    return data if isinstance(data, dict) else None


# ---------------------------------------------------------------------------
# Record (de)serialisation
# ---------------------------------------------------------------------------

def _now_iso() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%S.000Z", time.gmtime())


def _record_to_status_dict(rec: dict) -> dict:
    """Project a loaded on-disk record into a status dict.

    A persisted ``running`` record means the process died mid-flight → the job
    is surfaced as ``interrupted`` (its thread cannot be resumed).
    """
    status = rec.get("status")
    if status == STATUS_RUNNING:
        status = STATUS_INTERRUPTED
    return {"job_id": rec.get("job_id"), "status": status}


def _record_to_result_dict(rec: dict) -> dict:
    status = rec.get("status")
    if status == STATUS_RUNNING:
        status = STATUS_INTERRUPTED
    return {
        "job_id": rec.get("job_id"),
        "status": status,
        "result": rec.get("result"),
        "error": rec.get("error"),
    }


class _Job:
    __slots__ = (
        "job_id", "status", "result", "error",
        "thread", "cancel_event", "_lock", "project_dir",
        "submitted_at", "_persist_lock",
    )

    def __init__(self, job_id: str, project_dir: str | None = None) -> None:
        self.job_id: str = job_id
        self.status: str = STATUS_RUNNING
        self.result: Any = None
        self.error: str | None = None
        self.cancel_event: threading.Event = threading.Event()
        self._lock: threading.Lock = threading.Lock()
        # Serialises the two persisters (start()'s RUNNING write and the
        # worker/timeout terminal write) so the terminal record can never be
        # clobbered by a late RUNNING write — see JobRegistry._persist.
        self._persist_lock: threading.Lock = threading.Lock()
        self.thread: threading.Thread | None = None
        self.project_dir: str | None = project_dir
        self.submitted_at: str = _now_iso()

    def to_status_dict(self) -> dict:
        with self._lock:
            return {"job_id": self.job_id, "status": self.status}

    def to_result_dict(self) -> dict:
        with self._lock:
            return {
                "job_id": self.job_id,
                "status": self.status,
                "result": self.result,
                "error": self.error,
            }

    def to_record(self) -> dict:
        """Serialise to a persistable record (caller holds self._lock)."""
        completed = self.status != STATUS_RUNNING
        return {
            "schema_version": _SCHEMA_VERSION,
            "job_id": self.job_id,
            "project_dir": self.project_dir or "",
            "status": self.status,
            "result": self.result,
            "error": self.error,
            "submitted_at": self.submitted_at,
            "completed_at": _now_iso() if completed else "",
        }


class JobRegistry:
    """Thread-safe registry of background jobs with optional disk persistence.

    Usage::

        registry = JobRegistry()
        job_id = registry.start(my_fn, arg1, kw=val, project_dir="/path/proj")
        registry.status(job_id)   # -> {"job_id": ..., "status": "running"}
        registry.cancel(job_id)   # -> {"job_id": ..., "cancelled": True/False}
        registry.result(job_id)   # -> {"job_id": ..., "status": "done", "result": ...}

    Persistence is engaged only when a ``project_dir`` is supplied to
    ``start``; without it the registry behaves exactly as before (in-memory
    only).  See the module docstring for restart / interrupted / cross-project
    semantics.
    """

    def __init__(self, max_concurrent: int = MAX_CONCURRENT) -> None:
        self._max_concurrent = max_concurrent
        self._jobs: dict[str, _Job] = {}
        self._lock = threading.Lock()

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _running_count(self) -> int:
        return sum(1 for j in self._jobs.values() if j.status == STATUS_RUNNING)

    def _persist(self, job: _Job) -> None:
        """Persist *job*'s current record to disk (no-op without project_dir).

        Terminal precedence: a non-terminal (``running``) write must never
        overwrite an already-terminal on-disk record.  Because the initial
        RUNNING persist (from ``start``) and the terminal persist (from the
        worker / timeout watcher) race — a fast job can reach ``done`` before
        the synchronous RUNNING write finishes its I/O — both go through this
        method under the job's ``_persist_lock``, and a RUNNING snapshot yields
        to a terminal record found on disk.

        Never lets a persistence failure break job execution — a job that ran
        successfully must still report success even if the disk write fails.
        """
        project_dir = job.project_dir
        if not project_dir:
            return
        path = _job_file(project_dir, job.job_id)
        with job._persist_lock:
            with job._lock:
                record = job.to_record()
            # If we are about to write a non-terminal record, defer to any
            # terminal record already on disk (the job finished first).
            if record.get("status") not in _TERMINAL_STATUSES:
                existing = _read_json_quiet(path)
                if existing and existing.get("status") in _TERMINAL_STATUSES:
                    return
            try:
                _write_with_lock(path, record)
                # Global job_id -> project_dir index for by-id lookups.
                _write_with_lock(_index_file(job.job_id), {"project_dir": project_dir})
            except Exception:
                # Fail-soft on persistence: the in-memory result is still valid.
                pass

    def _finish(
        self,
        job: _Job,
        status: str,
        *,
        result: Any = None,
        error: str | None = None,
    ) -> None:
        """Move *job* to a terminal *status*, writing disk BEFORE publishing.

        Disk-before-memory ordering guarantees an external reader (a fresh
        registry reading the file) is never *behind* a same-process reader that
        already saw the terminal status in memory: the moment ``status``/
        ``result`` report a terminal state, the on-disk record is at least as
        advanced.  Pre-emption is respected — a job already moved to
        ``cancelled`` (by ``cancel``) or ``timeout`` is left untouched.
        """
        with job._lock:
            if job.status in (STATUS_CANCELLED, STATUS_TIMEOUT):
                return  # pre-empted; the pre-emptor owns the terminal record
            if job.status != STATUS_RUNNING and status != STATUS_TIMEOUT:
                return  # already terminal via another path
            # Stage the terminal fields on the job so to_record() serialises
            # them, but DO NOT publish the status to readers yet.
            job.result = result
            job.error = error
            staged_status = status

        # Build + write the terminal record to disk first (status forced
        # terminal regardless of the not-yet-published in-memory status).
        if job.project_dir:
            with job._persist_lock:
                with job._lock:
                    record = job.to_record()
                    record["status"] = staged_status
                    record["completed_at"] = _now_iso()
                try:
                    _write_with_lock(_job_file(job.project_dir, job.job_id), record)
                    _write_with_lock(_index_file(job.job_id), {"project_dir": job.project_dir})
                except Exception:
                    pass  # fail-soft: in-memory result remains valid

        # Now publish the terminal status in memory.
        with job._lock:
            if job.status in (STATUS_CANCELLED, STATUS_TIMEOUT) and staged_status not in (
                STATUS_CANCELLED, STATUS_TIMEOUT
            ):
                return
            job.status = staged_status

    def _resolve_from_disk(self, job_id: str, project_dir: str | None) -> dict | None:
        """Load a job record from disk by id.  Returns the record dict or None.

        * ``project_dir`` given  -> read only that project's file (scoped;
          enforces cross-project isolation).
        * ``project_dir`` None   -> consult the global index to find the owning
          project, then read its file (by-id lookup, used by the servers).
        Bounded: at most a couple of file reads, never a directory walk.
        """
        if project_dir:
            return _read_json_quiet(_job_file(project_dir, job_id))
        idx = _read_json_quiet(_index_file(job_id))
        if not idx:
            return None
        owning = idx.get("project_dir")
        if not owning:
            return None
        return _read_json_quiet(_job_file(owning, job_id))

    # ------------------------------------------------------------------
    # Test seam
    # ------------------------------------------------------------------

    def _persist_running_record_for_test(self, project_dir: str) -> str:
        """Persist a fresh record in the RUNNING state and return its job_id.

        Simulates a job that began executing and was then killed before
        reaching a terminal state (used by the running→interrupted test).
        """
        job = _Job(uuid.uuid4().hex, project_dir=project_dir)
        with self._lock:
            self._jobs[job.job_id] = job
        self._persist(job)  # status is RUNNING
        return job.job_id

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def start(
        self,
        fn: Callable,
        *args: Any,
        timeout_s: int = DEFAULT_TIMEOUT_S,
        project_dir: str | None = None,
        **kwargs: Any,
    ) -> dict:
        """Start *fn* in a background thread and return {job_id, status}.

        Returns {"status": "busy", "job_id": None} when the concurrent cap
        is already reached — callers should retry later.

        The cancel_event is injected as keyword argument ``cancel_event``
        only if *fn* accepts it (checked via __code__.co_varnames).

        Args:
            fn: Callable to run in a background thread.
            *args: Positional arguments forwarded to *fn*.
            timeout_s: Wall-clock timeout in seconds.  When the job runs
                longer than this, its cancel_event is set and status
                transitions to ``"timeout"``.  Default: ``DEFAULT_TIMEOUT_S``
                (600 s).  Pass 0 to disable the timeout.
            project_dir: When given, the job's terminal record + result are
                persisted under ``<project_dir>/.cortex/cortex_jobs/`` so they
                survive a process restart.  When None, the job is in-memory
                only (legacy behaviour).
            **kwargs: Keyword arguments forwarded to *fn*.
        """
        with self._lock:
            if self._running_count() >= self._max_concurrent:
                return {"job_id": None, "status": "busy",
                        "message": f"server busy: max {self._max_concurrent} concurrent jobs reached"}

            job_id = uuid.uuid4().hex
            job = _Job(job_id, project_dir=project_dir)
            self._jobs[job_id] = job

        # Persist the initial RUNNING record so a death mid-flight is later
        # detectable as ``interrupted`` (only when persistence is enabled).
        self._persist(job)

        # Decide whether to pass cancel_event to the wrapped function.
        try:
            varnames = fn.__code__.co_varnames
        except AttributeError:
            varnames = ()
        inject_cancel = "cancel_event" in varnames

        def _worker() -> None:
            try:
                if inject_cancel:
                    result = fn(*args, cancel_event=job.cancel_event, **kwargs)
                else:
                    result = fn(*args, **kwargs)
                self._finish(job, STATUS_DONE, result=result)
            except Exception:
                self._finish(job, STATUS_ERROR, error=traceback.format_exc())

        def _timeout_watcher() -> None:
            """Wait timeout_s; if job is still running, cancel it."""
            if timeout_s <= 0:
                return
            job.cancel_event.wait(timeout=timeout_s)
            with job._lock:
                still_running = job.status == STATUS_RUNNING
                if still_running:
                    job.cancel_event.set()
            if still_running:
                self._finish(job, STATUS_TIMEOUT)

        t = threading.Thread(target=_worker, daemon=True)
        job.thread = t
        t.start()

        tw = threading.Thread(target=_timeout_watcher, daemon=True)
        tw.start()

        return {"job_id": job_id, "status": STATUS_RUNNING}

    def status(self, job_id: str, project_dir: str | None = None) -> dict:
        """Return current status dict or {"status": "not_found"} for unknown ids.

        Falls back to disk when the job is not in memory (e.g. after a restart);
        a persisted ``running`` record surfaces as ``interrupted``.  Passing
        ``project_dir`` scopes the disk lookup to that project only.
        """
        with self._lock:
            job = self._jobs.get(job_id)
        if job is not None:
            return job.to_status_dict()
        rec = self._resolve_from_disk(job_id, project_dir)
        if rec is None:
            return {"job_id": job_id, "status": "not_found"}
        return _record_to_status_dict(rec)

    def result(self, job_id: str, project_dir: str | None = None) -> dict:
        """Return result dict.  Status is still "running" if not yet done.

        Falls back to disk when the job is not in memory; a persisted
        ``running`` record surfaces as ``interrupted`` (result/None).  Passing
        ``project_dir`` scopes the disk lookup to that project only.
        """
        with self._lock:
            job = self._jobs.get(job_id)
        if job is not None:
            return job.to_result_dict()
        rec = self._resolve_from_disk(job_id, project_dir)
        if rec is None:
            return {"job_id": job_id, "status": "not_found", "result": None, "error": None}
        return _record_to_result_dict(rec)

    def cancel(self, job_id: str, project_dir: str | None = None) -> dict:
        """Signal the job's cancel_event.  Returns {job_id, cancelled: bool}.

        A job only living on disk (after a restart) cannot be cancelled — its
        thread is gone; it is reported with its persisted terminal/interrupted
        state instead.
        """
        with self._lock:
            job = self._jobs.get(job_id)
        if job is None:
            rec = self._resolve_from_disk(job_id, project_dir)
            if rec is None:
                return {"job_id": job_id, "cancelled": False, "reason": "not_found"}
            state = _record_to_status_dict(rec)["status"]
            return {"job_id": job_id, "cancelled": False,
                    "reason": f"job not in memory (persisted state: {state})"}
        do_persist = False
        with job._lock:
            if job.status == STATUS_RUNNING:
                job.cancel_event.set()
                job.status = STATUS_CANCELLED
                do_persist = True
        if do_persist:
            self._persist(job)
            return {"job_id": job_id, "cancelled": True}
        return {"job_id": job_id, "cancelled": False,
                "reason": f"job already in terminal state: {job.status}"}


# Module-level singleton used by both servers.
_registry = JobRegistry()


def start(
    fn: Callable,
    *args: Any,
    timeout_s: int = DEFAULT_TIMEOUT_S,
    project_dir: str | None = None,
    **kwargs: Any,
) -> dict:
    return _registry.start(fn, *args, timeout_s=timeout_s, project_dir=project_dir, **kwargs)


def status(job_id: str, project_dir: str | None = None) -> dict:
    return _registry.status(job_id, project_dir=project_dir)


def result(job_id: str, project_dir: str | None = None) -> dict:
    return _registry.result(job_id, project_dir=project_dir)


def cancel(job_id: str, project_dir: str | None = None) -> dict:
    return _registry.cancel(job_id, project_dir=project_dir)
