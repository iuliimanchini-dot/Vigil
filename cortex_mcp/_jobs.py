"""Background job registry for cortex_mcp servers.

Design constraints (the user's machine hangs under heavy parallel runs):
- At most MAX_CONCURRENT jobs running at any time (hard cap = 2).
- Each job runs in exactly ONE threading.Thread — no thread pools.
- Jobs are cancellable via a threading.Event that the worker can poll.
- A per-job wall-clock timeout (default 600 s) caps runaway jobs automatically.
- Results are stored in-process until explicitly retrieved.
"""
from __future__ import annotations

import threading
import traceback
import uuid
from typing import Any, Callable

MAX_CONCURRENT = 2   # Hard cap; callers get "busy" status when exceeded.

# Default wall-clock timeout for a single job (seconds).
DEFAULT_TIMEOUT_S: int = 600

# Job status values
STATUS_RUNNING   = "running"
STATUS_DONE      = "done"
STATUS_ERROR     = "error"
STATUS_CANCELLED = "cancelled"
STATUS_TIMEOUT   = "timeout"


class _Job:
    __slots__ = (
        "job_id", "status", "result", "error",
        "thread", "cancel_event", "_lock",
    )

    def __init__(self, job_id: str) -> None:
        self.job_id: str = job_id
        self.status: str = STATUS_RUNNING
        self.result: Any = None
        self.error: str | None = None
        self.cancel_event: threading.Event = threading.Event()
        self._lock: threading.Lock = threading.Lock()
        self.thread: threading.Thread | None = None

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


class JobRegistry:
    """Thread-safe registry of background jobs.

    Usage::

        registry = JobRegistry()
        job_id = registry.start(my_fn, arg1, kw=val)
        registry.status(job_id)   # -> {"job_id": ..., "status": "running"}
        registry.cancel(job_id)   # -> True / False
        registry.result(job_id)   # -> {"job_id": ..., "status": "done", "result": ...}

    Timeout::

        Each job has a wall-clock timeout (``timeout_s``).  When the job
        exceeds it, its cancel_event is set and the status transitions to
        ``"timeout"``.  The worker thread itself is NOT killed (Python does
        not support that), but any cooperative worker that polls cancel_event
        will stop promptly.
    """

    def __init__(self, max_concurrent: int = MAX_CONCURRENT) -> None:
        self._max_concurrent = max_concurrent
        self._jobs: dict[str, _Job] = {}
        self._lock = threading.Lock()

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _running_count(self) -> int:
        return sum(
            1 for j in self._jobs.values() if j.status == STATUS_RUNNING
        )

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def start(
        self,
        fn: Callable,
        *args: Any,
        timeout_s: int = DEFAULT_TIMEOUT_S,
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
            **kwargs: Keyword arguments forwarded to *fn*.
        """
        with self._lock:
            if self._running_count() >= self._max_concurrent:
                return {"job_id": None, "status": "busy",
                        "message": f"server busy: max {self._max_concurrent} concurrent jobs reached"}

            job_id = uuid.uuid4().hex
            job = _Job(job_id)
            self._jobs[job_id] = job

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
                with job._lock:
                    if job.status != STATUS_CANCELLED and job.status != STATUS_TIMEOUT:
                        job.result = result
                        job.status = STATUS_DONE
            except Exception:
                with job._lock:
                    if job.status != STATUS_CANCELLED and job.status != STATUS_TIMEOUT:
                        job.error = traceback.format_exc()
                        job.status = STATUS_ERROR

        def _timeout_watcher() -> None:
            """Wait timeout_s; if job is still running, cancel it."""
            if timeout_s <= 0:
                return
            # Use the cancel_event as a convenient interruptible sleep:
            # if the job finishes early it sets cancel_event — we detect
            # that the job is no longer running and exit silently.
            job.cancel_event.wait(timeout=timeout_s)
            with job._lock:
                if job.status == STATUS_RUNNING:
                    job.cancel_event.set()
                    job.status = STATUS_TIMEOUT

        t = threading.Thread(target=_worker, daemon=True)
        job.thread = t
        t.start()

        tw = threading.Thread(target=_timeout_watcher, daemon=True)
        tw.start()

        return {"job_id": job_id, "status": STATUS_RUNNING}

    def status(self, job_id: str) -> dict:
        """Return current status dict or {"status": "not_found"} for unknown ids."""
        with self._lock:
            job = self._jobs.get(job_id)
        if job is None:
            return {"job_id": job_id, "status": "not_found"}
        return job.to_status_dict()

    def result(self, job_id: str) -> dict:
        """Return result dict.  Status is still "running" if not yet done."""
        with self._lock:
            job = self._jobs.get(job_id)
        if job is None:
            return {"job_id": job_id, "status": "not_found", "result": None, "error": None}
        return job.to_result_dict()

    def cancel(self, job_id: str) -> dict:
        """Signal the job's cancel_event.  Returns {job_id, cancelled: bool}."""
        with self._lock:
            job = self._jobs.get(job_id)
        if job is None:
            return {"job_id": job_id, "cancelled": False, "reason": "not_found"}
        with job._lock:
            if job.status == STATUS_RUNNING:
                job.cancel_event.set()
                job.status = STATUS_CANCELLED
                return {"job_id": job_id, "cancelled": True}
            return {"job_id": job_id, "cancelled": False,
                    "reason": f"job already in terminal state: {job.status}"}


# Module-level singleton used by both servers.
_registry = JobRegistry()


def start(fn: Callable, *args: Any, timeout_s: int = DEFAULT_TIMEOUT_S, **kwargs: Any) -> dict:
    return _registry.start(fn, *args, timeout_s=timeout_s, **kwargs)


def status(job_id: str) -> dict:
    return _registry.status(job_id)


def result(job_id: str) -> dict:
    return _registry.result(job_id)


def cancel(job_id: str) -> dict:
    return _registry.cancel(job_id)
