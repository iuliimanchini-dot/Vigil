"""Runtime tracer orchestrator -- Map 2 subprocess-based startup capture.

Launches a target Python module in an isolated subprocess with sys.settrace
and __import__ hooks installed INSIDE that subprocess only (never in parent).

This module is the PARENT-side orchestrator only. It:
  - Sanitises environment (strips known API keys and secrets).
  - Spawns runtime_tracer_entry as a subprocess.
  - Reads the JSON output file written by the subprocess.
  - Returns structured trace results for merging into RuntimeNode map.

Security guarantees (per plan sec.7.2):
  - BLOCKED_ENV vars are never passed to subprocess.
  - shell=False always -- no shell injection possible.
  - Timeout enforced via subprocess.run(timeout=...).

Public API:
    capture_startup_trace(target_module, target_argv, project_dir, timeout_s)
        -> dict with keys: events, import_events, exit_code, duration_s, stderr
"""
from __future__ import annotations

import json
import logging
import os
import sys
import tempfile
import time
from pathlib import Path
from typing import Sequence

from .map_errors import RuntimeTracerError, RuntimeTracerTimeoutError

__all__ = ["capture_startup_trace", "BLOCKED_ENV"]

_log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Security: blocked environment variable names (plan §7.2)
# ---------------------------------------------------------------------------

BLOCKED_ENV: frozenset[str] = frozenset({
    "ANTHROPIC_API_KEY",
    "GEMINI_API_KEY",
    "OPENAI_API_KEY",
    "GITHUB_TOKEN",
    "AWS_SECRET_ACCESS_KEY",
    "AWS_ACCESS_KEY_ID",
    "SSH_AUTH_SOCK",
    "PERPLEXITY_API_KEY",
})


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _build_sanitised_env(project_dir: Path | None) -> dict[str, str]:
    """Return os.environ copy with BLOCKED_ENV keys removed + tracer marker set."""
    env = {k: v for k, v in os.environ.items() if k not in BLOCKED_ENV}
    env["CORTEX_MAP_BUILDER_TRACE"] = "1"

    if project_dir is not None:
        existing_pp = env.get("PYTHONPATH", "")
        project_str = str(project_dir.resolve())
        if existing_pp:
            env["PYTHONPATH"] = project_str + os.pathsep + existing_pp
        else:
            env["PYTHONPATH"] = project_str

    return env


def _build_argv(
    target_module: str,
    temp_path: str,
    timeout_s: float,
    target_argv: Sequence[str],
) -> list[str]:
    """Build subprocess argv list (shell=False safe, no injection possible)."""
    argv = [
        sys.executable,
        "-m",
        "vigil_mapper.runtime_tracer_entry",
        "--target", target_module,
        "--out", temp_path,
        "--timeout-s", str(timeout_s),
    ]
    if target_argv:
        argv += ["--", *target_argv]
    return argv


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def capture_startup_trace(
    target_module: str,
    target_argv: Sequence[str] = (),
    project_dir: Path | None = None,
    timeout_s: float = 30.0,
) -> dict:
    """Capture startup trace of target_module by running it in a subprocess.

    The subprocess installs sys.settrace and a __import__ hook, runs the
    target, then writes a JSON file with all captured events.

    Args:
        target_module: Dotted Python module name to run (e.g. "json" or
            "mypackage.app").
        target_argv: Arguments forwarded to the target module's sys.argv.
        project_dir: If provided, prepended to subprocess PYTHONPATH so the
            target module can be imported.
        timeout_s: Maximum seconds to allow the subprocess to run. Hard kill
            at timeout_s + 5 seconds via subprocess.run timeout param.

    Returns:
        dict with keys:
            events         - list[dict]: call-level trace events
            import_events  - list[dict]: import hook events
            exit_code      - int: target exit code (0 = normal)
            duration_s     - float: elapsed time inside subprocess
            stderr         - str: subprocess stderr output

    Raises:
        RuntimeTracerTimeoutError: If subprocess does not complete within
            timeout_s + 5 seconds.
        RuntimeTracerError: If the tracer entry itself fails to produce valid
            JSON output on a zero exit.
    """
    import subprocess

    if project_dir is not None:
        project_dir = project_dir.resolve()

    env = _build_sanitised_env(project_dir)

    # Create temp file. We close the fd immediately and pass the path to the
    # subprocess. The subprocess writes JSON there. We read it AFTER the
    # subprocess finishes (before we unlink).
    tmp_fd, tmp_path = tempfile.mkstemp(suffix=".json", prefix="cortex_trace_")
    os.close(tmp_fd)

    argv = _build_argv(target_module, tmp_path, timeout_s, target_argv)

    _log.info(
        "capture_startup_trace: spawning subprocess for target=%r timeout=%.1fs",
        target_module,
        timeout_s,
    )
    t_wall = time.perf_counter()

    timed_out = False
    proc = None
    try:
        proc = subprocess.run(
            argv,
            env=env,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout_s + 5.0,
            shell=False,
        )
    except subprocess.TimeoutExpired as exc:
        timed_out = True
        _log.error(
            "capture_startup_trace: subprocess timed out after %.1fs for target=%r",
            timeout_s + 5.0,
            target_module,
        )
        raise RuntimeTracerTimeoutError(
            "runtime tracer timed out after %.1fs for target %r" % (timeout_s + 5.0, target_module)
        ) from exc
    finally:
        if timed_out:
            # On timeout we can't read a partial file — just clean up.
            try:
                os.unlink(tmp_path)
            except OSError:
                pass

    wall_elapsed = time.perf_counter() - t_wall

    # Read output JSON from temp file, then clean up.
    payload: dict = {}
    read_error: str | None = None
    try:
        raw = Path(tmp_path).read_text(encoding="utf-8")
        if raw.strip():
            payload = json.loads(raw)
    except (OSError, json.JSONDecodeError) as exc:
        read_error = str(exc)
    finally:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass

    if proc.returncode != 0:
        _log.error(
            "capture_startup_trace: subprocess exited with code %d for target=%r stderr=%r",
            proc.returncode,
            target_module,
            proc.stderr[:500] if proc.stderr else "",
        )
        # Return partial result (events captured so far) — caller decides degraded mode.
        return {
            "events": payload.get("events", []),
            "import_events": payload.get("import_events", []),
            "exit_code": proc.returncode,
            "duration_s": payload.get("duration_s", wall_elapsed),
            "stderr": proc.stderr or "",
        }

    if read_error is not None:
        raise RuntimeTracerError(
            "runtime tracer for target %r exited 0 but output file unreadable: %s"
            % (target_module, read_error)
        )

    if not payload:
        raise RuntimeTracerError(
            "runtime tracer for target %r exited 0 but produced empty JSON output"
            % target_module
        )

    _log.debug(
        "capture_startup_trace: done exit=0 wall=%.2fs events=%d imports=%d",
        wall_elapsed,
        len(payload.get("events", [])),
        len(payload.get("import_events", [])),
    )

    return {
        "events": payload.get("events", []),
        "import_events": payload.get("import_events", []),
        "exit_code": payload.get("exit_code", 0),
        "duration_s": payload.get("duration_s", wall_elapsed),
        "stderr": proc.stderr or "",
    }
