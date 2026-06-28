"""Subprocess entrypoint for runtime startup tracing.

CRITICAL: This file must NEVER be imported by the parent process or any
other module. It is designed to run only as a __main__ subprocess via:
    python -m vigil_mapper.runtime_tracer_entry

It installs sys.settrace and a __import__ hook, runs the target module,
captures all call events and import events, and writes a JSON file to
the path given by --out.

Safety net: refuses to run unless CORTEX_MAP_BUILDER_TRACE=1 is set
in the environment, preventing accidental in-process execution.

Do NOT import this module. Do NOT add it to __all__ in __init__.py.
"""
from __future__ import annotations

import argparse
import builtins
import json
import os
import runpy
import sys
import time
from typing import Any
import logging
_log = logging.getLogger(__name__)


def main() -> int:
    # ------------------------------------------------------------------
    # Safety net: require CORTEX_MAP_BUILDER_TRACE=1.
    # This prevents accidental execution in-process by parent code that
    # accidentally imports this module.
    # ------------------------------------------------------------------
    if os.environ.get("CORTEX_MAP_BUILDER_TRACE") != "1":
        print(
            "ERROR: runtime_tracer_entry must only run as a subprocess with "
            "CORTEX_MAP_BUILDER_TRACE=1 set. Refusing to execute.",
            file=sys.stderr,
        )
        return 2

    # ------------------------------------------------------------------
    # Argument parsing.
    # We must handle `-- target_argv` manually: argparse stops at `--`.
    # ------------------------------------------------------------------
    parser = argparse.ArgumentParser(
        description="Subprocess entrypoint for cortex runtime tracer.",
        add_help=True,
    )
    parser.add_argument("--target", required=True, help="Dotted module name to run.")
    parser.add_argument("--out", required=True, help="Path to write JSON output.")
    parser.add_argument(
        "--timeout-s",
        type=float,
        default=30.0,
        help="Soft time budget for the target (informational only here).",
    )

    # Split off target argv (everything after `--`).
    raw_args = sys.argv[1:]
    target_argv_start: list[str] = []
    if "--" in raw_args:
        sep_idx = raw_args.index("--")
        target_argv_start = raw_args[sep_idx + 1:]
        raw_args = raw_args[:sep_idx]

    args = parser.parse_args(raw_args)
    target_module: str = args.target
    out_path: str = args.out

    # ------------------------------------------------------------------
    # Local accumulators (NOT module-level globals — plan ban).
    # ------------------------------------------------------------------
    events: list[dict[str, Any]] = []
    import_events: list[dict[str, Any]] = []
    t0 = time.perf_counter()

    # ------------------------------------------------------------------
    # Save original trace/import hooks so we can restore them in finally.
    # ------------------------------------------------------------------
    orig_settrace = sys.gettrace()
    orig_import = builtins.__import__

    exit_code: int = 0
    exception_info: dict[str, str] | None = None

    # ------------------------------------------------------------------
    # Skip-list for trace events: exclude non-user code.
    # ------------------------------------------------------------------
    _skip_fragments = (
        os.sep + "libs" + os.sep,
        "__pycache__",
        "frozen importlib",
        "importlib",
    )

    def _should_skip_filename(fname: str) -> bool:
        if not fname:
            return True
        if fname.startswith("<"):
            return True
        for frag in _skip_fragments:
            if frag in fname:
                return True
        return False

    # ------------------------------------------------------------------
    # Install sys.settrace call tracer.
    # ------------------------------------------------------------------
    def tracefunc(frame: Any, event: str, arg: Any) -> Any:
        if event == "call":
            fname = frame.f_code.co_filename
            if not _should_skip_filename(fname):
                qualname = frame.f_code.co_qualname if hasattr(frame.f_code, "co_qualname") else frame.f_code.co_name
                events.append({
                    "event": "call",
                    "qualname": qualname,
                    "filename": fname,
                    "lineno": frame.f_lineno,
                    "ts": time.perf_counter() - t0,
                })
        return tracefunc

    # ------------------------------------------------------------------
    # Install __import__ hook to capture import events.
    # ------------------------------------------------------------------
    def traced_import(name: str, *import_args: Any, **import_kwargs: Any) -> Any:
        import_events.append({
            "event": "import",
            "module": name,
            "ts": time.perf_counter() - t0,
        })
        return orig_import(name, *import_args, **import_kwargs)

    # ------------------------------------------------------------------
    # Run the target module with hooks installed.
    # ------------------------------------------------------------------
    sys.settrace(tracefunc)
    builtins.__import__ = traced_import

    try:
        # Set sys.argv so the target module sees appropriate argv.
        sys.argv = [target_module] + list(target_argv_start)
        runpy.run_module(target_module, run_name="__main__", alter_sys=True)
        exit_code = 0

    except SystemExit as exc:
        # Normal CLI exit — not a failure.
        code = exc.code
        if code is None:
            exit_code = 0
        elif isinstance(code, int):
            exit_code = code
        else:
            # SystemExit with a string message → treat as error (code 1).
            exit_code = 1

    except Exception as exc:  # noqa: BLE001 -- intentional broad catch for target
        exit_code = 2
        exception_info = {
            "type": type(exc).__name__,
            "message": str(exc),
        }

    finally:
        # Always restore hooks — plan §4b critical requirement.
        sys.settrace(None)
        builtins.__import__ = orig_import

    # ------------------------------------------------------------------
    # Write JSON output to the file specified by --out.
    # ------------------------------------------------------------------
    duration_s = time.perf_counter() - t0
    output: dict[str, Any] = {
        "events": events,
        "import_events": import_events,
        "exit_code": exit_code,
        "duration_s": duration_s,
    }
    if exception_info is not None:
        output["exception"] = exception_info

    try:
        out_text = json.dumps(output, ensure_ascii=False)
        with open(out_path, "w", encoding="utf-8") as fh:
            fh.write(out_text)
    except OSError as exc:
        print("ERROR: failed to write output file %r: %s" % (out_path, exc), file=sys.stderr)
        return 3

    # Return 0 if target exited normally (SystemExit 0 or clean return),
    # 2 if target raised an unhandled exception.
    return 0 if exit_code in (0,) else 2


if __name__ == "__main__":
    sys.exit(main())
