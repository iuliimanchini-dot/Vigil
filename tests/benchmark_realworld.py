#!/usr/bin/env python
"""Real-world fitness benchmark for cortex_forensic + cortex_map_builder.

Measures, on REAL third-party Python packages copied out of the local
``.venv/Lib/site-packages`` into a throw-away temp project dir:

  1. Public-API wiring (run_forensic_audit / run_map_build / load_repo_maps).
  2. Wall-clock for forensic audit and full map build.
  3. Peak RSS delta (psutil, sampled in a background thread).
  4. MCP summary-view output size (chars + est tokens = chars/4) for both
     _build_forensic_summary and _build_map_summary; checks <~6k token budget.
  5. Determinism: forensic run twice, identical (check_id,file,line) set.

Light by construction: workers=1 (forensic enforces internally), single map
build per target, no -n auto, packages are KB-scale.  __pycache__ is excluded
from the copy so only real source is audited.

Run:  .venv/Scripts/python.exe tests/benchmark_realworld.py
"""
from __future__ import annotations

import json
import shutil
import sys
import tempfile
import threading
import time
from collections import Counter
from pathlib import Path

import psutil

from cortex_forensic import run_forensic_audit
from cortex_map_builder import run_map_build, load_repo_maps
from cortex_mcp.forensic_server import _build_forensic_summary
from cortex_mcp.map_server import _build_map_summary, _repo_maps_to_serialisable

REPO = Path(__file__).resolve().parents[1]
SITE = REPO / ".venv" / "Lib" / "site-packages"
TARGETS = ["filelock", "mcp", "click"]


def _est_tokens(s: str) -> int:
    return len(s) // 4


class RSSSampler:
    """Sample process RSS in a background thread; report peak delta vs start."""

    def __init__(self, interval: float = 0.02) -> None:
        self.interval = interval
        self.proc = psutil.Process()
        self.baseline = self.proc.memory_info().rss
        self.peak = self.baseline
        self._stop = threading.Event()
        self._t: threading.Thread | None = None

    def _loop(self) -> None:
        while not self._stop.is_set():
            rss = self.proc.memory_info().rss
            if rss > self.peak:
                self.peak = rss
            self._stop.wait(self.interval)

    def __enter__(self) -> "RSSSampler":
        self.baseline = self.proc.memory_info().rss
        self.peak = self.baseline
        self._t = threading.Thread(target=self._loop, daemon=True)
        self._t.start()
        return self

    def __exit__(self, *exc) -> None:
        self._stop.set()
        if self._t:
            self._t.join(timeout=2)

    @property
    def peak_delta_mb(self) -> float:
        return (self.peak - self.baseline) / (1024 * 1024)


def _copy_package(name: str, dest_root: Path) -> Path:
    """Copy a site-packages package into dest_root/<name>, sans __pycache__.

    Also drops the repo's shipped default ``gate_profile.json`` INTO the copied
    target dir so the forensic audit resolves the *default profile* (file_warn
    750 / file_revise 1000 / nesting_warn 5), not the stricter hardcoded code
    fallback (600/800/4).  Without this the temp dir has no ancestor profile and
    the audit would silently run stricter-than-shipped thresholds.
    """
    src = SITE / name
    if not src.is_dir():
        raise SystemExit(f"target package not found: {src}")
    dst = dest_root / name
    shutil.copytree(
        src, dst,
        ignore=shutil.ignore_patterns("__pycache__", "*.pyc"),
    )
    # Activate the shipped default profile for this target (resolution step 1).
    shutil.copy2(REPO / "gate_profile.json", dst / "gate_profile.json")
    return dst


def _count_py(root: Path) -> tuple[int, int]:
    files = list(root.rglob("*.py"))
    loc = 0
    for f in files:
        try:
            loc += sum(1 for _ in f.open("r", encoding="utf-8", errors="replace"))
        except OSError:
            pass
    return len(files), loc


def _finding_key(f: dict) -> tuple:
    file = f.get("file")
    line = f.get("line")
    if file is None or line is None:
        for ev in f.get("evidence") or []:
            if not isinstance(ev, dict):
                continue
            if file is None and ev.get("path"):
                file = ev.get("path")
            if line is None:
                detail = str(ev.get("detail", ""))
                if detail.startswith("line:"):
                    line = detail.split("line:", 1)[1].strip()
    return (f.get("check_id"), str(file), str(line))


def bench_target(name: str) -> dict:
    out: dict = {"target": name}
    with tempfile.TemporaryDirectory(prefix=f"cortex_bench_{name}_") as td:
        proj = _copy_package(name, Path(td))
        nfiles, loc = _count_py(proj)
        out["py_files"] = nfiles
        out["loc"] = loc

        # --- forensic timing + memory ---
        with RSSSampler() as s:
            t = time.perf_counter()
            fres = run_forensic_audit(proj)
            out["forensic_s"] = round(time.perf_counter() - t, 2)
            out["forensic_mem_mb"] = round(s.peak_delta_mb, 1)
        out["forensic_findings"] = len(fres["findings"])
        out["forensic_exit"] = fres["exit_code"]
        out["forensic_files_scanned"] = fres["meta"].get("source_files_scanned")
        out["by_check_id"] = dict(
            Counter(f["check_id"] for f in fres["findings"]).most_common()
        )

        # --- forensic summary output size ---
        fsum = _build_forensic_summary(fres)
        fsum_json = json.dumps(fsum, default=str)
        out["forensic_summary_chars"] = len(fsum_json)
        out["forensic_summary_tokens"] = _est_tokens(fsum_json)

        # --- determinism: run forensic again, compare key sets ---
        fres2 = run_forensic_audit(proj)
        set1 = sorted(_finding_key(f) for f in fres["findings"])
        set2 = sorted(_finding_key(f) for f in fres2["findings"])
        out["deterministic"] = set1 == set2
        out["determinism_n1"] = len(set1)
        out["determinism_n2"] = len(set2)

        # --- map build timing + memory (map='all') ---
        with RSSSampler() as s:
            t = time.perf_counter()
            rc = run_map_build(proj, map="all", timeout_s=300)
            out["map_s"] = round(time.perf_counter() - t, 2)
            out["map_mem_mb"] = round(s.peak_delta_mb, 1)
        out["map_exit"] = rc

        maps = load_repo_maps(proj)
        serial = _repo_maps_to_serialisable(maps)
        msum = _build_map_summary(serial)
        msum_json = json.dumps(msum, default=str)
        out["map_summary_chars"] = len(msum_json)
        out["map_summary_tokens"] = _est_tokens(msum_json)
        out["map_counts"] = msum.get("by_map_type", {})

    return out


def main() -> None:
    results = []
    for name in TARGETS:
        print(f"=== {name} ===", flush=True)
        r = bench_target(name)
        results.append(r)
        print(json.dumps(r, indent=2), flush=True)

    print("\n===== SUMMARY TABLE =====", flush=True)
    hdr = f"{'target':12} {'files':>6} {'loc':>7} {'forensic_s':>10} {'fmem_mb':>8} {'map_s':>7} {'mmem_mb':>8} {'f_tok':>6} {'m_tok':>6} {'det':>5}"
    print(hdr, flush=True)
    for r in results:
        print(
            f"{r['target']:12} {r['py_files']:>6} {r['loc']:>7} "
            f"{r['forensic_s']:>10} {r['forensic_mem_mb']:>8} {r['map_s']:>7} "
            f"{r['map_mem_mb']:>8} {r['forensic_summary_tokens']:>6} "
            f"{r['map_summary_tokens']:>6} {str(r['deterministic']):>5}",
            flush=True,
        )

    # Dump machine-readable results next to this script for the README write-up.
    (Path(__file__).resolve().parent / "_benchmark_results.json").write_text(
        json.dumps(results, indent=2), encoding="utf-8"
    )
    print("\nwrote tests/_benchmark_results.json", flush=True)


if __name__ == "__main__":
    main()
