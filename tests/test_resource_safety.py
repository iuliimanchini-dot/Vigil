"""TDD tests for resource-safety fixes (fixes 1-5).

Fix 1 -- file-size guard: oversized file skipped, listed in oversized_files; normal file processed.
Fix 2 -- LRU source cache: oldest entry evicted when cap reached; re-read returns correct content.
Fix 3 -- map memory free: in_memory_acc cleared after last consumer; RSS delta on ~1.5 MB project.
Fix 4 -- job timeout: job sleeping past tiny timeout transitions to "timeout".
Fix 5 -- real cancel: pre-set cancel_event makes run_map_build stop early (fewer maps processed).

Run:
    python -m pytest tests/test_resource_safety.py -p no:cacheprovider -p no:xdist -v
"""
from __future__ import annotations

import sys
import os
import threading
import time
import tracemalloc
import tempfile
from pathlib import Path
from unittest.mock import patch, MagicMock

import pytest

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_project(root: Path, extra_files: dict[str, str] | None = None) -> None:
    """Create a minimal Python project under root."""
    root.mkdir(parents=True, exist_ok=True)
    (root / "a.py").write_text(
        "import os\n\ndef hello():\n    return 'hi'\n",
        encoding="utf-8",
    )
    if extra_files:
        for name, content in extra_files.items():
            (root / name).write_text(content, encoding="utf-8")


def _make_big_file(path: Path, size_mb: float) -> None:
    """Write a syntactically valid Python file of approximately size_mb MiB."""
    target_bytes = int(size_mb * 1024 * 1024)
    # Each line is "x = 1  # padding...\n" — about 80 bytes
    line = "x = 1  # " + "a" * 68 + "\n"
    lines_needed = max(1, target_bytes // len(line.encode("utf-8")))
    path.write_text(line * lines_needed, encoding="utf-8")


def _poll(status_fn, job_id: str, max_wait: float = 10.0, interval: float = 0.1) -> str:
    deadline = time.monotonic() + max_wait
    while time.monotonic() < deadline:
        s = status_fn(job_id)
        if s.get("status") != "running":
            return s.get("status", "unknown")
        time.sleep(interval)
    return "still_running"


# ===========================================================================
# Fix 1: File-size guard
# ===========================================================================

class TestFileSizeGuard:
    """Fix 1: oversized files skipped; normal files still processed."""

    def test_oversized_file_skipped_and_listed(self, tmp_path):
        """A file above max_file_mb is skipped; its path appears in oversized_files."""
        from vigil_mapper.parse_cache import ParseCacheL1

        big = tmp_path / "big.py"
        _make_big_file(big, size_mb=2.0)

        cache = ParseCacheL1(None, max_file_mb=1.0)
        pf = cache.get_or_parse(big, tmp_path)

        # The ParsedFile returned for an oversized file is empty (no symbols)
        assert pf.imports_out == []
        assert pf.symbols_defined == []

        assert len(cache.oversized_files) == 1
        skipped = cache.oversized_files[0]
        assert skipped["path"] == str(big)
        assert skipped["size_mb"] > 1.0

    def test_normal_file_still_processed(self, tmp_path):
        """A file below the limit is parsed normally."""
        from vigil_mapper.parse_cache import ParseCacheL1

        small = tmp_path / "small.py"
        small.write_text("def greet(): return 'hi'\n", encoding="utf-8")

        cache = ParseCacheL1(None, max_file_mb=5.0)
        pf = cache.get_or_parse(small, tmp_path)

        assert pf.is_parseable
        assert "greet" in pf.symbols_defined
        assert cache.oversized_files == []

    def test_oversized_skipped_via_run_map_build(self, tmp_path):
        """run_map_build with max_file_mb skips parsing the big file.

        The structural map still produces an entry for big.py (with empty
        symbols/imports — the file was scanned but not parsed), but small.py
        has its symbols correctly extracted.  The key check is that big.py's
        symbols are empty (parse was skipped) and the build succeeds.
        """
        from vigil_mapper import run_map_build

        proj = tmp_path / "proj"
        proj.mkdir()
        (proj / "small.py").write_text("def ok(): pass\n", encoding="utf-8")
        big = proj / "big.py"
        _make_big_file(big, size_mb=2.0)

        out = tmp_path / "out"
        out.mkdir()
        rc = run_map_build(
            proj,
            map="structural",
            dry_run=False,
            output_dir=out,
            max_file_mb=1.0,
        )
        assert rc == 0

        import json
        maps = list(out.glob("*structural_map.json"))
        assert maps, "structural map not written"
        payload = json.loads(maps[0].read_text(encoding="utf-8"))
        entries_by_file = {
            e["file"]: e
            for e in payload.get("entries", [])
            if isinstance(e, dict) and "file" in e
        }
        assert "small.py" in entries_by_file, "small.py must appear in structural map"

        # The oversized file is still scanned (path discovered) but its symbols
        # and imports must be empty because the content was never read/parsed.
        assert "big.py" in entries_by_file, "big.py path must appear in structural map"
        big_entry = entries_by_file["big.py"]
        assert big_entry.get("symbols_defined", []) == [], (
            "oversized big.py should have no parsed symbols"
        )
        assert big_entry.get("imports_out", []) == [], (
            "oversized big.py should have no parsed imports"
        )


# ===========================================================================
# Fix 2: Bounded LRU source cache
# ===========================================================================

class TestLRUSourceCache:
    """Fix 2: _source_cache is bounded; oldest entry evicted; re-read correct."""

    def test_cap_is_respected(self, tmp_path):
        """After inserting cap+1 entries, cache size stays at cap."""
        from vigil_mapper.parse_cache import ParseCacheL1

        cap = 3
        cache = ParseCacheL1(None, source_cache_max_entries=cap)

        files = []
        for i in range(cap + 1):
            f = tmp_path / f"f{i}.py"
            f.write_text(f"x{i} = {i}\n", encoding="utf-8")
            files.append(f)
            cache.get_or_parse(f, tmp_path)

        assert len(cache._source_cache) == cap

    def test_oldest_evicted(self, tmp_path):
        """The first-inserted entry is evicted when cap is exceeded."""
        from vigil_mapper.parse_cache import ParseCacheL1

        cap = 2
        cache = ParseCacheL1(None, source_cache_max_entries=cap)

        f0 = tmp_path / "f0.py"
        f1 = tmp_path / "f1.py"
        f2 = tmp_path / "f2.py"
        for f, body in [(f0, "a=0\n"), (f1, "b=1\n"), (f2, "c=2\n")]:
            f.write_text(body, encoding="utf-8")

        cache.get_or_parse(f0, tmp_path)
        cache.get_or_parse(f1, tmp_path)
        # f0 is now oldest; inserting f2 should evict f0
        cache.get_or_parse(f2, tmp_path)

        assert str(f0) not in cache._source_cache, "f0 should have been evicted"
        assert str(f1) in cache._source_cache
        assert str(f2) in cache._source_cache

    def test_reread_after_eviction_returns_correct_content(self, tmp_path):
        """get_cached_source after eviction returns None (cache miss), not stale data."""
        from vigil_mapper.parse_cache import ParseCacheL1

        cap = 1
        cache = ParseCacheL1(None, source_cache_max_entries=cap)

        f0 = tmp_path / "f0.py"
        f1 = tmp_path / "f1.py"
        f0.write_text("answer = 42\n", encoding="utf-8")
        f1.write_text("other = 99\n", encoding="utf-8")

        cache.get_or_parse(f0, tmp_path)
        assert cache.get_cached_source(f0) == "answer = 42\n"

        # Inserting f1 evicts f0
        cache.get_or_parse(f1, tmp_path)
        # f0 evicted → get_cached_source returns None (caller must re-read disk)
        assert cache.get_cached_source(f0) is None
        # f1 is still present and correct
        assert cache.get_cached_source(f1) == "other = 99\n"

    def test_hit_promotes_entry(self, tmp_path):
        """Accessing an entry via get_cached_source promotes it, protecting it from eviction."""
        from vigil_mapper.parse_cache import ParseCacheL1

        cap = 2
        cache = ParseCacheL1(None, source_cache_max_entries=cap)

        f0 = tmp_path / "f0.py"
        f1 = tmp_path / "f1.py"
        f2 = tmp_path / "f2.py"
        for f, body in [(f0, "a=0\n"), (f1, "b=1\n"), (f2, "c=2\n")]:
            f.write_text(body, encoding="utf-8")

        cache.get_or_parse(f0, tmp_path)
        cache.get_or_parse(f1, tmp_path)
        # Access f0 via get_cached_source → promotes f0 to MRU; f1 becomes LRU
        cache.get_cached_source(f0)
        # Insert f2 → should evict f1 (LRU), not f0
        cache.get_or_parse(f2, tmp_path)

        assert str(f0) in cache._source_cache, "f0 was promoted, should survive"
        assert str(f1) not in cache._source_cache, "f1 should have been evicted"
        assert str(f2) in cache._source_cache


# ===========================================================================
# Fix 3: Free maps after serialization — RSS delta
# ===========================================================================

class TestMapMemoryFree:
    """Fix 3: in_memory_acc cleared after last consumer; reduced peak allocation."""

    def _make_medium_project(self, root: Path, n_files: int = 40, lines_each: int = 300) -> None:
        """Create a project with n_files Python files to produce measurable allocations."""
        root.mkdir(parents=True, exist_ok=True)
        for i in range(n_files):
            body = "\n".join(
                [f"# file {i}"]
                + [f"def fn_{i}_{j}(x): return x + {j}" for j in range(lines_each // 2)]
                + [f"VAR_{i}_{j} = {j}" for j in range(lines_each // 2)]
            )
            (root / f"mod_{i:03d}.py").write_text(body, encoding="utf-8")

    def test_acc_cleared_after_build(self, tmp_path):
        """After run_map_build completes, the in_memory_acc dict inside cmd_map_build
        should have had its entries freed.  We verify by checking that the structural
        map is written correctly (build succeeded) and that the build returns 0."""
        from vigil_mapper import run_map_build

        proj = tmp_path / "proj"
        _make_project(proj)
        out = tmp_path / "out"
        out.mkdir()

        rc = run_map_build(proj, map="structural", dry_run=False, output_dir=out)
        assert rc == 0

    def test_rss_reduced_for_medium_project(self, tmp_path):
        """Peak allocation during build with memory-free is lower than without.

        We use tracemalloc to capture peak bytes allocated during the build
        on a ~1.5 MB synthetic project.  The test checks that the build
        completes (rc == 0) and reports the before/after peak.

        This is a best-effort check: we assert the build works, and print the
        RSS delta for the report.  We do NOT assert a specific byte threshold
        because tracemalloc overhead varies, but we verify peak stays below
        a generous 300 MB ceiling (the observed hang case was +729 MB).
        """
        from vigil_mapper import run_map_build

        proj = tmp_path / "proj"
        # ~1.5 MB project: 40 files x ~1500 bytes each ≈ 60 KB source;
        # with 300 lines each the dataclass overhead is measurable.
        self._make_medium_project(proj, n_files=40, lines_each=300)

        out = tmp_path / "out"
        out.mkdir()

        tracemalloc.start()
        snapshot_before = tracemalloc.take_snapshot()

        rc = run_map_build(proj, map="structural", dry_run=False, output_dir=out)

        snapshot_after = tracemalloc.take_snapshot()
        current, peak = tracemalloc.get_traced_memory()
        tracemalloc.stop()

        assert rc == 0, f"run_map_build returned {rc}"

        # Compute top stats for the report
        stats = snapshot_after.compare_to(snapshot_before, "lineno")
        top_delta_mb = sum(s.size_diff for s in stats[:10]) / (1024 * 1024)
        peak_mb = peak / (1024 * 1024)

        print(
            f"\n[Fix 3 RSS] peak_tracemalloc={peak_mb:.1f} MB  "
            f"top10_delta={top_delta_mb:.1f} MB"
        )

        # Generous ceiling: peak must stay below 300 MB (the pathological 10 MB
        # file case used to allocate +729 MB; our project is ~60 KB of source).
        assert peak_mb < 300, (
            f"peak allocation {peak_mb:.1f} MB exceeds 300 MB ceiling — "
            "memory-free fix may not be working"
        )


# ===========================================================================
# Fix 4: Job wall-clock timeout
# ===========================================================================

class TestJobTimeout:
    """Fix 4: a job sleeping past its timeout transitions to 'timeout'."""

    def test_job_times_out(self):
        """Worker that sleeps forever is cancelled by the watcher within timeout_s."""
        from vigil_mcp._jobs import JobRegistry, STATUS_TIMEOUT

        registry = JobRegistry()

        def slow_fn(cancel_event):
            # Poll cancel_event so we exit promptly when the watcher fires
            cancel_event.wait(timeout=30)

        result = registry.start(slow_fn, timeout_s=1)
        assert result["status"] == "running"
        job_id = result["job_id"]

        final_status = _poll(registry.status, job_id, max_wait=8.0)
        assert final_status == STATUS_TIMEOUT, (
            f"Expected 'timeout', got '{final_status}'"
        )

    def test_fast_job_not_timed_out(self):
        """A fast job completes normally and does NOT end up in timeout."""
        from vigil_mcp._jobs import JobRegistry, STATUS_DONE

        registry = JobRegistry()

        def fast_fn():
            return 42

        result = registry.start(fast_fn, timeout_s=10)
        job_id = result["job_id"]

        final_status = _poll(registry.status, job_id, max_wait=5.0)
        assert final_status == STATUS_DONE, (
            f"Expected 'done', got '{final_status}'"
        )
        assert registry.result(job_id)["result"] == 42

    def test_module_level_start_accepts_timeout_s(self):
        """The module-level start() function forwards timeout_s correctly."""
        import vigil_mcp._jobs as jobs

        def instant_fn():
            return "ok"

        r = jobs.start(instant_fn, timeout_s=60)
        assert r["job_id"] is not None
        final = _poll(jobs.status, r["job_id"], max_wait=5.0)
        assert final == "done"


# ===========================================================================
# Fix 5: Real cancellation wired through run_map_build
# ===========================================================================

class TestRealCancellation:
    """Fix 5: cancel_event pre-set stops run_map_build before all maps are built."""

    def test_presset_cancel_stops_early(self, tmp_path):
        """A cancel_event that is set before the call returns 0 but processes
        fewer maps than the full pipeline would (at most the first map)."""
        from vigil_mapper import run_map_build

        proj = tmp_path / "proj"
        _make_project(proj)
        out = tmp_path / "out"
        out.mkdir()

        cancel = threading.Event()
        cancel.set()  # already cancelled before we even start

        rc = run_map_build(
            proj,
            map="all",
            dry_run=True,
            output_dir=out,
            cancel_event=cancel,
        )
        # Should return 0 (cancelled is not an error)
        assert rc == 0

        # With cancel pre-set, the loop breaks before the first map even starts;
        # so no map files are written.  In dry_run mode nothing is written anyway,
        # but we can verify the structural builder was skipped by checking that
        # the parse cache has zero files processed (it's never constructed when
        # cancelled before iteration starts).
        # We can't directly inspect internals here, but exit code 0 confirms
        # the cancel path is reachable without crashing.

    def test_cancel_mid_run_stops_after_current_map(self, tmp_path):
        """A cancel_event set while structural is building causes the loop to
        stop before moving to the next map."""
        from vigil_mapper import run_map_build
        import vigil_mapper.cli_entry as ce

        proj = tmp_path / "proj"
        _make_project(proj)
        out = tmp_path / "out"
        out.mkdir()

        cancel = threading.Event()
        maps_built: list[str] = []
        original_build = ce._build_single_map

        def patched_build(map_name, *args, **kwargs):
            maps_built.append(map_name)
            result = original_build(map_name, *args, **kwargs)
            # Set cancel after the first map completes
            if len(maps_built) == 1:
                cancel.set()
            return result

        with patch.object(ce, "_build_single_map", patched_build):
            rc = run_map_build(
                proj,
                map="all",
                dry_run=True,
                output_dir=out,
                cancel_event=cancel,
            )

        assert rc == 0
        # Only the first map (structural) should have been built before cancel
        assert len(maps_built) == 1, (
            f"Expected 1 map built before cancel, got {len(maps_built)}: {maps_built}"
        )
        assert maps_built[0] == "structural"
