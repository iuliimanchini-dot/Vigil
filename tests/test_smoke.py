"""Smoke test for the standalone vigil_mapper package.

Creates a tiny 3-file project (Python, Go, TypeScript) and runs
run_map_build on it. Asserts exit code 0 and structural map has
entries for all 3 files.

Run with:
    python -m pytest tests/test_smoke.py -p no:cacheprovider -p no:xdist -v
"""
from __future__ import annotations

import sys
import os

# Ensure UTF-8 stdout on Windows
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

import json
import shutil
import tempfile
from pathlib import Path

import pytest


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_sample_project(root: Path) -> None:
    """Create a minimal 3-language project under root."""
    root.mkdir(parents=True, exist_ok=True)

    # a.py: a simple import + a function
    (root / "a.py").write_text(
        "import os\nimport json\n\ndef greet(name: str) -> str:\n    return f'hello {name}'\n",
        encoding="utf-8",
    )

    # b.go: package + func
    (root / "b.go").write_text(
        'package main\n\nimport "fmt"\n\nfunc Greet(name string) string {\n    return fmt.Sprintf("hello %s", name)\n}\n',
        encoding="utf-8",
    )

    # c.ts: import + export function
    (root / "c.ts").write_text(
        'import { readFileSync } from "fs";\n\nexport function greet(name: string): string {\n    return `hello ${name}`;\n}\n',
        encoding="utf-8",
    )


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

def test_run_map_build_returns_zero():
    """run_map_build on a tiny multi-language project returns exit code 0."""
    from vigil_mapper import run_map_build

    with tempfile.TemporaryDirectory() as tmp:
        project = Path(tmp) / "sample_project"
        _make_sample_project(project)

        output_dir = Path(tmp) / "maps_out"
        output_dir.mkdir()

        exit_code = run_map_build(
            project,
            map="structural",
            dry_run=False,
            output_dir=output_dir,
        )

        assert exit_code == 0, f"run_map_build returned {exit_code}, expected 0"


def test_structural_map_has_all_three_files():
    """Structural map output contains entries for a.py, b.go, and c.ts."""
    from vigil_mapper import run_map_build

    with tempfile.TemporaryDirectory() as tmp:
        project = Path(tmp) / "sample_project"
        _make_sample_project(project)

        output_dir = Path(tmp) / "maps_out"
        output_dir.mkdir()

        exit_code = run_map_build(
            project,
            map="structural",
            dry_run=False,
            output_dir=output_dir,
        )
        assert exit_code == 0

        # Find the structural map JSON (filename prefix may vary by version)
        structural_files = list(output_dir.glob("*structural_map.json"))
        assert structural_files, (
            f"01_structural_map.json not found in {output_dir}. "
            f"Files present: {list(output_dir.iterdir())}"
        )

        payload = json.loads(structural_files[0].read_text(encoding="utf-8"))
        entries = payload.get("entries", [])
        assert entries, "structural map has no entries"

        file_keys = {e["file"] for e in entries if isinstance(e, dict) and "file" in e}

        assert "a.py" in file_keys, f"a.py not in structural map entries: {file_keys}"
        assert "b.go" in file_keys, f"b.go not in structural map entries: {file_keys}"
        assert "c.ts" in file_keys, f"c.ts not in structural map entries: {file_keys}"


def test_package_import_works():
    """Basic: package imports without errors."""
    import vigil_mapper
    assert hasattr(vigil_mapper, "run_map_build")
    assert callable(vigil_mapper.run_map_build)
