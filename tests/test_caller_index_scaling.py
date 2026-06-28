"""P0+P4: caller-index scaling fix + __init__ reexport FP.

Verifies the O(N) import-index replaces the old O(N^2) per-module corpus rescan,
preserves behavior on real dead shims, and stops flagging __init__ reexports.
"""
from __future__ import annotations

import time

from vigil_forensic.gate_checks.forensic_clusters.legacy_debt import (
    build_import_index,
    check_unused_shim_module,
)


def test_build_import_index_inverts_corpus():
    corpus = {
        "a.py": "from foo import bar\nimport baz\n",
        "b.py": "import foo\n",
    }
    idx = build_import_index(corpus)
    assert "a.py" in idx.get("foo", frozenset())
    assert "b.py" in idx.get("foo", frozenset())
    assert "a.py" in idx.get("baz", frozenset())


def test_dead_shim_still_flagged():
    """Behavior preserved: a pure-reexport shim with zero importers IS flagged."""
    shim = "from real.module import Thing\n__all__ = ['Thing']\n"
    idx = build_import_index({"foo_shim.py": shim})  # only itself
    findings = check_unused_shim_module("foo_shim.py", shim, idx)
    assert len(findings) == 1
    assert "unused_shim" in findings[0].check_id


def test_shim_with_importer_not_flagged():
    """Index correctness: a shim that IS imported elsewhere is not flagged."""
    shim = "from real.module import Thing\n__all__ = ['Thing']\n"
    caller = "from foo_shim import Thing\n"
    idx = build_import_index({"foo_shim.py": shim, "user.py": caller})
    findings = check_unused_shim_module("foo_shim.py", shim, idx)
    assert findings == []


def test_init_reexport_not_flagged():
    """P4: a package __init__.py reexport with 0 direct callers is NOT a dead shim."""
    init = "from .sub import X\n__all__ = ['X']\n"
    idx = build_import_index({"pkg/__init__.py": init})
    findings = check_unused_shim_module("pkg/__init__.py", init, idx)
    assert findings == []


def test_scaling_under_threshold():
    """O(N^2) would crawl; the index keeps a 400-file corpus well under 5s."""
    corpus = {
        f"mod_{i}.py": f"from real import Thing{i}\n__all__ = ['Thing{i}']\n"
        for i in range(400)
    }
    t = time.time()
    idx = build_import_index(corpus)
    for path, content in corpus.items():
        check_unused_shim_module(path, content, idx)
    dt = time.time() - t
    assert dt < 5.0, f"caller-index too slow: {dt:.1f}s (O(N^2) regression?)"
