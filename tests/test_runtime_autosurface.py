"""TDD: runtime map auto-surfaces real entrypoints WITHOUT a seed file.

Background
----------
``build_runtime_map_static`` auto-discovers runtime signals via the Python AST
visitor (``_runtime_ast._RuntimeVisitor``) and adapter dispatch (Go/Java/JS/TS).
Historically the Python visitor detected only module-level call statements,
route/dispatch decorators, background-task spawns inside init-style functions,
and ``os.environ`` reads. It did NOT recognise the single most common Python
entrypoint -- an ``if __name__ == "__main__":`` block -- so a plain script with

    def main(): ...
    if __name__ == "__main__":
        main()

produced ``runtime == 0`` and the map was useless out-of-the-box (verified).

The fix: surface genuine entrypoints discovered from the AST as inferred
``RuntimeNode`` entries (``status="inferred"``, ``source="static_scan"``,
evidence pointing to ``file:line``). Covered:
  - ``if __name__ == "__main__":`` blocks (kind ``main_entrypoint``);
  - the module-level entry function(s) invoked from that block;
  - async entrypoints (``async def main`` / ``asyncio.run(...)``).

Precision guard (verified against the discovery logic, not docstrings): an
ordinary helper function or a plain import must NOT become a runtime node. Only
real entrypoints / runtime signals surface.

With a seed present, behaviour is preserved: the seed refines/augments and the
same node is not double-surfaced.

Multi-language: adapter runtime signals (e.g. Go ``init``/goroutine) already
surface without a seed via ``collect_adapter_runtime_nodes``; a regression test
pins that.

Run:  pytest tests/test_runtime_autosurface.py -v
"""
from __future__ import annotations

import json
from pathlib import Path

from vigil_mapper.map_storage import seeds_dir
from vigil_mapper.runtime_builder import build_runtime_map_static


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _write_seed(project_dir: Path, nodes: list[dict]) -> None:
    sd = seeds_dir(project_dir)
    sd.mkdir(parents=True, exist_ok=True)
    (sd / "runtime_seed.json").write_text(
        json.dumps({"schema_version": "1.0.0", "nodes": nodes}),
        encoding="utf-8",
    )


def _kinds(nodes) -> set[str]:
    return {n.kind for n in nodes}


# ---------------------------------------------------------------------------
# 1. No seed -> a __main__ entrypoint auto-surfaces, naming entrypoint + file
# ---------------------------------------------------------------------------

def test_no_seed_main_entrypoint_autosurfaces(tmp_path: Path) -> None:
    """`if __name__ == "__main__": main()` with NO seed -> runtime >= 1 node,
    and that node names the entrypoint + the file."""
    (tmp_path / "app.py").write_text(
        "def main():\n"
        "    print('hi')\n"
        "\n"
        "if __name__ == '__main__':\n"
        "    main()\n",
        encoding="utf-8",
    )

    nodes = build_runtime_map_static(tmp_path)

    assert len(nodes) >= 1, "expected >=1 runtime node for a __main__ entrypoint"

    # A main_entrypoint node exists and references the file.
    main_nodes = [n for n in nodes if n.kind == "main_entrypoint"]
    assert main_nodes, "no main_entrypoint node surfaced: %r" % _kinds(nodes)
    assert any("app.py" in n.node for n in main_nodes), (
        "main_entrypoint node does not name the file: %r" % [n.node for n in main_nodes]
    )
    # The invoked entry function 'main' is named somewhere (node or calls/evidence).
    me = main_nodes[0]
    named_main = (
        "main" in me.node
        or "main" in me.calls
        or any("main" in ev for ev in me.evidence)
    )
    assert named_main, (
        "entry function 'main' not named on the main_entrypoint node: "
        "node=%r calls=%r evidence=%r" % (me.node, me.calls, me.evidence)
    )


def test_no_seed_main_entrypoint_metadata(tmp_path: Path) -> None:
    """Surfaced entrypoint nodes are status=inferred, source=static_scan, with
    file:line evidence and modest confidence."""
    (tmp_path / "app.py").write_text(
        "def main():\n"
        "    pass\n"
        "if __name__ == '__main__':\n"
        "    main()\n",
        encoding="utf-8",
    )

    nodes = build_runtime_map_static(tmp_path)
    main_nodes = [n for n in nodes if n.kind == "main_entrypoint"]
    assert main_nodes, "no main_entrypoint node surfaced"
    n = main_nodes[0]
    assert n.status == "inferred", "entrypoint must be inferred, got %r" % n.status
    assert n.source == "static_scan", "source should be static_scan, got %r" % n.source
    assert 0.0 < n.confidence < 1.0, "confidence should be modest, got %r" % n.confidence
    assert n.defined_in.endswith("app.py"), "defined_in wrong: %r" % n.defined_in
    # Evidence points at a file:line.
    assert any(":" in ev for ev in n.evidence), "evidence lacks file:line: %r" % (n.evidence,)


# ---------------------------------------------------------------------------
# 2. Async entrypoint: async def main + asyncio.run surfaces
# ---------------------------------------------------------------------------

def test_no_seed_async_entrypoint_autosurfaces(tmp_path: Path) -> None:
    """`async def main()` invoked via `asyncio.run(main())` in a __main__ block
    surfaces as a runtime node without a seed."""
    (tmp_path / "svc.py").write_text(
        "import asyncio\n"
        "async def main():\n"
        "    await asyncio.sleep(0)\n"
        "if __name__ == '__main__':\n"
        "    asyncio.run(main())\n",
        encoding="utf-8",
    )

    nodes = build_runtime_map_static(tmp_path)
    assert len(nodes) >= 1, "expected >=1 runtime node for an async entrypoint"
    # Either a dedicated async kind or the main_entrypoint references asyncio.run.
    surfaced = [n for n in nodes if "svc.py" in n.node]
    assert surfaced, "no runtime node for svc.py: %r" % [n.node for n in nodes]
    joined = " ".join(
        [n.kind for n in surfaced]
        + [c for n in surfaced for c in n.calls]
        + [ev for n in surfaced for ev in n.evidence]
    )
    assert "asyncio.run" in joined or "async" in joined, (
        "async entrypoint signal (asyncio.run / async) not surfaced: %r"
        % [(n.node, n.kind, n.calls, n.evidence) for n in surfaced]
    )


# ---------------------------------------------------------------------------
# 3. Precision guard: helper-only module + plain import -> runtime 0 (no FP)
# ---------------------------------------------------------------------------

def test_no_seed_helpers_only_produces_zero(tmp_path: Path) -> None:
    """A module of only ordinary helper functions + a plain import, no
    entrypoint, must produce runtime == 0 (no false positives)."""
    (tmp_path / "helpers.py").write_text(
        "import os.path\n"
        "\n"
        "def add(a, b):\n"
        "    return a + b\n"
        "\n"
        "def mul(a, b):\n"
        "    return a * b\n"
        "\n"
        "class Calc:\n"
        "    def run(self, x):\n"
        "        return add(x, mul(x, x))\n",
        encoding="utf-8",
    )

    nodes = build_runtime_map_static(tmp_path)
    assert len(nodes) == 0, (
        "helper-only module must NOT surface runtime nodes, got %d: %r"
        % (len(nodes), [(n.node, n.kind) for n in nodes])
    )


def test_no_seed_plain_function_def_not_entrypoint(tmp_path: Path) -> None:
    """A bare `def main(): ...` with NO __main__ guard is just a function, not
    an entrypoint -> no main_entrypoint node."""
    (tmp_path / "lib.py").write_text(
        "def main():\n"
        "    return 42\n"
        "\n"
        "def helper():\n"
        "    return main()\n",
        encoding="utf-8",
    )

    nodes = build_runtime_map_static(tmp_path)
    assert not any(n.kind == "main_entrypoint" for n in nodes), (
        "a function named main without a __main__ guard must NOT be an "
        "entrypoint: %r" % [(n.node, n.kind) for n in nodes]
    )


# ---------------------------------------------------------------------------
# 4. Seed present -> still works, no double-surface of the same node
# ---------------------------------------------------------------------------

def test_seed_present_no_double_surface(tmp_path: Path) -> None:
    """With a runtime seed naming the same entrypoint node, the node appears
    exactly once (canonical seed wins; auto does not duplicate it)."""
    (tmp_path / "app.py").write_text(
        "def main():\n"
        "    pass\n"
        "if __name__ == '__main__':\n"
        "    main()\n",
        encoding="utf-8",
    )

    # Discover the auto-surfaced node name first (no seed).
    auto_nodes = build_runtime_map_static(tmp_path)
    main_auto = [n for n in auto_nodes if n.kind == "main_entrypoint"]
    assert main_auto, "precondition: expected a main_entrypoint without seed"
    node_name = main_auto[0].node

    # Seed that exact node name.
    _write_seed(tmp_path, [
        {"node": node_name, "defined_in": "app.py", "kind": "main_entrypoint"}
    ])

    seeded = build_runtime_map_static(tmp_path)
    matching = [n for n in seeded if n.node == node_name]
    assert len(matching) == 1, (
        "node %r surfaced %d times with a seed (expected exactly 1): %r"
        % (node_name, len(matching), [(n.node, n.status) for n in matching])
    )
    assert matching[0].status == "canonical", (
        "seeded node must be canonical, got %r" % matching[0].status
    )


def test_seed_still_augments(tmp_path: Path) -> None:
    """A seed node for a separate concept still surfaces alongside the
    auto-discovered entrypoint (seed augments, does not replace auto)."""
    (tmp_path / "app.py").write_text(
        "def main():\n"
        "    pass\n"
        "if __name__ == '__main__':\n"
        "    main()\n",
        encoding="utf-8",
    )
    _write_seed(tmp_path, [
        {"node": "external:db_pool", "defined_in": "infra/db.py", "kind": "service"}
    ])

    nodes = build_runtime_map_static(tmp_path)
    names = {n.node for n in nodes}
    assert "external:db_pool" in names, "seed node missing: %r" % names
    assert any(n.kind == "main_entrypoint" for n in nodes), (
        "auto entrypoint must still surface with an augmenting seed: %r"
        % [(n.node, n.kind) for n in nodes]
    )


# ---------------------------------------------------------------------------
# 5. Multi-language: a Go adapter runtime signal surfaces without a seed
# ---------------------------------------------------------------------------

def test_no_seed_go_runtime_signal_autosurfaces(tmp_path: Path) -> None:
    """A Go file with init()/goroutine and NO seed surfaces adapter runtime
    nodes (init/worker) -- regression pin for the adapter path."""
    (tmp_path / "main.go").write_text(
        "package main\n"
        'import "fmt"\n'
        "func init() {\n"
        '    fmt.Println("init")\n'
        "}\n"
        "func main() {\n"
        "    go worker()\n"
        "}\n"
        "func worker() {}\n",
        encoding="utf-8",
    )

    nodes = build_runtime_map_static(tmp_path)
    go_nodes = [n for n in nodes if n.node.endswith("main.go:init") or "main.go" in n.node]
    assert go_nodes, "Go runtime signals not surfaced without a seed: %r" % [
        (n.node, n.kind) for n in nodes
    ]
    assert any(n.kind == "init" for n in go_nodes), (
        "Go init signal not surfaced: %r" % [(n.node, n.kind) for n in go_nodes]
    )
