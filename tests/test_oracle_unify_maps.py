"""Oracle-corpus parity tests for the authority+runtime adapter unification.

These pin the relocated Python logic that the vigil source tree does NOT
exercise (its writes resolve to __unknown_target__; it has no merged-side-effect
modules or __main__ entrypoints worth this level of assertion). The fixtures
under tests/oracle_unify/ deliberately drive every relocated code path; this
file asserts the PythonAdapter-routed extraction produces the rich, resolved
output (target resolution, provenance, os.replace, side-effect merge, entrypoint
cross-ref) -- i.e. that the unification did not silently fall back to the thin
candidate/signal shapes.

Run: pytest tests/test_oracle_unify_maps.py -v
"""
from __future__ import annotations

import json
from pathlib import Path

from vigil_mapper.authority_builder import build_authority_map
from vigil_mapper.runtime_builder import build_runtime_map_static
from vigil_mapper.source_adapters import get_adapter_for_file

ORACLE = Path(__file__).parent / "oracle_unify"
_PY = Path("m.py")


def _ad():
    return get_adapter_for_file(_PY)


# ---------------------------------------------------------------------------
# Authority adapter: the enriched candidate carries resolved target/provenance
# ---------------------------------------------------------------------------

def test_authority_adapter_resolves_targets_and_provenance():
    src = (ORACLE / "authority_writers.py").read_text(encoding="utf-8")
    cands = _ad().extract_writer_calls(src, ORACLE / "authority_writers.py")
    by_op: dict[str, list] = {}
    for c in cands:
        by_op.setdefault(c.operation, []).append(c)

    # Every relocated operation kind is present (thin adapter lacked save/os.replace).
    assert {"write_text", "write_bytes", "save", "os.replace", "open_write", "json_dump"} <= set(by_op), (
        "missing relocated operations: %r" % sorted(by_op)
    )

    # Resolved targets + provenance reach the candidate (thin candidate had neither).
    targets = {c.resolved_target for c in cands}
    assert "out.json" in targets, "path_constructor target not resolved: %r" % targets
    assert "report.txt" in targets, "string_literal target not resolved: %r" % targets
    assert "state.db" in targets, "os.replace target not resolved: %r" % targets

    provs = {c.provenance for c in cands}
    assert "path_constructor" in provs
    assert "string_literal" in provs


def test_authority_adapter_read_only_is_empty():
    # The read-only helper (read_text / open(r) / json.load) must yield nothing
    # from the relocated resolver -- routed through the adapter.
    src = (
        "import json\n"
        "from pathlib import Path\n"
        "def load():\n"
        "    a = Path('in.txt').read_text()\n"
        "    with open('in2.txt') as f:\n"
        "        b = f.read()\n"
        "    c = json.load(open('s.json'))\n"
        "    return a, b, c\n"
    )
    assert _ad().extract_writer_calls(src, _PY) == []


def test_authority_map_oracle_resolves_shared_write_cluster():
    domains = build_authority_map(ORACLE)
    names = {d.authority_domain for d in domains}
    # The two pkg_a/pkg_b writers to shared/state.json form a shared-write cluster.
    assert any(n.startswith("shared_write:") for n in names), (
        "shared-write auto-discovery cluster missing: %r" % names
    )
    # The resolver-rich writer file surfaces its resolved targets.
    wd = [json.loads(w) for d in domains for w in d.writers_detected]
    ops = {w.get("operation") for w in wd}
    assert {"os.replace", "json_dump", "save"} <= ops, "rich ops not surfaced in map: %r" % ops


# ---------------------------------------------------------------------------
# Runtime adapter: rich visitor results (merge + entrypoint cross-ref)
# ---------------------------------------------------------------------------

def test_runtime_adapter_emits_module_side_effects_for_each_top_level_call():
    # Contract: the adapter returns the _RuntimeVisitor RAW per-call results
    # (one :module dict per top-level side-effect call). The cross-result MERGE
    # into a single RuntimeNode is the builder's job -- asserted on the final
    # map in test_runtime_map_oracle_has_entrypoints_and_merged_module.
    src = (ORACLE / "runtime_side_effects.py").read_text(encoding="utf-8")
    results = _ad().extract_runtime_results(src, "runtime_side_effects.py")
    module_dicts = [r for r in results if r["node"] == "runtime_side_effects.py:module"
                    and r["kind"] == "import_time_side_effect"]
    # Three top-level calls -> three raw :module dicts at the adapter layer.
    assert len(module_dicts) == 3, "expected 3 raw :module dicts: %r" % [
        (r["node"], r["kind"]) for r in results
    ]
    all_se = {se for r in module_dicts for se in r["side_effects"]}
    assert {"configure_logging", "register_plugins", "warm_cache"} <= all_se, (
        "raw :module dicts missing the three side-effect calls: %r" % all_se
    )


def test_runtime_adapter_entrypoint_cross_reference():
    src = (ORACLE / "runtime_entrypoint.py").read_text(encoding="utf-8")
    results = _ad().extract_runtime_results(src, "runtime_entrypoint.py")
    kinds = {(r["node"], r["kind"]) for r in results}
    assert ("runtime_entrypoint.py:__main__", "main_entrypoint") in kinds, (
        "no main_entrypoint node: %r" % kinds
    )
    # The invoked `main` def is cross-referenced as an entry_function.
    assert ("runtime_entrypoint.py:main", "entry_function") in kinds, (
        "entry-function cross-ref missing: %r" % kinds
    )
    # The plain helper must NOT be an entrypoint.
    assert not any("helper" in node and kind in ("main_entrypoint", "entry_function")
                   for node, kind in kinds), "helper wrongly surfaced: %r" % kinds


def test_runtime_map_oracle_has_entrypoints_and_merged_module():
    nodes = build_runtime_map_static(ORACLE)
    kinds = {n.kind for n in nodes}
    assert "main_entrypoint" in kinds
    assert "entry_function" in kinds
    # Exactly one merged :module node for the multi-side-effect file.
    module_nodes = [n for n in nodes if n.node == "runtime_side_effects.py:module"]
    assert len(module_nodes) == 1, "expected one merged :module node, got %r" % [
        n.node for n in module_nodes
    ]
    m = module_nodes[0]
    assert set(m.depends_on_env) >= {"AWS_REGION", "DEBUG"}, "module env not merged: %r" % (
        m.depends_on_env,
    )
