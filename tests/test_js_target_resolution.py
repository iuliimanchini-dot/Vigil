"""JavaScript authority TARGET RESOLUTION — per-case assertions on the oracle.

Brings the Go PoC's write-target resolution depth to the JavaScript adapter.
The fs-family path-argument writers (``fs.writeFile`` / ``fs.writeFileSync`` /
``fs.appendFile`` / ``fs.appendFileSync`` / ``fs.createWriteStream`` and the bare
``writeFile`` / ``writeFileSync``) now resolve their first argument into
``resolved_target`` + ``provenance`` via the shared tree-sitter resolver
(``_ts_target_resolution`` — TS/JS share the grammar):

  - string-literal arg     -> the literal, provenance="string_literal"
  - ``path.join(...)`` arg -> joined path, provenance="path_constructor"
  - variable arg           -> traced to its const/let/var initializer in scope
  - parameter arg          -> provenance="function_parameter", target sentinel
  - unresolvable (incl. ORM/storage) -> __unknown_target__ / unknown

A second tier BUILDS the authority map on the oracle and asserts the resolved
target + provenance SURFACE in the built map, and that unresolvable writers stay
``__unknown_target__``.

Run: pytest tests/test_js_target_resolution.py -v
"""
from __future__ import annotations

import json
import shutil
import tempfile
from pathlib import Path

from vigil_mapper.source_adapters.javascript import JavascriptAdapter
from vigil_mapper.source_adapters._ir import AuthorityWriteCandidate
from vigil_mapper.authority_builder import build_authority_map

ORACLE = Path(__file__).parent / "oracle_target_js" / "writers.js"
_UNKNOWN = "__unknown_target__"


def _by_hint() -> dict[str, AuthorityWriteCandidate]:
    src = ORACLE.read_text(encoding="utf-8")
    cands = JavascriptAdapter().extract_writer_calls(src, ORACLE)
    return {c.target_hint: c for c in cands}


# ---------------------------------------------------------------------------
# Adapter-level resolution
# ---------------------------------------------------------------------------

def test_oracle_write_site_count() -> None:
    src = ORACLE.read_text(encoding="utf-8")
    cands = JavascriptAdapter().extract_writer_calls(src, ORACLE)
    # 9 fs-family writers + 1 ORM save = 10.
    assert len(cands) == 10, "expected 10 write sites, got %d: %r" % (
        len(cands), [(c.line, c.write_kind, c.target_hint) for c in cands]
    )


def test_literal_arg_resolves() -> None:
    c = _by_hint()["config.json"]
    assert c.resolved_target == "config.json"
    assert c.provenance == "string_literal"


def test_const_var_resolves() -> None:
    c = _by_hint()["p"]
    assert c.resolved_target == "out.json"
    assert c.provenance == "string_literal"


def test_let_var_resolves() -> None:
    c = _by_hint()["q"]
    assert c.resolved_target == "data.txt"
    assert c.provenance == "string_literal"


def test_var_decl_resolves() -> None:
    # var r = "old.txt"; fs.writeFile(r, ...)
    c = _by_hint()["r"]
    assert c.resolved_target == "old.txt"
    assert c.provenance == "string_literal"


def test_var_join_resolves() -> None:
    c = _by_hint()["j"]
    assert c.resolved_target == "a/b.json"
    assert c.provenance == "path_constructor"


def test_inline_join_resolves() -> None:
    c = _by_hint()['path.join("d", "e.txt")']
    assert c.resolved_target == "d/e.txt"
    assert c.provenance == "path_constructor"


def test_function_parameter_noted_not_guessed() -> None:
    c = _by_hint()["target"]
    assert c.resolved_target == _UNKNOWN
    assert c.provenance == "function_parameter"


def test_create_write_stream_literal_resolves() -> None:
    c = _by_hint()["stream.log"]
    assert c.resolved_target == "stream.log"
    assert c.provenance == "string_literal"
    assert c.write_kind == "fs_write"


def test_append_literal_resolves_and_is_append_kind() -> None:
    c = _by_hint()["log.txt"]
    assert c.resolved_target == "log.txt"
    assert c.provenance == "string_literal"
    assert c.write_kind == "fs_append"


def test_orm_save_stays_unresolved() -> None:
    # repo.save(entity) — receiver is not a path target.
    c = _by_hint()["repo"]
    assert c.write_kind == "orm_save"
    assert c.resolved_target == _UNKNOWN
    assert c.provenance == "unknown"


# ---------------------------------------------------------------------------
# Inline / edge cases
# ---------------------------------------------------------------------------

def test_unknown_variable_stays_unresolved() -> None:
    src = (
        "const fs = require('fs');\n"
        "function compute() { return 'x'; }\n"
        "function f(data) {\n"
        "  const p = compute();\n"
        "  fs.writeFile(p, data, () => {});\n"
        "}\n"
    )
    cands = JavascriptAdapter().extract_writer_calls(src, Path("unk.js"))
    fs_cands = [c for c in cands if c.write_kind == "fs_write"]
    assert len(fs_cands) == 1, [(c.line, c.target_hint) for c in cands]
    assert fs_cands[0].resolved_target == _UNKNOWN
    assert fs_cands[0].provenance == "unknown"


def test_storage_setitem_unaffected() -> None:
    # localStorage.setItem stays storage_write with no resolved target.
    src = (
        "function f() {\n"
        "  localStorage.setItem('k', 'v');\n"
        "}\n"
    )
    cands = JavascriptAdapter().extract_writer_calls(src, Path("st.js"))
    store = [c for c in cands if c.write_kind == "storage_write"]
    assert len(store) == 1
    assert store[0].resolved_target == _UNKNOWN
    assert store[0].provenance == "unknown"


# ---------------------------------------------------------------------------
# End-to-end: the BUILT authority map surfaces resolved target+provenance
# ---------------------------------------------------------------------------

def _build_oracle_map_entries() -> list[dict]:
    src = ORACLE.read_text(encoding="utf-8")
    tmp = Path(tempfile.mkdtemp(prefix="js_target_oracle_"))
    try:
        (tmp / "writers.js").write_text(src, encoding="utf-8")
        domains = build_authority_map(tmp)
        return [json.loads(wd) for d in domains for wd in d.writers_detected]
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def test_map_surfaces_resolved_targets() -> None:
    entries = _build_oracle_map_entries()
    by_target = {e["target"]: e for e in entries}
    expected = {
        "config.json": "string_literal",
        "out.json": "string_literal",
        "data.txt": "string_literal",
        "old.txt": "string_literal",
        "a/b.json": "path_constructor",
        "d/e.txt": "path_constructor",
        "stream.log": "string_literal",
        "log.txt": "string_literal",
    }
    for target, prov in expected.items():
        assert target in by_target, "resolved target %r missing from built map; got %r" % (
            target, sorted(by_target)
        )
        assert by_target[target]["provenance"] == prov, (
            "target %r provenance %r != expected %r"
            % (target, by_target[target]["provenance"], prov)
        )


def test_map_unresolvable_stays_unknown() -> None:
    entries = _build_oracle_map_entries()
    resolved_paths = {
        "config.json", "out.json", "data.txt", "old.txt", "a/b.json",
        "d/e.txt", "stream.log", "log.txt",
    }
    for e in entries:
        if e["target"] not in resolved_paths:
            assert e["provenance"] == "unknown", (
                "non-resolved writer at line %s surfaced provenance %r (target=%r)"
                % (e.get("line"), e["provenance"], e.get("target"))
            )
