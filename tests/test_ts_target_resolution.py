"""TypeScript authority TARGET RESOLUTION — per-case assertions on the oracle.

Brings the Go PoC's write-target resolution depth to the TypeScript adapter.
The fs-family path-argument writers (``fs.writeFile`` / ``fs.writeFileSync`` /
``fs.appendFile`` / ``fs.appendFileSync`` / ``fs.createWriteStream`` and the bare
``writeFile`` / ``writeFileSync``) now resolve their first argument into
``resolved_target`` + ``provenance`` via tree-sitter on the RAW content (regex
could not — ``strip_comments_and_strings`` blanks the literal path):

  - string-literal arg     -> the literal, provenance="string_literal"
  - ``path.join(...)`` arg -> joined path, provenance="path_constructor"
  - variable arg           -> traced to its const/let/var initializer in scope
  - parameter arg          -> provenance="function_parameter", target sentinel
  - unresolvable (incl. ORM/prisma/etc.) -> __unknown_target__ / unknown

A second tier BUILDS the authority map on the oracle and asserts the resolved
target + provenance SURFACE in the built map, and that unresolvable writers stay
``__unknown_target__``.

Run: pytest tests/test_ts_target_resolution.py -v
"""
from __future__ import annotations

import json
import shutil
import tempfile
from pathlib import Path

from vigil_mapper.source_adapters.typescript import TypescriptAdapter
from vigil_mapper.source_adapters._ir import AuthorityWriteCandidate
from vigil_mapper.authority_builder import build_authority_map

ORACLE = Path(__file__).parent / "oracle_target_ts" / "writers.ts"
_UNKNOWN = "__unknown_target__"


def _by_hint() -> dict[str, AuthorityWriteCandidate]:
    src = ORACLE.read_text(encoding="utf-8")
    cands = TypescriptAdapter().extract_writer_calls(src, ORACLE)
    return {c.target_hint: c for c in cands}


# ---------------------------------------------------------------------------
# Adapter-level resolution
# ---------------------------------------------------------------------------

def test_oracle_write_site_count() -> None:
    src = ORACLE.read_text(encoding="utf-8")
    cands = TypescriptAdapter().extract_writer_calls(src, ORACLE)
    # 8 fs-family writers + 1 ORM save = 9.
    assert len(cands) == 9, "expected 9 write sites, got %d: %r" % (
        len(cands), [(c.line, c.write_kind, c.target_hint) for c in cands]
    )


def test_literal_arg_resolves() -> None:
    c = _by_hint()["config.json"]
    assert c.resolved_target == "config.json"
    assert c.provenance == "string_literal"


def test_const_var_resolves() -> None:
    # const p = "out.json"; fs.writeFile(p, ...)
    c = _by_hint()["p"]
    assert c.resolved_target == "out.json"
    assert c.provenance == "string_literal"


def test_let_var_resolves() -> None:
    # let q = "data.txt"; fs.writeFileSync(q, ...)
    c = _by_hint()["q"]
    assert c.resolved_target == "data.txt"
    assert c.provenance == "string_literal"


def test_var_join_resolves() -> None:
    # const j = path.join("a","b.json"); fs.writeFile(j, ...)
    c = _by_hint()["j"]
    assert c.resolved_target == "a/b.json"
    assert c.provenance == "path_constructor"


def test_inline_join_resolves() -> None:
    # fs.writeFile(path.join("d","e.txt"), ...)
    c = _by_hint()['path.join("d", "e.txt")']
    assert c.resolved_target == "d/e.txt"
    assert c.provenance == "path_constructor"


def test_function_parameter_noted_not_guessed() -> None:
    # function writeParam(target: string){ fs.writeFile(target, ...) }
    c = _by_hint()["target"]
    assert c.resolved_target == _UNKNOWN
    assert c.provenance == "function_parameter"


def test_create_write_stream_literal_resolves() -> None:
    # fs.createWriteStream("stream.log")
    c = _by_hint()["stream.log"]
    assert c.resolved_target == "stream.log"
    assert c.provenance == "string_literal"
    assert c.write_kind == "fs_write"


def test_append_literal_resolves_and_is_append_kind() -> None:
    # fs.appendFileSync("log.txt", ...)
    c = _by_hint()["log.txt"]
    assert c.resolved_target == "log.txt"
    assert c.provenance == "string_literal"
    assert c.write_kind == "fs_append"


def test_orm_save_stays_unresolved() -> None:
    # repo.save(entity) — ORM receiver, not a path target. target_hint is "".
    c = _by_hint()[""]
    assert c.write_kind == "orm_save"
    assert c.resolved_target == _UNKNOWN
    assert c.provenance == "unknown"


# ---------------------------------------------------------------------------
# Inline / edge cases
# ---------------------------------------------------------------------------

def test_unknown_variable_stays_unresolved() -> None:
    # A variable assigned from a non-resolvable call must NOT yield a guess.
    src = (
        "import * as fs from 'fs';\n"
        "function compute(): string { return 'x'; }\n"
        "function f(data: string): void {\n"
        "  const p = compute();\n"
        "  fs.writeFile(p, data, () => {});\n"
        "}\n"
    )
    cands = TypescriptAdapter().extract_writer_calls(src, Path("unk.ts"))
    fs_cands = [c for c in cands if c.write_kind == "fs_write"]
    assert len(fs_cands) == 1, [(c.line, c.target_hint) for c in cands]
    assert fs_cands[0].resolved_target == _UNKNOWN
    assert fs_cands[0].provenance == "unknown"


def test_standalone_writefile_resolves_with_lower_confidence() -> None:
    # Bare writeFile(...) (no fs. receiver) -> fs_write at confidence 0.85.
    src = (
        "import { writeFile } from 'fs/promises';\n"
        "async function f(data: string): Promise<void> {\n"
        "  await writeFile('bare.json', data);\n"
        "}\n"
    )
    cands = TypescriptAdapter().extract_writer_calls(src, Path("bare.ts"))
    fs_cands = [c for c in cands if c.write_kind == "fs_write"]
    assert len(fs_cands) == 1, [(c.line, c.target_hint, c.write_kind) for c in cands]
    assert fs_cands[0].resolved_target == "bare.json"
    assert fs_cands[0].provenance == "string_literal"
    assert fs_cands[0].confidence == 0.85


# ---------------------------------------------------------------------------
# End-to-end: the BUILT authority map surfaces resolved target+provenance
# ---------------------------------------------------------------------------

def _build_oracle_map_entries() -> list[dict]:
    src = ORACLE.read_text(encoding="utf-8")
    tmp = Path(tempfile.mkdtemp(prefix="ts_target_oracle_"))
    try:
        (tmp / "writers.ts").write_text(src, encoding="utf-8")
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
        "config.json", "out.json", "data.txt", "a/b.json", "d/e.txt",
        "stream.log", "log.txt",
    }
    for e in entries:
        if e["target"] not in resolved_paths:
            assert e["provenance"] == "unknown", (
                "non-resolved writer at line %s surfaced provenance %r (target=%r)"
                % (e.get("line"), e["provenance"], e.get("target"))
            )
