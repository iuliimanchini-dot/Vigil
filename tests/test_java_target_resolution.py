"""Java authority TARGET RESOLUTION — per-case assertions on the oracle corpus.

Brings the Go PoC's write-target resolution depth to the Java adapter. The
JavaAdapter now resolves the first-argument file target of ``Files.write`` /
``Files.writeString`` and ``new FileWriter`` / ``new FileOutputStream`` into
``resolved_target`` + ``provenance``:

  - string-literal arg                 -> the literal, provenance="string_literal"
  - ``Path.of("x")`` (single literal)  -> the literal, provenance="string_literal"
  - ``Path.of("a","b")`` / ``Paths.get`` -> joined path, provenance="path_constructor"
  - variable arg (local declaration)   -> traced to its initializer in scope
  - method-parameter arg               -> provenance="function_parameter", target sentinel
  - unresolvable (incl. receiver       -> __unknown_target__ / unknown (NO false target)
    write/append/save)

A second tier of tests BUILDS the authority map on the oracle and asserts the
resolved target + provenance SURFACE in the built map (end-to-end builder
consumption), and that unresolvable writers stay ``__unknown_target__``.

Run: pytest tests/test_java_target_resolution.py -v
"""
from __future__ import annotations

import json
import shutil
import tempfile
from pathlib import Path

import pytest

from vigil_mapper.source_adapters.java import JavaAdapter
from vigil_mapper.source_adapters._ir import AuthorityWriteCandidate
from vigil_mapper.authority_builder import build_authority_map

ORACLE = Path(__file__).parent / "oracle_target_java" / "Writers.java"
_UNKNOWN = "__unknown_target__"


def _by_hint() -> dict[str, AuthorityWriteCandidate]:
    """Resolve the oracle and key candidates by their (unique) target_hint."""
    src = ORACLE.read_text(encoding="utf-8")
    cands = JavaAdapter().extract_writer_calls(src, ORACLE)
    out: dict[str, AuthorityWriteCandidate] = {}
    for c in cands:
        out[c.target_hint] = c
    return out


# ---------------------------------------------------------------------------
# Adapter-level resolution
# ---------------------------------------------------------------------------

def test_oracle_has_all_nine_write_sites() -> None:
    src = ORACLE.read_text(encoding="utf-8")
    cands = JavaAdapter().extract_writer_calls(src, ORACLE)
    assert len(cands) == 9, "expected 9 write sites, got %d: %r" % (
        len(cands), [(c.line, c.target_hint) for c in cands]
    )


def test_literal_arg_resolves_to_literal() -> None:
    # Files.writeString("config.json", ...)
    c = _by_hint()["config.json"]
    assert c.resolved_target == "config.json"
    assert c.provenance == "string_literal"


def test_path_of_single_literal_resolves() -> None:
    # Files.write(Path.of("plain.txt"), ...) -> the literal itself.
    c = _by_hint()['Path.of("plain.txt")']
    assert c.resolved_target == "plain.txt"
    assert c.provenance == "string_literal"


def test_local_var_decl_arg_resolves() -> None:
    # String q = "data.txt"; Files.writeString(q, ...)
    c = _by_hint()["q"]
    assert c.resolved_target == "data.txt"
    assert c.provenance == "string_literal"


def test_paths_get_join_resolves() -> None:
    # Files.write(Paths.get("a", "b.json"), ...) -> "a/b.json"
    c = _by_hint()['Paths.get("a", "b.json")']
    assert c.resolved_target == "a/b.json"
    assert c.provenance == "path_constructor"


def test_local_var_join_resolves() -> None:
    # Path j = Path.of("d", "e.txt"); Files.write(j, ...) -> "d/e.txt"
    c = _by_hint()["j"]
    assert c.resolved_target == "d/e.txt"
    assert c.provenance == "path_constructor"


def test_function_parameter_arg_noted_not_guessed() -> None:
    # void writeParam(String target) { Files.write(Path.of(target), ...) }
    # Provenance reflects the parameter; the target is NOT guessed.
    c = _by_hint()["Path.of(target)"]
    assert c.resolved_target == _UNKNOWN
    assert c.provenance == "function_parameter"


def test_filewriter_literal_resolves() -> None:
    # new FileWriter("direct.log")
    c = _by_hint()["direct.log"]
    assert c.resolved_target == "direct.log"
    assert c.provenance == "string_literal"


def test_receiver_write_stays_unresolved() -> None:
    # writer.write(...) — receiver is an IO writer, not a path target.
    c = _by_hint()["writer"]
    assert c.resolved_target == _UNKNOWN
    assert c.provenance == "unknown"


def test_repo_save_stays_unresolved() -> None:
    # repo.save(entity) — receiver is a repository, not a path target.
    c = _by_hint()["repo"]
    assert c.resolved_target == _UNKNOWN
    assert c.provenance == "unknown"


# ---------------------------------------------------------------------------
# Inline / edge cases (no intermediate variable)
# ---------------------------------------------------------------------------

def test_unknown_variable_stays_unresolved() -> None:
    # A variable assigned from a non-resolvable call result must NOT yield a
    # guessed target.
    src = (
        "import java.nio.file.Files;\n"
        "import java.nio.file.Path;\n"
        "class C {\n"
        "  String compute() { return \"x\"; }\n"
        "  void f() throws Exception {\n"
        "    String p = compute();\n"
        "    Files.writeString(p, \"x\");\n"
        "  }\n"
        "}\n"
    )
    cands = JavaAdapter().extract_writer_calls(src, Path("Unk.java"))
    assert len(cands) == 1, [(c.line, c.target_hint) for c in cands]
    assert cands[0].resolved_target == _UNKNOWN
    assert cands[0].provenance == "unknown"


def test_filewriter_var_resolves() -> None:
    # String name = "f.log"; new FileWriter(name)
    src = (
        "import java.io.FileWriter;\n"
        "class C {\n"
        "  void f() throws Exception {\n"
        "    String name = \"f.log\";\n"
        "    FileWriter fw = new FileWriter(name);\n"
        "  }\n"
        "}\n"
    )
    cands = JavaAdapter().extract_writer_calls(src, Path("Fw.java"))
    assert len(cands) == 1
    assert cands[0].resolved_target == "f.log"
    assert cands[0].provenance == "string_literal"


# ---------------------------------------------------------------------------
# End-to-end: the BUILT authority map surfaces the resolved target+provenance
# ---------------------------------------------------------------------------

def _build_oracle_map_entries() -> list[dict]:
    """Build the authority map on a temp copy of the oracle; return the flat
    list of ``writers_detected`` dicts for the Writers.java writer file."""
    src = ORACLE.read_text(encoding="utf-8")
    tmp = Path(tempfile.mkdtemp(prefix="java_target_oracle_"))
    try:
        (tmp / "Writers.java").write_text(src, encoding="utf-8")
        domains = build_authority_map(tmp)
        entries: list[dict] = []
        for d in domains:
            for wd in d.writers_detected:
                entries.append(json.loads(wd))
        return entries
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def test_map_surfaces_resolved_targets() -> None:
    """The built map must show the real resolved path + provenance for every
    resolvable writer (not the receiver/unknown fallback)."""
    entries = _build_oracle_map_entries()
    by_target = {e["target"]: e for e in entries}

    # Each resolvable target surfaces with its provenance.
    expected = {
        "config.json": "string_literal",
        "plain.txt": "string_literal",
        "data.txt": "string_literal",
        "a/b.json": "path_constructor",
        "d/e.txt": "path_constructor",
        "direct.log": "string_literal",
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
    """Receiver/parameter writers must NOT surface a real resolved path: their
    provenance stays ``unknown`` in the built map."""
    entries = _build_oracle_map_entries()
    # The resolved real paths -- everything else must carry provenance="unknown".
    resolved_paths = {"config.json", "plain.txt", "data.txt", "a/b.json", "d/e.txt", "direct.log"}
    for e in entries:
        if e["target"] not in resolved_paths:
            assert e["provenance"] == "unknown", (
                "non-resolved writer at line %s surfaced provenance %r (target=%r)"
                % (e.get("line"), e["provenance"], e.get("target"))
            )
