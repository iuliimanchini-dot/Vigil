"""Go authority TARGET RESOLUTION — per-case assertions on the oracle corpus.

A PoC that brings Python-level write-target resolution depth (see
``vigil_mapper/_authority_ast.py``) to the Go adapter. The GoAdapter now
resolves the first-argument file target of ``os.WriteFile`` / ``os.Create`` /
``os.OpenFile`` (and DB ``Exec``) into ``resolved_target`` + ``provenance``:

  - string-literal arg            -> the literal, provenance="string_literal"
  - variable arg (`:=` / `var`)   -> traced to its assignment in scope
  - filepath.Join(...) arg/assign -> joined path, provenance="path_constructor"
  - function-parameter arg        -> provenance="function_parameter", target sentinel
  - unresolvable (incl. receiver  -> __unknown_target__ / unknown (NO false target)
    Write/WriteString)

The fixture ``tests/oracle_target_go/writers.go`` drives every case. These
tests pin the resolution; the receiver/parameter cases pin the NO-regression /
NO-false-target guarantee.

Run: pytest tests/test_go_target_resolution.py -v
"""
from __future__ import annotations

from pathlib import Path

from vigil_mapper.source_adapters.go import GoAdapter
from vigil_mapper.source_adapters._ir import AuthorityWriteCandidate

ORACLE = Path(__file__).parent / "oracle_target_go" / "writers.go"
_UNKNOWN = "__unknown_target__"


def _by_hint() -> dict[str, AuthorityWriteCandidate]:
    """Resolve the oracle and key candidates by their (unique) target_hint."""
    src = ORACLE.read_text(encoding="utf-8")
    cands = GoAdapter().extract_writer_calls(src, ORACLE)
    out: dict[str, AuthorityWriteCandidate] = {}
    for c in cands:
        out[c.target_hint] = c
    return out


def test_oracle_has_all_six_write_sites() -> None:
    src = ORACLE.read_text(encoding="utf-8")
    cands = GoAdapter().extract_writer_calls(src, ORACLE)
    assert len(cands) == 6, "expected 6 write sites, got %d: %r" % (
        len(cands), [(c.line, c.target_hint) for c in cands]
    )


def test_literal_arg_resolves_to_literal() -> None:
    c = _by_hint()["config.json"]
    assert c.resolved_target == "config.json"
    assert c.provenance == "string_literal"


def test_short_var_decl_arg_resolves() -> None:
    # p := "out.json"; os.WriteFile(p, ...)
    c = _by_hint()["p"]
    assert c.resolved_target == "out.json"
    assert c.provenance == "string_literal"


def test_var_decl_arg_resolves() -> None:
    # var q = "data.txt"; os.WriteFile(q, ...)
    c = _by_hint()["q"]
    assert c.resolved_target == "data.txt"
    assert c.provenance == "string_literal"


def test_filepath_join_arg_resolves() -> None:
    # j := filepath.Join("a", "b"); os.WriteFile(j, ...)
    c = _by_hint()["j"]
    assert c.resolved_target == "a/b"
    assert c.provenance == "path_constructor"


def test_function_parameter_arg_noted_not_guessed() -> None:
    # func WriteParam(target string) { os.WriteFile(target, ...) }
    # Provenance reflects the parameter; target is NOT guessed.
    c = _by_hint()["target"]
    assert c.resolved_target == _UNKNOWN
    assert c.provenance == "function_parameter"


def test_receiver_write_stays_unresolved() -> None:
    # w.Write(...) — receiver is an IO writer, not a path target.
    c = _by_hint()["w"]
    assert c.resolved_target == _UNKNOWN
    assert c.provenance == "unknown"


def test_inline_filepath_join_argument_resolves() -> None:
    # filepath.Join passed DIRECTLY as the WriteFile arg (no intermediate var).
    src = (
        "package main\n"
        'import (\n\t"os"\n\t"path/filepath"\n)\n'
        "func F() {\n"
        '\tos.WriteFile(filepath.Join("dir", "f.json"), nil, 0644)\n'
        "}\n"
    )
    cands = GoAdapter().extract_writer_calls(src, Path("inline.go"))
    assert len(cands) == 1
    assert cands[0].resolved_target == "dir/f.json"
    assert cands[0].provenance == "path_constructor"


def test_unknown_variable_stays_unresolved() -> None:
    # A variable with no resolvable assignment (assigned from a function call
    # result that is not filepath.Join) must NOT yield a guessed target.
    src = (
        "package main\n"
        'import "os"\n'
        "func compute() string { return \"x\" }\n"
        "func F() {\n"
        "\tp := compute()\n"
        "\tos.WriteFile(p, nil, 0644)\n"
        "}\n"
    )
    cands = GoAdapter().extract_writer_calls(src, Path("unk.go"))
    assert len(cands) == 1, [(c.line, c.target_hint) for c in cands]
    assert cands[0].resolved_target == _UNKNOWN
    assert cands[0].provenance == "unknown"


def test_os_create_resolves_literal() -> None:
    src = (
        "package main\n"
        'import "os"\n'
        "func F() {\n"
        '\tos.Create("created.txt")\n'
        "}\n"
    )
    cands = GoAdapter().extract_writer_calls(src, Path("create.go"))
    assert len(cands) == 1
    assert cands[0].resolved_target == "created.txt"
    assert cands[0].provenance == "string_literal"
