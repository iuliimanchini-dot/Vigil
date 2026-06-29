"""Swift authority TARGET RESOLUTION — per-case assertions on the oracle corpus.

Brings the Go PoC's write-target resolution depth to the Swift adapter. The
SwiftAdapter now resolves the labeled path argument (``to:`` for ``write`` /
``atPath:`` for ``createFile``) into ``resolved_target`` + ``provenance``:

  - string-literal arg                 -> the literal, provenance="string_literal"
  - ``URL(fileURLWithPath: "x")`` /     -> joined/wrapped path, provenance=
    ``base.appendingPathComponent("x")``    "path_constructor"
  - variable arg (``let``/``var``)      -> traced to its property declaration
  - parameter arg (incl. wrapped in     -> provenance="function_parameter",
    ``URL(fileURLWithPath: param)``)        target sentinel (NOT guessed)
  - unresolvable (incl. receiver        -> __unknown_target__ / unknown (NO false
    save / handle write)                    target)

A second tier BUILDS the authority map on the oracle and asserts the resolved
target + provenance SURFACE in the built map, and that unresolvable writers stay
``__unknown_target__``.

Run: pytest tests/test_swift_target_resolution.py -v
"""
from __future__ import annotations

import json
import shutil
import tempfile
from pathlib import Path

from vigil_mapper.source_adapters.swift import SwiftAdapter
from vigil_mapper.source_adapters._ir import AuthorityWriteCandidate
from vigil_mapper.authority_builder import build_authority_map

ORACLE = Path(__file__).parent / "oracle_target_swift" / "Writers.swift"
_UNKNOWN = "__unknown_target__"


def _cands() -> list[AuthorityWriteCandidate]:
    src = ORACLE.read_text(encoding="utf-8")
    return SwiftAdapter().extract_writer_calls(src, ORACLE)


def _by_line() -> dict[int, AuthorityWriteCandidate]:
    return {c.line: c for c in _cands()}


# ---------------------------------------------------------------------------
# Adapter-level resolution
# ---------------------------------------------------------------------------

def test_oracle_write_site_count() -> None:
    cands = _cands()
    # 6 fs_write (createFile/write incl. param + handle) + 1 orm_save = 7,
    # plus the handle.write -> fs_write = 8 total.
    assert len(cands) == 8, "expected 8 write sites, got %d: %r" % (
        len(cands), [(c.line, c.write_kind, c.target_hint) for c in cands]
    )


def test_atpath_literal_resolves() -> None:
    # FileManager.default.createFile(atPath: "created.txt", ...)
    c = _by_line()[18]
    assert c.resolved_target == "created.txt"
    assert c.provenance == "string_literal"


def test_write_to_url_ctor_resolves_as_path_constructor() -> None:
    # data.write(to: URL(fileURLWithPath: "config.json"))
    c = _by_line()[23]
    assert c.resolved_target == "config.json"
    assert c.provenance == "path_constructor"


def test_var_string_resolves() -> None:
    # let p = "out.json"; createFile(atPath: p, ...)
    c = _by_line()[29]
    assert c.resolved_target == "out.json"
    assert c.provenance == "string_literal"


def test_var_url_resolves_as_path_constructor() -> None:
    # let u = URL(fileURLWithPath: "data.bin"); data.write(to: u)
    c = _by_line()[35]
    assert c.resolved_target == "data.bin"
    assert c.provenance == "path_constructor"


def test_param_atpath_noted_not_guessed() -> None:
    # func writeParam(target: String) { createFile(atPath: target, ...) }
    c = _by_line()[40]
    assert c.resolved_target == _UNKNOWN
    assert c.provenance == "function_parameter"


def test_param_wrapped_in_url_noted_not_guessed() -> None:
    # data.write(to: URL(fileURLWithPath: target)) — param wrapped in URL.
    c = _by_line()[45]
    assert c.resolved_target == _UNKNOWN
    assert c.provenance == "function_parameter"


def test_save_receiver_stays_unresolved() -> None:
    # context.save() — receiver is not a path target.
    c = _by_line()[50]
    assert c.write_kind == "orm_save"
    assert c.resolved_target == _UNKNOWN
    assert c.provenance == "unknown"


def test_handle_write_without_to_label_stays_unresolved() -> None:
    # handle.write(buffer) — no to: label, no resolvable path target.
    c = _by_line()[55]
    assert c.write_kind == "fs_write"
    assert c.resolved_target == _UNKNOWN
    assert c.provenance == "unknown"


# ---------------------------------------------------------------------------
# Inline / edge cases
# ---------------------------------------------------------------------------

def test_unknown_variable_stays_unresolved() -> None:
    # A let bound to a non-resolvable call must NOT yield a guessed target.
    src = (
        "import Foundation\n"
        "func compute() -> String { return \"x\" }\n"
        "func f() {\n"
        "    let p = compute()\n"
        "    FileManager.default.createFile(atPath: p, contents: nil)\n"
        "}\n"
    )
    cands = SwiftAdapter().extract_writer_calls(src, Path("Unk.swift"))
    fs = [c for c in cands if c.write_kind == "fs_write"]
    assert len(fs) == 1, [(c.line, c.target_hint) for c in cands]
    assert fs[0].resolved_target == _UNKNOWN
    assert fs[0].provenance == "unknown"


# ---------------------------------------------------------------------------
# End-to-end: the BUILT authority map surfaces resolved target+provenance
# ---------------------------------------------------------------------------

def _build_oracle_map_entries() -> list[dict]:
    src = ORACLE.read_text(encoding="utf-8")
    tmp = Path(tempfile.mkdtemp(prefix="swift_target_oracle_"))
    try:
        (tmp / "Writers.swift").write_text(src, encoding="utf-8")
        domains = build_authority_map(tmp)
        return [json.loads(wd) for d in domains for wd in d.writers_detected]
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def test_map_surfaces_resolved_targets() -> None:
    entries = _build_oracle_map_entries()
    by_target = {e["target"]: e for e in entries}
    expected = {
        "created.txt": "string_literal",
        "config.json": "path_constructor",
        "out.json": "string_literal",
        "data.bin": "path_constructor",
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
    resolved_paths = {"created.txt", "config.json", "out.json", "data.bin"}
    for e in entries:
        if e["target"] not in resolved_paths:
            assert e["provenance"] == "unknown", (
                "non-resolved writer at line %s surfaced provenance %r (target=%r)"
                % (e.get("line"), e["provenance"], e.get("target"))
            )
