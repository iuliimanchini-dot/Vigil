"""Oracle tests for SwiftAdapter — verifies each map extracts the expected
Swift symbols/contracts/imports/runtime/writes from the tests/oracle_swift
fixtures.

Counts asserted here are pinned to the real extraction output captured at
implementation time (tree-sitter-swift on tree-sitter==0.25).  Swift support is
ADDITIVE; these tests do not touch any other language adapter.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from vigil_mapper.source_adapters import ADAPTERS, get_adapter_for_file
from vigil_mapper.source_adapters.swift import SwiftAdapter

ORACLE_DIR = Path(__file__).parent / "oracle_swift"
MODELS = ORACLE_DIR / "Models.swift"
MAIN = ORACLE_DIR / "main.swift"


@pytest.fixture(scope="module")
def adapter() -> SwiftAdapter:
    return SwiftAdapter()


@pytest.fixture(scope="module")
def models_src() -> str:
    return MODELS.read_text(encoding="utf-8")


@pytest.fixture(scope="module")
def main_src() -> str:
    return MAIN.read_text(encoding="utf-8")


# ---------------------------------------------------------------------------
# Registration
# ---------------------------------------------------------------------------

class TestSwiftRegistration:
    def test_swift_extension_registered(self):
        assert ".swift" in ADAPTERS
        assert isinstance(ADAPTERS[".swift"], SwiftAdapter)

    def test_get_adapter_resolves_swift(self):
        a = get_adapter_for_file(Path("foo.swift"))
        assert isinstance(a, SwiftAdapter)
        assert a.language == "swift"

    def test_capability_flags_all_true(self, adapter: SwiftAdapter):
        assert adapter.supports_structural
        assert adapter.supports_contracts
        assert adapter.supports_runtime_signals
        assert adapter.supports_authority_writes


# ---------------------------------------------------------------------------
# Imports
# ---------------------------------------------------------------------------

class TestSwiftImports:
    def test_models_imports(self, adapter: SwiftAdapter, models_src: str):
        edges = adapter.extract_imports(models_src, MODELS)
        modules = [e.to_module for e in edges]
        assert modules == ["Foundation", "UIKit", "Combine"]
        assert all(e.kind == "absolute" for e in edges)
        assert all(e.confidence == 1.0 for e in edges)

    def test_main_imports(self, adapter: SwiftAdapter, main_src: str):
        edges = adapter.extract_imports(main_src, MAIN)
        assert [e.to_module for e in edges] == ["Foundation"]


# ---------------------------------------------------------------------------
# Symbols
# ---------------------------------------------------------------------------

class TestSwiftSymbols:
    def test_models_symbol_count(self, adapter: SwiftAdapter, models_src: str):
        syms = adapter.extract_symbols(models_src, MODELS)
        assert len(syms) == 6

    def test_models_symbol_kinds_and_names(self, adapter: SwiftAdapter, models_src: str):
        syms = {s.name: s for s in adapter.extract_symbols(models_src, MODELS)}
        assert syms["Point"].kind == "struct"
        assert syms["Drawable"].kind == "protocol"
        assert syms["Direction"].kind == "enum"
        assert syms["Vehicle"].kind == "class"
        assert syms["helperFunction"].kind == "function"
        assert syms["secretFunction"].kind == "function"

    def test_models_visibility(self, adapter: SwiftAdapter, models_src: str):
        syms = {s.name: s for s in adapter.extract_symbols(models_src, MODELS)}
        assert syms["Point"].visibility == "public"
        assert syms["Vehicle"].visibility == "public"
        # internal (no modifier) -> "module"
        assert syms["Drawable"].visibility == "module"
        assert syms["helperFunction"].visibility == "module"
        # private / fileprivate -> "private"
        assert syms["secretFunction"].visibility == "private"

    def test_main_symbols(self, adapter: SwiftAdapter, main_src: str):
        syms = adapter.extract_symbols(main_src, MAIN)
        names = {s.name for s in syms}
        assert "AppEntry" in names
        assert "Document" in names
        assert "PersistenceStore" in names
        assert len(syms) == 5


# ---------------------------------------------------------------------------
# Contracts
# ---------------------------------------------------------------------------

class TestSwiftContracts:
    def test_models_contracts(self, adapter: SwiftAdapter, models_src: str):
        cons = {c.name: c.contract_kind for c in adapter.extract_contracts(models_src, MODELS)}
        assert cons == {
            "Point": "struct",
            "Drawable": "protocol",
            "Direction": "enum",
            "Vehicle": "class",
        }

    def test_main_contracts(self, adapter: SwiftAdapter, main_src: str):
        cons = adapter.extract_contracts(main_src, MAIN)
        kinds = {c.name: c.contract_kind for c in cons}
        assert kinds["AppEntry"] == "struct"
        assert kinds["Document"] == "struct"
        assert kinds["PersistenceStore"] == "struct"
        assert len(cons) == 3

    def test_test_file_excluded(self, adapter: SwiftAdapter):
        # A file named *Tests.swift must yield no contracts (test-file skip).
        cons = adapter.extract_contracts("struct Foo {}", Path("FooTests.swift"))
        assert cons == []


# ---------------------------------------------------------------------------
# Runtime
# ---------------------------------------------------------------------------

class TestSwiftRuntime:
    def test_main_runtime_signals(self, adapter: SwiftAdapter, main_src: str):
        runs = adapter.extract_runtime(main_src, MAIN)
        kinds = sorted(r.kind for r in runs)
        # @main entrypoint + Task + DispatchQueue.async
        assert "entrypoint" in kinds
        assert kinds.count("background_job") == 2
        assert len(runs) == 3

    def test_entrypoint_payload(self, adapter: SwiftAdapter, main_src: str):
        runs = adapter.extract_runtime(main_src, MAIN)
        entry = [r for r in runs if r.kind == "entrypoint"]
        assert len(entry) == 1
        assert entry[0].payload["call"] == "AppEntry"

    def test_models_has_no_runtime(self, adapter: SwiftAdapter, models_src: str):
        # Pure model file: no @main, no concurrency.
        assert adapter.extract_runtime(models_src, MODELS) == []


# ---------------------------------------------------------------------------
# Authority writes
# ---------------------------------------------------------------------------

class TestSwiftWrites:
    def test_main_writes(self, adapter: SwiftAdapter, main_src: str):
        wrs = adapter.extract_writer_calls(main_src, MAIN)
        assert len(wrs) == 4
        kinds = sorted(w.write_kind for w in wrs)
        assert kinds == ["fs_write", "fs_write", "orm_save", "orm_save"]

    def test_write_to_url_detected(self, adapter: SwiftAdapter, main_src: str):
        wrs = adapter.extract_writer_calls(main_src, MAIN)
        # data.write(to: url) -> fs_write with receiver hint "data"
        fs = [w for w in wrs if w.write_kind == "fs_write" and w.target_hint == "data"]
        assert len(fs) == 1

    def test_save_detected(self, adapter: SwiftAdapter, main_src: str):
        wrs = adapter.extract_writer_calls(main_src, MAIN)
        saves = [w for w in wrs if w.write_kind == "orm_save"]
        assert {w.target_hint for w in saves} == {"document", "store"}

    def test_models_has_no_writes(self, adapter: SwiftAdapter, models_src: str):
        assert adapter.extract_writer_calls(models_src, MODELS) == []


# ---------------------------------------------------------------------------
# Additive-default sanity: non-Python adapters carry the IR defaults.
# ---------------------------------------------------------------------------

class TestSwiftIRDefaults:
    def test_contract_shape_defaults_empty(self, adapter: SwiftAdapter, models_src: str):
        for c in adapter.extract_contracts(models_src, MODELS):
            assert c.shape == {}
            assert c.serializer_shapes == {}

    def test_write_resolver_fields(self, adapter: SwiftAdapter, main_src: str):
        # Swift now resolves the labeled path argument (to:/atPath:) into
        # resolved_target + provenance (see test_swift_target_resolution.py).
        # ``operation`` stays "" (Python-only field). The two receiver-only
        # saves keep the unknown sentinel; the two fs writes resolve.
        by_line = {w.line: w for w in adapter.extract_writer_calls(main_src, MAIN)}
        for w in by_line.values():
            assert w.operation == ""

        # document.save() / store.save() — receivers, no resolvable path.
        saves = [w for w in by_line.values() if w.write_kind == "orm_save"]
        assert len(saves) == 2
        for w in saves:
            assert w.resolved_target == "__unknown_target__"
            assert w.provenance == "unknown"

        # data.write(to: url) where let url = URL(fileURLWithPath: "/tmp/out.dat")
        # -> traced through the variable to the URL path-constructor.
        assert by_line[11].resolved_target == "/tmp/out.dat"
        assert by_line[11].provenance == "path_constructor"

        # FileManager.default.createFile(atPath: "/tmp/file.txt", ...) -> literal.
        assert by_line[13].resolved_target == "/tmp/file.txt"
        assert by_line[13].provenance == "string_literal"
