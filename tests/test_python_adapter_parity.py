"""P2: PythonAdapter contracts/runtime/writers parity with Go/Java/TS.

Previously these adapter methods were L1 stubs returning [] — Python relied on
separate builders, leaving the adapter layer behind the tree-sitter languages.
Now they extract via ast.
"""
from __future__ import annotations

from pathlib import Path

from vigil_mapper.source_adapters import get_adapter_for_file

_P = Path("m.py")


def _ad():
    return get_adapter_for_file(_P)


def test_python_contracts_dataclass_and_pydantic():
    src = (
        "from dataclasses import dataclass\n"
        "@dataclass\nclass Trade:\n    price: float\n"
        "class Cfg(BaseModel):\n    x: int\n"
    )
    kinds = {(c.name, c.contract_kind) for c in _ad().extract_contracts(src, _P)}
    assert ("Trade", "dataclass") in kinds
    assert ("Cfg", "pydantic_model") in kinds


def test_python_contracts_typeddict_namedtuple():
    src = (
        "class Row(TypedDict):\n    a: int\n"
        "class Pt(NamedTuple):\n    x: int\n"
    )
    kinds = {(c.name, c.contract_kind) for c in _ad().extract_contracts(src, _P)}
    assert ("Row", "TypedDict") in kinds
    assert ("Pt", "NamedTuple") in kinds


def test_python_no_false_contract_on_plain_class():
    assert _ad().extract_contracts("class Plain:\n    def m(self): pass\n", _P) == []


def test_python_runtime_signals():
    src = (
        "import os\n"
        "app.run()\n"
        "x = os.getenv('PATH')\n"
        "@app.route('/x')\ndef h():\n    pass\n"
    )
    runs = {r.signal_kind for r in _ad().extract_runtime(src, _P)}
    assert "import_time_side_effects" in runs
    assert "env_var_read" in runs
    assert "decorator_registry" in runs


def test_python_writer_calls():
    src = (
        "import json\n"
        "def f(p, fh):\n"
        "    p.write_text('x')\n"
        "    json.dump({}, fh)\n"
        "    open('out.txt', 'w')\n"
    )
    kinds = {w.write_kind for w in _ad().extract_writer_calls(src, _P)}
    assert "write_text" in kinds
    assert "json_dump" in kinds
    assert "open_write" in kinds


def test_python_no_false_writer_on_read():
    # open in read mode + plain attr access is not a write
    src = "def f(p):\n    open('in.txt', 'r')\n    return p.read_text()\n"
    assert _ad().extract_writer_calls(src, _P) == []
