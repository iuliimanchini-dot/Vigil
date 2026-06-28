"""TDD: authority map auto-surfaces discovered writers WITHOUT a seed file.

Background
----------
``build_authority_map`` auto-discovers write sites via AST (Python) and adapter
dispatch (Go/Java/JS/TS). Historically these writers were only turned into
``AuthorityDomain`` entries inside the per-seed-domain loop, gated on a domain's
``target_file_patterns``. With NO seed file, ``seed_list`` was empty, that loop
never ran, and the only seed-free path (``_auto_discover_domains``) surfaced ONLY
*shared* targets (2+ writers from different module prefixes). Result: a normal
project with no seed produced an EMPTY authority map -- a single file that writes
``config.json`` yielded ``authority == 0`` and was useless out-of-the-box.

The fix: when ``_load_seed`` returns ``None`` (no seed), surface EVERY discovered
write candidate as an inferred ``AuthorityDomain`` (status="inferred",
source="static_scan"), each naming the writer file + its write target(s)/kind.
With a seed present, behaviour is unchanged (seed domains + target_file_patterns,
plus the existing shared-write auto-discovery).

Honest scope note (verified against the discovery logic, not the docstrings):
the Python AST pass detects ``.write_text`` / ``.write_bytes`` / ``.save`` /
``os.replace``, plus -- added alongside this change so the surfaced evidence is
real -- ``open(..., "w"/"a"/"x")`` and ``json.dump(...)``. A pure read
(``open(p)`` / ``open(p, "r")`` / ``.read_text()``) is NOT a write and must NOT
produce an authority entry.

Run:  pytest tests/test_authority_autosurface.py -v
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from vigil_mapper.authority_builder import build_authority_map
from vigil_mapper.map_storage import seeds_dir


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _writers_detected(domain) -> list[dict]:
    """Decode the JSON-serialised writers_detected entries of one domain."""
    return [json.loads(w) for w in domain.writers_detected]


def _all_writers_detected(domains) -> list[dict]:
    out: list[dict] = []
    for d in domains:
        out.extend(_writers_detected(d))
    return out


def _write_seed(project_dir: Path, domains: list[dict]) -> None:
    sd = seeds_dir(project_dir)
    sd.mkdir(parents=True, exist_ok=True)
    (sd / "authority_domains.json").write_text(
        json.dumps({"schema_version": "1.0", "domains": domains}),
        encoding="utf-8",
    )


# ---------------------------------------------------------------------------
# 1. No seed -> Python writers auto-surface (write_text + open('w') + json.dump)
# ---------------------------------------------------------------------------

def test_no_seed_python_writer_autosurfaces(tmp_path: Path) -> None:
    """A Python file with write_text / open('w') / json.dump and NO seed must
    produce >= 1 authority entry naming the writer file + a target/kind."""
    (tmp_path / "writer.py").write_text(
        "import json\n"
        "from pathlib import Path\n"
        "def save(cfg):\n"
        "    Path('out/config.json').write_text('x')\n"
        "    with open('out/data.txt', 'w') as f:\n"
        "        f.write('y')\n"
        "    with open('out/meta.json', 'w') as f:\n"
        "        json.dump(cfg, f)\n",
        encoding="utf-8",
    )

    domains = build_authority_map(tmp_path)

    assert len(domains) >= 1, "expected >=1 authority entry without a seed"

    wd = _all_writers_detected(domains)
    # Writer file is named.
    assert any(w.get("location") == "writer.py" for w in wd), (
        "writer file 'writer.py' not named in any entry: %r" % wd
    )
    # Targets / kinds are actionable: the three known write targets surface.
    operations = {w.get("operation") for w in wd}
    targets = {w.get("target") for w in wd}
    assert "write_text" in operations, "write_text not surfaced: %r" % operations
    # open('w') + json.dump must be discovered too (extended Python discovery).
    assert {"open_write", "json_dump"} & operations, (
        "open('w') / json.dump not surfaced: %r" % operations
    )
    assert any(t and "config.json" in t for t in targets), (
        "write target 'config.json' not surfaced: %r" % targets
    )


def test_no_seed_entries_are_inferred_static_scan(tmp_path: Path) -> None:
    """Auto-surfaced (no-seed) entries are status=inferred, source names static_scan."""
    (tmp_path / "writer.py").write_text(
        "from pathlib import Path\n"
        "def save():\n"
        "    Path('state.json').write_text('x')\n",
        encoding="utf-8",
    )

    domains = build_authority_map(tmp_path)
    assert domains, "expected an inferred entry"
    for d in domains:
        assert d.status == "inferred", "no-seed entry must be inferred, got %r" % d.status
        assert "static_scan" in d.source, "source should name static_scan, got %r" % d.source
        assert 0.0 < d.confidence < 1.0, "confidence should be modest, got %r" % d.confidence


# ---------------------------------------------------------------------------
# 2. Precision guard: a read-only file produces NO authority entry (no FP)
# ---------------------------------------------------------------------------

def test_no_seed_read_only_file_produces_zero(tmp_path: Path) -> None:
    """open(p) / open(p,'r') / .read_text() are reads -> authority == 0."""
    (tmp_path / "reader.py").write_text(
        "import json\n"
        "from pathlib import Path\n"
        "def load():\n"
        "    txt = Path('in.txt').read_text()\n"
        "    with open('in2.txt') as f:\n"
        "        a = f.read()\n"
        "    with open('in3.json', 'r') as f:\n"
        "        b = json.load(f)\n"
        "    return txt, a, b\n",
        encoding="utf-8",
    )

    domains = build_authority_map(tmp_path)
    assert len(domains) == 0, (
        "read-only file must NOT produce authority entries, got %d: %r"
        % (len(domains), [d.authority_domain for d in domains])
    )


# ---------------------------------------------------------------------------
# 3. Seed present -> behaviour unchanged (seeded domains still surface)
# ---------------------------------------------------------------------------

def test_seed_present_behaviour_unchanged(tmp_path: Path) -> None:
    """With a seed, structured per-domain surfacing via target_file_patterns
    is preserved (observed status, allowed_writers honoured)."""
    (tmp_path / "cfg_writer.py").write_text(
        "from pathlib import Path\n"
        "def save():\n"
        "    Path('settings/config.json').write_text('x')\n",
        encoding="utf-8",
    )
    _write_seed(tmp_path, [
        {
            "authority_domain": "config",
            "canonical_owner": "cfg_writer.py",
            "allowed_writers": ["cfg_writer.py"],
            "target_file_patterns": ["settings/*.json"],
        }
    ])

    domains = build_authority_map(tmp_path)

    seeded = [d for d in domains if d.authority_domain == "config"]
    assert len(seeded) == 1, "seeded domain 'config' missing: %r" % [d.authority_domain for d in domains]
    d = seeded[0]
    assert d.status == "observed", "seeded domain must stay observed, got %r" % d.status
    wd = _writers_detected(d)
    assert any(w["location"] == "cfg_writer.py" and w["kind"] == "canonical_write" for w in wd), (
        "seeded writer not attributed as canonical_write: %r" % wd
    )
    # No-seed auto-surface domain must NOT also appear (no double-surfacing).
    auto = [d for d in domains if d.authority_domain.startswith("auto_discovered")]
    assert not auto, "auto_discovered domain must not appear when a seed exists: %r" % auto


def test_seed_present_does_not_double_surface(tmp_path: Path) -> None:
    """The same writer must not be surfaced both by a seed domain and by the
    no-seed auto branch."""
    (tmp_path / "w.py").write_text(
        "from pathlib import Path\n"
        "def save():\n"
        "    Path('data/state.json').write_text('x')\n",
        encoding="utf-8",
    )
    _write_seed(tmp_path, [
        {
            "authority_domain": "state",
            "allowed_writers": ["w.py"],
            "target_file_patterns": ["data/*.json"],
        }
    ])
    domains = build_authority_map(tmp_path)
    locations = [w["location"] for w in _all_writers_detected(domains)]
    assert locations.count("w.py") == 1, (
        "writer w.py surfaced more than once with a seed: %r" % locations
    )


# ---------------------------------------------------------------------------
# 4. Multi-language: a Go writer surfaces without a seed
# ---------------------------------------------------------------------------

def test_no_seed_go_writer_autosurfaces(tmp_path: Path) -> None:
    """A Go file with os.WriteFile and NO seed must auto-surface (adapter path)."""
    (tmp_path / "writer.go").write_text(
        "package main\n"
        "import \"os\"\n"
        "func Save() {\n"
        "    os.WriteFile(\"out/config.json\", []byte(\"x\"), 0644)\n"
        "}\n",
        encoding="utf-8",
    )

    domains = build_authority_map(tmp_path)
    wd = _all_writers_detected(domains)
    assert any(w.get("location") == "writer.go" for w in wd), (
        "Go writer 'writer.go' not surfaced without a seed: %r"
        % [d.authority_domain for d in domains]
    )
