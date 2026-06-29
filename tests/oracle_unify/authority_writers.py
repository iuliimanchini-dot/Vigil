"""Authority resolver oracle -- exercises every write-resolution code path.

Each function pins a specific branch of the legacy Python authority resolver
(_collect_assignments / _resolve_call_target / _resolve_func_arg_target /
_detect_func_write / _scan_write_calls). The vigil source tree does not exercise
these (its writes resolve to __unknown_target__), so an empty baseline-diff on
vigil alone would be false confidence. This file is the real gate.

The constructs below were chosen to ACTUALLY RESOLVE under the legacy resolver
(verified), so the relocated code paths produce non-trivial targets/provenance
(path_constructor, string_literal, os.replace, json_dump, open_write, save,
write_text, write_bytes) rather than silently collapsing to unknown.
"""
from __future__ import annotations

import json
import os
from pathlib import Path


# --- 1. path_constructor provenance: var = Path("literal"); var.write_text(...)
def write_resolved_target(payload):
    p = Path("out.json")
    p.write_text(payload)


# --- 2. string_literal provenance: var = "literal"; var.write_text(...)
#        (resolver tracks the literal statically; provenance=string_literal)
def write_string_literal_target(payload):
    target = "report.txt"
    target.write_text(payload)


# --- 3. function_parameter provenance: write through a bare parameter
#        (resolves to "" -> unknown target; pins the param-tracking branch)
def write_param_target(dest, payload):
    dest.write_bytes(payload)


# --- 4. write_bytes with a path_constructor receiver
def write_bytes_resolved(payload):
    blob = Path("aliased.bin")
    blob.write_bytes(payload)


# --- 5. atomic write trio: mkstemp + fdopen.write + os.replace(tmp, final)
#        final/tmp are path_constructor vars so os.replace dst RESOLVES.
def write_atomic(payload):
    final = Path("state.db")
    tmp = Path("state.db.tmp")
    fd = os.open(str(tmp), os.O_WRONLY)
    os.fdopen(fd, "w").write(payload)
    os.replace(tmp, final)


# --- 6. literal-path open(..., "w") write
def write_open_literal(payload):
    with open("data/output.log", "w") as fh:
        fh.write(payload)


# --- 7. json.dump(obj, fp) write (fp is a handle var)
def write_json_dump(obj):
    fh = open("dump.json", "w")
    json.dump(obj, fh)


# --- 8. .save() method write
def write_save(model):
    model.save()


# --- 9. with_suffix alias: base.with_suffix(".bak").write_text(...)
#        pins the alias-chain (with_suffix) resolution branch.
def write_with_suffix(payload):
    base = Path("archive.dat")
    base.with_suffix(".bak").write_text(payload)


# --- 10. self.attr assignment + write (self.path = Path(...); self.path.write_text)
class Store:
    def __init__(self, root):
        self.path = Path("store/index.json")

    def persist(self, data):
        self.path.write_text(data)


# --- 11. read-only: MUST NOT surface as a write (precision guard)
def read_only(src):
    txt = Path("input.txt").read_text()
    with open("config.ini") as fh:
        cfg = fh.read()
    with open("readme.md", "r") as fh2:
        more = fh2.read()
    data = json.load(open("settings.json"))
    return txt, cfg, more, data
