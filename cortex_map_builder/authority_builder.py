"""Authority map builder -- reads seed file and auto-discovers writers via AST.

Generic tool: operates on any target project_dir.
Seed file: <project_dir>/.cortex/map_seeds/authority_domains.json

WITH a seed: each domain seed entry may carry ``target_file_patterns`` (glob
patterns). A writer is attributed to a domain only when at least one resolved
write-target path matches a pattern. Writers with unresolvable targets are
dropped from all domains. Empty/missing patterns -> no per-domain discovery.

WITHOUT a seed (out-of-box): every discovered write site is auto-surfaced as an
inferred per-writer ``AuthorityDomain`` (status="inferred", source="static_scan")
so the map is useful immediately. Each entry names the writer file plus its
write targets and operation kinds. Pure reads never produce an entry.

Write detection (Python AST): ``.write_text`` / ``.write_bytes`` / ``.save`` /
``os.replace`` (method writes) and ``open(..., "w"/"a"/"x"/"+")`` / ``json.dump``
(function writes). Reads -- ``open(p)`` / ``open(p, "r")`` / ``.read_text()`` /
``json.load`` / ``json.dumps`` -- are NOT writes. Non-Python writers (Go/Java/
JS/TS) are detected via adapter ``extract_writer_calls`` and surface the same way.
"""
from __future__ import annotations

import ast
import fnmatch
import hashlib
import json
import logging
import re
from pathlib import Path
from typing import Any, NamedTuple, Sequence

from .map_common import classify_file_role, iter_py_files, iter_source_files, make_metadata
from .source_adapters import get_adapter_for_file
from .source_adapters._ir import AuthorityWriteCandidate
from .map_errors import MapIntegrityError
from .map_models import AuthorityDomain
from .map_storage import seeds_dir

__all__ = ["build_authority_map"]

_log = logging.getLogger(__name__)

_SEED_FILENAME = "authority_domains.json"
_WRITE_METHOD_NAMES = frozenset({"write_text", "write_bytes", "save"})
_UNKNOWN_TARGET = "__unknown_target__"


def _open_mode_is_write(mode: str) -> bool:
    """True iff an open() mode string mutates the target.

    Write modes contain 'w', 'a', 'x' (create/truncate/append) or '+'
    (read-update / write-update — both can write). A bare ``open(p)`` defaults
    to ``"r"``; ``"r"`` / ``"rb"`` / ``"rt"`` are pure READS → not writes.
    The ``b``/``t`` flags are binary/text modifiers and do not imply a write.
    """
    return any(ch in mode for ch in ("w", "a", "x", "+"))

# Provenance type constants for path tracking
_PROVENANCE_PATH_CONSTRUCTOR = "path_constructor"  # Path(...), PurePath(...), etc.
_PROVENANCE_STRING_LITERAL = "string_literal"      # "literal_path"
_PROVENANCE_FUNCTION_PARAM = "function_parameter"  # def foo(target):
_PROVENANCE_UNKNOWN = "unknown"


# ---------------------------------------------------------------------------
# Write call tracking
# ---------------------------------------------------------------------------

class WriteCall(NamedTuple):
    """Represents a single write call with provenance and location info."""
    target: str       # resolved target path or _UNKNOWN_TARGET
    operation: str    # "write_text" | "write_bytes" | "os.replace" | "save" | "unknown"
    line: int | None  # source line number of the call (or None if unavailable)
    provenance: str   # "path_constructor" | "string_literal" | "function_parameter" | "unknown"


# ---------------------------------------------------------------------------
# Glob matching — ** support (PurePath.match added ** only in Python 3.12)
# ---------------------------------------------------------------------------

def _match_glob_path(path: str, pattern: str) -> bool:
    """Match forward-slash path against glob pattern supporting **."""
    path = path.replace("\\", "/")
    pattern = pattern.replace("\\", "/")
    if "**" not in pattern:
        return fnmatch.fnmatch(path, pattern)
    return _match_double_star(path, pattern)


def _match_double_star(path: str, pattern: str) -> bool:
    """Recursive ** expansion: ** matches zero or more path segments."""
    if "**" not in pattern:
        return fnmatch.fnmatch(path, pattern)
    idx = pattern.find("**")
    prefix = pattern[:idx].rstrip("/")
    rest = pattern[idx + 2:].lstrip("/")
    path_parts = path.split("/")
    if prefix:
        n = len(prefix.split("/"))
        if len(path_parts) < n:
            return False
        if not fnmatch.fnmatch("/".join(path_parts[:n]), prefix):
            return False
        path_parts = path_parts[n:]
    if not rest:
        return True
    for i in range(len(path_parts) + 1):
        if _match_double_star("/".join(path_parts[i:]), rest):
            return True
    return False


# ---------------------------------------------------------------------------
# AST helpers
# ---------------------------------------------------------------------------

def _extract_string_value(node: ast.expr | None) -> str | None:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    return None


def _normalize_target_path(target: str) -> str:
    """Strip .tmp/.bak/.backup/.temp suffixes → canonical base target."""
    name = Path(target).name
    for suffix in (".tmp", ".bak", ".backup", ".temp"):
        if name.endswith(suffix):
            return str(Path(target).with_name(name[: -len(suffix)]))
    # Also strip uuid-based suffixes: state.abc123.tmp → state
    # Pattern: name.<hex/uuid>.<ext_or_tmp>
    stripped = re.sub(r'\.[0-9a-f\-]{8,}\.tmp$', '', target)
    if stripped != target:
        return stripped
    return target


def _is_plausible_path(s: str) -> bool:
    """True iff s looks like a file path (not a multi-line string or code snippet).

    Bare filenames (Makefile, Dockerfile, LICENSE, Procfile, README) are valid.
    """
    if not s or len(s) > 512:
        return False
    if '\n' in s or '\r' in s:
        return False
    # Bare filenames that are valid write targets
    if Path(s).name in {"Makefile", "Dockerfile", "Procfile", "LICENSE", "README"}:
        return True
    # Otherwise must contain at least one path-like character
    if '/' not in s and '\\' not in s and '.' not in s:
        return False
    return True


def _module_prefix(rel_posix: str) -> str:
    """First path component = top-level module/package."""
    return rel_posix.split("/")[0]


def _safe_domain_name(target: str) -> str:
    """Convert target path to safe domain name (parent_stem_hash, max 40 chars).

    Includes parent directory to avoid collisions: api/config.json vs settings/config.yaml.
    Uses stable blake2s hash (deterministic across processes) for collision avoidance.
    """
    p = Path(target)
    parts = []
    # Add parent directory name if present
    if p.parent.name and p.parent.name not in (".", ""):
        parts.append(p.parent.name)
    # Add filename stem
    parts.append(p.stem)
    # Include first 4 chars of stable blake2s hash for collision avoidance
    target_hash = hashlib.blake2s(
        target.encode("utf-8"),
        digest_size=2,
    ).hexdigest()
    parts.append(target_hash)
    raw = "_".join(parts)
    # Sanitize and truncate
    return re.sub(r'[^a-zA-Z0-9_]', '_', raw)[:40]


def _seed_covers_target(target: str, seed_domains: list[dict]) -> bool:
    """True if any seed domain's target_file_patterns matches this target."""
    for domain_def in seed_domains:
        for pattern in domain_def.get("target_file_patterns", []):
            if _match_glob_path(target, pattern):
                return True
    return False


def _resolve_call_target(
    call_node: ast.Call,
    assignments: dict[str, str],
    aliases: dict[str, str] | None = None,
) -> str | None:
    """Resolve the file-path target of a write call via AST analysis."""
    if aliases is None:
        aliases = {}
    func = call_node.func
    if not isinstance(func, ast.Attribute):
        return None
    receiver = func.value
    # Path("literal").write_text(...) or path.with_suffix(...).write_text(...)
    if isinstance(receiver, ast.Call) and isinstance(receiver.func, (ast.Name, ast.Attribute)):
        fname = receiver.func.id if isinstance(receiver.func, ast.Name) else receiver.func.attr
        if fname in ("Path", "PurePath", "PosixPath", "WindowsPath") and receiver.args:
            return _extract_string_value(receiver.args[0])
        # .with_suffix(...).write_text() or .with_name(...).write_text()
        if fname in ("with_suffix", "with_name", "with_stem"):
            inner = receiver.func.value if isinstance(receiver.func, ast.Attribute) else None
            if isinstance(inner, ast.Name):
                name = inner.id
                resolved = name
                visited: set[str] = {resolved}
                for _ in range(8):
                    nxt = aliases.get(resolved)
                    if nxt is None or nxt in visited:
                        break
                    visited.add(nxt)
                    resolved = nxt
                return assignments.get(resolved)
    # name.write_text(...) with alias following
    if isinstance(receiver, ast.Name):
        name = receiver.id
        resolved = name
        visited: set[str] = {resolved}
        for _ in range(8):
            nxt = aliases.get(resolved)
            if nxt is None or nxt in visited:
                break
            visited.add(nxt)
            resolved = nxt
        return assignments.get(resolved)
    # self.attr.write_text(...)
    if isinstance(receiver, ast.Attribute) and isinstance(receiver.value, ast.Name):
        return assignments.get("%s.%s" % (receiver.value.id, receiver.attr))
    return None


def _resolve_func_arg_target(
    arg_node: ast.expr | None,
    assignments: dict[str, str],
    aliases: dict[str, str],
) -> str | None:
    """Resolve a path-like target from a positional call argument.

    Handles a string literal, ``Path("literal")``, or a variable name that an
    assignment resolved to a string/Path (with alias chaining). Returns None
    when the target cannot be resolved.
    """
    if arg_node is None:
        return None
    # "literal"
    lit = _extract_string_value(arg_node)
    if lit is not None:
        return lit
    # Path("literal") / PurePath("literal")
    if isinstance(arg_node, ast.Call) and isinstance(arg_node.func, (ast.Name, ast.Attribute)):
        fname = arg_node.func.id if isinstance(arg_node.func, ast.Name) else arg_node.func.attr
        if fname in ("Path", "PurePath", "PosixPath", "WindowsPath") and arg_node.args:
            return _extract_string_value(arg_node.args[0])
    # variable name -> resolve through aliases + assignments
    if isinstance(arg_node, ast.Name):
        resolved = arg_node.id
        visited: set[str] = {resolved}
        for _ in range(8):
            nxt = aliases.get(resolved)
            if nxt is None or nxt in visited:
                break
            visited.add(nxt)
            resolved = nxt
        return assignments.get(resolved)
    return None


def _detect_func_write(
    node: ast.Call,
    assignments: dict[str, str],
    aliases: dict[str, str],
) -> tuple[str, str | None] | None:
    """Detect ``open(path, "w")`` and ``json.dump(obj, fp)`` function-call writes.

    These are plain function calls (``ast.Name`` / module ``ast.Attribute``),
    NOT receiver-method calls, so the standard ``_WRITE_METHOD_NAMES`` scan
    misses them. Returns ``(operation, target_or_None)`` for a write, else None.

    - ``open(path, mode)`` is a write only when ``mode`` mutates the target
      (see :func:`_open_mode_is_write`). A bare ``open(p)`` / ``open(p, "r")``
      is a READ → returns None (precision guard).
    - ``json.dump(obj, fp)`` writes to ``fp``; ``json.dumps`` (returns a string)
      and ``json.load`` / ``json.loads`` (reads) are NOT writes.
    """
    func = node.func

    # open(...) — builtin name (assume builtin; shadowing is rare and out of scope)
    if isinstance(func, ast.Name) and func.id == "open":
        mode = "r"  # open() default
        if len(node.args) >= 2:
            lit = _extract_string_value(node.args[1])
            if lit is not None:
                mode = lit
        else:
            for kw in node.keywords:
                if kw.arg == "mode":
                    lit = _extract_string_value(kw.value)
                    if lit is not None:
                        mode = lit
        if not _open_mode_is_write(mode):
            return None
        target = _resolve_func_arg_target(
            node.args[0] if node.args else None, assignments, aliases
        )
        return ("open_write", target)

    # json.dump(obj, fp, ...) — module attribute call. Target = fp (2nd arg),
    # best-effort (usually a file handle variable). dumps/load/loads excluded.
    if isinstance(func, ast.Attribute) and func.attr == "dump":
        receiver = func.value
        if isinstance(receiver, ast.Name) and receiver.id == "json":
            fp_node = node.args[1] if len(node.args) >= 2 else None
            target = _resolve_func_arg_target(fp_node, assignments, aliases)
            return ("json_dump", target)

    return None


def _collect_assignments(tree: ast.AST) -> tuple[dict[str, tuple[str, str]], dict[str, str]]:
    """Return (assignments_typed, aliases).

    assignments_typed: name -> (string-path, provenance_type)
    - Provenance types: path_constructor, string_literal, function_parameter, unknown
    aliases: name -> other_name (for .with_suffix/.with_name/.with_stem chains)

    First pass: extract function parameters (lower precedence)
    Second pass: extract assignments (higher precedence, overwrites params)
    """
    assignments_typed: dict[str, tuple[str, str]] = {}
    aliases: dict[str, str] = {}

    # PASS 1: Extract function parameters
    for node in ast.walk(tree):
        if not isinstance(node, ast.FunctionDef):
            continue
        for arg in node.args.args:
            # Function parameter: store with empty path, provenance_type = function_parameter
            assignments_typed[arg.arg] = ("", _PROVENANCE_FUNCTION_PARAM)

    # PASS 2: Extract assignments (overwrites function params if same name)
    for node in ast.walk(tree):
        if not isinstance(node, ast.Assign) or len(node.targets) != 1:
            continue
        target = node.targets[0]
        if isinstance(target, ast.Name):
            key = target.id
        elif isinstance(target, ast.Attribute) and isinstance(target.value, ast.Name):
            key = "%s.%s" % (target.value.id, target.attr)
        else:
            continue
        value = node.value
        if isinstance(value, ast.Constant) and isinstance(value.value, str):
            # String literal assignment
            assignments_typed[key] = (value.value, _PROVENANCE_STRING_LITERAL)
        elif isinstance(value, ast.Call) and isinstance(value.func, (ast.Name, ast.Attribute)):
            fname = value.func.id if isinstance(value.func, ast.Name) else value.func.attr
            if fname in ("Path", "PurePath", "PosixPath", "WindowsPath") and value.args:
                val = _extract_string_value(value.args[0])
                if val is not None:
                    # Path constructor
                    assignments_typed[key] = (val, _PROVENANCE_PATH_CONSTRUCTOR)
                else:
                    assignments_typed[key] = ("", _PROVENANCE_UNKNOWN)
            elif fname in ("with_suffix", "with_name", "with_stem"):
                receiver = value.func.value
                if isinstance(receiver, ast.Name):
                    aliases[key] = receiver.id
    return assignments_typed, aliases


def _scan_write_calls(
    tree: ast.AST,
    assignments_typed: dict[str, tuple[str, str]],
    aliases: dict[str, str] | None = None,
) -> list[WriteCall]:
    """Return WriteCall objects for each write call found in tree.

    Args:
        tree: AST tree to scan
        assignments_typed: {var_name: (target_path, provenance_type)}
        aliases: {var_name: alias_var_name} for .with_suffix chains

    Returns:
        list[WriteCall] with target, operation, line, and provenance
    """
    if aliases is None:
        aliases = {}

    # Flatten assignments for target resolution
    assignments = {k: v[0] for k, v in assignments_typed.items()}

    calls: list[WriteCall] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue

        line_no = node.lineno if hasattr(node, 'lineno') else None

        # Function-call writes: open(path, "w"), json.dump(obj, fp).
        # These are NOT receiver-method calls, so handle them before the
        # ast.Attribute gate below. Reads (open(p)/open(p,"r")) return None.
        func_write = _detect_func_write(node, assignments, aliases)
        if func_write is not None:
            operation, resolved = func_write
            if resolved is not None and not _is_plausible_path(resolved):
                resolved = _UNKNOWN_TARGET
            target = resolved if resolved is not None else _UNKNOWN_TARGET
            provenance = _PROVENANCE_UNKNOWN
            for var_name, (path, prov_type) in assignments_typed.items():
                if path == target and target != _UNKNOWN_TARGET:
                    provenance = prov_type
                    break
            calls.append(WriteCall(target=target, operation=operation, line=line_no, provenance=provenance))
            continue

        if not isinstance(node.func, ast.Attribute):
            continue

        # Standard write methods: path.write_text(), path.save(), etc.
        if node.func.attr in _WRITE_METHOD_NAMES:
            operation = node.func.attr
            resolved = _resolve_call_target(node, assignments, aliases)
            if resolved is not None and not _is_plausible_path(resolved):
                resolved = _UNKNOWN_TARGET
            target = resolved if resolved is not None else _UNKNOWN_TARGET

            # Determine provenance from assignments_typed
            provenance = _PROVENANCE_UNKNOWN
            for var_name, (path, prov_type) in assignments_typed.items():
                if path == target and target != _UNKNOWN_TARGET:
                    provenance = prov_type
                    break

            calls.append(WriteCall(target=target, operation=operation, line=line_no, provenance=provenance))
            continue

        # os.replace(src, dst) — dst is second positional arg
        if (node.func.attr == "replace" and
            isinstance(node.func.value, ast.Name) and
            node.func.value.id == "os" and
            len(node.args) >= 2):
            operation = "os.replace"
            dst_node = node.args[1]
            if isinstance(dst_node, ast.Name):
                name = dst_node.id
                resolved = name
                visited: set[str] = {resolved}
                for _ in range(8):
                    nxt = aliases.get(resolved)
                    if nxt is None or nxt in visited:
                        break
                    visited.add(nxt)
                    resolved = nxt
                target = assignments.get(resolved, _UNKNOWN_TARGET)

                # Determine provenance
                provenance = _PROVENANCE_UNKNOWN
                for var_name, (path, prov_type) in assignments_typed.items():
                    if path == target and target != _UNKNOWN_TARGET:
                        provenance = prov_type
                        break

                calls.append(WriteCall(target=target, operation=operation, line=line_no, provenance=provenance))

    return calls


# ---------------------------------------------------------------------------
# Per-file scan
# ---------------------------------------------------------------------------

def _scan_writers(
    project_dir: Path,
    include_roots: Sequence[str] | None,
) -> dict[str, list[WriteCall]]:
    """Return mapping writer_rel_posix -> list[WriteCall].

    Uses parallel ThreadPoolExecutor for faster AST scanning on large projects.
    """
    from concurrent.futures import ThreadPoolExecutor, as_completed
    import os as _os

    project_dir = project_dir.resolve()
    py_files = sorted(iter_py_files(project_dir, include_roots))

    def _scan_one(py_file: Path) -> tuple[str, list[WriteCall]] | None:
        try:
            source = py_file.read_text(encoding="utf-8", errors="replace")
            tree = ast.parse(source, filename=str(py_file))
        except (OSError, SyntaxError) as exc:
            _log.debug("_scan_writers: skipping %s: %s", py_file, exc)
            return None
        # Cheap pre-filter: skip files with no candidate write-shaped call.
        # Method writes (.write_text/.save/os.replace) are ast.Attribute; the
        # function-call writes open(...) / json.dump(...) are ast.Name / module
        # attribute respectively. Mode/target precision is decided later in
        # _scan_write_calls — this is only a coarse "worth parsing?" gate.
        def _is_candidate(node: ast.AST) -> bool:
            if not isinstance(node, ast.Call):
                return False
            func = node.func
            if isinstance(func, ast.Name):
                return func.id == "open"  # mode filtered later
            if isinstance(func, ast.Attribute):
                if func.attr in _WRITE_METHOD_NAMES:
                    return True
                if func.attr == "dump" and isinstance(func.value, ast.Name) and func.value.id == "json":
                    return True
                if (func.attr == "replace"
                        and isinstance(func.value, ast.Name)
                        and func.value.id == "os"):
                    return True
            return False

        if not any(_is_candidate(node) for node in ast.walk(tree)):
            return None
        assignments_typed, aliases = _collect_assignments(tree)
        write_calls = _scan_write_calls(tree, assignments_typed, aliases)
        if not write_calls:
            return None
        try:
            rel = py_file.resolve().relative_to(project_dir).as_posix()
        except ValueError:
            _log.debug("_scan_writers: cannot relativize %s", py_file)
            return None
        return rel, write_calls

    raw: dict[str, list[WriteCall]] = {}
    max_workers = min(8, (_os.cpu_count() or 4))
    with ThreadPoolExecutor(max_workers=max_workers) as pool:
        futures = {pool.submit(_scan_one, f): f for f in py_files}
        for future in as_completed(futures):
            out = future.result()
            if out is not None:
                rel, write_calls = out
                raw[rel] = write_calls

    # Sort for determinism (as_completed order is arbitrary)
    result = dict(sorted(raw.items()))
    _log.debug("_scan_writers: found %d writer file(s)", len(result))
    return result


# ---------------------------------------------------------------------------
# Classification + domain matching
# ---------------------------------------------------------------------------

def _classify_writer(rel_path: str, allowed_writers: tuple[str, ...]) -> str:
    return "canonical_write" if rel_path in allowed_writers else "illegal_write"


def _writer_matches_domain(targets: list[str], patterns: tuple[str, ...]) -> bool:
    """True if any resolved (non-unknown) target matches any domain pattern."""
    for target in targets:
        if target == _UNKNOWN_TARGET:
            continue
        for pattern in patterns:
            if _match_glob_path(target, pattern):
                return True
    return False


# ---------------------------------------------------------------------------
# Seed loading
# ---------------------------------------------------------------------------

def _load_seed(project_dir: Path) -> list[dict] | None:
    """Load authority domains seed. Returns None if missing, raises on corrupt."""
    seed_path = seeds_dir(project_dir) / _SEED_FILENAME
    if not seed_path.exists():
        _log.info("build_authority_map: no seed at %s, returning empty map", seed_path)
        return None
    try:
        raw = json.loads(seed_path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError, UnicodeDecodeError) as exc:
        raise MapIntegrityError(
            "authority seed corrupt (JSON parse failed): %s -- %s" % (seed_path, exc)
        ) from exc
    if not isinstance(raw, dict):
        raise MapIntegrityError(
            "authority seed must be a JSON object, got %s" % type(raw).__name__
        )
    schema_version = raw.get("schema_version")
    if schema_version is None:
        raise MapIntegrityError(
            "authority seed missing required field 'schema_version' in %s" % seed_path
        )
    try:
        major = int(str(schema_version).split(".")[0])
    except (ValueError, IndexError) as exc:
        raise MapIntegrityError(
            "authority seed has unparseable schema_version %r in %s" % (schema_version, seed_path)
        ) from exc
    if major > 1:
        raise MapIntegrityError(
            "authority seed schema_version %r has major version %d > 1 -- "
            "upgrade the builder to read this seed" % (schema_version, major)
        )
    domains = raw.get("domains", [])
    if not isinstance(domains, list):
        raise MapIntegrityError(
            "authority seed 'domains' must be a list, got %s" % type(domains).__name__
        )
    _log.debug("_load_seed: loaded %d domain(s) from %s", len(domains), seed_path)
    return domains


# ---------------------------------------------------------------------------
# Auto-discovery: collect targets and infer domains (seed-free)
# ---------------------------------------------------------------------------

def _collect_auto_write_targets(
    writers_map: dict[str, list[WriteCall]],
    adapter_candidates: dict[str, list],
) -> tuple[dict[str, list[str]], dict[str, list[tuple[str, WriteCall | None]]]]:
    """Collect target -> [writer_rel_posix] mapping and WriteCall tracking.

    Returns:
        (target_to_writers, target_to_write_calls) where:
        - target_to_writers: target -> [writer_rel_posix] (backward compat)
        - target_to_write_calls: target -> [(writer_rel, WriteCall|None), ...]
            WriteCall is None for non-Python adapter writers (no AST info).

    target keys are normalized (tmp/bak stripped).
    Only non-UNKNOWN targets included.
    Result is sorted for determinism.
    """
    target_to_writers: dict[str, list[str]] = {}
    target_to_write_calls: dict[str, list[tuple[str, WriteCall | None]]] = {}

    # Python AST writers
    for writer_rel, write_calls in sorted(writers_map.items()):
        for write_call in write_calls:
            target = write_call.target
            if target == _UNKNOWN_TARGET:
                continue
            base = _normalize_target_path(target)
            target_to_writers.setdefault(base, []).append(writer_rel)
            target_to_write_calls.setdefault(base, []).append((writer_rel, write_call))

    # Non-Python adapter writers (TS/JS/Go/Java etc.)
    for writer_rel, candidates in sorted(adapter_candidates.items()):
        for candidate in candidates:
            if not candidate.target_hint:
                continue
            base = _normalize_target_path(candidate.target_hint)
            target_to_writers.setdefault(base, []).append(writer_rel)
            # No WriteCall object available for adapters
            target_to_write_calls.setdefault(base, []).append((writer_rel, None))

    # Deduplicate and sort writers lists for determinism
    target_to_writers_result = {
        target: sorted(dict.fromkeys(writers))
        for target, writers in sorted(target_to_writers.items())
    }

    # Deduplicate WriteCall entries (keep first occurrence per writer_rel)
    target_to_write_calls_result = {}
    for target in sorted(target_to_write_calls.keys()):
        # Keep only first WriteCall per writer_rel for this target
        seen_writers: dict[str, tuple[str, WriteCall | None]] = {}
        for writer_rel, write_call in target_to_write_calls[target]:
            if writer_rel not in seen_writers:
                seen_writers[writer_rel] = (writer_rel, write_call)
        target_to_write_calls_result[target] = list(seen_writers.values())

    return target_to_writers_result, target_to_write_calls_result


def _auto_discover_domains(
    target_to_writers: dict[str, list[str]],
    target_to_write_calls: dict[str, list[tuple[str, WriteCall | None]]],
    seed_domains: list[dict],
) -> list[dict]:
    """Find shared-write clusters not covered by seed.

    Returns synthetic domain defs for build_authority_map() merge loop.
    Only includes groups with 2+ writers from DIFFERENT module prefixes.
    Seed-covered targets are skipped.
    Test-only shared writes (all writers non-production) are skipped.

    Args:
        target_to_writers: target -> [writer_rel] mapping (backward compat usage)
        target_to_write_calls: target -> [(writer_rel, WriteCall|None)] mapping
        seed_domains: list of seed domain definitions
    """
    auto_domains = []
    for target, writers in target_to_writers.items():
        if len(writers) < 2:
            continue
        # Must come from different module prefixes
        prefixes = {_module_prefix(w) for w in writers}
        if len(prefixes) < 2:
            continue
        # Skip if any seed domain already covers this target
        if _seed_covers_target(target, seed_domains):
            continue
        # Skip if all writers are non-production (test/fixture/generated)
        roles = {classify_file_role(w) for w in writers}
        if "production" not in roles:
            continue
        auto_domains.append({
            "_auto": True,
            "authority_domain": f"shared_write:{_safe_domain_name(target)}",
            "canonical_owner": "",
            "allowed_writers": [],
            "target_file_patterns": [target],
            "_shared_target": target,
            "_all_writers": writers,
            "_write_calls": target_to_write_calls.get(target, []),
        })
    return auto_domains


def _safe_writer_domain_name(writer_rel: str) -> str:
    """Stable, filesystem-safe domain name for a writer file (no-seed mode)."""
    digest = hashlib.blake2s(writer_rel.encode("utf-8"), digest_size=2).hexdigest()
    stem = Path(writer_rel).stem
    raw = "%s_%s" % (stem, digest)
    return "auto_discovered:" + re.sub(r"[^a-zA-Z0-9_]", "_", raw)[:48]


def _build_no_seed_writer_domains(
    writers_map: dict[str, list[WriteCall]],
    adapter_candidates: dict[str, list[AuthorityWriteCandidate]],
) -> list[AuthorityDomain]:
    """Auto-surface every discovered writer as an inferred AuthorityDomain.

    Used ONLY when no seed file exists. One domain per writer file: the writer
    is named as canonical_owner and listed in writers_detected together with
    each resolved write target + operation/kind, so the entry is actionable
    out-of-the-box. status="inferred", source names "static_scan".

    Writers with no resolvable targets are still surfaced (with an unknown
    target) because a confirmed write operation is itself authority evidence;
    pure reads never reach this map (they produce no WriteCall / candidate).
    """
    metadata = make_metadata(source="static_scan", confidence=0.5, status="inferred")
    domains: list[AuthorityDomain] = []

    # union of all writer files (Python AST + non-Python adapter), sorted
    all_writers = sorted(set(writers_map) | set(adapter_candidates))

    for writer_rel in all_writers:
        writers_detected: list[dict] = []
        targets: list[str] = []

        # Python AST write calls
        for wc in writers_map.get(writer_rel, []):
            target = wc.target if wc.target != _UNKNOWN_TARGET else ""
            if target:
                targets.append(_normalize_target_path(target))
            writers_detected.append({
                "location": writer_rel,
                "kind": "write",
                "target": _normalize_target_path(target) if target else "",
                "operation": wc.operation,
                "line": wc.line,
                "provenance": wc.provenance,
                "file_role": classify_file_role(writer_rel),
            })

        # Non-Python adapter candidates (Go/Java/JS/TS)
        for cand in adapter_candidates.get(writer_rel, []):
            target = cand.target_hint or ""
            if target:
                targets.append(_normalize_target_path(target))
            writers_detected.append({
                "location": writer_rel,
                "kind": cand.write_kind,
                "target": _normalize_target_path(target) if target else "",
                "operation": cand.write_kind,
                "line": cand.line,
                "provenance": _PROVENANCE_UNKNOWN,
                "file_role": classify_file_role(writer_rel),
            })

        if not writers_detected:
            continue

        # Deterministic order inside the entry
        writers_detected.sort(key=lambda w: (w.get("line") or 0, w.get("target", ""), w.get("operation", "")))
        resolved_targets = sorted(dict.fromkeys(t for t in targets if t))

        domains.append(AuthorityDomain(
            authority_domain=_safe_writer_domain_name(writer_rel),
            canonical_owner=writer_rel,
            allowed_writers=(writer_rel,),
            derived_readers=(),
            cache_layers=(),
            freshness_sla="immediate",
            invalidation_rule="unknown",
            drift_policy="observe",
            writers_detected=tuple(
                json.dumps(w, sort_keys=True) for w in writers_detected
            ),
            last_drift_events=(),
            target_file_patterns=tuple(resolved_targets),
            source=metadata["source"],
            evidence=tuple(metadata["evidence"]),
            confidence=metadata["confidence"],
            freshness=metadata["freshness"],
            status=metadata["status"],
        ))

    return domains


# ---------------------------------------------------------------------------
# Non-Python adapter writer collection (L7a)
# ---------------------------------------------------------------------------

def _collect_adapter_writer_candidates(
    project_dir: Path,
    include_roots: Sequence[str] | None,
) -> dict[str, list[AuthorityWriteCandidate]]:
    """Return mapping rel_posix -> list[AuthorityWriteCandidate] for non-Python files.

    Iterates all source files via iter_source_files, skips Python (handled by
    AST pass), skips adapters without supports_authority_writes=True.
    """
    result: dict[str, list[AuthorityWriteCandidate]] = {}
    project_dir = project_dir.resolve()
    for src_file in iter_source_files(project_dir, include_roots=include_roots):
        adapter = get_adapter_for_file(src_file)
        if adapter is None:
            continue
        if adapter.language == "python":
            continue
        if not getattr(adapter, "supports_authority_writes", False):
            continue
        try:
            content = src_file.read_text(encoding="utf-8", errors="replace")
        except OSError as exc:
            _log.debug("_collect_adapter_writer_candidates: skipping %s: %s", src_file, exc)
            continue
        try:
            candidates = adapter.extract_writer_calls(content, src_file)  # type: ignore[attr-defined]
        except Exception as exc:  # noqa: BLE001
            _log.debug(
                "_collect_adapter_writer_candidates: error in %s for %s: %s",
                adapter.language, src_file, exc,
            )
            continue
        if not candidates:
            continue
        try:
            rel = src_file.resolve().relative_to(project_dir).as_posix()
        except ValueError:
            _log.debug("_collect_adapter_writer_candidates: cannot relativize %s", src_file)
            continue
        result[rel] = candidates
    _log.debug(
        "_collect_adapter_writer_candidates: found %d non-Python writer file(s)", len(result)
    )
    return result


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def build_authority_map(
    project_dir: Path,
    include_roots: Sequence[str] | None = None,
    parse_cache: Any | None = None,
) -> list[AuthorityDomain]:
    """Build authority map for a target project.

    Reads seed from <project_dir>/.cortex/map_seeds/authority_domains.json.
    Each domain's ``target_file_patterns`` controls which writers are attributed
    to it via AST-resolved write-target matching. Missing patterns -> no
    auto-discovery for that domain.

    Also performs seed-free auto-discovery: detects shared write targets
    (2+ writers from different module prefixes) and creates inferred domains.

    When NO seed file exists, additionally auto-surfaces every discovered write
    site as an inferred per-writer domain (out-of-box usefulness). With a seed
    present this step is skipped to preserve the structured behaviour.

    Returns empty list only if no seed file exists AND no write sites were found.
    Raises MapIntegrityError if seed is corrupt or has incompatible version.
    """
    project_dir = Path(project_dir).resolve()
    _log.info("build_authority_map: starting for %s", project_dir)
    # parse_cache is accepted for API uniformity with other builders.
    # _scan_writers uses ThreadPoolExecutor internally, and ParseCacheL1 is
    # not thread-safe, so the cache is not passed into the threaded scan path.
    if parse_cache is not None:
        _log.debug("build_authority_map: parse_cache provided but not used in threaded _scan_writers")
    domains_raw = _load_seed(project_dir)
    no_seed = domains_raw is None  # no seed file at all -> auto-surface mode
    seed_list: list[dict] = domains_raw or []

    # ALWAYS scan writers (not gated behind seed anymore)
    _log.info("build_authority_map: scanning writers via AST in %s", project_dir)
    writers_map = _scan_writers(project_dir, include_roots)
    _log.debug("build_authority_map: %d Python writer file(s)", len(writers_map))

    # L7a: collect non-Python write candidates via adapter dispatch
    adapter_candidates = _collect_adapter_writer_candidates(project_dir, include_roots)
    _log.debug(
        "build_authority_map: %d non-Python writer file(s)", len(adapter_candidates)
    )

    # Collect shared write targets (Python + non-Python)
    target_to_writers, target_to_write_calls = _collect_auto_write_targets(writers_map, adapter_candidates)

    metadata = make_metadata(source="seed + static_scan", confidence=0.85, status="observed")
    results: list[AuthorityDomain] = []

    for domain_def in seed_list:
        if not isinstance(domain_def, dict):
            raise MapIntegrityError(
                "authority seed domain entry must be a dict, got %s" % type(domain_def).__name__
            )
        authority_domain = str(domain_def.get("authority_domain", ""))
        if not authority_domain:
            raise MapIntegrityError(
                "authority seed domain entry missing 'authority_domain' field: %r" % domain_def
            )

        allowed_writers: tuple[str, ...] = tuple(domain_def.get("allowed_writers", []))
        target_file_patterns: tuple[str, ...] = tuple(domain_def.get("target_file_patterns", []))

        if not target_file_patterns:
            _log.info(
                "build_authority_map: domain=%s has no target_file_patterns -- "
                "skipping auto-discovery",
                authority_domain,
            )

        seen_locations: set[str] = set()
        writers_detected_dicts: list[dict] = []
        if target_file_patterns:
            # Python AST writers
            for writer_path, write_calls in sorted(writers_map.items()):
                if writer_path in seen_locations:
                    continue
                # Extract targets from WriteCall objects for domain matching
                targets = [wc.target for wc in write_calls]
                if _writer_matches_domain(targets, target_file_patterns):
                    kind = _classify_writer(writer_path, allowed_writers)
                    # Pick most significant write call (by provenance priority)
                    # Priority: path_constructor > string_literal > function_parameter > unknown
                    _prov_priority = {
                        _PROVENANCE_PATH_CONSTRUCTOR: 3,
                        _PROVENANCE_STRING_LITERAL: 2,
                        _PROVENANCE_FUNCTION_PARAM: 1,
                        _PROVENANCE_UNKNOWN: 0,
                    }
                    best_wc = max(write_calls, key=lambda wc: _prov_priority.get(wc.provenance, -1))
                    writers_detected_dicts.append({
                        "location": writer_path,
                        "kind": kind,
                        "file_role": classify_file_role(writer_path),
                        "operation": best_wc.operation,
                        "line": best_wc.line,
                        "provenance": best_wc.provenance,
                    })
                    seen_locations.add(writer_path)

            # Non-Python adapter writers (L7a)
            for writer_path, aw_candidates in sorted(adapter_candidates.items()):
                if writer_path in seen_locations:
                    continue
                # Use target_hint values as synthetic targets for domain matching.
                # Empty hints are treated as unknown targets (same as Python's
                # _UNKNOWN_TARGET) and do not contribute to domain matching.
                synthetic_targets = [
                    c.target_hint for c in aw_candidates if c.target_hint
                ]
                if not synthetic_targets:
                    continue
                if _writer_matches_domain(synthetic_targets, target_file_patterns):
                    kind = _classify_writer(writer_path, allowed_writers)
                    writers_detected_dicts.append({
                        "location": writer_path,
                        "kind": kind,
                        "file_role": classify_file_role(writer_path),
                    })
                    seen_locations.add(writer_path)

        domain = AuthorityDomain(
            authority_domain=authority_domain,
            canonical_owner=str(domain_def.get("canonical_owner", "")),
            allowed_writers=allowed_writers,
            derived_readers=tuple(domain_def.get("derived_readers", [])),
            cache_layers=tuple(domain_def.get("cache_layers", [])),
            freshness_sla=str(domain_def.get("freshness_sla", "immediate")),
            invalidation_rule=str(domain_def.get("invalidation_rule", "")),
            drift_policy=str(domain_def.get("drift_policy", "fail_close")),
            writers_detected=tuple(json.dumps(w, sort_keys=True) for w in writers_detected_dicts),
            last_drift_events=(),
            target_file_patterns=target_file_patterns,
            source=metadata["source"],
            evidence=tuple(metadata["evidence"]),
            confidence=metadata["confidence"],
            freshness=metadata["freshness"],
            status=metadata["status"],
        )
        results.append(domain)
        _log.debug(
            "build_authority_map: domain=%s patterns=%d writers_detected=%d",
            authority_domain, len(target_file_patterns), len(writers_detected_dicts),
        )

    # --- Auto-discovered domains (seed-free) ---
    auto_domains = _auto_discover_domains(target_to_writers, target_to_write_calls, seed_list)
    auto_metadata = make_metadata(source="auto_scan", confidence=0.6, status="inferred")

    for ad in auto_domains:
        writers_detected_list = []
        # Build mapping of writer -> WriteCall for quick lookup
        write_calls_by_writer: dict[str, WriteCall | None] = {}
        for writer_rel, write_call in ad["_write_calls"]:
            write_calls_by_writer[writer_rel] = write_call

        for w in ad["_all_writers"]:
            # Look up WriteCall for this writer
            write_call = write_calls_by_writer.get(w)

            if write_call is not None:
                # Python AST writer with full WriteCall information
                provenance = write_call.provenance
                operation = write_call.operation
                line = write_call.line
            else:
                # Non-Python adapter writer (no AST info available)
                provenance = _PROVENANCE_UNKNOWN
                operation = "unknown"
                line = None

            writers_detected_list.append({
                "location": w,
                "kind": "shared_write",
                "target": ad["_shared_target"],
                "module_prefix": _module_prefix(w),
                "file_role": classify_file_role(w),
                "operation": operation,
                "line": line,
                "provenance": provenance,
            })

        writers_detected = tuple(
            json.dumps(w, sort_keys=True)
            for w in writers_detected_list
        )
        results.append(AuthorityDomain(
            authority_domain=ad["authority_domain"],
            canonical_owner="",
            allowed_writers=(),
            derived_readers=(),
            cache_layers=(),
            freshness_sla="immediate",
            invalidation_rule="unknown",
            drift_policy="observe",
            writers_detected=writers_detected,
            last_drift_events=(),
            target_file_patterns=tuple(ad["target_file_patterns"]),
            source=auto_metadata["source"],
            evidence=tuple(auto_metadata["evidence"]),
            confidence=auto_metadata["confidence"],
            freshness=auto_metadata["freshness"],
            status=auto_metadata["status"],
        ))
        _log.debug(
            "build_authority_map: auto domain=%s target=%s writers_detected=%d",
            ad["authority_domain"], ad["_shared_target"], len(ad["_all_writers"]),
        )

    # --- No-seed auto-surface (out-of-box) ---
    # When NO seed file exists, the per-domain loop above never runs and the
    # shared-write heuristic only catches multi-writer targets, so most projects
    # got an empty authority map. Surface every discovered writer (Python +
    # adapter) as an inferred per-writer domain so the map is useful immediately.
    # When a seed exists we keep the structured behaviour and do NOT add these
    # (avoids double-surfacing writers already attributed to seed domains).
    no_seed_count = 0
    if no_seed:
        no_seed_domains = _build_no_seed_writer_domains(writers_map, adapter_candidates)
        results.extend(no_seed_domains)
        no_seed_count = len(no_seed_domains)

    _log.info(
        "build_authority_map: completed %d domain(s) (seed=%d auto=%d no_seed=%d), %d writer file(s) scanned",
        len(results), len([r for r in results if r.status == "observed"]),
        len(auto_domains), no_seed_count, len(writers_map),
    )
    return results
