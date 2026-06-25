"""Two-level parse cache for the map builder subsystem.

L1 (ParseCacheL1): In-memory cache for a single build session.
L2 (ParseCacheL2): On-disk persistent cache in <project>/.cortex/.map_cache/.

Design:
- ParsedFile holds per-file signals extracted by AST parsing (no ast.Module —
  not serialisable). Reused by structural, runtime, data_contract, authority
  builders so each file is parsed at most once per build.
- content_hash = sha256(source_bytes).hexdigest()[:32]  (full 32-char hex)
- adapter_version_hash = sha256(sorted adapter repr strings)[:16]
- L2 cache entries live in .cortex/.map_cache/<content_hash>.json
- Corrupt / wrong-version entries are treated as cache misses, never raised.
- Thread-safety: L1 is not thread-safe (single-threaded builder loop).
  L2 writes are atomic (tempfile + os.replace).
"""
from __future__ import annotations

import collections
import hashlib
import json
import logging
import os
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    pass

__all__ = [
    "ParsedFile",
    "ParseCacheL1",
    "ParseCacheL2",
]

_log = logging.getLogger(__name__)

# Bump this when ParsedFile schema changes incompatibly.
_CACHE_FORMAT_VERSION = 1

# Subdirectory inside .cortex for the L2 on-disk cache.
_CACHE_SUBDIR = ".cortex/.map_cache"


# ---------------------------------------------------------------------------
# Adapter version hash — invalidates cache when parser logic changes
# ---------------------------------------------------------------------------

def _compute_adapter_version_hash() -> str:
    """Return a 16-char hex hash derived from adapter capabilities + source code.

    Combines:
    1. Adapter class names + capability flags (structural, contracts, runtime, writes)
    2. Source code of critical extraction modules (parse_cache.py, source_adapters.py)

    When adapters change, capabilities change, OR extraction logic changes,
    the hash changes and all L2 entries from prior builds become invalid.
    """
    from .source_adapters import ADAPTERS  # noqa: PLC0415

    parts: list[str] = []

    # Part 1: Adapter capabilities (as before)
    for ext in sorted(ADAPTERS):
        a = ADAPTERS[ext]
        parts.append(
            "%s|%s|structural=%s|contracts=%s|runtime=%s|writes=%s" % (
                ext,
                a.__class__.__name__,
                a.supports_structural,
                a.supports_contracts,
                a.supports_runtime_signals,
                a.supports_authority_writes,
            )
        )

    # Part 2: Source code hash of critical extraction modules
    # This invalidates cache when extraction logic changes
    map_builder_dir = Path(__file__).parent
    critical_modules = [
        "parse_cache.py",
        "structural_builder.py",
        "runtime_builder.py",
        "data_contract_builder.py",
        "authority_builder.py",
    ]

    module_parts: list[str] = []
    for mod_name in critical_modules:
        mod_path = map_builder_dir / mod_name
        if mod_path.exists():
            try:
                source = mod_path.read_text(encoding="utf-8")
                mod_hash = hashlib.sha256(source.encode("utf-8")).hexdigest()[:8]
                module_parts.append(f"{mod_name}:{mod_hash}")
            except (OSError, UnicodeDecodeError):
                _log.debug("_compute_adapter_version_hash: failed to read %s", mod_name)
                # Use empty hash if file cannot be read (failure is not silenced,
                # ensures rebuilds happen on file access issues)
                module_parts.append(f"{mod_name}:ERROR")
        else:
            # Module doesn't exist in this version of map_builder (acceptable)
            module_parts.append(f"{mod_name}:MISSING")

    # source_adapters/ is a package directory — hash all *.py files combined so
    # any adapter file change invalidates the cache.
    source_adapters_dir = map_builder_dir / "source_adapters"
    if source_adapters_dir.is_dir():
        adapter_files = sorted(source_adapters_dir.glob("*.py"))
        per_file_hashes: list[str] = []
        for adapter_path in adapter_files:
            try:
                adapter_source = adapter_path.read_text(encoding="utf-8")
                file_hash = hashlib.sha256(adapter_source.encode("utf-8")).hexdigest()
                per_file_hashes.append(f"{adapter_path.name}:{file_hash}")
            except (OSError, UnicodeDecodeError):
                _log.debug(
                    "_compute_adapter_version_hash: failed to read %s",
                    adapter_path.name,
                )
                per_file_hashes.append(f"{adapter_path.name}:ERROR")
        combined_adapter_hash = hashlib.sha256(
            "\n".join(per_file_hashes).encode("utf-8")
        ).hexdigest()[:8]
        module_parts.append(f"source_adapters_dir:{combined_adapter_hash}")
    else:
        _log.warning(
            "_compute_adapter_version_hash: source_adapters/ directory missing at %s",
            source_adapters_dir,
        )
        module_parts.append("source_adapters_dir:MISSING")

    parts.append("extraction_code:" + ",".join(module_parts))
    combined = "\n".join(sorted(parts))
    return hashlib.sha256(combined.encode("utf-8")).hexdigest()[:16]


# Computed once per process lifetime (adapters are registered at import time).
_ADAPTER_VERSION_HASH: str | None = None


def _get_adapter_version_hash() -> str:
    global _ADAPTER_VERSION_HASH  # noqa: PLW0603
    if _ADAPTER_VERSION_HASH is None:
        _ADAPTER_VERSION_HASH = _compute_adapter_version_hash()
    return _ADAPTER_VERSION_HASH


# ---------------------------------------------------------------------------
# ParsedFile dataclass
# ---------------------------------------------------------------------------

@dataclass
class ParsedFile:
    """Per-file signals extracted from source.  No ast.Module (not serialisable).

    All list fields are plain lists (not tuples) so they round-trip through JSON
    without conversion.  Builders that need tuples cast on consumption.
    """

    # Structural signals
    imports_out: list[str]       # dotted module names imported by this file
    symbols_defined: list[str]   # class / function names at any scope

    # Runtime signals
    env_vars: list[str]          # os.environ keys read by this file
    side_effects: list[str]      # import-time side-effect categories detected
    write_calls: list[str]       # write-target paths detected by AST

    # Data-contract signals
    entity_classes: list[str]    # dataclass / pydantic / NamedTuple / TypedDict names

    # Meta
    is_parseable: bool           # False iff source had a SyntaxError
    content_hash: str            # sha256(source)[:32]
    size_lines: int              # line count of source


def _parsed_file_to_dict(pf: ParsedFile) -> dict:
    return {
        "imports_out": pf.imports_out,
        "symbols_defined": pf.symbols_defined,
        "env_vars": pf.env_vars,
        "side_effects": pf.side_effects,
        "write_calls": pf.write_calls,
        "entity_classes": pf.entity_classes,
        "is_parseable": pf.is_parseable,
        "content_hash": pf.content_hash,
        "size_lines": pf.size_lines,
    }


def _parsed_file_from_dict(d: dict) -> ParsedFile:
    return ParsedFile(
        imports_out=list(d.get("imports_out", [])),
        symbols_defined=list(d.get("symbols_defined", [])),
        env_vars=list(d.get("env_vars", [])),
        side_effects=list(d.get("side_effects", [])),
        write_calls=list(d.get("write_calls", [])),
        entity_classes=list(d.get("entity_classes", [])),
        is_parseable=bool(d.get("is_parseable", True)),
        content_hash=str(d.get("content_hash", "")),
        size_lines=int(d.get("size_lines", 0)),
    )


# ---------------------------------------------------------------------------
# ParseCacheL2 — on-disk persistent cache
# ---------------------------------------------------------------------------

class ParseCacheL2:
    """On-disk JSON cache stored in <project_dir>/.cortex/.map_cache/.

    Cache key is content_hash (sha256[:32]).  Each entry is a JSON file
    named <content_hash>.json containing parsed signals + a meta envelope
    for format/adapter-version validation.

    Partial failures (corrupt JSON, schema mismatch, OSError) are treated as
    cache misses — they never propagate to callers.
    """

    def __init__(self, project_dir: Path) -> None:
        self._cache_dir = project_dir.resolve() / _CACHE_SUBDIR
        self._adapter_hash = _get_adapter_version_hash()
        self._hits = 0
        self._misses = 0

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def get(self, content_hash: str) -> ParsedFile | None:
        """Return cached ParsedFile for content_hash, or None on miss/error."""
        entry_path = self._cache_dir / (content_hash + ".json")
        if not entry_path.exists():
            self._misses += 1
            return None

        try:
            raw = entry_path.read_text(encoding="utf-8")
            payload = json.loads(raw)
        except (OSError, json.JSONDecodeError, UnicodeDecodeError) as exc:
            _log.debug("ParseCacheL2.get: corrupt entry %s, treating as miss: %s", entry_path.name, exc)
            self._misses += 1
            return None

        if not isinstance(payload, dict):
            _log.debug("ParseCacheL2.get: non-dict payload in %s, treating as miss", entry_path.name)
            self._misses += 1
            return None

        # Validate format version
        if payload.get("format_version") != _CACHE_FORMAT_VERSION:
            _log.debug(
                "ParseCacheL2.get: format_version mismatch in %s (got %r, want %r), miss",
                entry_path.name,
                payload.get("format_version"),
                _CACHE_FORMAT_VERSION,
            )
            self._misses += 1
            return None

        # Validate adapter version
        if payload.get("adapter_version_hash") != self._adapter_hash:
            _log.debug(
                "ParseCacheL2.get: adapter_version_hash mismatch in %s, miss",
                entry_path.name,
            )
            self._misses += 1
            return None

        signals = payload.get("signals")
        if not isinstance(signals, dict):
            _log.debug("ParseCacheL2.get: missing 'signals' in %s, miss", entry_path.name)
            self._misses += 1
            return None

        try:
            pf = _parsed_file_from_dict(signals)
        except Exception as exc:
            _log.debug("ParseCacheL2.get: failed to deserialise %s: %s", entry_path.name, exc)
            self._misses += 1
            return None

        self._hits += 1
        return pf

    def put(self, content_hash: str, parsed_file: ParsedFile) -> None:
        """Atomically write parsed_file to cache.  Silently swallows write errors."""
        self._cache_dir.mkdir(parents=True, exist_ok=True)
        entry_path = self._cache_dir / (content_hash + ".json")
        payload = {
            "format_version": _CACHE_FORMAT_VERSION,
            "adapter_version_hash": self._adapter_hash,
            "content_hash": content_hash,
            "signals": _parsed_file_to_dict(parsed_file),
        }
        try:
            self._atomic_write(entry_path, payload)
        except Exception as exc:
            _log.debug("ParseCacheL2.put: failed to write %s: %s", entry_path.name, exc)

    def flush(self) -> None:
        """No-op — all writes are already atomic.  Reserved for future cleanup."""

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _atomic_write(self, path: Path, payload: dict) -> None:
        """Write payload atomically via tempfile + os.replace."""
        path.parent.mkdir(parents=True, exist_ok=True)
        fd, tmp_path = tempfile.mkstemp(
            dir=str(path.parent),
            prefix=".pcache_",
            suffix=".tmp",
        )
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                fh.write(json.dumps(payload, indent=2, ensure_ascii=False, sort_keys=True))
                fh.write("\n")
            os.replace(tmp_path, str(path))
        except BaseException:
            try:
                os.unlink(tmp_path)
            except OSError:
                pass
            raise


# ---------------------------------------------------------------------------
# ParseCacheL1 — in-memory cache for one build session
# ---------------------------------------------------------------------------

class ParseCacheL1:
    """In-memory parse cache backed by an optional ParseCacheL2.

    Lifetime: one map-build invocation.  Keyed by resolved absolute path.
    On get_or_parse() miss: reads the file, hashes content, checks L2,
    then falls back to full AST parse.  Result stored in both L1 and L2.

    Also caches source text in L1 (not serialized to L2) to avoid re-reading
    files when multiple builders consume the same file.
    """

    # Default cap for the source-text LRU: keeps at most this many file texts
    # in memory simultaneously.  On a typical project the working set is small
    # (builders read each file once), so 256 covers virtually all cases while
    # preventing unbounded growth when a repo has thousands of source files.
    _SOURCE_CACHE_MAX_ENTRIES: int = 256

    def __init__(
        self,
        l2: ParseCacheL2 | None = None,
        *,
        max_file_mb: float = 5.0,
        source_cache_max_entries: int | None = None,
    ) -> None:
        """Initialise the L1 in-memory cache.

        Args:
            l2: Optional L2 on-disk cache.
            max_file_mb: Files larger than this threshold (in MiB) are SKIPPED —
                their full-text is never loaded and an empty ParsedFile is
                returned.  The skipped file is recorded in ``oversized_files``.
                Default is 5.0 MiB.  Pass ``float('inf')`` to disable.
            source_cache_max_entries: Maximum number of raw source strings to
                retain in the LRU text cache.  Oldest entry is evicted when the
                cap is reached.  Default: ``_SOURCE_CACHE_MAX_ENTRIES`` (256).
        """
        self._l2 = l2
        self._max_file_bytes: float = max_file_mb * 1024 * 1024
        _cap = source_cache_max_entries if source_cache_max_entries is not None else self._SOURCE_CACHE_MAX_ENTRIES
        self._source_cache_max: int = max(1, _cap)
        self._cache: dict[str, ParsedFile] = {}  # key: str(abs_path)
        # Bounded LRU: OrderedDict keeps insertion order; we move-to-end on hit
        # and pop the oldest entry when the cap is reached.
        self._source_cache: collections.OrderedDict[str, str] = collections.OrderedDict()

        # Oversized-file tracking (consumed by cli_entry to populate meta)
        self.oversized_files: list[dict] = []  # [{path, size_mb}]

        # Counters
        self.hits = 0           # L1 hits
        self.misses = 0         # L1 misses (file parsed fresh or from L2)
        self.l2_hits = 0        # subset of misses served by L2
        self.l2_misses = 0      # subset of misses that required full parse
        self.total_files = 0    # total get_or_parse() calls
        self.time_saved_ms: float = 0.0  # estimated ms saved by L1+L2 cache hits

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def get_or_parse(self, abs_path: Path, project_dir: Path) -> ParsedFile:
        """Return ParsedFile for abs_path, computing it if necessary.

        Order of precedence:
            1. L1 in-memory cache (fastest)
            2. L2 on-disk cache (keyed by content_hash)
            3. Full AST parse (slowest — result stored in L1 + L2)

        Also caches the source text in L1 for later retrieval via get_cached_source().
        """
        self.total_files += 1
        key = str(abs_path)

        # --- L1 hit ---
        if key in self._cache:
            self.hits += 1
            _log.debug("ParseCacheL1: L1 hit for %s", abs_path.name)
            return self._cache[key]

        self.misses += 1
        t0 = time.perf_counter()

        # --- File-size guard (fast stat before read) ---
        try:
            file_bytes = abs_path.stat().st_size
        except OSError:
            file_bytes = 0
        if file_bytes > self._max_file_bytes:
            size_mb = file_bytes / (1024 * 1024)
            _log.warning(
                "ParseCacheL1: skipping oversized file %s (%.1f MiB > %.1f MiB limit)",
                abs_path, size_mb, self._max_file_bytes / (1024 * 1024),
            )
            self.oversized_files.append({"path": str(abs_path), "size_mb": round(size_mb, 3)})
            pf = _empty_parsed_file("")
            self._cache[key] = pf
            return pf

        # Read source
        try:
            source = abs_path.read_text(encoding="utf-8", errors="replace")
        except OSError as exc:
            _log.warning("ParseCacheL1.get_or_parse: cannot read %s: %s", abs_path, exc)
            pf = _empty_parsed_file("")
            self._cache[key] = pf
            return pf

        # Store source in bounded LRU cache (evict oldest when cap reached)
        if key not in self._source_cache and len(self._source_cache) >= self._source_cache_max:
            self._source_cache.popitem(last=False)  # evict oldest
        self._source_cache[key] = source
        self._source_cache.move_to_end(key)  # mark as most-recently used

        content_hash = hashlib.sha256(source.encode("utf-8")).hexdigest()[:32]

        # --- L2 hit ---
        if self._l2 is not None:
            cached = self._l2.get(content_hash)
            if cached is not None:
                self.l2_hits += 1
                elapsed_ms = (time.perf_counter() - t0) * 1000
                self.time_saved_ms += _estimate_parse_time_ms(source) - elapsed_ms
                _log.debug("ParseCacheL1: L2 hit for %s (hash=%s)", abs_path.name, content_hash)
                self._cache[key] = cached
                return cached

        # --- Full parse ---
        self.l2_misses += 1
        pf = _parse_file(source, content_hash, abs_path, project_dir)
        _log.debug("ParseCacheL1: parsed %s (%d lines)", abs_path.name, pf.size_lines)

        # Store results
        self._cache[key] = pf
        if self._l2 is not None:
            self._l2.put(content_hash, pf)

        return pf

    def get_cached_source(self, abs_path: Path) -> str | None:
        """Return cached source text if available, else None.

        Used by runtime/data_contract builders to avoid re-reading files
        that were already read by get_or_parse().  On hit the entry is
        promoted to most-recently-used so it survives longer in the LRU.
        """
        key = str(abs_path)
        src = self._source_cache.get(key)
        if src is not None:
            self._source_cache.move_to_end(key)
        return src

    def log_stats(self) -> None:
        """Log hit/miss stats at INFO level."""
        total = self.total_files
        l1_rate = (self.hits / total * 100) if total > 0 else 0.0
        l2_rate = (self.l2_hits / max(self.misses, 1) * 100) if self.misses > 0 else 0.0
        _log.info(
            "ParseCacheL1 stats: total=%d  L1_hits=%d (%.0f%%)  "
            "L2_hits=%d (%.0f%% of L1-misses)  full_parses=%d  "
            "estimated_saved=%.0fms",
            total,
            self.hits,
            l1_rate,
            self.l2_hits,
            l2_rate,
            self.l2_misses,
            self.time_saved_ms,
        )


# ---------------------------------------------------------------------------
# Parsing implementation (no ast.Module stored in ParsedFile)
# ---------------------------------------------------------------------------

def _empty_parsed_file(content_hash: str) -> ParsedFile:
    """Return a minimal ParsedFile for unreadable files."""
    return ParsedFile(
        imports_out=[],
        symbols_defined=[],
        env_vars=[],
        side_effects=[],
        write_calls=[],
        entity_classes=[],
        is_parseable=False,
        content_hash=content_hash,
        size_lines=0,
    )


def _estimate_parse_time_ms(source: str) -> float:
    """Rough estimate of AST parse time based on file size.

    Used only for time_saved_ms accounting — not a hard measurement.
    Empirically: ~1ms per 200 lines on modern hardware.
    """
    lines = source.count("\n") + 1
    return max(1.0, lines / 200.0)


def _parse_file(
    source: str,
    content_hash: str,
    abs_path: Path,
    project_dir: Path,
) -> ParsedFile:
    """Extract all signals from source via AST.  Never raises on SyntaxError."""
    import ast  # noqa: PLC0415

    size_lines = source.count("\n") + (1 if source and not source.endswith("\n") else 0)

    # --- Parseability check ---
    try:
        tree = ast.parse(source)
        is_parseable = True
    except SyntaxError:
        return ParsedFile(
            imports_out=[],
            symbols_defined=[],
            env_vars=[],
            side_effects=[],
            write_calls=[],
            entity_classes=[],
            is_parseable=False,
            content_hash=content_hash,
            size_lines=size_lines,
        )

    # --- Imports ---
    imports_out: list[str] = _extract_imports_out(tree, source)

    # --- Symbols defined ---
    symbols_defined: list[str] = [
        node.name
        for node in ast.walk(tree)
        if isinstance(node, (ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef))
    ]

    # --- Env vars ---
    env_vars: list[str] = _extract_env_vars(tree)

    # --- Side effects (import-time call statements) ---
    side_effects: list[str] = _extract_side_effects(tree)

    # --- Write calls ---
    write_calls: list[str] = _extract_write_calls(tree)

    # --- Entity classes (dataclass / pydantic / NamedTuple / TypedDict) ---
    entity_classes: list[str] = _extract_entity_classes(tree)

    return ParsedFile(
        imports_out=imports_out,
        symbols_defined=symbols_defined,
        env_vars=env_vars,
        side_effects=side_effects,
        write_calls=write_calls,
        entity_classes=entity_classes,
        is_parseable=is_parseable,
        content_hash=content_hash,
        size_lines=size_lines,
    )


def _extract_imports_out(tree: "ast.Module", source: str) -> list[str]:
    """Collect all import targets including 'from X import Y' → 'X.Y' candidates."""
    import ast  # noqa: PLC0415

    seen: set[str] = set()
    result: list[str] = []

    def _add(name: str) -> None:
        if name and name not in seen:
            seen.add(name)
            result.append(name)

    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                _add(alias.name)
        elif isinstance(node, ast.ImportFrom):
            if node.level == 0 and node.module:
                # Module-level import
                _add(node.module)
                # Also produce 'module.name' candidates for sub-module resolution
                for alias in node.names:
                    if alias.name != "*":
                        _add("%s.%s" % (node.module, alias.name))
            elif node.level > 0:
                # Relative import: represent as ".name" or "..name"
                dots = "." * node.level
                if node.module:
                    _add(dots + node.module)
                else:
                    for alias in node.names:
                        if alias.name != "*":
                            _add(dots + alias.name)

    return result


_ENV_CALL_PATTERNS = frozenset({
    ("os", "environ", "get"),    # os.environ.get(...)
    ("os", "getenv"),            # os.getenv(...)
})


def _extract_env_vars(tree: "ast.Module") -> list[str]:
    """Extract string keys from os.environ.get/os.getenv calls."""
    import ast  # noqa: PLC0415

    found: list[str] = []
    seen: set[str] = set()

    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        func = node.func
        # os.environ.get("KEY") — func is Attribute(value=Attribute(value=Name("os"), attr="environ"), attr="get")
        if (
            isinstance(func, ast.Attribute)
            and func.attr == "get"
            and isinstance(func.value, ast.Attribute)
            and func.value.attr == "environ"
            and isinstance(func.value.value, ast.Name)
            and func.value.value.id == "os"
        ):
            if node.args and isinstance(node.args[0], ast.Constant) and isinstance(node.args[0].value, str):
                key = node.args[0].value
                if key not in seen:
                    seen.add(key)
                    found.append(key)
        # os.getenv("KEY") — func is Attribute(value=Name("os"), attr="getenv")
        elif (
            isinstance(func, ast.Attribute)
            and func.attr == "getenv"
            and isinstance(func.value, ast.Name)
            and func.value.id == "os"
        ):
            if node.args and isinstance(node.args[0], ast.Constant) and isinstance(node.args[0].value, str):
                key = node.args[0].value
                if key not in seen:
                    seen.add(key)
                    found.append(key)

    # Also catch os.environ["KEY"] subscripts
    for node in ast.walk(tree):
        if (
            isinstance(node, ast.Subscript)
            and isinstance(node.value, ast.Attribute)
            and node.value.attr == "environ"
            and isinstance(node.value.value, ast.Name)
            and node.value.value.id == "os"
        ):
            key_node = node.slice
            # Python 3.9+: slice is the node directly; 3.8: wrapped in Index
            if isinstance(key_node, ast.Constant) and isinstance(key_node.value, str):
                key = key_node.value
                if key not in seen:
                    seen.add(key)
                    found.append(key)

    return found


def _extract_side_effects(tree: "ast.Module") -> list[str]:
    """Detect import-time side-effect categories at module top level."""
    import ast  # noqa: PLC0415

    categories: list[str] = []
    seen: set[str] = set()

    def _add(cat: str) -> None:
        if cat not in seen:
            seen.add(cat)
            categories.append(cat)

    # Module body: top-level statements that are expressions (calls) indicate
    # side-effects at import time.
    for stmt in getattr(tree, "body", []):
        if isinstance(stmt, ast.Expr) and isinstance(stmt.value, ast.Call):
            func = stmt.value.func
            func_name = ""
            if isinstance(func, ast.Name):
                func_name = func.id
            elif isinstance(func, ast.Attribute):
                func_name = func.attr
            # Common side-effect patterns
            if func_name in ("register", "setup", "configure", "init", "bootstrap", "start"):
                _add("import_time_side_effects")
            elif func_name in ("Thread", "Process", "create_task"):
                _add("background_task")
            else:
                _add("import_time_side_effects")

    return categories


def _extract_write_calls(tree: "ast.Module") -> list[str]:
    """Extract literal path targets from .write_text / .write_bytes / .save calls."""
    import ast  # noqa: PLC0415

    _WRITE_METHODS = frozenset({"write_text", "write_bytes", "save"})
    found: list[str] = []
    seen: set[str] = set()

    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        func = node.func
        if not (isinstance(func, ast.Attribute) and func.attr in _WRITE_METHODS):
            continue
        # Try to extract literal path from receiver: Path("literal").write_text(...)
        receiver = func.value
        if isinstance(receiver, ast.Call):
            func2 = receiver.func
            fname = func2.id if isinstance(func2, ast.Name) else getattr(func2, "attr", "")
            if fname in ("Path", "PurePath", "PosixPath", "WindowsPath") and receiver.args:
                arg0 = receiver.args[0]
                if isinstance(arg0, ast.Constant) and isinstance(arg0.value, str):
                    target = arg0.value
                    if target not in seen:
                        seen.add(target)
                        found.append(target)

    return found


def _extract_entity_classes(tree: "ast.Module") -> list[str]:
    """Return names of dataclass / pydantic / NamedTuple / TypedDict classes."""
    import ast  # noqa: PLC0415

    _DATACLASS_DECS = frozenset({"dataclass", "dataclasses.dataclass"})
    _ENTITY_BASES = frozenset({
        "NamedTuple", "typing.NamedTuple",
        "TypedDict", "typing.TypedDict",
        "BaseModel", "pydantic.BaseModel",
    })

    def _name_of(node: ast.expr) -> str:
        if isinstance(node, ast.Name):
            return node.id
        if isinstance(node, ast.Attribute):
            return "%s.%s" % (_name_of(node.value), node.attr)
        return ""

    names: list[str] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.ClassDef):
            continue
        # Decorated with @dataclass / @dataclasses.dataclass
        if any(_name_of(d) in _DATACLASS_DECS for d in node.decorator_list):
            names.append(node.name)
            continue
        # Inherits from entity base
        bases = {_name_of(b) for b in node.bases}
        if bases & _ENTITY_BASES:
            names.append(node.name)

    return names
