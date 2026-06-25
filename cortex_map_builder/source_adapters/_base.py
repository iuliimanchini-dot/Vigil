"""Source adapter protocol and regex base class.

Adapters extract language-specific code structure and emit IR signals.
Builders consume IR signals, decoupling language parsing from map semantics.

L1: protocol defined; PythonAdapter implements it via AST.
L2+: TypeScript/JavaScript adapters added as RegexAdapterBase subclasses.
"""
from __future__ import annotations

import logging
from pathlib import Path
from re import Pattern
from typing import Protocol, runtime_checkable

from ._ir import (
    AuthorityWriteCandidate,
    ContractCandidate,
    ImportEdge,
    RuntimeSignal,
    SymbolDef,
)

__all__ = ["SourceAdapter", "RegexAdapterBase"]

_log = logging.getLogger(__name__)


@runtime_checkable
class SourceAdapter(Protocol):
    """Language-specific source extractor. Declares capabilities per map type.

    Attributes:
        language: Canonical language name, e.g. ``"python"``, ``"typescript"``.
        file_extensions: Tuple of lowercase extensions this adapter handles,
                         e.g. ``(".py",)`` or ``(".ts", ".tsx")``.
        supports_structural: True when extract_imports + extract_symbols are
                             implemented (not just the empty-list fallback).
        supports_contracts: True when extract_contracts is implemented.
        supports_runtime_signals: True when extract_runtime is implemented.
        supports_authority_writes: True when extract_writer_calls is implemented.
    """

    language: str
    file_extensions: tuple[str, ...]
    supports_structural: bool
    supports_contracts: bool
    supports_runtime_signals: bool
    supports_authority_writes: bool

    def extract_imports(self, content: str, path: Path) -> list[ImportEdge]:
        """Return all import relationships found in *content*."""
        ...

    def extract_symbols(self, content: str, path: Path) -> list[SymbolDef]:
        """Return all top-level class/function definitions found in *content*."""
        ...

    def extract_contracts(self, content: str, path: Path) -> list[ContractCandidate]:
        """Return data-contract-style type definitions found in *content*."""
        ...

    def extract_runtime(self, content: str, path: Path) -> list[RuntimeSignal]:
        """Return import-time side effects / dynamic patterns found in *content*."""
        ...

    def extract_writer_calls(
        self, content: str, path: Path
    ) -> list[AuthorityWriteCandidate]:
        """Return write/save operations that may indicate data-authority ownership."""
        ...


class RegexAdapterBase:
    """Shared infrastructure for regex-based adapters.

    L2+ languages (TypeScript, JavaScript, Go, Java) inherit from this class
    and override the capability methods they support together with the
    ``supports_*`` flags.

    Subclasses should also override ``_preprocess`` to strip comments and
    string literals before regex matching (use ``_lexer`` helpers).
    """

    language: str = "unknown"
    file_extensions: tuple[str, ...] = ()
    supports_structural: bool = False
    supports_contracts: bool = False
    supports_runtime_signals: bool = False
    supports_authority_writes: bool = False

    # ------------------------------------------------------------------
    # Pre-processing hook — subclasses override for comment/string removal
    # ------------------------------------------------------------------

    def _preprocess(self, content: str) -> str:
        """Strip comments and strings, normalize multiline constructs.

        Default: no-op. Subclasses import helpers from ``_lexer`` and override.
        Python adapter does NOT override -- it uses ``ast.parse`` directly.
        """
        return content

    # ------------------------------------------------------------------
    # Default unsupported implementations — return empty lists
    # Subclasses override per capability and set the matching supports_* flag.
    # ------------------------------------------------------------------

    def extract_imports(self, content: str, path: Path) -> list[ImportEdge]:
        """Default: unsupported. Returns []."""
        return []

    def extract_symbols(self, content: str, path: Path) -> list[SymbolDef]:
        """Default: unsupported. Returns []."""
        return []

    def extract_contracts(self, content: str, path: Path) -> list[ContractCandidate]:
        """Default: unsupported. Returns []."""
        return []

    def extract_runtime(self, content: str, path: Path) -> list[RuntimeSignal]:
        """Default: unsupported. Returns []."""
        _log.debug("extract_runtime: %s -- not supported by %s", path, self.__class__.__name__)
        return []

    def extract_writer_calls(
        self, content: str, path: Path
    ) -> list[AuthorityWriteCandidate]:
        """Default: unsupported. Returns []."""
        return []

    # ------------------------------------------------------------------
    # Shared ES-module / CommonJS import extraction algorithm
    # ------------------------------------------------------------------

    @staticmethod
    def _line_of(match_start: int, content: str) -> int:
        """Return the 1-based line number of *match_start* within *content*."""
        return content.count("\n", 0, match_start) + 1

    def _symbols_from_ordered_patterns(
        self,
        ordered: tuple[tuple[str, "Pattern[str]"], ...],
        cleaned: str,
    ) -> "list[SymbolDef]":
        """Collect SymbolDefs by iterating ordered (kind, regex) pairs over *cleaned*.

        Deduplicates by match start position so a declaration matched by multiple
        patterns is emitted only once (first-match-wins via ordering).
        """
        syms: list[SymbolDef] = []
        seen_positions: set[int] = set()
        for kind, pat in ordered:
            for m in pat.finditer(cleaned):
                pos = m.start()
                if pos in seen_positions:
                    continue
                seen_positions.add(pos)
                name = m.group("name")
                visibility = "public" if m.group("export") else "module"
                syms.append(SymbolDef(
                    name=name,
                    kind=kind,
                    line=self._line_of(pos, cleaned),
                    visibility=visibility,
                    confidence=0.9 if visibility == "public" else 0.8,
                ))
        syms.sort(key=lambda s: (s.line, s.name))
        return syms

    def _extract_imports_from_patterns(
        self,
        from_path_posix: str,
        multi_collapsed: str,
        was_multiline_in_source: bool,
        specific_patterns: tuple[Pattern[str], ...],
        side_effect_patterns: tuple[Pattern[str], ...],
        dynamic_pattern: Pattern[str],
        classify_fn: object,
    ) -> list[ImportEdge]:
        """Core ES-module / CJS import extraction loop shared by JS and TS adapters.

        Parameters:
            from_path_posix:        Posix path of the source file (used in ImportEdge).
            multi_collapsed:        Source text after comment-stripping and multiline
                                    import collapsing.
            was_multiline_in_source: True when the collapsing step changed the text;
                                    used to downgrade confidence to 0.7.
            specific_patterns:      Ordered tuple of compiled regexes for named/
                                    namespace/default/type/re-export forms. All must
                                    expose a ``module`` named group.
            side_effect_patterns:   Regexes for side-effect and bare require imports.
                                    Applied after *specific_patterns*; same group
                                    requirement.
            dynamic_pattern:        Regex for dynamic ``import('...')`` -- always
                                    emitted at confidence 0.7.
            classify_fn:            Callable(module: str) -> str -- returns
                                    ``"absolute"`` or ``"relative"``.

        Returns a list of ImportEdge sorted by (line, to_module, kind).
        """
        from typing import Callable
        _classify: Callable[[str], str] = classify_fn  # type: ignore[assignment]

        edges: list[ImportEdge] = []
        seen: set[tuple[int, str, str]] = set()

        def _emit(module: str, line: int, kind: str, base_confidence: float) -> None:
            if not module:
                return
            key = (line, module, kind)
            if key in seen:
                return
            seen.add(key)
            confidence = 0.7 if was_multiline_in_source else base_confidence
            edges.append(
                ImportEdge(
                    from_file=from_path_posix,
                    to_module=module,
                    kind=kind,
                    line=line,
                    confidence=confidence,
                )
            )

        # Specific forms first (named, namespace, default, type-only, re-export).
        for pat in specific_patterns:
            for m in pat.finditer(multi_collapsed):
                module = m.group("module")
                kind = _classify(module)
                base = 0.9 if kind == "absolute" else 0.8
                _emit(module, self._line_of(m.start(), multi_collapsed), kind, base)

        # Side-effect and bare require forms — run after specific patterns.
        for pat in side_effect_patterns:
            for m in pat.finditer(multi_collapsed):
                module = m.group("module")
                kind = _classify(module)
                base = 0.9 if kind == "absolute" else 0.8
                _emit(module, self._line_of(m.start(), multi_collapsed), kind, base)

        # Dynamic imports — always confidence 0.7 regardless of multiline.
        for m in dynamic_pattern.finditer(multi_collapsed):
            module = m.group("module")
            if not module:
                continue
            kind = _classify(module)
            line = self._line_of(m.start(), multi_collapsed)
            key = (line, module, kind)
            if key in seen:
                continue
            seen.add(key)
            edges.append(
                ImportEdge(
                    from_file=from_path_posix,
                    to_module=module,
                    kind=kind,
                    line=line,
                    confidence=0.7,
                )
            )

        edges.sort(key=lambda e: (e.line, e.to_module, e.kind))
        return edges
