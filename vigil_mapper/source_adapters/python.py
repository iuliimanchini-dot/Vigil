"""Python source adapter -- wraps stdlib ``ast`` for IR signal extraction.

Does NOT use regex. Does NOT depend on ``_lexer``. Uses ``ast.parse``
exclusively, inheriting empty-list fallbacks from ``RegexAdapterBase`` for
capability methods not yet wired into builders (L1 stubs).

Capabilities:
    - extract_imports: working AST walker (``ast.Import`` / ``ast.ImportFrom``).
    - extract_symbols: working AST walker (top-level class / function defs).
    - extract_contracts: L1 stub -- returns []. L3+ wires data_contract_builder.
    - extract_runtime: L1 stub -- returns []. L3+ wires runtime_builder.
    - extract_writer_calls: L1 stub -- returns []. L3+ wires authority_builder.

Builders do NOT consume IR in L1 -- they continue calling their internal
helpers directly. PythonAdapter is ready for L2+ dispatch wiring.
"""
from __future__ import annotations

import ast
import logging
from pathlib import Path

from ._base import RegexAdapterBase
from ._ir import (
    AuthorityWriteCandidate,
    ContractCandidate,
    ImportEdge,
    RuntimeSignal,
    SymbolDef,
)

__all__ = ["PythonAdapter"]

_log = logging.getLogger(__name__)


class PythonAdapter(RegexAdapterBase):
    """Python adapter using stdlib ``ast``. All four map capabilities declared.

    extract_imports and extract_symbols are fully implemented via AST walking.
    extract_contracts, extract_runtime, and extract_writer_calls are L1 stubs
    that return empty lists -- their existing builder implementations remain
    authoritative until L3+ dispatch wiring.
    """

    language = "python"
    file_extensions = (".py",)
    supports_structural = True
    supports_contracts = True
    supports_runtime_signals = True
    supports_authority_writes = True

    # ------------------------------------------------------------------
    # Structural: imports + symbols
    # ------------------------------------------------------------------

    def extract_imports(self, content: str, path: Path) -> list[ImportEdge]:
        """Parse *content* with ``ast`` and return one ImportEdge per import.

        Handles:
            ``import X`` -- kind="absolute"
            ``import X as Y`` -- kind="absolute" (alias ignored; module name kept)
            ``from X import Y`` -- kind="absolute"
            ``from .X import Y`` -- kind="relative" (leading dots preserved)
            ``from ..X import Y`` -- kind="relative"

        Returns [] on ``SyntaxError`` without raising.
        """
        try:
            tree = ast.parse(content)
        except SyntaxError as exc:
            _log.debug(
                "extract_imports: SyntaxError in %s at line %s -- returning []",
                path,
                getattr(exc, "lineno", "?"),
            )
            return []

        imports: list[ImportEdge] = []

        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    imports.append(
                        ImportEdge(
                            from_file=path.as_posix(),
                            to_module=alias.name,
                            kind="absolute",
                            line=node.lineno,
                            confidence=1.0,
                        )
                    )

            elif isinstance(node, ast.ImportFrom):
                if node.module is None:
                    # ``from . import X`` — no module name; emit one edge per name
                    dots = "." * (node.level or 0)
                    for alias in node.names:
                        imports.append(
                            ImportEdge(
                                from_file=path.as_posix(),
                                to_module=f"{dots}{alias.name}",
                                kind="relative",
                                line=node.lineno,
                                confidence=1.0,
                            )
                        )
                else:
                    dots = "." * (node.level or 0)
                    kind = "relative" if node.level else "absolute"
                    imports.append(
                        ImportEdge(
                            from_file=path.as_posix(),
                            to_module=f"{dots}{node.module}",
                            kind=kind,
                            line=node.lineno,
                            confidence=1.0,
                        )
                    )

        return imports

    def extract_symbols(self, content: str, path: Path) -> list[SymbolDef]:
        """Parse *content* with ``ast`` and return top-level class/function defs.

        Only inspects ``tree.body`` (module-level statements) -- nested classes
        and functions are not emitted in L1. Visibility follows Python convention:
        names starting with ``_`` are ``"private"``, all others ``"public"``.

        Returns [] on ``SyntaxError`` without raising.
        """
        try:
            tree = ast.parse(content)
        except SyntaxError as exc:
            _log.debug(
                "extract_symbols: SyntaxError in %s at line %s -- returning []",
                path,
                getattr(exc, "lineno", "?"),
            )
            return []

        syms: list[SymbolDef] = []

        for node in tree.body:
            if isinstance(node, ast.ClassDef):
                syms.append(
                    SymbolDef(
                        name=node.name,
                        kind="class",
                        line=node.lineno,
                        visibility=(
                            "private" if node.name.startswith("_") else "public"
                        ),
                        confidence=1.0,
                    )
                )
            elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                syms.append(
                    SymbolDef(
                        name=node.name,
                        kind="function",
                        line=node.lineno,
                        visibility=(
                            "private" if node.name.startswith("_") else "public"
                        ),
                        confidence=1.0,
                    )
                )

        return syms

    # ------------------------------------------------------------------
    # L1 stubs — existing builders remain authoritative until L3+
    # ------------------------------------------------------------------

    def extract_contracts(self, content: str, path: Path) -> list[ContractCandidate]:
        """L1 stub: returns [].

        TODO L3+: extract @dataclass, NamedTuple, TypedDict, pydantic.BaseModel
        detection from data_contract_builder and consume ContractCandidate here.
        """
        return []

    def extract_runtime(self, content: str, path: Path) -> list[RuntimeSignal]:
        """L1 stub: returns [].

        TODO L3+: extract import-time side effects, decorator registries, and
        background task patterns from _runtime_ast and emit RuntimeSignal here.
        """
        return []

    def extract_writer_calls(
        self, content: str, path: Path
    ) -> list[AuthorityWriteCandidate]:
        """L1 stub: returns [].

        TODO L3+: extract .write_text, .write_bytes, .save, json.dump, open("w")
        patterns from authority_builder and emit AuthorityWriteCandidate here.
        """
        return []
