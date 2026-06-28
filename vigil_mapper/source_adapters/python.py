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
    # AST helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _dotted(node: ast.AST) -> str:
        """Return the dotted name of a Name/Attribute chain (best effort)."""
        parts: list[str] = []
        cur = node
        while isinstance(cur, ast.Attribute):
            parts.append(cur.attr)
            cur = cur.value
        if isinstance(cur, ast.Name):
            parts.append(cur.id)
        return ".".join(reversed(parts))

    @staticmethod
    def _receiver_hint(func_node: ast.AST) -> str:
        """For an attribute call ``x.write_text(...)`` return the receiver name."""
        if isinstance(func_node, ast.Attribute):
            recv = func_node.value
            if isinstance(recv, ast.Name):
                return recv.id
            if isinstance(recv, ast.Attribute):
                return recv.attr
        return ""

    # ------------------------------------------------------------------
    # Contracts: @dataclass / NamedTuple / TypedDict / pydantic.BaseModel
    # ------------------------------------------------------------------

    def extract_contracts(self, content: str, path: Path) -> list[ContractCandidate]:
        """Detect data-contract classes via ``ast`` (parity with Go/Java/TS)."""
        try:
            tree = ast.parse(content)
        except SyntaxError:
            return []
        out: list[ContractCandidate] = []
        for node in ast.walk(tree):
            if not isinstance(node, ast.ClassDef):
                continue
            kind: str | None = None
            for dec in node.decorator_list:
                target = dec.func if isinstance(dec, ast.Call) else dec
                if self._dotted(target).split(".")[-1] == "dataclass":
                    kind = "dataclass"
                    break
            if kind is None:
                for base in node.bases:
                    leaf = self._dotted(base).split(".")[-1]
                    if leaf == "BaseModel":
                        kind = "pydantic_model"
                        break
                    if leaf == "TypedDict":
                        kind = "TypedDict"
                        break
                    if leaf == "NamedTuple":
                        kind = "NamedTuple"
                        break
            if kind:
                out.append(ContractCandidate(
                    name=node.name, contract_kind=kind, line=node.lineno, confidence=1.0,
                ))
        return out

    # ------------------------------------------------------------------
    # Runtime: import-time side effects, decorator registries, env reads
    # ------------------------------------------------------------------

    _REGISTRY_DECORATORS = frozenset({
        "route", "register", "task", "command", "on_event",
        "get", "post", "put", "delete", "fixture", "app",
    })

    def extract_runtime(self, content: str, path: Path) -> list[RuntimeSignal]:
        """Detect import-time side effects / decorator registries / env reads via ``ast``."""
        try:
            tree = ast.parse(content)
        except SyntaxError:
            return []
        out: list[RuntimeSignal] = []
        # module-level bare calls = import-time side effects
        for stmt in tree.body:
            if isinstance(stmt, ast.Expr) and isinstance(stmt.value, ast.Call):
                fname = self._dotted(stmt.value.func)
                out.append(RuntimeSignal(
                    signal_kind="import_time_side_effects",
                    detail=f"module-level call {fname}()",
                    line=stmt.lineno, confidence=0.8,
                ))
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                fn = self._dotted(node.func)
                if fn in ("os.getenv",) or fn.endswith("environ.get") or fn.endswith("os.environ"):
                    out.append(RuntimeSignal(
                        signal_kind="env_var_read", detail=fn,
                        line=int(getattr(node, "lineno", 0) or 0), confidence=0.9,
                    ))
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                for dec in node.decorator_list:
                    target = dec.func if isinstance(dec, ast.Call) else dec
                    dn = self._dotted(target)
                    if dn.split(".")[-1] in self._REGISTRY_DECORATORS:
                        out.append(RuntimeSignal(
                            signal_kind="decorator_registry",
                            detail=f"@{dn} on {node.name}",
                            line=node.lineno, confidence=0.7,
                        ))
        return out

    # ------------------------------------------------------------------
    # Authority writes: .write_text/.write_bytes/.save/json.dump/open("w")
    # ------------------------------------------------------------------

    def extract_writer_calls(
        self, content: str, path: Path
    ) -> list[AuthorityWriteCandidate]:
        """Detect write/save operations via ``ast`` (parity with other adapters)."""
        try:
            tree = ast.parse(content)
        except SyntaxError:
            return []
        out: list[AuthorityWriteCandidate] = []
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            fn = self._dotted(node.func)
            leaf = fn.split(".")[-1]
            ln = int(getattr(node, "lineno", 0) or 0)
            if leaf in ("write_text", "write_bytes"):
                out.append(AuthorityWriteCandidate(
                    write_kind=leaf, target_hint=self._receiver_hint(node.func),
                    line=ln, confidence=0.9,
                ))
            elif leaf == "save":
                out.append(AuthorityWriteCandidate(
                    write_kind="save", target_hint=self._receiver_hint(node.func),
                    line=ln, confidence=0.7,
                ))
            elif fn in ("json.dump",):
                out.append(AuthorityWriteCandidate(
                    write_kind="json_dump", target_hint="", line=ln, confidence=0.9,
                ))
            elif leaf == "open" and len(node.args) >= 2:
                mode = node.args[1]
                if (
                    isinstance(mode, ast.Constant)
                    and isinstance(mode.value, str)
                    and any(c in mode.value for c in "wax+")
                ):
                    out.append(AuthorityWriteCandidate(
                        write_kind="open_write", target_hint="", line=ln, confidence=0.8,
                    ))
        return out
