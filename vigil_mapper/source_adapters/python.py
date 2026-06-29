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
        """Parse *content* with ``ast`` and return one ImportEdge per import token.

        Reproduces the full import-target richness that the structural map builder
        historically extracted for Python via ``parse_cache._extract_imports_out``
        (the production AST path) plus the slow-path ``_extract_imports`` donor:

            ``import X`` / ``import X.Y`` -- one edge per dotted alias name.
            ``from X import a, b``        -- edge for ``X`` AND edges for the
                                             sub-module candidates ``X.a`` / ``X.b``
                                             (so ``from pkg import sub`` resolves to
                                             ``pkg/sub.py``). ``*`` is skipped.
            ``from .X import a``          -- relative; leading dots preserved on the
                                             module (``.X``). When there is no module
                                             (``from . import a``) the candidate is
                                             ``.a`` (dots + name).
            dynamic ``importlib.import_module("m")`` / ``__import__("m")`` -- edge for
                                             the literal module string.

        Emission ORDER and de-duplication match ``_extract_imports_out`` exactly:
        a single ``ast.walk`` pass, each new ``to_module`` emitted once in first-seen
        order.  Structural builder consumes ``e.to_module`` (dedup, order-preserving),
        so this ordering is load-bearing for parity.

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

        from_posix = path.as_posix()
        imports: list[ImportEdge] = []
        seen: set[str] = set()

        def _emit(module: str, kind: str, line: int) -> None:
            if not module or module in seen:
                return
            seen.add(module)
            imports.append(
                ImportEdge(
                    from_file=from_posix,
                    to_module=module,
                    kind=kind,
                    line=line,
                    confidence=1.0,
                )
            )

        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    _emit(alias.name, "absolute", node.lineno)

            elif isinstance(node, ast.ImportFrom):
                level = node.level or 0
                if level == 0 and node.module:
                    _emit(node.module, "absolute", node.lineno)
                    for alias in node.names:
                        if alias.name != "*":
                            _emit("%s.%s" % (node.module, alias.name), "absolute", node.lineno)
                elif level > 0:
                    dots = "." * level
                    if node.module:
                        _emit(dots + node.module, "relative", node.lineno)
                    else:
                        for alias in node.names:
                            if alias.name != "*":
                                _emit(dots + alias.name, "relative", node.lineno)

            elif isinstance(node, ast.Call):
                func = node.func
                if (
                    isinstance(func, ast.Attribute)
                    and func.attr == "import_module"
                ) or (isinstance(func, ast.Name) and func.id == "__import__"):
                    if node.args and isinstance(node.args[0], ast.Constant) and isinstance(
                        node.args[0].value, str
                    ):
                        _emit(node.args[0].value, "absolute", getattr(node, "lineno", 0))

        return imports

    def extract_symbols(self, content: str, path: Path) -> list[SymbolDef]:
        """Parse *content* with ``ast`` and return class/function defs at ANY scope.

        Walks the whole tree (``ast.walk``) so nested classes, methods, and inner
        functions are all emitted -- matching the structural map builder's historic
        ``_extract_symbols_defined`` / ``parse_cache`` behaviour (which collected
        every ``ClassDef`` / ``FunctionDef`` / ``AsyncFunctionDef`` name).  Order is
        ``ast.walk`` order, which is what the builder serialises.

        Visibility follows Python convention: names starting with ``_`` are
        ``"private"``, all others ``"public"``.

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

        for node in ast.walk(tree):
            if isinstance(node, ast.ClassDef):
                kind = "class"
            elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                kind = "function"
            else:
                continue
            syms.append(
                SymbolDef(
                    name=node.name,
                    kind=kind,
                    line=node.lineno,
                    visibility=("private" if node.name.startswith("_") else "public"),
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

    # Serializer methods whose bodies are scanned for emitted dict keys.
    # Mirrors data_contract_builder._SERIALIZER_METHODS exactly.
    _SERIALIZER_METHODS = frozenset({"to_dict", "to_json", "dict", "model_dump"})

    @staticmethod
    def _contract_shape(cls: ast.ClassDef) -> "dict[str, str]":
        """Top-level annotated fields of *cls* -> {field: annotation}.

        Iterates ``cls.body`` directly (NOT ast.walk) so AnnAssign statements
        inside method bodies are never mistaken for class fields.  Identical to
        data_contract_builder._extract_shape.
        """
        shape: dict[str, str] = {}
        for stmt in cls.body:
            if isinstance(stmt, ast.AnnAssign) and isinstance(stmt.target, ast.Name):
                try:
                    ann = ast.unparse(stmt.annotation)
                except Exception:
                    ann = "<unknown>"
                shape[stmt.target.id] = ann
        return shape

    @classmethod
    def _contract_serializer_shapes(cls, node: ast.ClassDef) -> "dict[str, list[str]]":
        """Serializer-method -> emitted literal string dict keys.

        Identical to data_contract_builder._extract_serializer_shapes.
        """
        result: dict[str, list[str]] = {}
        for stmt in node.body:
            if not isinstance(stmt, ast.FunctionDef) or stmt.name not in cls._SERIALIZER_METHODS:
                continue
            keys = [
                k.value
                for n in ast.walk(stmt)
                if isinstance(n, ast.Dict)
                for k in n.keys
                if isinstance(k, ast.Constant) and isinstance(k.value, str)
            ]
            result[stmt.name] = keys
        return result

    def extract_contracts(self, content: str, path: Path) -> list[ContractCandidate]:
        """Detect data-contract classes via ``ast`` (parity with Go/Java/TS).

        Emits a ``ContractCandidate`` per detected entity, populated with the
        full per-file richness the data_contract map builder historically
        extracted via its internal ``_scan_file`` (``shape`` of top-level
        annotated fields + ``serializer_shapes`` of ``to_dict``/``to_json``/
        ``dict``/``model_dump`` methods).  Cross-file aggregation (writers,
        readers, drift, canonical selection) remains the builder's job.
        """
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
                    name=node.name,
                    contract_kind=kind,
                    line=node.lineno,
                    confidence=1.0,
                    shape=self._contract_shape(node),
                    serializer_shapes=self._contract_serializer_shapes(node),
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
