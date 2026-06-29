"""IR (Intermediate Representation) signal dataclasses for source adapters.

Each dataclass represents one extracted piece of information from a source file.
Builders consume these signals in L2+ to decouple language parsing from map semantics.

L1: defined and populated by PythonAdapter; builders still use internal logic directly.
L2+: builders switch to consuming IR signals via adapter dispatch.
"""
from __future__ import annotations

from dataclasses import dataclass, field
import logging
_log = logging.getLogger(__name__)

__all__ = [
    "ImportEdge",
    "SymbolDef",
    "ContractCandidate",
    "RuntimeSignal",
    "TSRuntimeSignal",
    "AuthorityWriteCandidate",
]


@dataclass(frozen=True)
class ImportEdge:
    """A single import relationship extracted from a source file.

    Attributes:
        from_file: Posix path of the file containing the import statement.
        to_module: Dotted module name being imported (may include leading dots
                   for relative imports, e.g. ``".sibling"``).
        kind: ``"absolute"`` or ``"relative"``.
        line: 1-based line number of the import statement in the source file.
        confidence: Extraction confidence in [0.0, 1.0].
                    AST-based extractions emit 1.0; regex-based may be lower.
    """

    from_file: str
    to_module: str
    kind: str        # "absolute" | "relative"
    line: int
    confidence: float


@dataclass(frozen=True)
class SymbolDef:
    """A top-level symbol (class or function) defined in a source file.

    Attributes:
        name: Symbol identifier (e.g. ``"MyClass"`` or ``"my_function"``).
        kind: ``"class"`` or ``"function"``.
        line: 1-based line number of the definition.
        visibility: ``"public"`` (no leading underscore) or ``"private"``.
        confidence: Extraction confidence in [0.0, 1.0].
    """

    name: str
    kind: str        # "class" | "function"
    line: int
    visibility: str  # "public" | "private"
    confidence: float


@dataclass(frozen=True)
class ContractCandidate:
    """A data-contract-style type definition detected in a source file.

    Covers: ``@dataclass``, ``NamedTuple``, ``TypedDict``, ``pydantic.BaseModel``.

    Attributes:
        name: Class name.
        contract_kind: Detection pattern, e.g. ``"dataclass"``, ``"TypedDict"``,
                       ``"NamedTuple"``, ``"pydantic_model"``.
        line: 1-based line number.
        confidence: Extraction confidence in [0.0, 1.0].
        shape: Optional mapping of field-name -> annotation string for the
               entity's top-level annotated fields.  Populated by adapters that
               can resolve member types (PythonAdapter); empty for regex
               adapters (Go/Java/TS) that only detect the entity name+kind.
        serializer_shapes: Optional mapping of serializer-method-name -> list of
               literal string dict keys produced by that method (e.g. ``to_dict``
               returning ``{"a": ...}`` -> ``{"to_dict": ["a"]}``).  Empty for
               adapters that do not analyse serializer bodies.
    """

    name: str
    contract_kind: str
    line: int
    confidence: float
    # Optional richer fields (additive; default empty so existing regex adapters
    # and their parity tests are unaffected).
    shape: "dict[str, str]" = field(default_factory=dict)
    serializer_shapes: "dict[str, list[str]]" = field(default_factory=dict)


@dataclass(frozen=True)
class RuntimeSignal:
    """An import-time side effect or dynamic registration pattern.

    Covers: import-time side effects, ``@decorator`` registries, background
    task spawns, ``os.environ`` / ``os.getenv`` reads.

    Attributes:
        signal_kind: Category tag, e.g. ``"import_time_side_effects"``,
                     ``"decorator_registry"``, ``"background_task"``,
                     ``"env_var_read"``.
        detail: Human-readable description of the detected pattern.
        line: 1-based line number (0 if unavailable).
        confidence: Extraction confidence in [0.0, 1.0].
    """

    signal_kind: str
    detail: str
    line: int
    confidence: float


@dataclass(frozen=True)
class TSRuntimeSignal:
    """A runtime signal extracted from a TypeScript/TSX source file.

    Used by TypescriptAdapter.extract_runtime() to represent framework routes,
    middleware, server bootstrap, background jobs, and environment variable
    reads detected via regex.

    Attributes:
        kind: Signal category -- ``"framework_route"``, ``"middleware"``,
              ``"module_init"``, ``"background_job"``, or ``"env_access"``.
        file: Posix path of the source file (relative to project root when
              available, absolute otherwise).
        line: 1-based line number of the detected pattern.
        confidence: Extraction confidence in [0.0, 1.0].
        payload: Kind-specific detail dict.  Keys vary per kind:
                 ``framework_route``: ``route_path``, ``http_methods``, ``framework``
                 ``middleware``:      ``framework``
                 ``module_init``:     ``call``
                 ``background_job``:  ``call``
                 ``env_access``:      ``env_var``
    """

    kind: str         # "framework_route" | "middleware" | "module_init" | "background_job" | "env_access"
    file: str         # posix path
    line: int
    confidence: float
    payload: dict     # kind-specific detail


@dataclass(frozen=True)
class AuthorityWriteCandidate:
    """A write/save operation that may indicate data-authority ownership.

    Covers: ``.write_text()``, ``.write_bytes()``, ``.save()``, ``json.dump()``,
    ``open(..., "w")``, and similar patterns.

    Attributes:
        write_kind: Pattern category, e.g. ``"write_text"``, ``"json_dump"``,
                    ``"open_write"``.
        target_hint: Best-effort string identifying the write target (variable
                     name or path fragment) -- empty string if unknown.
        line: 1-based line number.
        confidence: Extraction confidence in [0.0, 1.0].
    """

    write_kind: str
    target_hint: str
    line: int
    confidence: float
