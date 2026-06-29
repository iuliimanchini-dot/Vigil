"""Swift source adapter -- tree-sitter AST-based structural extractor.

Parses ``.swift`` files via tree-sitter (tree-sitter-swift grammar) for true
AST accuracy.  All extracted IR items carry ``confidence=1.0``.

Capabilities (full L5 + authority scope + Swift runtime):
    - supports_structural      = True  (extract_imports + extract_symbols)
    - supports_contracts       = True  (extract_contracts)
    - supports_runtime_signals = True  (extract_runtime)
    - supports_authority_writes = True (extract_writer_calls)

tree-sitter-swift node-type notes (verified via probe on tree-sitter==0.25):
    - ``import_declaration`` wraps an ``identifier`` whose text is the module
      name (e.g. ``import Foundation`` -> module ``"Foundation"``).
    - ``struct``, ``class``, AND ``enum`` ALL parse as ``class_declaration``.
      The keyword is disambiguated by the ``declaration_kind`` field
      (``"struct"`` / ``"class"`` / ``"enum"`` / ``"actor"``); the name is the
      ``name`` field (a ``type_identifier``).
    - ``protocol`` is its own ``protocol_declaration`` node (name in a
      ``type_identifier`` child).
    - ``function_declaration`` carries its name in a ``simple_identifier``
      child; visibility comes from a ``modifiers`` > ``visibility_modifier``.
    - ``@main`` (and other attributes) appear as an ``attribute`` node inside
      the declaration's ``modifiers`` child.
    - A call like ``data.write(to:)`` is a ``call_expression`` whose first
      named child is a ``navigation_expression`` (fields ``target`` + a
      ``navigation_suffix`` whose ``simple_identifier`` child is the method
      name); a bare call like ``Task { }`` has a ``simple_identifier`` callee.

Visibility rule (Swift):
    - ``"private"``  -- declaration has a ``private`` or ``fileprivate`` modifier.
    - ``"public"``   -- declaration has a ``public`` or ``open`` modifier.
    - ``"module"``   -- no explicit access modifier (Swift ``internal`` default).

Uses the shared ``_treesitter`` helpers, mirroring the Go/Java adapters.
"""
from __future__ import annotations

import logging
from pathlib import Path

from ._base import RegexAdapterBase
from ._ir import AuthorityWriteCandidate, ContractCandidate, ImportEdge, SymbolDef, TSRuntimeSignal
from ._treesitter import (
    iter_named_children,
    node_line,
    node_text,
    parse_bytes,
    walk_named,
)

__all__ = ["SwiftAdapter"]

_log = logging.getLogger(__name__)

_LANGUAGE = "swift"

# struct / class / enum all share the `class_declaration` node type; the
# `declaration_kind` field distinguishes them.  `actor` is included for
# completeness (Swift concurrency type) and maps to "class".
_TYPE_DECL_KIND: dict[str, str] = {
    "struct": "struct",
    "class": "class",
    "enum": "enum",
    "actor": "class",
}


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _declaration_kind(node) -> str | None:
    """Return the Swift keyword for a ``class_declaration`` node.

    tree-sitter-swift exposes the keyword via the ``declaration_kind`` field
    (``"struct"`` / ``"class"`` / ``"enum"`` / ``"actor"``).  Falls back to
    scanning the leading unnamed tokens if the field is absent.
    """
    fld = node.child_by_field_name("declaration_kind")
    if fld is not None:
        return fld.type
    for child in node.children:
        if not child.is_named and child.type in _TYPE_DECL_KIND:
            return child.type
    return None


def _type_decl_name(node, src: bytes) -> str:
    """Return the declared type name from a ``class_declaration`` /
    ``protocol_declaration`` node.

    Prefers the ``name`` field (a ``type_identifier``); falls back to the first
    named ``type_identifier`` child.
    """
    fld = node.child_by_field_name("name")
    if fld is not None:
        return node_text(fld, src)
    for child in node.children:
        if child.is_named and child.type == "type_identifier":
            return node_text(child, src)
    return ""


def _visibility(node, src: bytes) -> str:
    """Return Swift visibility for a declaration node.

    Reads the access modifier from the ``modifiers`` > ``visibility_modifier``
    child:
        - ``private`` / ``fileprivate`` -> ``"private"``
        - ``public`` / ``open``         -> ``"public"``
        - none (Swift ``internal`` default) -> ``"module"``
    """
    for child in node.children:
        if child.type != "modifiers":
            continue
        for mod in child.children:
            if mod.type != "visibility_modifier":
                continue
            token = node_text(mod, src).strip()
            if token in ("private", "fileprivate"):
                return "private"
            if token in ("public", "open"):
                return "public"
    return "module"


def _has_attribute(node, src: bytes, attr_name: str) -> bool:
    """True if *node*'s ``modifiers`` child contains an ``attribute`` whose
    name matches *attr_name* (e.g. ``"main"`` for ``@main``)."""
    for child in node.children:
        if child.type != "modifiers":
            continue
        for mod in child.children:
            if mod.type != "attribute":
                continue
            # attribute node text is e.g. "@main"; compare bare name.
            text = node_text(mod, src).lstrip("@").strip()
            if text == attr_name:
                return True
    return False


def _navigation_method(callee, src: bytes) -> tuple[str, str]:
    """Decompose a call callee into (receiver_text, method_name).

    For a ``navigation_expression`` (``recv.method``) returns
    (``recv`` text, ``method`` simple name).  For a bare ``simple_identifier``
    callee (``foo(...)``) returns ("", identifier text).  Otherwise ("", "").
    """
    if callee is None:
        return "", ""
    if callee.type == "simple_identifier":
        return "", node_text(callee, src)
    if callee.type == "navigation_expression":
        target = callee.child_by_field_name("target")
        receiver = node_text(target, src) if target is not None else ""
        # The method name is the simple_identifier inside the navigation_suffix.
        method = ""
        for child in callee.children:
            if child.type == "navigation_suffix":
                for gc in child.children:
                    if gc.is_named and gc.type == "simple_identifier":
                        method = node_text(gc, src)
                        break
                break
        return receiver, method
    return "", ""


def _call_callee(call) -> object | None:
    """Return the first named child of a ``call_expression`` that is the
    callee (skips the trailing ``call_suffix``)."""
    for child in call.children:
        if child.is_named and child.type != "call_suffix":
            return child
    return None


# ---------------------------------------------------------------------------
# Adapter
# ---------------------------------------------------------------------------

class SwiftAdapter(RegexAdapterBase):
    """Swift adapter -- AST-based structural extractor via tree-sitter.

    Operates on ``.swift`` files. Implements all four capability methods
    (structural, contracts, runtime, authority writes), each emitting IR
    signals at ``confidence=1.0``.  Follows the same structure as the Go and
    Java adapters and reuses the shared ``_treesitter`` helpers.
    """

    language = "swift"
    file_extensions = (".swift",)
    supports_structural = True
    supports_contracts = True
    supports_runtime_signals = True
    supports_authority_writes = True

    # ------------------------------------------------------------------
    # Structural: imports
    # ------------------------------------------------------------------

    def extract_imports(self, content: str, path: Path) -> list[ImportEdge]:
        """Return one ImportEdge per ``import_declaration`` in *content*.

        Handled forms:
            ``import Foundation``           -- module "Foundation"
            ``import UIKit``                -- module "UIKit"
            ``import struct Foo.Bar``       -- submodule path (best effort)

        All Swift imports are treated as absolute (no relative import syntax).
        """
        _log.debug("extract_imports (tree-sitter): %s (%d chars)", path, len(content))
        src: bytes = content.encode("utf-8", errors="replace")
        root = parse_bytes(_LANGUAGE, src)
        from_path = Path(path).as_posix()

        edges: list[ImportEdge] = []
        seen: set[tuple[int, str]] = set()

        for decl in iter_named_children(root, "import_declaration"):
            # The module name lives in an `identifier` child (which itself wraps
            # one or more simple_identifier tokens, dotted for submodules).
            module = ""
            for child in decl.children:
                if child.is_named and child.type == "identifier":
                    module = node_text(child, src).strip()
                    break
            if not module:
                continue
            line = node_line(decl)
            key = (line, module)
            if key in seen:
                continue
            seen.add(key)
            edges.append(ImportEdge(
                from_file=from_path,
                to_module=module,
                kind="absolute",
                line=line,
                confidence=1.0,
            ))

        edges.sort(key=lambda e: (e.line, e.to_module, e.kind))
        return edges

    # ------------------------------------------------------------------
    # Structural: symbols
    # ------------------------------------------------------------------

    def extract_symbols(self, content: str, path: Path) -> list[SymbolDef]:
        """Return one SymbolDef per top-level declaration in *content*.

        Detected kinds:
            struct    -- ``struct X { ... }``      (class_declaration kind=struct)
            class     -- ``class X { ... }`` / ``actor X`` (class_declaration)
            enum      -- ``enum X { ... }``        (class_declaration kind=enum)
            protocol  -- ``protocol X { ... }``    (protocol_declaration)
            function  -- top-level ``func name(...)``

        Visibility:
            - ``"private"`` for ``private`` / ``fileprivate`` declarations.
            - ``"public"``  for ``public`` / ``open`` declarations.
            - ``"module"``  otherwise (Swift ``internal`` default).

        Only top-level declarations are emitted: members live inside a
        ``class_body`` / ``protocol_body`` and are not direct children of the
        ``source_file`` root.
        """
        _log.debug("extract_symbols (tree-sitter): %s (%d chars)", path, len(content))
        src: bytes = content.encode("utf-8", errors="replace")
        root = parse_bytes(_LANGUAGE, src)

        syms: list[SymbolDef] = []

        for node in root.children:
            if not node.is_named:
                continue

            if node.type == "class_declaration":
                kw = _declaration_kind(node)
                kind = _TYPE_DECL_KIND.get(kw or "", "class")
                name = _type_decl_name(node, src)
                if not name:
                    continue
                syms.append(SymbolDef(
                    name=name,
                    kind=kind,
                    line=node_line(node),
                    visibility=_visibility(node, src),
                    confidence=1.0,
                ))

            elif node.type == "protocol_declaration":
                name = _type_decl_name(node, src)
                if not name:
                    continue
                syms.append(SymbolDef(
                    name=name,
                    kind="protocol",
                    line=node_line(node),
                    visibility=_visibility(node, src),
                    confidence=1.0,
                ))

            elif node.type == "function_declaration":
                name = ""
                for child in node.children:
                    if child.is_named and child.type == "simple_identifier":
                        name = node_text(child, src)
                        break
                if not name:
                    continue
                syms.append(SymbolDef(
                    name=name,
                    kind="function",
                    line=node_line(node),
                    visibility=_visibility(node, src),
                    confidence=1.0,
                ))

        syms.sort(key=lambda s: (s.line, s.name))
        return syms

    # ------------------------------------------------------------------
    # Contracts: struct / class / protocol / enum type declarations
    # ------------------------------------------------------------------

    def extract_contracts(self, content: str, path: Path) -> list[ContractCandidate]:
        """Return one ContractCandidate per top-level declared type.

        Handled forms (``contract_kind`` = the Swift keyword):
            ``struct X { ... }``     → contract_kind="struct"
            ``class X { ... }``      → contract_kind="class"  (``actor`` too)
            ``protocol X { ... }``   → contract_kind="protocol"
            ``enum X { ... }``       → contract_kind="enum"

        Top-level types only: nested types live inside a ``class_body`` and are
        not direct children of the ``source_file`` root.

        Test files (path name ending with ``Tests.swift`` or ``Test.swift``)
        return ``[]``.

        All results carry ``confidence=1.0`` (AST-based extraction).
        Results are sorted by ``(line, name)``.
        """
        if _is_swift_test_file(path):
            return []

        _log.debug("extract_contracts (tree-sitter): %s (%d chars)", path, len(content))
        src: bytes = content.encode("utf-8", errors="replace")
        root = parse_bytes(_LANGUAGE, src)

        candidates: list[ContractCandidate] = []

        for node in root.children:
            if not node.is_named:
                continue

            if node.type == "class_declaration":
                kw = _declaration_kind(node)
                contract_kind = _TYPE_DECL_KIND.get(kw or "")
                if contract_kind is None:
                    continue
                # `actor` maps to "class" in _TYPE_DECL_KIND; preserve the
                # exact Swift keyword for contract_kind when it is one of the
                # canonical contract keywords.
                if kw in ("struct", "class", "enum"):
                    contract_kind = kw
                name = _type_decl_name(node, src)
                if not name:
                    continue
                candidates.append(ContractCandidate(
                    name=name,
                    contract_kind=contract_kind,
                    line=node_line(node),
                    confidence=1.0,
                ))

            elif node.type == "protocol_declaration":
                name = _type_decl_name(node, src)
                if not name:
                    continue
                candidates.append(ContractCandidate(
                    name=name,
                    contract_kind="protocol",
                    line=node_line(node),
                    confidence=1.0,
                ))

        candidates.sort(key=lambda c: (c.line, c.name))
        return candidates

    # ------------------------------------------------------------------
    # Runtime signals: @main entrypoint, top-level effects in main.swift,
    # Task { } and DispatchQueue concurrency spawns.
    # ------------------------------------------------------------------

    def extract_runtime(self, content: str, path: Path) -> list[TSRuntimeSignal]:
        """Detect Swift entrypoint and concurrency side effects via tree-sitter AST.

        Emits TSRuntimeSignal (confidence=1.0) for:
            ``@main struct/class X``  (attribute on a type declaration)
                → kind="entrypoint", payload={"call": <type name>}
            top-level statements in a file named ``main.swift`` (Swift treats
            ``main.swift`` as executable script scope)
                → kind="top_level_effect", payload={"call": "main.swift"}
            ``Task { ... }``  (structured-concurrency task spawn)
                → kind="background_job", payload={"call": "Task"}
            ``DispatchQueue....async { ... }`` / ``.sync`` (GCD dispatch)
                → kind="background_job", payload={"call": "DispatchQueue.<m>"}

        Test files return ``[]``.  Results are sorted by ``(line, kind)``.
        """
        if _is_swift_test_file(path):
            return []

        _log.debug("extract_runtime (tree-sitter): %s (%d chars)", path, len(content))
        src: bytes = content.encode("utf-8", errors="replace")
        root = parse_bytes(_LANGUAGE, src)
        file_posix = Path(path).as_posix()
        is_main_swift = Path(path).name == "main.swift"

        signals: list[TSRuntimeSignal] = []

        # --- Pass 1: @main attribute on a top-level type declaration ---
        for node in root.children:
            if not node.is_named or node.type != "class_declaration":
                continue
            if _has_attribute(node, src, "main"):
                signals.append(TSRuntimeSignal(
                    kind="entrypoint",
                    file=file_posix,
                    line=node_line(node),
                    confidence=1.0,
                    payload={"call": _type_decl_name(node, src) or "main"},
                ))

        # --- Pass 2: top-level executable statements in main.swift ---
        # Swift runs top-level code only in a file literally named main.swift.
        # We surface a single import-time effect signal if such a file has any
        # top-level call_expression / property_declaration with a side effect.
        if is_main_swift:
            for node in root.children:
                if not node.is_named:
                    continue
                if node.type in ("call_expression", "property_declaration", "assignment"):
                    signals.append(TSRuntimeSignal(
                        kind="top_level_effect",
                        file=file_posix,
                        line=node_line(node),
                        confidence=1.0,
                        payload={"call": "main.swift"},
                    ))
                    break  # one signal per file is enough (script entry scope)

        # --- Pass 3: concurrency spawns anywhere in the file ---
        for call in walk_named(root, "call_expression"):
            callee = _call_callee(call)
            receiver, method = _navigation_method(callee, src)

            # Task { ... }  (bare identifier callee with a trailing closure)
            if not receiver and method == "Task":
                signals.append(TSRuntimeSignal(
                    kind="background_job",
                    file=file_posix,
                    line=node_line(call),
                    confidence=1.0,
                    payload={"call": "Task"},
                ))
                continue

            # DispatchQueue.*.async { } / .sync { }
            if method in ("async", "sync") and "DispatchQueue" in receiver:
                signals.append(TSRuntimeSignal(
                    kind="background_job",
                    file=file_posix,
                    line=node_line(call),
                    confidence=1.0,
                    payload={"call": f"DispatchQueue.{method}"},
                ))

        signals.sort(key=lambda s: (s.line, s.kind))
        return signals

    # ------------------------------------------------------------------
    # Authority writes
    # ------------------------------------------------------------------

    def extract_writer_calls(
        self, content: str, path: Path
    ) -> list[AuthorityWriteCandidate]:
        """Detect write operations in Swift source via tree-sitter AST.

        Walks all ``call_expression`` nodes and matches writer patterns by the
        called method (the ``navigation_suffix`` of a ``navigation_expression``
        callee):

        - ``data.write(to: url)``  (Data / String write-to-URL)
              → ``write_kind="fs_write"``, target_hint = receiver text
        - ``FileManager.*.createFile(...)`` / ``.removeItem(...)`` /
          ``.copyItem(...)`` / ``.moveItem(...)``  (FileManager mutations)
              → ``write_kind="fs_write"``, target_hint = receiver text
        - ``*.save(...)``  (Core Data / repository save)
              → ``write_kind="orm_save"``, target_hint = receiver text
        - ``*.write(...)``  (any other receiver — stream/handle write)
              → ``write_kind="fs_write"``, target_hint = receiver text

        Test files return ``[]``.  All results carry ``confidence=1.0``.
        Results are sorted by ``(line, write_kind)``.
        """
        if _is_swift_test_file(path):
            return []

        _log.debug("extract_writer_calls (tree-sitter): %s (%d chars)", path, len(content))
        src: bytes = content.encode("utf-8", errors="replace")
        root = parse_bytes(_LANGUAGE, src)

        candidates: list[AuthorityWriteCandidate] = []

        def _hint(text: str) -> str:
            """Strip surrounding quotes and cap at 30 chars."""
            t = text.strip().strip('"\'`').strip()
            return t[:30]

        _FILEMANAGER_METHODS = frozenset({
            "createFile", "removeItem", "copyItem", "moveItem",
        })

        for call in walk_named(root, "call_expression"):
            callee = _call_callee(call)
            if callee is None or callee.type != "navigation_expression":
                continue
            receiver, method = _navigation_method(callee, src)
            if not method:
                continue
            line = node_line(call)

            # FileManager mutations (createFile/removeItem/copyItem/moveItem)
            if method in _FILEMANAGER_METHODS:
                candidates.append(AuthorityWriteCandidate(
                    write_kind="fs_write",
                    target_hint=_hint(receiver),
                    line=line,
                    confidence=1.0,
                ))

            # *.save(...) — Core Data / repository persistence
            elif method == "save":
                candidates.append(AuthorityWriteCandidate(
                    write_kind="orm_save",
                    target_hint=_hint(receiver),
                    line=line,
                    confidence=1.0,
                ))

            # *.write(...) — Data.write(to:), stream/handle writes
            elif method == "write":
                candidates.append(AuthorityWriteCandidate(
                    write_kind="fs_write",
                    target_hint=_hint(receiver),
                    line=line,
                    confidence=1.0,
                ))

        candidates.sort(key=lambda c: (c.line, c.write_kind))
        return candidates


# ---------------------------------------------------------------------------
# Module-level test-file helper
# ---------------------------------------------------------------------------

def _is_swift_test_file(path: Path) -> bool:
    """True if *path* looks like a Swift test file.

    XCTest convention: files ending ``Tests.swift`` (e.g. ``FooTests.swift``)
    or ``Test.swift``; mirrors the Go/Java adapters' test-file exclusion so
    contracts/runtime/authority maps skip test fixtures.
    """
    name = Path(path).name
    return name.endswith("Tests.swift") or name.endswith("Test.swift")
