"""Go source adapter -- tree-sitter AST-based structural extractor.

Parses ``.go`` files via tree-sitter for true AST accuracy, replacing the
former regex+lexer approach.  All extracted IR items carry ``confidence=1.0``.

Capabilities (L5 + authority scope + Go runtime):
    - supports_structural      = True  (extract_imports + extract_symbols)
    - supports_contracts       = True  (extract_contracts)
    - supports_runtime_signals = True  (extract_runtime)
    - supports_authority_writes = True  (extract_writer_calls)

Import forms handled:
    ``import "pkg"``              -- single unaliased
    ``import alias "pkg"``        -- single aliased
    ``import _ "pkg"``            -- blank import
    ``import ( "pkg" ... )``      -- grouped block (all entry forms above)

Symbol kinds extracted (top-level only):
    function  -- ``func Name(``           (NOT method declarations with receiver)
    struct    -- ``type X struct``
    interface -- ``type X interface``
    type      -- ``type X = ...``         (type alias, via type_alias node)
                 ``type X SomeType``      (type definition, via type_spec node)
    const     -- ``const X`` / ``const ( X ... )``
                 ``var X``  / ``var ( X ... )``  (emitted as kind="const" for
                                                   parity with the prior adapter)

Visibility rule (Go):
    - ``"public"``  -- name starts with an uppercase letter (exported)
    - ``"module"``  -- name starts with a lowercase letter (unexported)

Uses shared ``_treesitter`` helpers; Java/JS/TS adapters will reuse the same
module.  The public interface (class name, method signatures, flags,
file_extensions) is identical to the former regex adapter.
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

__all__ = ["GoAdapter"]

_log = logging.getLogger(__name__)

_LANGUAGE = "go"

# Target-resolution constants (mirror _authority_ast.py provenance levels so the
# Go adapter speaks the same provenance vocabulary as the Python resolver).
_UNKNOWN_TARGET = "__unknown_target__"
_PROVENANCE_PATH_CONSTRUCTOR = "path_constructor"  # filepath.Join(...), path.Join(...)
_PROVENANCE_STRING_LITERAL = "string_literal"      # "literal_path"
_PROVENANCE_FUNCTION_PARAM = "function_parameter"  # func f(target string)
_PROVENANCE_UNKNOWN = "unknown"


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _visibility(name: str) -> str:
    """Return Go visibility based on first character of *name*.

    Exported (uppercase first character) → ``"public"``.
    Unexported → ``"module"``.
    """
    return "public" if name and name[0].isupper() else "module"


def _extract_import_spec(
    spec_node,
    src: bytes,
    from_path: str,
) -> ImportEdge | None:
    """Build an ImportEdge from a single ``import_spec`` node.

    The path string is inside an ``interpreted_string_literal``; we take
    the ``interpreted_string_literal_content`` child to get the bare path
    without quotes.  If no path literal is found, return None.
    """
    path_literal = None
    for child in spec_node.children:
        if child.type == "interpreted_string_literal":
            path_literal = child
            break

    if path_literal is None:
        return None

    # Extract the bare module path (without surrounding quotes).
    content_node = None
    for child in path_literal.children:
        if child.type == "interpreted_string_literal_content":
            content_node = child
            break

    pkg = node_text(content_node, src) if content_node else node_text(path_literal, src).strip('"')
    if not pkg:
        return None

    line = node_line(spec_node)
    return ImportEdge(
        from_file=from_path,
        to_module=pkg,
        kind="absolute",   # Go has no relative imports
        line=line,
        confidence=1.0,
    )


# ---------------------------------------------------------------------------
# Target resolution (Go write-site analysis -- mirrors _authority_ast.py)
# ---------------------------------------------------------------------------

def _string_literal_value(node, src: bytes) -> str | None:
    """Return the bare value of a Go string-literal node, else None.

    Handles ``interpreted_string_literal`` (double-quoted) and
    ``raw_string_literal`` (back-quoted). The bare value lives in the
    ``*_content`` child; if absent (empty string ``""``), return "".
    """
    if node is None:
        return None
    if node.type == "interpreted_string_literal":
        for child in node.children:
            if child.type == "interpreted_string_literal_content":
                return node_text(child, src)
        return ""  # empty interpreted literal: ""
    if node.type == "raw_string_literal":
        for child in node.children:
            if child.type == "raw_string_literal_content":
                return node_text(child, src)
        return ""
    return None


def _is_plausible_path(s: str) -> bool:
    """True iff *s* looks like a file path (mirror of the Python resolver guard).

    Rejects empty / oversized / multi-line strings. Bare well-known filenames
    are valid targets; otherwise the string must contain a path-like character
    (``/``, ``\\`` or ``.``).
    """
    if not s or len(s) > 512:
        return False
    if "\n" in s or "\r" in s:
        return False
    if Path(s).name in {"Makefile", "Dockerfile", "Procfile", "LICENSE", "README"}:
        return True
    if "/" not in s and "\\" not in s and "." not in s:
        return False
    return True


def _resolve_filepath_join(call_node, src: bytes) -> str | None:
    """Resolve ``filepath.Join("a", "b", ...)`` / ``path.Join(...)`` to ``"a/b/..."``.

    Best-effort: joins consecutive STRING-LITERAL arguments with ``/`` (the Go
    path separator semantics). If ANY argument is a non-literal (variable,
    call, etc.) the join is not fully determinable -> return None (no guess).
    Returns None when the call is not a ``*.Join`` selector call.
    """
    fn = call_node.child_by_field_name("function")
    if fn is None or fn.type != "selector_expression":
        return None
    operand = fn.child_by_field_name("operand")
    field = fn.child_by_field_name("field")
    if operand is None or field is None:
        return None
    if node_text(field, src) != "Join" or node_text(operand, src) not in ("filepath", "path"):
        return None

    args = call_node.child_by_field_name("arguments")
    if args is None:
        return None
    parts: list[str] = []
    for arg in args.children:
        if not arg.is_named:
            continue
        lit = _string_literal_value(arg, src)
        if lit is None:
            return None  # non-literal segment -> cannot fully resolve
        parts.append(lit)
    if not parts:
        return None
    return "/".join(parts)


def _collect_go_assignments(
    root, src: bytes
) -> dict[str, tuple[str, str]]:
    """Return ``name -> (resolved_path, provenance)`` for the whole file.

    Two passes, mirroring ``_authority_ast._collect_assignments``:
      PASS 1 (lower precedence): function PARAMETERS -> ("", function_parameter).
      PASS 2 (higher precedence): assignments overwrite params for the same name.

    Assignment forms handled (value must be a single expression):
      - ``p := "literal"``           (short_var_declaration)  -> string_literal
      - ``var q = "literal"``        (var_declaration)        -> string_literal
      - ``p := filepath.Join(...)``  (short_var_declaration)  -> path_constructor
      - ``var q = filepath.Join(...)``                        -> path_constructor

    File scope (not per-function) is sufficient for this PoC: Go disallows
    duplicate identifiers across overlapping scopes in the oracle cases, and the
    Python reference resolver is likewise whole-tree. Multi-name declarations
    (``a, b := f()``) and re-assignment are out of scope -> left unresolved.
    """
    assignments: dict[str, tuple[str, str]] = {}

    def _value_provenance(value_node) -> tuple[str, str] | None:
        """Map a single RHS expression node to (path, provenance), or None."""
        lit = _string_literal_value(value_node, src)
        if lit is not None and lit != "":
            return (lit, _PROVENANCE_STRING_LITERAL)
        if value_node.type == "call_expression":
            joined = _resolve_filepath_join(value_node, src)
            if joined is not None:
                return (joined, _PROVENANCE_PATH_CONSTRUCTOR)
        return None

    # PASS 1: function parameters (lowest precedence).
    for param in walk_named(root, "parameter_declaration"):
        for child in param.children:
            if child.is_named and child.type == "identifier":
                assignments[node_text(child, src)] = ("", _PROVENANCE_FUNCTION_PARAM)

    # PASS 2: assignments. Single-name LHS only (skip multi-assign / blanks).
    def _record(name_node, value_node) -> None:
        if name_node is None or value_node is None:
            return
        resolved = _value_provenance(value_node)
        if resolved is not None:
            assignments[node_text(name_node, src)] = resolved

    # short_var_declaration: left expression_list (names), right expression_list (values).
    for decl in walk_named(root, "short_var_declaration"):
        expr_lists = [c for c in decl.children if c.is_named and c.type == "expression_list"]
        if len(expr_lists) != 2:
            continue
        left = [c for c in expr_lists[0].children if c.is_named]
        right = [c for c in expr_lists[1].children if c.is_named]
        if len(left) != 1 or len(right) != 1 or left[0].type != "identifier":
            continue  # multi-name / unbalanced -> out of scope
        _record(left[0], right[0])

    # var_declaration: var_spec (single) or var_spec_list (grouped).
    def _handle_var_spec(spec) -> None:
        ids = [c for c in spec.children if c.is_named and c.type == "identifier"]
        val_lists = [c for c in spec.children if c.is_named and c.type == "expression_list"]
        if len(ids) != 1 or not val_lists:
            return  # multi-name or no initializer -> out of scope
        values = [c for c in val_lists[0].children if c.is_named]
        if len(values) != 1:
            return
        _record(ids[0], values[0])

    for var_decl in walk_named(root, "var_declaration"):
        for child in var_decl.children:
            if not child.is_named:
                continue
            if child.type == "var_spec":
                _handle_var_spec(child)
            elif child.type == "var_spec_list":
                for spec in iter_named_children(child, "var_spec"):
                    _handle_var_spec(spec)

    return assignments


def _resolve_arg_target(
    arg_node, src: bytes, assignments: dict[str, tuple[str, str]]
) -> tuple[str, str]:
    """Resolve a call's first-argument node to ``(resolved_target, provenance)``.

    Returns ``(_UNKNOWN_TARGET, _PROVENANCE_UNKNOWN)`` when the target cannot be
    resolved -- never a guessed/false target.

    Resolution order (mirrors ``_authority_ast._resolve_func_arg_target``):
      1. string literal arg              -> (literal, string_literal)
      2. filepath.Join(...) inline arg   -> (joined, path_constructor)
      3. identifier -> assignment lookup -> resolved (string_literal/path_constructor)
         or, if the identifier is a function parameter, ("", function_parameter)
    """
    if arg_node is None:
        return (_UNKNOWN_TARGET, _PROVENANCE_UNKNOWN)

    # 1. Inline string literal.
    lit = _string_literal_value(arg_node, src)
    if lit is not None and lit != "" and _is_plausible_path(lit):
        return (lit, _PROVENANCE_STRING_LITERAL)

    # 2. Inline filepath.Join(...).
    if arg_node.type == "call_expression":
        joined = _resolve_filepath_join(arg_node, src)
        if joined is not None and _is_plausible_path(joined):
            return (joined, _PROVENANCE_PATH_CONSTRUCTOR)

    # 3. Identifier -> assignment / parameter.
    if arg_node.type == "identifier":
        name = node_text(arg_node, src)
        entry = assignments.get(name)
        if entry is not None:
            path, prov = entry
            if prov == _PROVENANCE_FUNCTION_PARAM:
                # Target is a parameter: note provenance, but no literal path
                # is known at this site -> keep the unknown sentinel target.
                return (_UNKNOWN_TARGET, _PROVENANCE_FUNCTION_PARAM)
            if path and _is_plausible_path(path):
                return (path, prov)

    return (_UNKNOWN_TARGET, _PROVENANCE_UNKNOWN)


# ---------------------------------------------------------------------------
# Adapter
# ---------------------------------------------------------------------------

class GoAdapter(RegexAdapterBase):
    """Go adapter -- AST-based structural extractor via tree-sitter.

    Operates on ``.go`` files. Structural capability only for L5; all other
    supports_* flags remain False until later phases wire the corresponding
    builders to IR dispatch.

    Public interface (class name, method signatures, attributes, flags)
    is preserved exactly from the prior regex-based GoAdapter.
    """

    language = "go"
    file_extensions = (".go",)
    supports_structural = True
    supports_contracts = True
    supports_runtime_signals = True
    supports_authority_writes = True

    # ------------------------------------------------------------------
    # Structural: imports
    # ------------------------------------------------------------------

    def extract_imports(self, content: str, path: Path) -> list[ImportEdge]:
        """Return one ImportEdge per import path found in *content*.

        Handled forms:
            ``import "pkg"``              -- confidence 1.0
            ``import alias "pkg"``        -- confidence 1.0
            ``import _ "pkg"``            -- confidence 1.0
            ``import ( "pkg" ... )``      -- confidence 1.0 per entry

        All Go imports are absolute (Go has no relative import syntax).
        """
        _log.debug("extract_imports (tree-sitter): %s (%d chars)", path, len(content))
        src: bytes = content.encode("utf-8", errors="replace")
        root = parse_bytes(_LANGUAGE, src)
        from_path = Path(path).as_posix()

        edges: list[ImportEdge] = []
        seen: set[tuple[int, str]] = set()

        for decl in iter_named_children(root, "import_declaration"):
            for child in decl.children:
                if child.type == "import_spec":
                    # Single import (unaliased, aliased, or blank).
                    edge = _extract_import_spec(child, src, from_path)
                    if edge:
                        key = (edge.line, edge.to_module)
                        if key not in seen:
                            seen.add(key)
                            edges.append(edge)

                elif child.type == "import_spec_list":
                    # Grouped import block: import ( ... )
                    for spec in iter_named_children(child, "import_spec"):
                        edge = _extract_import_spec(spec, src, from_path)
                        if edge:
                            key = (edge.line, edge.to_module)
                            if key not in seen:
                                seen.add(key)
                                edges.append(edge)

        edges.sort(key=lambda e: (e.line, e.to_module, e.kind))
        return edges

    # ------------------------------------------------------------------
    # Structural: symbols
    # ------------------------------------------------------------------

    def extract_symbols(self, content: str, path: Path) -> list[SymbolDef]:
        """Return one SymbolDef per top-level declaration in *content*.

        Detected kinds:
            function  -- top-level ``func Name(`` (NOT method receivers)
            struct    -- ``type X struct``
            interface -- ``type X interface``
            type      -- ``type X = ...`` or ``type X SomeType`` (alias/def)
            const     -- ``const X`` / ``const ( X ... )`` and
                        ``var X`` / ``var ( X ... )`` at package level

        Visibility:
            - ``"public"`` if name starts with an uppercase letter (exported).
            - ``"module"`` otherwise (unexported).
        """
        _log.debug("extract_symbols (tree-sitter): %s (%d chars)", path, len(content))
        src: bytes = content.encode("utf-8", errors="replace")
        root = parse_bytes(_LANGUAGE, src)

        syms: list[SymbolDef] = []

        def _emit(name: str, kind: str, line: int) -> None:
            syms.append(SymbolDef(
                name=name,
                kind=kind,
                line=line,
                visibility=_visibility(name),
                confidence=1.0,
            ))

        for node in root.children:
            if not node.is_named:
                continue

            # --- function_declaration: top-level func (NOT method) ---
            if node.type == "function_declaration":
                for child in iter_named_children(node, "identifier"):
                    _emit(node_text(child, src), "function", node_line(node))
                    break  # only the function name identifier

            # --- type_declaration: struct / interface / alias / typedef ---
            elif node.type == "type_declaration":
                for spec in node.children:
                    if not spec.is_named:
                        continue

                    if spec.type == "type_spec":
                        # Children: type_identifier, then the type body.
                        # Body type determines kind: struct_type, interface_type,
                        # or a plain type_identifier (typedef).
                        name_node = None
                        body_type = None
                        for child in spec.children:
                            if child.is_named and child.type == "type_identifier" and name_node is None:
                                name_node = child
                            elif child.is_named and name_node is not None:
                                body_type = child.type
                                break
                        if name_node is None:
                            continue
                        name = node_text(name_node, src)
                        if body_type == "struct_type":
                            kind = "struct"
                        elif body_type == "interface_type":
                            kind = "interface"
                        else:
                            kind = "type"
                        _emit(name, kind, node_line(spec))

                    elif spec.type == "type_alias":
                        # type X = OtherType
                        for child in iter_named_children(spec, "type_identifier"):
                            _emit(node_text(child, src), "type", node_line(spec))
                            break

            # --- const_declaration: const X / const ( ... ) ---
            elif node.type == "const_declaration":
                for spec in iter_named_children(node, "const_spec"):
                    for id_node in iter_named_children(spec, "identifier"):
                        _emit(node_text(id_node, src), "const", node_line(spec))
                        break  # first identifier per spec (iota/multi-name handled)

            # --- var_declaration: var X / var ( ... ) ---
            elif node.type == "var_declaration":
                # var_spec_list wraps grouped vars; single var uses var_spec directly.
                for child in node.children:
                    if not child.is_named:
                        continue
                    if child.type == "var_spec_list":
                        for spec in iter_named_children(child, "var_spec"):
                            for id_node in iter_named_children(spec, "identifier"):
                                _emit(node_text(id_node, src), "const", node_line(spec))
                                break
                    elif child.type == "var_spec":
                        for id_node in iter_named_children(child, "identifier"):
                            _emit(node_text(id_node, src), "const", node_line(child))
                            break

        syms.sort(key=lambda s: (s.line, s.name))
        return syms

    # ------------------------------------------------------------------
    # Contracts: struct and interface type definitions
    # ------------------------------------------------------------------

    def extract_contracts(self, content: str, path: Path) -> list[ContractCandidate]:
        """Return one ContractCandidate per top-level struct or interface type.

        Handled forms:
            ``type X struct { ... }``      → contract_kind="struct"
            ``type X interface { ... }``   → contract_kind="interface"
            ``type ( A struct{} ... )``    → grouped block, one entry per type

        Plain type aliases / type definitions (``type X = Foo`` or
        ``type X SomeType``) are excluded — they are not data contracts.

        Test files (path name ending with ``_test.go``) return ``[]``.

        All results carry ``confidence=1.0`` (AST-based extraction).
        Results are sorted by ``(line, name)``.
        """
        if Path(path).name.endswith("_test.go"):
            return []

        _log.debug("extract_contracts (tree-sitter): %s (%d chars)", path, len(content))
        src: bytes = content.encode("utf-8", errors="replace")
        root = parse_bytes(_LANGUAGE, src)

        candidates: list[ContractCandidate] = []

        for node in root.children:
            if not node.is_named or node.type != "type_declaration":
                continue

            for spec in node.children:
                if not spec.is_named or spec.type != "type_spec":
                    continue

                # Walk children of type_spec: first named type_identifier is the
                # name; the next named child's type determines contract_kind.
                name_node = None
                body_type: str | None = None
                for child in spec.children:
                    if not child.is_named:
                        continue
                    if child.type == "type_identifier" and name_node is None:
                        name_node = child
                    elif name_node is not None:
                        body_type = child.type
                        break

                if name_node is None or body_type not in ("struct_type", "interface_type"):
                    continue

                contract_kind = "struct" if body_type == "struct_type" else "interface"
                candidates.append(ContractCandidate(
                    name=node_text(name_node, src),
                    contract_kind=contract_kind,
                    line=node_line(spec),
                    confidence=1.0,
                ))

        candidates.sort(key=lambda c: (c.line, c.name))
        return candidates

    # ------------------------------------------------------------------
    # Runtime signals: init functions, goroutine spawns, package-level
    # var initialized by a call (import-time side effects).
    # ------------------------------------------------------------------

    def extract_runtime(self, content: str, path: Path) -> list[TSRuntimeSignal]:
        """Detect Go import-time and concurrency side effects via tree-sitter AST.

        Emits TSRuntimeSignal (confidence=1.0) for:
            ``func init() { ... }``
                → kind="init_function", payload={"call": "init"}
            ``go someCall(...)``  (go_statement anywhere in the file)
                → kind="goroutine_spawn", payload={"call": <full callee text>}
            Top-level ``var X = <call_expr>`` (package-level var initialized by
            a function call — import-time side effect)
                → kind="package_init", payload={"call": <var name>}

        Test files (path ending with ``_test.go``) return ``[]``.
        Results are sorted by ``(line, kind)``.
        """
        if Path(path).name.endswith("_test.go"):
            return []

        _log.debug("extract_runtime (tree-sitter): %s (%d chars)", path, len(content))
        src: bytes = content.encode("utf-8", errors="replace")
        root = parse_bytes(_LANGUAGE, src)
        file_posix = Path(path).as_posix()

        signals: list[TSRuntimeSignal] = []

        # ------------------------------------------------------------------
        # Pass 1: top-level declarations — init functions and package-level
        # vars initialized by a call expression.
        # ------------------------------------------------------------------
        for node in root.children:
            if not node.is_named:
                continue

            # func init() { ... }
            if node.type == "function_declaration":
                for child in iter_named_children(node, "identifier"):
                    if node_text(child, src) == "init":
                        signals.append(TSRuntimeSignal(
                            kind="init_function",
                            file=file_posix,
                            line=node_line(node),
                            confidence=1.0,
                            payload={"call": "init"},
                        ))
                    break  # only inspect the first identifier (function name)

            # var X = <call_expr> at package level
            elif node.type == "var_declaration":
                for child in node.children:
                    if not child.is_named:
                        continue
                    specs: list = []
                    if child.type == "var_spec_list":
                        specs = list(iter_named_children(child, "var_spec"))
                    elif child.type == "var_spec":
                        specs = [child]
                    for spec in specs:
                        # Extract the first identifier (var name) and check
                        # whether the value contains a call_expression.
                        var_name = ""
                        has_call = False
                        for spec_child in spec.children:
                            if spec_child.is_named and spec_child.type == "identifier" and not var_name:
                                var_name = node_text(spec_child, src)
                            if spec_child.is_named and spec_child.type == "expression_list":
                                for expr in walk_named(spec_child, "call_expression"):
                                    has_call = True
                                    break
                        if var_name and has_call:
                            signals.append(TSRuntimeSignal(
                                kind="package_init",
                                file=file_posix,
                                line=node_line(spec),
                                confidence=1.0,
                                payload={"call": var_name},
                            ))

        # ------------------------------------------------------------------
        # Pass 2: goroutine spawns — walk entire tree for go_statement nodes.
        # ------------------------------------------------------------------
        for go_node in walk_named(root, "go_statement"):
            # The call expression is a direct child of go_statement.
            call_text = ""
            for child in go_node.children:
                if child.is_named and child.type == "call_expression":
                    call_text = node_text(child, src)
                    break
            signals.append(TSRuntimeSignal(
                kind="goroutine_spawn",
                file=file_posix,
                line=node_line(go_node),
                confidence=1.0,
                payload={"call": call_text},
            ))

        signals.sort(key=lambda s: (s.line, s.kind))
        return signals

    # ------------------------------------------------------------------
    # Authority writes
    # ------------------------------------------------------------------

    def extract_writer_calls(
        self, content: str, path: Path
    ) -> list[AuthorityWriteCandidate]:
        """Detect write operations in Go source via tree-sitter AST.

        Walks all ``call_expression`` nodes and matches writer patterns by the
        called function (a ``selector_expression`` with ``operand`` + ``field``):

        - ``os.WriteFile(name, ...)`` / ``ioutil.WriteFile(name, ...)``
              → ``write_kind="fs_write"``, target_hint = first arg text
        - ``os.Create(name)`` / ``os.OpenFile(name, ...)``
              → ``write_kind="fs_write"``, target_hint = first arg text
        - ``recv.Write(...)`` / ``recv.WriteString(...)``  (any receiver)
              → ``write_kind="fs_write"``, target_hint = receiver text
        - ``recv.Exec(...)``  (any receiver, db exec pattern)
              → ``write_kind="db_write"``, target_hint = first arg text (best-effort)

        Target resolution (additive — mirrors the Python ``_authority_ast``
        resolver). For the path-argument writers (``WriteFile`` / ``Create`` /
        ``OpenFile`` / ``Exec``) the first argument is resolved into
        ``resolved_target`` + ``provenance``:

        - string-literal arg            → literal, ``provenance="string_literal"``
        - variable arg                  → traced to its ``:=`` / ``var`` assignment
          in scope (string literal or ``filepath.Join`` of literals)
        - ``filepath.Join(...)`` arg    → joined path, ``provenance="path_constructor"``
        - function-parameter arg        → ``provenance="function_parameter"`` (the
          target is a param, no literal at the call site) — target stays the
          ``__unknown_target__`` sentinel
        - unresolvable (incl. receiver  → ``resolved_target="__unknown_target__"``,
          ``Write``/``WriteString``)      ``provenance="unknown"`` (no guessed target)

        Test files (path ending with ``_test.go``) return ``[]``.
        All results carry ``confidence=1.0``.
        Results are sorted by ``(line, write_kind)``.
        """
        if Path(path).name.endswith("_test.go"):
            return []

        _log.debug("extract_writer_calls (tree-sitter): %s (%d chars)", path, len(content))
        src: bytes = content.encode("utf-8", errors="replace")
        root = parse_bytes(_LANGUAGE, src)

        # Resolve assignments once for the whole file (name -> (path, provenance)).
        assignments = _collect_go_assignments(root, src)

        candidates: list[AuthorityWriteCandidate] = []

        def _hint(text: str) -> str:
            """Strip surrounding quotes and cap at 30 chars."""
            t = text.strip().strip('"\'`').strip()
            return t[:30]

        def _first_arg_node(call_node):
            """Return the first named argument node of a call_expression, or None."""
            args = call_node.child_by_field_name("arguments")
            if args is None:
                return None
            for c in args.children:
                if c.is_named:
                    return c
            return None

        def _first_arg_text(call_node) -> str:
            """Return the text of the first argument of a call_expression, or ''."""
            node = _first_arg_node(call_node)
            return node_text(node, src) if node is not None else ""

        for call in walk_named(root, "call_expression"):
            fn = call.child_by_field_name("function")
            if fn is None or fn.type != "selector_expression":
                continue

            operand = fn.child_by_field_name("operand")
            field = fn.child_by_field_name("field")
            if operand is None or field is None:
                continue

            pkg = node_text(operand, src)
            method = node_text(field, src)
            line = node_line(call)

            # os.WriteFile / ioutil.WriteFile
            if method == "WriteFile" and pkg in ("os", "ioutil"):
                resolved, prov = _resolve_arg_target(_first_arg_node(call), src, assignments)
                candidates.append(AuthorityWriteCandidate(
                    write_kind="fs_write",
                    target_hint=_hint(_first_arg_text(call)),
                    line=line,
                    confidence=1.0,
                    resolved_target=resolved,
                    provenance=prov,
                ))

            # os.Create / os.OpenFile
            elif method in ("Create", "OpenFile") and pkg == "os":
                resolved, prov = _resolve_arg_target(_first_arg_node(call), src, assignments)
                candidates.append(AuthorityWriteCandidate(
                    write_kind="fs_write",
                    target_hint=_hint(_first_arg_text(call)),
                    line=line,
                    confidence=1.0,
                    resolved_target=resolved,
                    provenance=prov,
                ))

            # *.Write / *.WriteString  (any receiver — IO writer pattern)
            # The receiver is an IO writer, NOT a path target -> no resolution
            # (resolved_target/provenance keep the unknown defaults).
            elif method in ("Write", "WriteString"):
                candidates.append(AuthorityWriteCandidate(
                    write_kind="fs_write",
                    target_hint=_hint(pkg),
                    line=line,
                    confidence=1.0,
                ))

            # *.Exec  (any receiver — DB exec pattern)
            elif method == "Exec":
                resolved, prov = _resolve_arg_target(_first_arg_node(call), src, assignments)
                candidates.append(AuthorityWriteCandidate(
                    write_kind="db_write",
                    target_hint=_hint(_first_arg_text(call)),
                    line=line,
                    confidence=1.0,
                    resolved_target=resolved,
                    provenance=prov,
                ))

        candidates.sort(key=lambda c: (c.line, c.write_kind))
        return candidates
