"""JavaScript source adapter -- tree-sitter AST-based structural extractor.

Parses .js / .jsx / .mjs / .cjs files via tree-sitter for true AST accuracy,
replacing the former regex+lexer approach.  All extracted IR items carry
``confidence=1.0``.

Capabilities (L6a scope):
    - supports_structural      = True
    - supports_contracts       = False (L6b)
    - supports_runtime_signals = True  (L6a: timer/event_listener/top_level_effect)
    - supports_authority_writes = True

Import forms handled (ES-module):
    ``import X from 'Y'``               -- default import
    ``import { A, B } from 'Y'``        -- named imports
    ``import * as X from 'Y'``          -- namespace import
    ``import 'Y'``                      -- side-effect import
    ``export { A, B } from 'Y'``        -- re-export named
    ``export * from 'Y'``               -- re-export star
    ``import('Y')`` / ``await import('Y')``  -- dynamic import

Import forms handled (CommonJS):
    ``const X = require('Y')``          -- lexical_declaration
    ``let X = require('Y')``            -- lexical_declaration
    ``const { X } = require('Y')``      -- destructuring
    ``var X = require('Y')``            -- variable_declaration
    ``require('Y');``                   -- bare side-effect

Symbol kinds extracted (top-level only):
    function  -- ``function_declaration`` (exported or not)
    class     -- ``class_declaration`` (exported or not)
    const     -- ``lexical_declaration`` / ``variable_declaration``

Visibility rule (JS):
    - ``"public"``  -- declaration is wrapped in an ``export_statement``
    - ``"module"``  -- declaration is not exported

Known limitations (explicit L2 tech-debt, do NOT fix here):
    - ``module.exports = { ... }`` / ``exports.foo = ...`` are NOT emitted as
      symbols. CJS exports are tracked as import edges for their consumers;
      the producer side is L6 work.
    - JSX attribute expressions are not inspected (treated as JS).
    - ``require.resolve(...)`` and ``require.cache`` are ignored.
    - Dynamic ``import(variable)`` with non-literal argument is skipped
      (consistent with prior adapter behaviour).
    - ``enum`` is not valid JavaScript; tree-sitter parses it as ERROR and it
      is silently ignored (no SymbolDef emitted).
"""
from __future__ import annotations

import logging
from pathlib import Path

from ._base import RegexAdapterBase
from ._ir import AuthorityWriteCandidate, ImportEdge, SymbolDef, TSRuntimeSignal
from ._patterns import classify_import
from ._treesitter import (
    iter_named_children,
    node_line,
    node_text,
    parse_bytes,
    walk_named,
)

__all__ = ["JavascriptAdapter"]

_log = logging.getLogger(__name__)

_LANGUAGE = "javascript"


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _string_module(string_node, src: bytes) -> str:
    """Extract the bare module specifier from a tree-sitter ``string`` node.

    Looks for a ``string_fragment`` child first (single/double-quoted strings);
    falls back to stripping quote characters from the node's full text.
    """
    for child in string_node.children:
        if child.type == "string_fragment":
            return node_text(child, src)
    # Fallback: strip surrounding quotes from raw node text.
    raw = node_text(string_node, src)
    return raw.strip("'\"")


def _find_require_module(call_expr_node, src: bytes) -> str | None:
    """Return the string literal passed to ``require(...)`` or ``None``.

    Checks that the callee is an ``identifier`` named ``require`` and that
    the first argument is a ``string`` literal.
    """
    callee = None
    args_node = None
    for child in call_expr_node.children:
        if not child.is_named:
            continue
        if child.type == "identifier":
            callee = child
        elif child.type == "arguments":
            args_node = child

    if callee is None or node_text(callee, src) != "require":
        return None
    if args_node is None:
        return None

    # First named child of arguments that is a string literal.
    for arg in args_node.children:
        if not arg.is_named:
            continue
        if arg.type == "string":
            return _string_module(arg, src)

    return None


def _find_dynamic_import_module(node, src: bytes) -> str | None:
    """Recursively search *node* for a dynamic ``import('literal')`` call.

    Returns the module specifier string if found and the argument is a string
    literal, otherwise None.
    """
    # call_expression whose function part is the ``import`` keyword node.
    if node.type == "call_expression":
        # First unnamed/named child should be ``import`` keyword.
        for child in node.children:
            if child.type == "import":
                # Found a dynamic import — extract the first string argument.
                for sibling in node.children:
                    if sibling.is_named and sibling.type == "arguments":
                        for arg in sibling.children:
                            if arg.is_named and arg.type == "string":
                                return _string_module(arg, src)
                return None  # Dynamic import with non-literal arg — skip.

    # Recurse into named children.
    for child in node.children:
        result = _find_dynamic_import_module(child, src)
        if result is not None:
            return result
    return None


# ---------------------------------------------------------------------------
# Adapter
# ---------------------------------------------------------------------------

class JavascriptAdapter(RegexAdapterBase):
    """JavaScript adapter -- AST-based structural extractor via tree-sitter.

    Operates on ``.js``, ``.jsx``, ``.mjs``, ``.cjs``. Structural capability
    only for L2; all other supports_* flags remain False until later phases
    wire the corresponding builders to IR dispatch.

    Public interface (class name, method signatures, attributes, flags)
    is preserved exactly from the prior regex-based JavascriptAdapter.
    """

    language = "javascript"
    file_extensions = (".js", ".jsx", ".mjs", ".cjs")
    supports_structural = True
    supports_contracts = False
    supports_runtime_signals = True
    supports_authority_writes = True

    # ------------------------------------------------------------------
    # Structural: imports
    # ------------------------------------------------------------------

    def extract_imports(self, content: str, path: Path) -> list[ImportEdge]:
        """Return one ImportEdge per ES-module / CJS / dynamic import.

        Handled forms:
            ES-module:
                ``import X from 'Y'``               -- confidence 1.0
                ``import { A, B } from 'Y'``        -- confidence 1.0
                ``import * as X from 'Y'``          -- confidence 1.0
                ``import 'Y'``                      -- confidence 1.0
                ``export { A, B } from 'Y'``        -- confidence 1.0
                ``export * from 'Y'`` / ``export * as NS from 'Y'``
            CommonJS:
                ``const X = require('Y')``          -- confidence 1.0
                ``bare require('Y')``               -- confidence 1.0
            Dynamic:
                ``import('Y')`` (literal module)    -- confidence 1.0
        """
        _log.debug("extract_imports (tree-sitter): %s (%d chars)", path, len(content))
        src: bytes = content.encode("utf-8", errors="replace")
        root = parse_bytes(_LANGUAGE, src)
        from_path = Path(path).as_posix()

        edges: list[ImportEdge] = []
        seen: set[tuple[int, str]] = set()

        def _emit(module: str, line: int) -> None:
            if not module:
                return
            key = (line, module)
            if key in seen:
                return
            seen.add(key)
            edges.append(ImportEdge(
                from_file=from_path,
                to_module=module,
                kind=classify_import(module),
                line=line,
                confidence=1.0,
            ))

        for node in root.children:
            if not node.is_named:
                continue

            # ---------------------------------------------------------------
            # ES-module: import_statement
            # ---------------------------------------------------------------
            if node.type == "import_statement":
                # The module specifier is always the last ``string`` child.
                for child in node.children:
                    if child.is_named and child.type == "string":
                        _emit(_string_module(child, src), node_line(node))
                        break

            # ---------------------------------------------------------------
            # ES-module re-exports: export_statement with a ``from`` clause
            # (export { X } from '...') and (export * from '...')
            # ---------------------------------------------------------------
            elif node.type == "export_statement":
                # A re-export has a ``string`` child at the top level of the
                # export_statement node (the ``from '...'`` part).
                for child in node.children:
                    if child.is_named and child.type == "string":
                        _emit(_string_module(child, src), node_line(node))
                        break
                # Note: exported declarations (function/class/const) are handled
                # in extract_symbols and do NOT produce ImportEdge entries.

            # ---------------------------------------------------------------
            # CommonJS: lexical_declaration (const/let = require(...))
            # ---------------------------------------------------------------
            elif node.type in ("lexical_declaration", "variable_declaration"):
                for decl in iter_named_children(node, "variable_declarator"):
                    # Check if the initialiser (or part of it) is a require call.
                    for child in decl.children:
                        if child.is_named and child.type == "call_expression":
                            module = _find_require_module(child, src)
                            if module is not None:
                                _emit(module, node_line(node))
                        # Dynamic import: await import('...') inside a declarator
                        elif child.is_named and child.type == "await_expression":
                            module = _find_dynamic_import_module(child, src)
                            if module is not None:
                                _emit(module, node_line(node))
                        # Non-await dynamic import: const m = import('...')
                        elif child.is_named and child.type == "call_expression":
                            module = _find_dynamic_import_module(child, src)
                            if module is not None:
                                _emit(module, node_line(node))

            # ---------------------------------------------------------------
            # CommonJS: expression_statement -- bare require('...')
            # Also catches: bare import('...') as an expression statement
            # ---------------------------------------------------------------
            elif node.type == "expression_statement":
                for child in iter_named_children(node, "call_expression"):
                    module = _find_require_module(child, src)
                    if module is not None:
                        _emit(module, node_line(node))
                        continue
                    module = _find_dynamic_import_module(child, src)
                    if module is not None:
                        _emit(module, node_line(node))

        edges.sort(key=lambda e: (e.line, e.to_module, e.kind))
        return edges

    # ------------------------------------------------------------------
    # Structural: symbols
    # ------------------------------------------------------------------

    def extract_symbols(self, content: str, path: Path) -> list[SymbolDef]:
        """Return one SymbolDef per top-level declaration in *content*.

        Detected kinds (first match wins for a given declaration):
            function  -- ``function_declaration``
            class     -- ``class_declaration``
            const     -- ``lexical_declaration`` / ``variable_declaration``

        No ``interface`` / ``type`` -- those are TS-only.
        ``enum`` is not valid JS in the tree-sitter grammar; it parses as
        ERROR and is silently skipped.

        Visibility:
            - ``"public"`` if the declaration is wrapped in an
              ``export_statement``.
            - ``"module"`` otherwise (CJS ``module.exports`` not tracked at
              the symbol level in L2; see module-level docstring).
        """
        _log.debug("extract_symbols (tree-sitter): %s (%d chars)", path, len(content))
        src: bytes = content.encode("utf-8", errors="replace")
        root = parse_bytes(_LANGUAGE, src)

        syms: list[SymbolDef] = []

        def _emit(name: str, kind: str, line: int, exported: bool) -> None:
            syms.append(SymbolDef(
                name=name,
                kind=kind,
                line=line,
                visibility="public" if exported else "module",
                confidence=1.0,
            ))

        def _process_declaration(decl_node, exported: bool) -> None:
            """Extract symbol(s) from a function/class/lexical/var declaration."""
            t = decl_node.type

            if t == "function_declaration":
                for child in iter_named_children(decl_node, "identifier"):
                    _emit(node_text(child, src), "function", node_line(decl_node), exported)
                    break  # only the function name

            elif t == "class_declaration":
                for child in iter_named_children(decl_node, "identifier"):
                    _emit(node_text(child, src), "class", node_line(decl_node), exported)
                    break  # only the class name

            elif t in ("lexical_declaration", "variable_declaration"):
                for var_decl in iter_named_children(decl_node, "variable_declarator"):
                    # Name may be a plain identifier or a destructuring pattern.
                    for child in var_decl.children:
                        if not child.is_named:
                            continue
                        if child.type == "identifier":
                            _emit(
                                node_text(child, src),
                                "const",
                                node_line(decl_node),
                                exported,
                            )
                            break  # first identifier per declarator
                        # Destructuring patterns (object_pattern, array_pattern):
                        # emit the enclosing const with the declarator's line;
                        # individual destructured names are not promoted to symbols
                        # (parity with prior adapter behaviour).
                        break

        for node in root.children:
            if not node.is_named:
                continue

            if node.type == "export_statement":
                # Walk the export_statement's direct children for declarations.
                for child in node.children:
                    if not child.is_named:
                        continue
                    _process_declaration(child, exported=True)

            else:
                _process_declaration(node, exported=False)

        syms.sort(key=lambda s: (s.line, s.name))
        return syms

    # ------------------------------------------------------------------
    # Runtime signals: timers, event listeners, top-level effects
    # ------------------------------------------------------------------

    #: Identifier names that indicate a timer call.
    _TIMER_FNS: frozenset[str] = frozenset({"setInterval", "setTimeout", "setImmediate"})

    #: Member-expression property names that indicate an event-listener call.
    _EVENT_METHODS: frozenset[str] = frozenset({"addEventListener", "on"})

    #: Identifier names that must NOT produce a top_level_effect signal.
    _EXCLUDED_CALL_IDS: frozenset[str] = frozenset({"require"}) | _TIMER_FNS

    def extract_runtime(self, content: str, path: Path) -> list[TSRuntimeSignal]:
        """Detect JavaScript runtime side-effects via tree-sitter AST.

        Emits TSRuntimeSignal (confidence=1.0) for TOP-LEVEL expression_statement
        nodes (direct children of ``program``) that contain a call_expression:

            setInterval(...) / setTimeout(...) / setImmediate(...)
                → kind="timer", payload={"call": <fn name>}
            *.addEventListener(...) / *.on(...)
                → kind="event_listener", payload={"call": "<receiver>.<method>"}
            Any other top-level call that is NOT require() and NOT a timer/listener
                → kind="top_level_effect", payload={"call": <callee text, ≤30 chars>}

        Calls nested inside function bodies are NOT flagged as top_level_effect
        because they are not direct children of ``program``.

        Test files (``*.test.js``, ``*.spec.js``, paths containing ``__tests__/``)
        return ``[]``.
        Results are sorted by ``(line, kind)``.
        """
        p = Path(path)
        name = p.name
        if name.endswith(".test.js") or name.endswith(".spec.js"):
            return []
        if "__tests__" in p.as_posix().split("/"):
            return []

        _log.debug("extract_runtime (tree-sitter): %s (%d chars)", path, len(content))
        src: bytes = content.encode("utf-8", errors="replace")
        root = parse_bytes(_LANGUAGE, src)
        file_posix = p.as_posix()

        signals: list[TSRuntimeSignal] = []

        for node in root.children:
            if not node.is_named or node.type != "expression_statement":
                continue

            # Direct child call_expression of the expression_statement
            call_expr = None
            for child in node.children:
                if child.is_named and child.type == "call_expression":
                    call_expr = child
                    break
            if call_expr is None:
                continue

            fn_node = call_expr.child_by_field_name("function")
            if fn_node is None:
                continue

            line = node_line(call_expr)

            if fn_node.type == "identifier":
                fn_name = node_text(fn_node, src)

                # Timer
                if fn_name in self._TIMER_FNS:
                    signals.append(TSRuntimeSignal(
                        kind="timer",
                        file=file_posix,
                        line=line,
                        confidence=1.0,
                        payload={"call": fn_name},
                    ))

                # Skip require() — not a runtime side-effect signal
                elif fn_name == "require":
                    continue

                # Top-level effect (anything else)
                else:
                    signals.append(TSRuntimeSignal(
                        kind="top_level_effect",
                        file=file_posix,
                        line=line,
                        confidence=1.0,
                        payload={"call": fn_name[:30]},
                    ))

            elif fn_node.type == "member_expression":
                obj_node = fn_node.child_by_field_name("object")
                prop_node = fn_node.child_by_field_name("property")
                if obj_node is None or prop_node is None:
                    continue

                method = node_text(prop_node, src)
                receiver = node_text(obj_node, src)

                # Event listener
                if method in self._EVENT_METHODS:
                    detail = f"{receiver}.{method}"
                    signals.append(TSRuntimeSignal(
                        kind="event_listener",
                        file=file_posix,
                        line=line,
                        confidence=1.0,
                        payload={"call": detail},
                    ))

                # Other member-expression top-level calls
                else:
                    callee_text = node_text(fn_node, src)[:30]
                    signals.append(TSRuntimeSignal(
                        kind="top_level_effect",
                        file=file_posix,
                        line=line,
                        confidence=1.0,
                        payload={"call": callee_text},
                    ))

        signals.sort(key=lambda s: (s.line, s.kind))
        return signals

    # ------------------------------------------------------------------
    # Authority writes
    # ------------------------------------------------------------------

    def extract_writer_calls(
        self, content: str, path: Path
    ) -> list[AuthorityWriteCandidate]:
        """Detect write operations in JavaScript source via tree-sitter AST.

        Walks all ``call_expression`` nodes and matches by function shape:

        ``member_expression`` (object.property):
        - ``fs.writeFile`` / ``fs.writeFileSync``
              → ``write_kind="fs_write"``, target_hint = first arg
        - ``fs.appendFile`` / ``fs.appendFileSync``
              → ``write_kind="fs_append"``, target_hint = first arg
        - ``localStorage.setItem`` / ``sessionStorage.setItem``
              → ``write_kind="storage_write"``, target_hint = first arg
        - ``*.save`` / ``*.create``  (ORM — any receiver)
              → ``write_kind="orm_save"``, target_hint = receiver
        - ``*.update``  (ORM — any receiver)
              → ``write_kind="orm_write"``, target_hint = receiver

        ``identifier`` (standalone call):
        - ``writeFile(...)``
              → ``write_kind="fs_write"``, target_hint = first arg

        Test files (``*.test.js``, ``*.spec.js``, paths containing
        ``__tests__/``) return ``[]``.
        All results carry ``confidence=1.0``.
        Results are sorted by ``(line, write_kind)``.
        """
        p = Path(path)
        name = p.name
        if name.endswith(".test.js") or name.endswith(".spec.js"):
            return []
        if "__tests__" in p.as_posix().split("/"):
            return []

        _log.debug("extract_writer_calls (tree-sitter): %s (%d chars)", path, len(content))
        src: bytes = content.encode("utf-8", errors="replace")
        root = parse_bytes(_LANGUAGE, src)

        candidates: list[AuthorityWriteCandidate] = []

        def _hint(text: str) -> str:
            """Strip surrounding quotes and cap at 30 chars."""
            t = text.strip().strip("'\"`").strip()
            return t[:30]

        def _first_arg_text(args_node) -> str:
            if args_node is None:
                return ""
            named = [c for c in args_node.children if c.is_named]
            return node_text(named[0], src) if named else ""

        for call in walk_named(root, "call_expression"):
            fn = call.child_by_field_name("function")
            args = call.child_by_field_name("arguments")
            if fn is None:
                continue

            line = node_line(call)

            if fn.type == "member_expression":
                obj = fn.child_by_field_name("object")
                prop = fn.child_by_field_name("property")
                if obj is None or prop is None:
                    continue
                receiver = node_text(obj, src)
                method = node_text(prop, src)

                # fs.writeFile / fs.writeFileSync
                if method in ("writeFile", "writeFileSync") and receiver == "fs":
                    candidates.append(AuthorityWriteCandidate(
                        write_kind="fs_write",
                        target_hint=_hint(_first_arg_text(args)),
                        line=line,
                        confidence=1.0,
                    ))

                # fs.appendFile / fs.appendFileSync
                elif method in ("appendFile", "appendFileSync") and receiver == "fs":
                    candidates.append(AuthorityWriteCandidate(
                        write_kind="fs_append",
                        target_hint=_hint(_first_arg_text(args)),
                        line=line,
                        confidence=1.0,
                    ))

                # localStorage.setItem / sessionStorage.setItem
                elif method == "setItem" and receiver in ("localStorage", "sessionStorage"):
                    candidates.append(AuthorityWriteCandidate(
                        write_kind="storage_write",
                        target_hint=_hint(_first_arg_text(args)),
                        line=line,
                        confidence=1.0,
                    ))

                # *.save / *.create (ORM)
                elif method in ("save", "create"):
                    candidates.append(AuthorityWriteCandidate(
                        write_kind="orm_save",
                        target_hint=_hint(receiver),
                        line=line,
                        confidence=1.0,
                    ))

                # *.update (ORM)
                elif method == "update":
                    candidates.append(AuthorityWriteCandidate(
                        write_kind="orm_write",
                        target_hint=_hint(receiver),
                        line=line,
                        confidence=1.0,
                    ))

            elif fn.type == "identifier":
                fn_name = node_text(fn, src)

                # standalone writeFile(...)
                if fn_name == "writeFile":
                    candidates.append(AuthorityWriteCandidate(
                        write_kind="fs_write",
                        target_hint=_hint(_first_arg_text(args)),
                        line=line,
                        confidence=1.0,
                    ))

        candidates.sort(key=lambda c: (c.line, c.write_kind))
        return candidates
