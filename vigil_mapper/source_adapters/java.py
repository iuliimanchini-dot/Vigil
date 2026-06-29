"""Java source adapter -- tree-sitter AST-based structural extractor.

Parses ``.java`` files via tree-sitter for true AST accuracy, replacing the
former regex+lexer approach.  All extracted IR items carry ``confidence=1.0``.

Capabilities (L5 scope + runtime):
    - supports_structural      = True  (extract_imports + extract_symbols)
    - supports_contracts       = True  (extract_contracts: class/record/interface/enum)
    - supports_runtime_signals = True  (extract_runtime: static_block/spring/thread)
    - supports_authority_writes = True (extract_writer_calls)

Import forms handled:
    ``import com.example.Foo;``           -- regular
    ``import static com.example.Foo.m;``  -- static
    ``import com.example.*;``             -- wildcard
    ``import static com.example.Foo.*;``  -- static wildcard

Symbol kinds extracted (top-level type declarations only):
    class     -- ``class_declaration`` and ``record_declaration`` (Java 16+)
    interface -- ``interface_declaration`` and ``annotation_type_declaration``
    enum      -- ``enum_declaration``

Visibility rule (Java):
    - ``"public"``  -- declaration has an explicit ``public`` modifier
    - ``"module"``  -- no ``public`` modifier (package-private default)

Uses shared ``_treesitter`` helpers; the public interface (class name,
method signatures, flags, file_extensions) is identical to the former
regex adapter.
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

__all__ = ["JavaAdapter"]

_log = logging.getLogger(__name__)

_LANGUAGE = "java"

# Top-level declaration node types that map to SymbolDef entries.
_TYPE_DECL_NODES = frozenset({
    "class_declaration",
    "interface_declaration",
    "enum_declaration",
    "record_declaration",
    "annotation_type_declaration",
})

# Target-resolution constants (mirror the Go adapter / _authority_ast.py
# provenance vocabulary so every adapter speaks the same provenance levels).
_UNKNOWN_TARGET = "__unknown_target__"
_PROVENANCE_PATH_CONSTRUCTOR = "path_constructor"  # Paths.get(...), Path.of("a","b")
_PROVENANCE_STRING_LITERAL = "string_literal"      # "literal_path"
_PROVENANCE_FUNCTION_PARAM = "function_parameter"  # void f(String target)
_PROVENANCE_UNKNOWN = "unknown"

# Java path-builder selectors whose all-string-literal args join into one path.
# ``Path.of("a", "b")`` and ``Paths.get("a", "b")`` are the canonical forms; a
# single-arg ``Path.of("literal.txt")`` is treated as the bare literal itself.
_PATH_BUILDER_RECEIVERS = frozenset({"Path", "Paths"})
_PATH_BUILDER_METHODS = frozenset({"of", "get"})


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _fqn_from_import(decl_node, src: bytes) -> str:
    """Reconstruct the fully-qualified import name from an import_declaration node.

    Handles regular, static, and wildcard (``*``) forms.

    Returns the fqn string, e.g. ``"com.example.Foo"`` or ``"com.example.*"``.
    Returns empty string if the structure is unexpected.
    """
    # Collect named children; filter unnamed punctuation.
    # Children layout (unnamed tokens are `import`, `static`, `.`, `;`):
    #   regular:         import <scoped_identifier> ;
    #   static:          import static <scoped_identifier> ;
    #   wildcard:        import <scoped_identifier> . <asterisk> ;
    #   static wildcard: import static <scoped_identifier> . <asterisk> ;

    fqn_parts: list[str] = []
    is_wildcard = False

    for child in decl_node.children:
        ctype = child.type
        if ctype == "scoped_identifier" or ctype == "identifier":
            fqn_parts.append(node_text(child, src))
        elif ctype == "asterisk":
            is_wildcard = True

    if not fqn_parts:
        return ""

    fqn = fqn_parts[0]  # scoped_identifier already contains dots
    if is_wildcard:
        fqn = fqn + ".*"
    return fqn


def _visibility_from_modifiers(decl_node, src: bytes) -> str:
    """Return visibility string for a type declaration node.

    Java convention used by this adapter (matches prior regex adapter):
        - ``"public"``  if a ``modifiers`` child contains a ``public`` token
        - ``"module"``  otherwise (package-private default)
    """
    for child in decl_node.children:
        if child.type == "modifiers":
            mods_text = node_text(child, src)
            if "public" in mods_text.split():
                return "public"
            return "module"
    return "module"


def _kind_from_node_type(node_type: str) -> str:
    """Map a tree-sitter declaration node type to an IR kind string."""
    if node_type == "class_declaration":
        return "class"
    if node_type == "record_declaration":
        return "class"        # records map to "class" for parity with prior adapter
    if node_type == "interface_declaration":
        return "interface"
    if node_type == "annotation_type_declaration":
        return "interface"    # @interface maps to "interface" for parity
    if node_type == "enum_declaration":
        return "enum"
    return "class"            # unreachable given _TYPE_DECL_NODES guard


def _name_from_decl(decl_node, src: bytes) -> str:
    """Extract the simple name identifier from a type declaration node."""
    for child in decl_node.children:
        if child.type == "identifier" and child.is_named:
            return node_text(child, src)
    return ""


# ---------------------------------------------------------------------------
# Target resolution (Java write-site analysis -- mirrors the Go PoC)
# ---------------------------------------------------------------------------

def _string_literal_value(node, src: bytes) -> str | None:
    """Return the bare value of a Java ``string_literal`` node, else None.

    The bare value lives in the ``string_fragment`` child; an empty literal
    ``""`` has no fragment and returns "".  Non-string nodes return None.
    """
    if node is None or node.type != "string_literal":
        return None
    for child in node.children:
        if child.type == "string_fragment":
            return node_text(child, src)
    return ""  # empty literal: ""


def _is_plausible_path(s: str) -> bool:
    """True iff *s* looks like a file path (mirror of the Go/Python guard).

    Rejects empty / oversized / multi-line strings.  Bare well-known filenames
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


def _resolve_path_builder(call_node, src: bytes) -> str | None:
    """Resolve ``Path.of("a","b")`` / ``Paths.get("a","b")`` to ``"a/b"``.

    Best-effort: joins consecutive STRING-LITERAL arguments with ``/``.  A
    single literal argument resolves to that literal (so ``Path.of("x.txt")``
    behaves like the bare literal).  Returns None when the node is not a
    ``Path.of`` / ``Paths.get`` invocation or any argument is a non-literal
    (variable, nested call, etc.) -> cannot fully resolve (no guess).
    """
    if call_node is None or call_node.type != "method_invocation":
        return None
    obj = call_node.child_by_field_name("object")
    name = call_node.child_by_field_name("name")
    if obj is None or name is None:
        return None
    if (
        node_text(obj, src) not in _PATH_BUILDER_RECEIVERS
        or node_text(name, src) not in _PATH_BUILDER_METHODS
    ):
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


def _value_provenance(value_node, src: bytes) -> tuple[str, str] | None:
    """Map a single RHS / argument expression node to (path, provenance).

    Returns None when the node does not yield a resolvable path.
    Resolution order: bare string literal -> Path.of/Paths.get builder.
    """
    if value_node is None:
        return None
    lit = _string_literal_value(value_node, src)
    if lit is not None and lit != "":
        return (lit, _PROVENANCE_STRING_LITERAL)
    if value_node.type == "method_invocation":
        # Single-arg Path.of("x.txt") -> string_literal; multi-arg -> constructor.
        built = _resolve_path_builder(value_node, src)
        if built is not None:
            args = value_node.child_by_field_name("arguments")
            n = len([c for c in args.children if c.is_named]) if args else 0
            prov = _PROVENANCE_STRING_LITERAL if n == 1 else _PROVENANCE_PATH_CONSTRUCTOR
            return (built, prov)
    return None


def _collect_java_assignments(root, src: bytes) -> dict[str, tuple[str, str]]:
    """Return ``name -> (resolved_path, provenance)`` for the whole file.

    Two passes, mirroring the Go/Python resolver:
      PASS 1 (lower precedence): method PARAMETERS -> ("", function_parameter).
      PASS 2 (higher precedence): local-variable initializers overwrite params.

    Local forms handled (value must be a single resolvable expression):
      - ``Path p = Path.of("x.txt");``        -> string_literal
      - ``String q = "data.txt";``            -> string_literal
      - ``Path j = Paths.get("a", "b");``     -> path_constructor

    File scope (not per-method) is sufficient for this PoC and matches the Go
    reference, whose resolver is likewise whole-tree.
    """
    assignments: dict[str, tuple[str, str]] = {}

    # PASS 1: method/constructor formal parameters (lowest precedence).
    for param in walk_named(root, "formal_parameter"):
        name_node = None
        for child in param.children:
            if child.is_named and child.type == "identifier":
                name_node = child  # last identifier is the param name
        if name_node is not None:
            assignments[node_text(name_node, src)] = ("", _PROVENANCE_FUNCTION_PARAM)

    # PASS 2: local variable declarations (single declarator with an initializer).
    for decl in walk_named(root, "local_variable_declaration"):
        for declr in decl.children:
            if not declr.is_named or declr.type != "variable_declarator":
                continue
            name_node = declr.child_by_field_name("name")
            value_node = declr.child_by_field_name("value")
            if name_node is None or value_node is None:
                continue
            resolved = _value_provenance(value_node, src)
            if resolved is not None:
                assignments[node_text(name_node, src)] = resolved

    return assignments


def _resolve_arg_target(
    arg_node, src: bytes, assignments: dict[str, tuple[str, str]]
) -> tuple[str, str]:
    """Resolve a writer's path argument node to ``(resolved_target, provenance)``.

    Returns ``(_UNKNOWN_TARGET, _PROVENANCE_UNKNOWN)`` when the target cannot be
    resolved -- never a guessed/false target.

    Resolution order (mirrors the Go ``_resolve_arg_target``):
      1. bare string literal                 -> (literal, string_literal)
      2. inline Path.of(...) / Paths.get(...) -> (joined, string_literal|path_constructor)
      3. identifier -> assignment lookup      -> resolved value, or, when the
         identifier is a method parameter, ("", function_parameter) sentinel.
      4. Path.of(<identifier>) wrapper        -> unwrap to step 3 (so a parameter
         wrapped in the idiomatic ``Path.of(param)`` keeps function_parameter
         provenance rather than collapsing to unknown).
    """
    if arg_node is None:
        return (_UNKNOWN_TARGET, _PROVENANCE_UNKNOWN)

    # 1 + 2: inline literal or Path.of/Paths.get builder of literals.
    inline = _value_provenance(arg_node, src)
    if inline is not None:
        path, prov = inline
        if _is_plausible_path(path):
            return (path, prov)

    # 4. Path.of(<identifier>) / Paths.get(<identifier>): unwrap a single
    #    identifier argument so a wrapped variable/parameter is still traced.
    if arg_node.type == "method_invocation":
        obj = arg_node.child_by_field_name("object")
        name = arg_node.child_by_field_name("name")
        args = arg_node.child_by_field_name("arguments")
        if (
            obj is not None and name is not None and args is not None
            and node_text(obj, src) in _PATH_BUILDER_RECEIVERS
            and node_text(name, src) in _PATH_BUILDER_METHODS
        ):
            inner = [c for c in args.children if c.is_named]
            if len(inner) == 1 and inner[0].type == "identifier":
                arg_node = inner[0]  # fall through to identifier handling below

    # 3. Identifier -> assignment / parameter.
    if arg_node.type == "identifier":
        name = node_text(arg_node, src)
        entry = assignments.get(name)
        if entry is not None:
            path, prov = entry
            if prov == _PROVENANCE_FUNCTION_PARAM:
                return (_UNKNOWN_TARGET, _PROVENANCE_FUNCTION_PARAM)
            if path and _is_plausible_path(path):
                return (path, prov)

    return (_UNKNOWN_TARGET, _PROVENANCE_UNKNOWN)


# ---------------------------------------------------------------------------
# Adapter
# ---------------------------------------------------------------------------

class JavaAdapter(RegexAdapterBase):
    """Java adapter -- AST-based structural extractor via tree-sitter.

    Operates on ``.java`` files. Structural capability only for L5; all other
    supports_* flags remain False until later phases wire the corresponding
    builders to IR dispatch.

    Public interface (class name, method signatures, attributes, flags)
    is preserved exactly from the prior regex-based JavaAdapter.
    """

    language = "java"
    file_extensions = (".java",)
    supports_structural = True
    supports_contracts = True
    supports_runtime_signals = True
    supports_authority_writes = True

    # ------------------------------------------------------------------
    # Structural: imports
    # ------------------------------------------------------------------

    def extract_imports(self, content: str, path: Path) -> list[ImportEdge]:
        """Return one ImportEdge per import statement found in *content*.

        Handled forms:
            ``import com.example.Foo;``           -- confidence 1.0
            ``import static com.example.Foo.m;``  -- confidence 1.0
            ``import com.example.*;``             -- confidence 1.0
            ``import static com.example.Foo.*;``  -- confidence 1.0

        All Java imports are absolute (no relative import syntax).
        """
        _log.debug("extract_imports (tree-sitter): %s (%d chars)", path, len(content))
        src: bytes = content.encode("utf-8", errors="replace")
        root = parse_bytes(_LANGUAGE, src)
        from_path = Path(path).as_posix()

        edges: list[ImportEdge] = []
        seen: set[tuple[int, str]] = set()

        for decl in iter_named_children(root, "import_declaration"):
            fqn = _fqn_from_import(decl, src)
            if not fqn:
                continue
            line = node_line(decl)
            key = (line, fqn)
            if key in seen:
                continue
            seen.add(key)
            edges.append(ImportEdge(
                from_file=from_path,
                to_module=fqn,
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
        """Return one SymbolDef per top-level type declaration in *content*.

        Detected kinds:
            class     -- ``class`` declarations and ``record`` declarations
            interface -- ``interface`` declarations and ``@interface`` (annotation)
            enum      -- ``enum`` declarations

        Visibility:
            - ``"public"`` if the declaration has a ``public`` modifier.
            - ``"module"`` otherwise (package-private default).

        Inner types are NOT emitted: tree-sitter nests them inside a
        ``class_body`` so they do not appear as direct children of ``program``.
        """
        _log.debug("extract_symbols (tree-sitter): %s (%d chars)", path, len(content))
        src: bytes = content.encode("utf-8", errors="replace")
        root = parse_bytes(_LANGUAGE, src)

        syms: list[SymbolDef] = []

        for node in root.children:
            if not node.is_named:
                continue
            if node.type not in _TYPE_DECL_NODES:
                continue

            name = _name_from_decl(node, src)
            if not name:
                continue

            kind = _kind_from_node_type(node.type)
            visibility = _visibility_from_modifiers(node, src)
            syms.append(SymbolDef(
                name=name,
                kind=kind,
                line=node_line(node),
                visibility=visibility,
                confidence=1.0,
            ))

        syms.sort(key=lambda s: (s.line, s.name))
        return syms

    # ------------------------------------------------------------------
    # Contracts: class, record, interface, enum type declarations
    # ------------------------------------------------------------------

    def extract_contracts(self, content: str, path: Path) -> list[ContractCandidate]:
        """Return one ContractCandidate per top-level declared type.

        Handled forms:
            ``public class X { ... }``      → contract_kind="class"
            ``public record X(...) { }``    → contract_kind="record"  (Java 16+)
            ``public interface X { ... }``  → contract_kind="interface"
            ``public enum X { ... }``       → contract_kind="enum"

        Top-level types only: inner types are nested inside a ``class_body``
        so they do not appear as direct children of ``program``.

        Test files (path name ending with ``Test.java``) return ``[]``.

        All results carry ``confidence=1.0`` (AST-based extraction).
        Results are sorted by ``(line, name)``.
        """
        if Path(path).name.endswith("Test.java"):
            return []

        _log.debug("extract_contracts (tree-sitter): %s (%d chars)", path, len(content))
        src: bytes = content.encode("utf-8", errors="replace")
        root = parse_bytes(_LANGUAGE, src)

        # Map tree-sitter node type → contract_kind string.
        _CONTRACT_KIND: dict[str, str] = {
            "class_declaration": "class",
            "record_declaration": "record",
            "interface_declaration": "interface",
            "enum_declaration": "enum",
        }

        candidates: list[ContractCandidate] = []

        for node in root.children:
            if not node.is_named:
                continue
            contract_kind = _CONTRACT_KIND.get(node.type)
            if contract_kind is None:
                continue

            name = _name_from_decl(node, src)
            if not name:
                continue

            candidates.append(ContractCandidate(
                name=name,
                contract_kind=contract_kind,
                line=node_line(node),
                confidence=1.0,
            ))

        candidates.sort(key=lambda c: (c.line, c.name))
        return candidates

    # ------------------------------------------------------------------
    # Runtime signals: static initializer blocks, Spring stereotypes,
    # thread / executor spawns.
    # ------------------------------------------------------------------

    #: Spring stereotype annotation names that indicate DI registration.
    _SPRING_STEREOTYPES: frozenset[str] = frozenset({
        "Component", "Service", "Repository", "Configuration",
        "Controller", "RestController",
    })

    def extract_runtime(self, content: str, path: Path) -> list[TSRuntimeSignal]:
        """Detect Java import-time and concurrency side effects via tree-sitter AST.

        Emits TSRuntimeSignal (confidence=1.0) for:
            ``static { ... }`` initializer block
                → kind="static_block", payload={"call": "static_init"}
            class annotated with a Spring stereotype
            (@Component/@Service/@Repository/@Configuration/@Controller/@RestController)
                → kind="spring_component", payload={"call": <class name>}
            ``new Thread(...)``  (object_creation_expression of type Thread)
                → kind="thread_spawn", payload={"call": "new Thread"}
            ``*.submit(...)`` / ``*.execute(...)`` on an executor
                → kind="thread_spawn", payload={"call": "<receiver>.submit"} etc.

        Test files (path name ending with ``Test.java``) return ``[]``.
        Results are sorted by ``(line, kind)``.
        """
        if Path(path).name.endswith("Test.java"):
            return []

        _log.debug("extract_runtime (tree-sitter): %s (%d chars)", path, len(content))
        src: bytes = content.encode("utf-8", errors="replace")
        root = parse_bytes(_LANGUAGE, src)
        file_posix = Path(path).as_posix()

        signals: list[TSRuntimeSignal] = []

        # ------------------------------------------------------------------
        # Pass 1: top-level class_declaration nodes.
        # Check modifiers for static_initializer blocks and Spring annotations.
        # ------------------------------------------------------------------
        for node in root.children:
            if not node.is_named or node.type != "class_declaration":
                continue

            class_name = _name_from_decl(node, src)

            # --- Spring stereotype detection ---
            # Annotations live in the modifiers child; each annotation is either
            # a marker_annotation (no args) or annotation (with args).
            for child in node.children:
                if child.type != "modifiers":
                    continue
                for mod in child.children:
                    if mod.type not in ("marker_annotation", "annotation"):
                        continue
                    # The first named child of an annotation node is the identifier.
                    for id_child in mod.children:
                        if id_child.is_named and id_child.type == "identifier":
                            ann_name = node_text(id_child, src)
                            if ann_name in self._SPRING_STEREOTYPES:
                                signals.append(TSRuntimeSignal(
                                    kind="spring_component",
                                    file=file_posix,
                                    line=node_line(node),
                                    confidence=1.0,
                                    payload={"call": class_name},
                                ))
                            break  # only first identifier per annotation node

            # --- static_initializer detection inside class_body ---
            for child in node.children:
                if child.type != "class_body":
                    continue
                for body_child in child.children:
                    if not body_child.is_named or body_child.type != "static_initializer":
                        continue
                    signals.append(TSRuntimeSignal(
                        kind="static_block",
                        file=file_posix,
                        line=node_line(body_child),
                        confidence=1.0,
                        payload={"call": "static_init"},
                    ))

        # ------------------------------------------------------------------
        # Pass 2: walk entire tree for thread/executor spawn patterns.
        # ------------------------------------------------------------------

        # new Thread(...)
        for creation in walk_named(root, "object_creation_expression"):
            type_node = creation.child_by_field_name("type")
            if type_node is None:
                continue
            if node_text(type_node, src) == "Thread":
                signals.append(TSRuntimeSignal(
                    kind="thread_spawn",
                    file=file_posix,
                    line=node_line(creation),
                    confidence=1.0,
                    payload={"call": "new Thread"},
                ))

        # *.submit(...) / *.execute(...)
        for call in walk_named(root, "method_invocation"):
            name_node = call.child_by_field_name("name")
            obj_node = call.child_by_field_name("object")
            if name_node is None or obj_node is None:
                continue
            method = node_text(name_node, src)
            if method in ("submit", "execute"):
                receiver = node_text(obj_node, src)
                signals.append(TSRuntimeSignal(
                    kind="thread_spawn",
                    file=file_posix,
                    line=node_line(call),
                    confidence=1.0,
                    payload={"call": f"{receiver}.{method}"},
                ))

        signals.sort(key=lambda s: (s.line, s.kind))
        return signals

    # ------------------------------------------------------------------
    # Authority writes
    # ------------------------------------------------------------------

    def extract_writer_calls(
        self, content: str, path: Path
    ) -> list[AuthorityWriteCandidate]:
        """Detect write operations in Java source via tree-sitter AST.

        Walks ``method_invocation`` nodes and ``object_creation_expression``
        nodes to match writer patterns:

        ``method_invocation`` (object.name(args)):
        - ``Files.write(...)`` / ``Files.writeString(...)``  (java.nio)
              → ``write_kind="fs_write"``, target_hint = first arg text
        - ``*.write(...)`` / ``*.append(...)``  (any receiver, writer/stream)
              → ``write_kind="fs_write"``, target_hint = receiver (object) text
        - ``*.save(...)`` / ``*.persist(...)``  (JPA/Spring repo)
              → ``write_kind="orm_save"``, target_hint = receiver text

        ``object_creation_expression`` (new Type(args)):
        - ``new FileWriter(...)`` / ``new FileOutputStream(...)``
              → ``write_kind="fs_write"``, target_hint = first arg text

        Target resolution (additive — mirrors the Go PoC / Python resolver).
        For the path-argument writers (``Files.write`` / ``Files.writeString`` /
        ``new FileWriter`` / ``new FileOutputStream``) the first argument is
        resolved into ``resolved_target`` + ``provenance``:

        - string-literal arg                 → literal, ``provenance="string_literal"``
        - ``Path.of("x")`` / single literal  → literal, ``provenance="string_literal"``
        - ``Path.of("a","b")`` / ``Paths.get`` → joined, ``provenance="path_constructor"``
        - variable arg                       → traced to its local-variable
          initializer in scope (string literal or Path.of/Paths.get of literals)
        - method-parameter arg               → ``provenance="function_parameter"``
          (the target is a param, no literal at the call site) — target stays
          the ``__unknown_target__`` sentinel
        - unresolvable, incl. receiver       → ``resolved_target="__unknown_target__"``,
          ``*.write``/``*.append``/``*.save``   ``provenance="unknown"`` (no guessed target)

        Test files (path name ending with ``Test.java``) return ``[]``.
        All results carry ``confidence=1.0``.
        Results are sorted by ``(line, write_kind)``.
        """
        if Path(path).name.endswith("Test.java"):
            return []

        _log.debug("extract_writer_calls (tree-sitter): %s (%d chars)", path, len(content))
        src: bytes = content.encode("utf-8", errors="replace")
        root = parse_bytes(_LANGUAGE, src)

        # Resolve local-variable / parameter bindings once for the whole file.
        assignments = _collect_java_assignments(root, src)

        candidates: list[AuthorityWriteCandidate] = []

        def _hint(text: str) -> str:
            """Strip surrounding quotes and cap at 30 chars."""
            t = text.strip().strip('"\'').strip()
            return t[:30]

        def _first_arg_node(args_node):
            """Return the first named argument node of an argument_list, or None."""
            if args_node is None:
                return None
            for c in args_node.children:
                if c.is_named:
                    return c
            return None

        def _first_arg_text(args_node) -> str:
            """Return the text of the first argument from an argument_list node."""
            node = _first_arg_node(args_node)
            return node_text(node, src) if node is not None else ""

        # --- method_invocation: object.method(args) ---
        for call in walk_named(root, "method_invocation"):
            obj = call.child_by_field_name("object")
            name_node = call.child_by_field_name("name")
            args = call.child_by_field_name("arguments")
            if obj is None or name_node is None:
                continue

            receiver = node_text(obj, src)
            method = node_text(name_node, src)
            line = node_line(call)

            # Files.write / Files.writeString (java.nio) — first arg is the path.
            if receiver == "Files" and method in ("write", "writeString"):
                resolved, prov = _resolve_arg_target(_first_arg_node(args), src, assignments)
                candidates.append(AuthorityWriteCandidate(
                    write_kind="fs_write",
                    target_hint=_hint(_first_arg_text(args)),
                    line=line,
                    confidence=1.0,
                    resolved_target=resolved,
                    provenance=prov,
                ))

            # *.write / *.append (any other receiver — stream/writer, NOT a path).
            elif method in ("write", "append") and receiver != "Files":
                candidates.append(AuthorityWriteCandidate(
                    write_kind="fs_write",
                    target_hint=_hint(receiver),
                    line=line,
                    confidence=1.0,
                ))

            # *.save / *.persist (JPA/Spring — receiver is a repo, NOT a path).
            elif method in ("save", "persist"):
                candidates.append(AuthorityWriteCandidate(
                    write_kind="orm_save",
                    target_hint=_hint(receiver),
                    line=line,
                    confidence=1.0,
                ))

        # --- object_creation_expression: new Type(args) — first arg is the path. ---
        _WRITER_TYPES = frozenset({"FileWriter", "FileOutputStream"})
        for creation in walk_named(root, "object_creation_expression"):
            type_node = creation.child_by_field_name("type")
            args = creation.child_by_field_name("arguments")
            if type_node is None:
                continue
            type_name = node_text(type_node, src)
            if type_name not in _WRITER_TYPES:
                continue
            resolved, prov = _resolve_arg_target(_first_arg_node(args), src, assignments)
            candidates.append(AuthorityWriteCandidate(
                write_kind="fs_write",
                target_hint=_hint(_first_arg_text(args)),
                line=node_line(creation),
                confidence=1.0,
                resolved_target=resolved,
                provenance=prov,
            ))

        candidates.sort(key=lambda c: (c.line, c.write_kind))
        return candidates
