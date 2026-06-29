"""Shared write-target resolver for the JavaScript / TypeScript tree-sitter grammar.

TS and JS share the same tree-sitter grammar shapes for the constructs that
matter to write-target resolution (``call_expression`` / ``member_expression`` /
``lexical_declaration`` / ``variable_declarator`` / ``string`` / parameters), so
both adapters resolve targets through this single module -- mirroring the Go PoC
(``source_adapters/go.py``) and the Java adapter, and speaking the same
provenance vocabulary as the Python resolver (``_authority_ast.py``).

What it resolves: the file-path argument of the fs-family writers
(``fs.writeFile`` / ``fs.writeFileSync`` / ``fs.appendFile`` /
``fs.appendFileSync`` / ``fs.createWriteStream``) and the bare standalone
``writeFile`` / ``writeFileSync``.  Resolution outcomes:

  - string-literal arg            -> (literal, "string_literal")
  - ``path.join(...)`` of literals -> (joined, "path_constructor")
  - variable arg                  -> traced to its ``const``/``let``/``var``
    initializer in scope (string literal or ``path.join`` of literals)
  - function-parameter arg        -> ("", "function_parameter") sentinel (the
    target is a parameter; no literal at the call site)
  - unresolvable                  -> ("__unknown_target__", "unknown")  (no guess)

It deliberately does NOT touch the ORM / prisma / supabase / storage write
patterns -- those carry no resolvable file-path target and keep their existing
adapter behaviour.
"""
from __future__ import annotations

from pathlib import Path

from ._treesitter import iter_named_children, node_line, node_text, parse_bytes, walk_named

__all__ = [
    "UNKNOWN_TARGET",
    "PROVENANCE_PATH_CONSTRUCTOR",
    "PROVENANCE_STRING_LITERAL",
    "PROVENANCE_FUNCTION_PARAM",
    "PROVENANCE_UNKNOWN",
    "resolve_fs_writers",
]

UNKNOWN_TARGET = "__unknown_target__"
PROVENANCE_PATH_CONSTRUCTOR = "path_constructor"  # path.join(...)
PROVENANCE_STRING_LITERAL = "string_literal"      # "literal_path"
PROVENANCE_FUNCTION_PARAM = "function_parameter"  # function f(target)
PROVENANCE_UNKNOWN = "unknown"

# fs methods whose FIRST argument is a file-path target.
_FS_PATH_METHODS = frozenset({
    "writeFile", "writeFileSync",
    "appendFile", "appendFileSync",
    "createWriteStream",
})
# Bare standalone path-arg writers (no ``fs.`` receiver).
_STANDALONE_PATH_FNS = frozenset({"writeFile", "writeFileSync"})

# write_kind reported for each method (parity with the existing adapters).
_APPEND_METHODS = frozenset({"appendFile", "appendFileSync"})


def _string_literal_value(node, src: bytes) -> str | None:
    """Return the bare value of a JS/TS ``string`` node, else None.

    The bare value lives in the ``string_fragment`` child; an empty string
    literal ``""`` has no fragment and returns "".
    """
    if node is None or node.type != "string":
        return None
    for child in node.children:
        if child.type == "string_fragment":
            return node_text(child, src)
    return ""  # empty literal: "" / ''


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


def _resolve_path_join(call_node, src: bytes) -> str | None:
    """Resolve ``path.join("a","b",...)`` to ``"a/b/..."``.

    Best-effort: joins consecutive STRING-LITERAL arguments with ``/``.  Returns
    None when the node is not a ``*.join`` member call or any argument is a
    non-literal (variable, nested call, etc.) -> cannot fully resolve (no guess).
    """
    if call_node is None or call_node.type != "call_expression":
        return None
    fn = call_node.child_by_field_name("function")
    if fn is None or fn.type != "member_expression":
        return None
    prop = fn.child_by_field_name("property")
    if prop is None or node_text(prop, src) != "join":
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
    """Map a single RHS / argument expression node to (path, provenance), else None."""
    if value_node is None:
        return None
    lit = _string_literal_value(value_node, src)
    if lit is not None and lit != "":
        return (lit, PROVENANCE_STRING_LITERAL)
    if value_node.type == "call_expression":
        joined = _resolve_path_join(value_node, src)
        if joined is not None:
            return (joined, PROVENANCE_PATH_CONSTRUCTOR)
    return None


def _collect_assignments(root, src: bytes) -> dict[str, tuple[str, str]]:
    """Return ``name -> (resolved_path, provenance)`` for the whole file.

    Two passes (lower precedence first), mirroring the Go/Python resolver:
      PASS 1: function PARAMETERS -> ("", function_parameter).
      PASS 2: variable initializers (``const``/``let``/``var``) overwrite params.

    Single-declarator initializers only; destructuring / multi-name / re-assign
    are out of scope (left unresolved) -- matching the Go reference.
    """
    assignments: dict[str, tuple[str, str]] = {}

    # PASS 1: parameters (lowest precedence).
    #   TS: required_parameter / optional_parameter wrap an ``identifier``.
    #   JS: bare ``identifier`` directly inside formal_parameters.
    for params in walk_named(root, "formal_parameters"):
        for child in params.children:
            if not child.is_named:
                continue
            if child.type == "identifier":
                assignments[node_text(child, src)] = ("", PROVENANCE_FUNCTION_PARAM)
            elif child.type in ("required_parameter", "optional_parameter"):
                for gc in child.children:
                    if gc.is_named and gc.type == "identifier":
                        assignments[node_text(gc, src)] = ("", PROVENANCE_FUNCTION_PARAM)
                        break

    # PASS 2: variable declarations (single declarator with an initializer).
    for decl in walk_named(root, "lexical_declaration", "variable_declaration"):
        declarators = [c for c in decl.children if c.is_named and c.type == "variable_declarator"]
        if len(declarators) != 1:
            continue  # multi-name declaration -> out of scope
        declr = declarators[0]
        name_node = declr.child_by_field_name("name")
        value_node = declr.child_by_field_name("value")
        if name_node is None or name_node.type != "identifier" or value_node is None:
            continue
        resolved = _value_provenance(value_node, src)
        if resolved is not None:
            assignments[node_text(name_node, src)] = resolved

    return assignments


def _resolve_arg_target(
    arg_node, src: bytes, assignments: dict[str, tuple[str, str]]
) -> tuple[str, str]:
    """Resolve a writer's first-argument node to ``(resolved_target, provenance)``.

    Returns ``(UNKNOWN_TARGET, PROVENANCE_UNKNOWN)`` when the target cannot be
    resolved -- never a guessed/false target.  Mirrors the Go resolver order:
    inline literal -> inline path.join -> identifier (assignment / parameter).
    """
    if arg_node is None:
        return (UNKNOWN_TARGET, PROVENANCE_UNKNOWN)

    # 1 + 2: inline string literal or path.join of literals.
    inline = _value_provenance(arg_node, src)
    if inline is not None:
        path, prov = inline
        if _is_plausible_path(path):
            return (path, prov)

    # 3. Identifier -> assignment / parameter.
    if arg_node.type == "identifier":
        name = node_text(arg_node, src)
        entry = assignments.get(name)
        if entry is not None:
            path, prov = entry
            if prov == PROVENANCE_FUNCTION_PARAM:
                return (UNKNOWN_TARGET, PROVENANCE_FUNCTION_PARAM)
            if path and _is_plausible_path(path):
                return (path, prov)

    return (UNKNOWN_TARGET, PROVENANCE_UNKNOWN)


def resolve_fs_writers(language: str, content: str):
    """Parse *content* and yield resolved fs-family writer descriptors.

    Yields one dict per detected path-argument writer:
        {
            "line": int,                 # 1-based source line of the call
            "write_kind": str,           # "fs_write" | "fs_append"
            "target_hint": str,          # first-arg text (quotes stripped, <=30)
            "resolved_target": str,      # resolved path or UNKNOWN_TARGET
            "provenance": str,           # string_literal|path_constructor|
                                         #   function_parameter|unknown
            "standalone": bool,          # True for a bare writeFile() call (no
                                         #   ``fs.`` receiver) -- lets the caller
                                         #   pick the matching confidence.
        }

    Detected patterns (``language`` is "javascript" or "typescript"):
      - ``fs.writeFile`` / ``fs.writeFileSync``        -> fs_write
      - ``fs.appendFile`` / ``fs.appendFileSync``      -> fs_append
      - ``fs.createWriteStream``                        -> fs_write
      - bare ``writeFile`` / ``writeFileSync``          -> fs_write

    The caller owns confidence + final ordering; this resolver only knows the
    write_kind / target / provenance.  Reads and ORM/prisma/etc. patterns are
    intentionally out of scope (no resolvable file-path target).
    """
    src: bytes = content.encode("utf-8", errors="replace")
    root = parse_bytes(language, src)
    assignments = _collect_assignments(root, src)

    def _hint(text: str) -> str:
        return text.strip().strip("'\"`").strip()[:30]

    def _first_arg_node(args_node):
        if args_node is None:
            return None
        for c in args_node.children:
            if c.is_named:
                return c
        return None

    def _first_arg_text(args_node) -> str:
        n = _first_arg_node(args_node)
        return node_text(n, src) if n is not None else ""

    out: list[dict] = []
    for call in walk_named(root, "call_expression"):
        fn = call.child_by_field_name("function")
        args = call.child_by_field_name("arguments")
        if fn is None:
            continue

        method: str | None = None
        is_fs_receiver = False
        is_standalone = False

        if fn.type == "member_expression":
            obj = fn.child_by_field_name("object")
            prop = fn.child_by_field_name("property")
            if obj is None or prop is None:
                continue
            method = node_text(prop, src)
            is_fs_receiver = node_text(obj, src) == "fs"
        elif fn.type == "identifier":
            method = node_text(fn, src)
            is_standalone = True
        else:
            continue

        # Match only the path-argument writers.
        if is_fs_receiver and method in _FS_PATH_METHODS:
            pass
        elif is_standalone and method in _STANDALONE_PATH_FNS:
            pass
        else:
            continue

        resolved, prov = _resolve_arg_target(_first_arg_node(args), src, assignments)
        write_kind = "fs_append" if method in _APPEND_METHODS else "fs_write"
        out.append({
            "line": node_line(call),
            "write_kind": write_kind,
            "target_hint": _hint(_first_arg_text(args)),
            "resolved_target": resolved,
            "provenance": prov,
            "standalone": is_standalone,
        })

    return out
