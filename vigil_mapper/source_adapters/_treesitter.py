"""Shared tree-sitter helpers for source adapters.

Provides a cached parser factory and ergonomic utilities for walking
tree-sitter parse trees.  Language-neutral — designed for reuse by Go,
Java, JavaScript, TypeScript adapters and any future tree-sitter adapter.

Public API
----------
get_ts_parser(language)
    Return a cached ``tree_sitter.Parser`` initialised for *language*.
    Supported language names match those accepted by
    ``tree_sitter_language_pack.get_language``.

parse_bytes(language, source_bytes)
    Convenience: parse *source_bytes* and return the root ``Node``.

node_text(node, source_bytes)
    Decode the byte slice that corresponds to *node* in *source_bytes*.

node_line(node)
    Return the 1-based source line number for *node*.

iter_named_children(node, *types)
    Yield direct named children of *node* whose ``type`` is in *types*.
    If no types are given, yield all named children.

walk_named(node, *types)
    Depth-first generator over ALL named descendant nodes (including
    *node* itself) whose ``type`` is in *types*.
    If no types are given, yield all named descendants.

Verified against tree-sitter==0.25.2 / tree-sitter-language-pack==1.10.8.
Parser is constructed as ``Parser(get_language(lang))`` — the ``get_parser``
wrapper is ABI-broken on 0.25 and must NOT be used.
"""
from __future__ import annotations

import logging
from functools import lru_cache
from typing import Generator

from tree_sitter import Node, Parser
from tree_sitter_language_pack import get_language

__all__ = [
    "get_ts_parser",
    "parse_bytes",
    "node_text",
    "node_line",
    "iter_named_children",
    "walk_named",
]

_log = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Parser cache
# ---------------------------------------------------------------------------

@lru_cache(maxsize=32)
def get_ts_parser(language: str) -> Parser:
    """Return a cached ``Parser`` initialised for *language*.

    Uses ``Parser(get_language(language))`` — the verified form for
    tree-sitter==0.25.  The result is cached per language string so
    adapters instantiated many times pay the initialisation cost only once.

    Parameters
    ----------
    language:
        Language name understood by ``tree_sitter_language_pack``,
        e.g. ``"go"``, ``"java"``, ``"javascript"``, ``"typescript"``.

    Raises
    ------
    LookupError
        If *language* is not available in the installed language pack.
    """
    lang_obj = get_language(language)
    parser = Parser(lang_obj)
    _log.debug("tree-sitter parser created for language=%r", language)
    return parser


# ---------------------------------------------------------------------------
# Parse convenience
# ---------------------------------------------------------------------------

def parse_bytes(language: str, source_bytes: bytes) -> Node:
    """Parse *source_bytes* with the cached parser for *language*.

    Parameters
    ----------
    language:
        Language name (see :func:`get_ts_parser`).
    source_bytes:
        Raw UTF-8 encoded source code.

    Returns
    -------
    Node
        The ``root_node`` of the parsed tree.
    """
    parser = get_ts_parser(language)
    tree = parser.parse(source_bytes)
    return tree.root_node


# ---------------------------------------------------------------------------
# Node utilities
# ---------------------------------------------------------------------------

def node_text(node: Node, source_bytes: bytes) -> str:
    """Return the source text slice that corresponds to *node*.

    Decodes as UTF-8 (errors replaced) so callers always get a ``str``.
    """
    return source_bytes[node.start_byte:node.end_byte].decode("utf-8", errors="replace")


def node_line(node: Node) -> int:
    """Return the 1-based line number of *node* in the source file.

    tree-sitter stores ``start_point`` as a ``(row, column)`` tuple where
    ``row`` is 0-based; we add 1 to match the convention used throughout
    the adapter IR.
    """
    return node.start_point[0] + 1


def iter_named_children(node: Node, *types: str) -> Generator[Node, None, None]:
    """Yield direct named children of *node* filtered by ``type``.

    Parameters
    ----------
    node:
        Parent node whose children to iterate.
    *types:
        Optional whitelist of node type strings.  If omitted, all named
        children are yielded.

    Yields
    ------
    Node
        Named child nodes matching the type filter.
    """
    type_set: frozenset[str] | None = frozenset(types) if types else None
    for child in node.children:
        if not child.is_named:
            continue
        if type_set is None or child.type in type_set:
            yield child


def walk_named(node: Node, *types: str) -> Generator[Node, None, None]:
    """Depth-first generator over all named descendants of *node*.

    *node* itself is included if it matches the type filter.

    Parameters
    ----------
    node:
        Starting node (included in traversal).
    *types:
        Optional whitelist of node type strings.  If omitted, all named
        nodes are yielded.

    Yields
    ------
    Node
        Named descendant nodes matching the type filter.
    """
    type_set: frozenset[str] | None = frozenset(types) if types else None
    stack = [node]
    while stack:
        current = stack.pop()
        if current.is_named and (type_set is None or current.type in type_set):
            yield current
        # Push children in reverse so left-to-right DFS order is preserved.
        for child in reversed(current.children):
            stack.append(child)
