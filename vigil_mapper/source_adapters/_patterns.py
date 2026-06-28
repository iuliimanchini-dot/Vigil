"""Shared regex patterns for TypeScript / JavaScript adapters.

Factoring out keeps the adapter modules under the 400-line budget and
guarantees that TS and JS behave identically on overlapping syntax
(ES-module import/export, top-level class/function declarations).

All patterns operate on *cleaned* source -- i.e. output of
``_lexer.strip_comments_and_strings`` then ``_lexer.join_multiline_imports``.
String bodies are therefore empty (``''`` / ``""`` / `` `` ``) and comments
are gone, which prevents ``//`` or ``/* import fake */`` from matching.
"""
from __future__ import annotations

import re
import logging
_log = logging.getLogger(__name__)

__all__ = [
    "RE_IMPORT_DEFAULT",
    "RE_IMPORT_NAMED",
    "RE_IMPORT_NAMESPACE",
    "RE_IMPORT_SIDE_EFFECT",
    "RE_IMPORT_TYPE_DEFAULT",
    "RE_IMPORT_TYPE_NAMED",
    "RE_EXPORT_FROM_NAMED",
    "RE_EXPORT_FROM_STAR",
    "RE_DYNAMIC_IMPORT",
    "RE_REQUIRE_ASSIGN",
    "RE_REQUIRE_BARE",
    "RE_SYMBOL_CLASS",
    "RE_SYMBOL_INTERFACE",
    "RE_SYMBOL_TYPE",
    "RE_SYMBOL_FUNCTION",
    "RE_SYMBOL_CONST",
    "RE_SYMBOL_ENUM",
    "classify_import",
]


# ---------------------------------------------------------------------------
# Import-form regex patterns (ES modules)
# ---------------------------------------------------------------------------
#
# Conventions:
#   - ``^`` anchors every pattern to start-of-line (re.MULTILINE) so that
#     nested ``import(...)`` inside a function body is still caught by the
#     dynamic-import pattern below (which is NOT line-anchored).
#   - Target module is captured as group ``module``.
#   - Quotes may be single or double. Template-literal imports are not
#     recognised here (rare; low confidence; explicit tech-debt for L6).

# ``import X from 'Y'``  (default only)
RE_IMPORT_DEFAULT = re.compile(
    r"""^[ \t]*import\s+
        (?!type\b)                                    # skip 'import type ...'
        [A-Za-z_$][\w$]*                              # default binding
        \s+from\s+
        ['"](?P<module>[^'"\n]+)['"]\s*;?\s*$""",
    re.MULTILINE | re.VERBOSE,
)

# ``import { A, B } from 'Y'`` (named only, maybe with default prefix)
RE_IMPORT_NAMED = re.compile(
    r"""^[ \t]*import\s+
        (?!type\b)
        (?:[A-Za-z_$][\w$]*\s*,\s*)?                  # optional default binding
        \{[^}]*\}                                      # named group (may be empty)
        \s+from\s+
        ['"](?P<module>[^'"\n]+)['"]\s*;?\s*$""",
    re.MULTILINE | re.VERBOSE,
)

# ``import * as X from 'Y'``
RE_IMPORT_NAMESPACE = re.compile(
    r"""^[ \t]*import\s+
        \*\s+as\s+[A-Za-z_$][\w$]*
        \s+from\s+
        ['"](?P<module>[^'"\n]+)['"]\s*;?\s*$""",
    re.MULTILINE | re.VERBOSE,
)

# ``import 'Y'`` (side-effect only)
RE_IMPORT_SIDE_EFFECT = re.compile(
    r"""^[ \t]*import\s+['"](?P<module>[^'"\n]+)['"]\s*;?\s*$""",
    re.MULTILINE | re.VERBOSE,
)

# ``import type X from 'Y'`` (TS-only)
RE_IMPORT_TYPE_DEFAULT = re.compile(
    r"""^[ \t]*import\s+type\s+
        [A-Za-z_$][\w$]*
        \s+from\s+
        ['"](?P<module>[^'"\n]+)['"]\s*;?\s*$""",
    re.MULTILINE | re.VERBOSE,
)

# ``import type { X } from 'Y'`` (TS-only)
RE_IMPORT_TYPE_NAMED = re.compile(
    r"""^[ \t]*import\s+type\s+
        \{[^}]*\}
        \s+from\s+
        ['"](?P<module>[^'"\n]+)['"]\s*;?\s*$""",
    re.MULTILINE | re.VERBOSE,
)

# ``export { A, B } from 'Y'`` (re-export)
RE_EXPORT_FROM_NAMED = re.compile(
    r"""^[ \t]*export\s+
        \{[^}]*\}
        \s+from\s+
        ['"](?P<module>[^'"\n]+)['"]\s*;?\s*$""",
    re.MULTILINE | re.VERBOSE,
)

# ``export * from 'Y'`` or ``export * as NS from 'Y'``
RE_EXPORT_FROM_STAR = re.compile(
    r"""^[ \t]*export\s+
        \*(?:\s+as\s+[A-Za-z_$][\w$]*)?
        \s+from\s+
        ['"](?P<module>[^'"\n]+)['"]\s*;?\s*$""",
    re.MULTILINE | re.VERBOSE,
)

# Dynamic ``import('Y')`` — NOT line-anchored; may appear inside expressions.
RE_DYNAMIC_IMPORT = re.compile(
    r"""\bimport\s*\(\s*
        ['"](?P<module>[^'"\n]+)['"]
        \s*\)""",
    re.VERBOSE,
)

# CommonJS: ``const|let|var X = require('Y')`` (assignment form)
RE_REQUIRE_ASSIGN = re.compile(
    r"""^[ \t]*(?:const|let|var)\s+
        (?:[A-Za-z_$][\w$]*|\{[^}]*\}|\[[^\]]*\])      # binding (ident | destructure)
        \s*=\s*require\s*\(\s*
        ['"](?P<module>[^'"\n]+)['"]
        \s*\)\s*;?\s*$""",
    re.MULTILINE | re.VERBOSE,
)

# CommonJS bare: ``require('Y');`` (side-effect)
RE_REQUIRE_BARE = re.compile(
    r"""^[ \t]*require\s*\(\s*
        ['"](?P<module>[^'"\n]+)['"]
        \s*\)\s*;?\s*$""",
    re.MULTILINE | re.VERBOSE,
)


# ---------------------------------------------------------------------------
# Symbol-definition regex patterns — top-level only
# ---------------------------------------------------------------------------
#
# Top-level is approximated by requiring the declaration keyword to start at
# column zero, optionally preceded by ``export `` / ``export default ``.
# Indented declarations inside function bodies, classes, or blocks are not
# captured — this is intentional for L2 (avoids nested noise; deep parsing
# is a tree-sitter job for L6+).

_EXPORT_PREFIX = r"(?P<export>export\s+(?:default\s+)?)?"
_TOPLEVEL_START = r"^" + _EXPORT_PREFIX

RE_SYMBOL_CLASS = re.compile(
    _TOPLEVEL_START
    + r"(?:abstract\s+)?class\s+(?P<name>[A-Za-z_$][\w$]*)",
    re.MULTILINE,
)

RE_SYMBOL_INTERFACE = re.compile(
    _TOPLEVEL_START + r"interface\s+(?P<name>[A-Za-z_$][\w$]*)",
    re.MULTILINE,
)

RE_SYMBOL_TYPE = re.compile(
    _TOPLEVEL_START + r"type\s+(?P<name>[A-Za-z_$][\w$]*)\s*(?:<[^>]*>)?\s*=",
    re.MULTILINE,
)

RE_SYMBOL_FUNCTION = re.compile(
    _TOPLEVEL_START
    + r"(?:async\s+)?function\s*\*?\s*(?P<name>[A-Za-z_$][\w$]*)\s*\(",
    re.MULTILINE,
)

RE_SYMBOL_CONST = re.compile(
    _TOPLEVEL_START
    + r"(?:const|let|var)\s+(?P<name>[A-Za-z_$][\w$]*)\s*[:=]",
    re.MULTILINE,
)

RE_SYMBOL_ENUM = re.compile(
    _TOPLEVEL_START
    + r"(?:const\s+)?enum\s+(?P<name>[A-Za-z_$][\w$]*)",
    re.MULTILINE,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def classify_import(module: str) -> str:
    """Return ``"relative"`` for dot-prefixed specifiers, else ``"absolute"``.

    Matches Node ESM / TS convention: a specifier starting with ``.`` or
    ``..`` (or ``/``) is relative to the file; anything else -- including
    scoped packages like ``@scope/pkg`` and node: builtins -- is absolute.
    """
    if module.startswith(".") or module.startswith("/"):
        return "relative"
    return "absolute"
