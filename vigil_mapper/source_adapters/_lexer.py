"""Shared preprocessing utilities for regex-based source adapters.

L2 implementation: C-family comment & string stripping plus multi-line import
collapsing for TypeScript / JavaScript. Single-pass character-by-character
scanner in ``strip_comments_and_strings`` -- O(n), stdlib only, no external
parser dependency.

Python adapter does NOT use this module -- it calls ``ast.parse`` directly.

Language argument is retained in the signature for future L5 dispatch
(Go / Java share the C-family rules) but currently only ``"typescript"``,
``"javascript"`` are recognised. Unknown languages fall back to a safe
passthrough (caller still works, just with comment/string false-positives).
"""
from __future__ import annotations

import logging
import re

__all__ = [
    "strip_comments_and_strings",
    "strip_comments_only",
    "join_multiline_imports",
    "strip_go_raw_strings",
]

_log = logging.getLogger(__name__)

# Languages that share C-family comment + string syntax.
_C_FAMILY: frozenset[str] = frozenset({"typescript", "javascript", "go", "java"})


def strip_comments_only(content: str, language: str) -> str:
    """Remove line and block comments while PRESERVING string literals intact.

    Used by ``extract_imports`` where the module specifier IS a string body
    (``from 'react'``) -- we must not destroy it. String literals are still
    scanned so that a comment opener inside a string (e.g. ``"http://x"``)
    does not accidentally trigger comment stripping.

    Unknown languages fall back to a passthrough.
    """
    if language not in _C_FAMILY:
        return content

    out: list[str] = []
    i = 0
    n = len(content)

    while i < n:
        ch = content[i]
        nxt = content[i + 1] if i + 1 < n else ""

        # Line comment //...
        if ch == "/" and nxt == "/":
            j = content.find("\n", i + 2)
            if j == -1:
                break
            out.append("\n")
            i = j + 1
            continue

        # Block comment /* ... */
        if ch == "/" and nxt == "*":
            j = content.find("*/", i + 2)
            if j == -1:
                for c in content[i:]:
                    if c == "\n":
                        out.append("\n")
                break
            for c in content[i:j + 2]:
                if c == "\n":
                    out.append("\n")
            i = j + 2
            continue

        # String literal — preserve contents verbatim but skip past so a
        # ``//`` / ``/*`` inside the body cannot trigger comment stripping.
        if ch in ("'", '"', "`"):
            quote = ch
            out.append(quote)
            i += 1
            while i < n:
                c = content[i]
                if c == "\\" and i + 1 < n:
                    out.append(c)
                    out.append(content[i + 1])
                    i += 2
                    continue
                out.append(c)
                if c == quote:
                    i += 1
                    break
                i += 1
            continue

        out.append(ch)
        i += 1

    return "".join(out)


def strip_comments_and_strings(content: str, language: str) -> str:
    """Remove comment and string literal regions from *content*.

    Replaces:
        - ``//`` line comments -> emit the trailing newline untouched.
        - ``/* ... */`` block comments -> emit newlines that fell inside.
        - ``'...'`` / ``"..."`` / `` `...` `` string spans -> emit empty body
          (quotes preserved) plus any internal newlines.

    Escape sequences (``\\"``, ``\\'``, ``\\\\``, ``\\n``, etc.) inside strings
    do NOT terminate the string. Template literals are treated as simple
    strings for L2 -- nested ``${...}`` expressions are NOT re-parsed.

    Newlines are always preserved so that ``re.MULTILINE`` patterns matching
    against the cleaned output still recover correct 1-based line numbers.

    Unknown languages fall back to a passthrough (returns *content* unchanged)
    -- L2 covers only ``typescript`` and ``javascript``.
    """
    if language not in _C_FAMILY:
        return content

    out: list[str] = []
    i = 0
    n = len(content)

    while i < n:
        ch = content[i]
        nxt = content[i + 1] if i + 1 < n else ""

        # Line comment //...\n
        if ch == "/" and nxt == "/":
            j = content.find("\n", i + 2)
            if j == -1:
                # Comment runs to EOF; emit nothing more.
                break
            # Preserve the newline so line numbers stay aligned.
            out.append("\n")
            i = j + 1
            continue

        # Block comment /* ... */
        if ch == "/" and nxt == "*":
            j = content.find("*/", i + 2)
            if j == -1:
                # Unterminated block comment runs to EOF — swallow, preserve
                # any embedded newlines so line counts don't collapse.
                for c in content[i:]:
                    if c == "\n":
                        out.append("\n")
                break
            # Preserve embedded newlines within the comment.
            for c in content[i:j + 2]:
                if c == "\n":
                    out.append("\n")
            i = j + 2
            continue

        # String literals
        if ch in ("'", '"', "`"):
            quote = ch
            out.append(quote)
            i += 1
            while i < n:
                c = content[i]
                if c == "\\" and i + 1 < n:
                    # Skip the escape + escaped char. Don't emit either into
                    # the body (body is intentionally empty), but preserve
                    # a newline only if the escape targets a literal newline.
                    esc = content[i + 1]
                    if esc == "\n":
                        out.append("\n")
                    i += 2
                    continue
                if c == quote:
                    out.append(quote)
                    i += 1
                    break
                if c == "\n":
                    # Preserve newline. Note: unescaped newlines in '...'/"..."
                    # are a syntax error in TS/JS, but template literals allow
                    # them. Either way we keep line counts correct.
                    out.append("\n")
                    i += 1
                    continue
                # Regular character inside string: drop (body becomes empty).
                i += 1
            else:
                # EOF reached without closing quote — bail cleanly.
                _log.debug(
                    "strip_comments_and_strings: unterminated %s string literal",
                    quote,
                )
            continue

        # Regular source character.
        out.append(ch)
        i += 1

    return "".join(out)


# Matches ``import { ... } from 'x'`` (or `"x"`) or the re-export form
# ``export { ... } from 'x'`` where the brace group may span multiple lines.
# ``from '...'`` is MANDATORY — this prevents the regex from swallowing
# unrelated brace groups like ``export class Foo {}`` or
# ``export function bar() { ... }``.
# Captured groups:
#   1: leading keyword phrase up to and including the opening brace
#   2: multi-line brace body (non-greedy, without braces)
#   3: trailing portion including ``from 'x'`` or ``from "x"``
_MULTILINE_BRACE_IMPORT = re.compile(
    r"(^[ \t]*(?:import|export)[^\n{]*?\{)"          # keyword ... {
    r"([^{}]*?)"                                      # body (no braces)
    r"(\}[ \t]*from[ \t]*['\"][^'\"\n]+['\"][ \t]*;?)",  # } from '...' ;
    re.MULTILINE | re.DOTALL,
)


def join_multiline_imports(content: str, language: str) -> str:
    """Collapse multi-line brace-group imports onto a single logical line.

    Transforms::

        import {
            ComponentA,
            ComponentB,
        } from './components';

    into::

        import {  ComponentA, ComponentB, } from './components';

    Leading indentation is preserved so the ``import`` keyword stays at the
    same 1-based line number (any embedded newlines inside the brace group
    are simply replaced with a single space). Lines preceding and following
    the statement are untouched, so downstream regex matchers that count via
    ``re.MULTILINE`` still report the original ``import`` line number.

    Unknown languages fall back to a passthrough.
    """
    if language not in _C_FAMILY:
        return content

    def _collapse(match: re.Match[str]) -> str:
        head, body, tail = match.group(1), match.group(2), match.group(3)
        # Count newlines that fall between the opening '{' and the ';' (or
        # line-end). We collapse them into a single space inside the brace
        # group, but append them AFTER the statement so the line number of
        # every subsequent ``import`` keyword — and every later symbol — is
        # preserved byte-for-byte against the original source.
        original = match.group(0)
        nl_count = original.count("\n")
        flat = re.sub(r"\s+", " ", body)
        collapsed = f"{head} {flat.strip()} {tail}"
        # Re-emit the newlines so downstream line numbers stay stable.
        return collapsed + ("\n" * nl_count)

    return _MULTILINE_BRACE_IMPORT.sub(_collapse, content)


def strip_go_raw_strings(content: str) -> str:
    """Replace Go backtick raw string bodies with empty bodies.

    Go raw string literals are delimited by backticks (`` ` ``).  They
    have NO escape sequences -- a backtick cannot appear inside the literal.
    The entire span from opening to closing backtick is therefore replaced by
    two consecutive backtick characters, preserving any embedded newlines as
    plain newlines so that downstream line-number counts remain stable.

    This function must be applied BEFORE ``strip_comments_only`` when
    processing Go source for import extraction, because ``strip_comments_only``
    preserves string bodies verbatim (needed for ``"..."`` import paths) and
    would otherwise keep the backtick body intact -- allowing fake imports
    embedded in raw string literals to produce false-positive ImportEdges.

    Usage::

        cleaned = strip_go_raw_strings(source)
        cleaned = strip_comments_only(cleaned, "go")
    """
    out: list[str] = []
    i = 0
    n = len(content)

    while i < n:
        ch = content[i]
        if ch == "`":
            # Opening backtick — scan until closing backtick (no escapes).
            out.append("`")
            i += 1
            while i < n:
                c = content[i]
                i += 1
                if c == "`":
                    # Closing backtick — emit it and stop.
                    out.append("`")
                    break
                if c == "\n":
                    # Preserve newlines to keep line numbers correct.
                    out.append("\n")
                # All other characters in the raw string are dropped.
        else:
            out.append(ch)
            i += 1

    return "".join(out)
