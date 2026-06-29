"""AST resolver utilities for the authority map (Python write-site analysis).

Internal module -- not part of the public API. Extracted VERBATIM from
authority_builder.py so the same byte-identical resolver can be shared by:
  - authority_builder.py (legacy consumption), and
  - source_adapters.python.PythonAdapter.extract_writer_calls (unified path).

This mirrors the existing _runtime_ast.py split (visitor extracted from
runtime_builder.py). No logic changes here: target resolution, alias chaining,
provenance tracking, os.replace / open(mode) / json.dump detection are all
identical to the historical authority_builder implementation.
"""
from __future__ import annotations

import ast
import re
from pathlib import Path
from typing import NamedTuple

__all__ = [
    "WriteCall",
    "_WRITE_METHOD_NAMES",
    "_UNKNOWN_TARGET",
    "_PROVENANCE_PATH_CONSTRUCTOR",
    "_PROVENANCE_STRING_LITERAL",
    "_PROVENANCE_FUNCTION_PARAM",
    "_PROVENANCE_UNKNOWN",
    "_open_mode_is_write",
    "_extract_string_value",
    "_is_plausible_path",
    "_resolve_call_target",
    "_resolve_func_arg_target",
    "_detect_func_write",
    "_collect_assignments",
    "_scan_write_calls",
]

_WRITE_METHOD_NAMES = frozenset({"write_text", "write_bytes", "save"})
_UNKNOWN_TARGET = "__unknown_target__"

# Provenance type constants for path tracking
_PROVENANCE_PATH_CONSTRUCTOR = "path_constructor"  # Path(...), PurePath(...), etc.
_PROVENANCE_STRING_LITERAL = "string_literal"      # "literal_path"
_PROVENANCE_FUNCTION_PARAM = "function_parameter"  # def foo(target):
_PROVENANCE_UNKNOWN = "unknown"


def _open_mode_is_write(mode: str) -> bool:
    """True iff an open() mode string mutates the target.

    Write modes contain 'w', 'a', 'x' (create/truncate/append) or '+'
    (read-update / write-update — both can write). A bare ``open(p)`` defaults
    to ``"r"``; ``"r"`` / ``"rb"`` / ``"rt"`` are pure READS → not writes.
    The ``b``/``t`` flags are binary/text modifiers and do not imply a write.
    """
    return any(ch in mode for ch in ("w", "a", "x", "+"))


# ---------------------------------------------------------------------------
# Write call tracking
# ---------------------------------------------------------------------------

class WriteCall(NamedTuple):
    """Represents a single write call with provenance and location info."""
    target: str       # resolved target path or _UNKNOWN_TARGET
    operation: str    # "write_text" | "write_bytes" | "os.replace" | "save" | "unknown"
    line: int | None  # source line number of the call (or None if unavailable)
    provenance: str   # "path_constructor" | "string_literal" | "function_parameter" | "unknown"


# ---------------------------------------------------------------------------
# AST helpers
# ---------------------------------------------------------------------------

def _extract_string_value(node: ast.expr | None) -> str | None:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    return None


def _is_plausible_path(s: str) -> bool:
    """True iff s looks like a file path (not a multi-line string or code snippet).

    Bare filenames (Makefile, Dockerfile, LICENSE, Procfile, README) are valid.
    """
    if not s or len(s) > 512:
        return False
    if '\n' in s or '\r' in s:
        return False
    # Bare filenames that are valid write targets
    if Path(s).name in {"Makefile", "Dockerfile", "Procfile", "LICENSE", "README"}:
        return True
    # Otherwise must contain at least one path-like character
    if '/' not in s and '\\' not in s and '.' not in s:
        return False
    return True


def _resolve_call_target(
    call_node: ast.Call,
    assignments: dict[str, str],
    aliases: dict[str, str] | None = None,
) -> str | None:
    """Resolve the file-path target of a write call via AST analysis."""
    if aliases is None:
        aliases = {}
    func = call_node.func
    if not isinstance(func, ast.Attribute):
        return None
    receiver = func.value
    # Path("literal").write_text(...) or path.with_suffix(...).write_text(...)
    if isinstance(receiver, ast.Call) and isinstance(receiver.func, (ast.Name, ast.Attribute)):
        fname = receiver.func.id if isinstance(receiver.func, ast.Name) else receiver.func.attr
        if fname in ("Path", "PurePath", "PosixPath", "WindowsPath") and receiver.args:
            return _extract_string_value(receiver.args[0])
        # .with_suffix(...).write_text() or .with_name(...).write_text()
        if fname in ("with_suffix", "with_name", "with_stem"):
            inner = receiver.func.value if isinstance(receiver.func, ast.Attribute) else None
            if isinstance(inner, ast.Name):
                name = inner.id
                resolved = name
                visited: set[str] = {resolved}
                for _ in range(8):
                    nxt = aliases.get(resolved)
                    if nxt is None or nxt in visited:
                        break
                    visited.add(nxt)
                    resolved = nxt
                return assignments.get(resolved)
    # name.write_text(...) with alias following
    if isinstance(receiver, ast.Name):
        name = receiver.id
        resolved = name
        visited: set[str] = {resolved}
        for _ in range(8):
            nxt = aliases.get(resolved)
            if nxt is None or nxt in visited:
                break
            visited.add(nxt)
            resolved = nxt
        return assignments.get(resolved)
    # self.attr.write_text(...)
    if isinstance(receiver, ast.Attribute) and isinstance(receiver.value, ast.Name):
        return assignments.get("%s.%s" % (receiver.value.id, receiver.attr))
    return None


def _resolve_func_arg_target(
    arg_node: ast.expr | None,
    assignments: dict[str, str],
    aliases: dict[str, str],
) -> str | None:
    """Resolve a path-like target from a positional call argument.

    Handles a string literal, ``Path("literal")``, or a variable name that an
    assignment resolved to a string/Path (with alias chaining). Returns None
    when the target cannot be resolved.
    """
    if arg_node is None:
        return None
    # "literal"
    lit = _extract_string_value(arg_node)
    if lit is not None:
        return lit
    # Path("literal") / PurePath("literal")
    if isinstance(arg_node, ast.Call) and isinstance(arg_node.func, (ast.Name, ast.Attribute)):
        fname = arg_node.func.id if isinstance(arg_node.func, ast.Name) else arg_node.func.attr
        if fname in ("Path", "PurePath", "PosixPath", "WindowsPath") and arg_node.args:
            return _extract_string_value(arg_node.args[0])
    # variable name -> resolve through aliases + assignments
    if isinstance(arg_node, ast.Name):
        resolved = arg_node.id
        visited: set[str] = {resolved}
        for _ in range(8):
            nxt = aliases.get(resolved)
            if nxt is None or nxt in visited:
                break
            visited.add(nxt)
            resolved = nxt
        return assignments.get(resolved)
    return None


def _detect_func_write(
    node: ast.Call,
    assignments: dict[str, str],
    aliases: dict[str, str],
) -> tuple[str, str | None] | None:
    """Detect ``open(path, "w")`` and ``json.dump(obj, fp)`` function-call writes.

    These are plain function calls (``ast.Name`` / module ``ast.Attribute``),
    NOT receiver-method calls, so the standard ``_WRITE_METHOD_NAMES`` scan
    misses them. Returns ``(operation, target_or_None)`` for a write, else None.

    - ``open(path, mode)`` is a write only when ``mode`` mutates the target
      (see :func:`_open_mode_is_write`). A bare ``open(p)`` / ``open(p, "r")``
      is a READ → returns None (precision guard).
    - ``json.dump(obj, fp)`` writes to ``fp``; ``json.dumps`` (returns a string)
      and ``json.load`` / ``json.loads`` (reads) are NOT writes.
    """
    func = node.func

    # open(...) — builtin name (assume builtin; shadowing is rare and out of scope)
    if isinstance(func, ast.Name) and func.id == "open":
        mode = "r"  # open() default
        if len(node.args) >= 2:
            lit = _extract_string_value(node.args[1])
            if lit is not None:
                mode = lit
        else:
            for kw in node.keywords:
                if kw.arg == "mode":
                    lit = _extract_string_value(kw.value)
                    if lit is not None:
                        mode = lit
        if not _open_mode_is_write(mode):
            return None
        target = _resolve_func_arg_target(
            node.args[0] if node.args else None, assignments, aliases
        )
        return ("open_write", target)

    # json.dump(obj, fp, ...) — module attribute call. Target = fp (2nd arg),
    # best-effort (usually a file handle variable). dumps/load/loads excluded.
    if isinstance(func, ast.Attribute) and func.attr == "dump":
        receiver = func.value
        if isinstance(receiver, ast.Name) and receiver.id == "json":
            fp_node = node.args[1] if len(node.args) >= 2 else None
            target = _resolve_func_arg_target(fp_node, assignments, aliases)
            return ("json_dump", target)

    return None


def _collect_assignments(tree: ast.AST) -> tuple[dict[str, tuple[str, str]], dict[str, str]]:
    """Return (assignments_typed, aliases).

    assignments_typed: name -> (string-path, provenance_type)
    - Provenance types: path_constructor, string_literal, function_parameter, unknown
    aliases: name -> other_name (for .with_suffix/.with_name/.with_stem chains)

    First pass: extract function parameters (lower precedence)
    Second pass: extract assignments (higher precedence, overwrites params)
    """
    assignments_typed: dict[str, tuple[str, str]] = {}
    aliases: dict[str, str] = {}

    # PASS 1: Extract function parameters
    for node in ast.walk(tree):
        if not isinstance(node, ast.FunctionDef):
            continue
        for arg in node.args.args:
            # Function parameter: store with empty path, provenance_type = function_parameter
            assignments_typed[arg.arg] = ("", _PROVENANCE_FUNCTION_PARAM)

    # PASS 2: Extract assignments (overwrites function params if same name)
    for node in ast.walk(tree):
        if not isinstance(node, ast.Assign) or len(node.targets) != 1:
            continue
        target = node.targets[0]
        if isinstance(target, ast.Name):
            key = target.id
        elif isinstance(target, ast.Attribute) and isinstance(target.value, ast.Name):
            key = "%s.%s" % (target.value.id, target.attr)
        else:
            continue
        value = node.value
        if isinstance(value, ast.Constant) and isinstance(value.value, str):
            # String literal assignment
            assignments_typed[key] = (value.value, _PROVENANCE_STRING_LITERAL)
        elif isinstance(value, ast.Call) and isinstance(value.func, (ast.Name, ast.Attribute)):
            fname = value.func.id if isinstance(value.func, ast.Name) else value.func.attr
            if fname in ("Path", "PurePath", "PosixPath", "WindowsPath") and value.args:
                val = _extract_string_value(value.args[0])
                if val is not None:
                    # Path constructor
                    assignments_typed[key] = (val, _PROVENANCE_PATH_CONSTRUCTOR)
                else:
                    assignments_typed[key] = ("", _PROVENANCE_UNKNOWN)
            elif fname in ("with_suffix", "with_name", "with_stem"):
                receiver = value.func.value
                if isinstance(receiver, ast.Name):
                    aliases[key] = receiver.id
    return assignments_typed, aliases


def _scan_write_calls(
    tree: ast.AST,
    assignments_typed: dict[str, tuple[str, str]],
    aliases: dict[str, str] | None = None,
) -> list[WriteCall]:
    """Return WriteCall objects for each write call found in tree.

    Args:
        tree: AST tree to scan
        assignments_typed: {var_name: (target_path, provenance_type)}
        aliases: {var_name: alias_var_name} for .with_suffix chains

    Returns:
        list[WriteCall] with target, operation, line, and provenance
    """
    if aliases is None:
        aliases = {}

    # Flatten assignments for target resolution
    assignments = {k: v[0] for k, v in assignments_typed.items()}

    calls: list[WriteCall] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue

        line_no = node.lineno if hasattr(node, 'lineno') else None

        # Function-call writes: open(path, "w"), json.dump(obj, fp).
        # These are NOT receiver-method calls, so handle them before the
        # ast.Attribute gate below. Reads (open(p)/open(p,"r")) return None.
        func_write = _detect_func_write(node, assignments, aliases)
        if func_write is not None:
            operation, resolved = func_write
            if resolved is not None and not _is_plausible_path(resolved):
                resolved = _UNKNOWN_TARGET
            target = resolved if resolved is not None else _UNKNOWN_TARGET
            provenance = _PROVENANCE_UNKNOWN
            for var_name, (path, prov_type) in assignments_typed.items():
                if path == target and target != _UNKNOWN_TARGET:
                    provenance = prov_type
                    break
            calls.append(WriteCall(target=target, operation=operation, line=line_no, provenance=provenance))
            continue

        if not isinstance(node.func, ast.Attribute):
            continue

        # Standard write methods: path.write_text(), path.save(), etc.
        if node.func.attr in _WRITE_METHOD_NAMES:
            operation = node.func.attr
            resolved = _resolve_call_target(node, assignments, aliases)
            if resolved is not None and not _is_plausible_path(resolved):
                resolved = _UNKNOWN_TARGET
            target = resolved if resolved is not None else _UNKNOWN_TARGET

            # Determine provenance from assignments_typed
            provenance = _PROVENANCE_UNKNOWN
            for var_name, (path, prov_type) in assignments_typed.items():
                if path == target and target != _UNKNOWN_TARGET:
                    provenance = prov_type
                    break

            calls.append(WriteCall(target=target, operation=operation, line=line_no, provenance=provenance))
            continue

        # os.replace(src, dst) — dst is second positional arg
        if (node.func.attr == "replace" and
            isinstance(node.func.value, ast.Name) and
            node.func.value.id == "os" and
            len(node.args) >= 2):
            operation = "os.replace"
            dst_node = node.args[1]
            if isinstance(dst_node, ast.Name):
                name = dst_node.id
                resolved = name
                visited: set[str] = {resolved}
                for _ in range(8):
                    nxt = aliases.get(resolved)
                    if nxt is None or nxt in visited:
                        break
                    visited.add(nxt)
                    resolved = nxt
                target = assignments.get(resolved, _UNKNOWN_TARGET)

                # Determine provenance
                provenance = _PROVENANCE_UNKNOWN
                for var_name, (path, prov_type) in assignments_typed.items():
                    if path == target and target != _UNKNOWN_TARGET:
                        provenance = prov_type
                        break

                calls.append(WriteCall(target=target, operation=operation, line=line_no, provenance=provenance))

    return calls
