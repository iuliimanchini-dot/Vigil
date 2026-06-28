"""AST visitor and utilities for runtime_builder.py (Map 2 static scanner).

Internal module -- not part of the public API.
Extracted from runtime_builder.py to keep each file under 400 lines.
"""
from __future__ import annotations

import ast
from typing import TYPE_CHECKING
import logging
_log = logging.getLogger(__name__)

__all__ = [
    "_RuntimeVisitor",
    "_call_name",
    "_decorator_registry_tag",
    "_background_task_tag",
    "_env_var_from_call",
    "_collect_env_vars_from_stmt",
    "_collect_env_vars_from_expr",
    "_ROUTE_DECORATOR_ATTRS",
    "_BACKGROUND_TASK_CALLS",
    "_SCANNED_FUNC_NAMES",
]

# ---------------------------------------------------------------------------
# Pattern constants
# ---------------------------------------------------------------------------

# Decorator attribute chains that signal route/dispatch registration.
_ROUTE_DECORATOR_ATTRS: frozenset[tuple[str, str]] = frozenset({
    ("app", "route"),
    ("bp", "route"),
    ("blueprint", "route"),
    ("router", "get"),
    ("router", "post"),
    ("router", "put"),
    ("router", "delete"),
    ("router", "patch"),
    ("router", "head"),
    ("router", "options"),
    ("router", "route"),
    ("api", "route"),
    ("dispatch", "register"),
})

# Background task call patterns: (module_attr, func_name)
_BACKGROUND_TASK_CALLS: frozenset[tuple[str, str]] = frozenset({
    ("threading", "Thread"),
    ("asyncio", "create_task"),
    ("subprocess", "Popen"),
    ("subprocess", "run"),
    ("subprocess", "call"),
})

# Functions whose bodies are scanned for background task spawns.
_SCANNED_FUNC_NAMES: frozenset[str] = frozenset({
    "__init__",
    "bootstrap",
    "setup",
    "startup",
    "start",
    "initialize",
    "init",
})


# ---------------------------------------------------------------------------
# AST utility functions
# ---------------------------------------------------------------------------

def _call_name(call: ast.Call) -> str:
    """Return a best-effort string representation of a call target."""
    func = call.func
    if isinstance(func, ast.Name):
        return func.id
    if isinstance(func, ast.Attribute):
        parts: list[str] = []
        node: ast.expr = func
        while isinstance(node, ast.Attribute):
            parts.append(node.attr)
            node = node.value
        if isinstance(node, ast.Name):
            parts.append(node.id)
        return ".".join(reversed(parts))
    return "<unknown>"


def _decorator_registry_tag(decorator: ast.expr) -> str | None:
    """Return 'decorator_registry' if the decorator matches a known route/dispatch pattern."""
    if isinstance(decorator, ast.Attribute):
        attr = decorator.attr
        value = decorator.value
        if isinstance(value, ast.Name):
            if (value.id, attr) in _ROUTE_DECORATOR_ATTRS:
                return "decorator_registry"
    elif isinstance(decorator, ast.Call):
        return _decorator_registry_tag(decorator.func)
    return None


def _is_main_guard(test: ast.expr) -> bool:
    """True iff *test* is the canonical ``__name__ == "__main__"`` comparison.

    Matches either operand order (``__name__ == "__main__"`` and
    ``"__main__" == __name__``). A bare ``def main(): ...`` without this guard
    is NOT an entrypoint -- this keeps the precision guard honest.
    """
    if not isinstance(test, ast.Compare):
        return False
    if len(test.ops) != 1 or not isinstance(test.ops[0], ast.Eq):
        return False
    operands = [test.left, *test.comparators]
    has_name = any(isinstance(o, ast.Name) and o.id == "__name__" for o in operands)
    has_main = any(
        isinstance(o, ast.Constant) and o.value == "__main__" for o in operands
    )
    return has_name and has_main


def _entry_calls_in_block(body: list[ast.stmt]) -> tuple[list[str], bool]:
    """Scan a ``__main__`` block body, returning (entry_call_names, is_async).

    entry_call_names: best-effort call targets invoked from the block (e.g.
        ``main``, ``app.run``, ``asyncio.run``), deduplicated, source order.
    is_async: True when an ``asyncio.run(...)`` call is present (async
        entrypoint signal).

    Only call expressions inside the block are inspected; a plain assignment or
    import in the guard does not by itself name an entry function.
    """
    names: list[str] = []
    is_async = False
    for stmt in body:
        for node in ast.walk(stmt):
            if not isinstance(node, ast.Call):
                continue
            cname = _call_name(node)
            if cname and cname not in ("<unknown>",) and cname not in names:
                names.append(cname)
            if cname in ("asyncio.run", "asyncio.get_event_loop"):
                is_async = True
    return names, is_async


def _background_task_tag(call: ast.Call) -> str | None:
    """Return kind string if call is a known background task spawn, else None."""
    func = call.func
    if isinstance(func, ast.Attribute):
        attr = func.attr
        value = func.value
        if isinstance(value, ast.Name):
            pair = (value.id, attr)
            if pair in _BACKGROUND_TASK_CALLS:
                if attr == "Thread":
                    return "threading_thread"
                if attr == "create_task":
                    return "asyncio_create_task"
                if attr in ("Popen", "run", "call"):
                    return "subprocess_spawn"
    return None


def _env_var_from_call(call: ast.Call) -> list[str]:
    """Extract env var name from os.environ.get(X), os.getenv(X)."""
    results: list[str] = []
    func = call.func
    if isinstance(func, ast.Attribute):
        attr = func.attr
        if attr in ("get", "getenv"):
            if call.args and isinstance(call.args[0], ast.Constant):
                var = call.args[0].value
                if isinstance(var, str):
                    results.append(var)
    return results


def _subscript_env_var(node: ast.Subscript) -> str | None:
    """Extract env var from os.environ['VAR'] subscript."""
    if not isinstance(node.value, ast.Attribute):
        return None
    attr = node.value
    if not (attr.attr == "environ" and isinstance(attr.value, ast.Name) and attr.value.id == "os"):
        return None
    slice_node = node.slice
    if isinstance(slice_node, ast.Constant) and isinstance(slice_node.value, str):
        return slice_node.value
    # Python 3.8 ast.Index wrapper
    if hasattr(slice_node, "value"):  # ast.Index
        inner = slice_node.value  # type: ignore[attr-defined]
        if isinstance(inner, ast.Constant) and isinstance(inner.value, str):
            return inner.value
    return None


def _collect_env_vars_from_stmt(stmt: ast.stmt) -> list[str]:
    """Walk an assignment statement collecting os.environ reads."""
    results: list[str] = []
    for node in ast.walk(stmt):
        if isinstance(node, ast.Call):
            results.extend(_env_var_from_call(node))
        elif isinstance(node, ast.Subscript):
            var = _subscript_env_var(node)
            if var:
                results.append(var)
    return results


def _collect_env_vars_from_expr(expr) -> list[str]:
    """Walk any expression collecting os.environ reads."""
    if expr is None:
        return []
    results: list[str] = []
    for node in ast.walk(expr):
        if isinstance(node, ast.Call):
            results.extend(_env_var_from_call(node))
        elif isinstance(node, ast.Subscript):
            var = _subscript_env_var(node)
            if var:
                results.append(var)
    return results


# ---------------------------------------------------------------------------
# AST Visitor
# ---------------------------------------------------------------------------

class _RuntimeVisitor(ast.NodeVisitor):
    """Walk an AST and collect runtime-relevant patterns.

    Collects:
      - Module-level Call statements       -> import_time_side_effects
      - Route/dispatch decorators          -> decorator_registry
      - Background task spawns in scanned
        function bodies                    -> background_task
      - os.environ reads                   -> depends_on_env
    """

    def __init__(self, rel: str) -> None:
        self._rel = rel
        self.results: list[dict] = []
        self._module_env_vars: list[str] = []
        # Names of functions invoked from a `__main__` block (entry functions).
        self._entry_func_names: set[str] = set()

    def visit_Module(self, node: ast.Module) -> None:
        """Visit top-level statements only (module-scope detection)."""
        # First pass: detect `if __name__ == "__main__":` entrypoint block(s).
        # Collect the invoked entry-function names so the corresponding
        # module-level def can also be surfaced as an entry function.
        for stmt in node.body:
            if isinstance(stmt, ast.If) and _is_main_guard(stmt.test):
                self._handle_main_block(stmt)

        for stmt in node.body:
            if isinstance(stmt, ast.Expr) and isinstance(stmt.value, ast.Call):
                call = stmt.value
                call_name_str = _call_name(call)
                node_name = "%s:module" % self._rel
                self.results.append({
                    "node": node_name,
                    "kind": "import_time_side_effect",
                    "tags": ["import_time_side_effects"],
                    "env_vars": [],
                    "side_effects": [call_name_str] if call_name_str else [],
                    "evidence": ("%s:module-level-call" % self._rel,),
                })
                # Also check if it's a bg task
                bg_tag = _background_task_tag(call)
                if bg_tag:
                    self.results.append({
                        "node": node_name,
                        "kind": bg_tag,
                        "tags": ["background_task"],
                        "env_vars": [],
                        "side_effects": [],
                        "evidence": ("%s:module-level-bg" % self._rel,),
                    })
            elif isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef)):
                self._check_function(stmt)
            elif isinstance(stmt, ast.ClassDef):
                self._check_class(stmt)

            # Collect module-level env vars from assignments
            if isinstance(stmt, ast.Assign):
                self._module_env_vars.extend(_collect_env_vars_from_stmt(stmt))
            elif isinstance(stmt, ast.Expr):
                self._module_env_vars.extend(
                    _collect_env_vars_from_expr(getattr(stmt, "value", None))
                )

        self._flush_module_env_vars()
        # Do NOT call generic_visit — class/function bodies handled explicitly

    def _flush_module_env_vars(self) -> None:
        if not self._module_env_vars:
            return
        node_name = "%s:module" % self._rel
        existing = [r for r in self.results if r["node"] == node_name]
        if existing:
            for r in existing:
                r["env_vars"].extend(self._module_env_vars)
        else:
            self.results.append({
                "node": node_name,
                "kind": "module_env_read",
                "tags": [],
                "env_vars": self._module_env_vars[:],
                "side_effects": [],
                "evidence": ("%s:module-env" % self._rel,),
            })

    def _handle_main_block(self, if_node: ast.If) -> None:
        """Emit a main_entrypoint node for a `__main__` guard block.

        Records the invoked entry-function names (for cross-referencing with
        module-level defs) and flags async entrypoints (asyncio.run).
        """
        entry_calls, is_async = _entry_calls_in_block(if_node.body)
        # Remember bare-name calls (e.g. `main()`) so the module-level def of
        # that function can be surfaced as an entry function too.
        for cname in entry_calls:
            if "." not in cname:
                self._entry_func_names.add(cname)
        line = getattr(if_node, "lineno", 0)
        node_name = "%s:__main__" % self._rel
        tags = ["entrypoint"]
        if is_async:
            tags.append("async_entrypoint")
        self.results.append({
            "node": node_name,
            "kind": "main_entrypoint",
            "tags": tags,
            "env_vars": [],
            "side_effects": list(entry_calls),
            "calls": list(entry_calls),
            "evidence": ("%s:%d" % (self._rel, line),),
        })

    def _check_class(self, class_node: ast.ClassDef) -> None:
        for item in ast.walk(class_node):
            if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)):
                self._check_function(item, class_name=class_node.name)

    def _check_function(
        self,
        func_node: ast.FunctionDef | ast.AsyncFunctionDef,
        class_name: str | None = None,
    ) -> None:
        func_name = func_node.name
        qualified = "%s.%s" % (class_name, func_name) if class_name else func_name

        # Entry-function: a module-level def invoked from a `__main__` block.
        # Only top-level functions qualify (class_name is None); a method named
        # `main` on some class is not the script entrypoint.
        if class_name is None and func_name in self._entry_func_names:
            node_name = "%s:%s" % (self._rel, qualified)
            is_async = isinstance(func_node, ast.AsyncFunctionDef)
            tags = ["entrypoint", "entry_function"]
            if is_async:
                tags.append("async_entrypoint")
            self.results.append({
                "node": node_name,
                "kind": "entry_function",
                "tags": tags,
                "env_vars": [],
                "side_effects": [],
                "calls": [],
                "evidence": ("%s:%d" % (self._rel, getattr(func_node, "lineno", 0)),),
            })

        # Decorators check
        for decorator in func_node.decorator_list:
            if _decorator_registry_tag(decorator):
                node_name = "%s:%s" % (self._rel, qualified)
                self.results.append({
                    "node": node_name,
                    "kind": "decorator_registry",
                    "tags": ["decorator_registry"],
                    "env_vars": [],
                    "side_effects": [],
                    "evidence": ("%s:decorator" % node_name,),
                })
                break

        # Body scan for scanned functions
        if func_name not in _SCANNED_FUNC_NAMES:
            return

        env_vars: list[str] = []
        for stmt in ast.walk(func_node):
            # Collect Call nodes for bg-task detection (both Expr and Assign rhs)
            calls_in_stmt: list[ast.Call] = []
            if isinstance(stmt, ast.Expr) and isinstance(
                getattr(stmt, "value", None), ast.Call
            ):
                calls_in_stmt.append(stmt.value)  # type: ignore[arg-type]
            elif isinstance(stmt, ast.Assign) and isinstance(stmt.value, ast.Call):
                calls_in_stmt.append(stmt.value)
                for inner in ast.walk(stmt.value):
                    if inner is not stmt.value and isinstance(inner, ast.Call):
                        calls_in_stmt.append(inner)

            for call in calls_in_stmt:
                bg_tag = _background_task_tag(call)
                if bg_tag:
                    node_name = "%s:%s" % (self._rel, qualified)
                    self.results.append({
                        "node": node_name,
                        "kind": bg_tag,
                        "tags": ["background_task"],
                        "env_vars": [],
                        "side_effects": [],
                        "evidence": ("%s:bg-task" % node_name,),
                    })

            # Env vars
            if isinstance(stmt, ast.Assign):
                env_vars.extend(_collect_env_vars_from_stmt(stmt))
            elif isinstance(stmt, ast.Expr):
                env_vars.extend(_collect_env_vars_from_expr(getattr(stmt, "value", None)))
            if isinstance(stmt, ast.Call):
                env_vars.extend(_env_var_from_call(stmt))

        if env_vars:
            node_name = "%s:%s" % (self._rel, qualified)
            existing = [r for r in self.results if r["node"] == node_name]
            if existing:
                for r in existing:
                    r["env_vars"].extend(env_vars)
            else:
                self.results.append({
                    "node": node_name,
                    "kind": "env_read",
                    "tags": [],
                    "env_vars": env_vars,
                    "side_effects": [],
                    "evidence": ("%s:env" % node_name,),
                })
