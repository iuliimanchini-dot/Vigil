"""Inlined import extractor — pure stdlib, no cross-cluster imports.

Extracted from the prompt_engineer_graph module of the parent app.
Provides: _extract_imports, ModuleNode, STANDARD_SKIP_DIRS.
"""
from __future__ import annotations

import ast
from dataclasses import dataclass, field
from pathlib import Path

# Standard skip dirs (from project_exclusions — inlined, pure stdlib)
STANDARD_SKIP_DIRS: frozenset[str] = frozenset({
    "__pycache__", ".git", ".hg", ".svn",
    "node_modules", ".tox", ".mypy_cache", ".pytest_cache", ".ruff_cache",
    ".venv", "venv", "env", ".env", ".eggs",
    "dist", "build",
    ".cortex", ".a1", ".prompt-engineer", ".claude", ".vendor",
})


@dataclass
class ModuleNode:
    """A Python module in the project."""
    path: str  # relative to project root
    package: str  # dotted module name
    imports: list[str] = field(default_factory=list)
    lazy_imports: list[str] = field(default_factory=list)
    dynamic_imports: list[str] = field(default_factory=list)
    re_exports: list[str] = field(default_factory=list)
    all_names: list[str] = field(default_factory=list)
    is_init: bool = False
    is_entry_point: bool = False
    is_test: bool = False
    line_count: int = 0
    mtime: float = 0.0


def _build_parent_map(tree: ast.Module) -> dict[int, ast.AST]:
    parent_map: dict[int, ast.AST] = {}
    for parent in ast.walk(tree):
        for child in ast.iter_child_nodes(parent):
            parent_map[id(child)] = parent
    return parent_map


def _is_in_function(node: ast.AST, parent_map: dict[int, ast.AST]) -> bool:
    current = parent_map.get(id(node))
    while current is not None:
        if isinstance(current, (ast.FunctionDef, ast.AsyncFunctionDef)):
            return True
        current = parent_map.get(id(current))
    return False


def _extract_imports(source: str, file_path: str) -> ModuleNode:
    """Parse a Python file and extract all import information."""
    node = ModuleNode(path=file_path, package="")
    lines = source.splitlines()
    node.line_count = len(lines)

    basename = Path(file_path).name
    node.is_init = basename == "__init__.py"
    node.is_test = basename.startswith("test_") or basename == "conftest.py"
    node.is_entry_point = False

    try:
        tree = ast.parse(source, filename=file_path)
    except SyntaxError:
        return node

    parent_map = _build_parent_map(tree)
    re_exports_seen: set[str] = set()

    for ast_node in ast.walk(tree):
        if isinstance(ast_node, ast.Import):
            for alias in ast_node.names:
                target = node.lazy_imports if _is_in_function(ast_node, parent_map) else node.imports
                target.append(alias.name)

        elif isinstance(ast_node, ast.ImportFrom):
            module = ast_node.module or ""
            if ast_node.level > 0:
                prefix = "." * ast_node.level
                full = f"{prefix}{module}" if module else prefix
            else:
                full = module
            target = node.lazy_imports if _is_in_function(ast_node, parent_map) else node.imports
            target.append(full)

            if node.is_init and not _is_in_function(ast_node, parent_map):
                for alias in ast_node.names:
                    key = f"{full}.{alias.name}"
                    if key not in re_exports_seen:
                        re_exports_seen.add(key)
                        node.re_exports.append(key)

        elif isinstance(ast_node, ast.Call):
            func = ast_node.func
            if isinstance(func, ast.Attribute) and func.attr == "import_module":
                if ast_node.args and isinstance(ast_node.args[0], ast.Constant):
                    node.dynamic_imports.append(str(ast_node.args[0].value))
            elif isinstance(func, ast.Name) and func.id == "__import__":
                if ast_node.args and isinstance(ast_node.args[0], ast.Constant):
                    node.dynamic_imports.append(str(ast_node.args[0].value))

        elif isinstance(ast_node, ast.Assign):
            for target in ast_node.targets:
                if isinstance(target, ast.Name) and target.id == "__all__":
                    if isinstance(ast_node.value, (ast.List, ast.Tuple)):
                        for elt in ast_node.value.elts:
                            if isinstance(elt, ast.Constant) and isinstance(elt.value, str):
                                node.all_names.append(elt.value)

        elif isinstance(ast_node, ast.If):
            test = ast_node.test
            if (isinstance(test, ast.Compare)
                    and isinstance(test.left, ast.Name) and test.left.id == "__name__"
                    and any(isinstance(c, ast.Constant) and c.value == "__main__"
                            for c in test.comparators)):
                node.is_entry_point = True

    return node
