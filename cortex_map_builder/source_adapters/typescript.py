"""TypeScript source adapter -- tree-sitter structural extractor.

``extract_imports`` and ``extract_symbols`` are backed by tree-sitter for
true AST accuracy; all emitted IR items carry ``confidence=1.0``.

``extract_contracts``, ``extract_runtime``, and ``extract_writer_calls``
remain on the original regex+lexer approach (separate sub-phase migration).

Capabilities (L7a scope):
    - supports_structural      = True  (extract_imports + extract_symbols)
    - supports_contracts       = True  (L6b -- extract_contracts)
    - supports_runtime_signals = True  (L6a -- extract_runtime)
    - supports_authority_writes = True  (L7a -- extract_writer_calls)

tree-sitter confidence:
    - 1.0 for all items from extract_imports / extract_symbols.

Regex confidence scale (contracts / runtime / writer_calls unchanged):
    - 0.9 -- clean absolute ES-module forms, exported symbols, etc.
    - 0.8 -- relative ES-module imports, non-exported symbols.
    - 0.7 -- dynamic ``import('...')`` and zod schemas.

Known limitations (explicit L2 tech-debt, do NOT fix here):
    - Template-literal module specifiers (``import(`${base}/mod`)``) are
      skipped -- tree-sitter argument is not a plain string literal.
    - Decorators are not emitted as symbols.
    - JSX inside a .tsx file is not inspected beyond its enclosing
      ``export const Foo = ...`` or ``export function Foo(...)``.
    - ``declare module '...'`` and ambient declarations are ignored.
"""
from __future__ import annotations

import logging
from pathlib import Path

import re

from ._base import RegexAdapterBase
from ._ir import AuthorityWriteCandidate, ContractCandidate, ImportEdge, SymbolDef, TSRuntimeSignal
from ._lexer import (
    join_multiline_imports,
    strip_comments_and_strings,
    strip_comments_only,
)
from ._patterns import (
    RE_DYNAMIC_IMPORT,
    RE_EXPORT_FROM_NAMED,
    RE_EXPORT_FROM_STAR,
    RE_IMPORT_DEFAULT,
    RE_IMPORT_NAMED,
    RE_IMPORT_NAMESPACE,
    RE_IMPORT_SIDE_EFFECT,
    RE_IMPORT_TYPE_DEFAULT,
    RE_IMPORT_TYPE_NAMED,
    RE_SYMBOL_CLASS,
    RE_SYMBOL_CONST,
    RE_SYMBOL_ENUM,
    RE_SYMBOL_FUNCTION,
    RE_SYMBOL_INTERFACE,
    RE_SYMBOL_TYPE,
    classify_import,
)
from ._treesitter import (
    iter_named_children,
    node_line,
    node_text,
    parse_bytes,
    walk_named,
)

_TS_LANGUAGE = "typescript"

__all__ = ["TypescriptAdapter"]

_log = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Internal tree-sitter helpers (used only by extract_imports / extract_symbols)
# ---------------------------------------------------------------------------

def _string_module(string_node, src: bytes) -> str:
    """Extract the bare module specifier from a tree-sitter ``string`` node.

    Looks for a ``string_fragment`` child first; falls back to stripping quote
    characters from the full node text (handles both single and double quotes).
    """
    for child in string_node.children:
        if child.type == "string_fragment":
            return node_text(child, src)
    raw = node_text(string_node, src)
    return raw.strip("'\"")


def _find_dynamic_import_module(node, src: bytes) -> str | None:
    """Recursively search *node* for a dynamic ``import('literal')`` call.

    Returns the module specifier if the argument is a string literal, else None.
    Dynamic imports with non-literal arguments are intentionally skipped.
    """
    if node.type == "call_expression":
        for child in node.children:
            if child.type == "import":
                # dynamic import — extract first string argument
                for sibling in node.children:
                    if sibling.is_named and sibling.type == "arguments":
                        for arg in sibling.children:
                            if arg.is_named and arg.type == "string":
                                return _string_module(arg, src)
                return None  # non-literal argument — skip
    for child in node.children:
        result = _find_dynamic_import_module(child, src)
        if result is not None:
            return result
    return None


class TypescriptAdapter(RegexAdapterBase):
    """TypeScript adapter -- ES-module imports + TS declarations via regex.

    Operates on both ``.ts`` and ``.tsx``. Structural capability only for
    L2; all other supports_* flags are False until later phases wire the
    corresponding builders to IR dispatch.
    """

    language = "typescript"
    file_extensions = (".ts", ".tsx")
    supports_structural = True
    supports_contracts = True
    supports_runtime_signals = True
    supports_authority_writes = True

    # ------------------------------------------------------------------
    # Authority write patterns (L7a)
    # ------------------------------------------------------------------

    # fs.writeFile / fs.writeFileSync
    _RE_FS_WRITE = re.compile(
        r"\bfs\.writeFile(?:Sync)?\s*\(([^,)]{0,60})",
    )
    # standalone writeFile / writeFileSync (no fs. prefix)
    _RE_STANDALONE_WRITE = re.compile(
        r"(?<![.\w])writeFile(?:Sync)?\s*\(([^,)]{0,60})",
    )
    # fs.appendFile / fs.appendFileSync
    _RE_FS_APPEND = re.compile(
        r"\bfs\.appendFile(?:Sync)?\s*\(([^,)]{0,60})",
    )
    # .save( / .save() — on any receiver
    _RE_ORM_SAVE = re.compile(
        r"\.\s*save\s*\(\s*",
    )
    # ORM-looking .create( / .update( / .upsert( — only on repo./db./repository./model. receivers
    _RE_ORM_WRITE = re.compile(
        r"\b(?:repo|db|repository|model)\s*\.\s*(?:create|update|upsert)\s*\(",
    )
    # prisma.X.create/update/upsert/delete
    _RE_PRISMA = re.compile(
        r"\bprisma\s*\.\s*([A-Za-z_$][A-Za-z0-9_$]*)\s*\.\s*(create|update|upsert|delete)\s*\(",
    )
    # supabase.from(...).insert/update/upsert/delete
    _RE_SUPABASE = re.compile(
        r"\bsupabase\s*\.\s*from\s*\([^)]{0,60}\)\s*\.\s*(insert|update|upsert|delete)\s*\(",
    )
    # localStorage.setItem / sessionStorage.setItem
    _RE_STORAGE_SET = re.compile(
        r"\b(?:localStorage|sessionStorage)\s*\.\s*setItem\s*\(",
    )

    # ------------------------------------------------------------------
    # Runtime signal patterns (L6a)
    # ------------------------------------------------------------------

    # A. Next.js App Router: named export of HTTP method (function form)
    _RE_APP_ROUTER_FN = re.compile(
        r"^export\s+(async\s+)?function\s+(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\b",
        re.MULTILINE,
    )
    # A2. Next.js App Router: const export of HTTP method
    _RE_APP_ROUTER_CONST = re.compile(
        r"^export\s+const\s+(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\s*=",
        re.MULTILINE,
    )
    # B. Next.js Pages Router API: export default function/arrow
    _RE_PAGES_API_DEFAULT = re.compile(
        r"^export\s+default\s+(async\s+)?(?:function\b|\()",
        re.MULTILINE,
    )
    # C. Next.js middleware: named middleware function/const/default
    _RE_MIDDLEWARE = re.compile(
        r"^export\s+(?:(?:async\s+)?function\s+middleware\b|(?:const|default)\s+middleware\b)",
        re.MULTILINE,
    )
    # D. Server bootstrap / module_init
    _RE_BOOTSTRAP = re.compile(
        r"^(?:(?:app|server)\.(?:listen|start)\s*\(|createServer\s*\(|new\s+(?:http\.Server|https\.Server)\s*\()",
        re.MULTILINE,
    )
    # E. Background job / cron (top-level lines starting with identifier or export)
    _RE_BACKGROUND = re.compile(
        r"^(?:export\s+)?(?:cron|schedule|setInterval|setTimeout)\s*\(",
        re.MULTILINE,
    )
    # F. Environment variable access
    _RE_ENV_ACCESS = re.compile(
        r"process\.env\.([A-Z_][A-Z0-9_]*)",
    )

    # ------------------------------------------------------------------
    # Contract patterns (L6b)
    # ------------------------------------------------------------------

    # A. interface X { ... } — any combo of export / declare modifiers
    _RE_CONTRACT_INTERFACE = re.compile(
        r"^(?:export\s+)?(?:declare\s+)?interface\s+"
        r"([A-Za-z_$][A-Za-z0-9_$]*)(?:\s*<[^{]*>)?\s*\{",
        re.MULTILINE,
    )
    # B. type X = { ... } — object-literal shape only (must end with `= {`)
    _RE_CONTRACT_TYPE_OBJECT = re.compile(
        r"^(?:export\s+)?(?:declare\s+)?type\s+"
        r"([A-Za-z_$][A-Za-z0-9_$]*)(?:\s*<[^=]*>)?\s*=\s*\{",
        re.MULTILINE,
    )
    # C. const/let/var X = z.object(...)
    _RE_CONTRACT_ZOD = re.compile(
        r"(?:export\s+)?(?:const|let|var)\s+"
        r"([A-Za-z_$][A-Za-z0-9_$]*)\s*=\s*z\.object\s*\(",
        re.MULTILINE,
    )

    # ------------------------------------------------------------------
    # Contracts (L6b)
    # ------------------------------------------------------------------

    def extract_contracts(
        self, content: str, path: Path
    ) -> list[ContractCandidate]:
        """Return ContractCandidate objects for TS type contracts.

        Detected:
            - ``interface X { }``                     -> kind="interface",    confidence=0.9
            - ``type X = { }``  (object literal only) -> kind="type_object",  confidence=0.8
            - ``const X = z.object(...)``              -> kind="zod_schema",   confidence=0.7

        Exclusions:
            - Test files (``*.test.ts``, ``*.spec.ts``, paths with ``__tests__/``).
            - Scalar aliases (``type X = string`` etc.) -- naturally excluded because
              the type_object pattern requires ``= {``.
            - Union / intersection types without ``{`` -- same reason.

        Uses ``strip_comments_and_strings`` so patterns inside comments or string
        literals do not produce false positives.

        Sorted by ``(line, name)``.
        """
        _log.debug("extract_contracts: %s (%d chars)", path, len(content))

        # Test-file exclusion
        path_posix = Path(path).as_posix()
        name = Path(path).name
        if name.endswith(".test.ts") or name.endswith(".spec.ts"):
            return []
        if name.endswith(".test.tsx") or name.endswith(".spec.tsx"):
            return []
        if "__tests__/" in path_posix:
            return []

        cleaned = strip_comments_and_strings(content, self.language)
        candidates: list[ContractCandidate] = []

        for m in self._RE_CONTRACT_INTERFACE.finditer(cleaned):
            candidates.append(ContractCandidate(
                name=m.group(1),
                contract_kind="interface",
                line=self._line_of(m.start(), cleaned),
                confidence=0.9,
            ))

        for m in self._RE_CONTRACT_TYPE_OBJECT.finditer(cleaned):
            candidates.append(ContractCandidate(
                name=m.group(1),
                contract_kind="type_object",
                line=self._line_of(m.start(), cleaned),
                confidence=0.8,
            ))

        for m in self._RE_CONTRACT_ZOD.finditer(cleaned):
            candidates.append(ContractCandidate(
                name=m.group(1),
                contract_kind="zod_schema",
                line=self._line_of(m.start(), cleaned),
                confidence=0.7,
            ))

        candidates.sort(key=lambda c: (c.line, c.name))
        _log.debug("extract_contracts: %s -> %d candidates", path, len(candidates))
        return candidates

    # ------------------------------------------------------------------
    # Authority writes (L7a)
    # ------------------------------------------------------------------

    def extract_writer_calls(
        self, content: str, path: Path
    ) -> list[AuthorityWriteCandidate]:
        """Detect write/save operations in TS/JS source.

        Detected patterns and confidence:
            - ``fs.writeFile(``, ``fs.writeFileSync(``       -> fs_write,   0.9
            - ``fs.appendFile(``, ``fs.appendFileSync(``     -> fs_append,  0.9
            - standalone ``writeFile(``, ``writeFileSync(``  -> fs_write,   0.85
            - ``.save(``                                     -> orm_save,   0.75
            - ``repo.create(``, ``db.update(`` etc.          -> orm_write,  0.7
            - ``prisma.X.create/update/upsert/delete(``      -> prisma_write, 0.85
            - ``supabase.from(...).insert/update/...``        -> supabase_write, 0.85
            - ``localStorage.setItem(``, ``sessionStorage.setItem(`` -> storage_write, 0.7

        HTTP .put() / .post() on fetch/axios are intentionally excluded (too noisy).
        Uses ``_preprocess`` before matching.
        Sorted by ``(line, write_kind)``.
        """
        _log.debug("extract_writer_calls: %s (%d chars)", path, len(content))
        path_posix = path.as_posix()
        cleaned = self._preprocess(content)
        candidates: list[AuthorityWriteCandidate] = []

        def _hint(group_text: str) -> str:
            """Trim first argument fragment to 30 chars as target hint."""
            h = group_text.strip().strip("\"'`").strip()
            return h[:30]

        # fs.writeFile / fs.writeFileSync
        for m in self._RE_FS_WRITE.finditer(cleaned):
            candidates.append(AuthorityWriteCandidate(
                write_kind="fs_write",
                target_hint=_hint(m.group(1)),
                line=self._line_of(m.start(), cleaned),
                confidence=0.9,
            ))

        # fs.appendFile / fs.appendFileSync
        for m in self._RE_FS_APPEND.finditer(cleaned):
            candidates.append(AuthorityWriteCandidate(
                write_kind="fs_append",
                target_hint=_hint(m.group(1)),
                line=self._line_of(m.start(), cleaned),
                confidence=0.9,
            ))

        # standalone writeFile / writeFileSync (no fs. prefix — already caught above via fs.*)
        # Use negative lookbehind in pattern so fs.writeFile is not double-counted.
        for m in self._RE_STANDALONE_WRITE.finditer(cleaned):
            candidates.append(AuthorityWriteCandidate(
                write_kind="fs_write",
                target_hint=_hint(m.group(1)),
                line=self._line_of(m.start(), cleaned),
                confidence=0.85,
            ))

        # prisma.X.create/update/upsert/delete
        for m in self._RE_PRISMA.finditer(cleaned):
            candidates.append(AuthorityWriteCandidate(
                write_kind="prisma_write",
                target_hint=m.group(1)[:30],
                line=self._line_of(m.start(), cleaned),
                confidence=0.85,
            ))

        # supabase.from(...).insert/update/upsert/delete
        for m in self._RE_SUPABASE.finditer(cleaned):
            candidates.append(AuthorityWriteCandidate(
                write_kind="supabase_write",
                target_hint=m.group(1)[:30],
                line=self._line_of(m.start(), cleaned),
                confidence=0.85,
            ))

        # ORM .save()
        for m in self._RE_ORM_SAVE.finditer(cleaned):
            candidates.append(AuthorityWriteCandidate(
                write_kind="orm_save",
                target_hint="",
                line=self._line_of(m.start(), cleaned),
                confidence=0.75,
            ))

        # ORM .create / .update / .upsert on repo/db/repository/model
        for m in self._RE_ORM_WRITE.finditer(cleaned):
            candidates.append(AuthorityWriteCandidate(
                write_kind="orm_write",
                target_hint="",
                line=self._line_of(m.start(), cleaned),
                confidence=0.7,
            ))

        # localStorage / sessionStorage .setItem
        for m in self._RE_STORAGE_SET.finditer(cleaned):
            candidates.append(AuthorityWriteCandidate(
                write_kind="storage_write",
                target_hint="",
                line=self._line_of(m.start(), cleaned),
                confidence=0.7,
            ))

        candidates.sort(key=lambda c: (c.line, c.write_kind))
        _log.debug("extract_writer_calls: %s -> %d candidates", path_posix, len(candidates))
        return candidates

    # ------------------------------------------------------------------
    # Preprocess hook — strip comments/strings, then collapse multiline imports
    # ------------------------------------------------------------------

    def _preprocess(self, content: str) -> str:
        """Apply the shared C-family lexer in the canonical order."""
        stripped = strip_comments_and_strings(content, self.language)
        return join_multiline_imports(stripped, self.language)

    # ------------------------------------------------------------------
    # Runtime signals (L6a)
    # ------------------------------------------------------------------

    def extract_runtime(self, content: str, path: Path) -> list[TSRuntimeSignal]:  # type: ignore[override]
        """Detect Next.js routes, middleware, server bootstrap, background jobs,
        and env-var accesses in TS/TSX files.

        Uses ``strip_comments_only`` so string bodies remain visible (needed for
        path-based guards) while comment false-positives are suppressed.

        Strict exclusions (path-based, no JSX parsing):
            - Test files: ``*.test.ts``, ``*.spec.ts``, paths containing ``__tests__/``.
            - UI component directories: paths containing ``components/`` or
              paths under ``app/`` / ``pages/`` that are NOT ``app/api/`` or
              ``pages/api/``.

        Sorted output by ``(line, kind)``.
        """
        _log.debug("extract_runtime: %s (%d chars)", path, len(content))

        path_posix = Path(path).as_posix()

        # ------ Exclusion guards ------
        # Test files
        name = Path(path).name
        if name.endswith(".test.ts") or name.endswith(".spec.ts"):
            return []
        if "__tests__/" in path_posix:
            return []

        # UI component directories (not api paths)
        if "components/" in path_posix:
            return []
        # pages/ but NOT pages/api/
        if "pages/" in path_posix and "pages/api/" not in path_posix:
            return []
        # app/ but NOT app/api/
        if "app/" in path_posix and "app/api/" not in path_posix:
            return []

        # ------ Preprocessing ------
        # strip_comments_only: comments removed, strings kept (needed for path checks)
        cleaned = strip_comments_only(content, self.language)

        signals: list[TSRuntimeSignal] = []

        # ------ A. App Router / Pages API routes ------
        is_app_api = "app/api/" in path_posix
        is_pages_api = "pages/api/" in path_posix

        if is_app_api:
            # Function-form HTTP method exports
            for m in self._RE_APP_ROUTER_FN.finditer(cleaned):
                method = m.group(2)
                line = self._line_of(m.start(), cleaned)
                signals.append(TSRuntimeSignal(
                    kind="framework_route",
                    file=path_posix,
                    line=line,
                    confidence=0.9,
                    payload={
                        "route_path": path_posix,
                        "http_methods": [method],
                        "framework": "nextjs",
                    },
                ))
            # Const-form HTTP method exports
            for m in self._RE_APP_ROUTER_CONST.finditer(cleaned):
                method = m.group(1)
                line = self._line_of(m.start(), cleaned)
                signals.append(TSRuntimeSignal(
                    kind="framework_route",
                    file=path_posix,
                    line=line,
                    confidence=0.9,
                    payload={
                        "route_path": path_posix,
                        "http_methods": [method],
                        "framework": "nextjs",
                    },
                ))

        elif is_pages_api:
            # B. Pages Router: export default
            for m in self._RE_PAGES_API_DEFAULT.finditer(cleaned):
                line = self._line_of(m.start(), cleaned)
                signals.append(TSRuntimeSignal(
                    kind="framework_route",
                    file=path_posix,
                    line=line,
                    confidence=0.9,
                    payload={
                        "route_path": path_posix,
                        "http_methods": ["*"],
                        "framework": "nextjs",
                    },
                ))

        # ------ C. Middleware ------
        # File must be named middleware.ts or middleware.tsx at project root or src/
        fname_no_ext = Path(path).stem
        if fname_no_ext == "middleware":
            for m in self._RE_MIDDLEWARE.finditer(cleaned):
                line = self._line_of(m.start(), cleaned)
                signals.append(TSRuntimeSignal(
                    kind="middleware",
                    file=path_posix,
                    line=line,
                    confidence=0.9,
                    payload={"framework": "nextjs"},
                ))

        # ------ D. Server bootstrap ------
        for m in self._RE_BOOTSTRAP.finditer(cleaned):
            matched_call = cleaned[m.start():m.end()].strip()
            line = self._line_of(m.start(), cleaned)
            signals.append(TSRuntimeSignal(
                kind="module_init",
                file=path_posix,
                line=line,
                confidence=0.7,
                payload={"call": matched_call},
            ))

        # ------ E. Background job / cron ------
        for m in self._RE_BACKGROUND.finditer(cleaned):
            matched_call = cleaned[m.start():m.end()].strip()
            line = self._line_of(m.start(), cleaned)
            signals.append(TSRuntimeSignal(
                kind="background_job",
                file=path_posix,
                line=line,
                confidence=0.7,
                payload={"call": matched_call},
            ))

        # ------ F. Env access (deduplicate per var name, keep first occurrence) ------
        seen_env: dict[str, int] = {}
        for m in self._RE_ENV_ACCESS.finditer(cleaned):
            var_name = m.group(1)
            line = self._line_of(m.start(), cleaned)
            if var_name not in seen_env:
                seen_env[var_name] = line

        for var_name, line in sorted(seen_env.items(), key=lambda kv: kv[1]):
            signals.append(TSRuntimeSignal(
                kind="env_access",
                file=path_posix,
                line=line,
                confidence=0.9,
                payload={"env_var": var_name},
            ))

        signals.sort(key=lambda s: (s.line, s.kind))
        _log.debug("extract_runtime: %s -> %d signals", path, len(signals))
        return signals

    # ------------------------------------------------------------------
    # Structural: imports (tree-sitter, confidence=1.0)
    # ------------------------------------------------------------------

    def extract_imports(self, content: str, path: Path) -> list[ImportEdge]:
        """Return one ImportEdge per ES-module / dynamic import statement.

        Backed by tree-sitter for true AST accuracy.  All items carry
        ``confidence=1.0``.

        Handled forms:
            ``import X from 'Y'``               -- default import
            ``import { A, B } from 'Y'``        -- named imports
            ``import * as X from 'Y'``          -- namespace import
            ``import 'Y'``                      -- side-effect import
            ``import type X from 'Y'``          -- type-only default import
            ``import type { X } from 'Y'``      -- type-only named imports
            ``export { A, B } from 'Y'``        -- re-export named
            ``export * from 'Y'``               -- re-export star
            ``export * as NS from 'Y'``         -- re-export namespace
            Dynamic ``import('Y')`` (literal)   -- dynamic import

        Dynamic imports with non-literal arguments are silently skipped
        (consistent with prior adapter behaviour and JS adapter).
        """
        _log.debug("extract_imports (tree-sitter): %s (%d chars)", path, len(content))
        src: bytes = content.encode("utf-8", errors="replace")
        root = parse_bytes(_TS_LANGUAGE, src)
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

        # -----------------------------------------------------------
        # Pass 1: static import/export statements (always top-level)
        # -----------------------------------------------------------
        for node in root.children:
            if not node.is_named:
                continue

            if node.type == "import_statement":
                # Covers: default, named, namespace, side-effect, type-only.
                # The module specifier is the last ``string`` child.
                for child in node.children:
                    if child.is_named and child.type == "string":
                        _emit(_string_module(child, src), node_line(node))
                        break

            elif node.type == "export_statement":
                # Re-exports: ``export { X } from '...'``, ``export * from '...'``.
                # A re-export has a ``string`` child at the top level.
                # Exported declarations are handled in extract_symbols, not here.
                for child in node.children:
                    if child.is_named and child.type == "string":
                        _emit(_string_module(child, src), node_line(node))
                        break

        # -----------------------------------------------------------
        # Pass 2: dynamic ``import('literal')`` calls anywhere in the tree.
        # Dynamic imports can appear inside function bodies, class methods,
        # conditionals, etc. — regex adapter found them everywhere, so we
        # walk the full tree here to preserve parity.
        # -----------------------------------------------------------
        for call_node in walk_named(root, "call_expression"):
            # _find_dynamic_import_module checks whether this call_expression
            # is actually a dynamic import (callee is the ``import`` keyword).
            module = _find_dynamic_import_module(call_node, src)
            if module is not None:
                _emit(module, node_line(call_node))

        edges.sort(key=lambda e: (e.line, e.to_module, e.kind))
        return edges

    # ------------------------------------------------------------------
    # Structural: symbols (tree-sitter, confidence=1.0)
    # ------------------------------------------------------------------

    def extract_symbols(self, content: str, path: Path) -> list[SymbolDef]:
        """Return one SymbolDef per top-level declaration in *content*.

        Backed by tree-sitter for true AST accuracy.  All items carry
        ``confidence=1.0``.

        Detected kinds:
            class       -- ``class_declaration`` / ``abstract_class_declaration``
            interface   -- ``interface_declaration``
            type        -- ``type_alias_declaration``
            enum        -- ``enum_declaration``
            function    -- ``function_declaration``
            const       -- ``lexical_declaration`` / ``variable_declaration``

        Visibility:
            - ``"public"``  -- declaration is wrapped in an ``export_statement``
            - ``"module"``  -- declaration is not exported
        """
        _log.debug("extract_symbols (tree-sitter): %s (%d chars)", path, len(content))
        src: bytes = content.encode("utf-8", errors="replace")
        root = parse_bytes(_TS_LANGUAGE, src)

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
            """Extract symbol(s) from a single declaration node."""
            t = decl_node.type

            if t in ("class_declaration", "abstract_class_declaration"):
                # TS class names are ``type_identifier`` nodes.
                for child in decl_node.children:
                    if child.is_named and child.type == "type_identifier":
                        _emit(node_text(child, src), "class", node_line(decl_node), exported)
                        break

            elif t == "interface_declaration":
                for child in decl_node.children:
                    if child.is_named and child.type == "type_identifier":
                        _emit(node_text(child, src), "interface", node_line(decl_node), exported)
                        break

            elif t == "type_alias_declaration":
                for child in decl_node.children:
                    if child.is_named and child.type == "type_identifier":
                        _emit(node_text(child, src), "type", node_line(decl_node), exported)
                        break

            elif t == "enum_declaration":
                # enum names are plain ``identifier`` nodes in the TS grammar.
                for child in decl_node.children:
                    if child.is_named and child.type == "identifier":
                        _emit(node_text(child, src), "enum", node_line(decl_node), exported)
                        break

            elif t == "function_declaration":
                for child in iter_named_children(decl_node, "identifier"):
                    _emit(node_text(child, src), "function", node_line(decl_node), exported)
                    break

            elif t in ("lexical_declaration", "variable_declaration"):
                for var_decl in iter_named_children(decl_node, "variable_declarator"):
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
                        break  # one declarator → one symbol (first identifier wins)

        for node in root.children:
            if not node.is_named:
                continue

            if node.type == "export_statement":
                for child in node.children:
                    if not child.is_named:
                        continue
                    _process_declaration(child, exported=True)
            else:
                _process_declaration(node, exported=False)

        syms.sort(key=lambda s: (s.line, s.name))
        return syms
