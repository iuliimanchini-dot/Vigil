"""Detect non-ASCII characters that crash Windows console (cp1252).

Windows default console encoding cannot render emoji, box-drawing, arrows,
smart quotes. Python print/raise/log crashes with UnicodeEncodeError.
This is a universal check -- applies to any project running on Windows.
"""
from __future__ import annotations

import ast
import re
import sys
from pathlib import Path

from cortex_forensic._shared import WINDOWS_CLI_RUNTIME_EXTENSIONS as _WINDOWS_CLI_RUNTIME_EXTENSIONS
from cortex_forensic._shared import EvidenceReference, GateCategory, GateImpact, GateSeverity, RepairKind
from cortex_forensic.gate_models import PostExecGateContext
from ..source_analysis import is_source_file
from .common import build_check_result, build_finding, iter_touched_snapshots
from ._deployment_detector import (
    detect_file_deployment,
    detect_project_deployment,
    get_explicit_deployment,
)
import logging
_log = logging.getLogger(__name__)

# subprocess calls that may need encoding=
_SUBPROCESS_CALL_RE = re.compile(
    r'\bsubprocess\.(run|Popen|check_output|check_call)\s*\(',
)

# Characters outside cp1252 range (U+0100+)
_DANGEROUS_RE = re.compile(r'[\u0100-\uffff]')

# Pure comment lines — safe, never reach stdout.
# Python/shell/PowerShell use "#", JS/TS/Go/Java/C* use "//", SQL uses "--".
# Keyed by file extension (lowercase). Extensions not listed fall back to
# scanning every line (the textual sink detector then filters out lines that
# don't contain a recognized output function, so noise stays low).
_COMMENT_PREFIXES_BY_EXT: dict[str, tuple[str, ...]] = {
    ".py": ("#",),
    ".ps1": ("#",),
    ".sh": ("#",),
    ".bash": ("#",),
    ".bat": ("rem ", "REM ", "::"),
    ".cmd": ("rem ", "REM ", "::"),
    ".js": ("//",),
    ".mjs": ("//",),
    ".cjs": ("//",),
    ".ts": ("//",),
    ".tsx": ("//",),
    ".go": ("//",),
    ".java": ("//",),
    ".sql": ("--",),
    ".ini": (";",),
}

# Legacy Python-comment regex (kept for back-compat with Python-AST path).
_COMMENT_RE = re.compile(r'^\s*#')

# High-risk Unicode ranges with human-readable names
_HIGH_RISK_RANGES = (
    (0x2500, 0x257F, "box-drawing"),
    (0x2190, 0x21FF, "arrows"),
    (0x2014, 0x2014, "em-dash"),
    (0x2013, 0x2013, "en-dash"),
    (0x201C, 0x201D, "smart-quotes"),
    (0x2018, 0x2019, "smart-apostrophes"),
    (0x2705, 0x2705, "checkmark-emoji"),
    (0x274C, 0x274C, "cross-emoji"),
    (0x1F300, 0x1F9FF, "emoji"),
    (0x2600, 0x26FF, "misc-symbols"),
    (0x2700, 0x27BF, "dingbats"),
)

# Keywords that indicate text reaches stdout/stderr directly — HIGH risk on cp1252
_STDOUT_SINK_RE = re.compile(
    r'print\s*\(|sys\.stdout\.write\s*\(|sys\.stderr\.write\s*\('
)

# Keywords that indicate logging sinks — bytes go through Python logging, not console codec
_LOGGING_SINK_RE = re.compile(
    r'(?:^|[^a-zA-Z_])(?:logging|_log|_logger|log|logger)\s*\.\s*(?:debug|info|warning|error|critical|exception)\s*\('
)

# Cross-language console-output substrings — used by the textual fallback
# sink detector when AST parsing is unavailable (non-Python files, or Python
# files with a syntax error). Matching is substring-based on the already-
# uncommented line, so ordering/anchoring is not required.
# HIGH: anything that writes to stdout/stderr and therefore hits the cp1252
# console codec on Windows.
_TEXTUAL_STDOUT_SINKS: tuple[str, ...] = (
    "print(",                # Python, also common in JS/TS via CommonJS
    "console.log(",          # JS/TS
    "console.error(",        # JS/TS — writes to stderr, still hits cp1252 console
    "console.warn(",         # JS/TS — writes to stderr on Node; HIGH on Windows Node
    "process.stdout.write(", # Node.js
    "process.stderr.write(", # Node.js
    "stderr.write(",         # Generic (covers sys.stderr.write and Go os.Stderr.Write alias-style)
    "sys.stdout.write(",     # Python
    "sys.stderr.write(",     # Python
    "printf ",               # POSIX shell printf builtin (with space)
    "printf(",               # C / Go fmt.Printf when imported unqualified
    "fmt.Print",             # Go — matches fmt.Print, fmt.Println, fmt.Printf (substring)
    "fmt.Fprint",            # Go — matches fmt.Fprint, fmt.Fprintln, fmt.Fprintf
    "log.Print",             # Go standard library log package (Print, Println, Printf)
    "System.out.print",      # Java (matches print and println)
    "System.err.print",      # Java
    "Write-Host",            # PowerShell — writes to host, bypasses codec-safe stream
    "Write-Output",          # PowerShell — piped, but rendered when terminal sink
    "Write-Error",           # PowerShell — writes to error stream, hits cp1252 console
    "echo ",                 # POSIX shell / batch
    "echo\t",                # POSIX shell with tab between echo and args
    "echo(",                 # Some shells
)
# MEDIUM: logger-style sinks — encoding usually handled internally, but stale
# tooling may still barf; rated MEDIUM (WARN) just like the Python AST path.
_TEXTUAL_LOGGER_SINKS: tuple[str, ...] = (
    "log.info", "log.debug", "log.warn", "log.warning", "log.error", "log.critical", "log.exception",
    "logger.info", "logger.debug", "logger.warn", "logger.warning", "logger.error", "logger.critical", "logger.exception",
    "console.info(", "console.debug(",
    "Write-Verbose",
    "Write-Warning",
    "Write-Information",
)

# F18b / Sprint C3 (2026-04-23): canonical whitelist of extensions whose
# runtime output passes through a locale-dependent console lives in
# SYSTEM.shared_helpers.file_extensions.WINDOWS_CLI_RUNTIME_EXTENSIONS. Re-
# exported above as ``_WINDOWS_CLI_RUNTIME_EXTENSIONS`` so the Layer 1
# extension filter below continues to resolve the private name.


def _should_scan_for_encoding(
    rel_path: str,
    content: str | None = None,
    project_dir: Path | None = None,
) -> bool:
    """Arbiter for 'is this file in scope for the encoding gate?'.

    Two layers, evaluated in order:

    1. **Extension whitelist (F18b).** Only runtimes whose output passes
       through a locale-dependent console (cp1252 on Windows). Python,
       Java, C#, Go, Rust, shell, PowerShell, batch. TypeScript / JavaScript
       / HTML / CSS / JSON / Markdown stay out regardless of deployment.

    2. **Deployment cascade (F19).** When the target project deploys only
       to Linux (or a file explicitly imports Unix-only modules / has a
       Unix shebang), cp1252 crashes cannot happen — skip the scan. The
       cascade checks:

       * Layer 3 — explicit ``.autoforensics/config.json`` /
         ``AUTOFORENSICS_DEPLOYMENT`` env var.
       * Layer 1 — per-file signals (shebang, Unix/Windows imports,
         ``sys.platform`` guards).
       * Layer 2 — project-level signals (pyproject classifiers,
         Dockerfile, GitHub Actions runners, Linux-exclusive deps).

       Precedence: explicit > file > project. When all layers return
       'unknown' we scan — a false positive is recoverable by allowlist;
       a false negative hides a real bug.

    Called per file. Project-level detection is cached inside the detector
    module, so a rubik-scale scan (~2000 files) only touches pyproject /
    workflows / Dockerfile once.
    """
    lower = rel_path.lower()
    extension_match = False
    for ext in _WINDOWS_CLI_RUNTIME_EXTENSIONS:
        if lower.endswith(ext):
            extension_match = True
            break
    if not extension_match:
        return False

    if project_dir is None:
        # Legacy caller / tests that do not propagate project_dir — keep
        # prior F18b behaviour (scan on extension match).
        return True

    # Layer 3 — explicit override. Wins over file and project signals.
    explicit = get_explicit_deployment(project_dir)
    if explicit is not None:
        if explicit == "linux-only":
            return False
        # windows-only / cross-platform → scan.
        return True

    # Layer 1 — per-file signal. A clear Unix file (shebang, fcntl import)
    # does not need scanning even in a cross-platform project; a clear
    # Windows file always scans.
    if content:
        file_signal = detect_file_deployment(content)
        if file_signal == "unix":
            return False
        if file_signal == "windows":
            return True

    # Layer 2 — project-level signal.
    project_signal = detect_project_deployment(project_dir)
    if project_signal == "linux-only":
        return False
    # windows-only / cross-platform / unknown → scan (conservative default).
    return True


def _classify_textual_sink(line: str) -> str | None:
    """Return 'stdout' | 'logger' | None for a non-AST line.

    Pure substring scan against two tables; stdout sinks dominate logger
    sinks when both appear. Used whenever AST parsing is unavailable:
    - Non-Python files (.js, .ts, .go, .java, .sh, .ps1, ...) by design.
    - Python files that fail to parse (syntax errors) — we still want to
      flag obviously broken sources rather than silently skipping them.
    """
    for needle in _TEXTUAL_STDOUT_SINKS:
        if needle in line:
            return "stdout"
    for needle in _TEXTUAL_LOGGER_SINKS:
        if needle in line:
            return "logger"
    return None


def _is_comment_line(line: str, ext: str) -> bool:
    """Language-aware comment detection.

    Returns True when `line` is entirely a comment for the given extension.
    Extensions with no known comment syntax return False (we then scan the
    line; the textual sink detector filters out non-sink lines anyway).
    """
    prefixes = _COMMENT_PREFIXES_BY_EXT.get(ext.lower())
    if not prefixes:
        return False
    stripped = line.lstrip()
    if not stripped:
        return False
    return any(stripped.startswith(p) for p in prefixes)

# Safe non-ASCII codepoints that transcode cleanly via every modern codec
# including Windows cp1252 (they all exist in the cp1252 character table or
# have a canonical cp1252 equivalent). When a line's entire non-ASCII content
# falls inside this set, the line is not a crash risk and no finding is emitted.
_SAFE_UNICODE_CODEPOINTS: frozenset[int] = frozenset({
    0x2013,  # en-dash
    0x2014,  # em-dash
    0x2018,  # left single smart quote
    0x2019,  # right single smart quote
    0x201C,  # left double smart quote
    0x201D,  # right double smart quote
    0x2026,  # horizontal ellipsis
    0x00A0,  # non-breaking space
    0x00B0,  # degree sign
    0x00B5,  # micro sign
    0x00AB,  # left guillemet
    0x00BB,  # right guillemet
})

# Loggers that apply errors='replace' or utf-8 under the hood — MEDIUM risk
_LOGGER_METHOD_NAMES: frozenset[str] = frozenset({
    "debug", "info", "warning", "warn", "error", "critical", "exception", "log",
})
_LOGGER_RECEIVER_NAMES: frozenset[str] = frozenset({
    "_log", "_logger", "log", "logger", "logging",
})

# F9a-tighten (2026-04-23): chained-call logger pattern — a Call whose func is
# an Attribute whose receiver is ITSELF a Call with ``.getLogger`` as the
# inner attribute. Matches ``logging.getLogger(...).exception(...)`` and
# similar one-shot logger-factory chains.
_LOGGER_FACTORY_INNER_METHODS: frozenset[str] = frozenset({
    "getLogger", "get_logger", "get_child_logger", "getChildLogger",
})

# F9a-tighten: string-transform wrapper methods we traverse through when the
# nearest enclosing Call is one of these. We then look at the GRANDPARENT
# Call to classify the sink. Covers ``print(s.format(lit))``,
# ``sys.stdout.write(' '.join(lits))``, etc.
_WRAPPER_METHOD_NAMES: frozenset[str] = frozenset({
    "format", "join", "strip", "lstrip", "rstrip", "replace",
    "upper", "lower", "title", "capitalize",
    "encode", "decode",
    "removeprefix", "removesuffix",
    "zfill", "ljust", "rjust", "center",
})


def _classify_char(ch: str) -> str:
    cp = ord(ch)
    for low, high, name in _HIGH_RISK_RANGES:
        if low <= cp <= high:
            return name
    return "non-cp1252"


def _is_test_path(rel_path: str, ctx: object = None) -> bool:
    """True when rel_path is a test surface the encoding gate should skip.

    Sprint C2 (2026-04-23): prefers ``ctx.project_context.test_topology``
    when available. Preserves the original "encoding" filename exception —
    any test file whose basename contains "encoding" remains scannable
    (the gate's own test suite exercises raw Unicode as test data and
    SHOULD be flagged).

    Tests are run under pytest, which captures stdout and does not write to
    the cp1252 console. Skipping test paths removes the dominant FP source
    (fixture-string Cyrillic, docstring em-dash, etc.).
    """
    if not rel_path:
        return False
    normalized = rel_path.replace("\\", "/")
    parts = normalized.split("/")
    basename = parts[-1].lower()

    # Exception: files whose basename advertises "encoding" test behavior
    # are intentionally scanned, regardless of where they live.
    if "encoding" in basename:
        return False

    topology = getattr(getattr(ctx, "project_context", None), "test_topology", None)
    if topology is not None:
        return topology.is_test_path(normalized)

    # Legacy fallback — original path-fragment rule.
    if "tests" not in parts:
        return False
    return True


def _classify_call_sink(call_node: ast.Call) -> str | None:
    """Return 'stdout', 'logger', or None for a given Call node.

    - 'stdout' : print(...), sys.stdout.write(...), sys.stderr.write(...),
                 os.write(1|2, ...) — crashes cp1252 console.
    - 'logger' : _log.info(...), logger.debug(...), logging.warning(...),
                 AND chained-call factories like
                 ``logging.getLogger(__name__).exception(...)`` (blind-spot D
                 chained Call traversal).
    - None     : json.dumps(...), _append_trace(...), foo.bar(...), etc. —
                 not a console sink; finding suppressed entirely.
    """
    func = call_node.func
    # print(...)
    if isinstance(func, ast.Name) and func.id == "print":
        return "stdout"
    if isinstance(func, ast.Attribute):
        attr = func.attr
        value = func.value
        # sys.stdout.write(...) / sys.stderr.write(...)
        if attr == "write" and isinstance(value, ast.Attribute):
            if value.attr in ("stdout", "stderr") and isinstance(value.value, ast.Name) and value.value.id == "sys":
                return "stdout"
        # os.write(1|2, ...)
        if attr == "write" and isinstance(value, ast.Name) and value.id == "os":
            if call_node.args:
                first = call_node.args[0]
                if isinstance(first, ast.Constant) and first.value in (1, 2):
                    return "stdout"
        # Logger methods: _log.info / logger.debug / logging.warning / self._log.info etc.
        if attr in _LOGGER_METHOD_NAMES:
            # Accept plain Name receivers (_log, logger, logging).
            if isinstance(value, ast.Name) and value.id in _LOGGER_RECEIVER_NAMES:
                return "logger"
            # Accept self.<logger>.method / cls.<logger>.method chains.
            if isinstance(value, ast.Attribute) and value.attr in _LOGGER_RECEIVER_NAMES:
                return "logger"
            # F9a-tighten (2026-04-23): chained call
            # ``logging.getLogger(__name__).exception(...)`` — the receiver
            # (func.value) is itself a Call whose inner attribute is a
            # known logger-factory name (``getLogger`` etc.). Classify the
            # OUTER method (info/error/exception/etc.) as a logger sink.
            if isinstance(value, ast.Call):
                inner_func = value.func
                if isinstance(inner_func, ast.Attribute) and inner_func.attr in _LOGGER_FACTORY_INNER_METHODS:
                    return "logger"
                if isinstance(inner_func, ast.Name) and inner_func.id in _LOGGER_FACTORY_INNER_METHODS:
                    return "logger"
    return None


def _collect_string_literal_sinks(source: str) -> dict[int, str]:
    """Map 1-based line number -> sink classification for non-ASCII string
    literals inside Call / Raise nodes.

    Returns a dict with entries only for lines containing a str/JoinedStr
    literal whose resolved sink classifies as 'stdout' or 'logger'. Lines
    not in the dict mean either (a) no string literal in a Call on that line
    or (b) the enclosing Call is a non-sink helper (json.dumps, etc.).

    F9a-tighten (2026-04-23):
      * Raise detection — a literal whose ancestor chain contains ``ast.Raise``
        is classified as 'stdout' HIGH (the exception message lands on
        stderr, which runs through the cp1252 codec on Windows).
      * Grandparent walk — when the nearest enclosing Call is a wrapper
        method (``.format`` / ``.join`` / ``.replace`` / etc.), we look at
        the outer Call that receives the wrapper's result. This catches
        ``print(fmt.format('cyr'))`` where the nearest Call is ``.format``
        but the eventual sink is ``print``.

    Empty dict on SyntaxError; caller falls back to "suppress all" behavior
    for a file that cannot be parsed (we prefer FN over FP).
    """
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return {}

    # Build parent map so we can walk a node's ancestors.
    parent: dict[int, ast.AST] = {}
    for node in ast.walk(tree):
        for child in ast.iter_child_nodes(node):
            parent[id(child)] = node

    def _is_wrapper_call(call: ast.Call) -> bool:
        """True if *call* is a transparent string-transform wrapper.

        We skip through these and look at the grandparent Call instead.
        """
        f = call.func
        if isinstance(f, ast.Attribute) and f.attr in _WRAPPER_METHOD_NAMES:
            return True
        # ``str.format(...)`` / ``str.join(...)`` — Name chain with attribute.
        if isinstance(f, ast.Attribute) and isinstance(f.value, ast.Name) and f.value.id == "str":
            if f.attr in _WRAPPER_METHOD_NAMES:
                return True
        return False

    def _has_raise_ancestor(node: ast.AST) -> bool:
        """True if *node*'s ancestor chain contains ``ast.Raise`` within the
        same statement scope.

        We stop at the first function/class boundary so a literal inside a
        nested def/lambda is not mis-attributed to an outer raise.
        """
        cur: ast.AST | None = parent.get(id(node))
        while cur is not None:
            if isinstance(cur, ast.Raise):
                return True
            if isinstance(cur, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda, ast.Module)):
                return False
            cur = parent.get(id(cur))
        return False

    def _resolve_sink(node: ast.AST) -> str | None:
        """F9a-tighten: walk ancestors, skipping wrapper Calls, and classify.

        Order of precedence (first hit wins):
          1. Raise ancestor in same statement → ``stdout`` (stderr sink).
          2. Nearest non-wrapper Call → ``_classify_call_sink``.
          3. Grandparent of wrapper Call — keep walking past the wrapper
             until we hit a classifier-matching Call.
          4. None.
        """
        # Priority 1: Raise ancestor. Exception messages render via
        # ``sys.stderr.write`` / ``traceback.print_exception`` which hit the
        # cp1252 codec on Windows. Check before call classification so
        # ``raise ValueError("cyr")`` classifies even though ``ValueError``
        # itself is not a known sink.
        if _has_raise_ancestor(node):
            return "stdout"

        # Walk upward, skipping wrapper Calls (grandparent traversal).
        cur: ast.AST | None = parent.get(id(node))
        while cur is not None:
            if isinstance(cur, ast.Call):
                if _is_wrapper_call(cur):
                    # Wrapper itself may classify (rare safety net).
                    direct = _classify_call_sink(cur)
                    if direct is not None:
                        return direct
                    # Skip past the wrapper: keep hunting for a real sink.
                    cur = parent.get(id(cur))
                    continue
                # Non-wrapper Call — definitive classifier (sink or None).
                return _classify_call_sink(cur)
            cur = parent.get(id(cur))
        return None

    result: dict[int, str] = {}

    def _record(node: ast.AST, sink: str) -> None:
        start = getattr(node, "lineno", None)
        end = getattr(node, "end_lineno", None) or start
        if start is None:
            return
        for ln in range(start, (end or start) + 1):
            # Upgrade: stdout dominates logger if multiple literals share line.
            prev = result.get(ln)
            if prev != "stdout":
                result[ln] = sink

    for node in ast.walk(tree):
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            sink = _resolve_sink(node)
            if sink is None:
                continue
            _record(node, sink)
        elif isinstance(node, ast.JoinedStr):
            sink = _resolve_sink(node)
            if sink is None:
                continue
            _record(node, sink)

    return result


def _collect_docstring_lines(source: str) -> set[int]:
    """Return 1-based line numbers belonging to any docstring in `source`.

    AST-based: identifies module-, class-, and function-body first statement
    when it is ``Expr(Constant(str))``. Docstring strings are compile-time
    constants never written to stdout — we skip them entirely (no finding,
    not even LOW). Returns empty set on SyntaxError so callers fall back to
    standard non-docstring processing for the whole file.
    """
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return set()

    docstring_lines: set[int] = set()

    def _mark(node: ast.AST) -> None:
        if not isinstance(node, ast.Expr):
            return
        val = node.value
        if not isinstance(val, ast.Constant) or not isinstance(val.value, str):
            return
        start = getattr(val, "lineno", None)
        end = getattr(val, "end_lineno", None) or start
        if start is None:
            return
        for ln in range(start, (end or start) + 1):
            docstring_lines.add(ln)

    # Module docstring: first stmt of tree.body.
    if tree.body:
        _mark(tree.body[0])

    # Class/function docstrings: first stmt of any Class/FunctionDef/AsyncFunctionDef body.
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            if node.body:
                _mark(node.body[0])

    return docstring_lines


def run_encoding_checks(ctx: PostExecGateContext):
    """Scan changed files for Windows-unsafe Unicode characters."""
    # Only relevant on Windows
    if sys.platform != "win32":
        return build_check_result(
            check_id="encoding_safety",
            category=GateCategory.RUNTIME_BEHAVIOR,
            notes=["Skipped: not running on Windows"],
        )

    findings = []
    # Resolve project_dir once — detection helpers cache per-project but
    # we still want a single Path instance per call (fewer attribute lookups).
    project_dir = getattr(ctx, "project_dir", None)

    for rel_path, snap in ctx.file_snapshots.items():
        if not snap.exists or not snap.text:
            continue
        # F18b: whitelist filter + F19: deployment cascade. Only scan files
        # whose runtime output passes through a locale-dependent console
        # (Python, Java, C#, Go, Rust, shell, PowerShell, batch) AND whose
        # deployment target is not provably Linux-only. TypeScript /
        # JavaScript / markup languages always skip; Linux-only deployments
        # also skip because cp1252 crashes cannot occur there.
        if not _should_scan_for_encoding(rel_path, snap.text, project_dir):
            continue
        # Part 1: skip test paths entirely (pytest captures stdout, not the
        # cp1252 console). Keep files whose basename contains "encoding" so
        # the gate's own test suite can still be scanned. Sprint C2: ctx
        # threaded through so _is_test_path can consult TestTopology.
        if _is_test_path(rel_path, ctx):
            continue

        all_lines = snap.text.splitlines()
        is_python = rel_path.endswith(".py")
        # Extension used for comment-prefix dispatch. We use the raw suffix
        # rather than going through get_language_id() because comment syntax
        # is per-extension (e.g. .bat differs from .cmd only in rare forms,
        # .jsx shares JS syntax, etc.).
        ext = ""
        dot = rel_path.rfind(".")
        if dot >= 0:
            ext = rel_path[dot:].lower()

        # Docstrings are compile-time constants, never reach stdout — skip
        # them entirely (no finding). AST-based so we correctly identify
        # module/class/function first-statement Expr(Constant(str)).
        # Python-only concept; other languages have no docstring semantics.
        docstring_lines = _collect_docstring_lines(snap.text) if is_python else set()

        # Part 3: AST-based sink map. For Python, line -> 'stdout' | 'logger'.
        # Lines not in the map either have no string literal inside a Call,
        # or the enclosing Call is a non-console helper (json.dumps, etc.) —
        # we suppress those findings entirely.
        #
        # When ast.parse fails (non-Python file by extension, OR a .py file
        # with a syntax error) `_collect_string_literal_sinks` returns {}
        # and we fall back to the textual-sink detector below. We prefer
        # false-negatives-on-sink-classification over silently skipping a
        # broken or non-Python source file.
        sink_map = _collect_string_literal_sinks(snap.text) if is_python else {}

        # For non-Python files we always go through the textual fallback.
        # For Python files with a non-empty sink_map we use AST. For Python
        # files whose sink_map came back empty (empty file -> empty dict;
        # parse error -> empty dict) we also go textual. We disambiguate
        # "empty because parse failed" vs "empty because no sinks present"
        # cheaply by attempting a parse here and caching the result.
        ast_available = is_python
        if is_python:
            try:
                ast.parse(snap.text)
            except SyntaxError:
                ast_available = False

        for line_num, line in enumerate(all_lines, 1):
            # Language-aware comment skip. For extensions without a known
            # comment syntax (none today, but e.g. .html, .json), we scan
            # the whole line and let the sink detector filter.
            if _is_comment_line(line, ext):
                continue

            # Skip docstring lines entirely — no finding emitted.
            if line_num in docstring_lines:
                continue

            # Respect explicit per-line allowlist.
            if "noqa: encoding" in line or "noqa:encoding" in line:
                continue

            matches = _DANGEROUS_RE.findall(line)
            if not matches:
                continue

            # Part 2: split matches into safe (cp1252-compatible) and unsafe.
            # When ALL chars on the line are safe → skip; safe chars transcode
            # cleanly so there is no crash risk regardless of sink.
            # This rule is language-agnostic: safe codepoints stay safe
            # regardless of the file's language.
            unsafe_chars = [ch for ch in matches if ord(ch) not in _SAFE_UNICODE_CODEPOINTS]
            if not unsafe_chars:
                continue

            # Sink resolution:
            #   - Python + AST-parsable: use AST map (precise, few FPs).
            #   - Otherwise: simple textual substring match against the
            #     cross-language sink tables. Lines with no recognized
            #     output function are skipped entirely — they are not a
            #     crash risk even if they contain unsafe unicode (e.g.
            #     a JS string constant never passed to console.log).
            if ast_available:
                sink = sink_map.get(line_num)
                if sink is None:
                    # Either the literal is not inside any Call, or the Call
                    # is a non-console helper. Suppress entirely — these are
                    # the dominant FP source (_append_trace, json.dumps,
                    # module-level constants, return values, etc.).
                    continue
                is_stdout_sink = sink == "stdout"
                is_logging_sink = sink == "logger"
            else:
                sink = _classify_textual_sink(line)
                if sink is None:
                    continue
                is_stdout_sink = sink == "stdout"
                is_logging_sink = sink == "logger"

            for ch in set(unsafe_chars):
                category = _classify_char(ch)

                if is_stdout_sink:
                    # Direct stdout/stderr — crashes cp1252 console
                    severity = GateSeverity.HIGH
                    impact = GateImpact.REVISE
                    sink_label = "stdout/stderr sink (print/sys.write)"
                    executor_action = (
                        "replace unicode with ASCII in print/stderr — crashes on cp1252 console"
                    )
                elif is_logging_sink:
                    # Logger handles encoding internally — no crash, but stale tooling may barf
                    severity = GateSeverity.MEDIUM
                    impact = GateImpact.WARN
                    sink_label = "logging sink"
                    executor_action = (
                        "consider ASCII for consistency; logger doesn't crash on utf8 but stale tooling may"
                    )
                else:
                    # Unreachable for Python (we `continue`d above) but kept
                    # for defensive completeness if future shell branch adds
                    # an "unknown" pathway.
                    severity = GateSeverity.MEDIUM
                    impact = GateImpact.WARN
                    sink_label = "code (unknown sink)"
                    executor_action = (
                        "consider ASCII for consistency; unknown whether this reaches cp1252 console"
                    )

                findings.append(build_finding(
                    check_id="encoding.windows_unsafe_char",
                    category=GateCategory.RUNTIME_BEHAVIOR,
                    title=f"Windows-unsafe U+{ord(ch):04X} ({category}) in {rel_path}:{line_num}",
                    severity=severity,
                    impact=impact,
                    summary=(
                        f"Character U+{ord(ch):04X} ({category}) in {sink_label}. "
                        f"Windows cp1252 console will crash with UnicodeEncodeError if this reaches stdout/stderr."
                    ),
                    recommendation=(
                        f"Replace with ASCII equivalent in {rel_path} line {line_num}. "
                        f"Common fixes: em-dash->--, arrows->->, checkmark->[OK], cross->[X]"
                    ),
                    evidence=(EvidenceReference(
                        kind="probe",
                        path=rel_path,
                        detail=f"Character U+{ord(ch):04X} ({category}) at line {line_num}",
                        ok=False,
                    ),),
                    repair_kind=RepairKind.FIX_ENCODING.value,
                    executor_action=executor_action,
                    proof_required="Proper encoding",
                    allowlist_allowed=False,
                ))

    return build_check_result(
        check_id="encoding_safety",
        category=GateCategory.RUNTIME_BEHAVIOR,
        findings=findings,
        notes=[f"Scanned {len(ctx.file_snapshots)} files for Windows-unsafe characters"],
    )


def _extract_call_block(lines: list[str], start_line: int, max_lines: int = 40) -> str:
    """Extract argument block of a call starting at start_line (1-based).

    Tracks paren depth so we stop at the matching close paren instead of
    grabbing N lines and accidentally spanning into the next call.
    Used as fallback when AST parsing is unavailable (syntax errors, etc.).
    """
    depth = 0
    block: list[str] = []
    for i in range(start_line - 1, min(start_line - 1 + max_lines, len(lines))):
        line = lines[i]
        block.append(line)
        depth += line.count("(") - line.count(")")
        if depth <= 0 and i > start_line - 1:
            break
    return " ".join(block)


def _extract_call_kwargs(file_content: str, call_lineno: int) -> set[str] | None:
    """Return the set of keyword argument names for the call at call_lineno.

    Uses AST so the result is exact regardless of how many lines the call
    spans.  Returns None when the file cannot be parsed (syntax error) so
    the caller can fall back to the regex-based approach.
    """
    try:
        tree = ast.parse(file_content)
    except SyntaxError:
        return None

    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and node.lineno == call_lineno:
            return {kw.arg for kw in node.keywords if kw.arg is not None}
    return set()


def run_subprocess_encoding_checks(ctx: PostExecGateContext):
    """Detect subprocess calls with text=True but missing encoding parameter.

    On Windows, text=True without encoding= defaults to the system locale
    (cp1252), crashing with UnicodeEncodeError on non-ASCII git output
    (branch names, file paths, commit messages).

    Fix: add encoding='utf-8', errors='replace' to every subprocess call
    that uses text=True.
    """
    findings = []

    for snapshot in iter_touched_snapshots(ctx):
        if not snapshot.exists or not snapshot.text:
            continue
        if not is_source_file(snapshot.path):
            continue

        lines = snapshot.text.splitlines()

        for match in _SUBPROCESS_CALL_RE.finditer(snapshot.text):
            call_name = match.group(1)
            line_num = snapshot.text.count("\n", 0, match.start()) + 1

            kwargs = _extract_call_kwargs(snapshot.text, line_num)
            if kwargs is not None:
                # AST path: exact keyword extraction, no line-cap FP.
                has_text_true = "text" in kwargs
                has_encoding = "encoding" in kwargs
                # AST gives us keyword names but not their values; we still
                # need to verify text=True (not text=False).  Re-check with
                # regex only when text kwarg is present.
                if has_text_true:
                    block = _extract_call_block(lines, line_num)
                    has_text_true = bool(re.search(r'\btext\s*=\s*True\b', block))
            else:
                # Fallback for files with syntax errors: regex over block.
                block = _extract_call_block(lines, line_num)
                has_text_true = bool(re.search(r'\btext\s*=\s*True\b', block))
                has_encoding = bool(re.search(r'\bencoding\s*=', block))

            if has_text_true and not has_encoding:
                findings.append(build_finding(
                    check_id="encoding.subprocess_missing_encoding",
                    category=GateCategory.RUNTIME_BEHAVIOR,
                    title=f"subprocess.{call_name}(text=True) missing encoding= in {snapshot.path}:{line_num}",
                    severity=GateSeverity.HIGH,
                    impact=GateImpact.REVISE,
                    summary=(
                        f"subprocess.{call_name}() at line {line_num} uses text=True without encoding=. "
                        f"On Windows defaults to cp1252 -- crashes with UnicodeEncodeError on non-ASCII "
                        f"git output (branch names, file paths, commit messages)."
                    ),
                    recommendation=(
                        f"Add encoding='utf-8', errors='replace' to subprocess.{call_name}() "
                        f"in {snapshot.path} line {line_num}."
                    ),
                    evidence=[
                        EvidenceReference(kind="file", path=snapshot.path, detail=f"line:{line_num}"),
                    ],
                    repair_kind=RepairKind.FIX_ENCODING.value,
                    executor_action="Fix encoding issues",
                    proof_required="Proper encoding",
                    allowlist_allowed=False,
                ))

    return build_check_result(
        check_id="subprocess_encoding",
        category=GateCategory.RUNTIME_BEHAVIOR,
        findings=findings,
    )
