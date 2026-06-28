"""Quality cluster wrappers -- clusters 10-31.

Covers: edit consistency, mutation verified, security patterns, test quality,
import cycles, roundtrip consistency, shared mutable state, dependency
vulnerabilities, secrets in code, dead code, unused imports, magic numbers,
error message quality, naming consistency, todo debt, log level quality,
encoding consistency, embedded code syntax, response shape drift, HTTP method
consistency, JS surface coverage, exception swallowing.
"""
from __future__ import annotations

import os
import re

from ...source_analysis import is_source_file, is_test_file, get_language_id
from ...gate_models import GateFinding, PostExecGateContext
from .._ast_helpers import collect_string_constant_line_ranges
from ..forensic_clusters import (
    DeadCodeItem,
    assess_dead_code,
    assess_dependency_vulnerabilities,
    assess_edit_consistency,
    assess_embedded_code_syntax,
    assess_encoding_consistency,
    assess_error_message_quality,
    assess_exception_swallowing,
    assess_http_method_consistency,
    assess_import_cycles,
    assess_js_surface_coverage,
    assess_log_level_quality,
    assess_magic_numbers,
    assess_mutation_verified,
    assess_naming_consistency,
    assess_response_shape_drift,
    assess_roundtrip_consistency,
    assess_secrets_in_code,
    assess_security_patterns,
    assess_shared_mutable_state,
    assess_test_quality,
    assess_todo_debt,
    assess_unused_imports,
    classify_dead_code_item,
)
from ._helpers import _MAX_FINDINGS_PER_CLUSTER
import logging
_log = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Cluster 10: Edit Consistency
# ---------------------------------------------------------------------------


def _check_edit_consistency(ctx: PostExecGateContext) -> list[GateFinding]:
    """Cluster 10: Check that repeated patterns are consistent across touched files."""
    snapshots = ctx.file_snapshots or {}
    if not snapshots:
        return []

    operator_files = {
        path: snap for path, snap in snapshots.items()
        if "operator_api" in path and hasattr(snap, "text")
    }

    if not operator_files:
        return []

    instances: dict[str, str] = {}
    for path, snap in operator_files.items():
        text = snap.text or ""
        for match in re.finditer(r"def (handle_\w+)\(", text):
            func_name = match.group(1)
            start = match.start()
            next_def = text.find("\ndef ", start + 1)
            body = text[start:next_def] if next_def != -1 else text[start:]

            if "_current_project_id(" in body:
                instances[f"{path}:{func_name}"] = "_current_project_id"
            elif "_bound_project_id(" in body:
                instances[f"{path}:{func_name}"] = "_bound_project_id"

    if not instances:
        return []

    return assess_edit_consistency(instances, r"_bound_project_id")


# ---------------------------------------------------------------------------
# Cluster 11: Mutation Without Verification
# ---------------------------------------------------------------------------


def _check_mutation_verified(ctx: PostExecGateContext) -> list[GateFinding]:
    """Cluster 11: Verify that file snapshots match actual disk content."""
    import hashlib

    snapshots = ctx.file_snapshots or {}
    if not snapshots:
        return []

    findings: list[GateFinding] = []
    sample_paths = sorted(snapshots.keys())[:10]

    for path in sample_paths:
        snap = snapshots[path]
        if not hasattr(snap, "text") or not snap.text:
            continue
        expected_hash = hashlib.sha256(snap.text.encode("utf-8")).hexdigest()
        findings.extend(
            assess_mutation_verified(
                path,
                expected_hash,
                project_dir=getattr(ctx, "project_dir", None),
            )
        )

    return findings


# ---------------------------------------------------------------------------
# Cluster 12: Security Patterns
# ---------------------------------------------------------------------------


def _check_security_patterns(ctx) -> list[GateFinding]:
    snapshots = ctx.file_snapshots or {}
    findings: list[GateFinding] = []
    for path, snap in snapshots.items():
        if not hasattr(snap, "text") or not snap.text:
            continue
        findings.extend(assess_security_patterns(path, snap.text))
        if len(findings) >= _MAX_FINDINGS_PER_CLUSTER:
            break
    return findings


# ---------------------------------------------------------------------------
# Cluster 13: Test Quality
# ---------------------------------------------------------------------------


def _check_test_quality(ctx) -> list[GateFinding]:
    snapshots = ctx.file_snapshots or {}
    findings: list[GateFinding] = []
    for path, snap in snapshots.items():
        if not path.replace("\\", "/").split("/")[-1].startswith("test_"):
            continue
        if not hasattr(snap, "text") or not snap.text:
            continue
        findings.extend(assess_test_quality(path, snap.text))
        if len(findings) >= _MAX_FINDINGS_PER_CLUSTER:
            break
    return findings


# ---------------------------------------------------------------------------
# Cluster 14: Import Cycles
# ---------------------------------------------------------------------------


def _check_import_cycles(ctx) -> list[GateFinding]:
    import re as _local_re
    snapshots = ctx.file_snapshots or {}
    module_imports = {}
    for path, snap in snapshots.items():
        if not is_source_file(path) or not hasattr(snap, "text") or not snap.text:
            continue
        if get_language_id(path) != "python":
            continue
        mod_name = path.replace("/", ".").replace("\\", ".").removesuffix(".py")
        imports = []
        for line in snap.text.splitlines():
            m = _local_re.match(r"from\s+\.(\w+)", line)
            if m:
                parent = ".".join(mod_name.split(".")[:-1])
                imports.append(f"{parent}.{m.group(1)}")
                continue
            m = _local_re.match(r"from\s+([\w.]+)\s+import", line)
            if m:
                imports.append(m.group(1))
        if imports:
            module_imports[mod_name] = imports
    return assess_import_cycles(module_imports)


# ---------------------------------------------------------------------------
# Cluster 15: Roundtrip Consistency
# ---------------------------------------------------------------------------


def _check_roundtrip_consistency(ctx) -> list[GateFinding]:
    # standalone: project_export roundtrip check not applicable
    return []


# ---------------------------------------------------------------------------
# Cluster 16: Shared Mutable State
# ---------------------------------------------------------------------------


def _check_shared_mutable_state(ctx) -> list[GateFinding]:
    snapshots = ctx.file_snapshots or {}
    findings: list[GateFinding] = []
    for path, snap in snapshots.items():
        if not is_source_file(path) or not hasattr(snap, "text") or not snap.text:
            continue
        if get_language_id(path) != "python":
            continue
        if path.replace("\\", "/").split("/")[-1].startswith("test_"):
            continue
        findings.extend(assess_shared_mutable_state(path, snap.text))
        if len(findings) >= _MAX_FINDINGS_PER_CLUSTER:
            break
    return findings


# ---------------------------------------------------------------------------
# Cluster 17: Dependency Vulnerabilities
# ---------------------------------------------------------------------------


def _check_dependency_vulnerabilities(ctx) -> list[GateFinding]:
    """Cluster 17: Run pip audit and parse results."""
    import logging as _logging
    _log = _logging.getLogger(__name__)
    if os.environ.get("AI_HOST_SKIP_PIP_AUDIT") == "1":
        _log.debug("_check_dependency_vulnerabilities: skipped (AI_HOST_SKIP_PIP_AUDIT=1)")
        return []
    import subprocess as _sp
    try:
        result = _sp.run(
            ["pip", "audit", "--format=json"],
            capture_output=True, text=True, encoding="utf-8",
            errors="replace", timeout=60,
        )
        return assess_dependency_vulnerabilities(result.stdout, "pip")
    except (FileNotFoundError, Exception):
        return []  # NOT_APPLICABLE -- pip audit unavailable


# ---------------------------------------------------------------------------
# Cluster 25: Secrets in Code
# ---------------------------------------------------------------------------


def _check_secrets_in_code(ctx) -> list[GateFinding]:
    """Cluster 25: Scan touched files for hardcoded secrets."""
    snapshots = ctx.file_snapshots or {}
    findings: list[GateFinding] = []
    for path, snap in snapshots.items():
        if not hasattr(snap, "text") or not snap.text:
            continue
        basename = path.replace("\\", "/").split("/")[-1]
        if basename.startswith("test_") or basename.endswith(".example"):
            continue
        findings.extend(assess_secrets_in_code(path, snap.text))
        if len(findings) >= _MAX_FINDINGS_PER_CLUSTER:
            break
    return findings


# ---------------------------------------------------------------------------
# Cluster 20: Dead Code
# ---------------------------------------------------------------------------


def _check_dead_code(ctx) -> list[GateFinding]:
    """Cluster 20: Find dead/forgotten code in touched files."""
    import re as _re
    snapshots = ctx.file_snapshots or {}
    if not snapshots:
        return []

    definitions: list[tuple[str, str, int, str]] = []
    all_content = ""
    module_alls: dict[str, set] = {}

    for path, snap in snapshots.items():
        if not is_source_file(path) or not hasattr(snap, "text") or not snap.text:
            continue
        if get_language_id(path) != "python":
            continue
        text = snap.text
        all_content += text + "\n"

        all_match = _re.search(r"__all__\s*=\s*[\[\(](.*?)[\]\)]", text, _re.DOTALL)
        if all_match:
            names = set(_re.findall(r"['\"](\w+)['\"]", all_match.group(1)))
            module_alls[path] = names

        # F14a: pre-compute string-literal line ranges so we skip `def foo`
        # matches that actually live inside a triple-quoted string fixture.
        file_string_lines = collect_string_constant_line_ranges(text)
        for m in _re.finditer(r"^def (\w+)\s*\(", text, _re.MULTILINE):
            line_start = text.rfind("\n", 0, m.start()) + 1
            if text[line_start:m.start()].strip():
                continue
            line = text[:m.start()].count("\n") + 1
            if line in file_string_lines:
                # Definition is inside a string literal (test fixture, docstring
                # example, embedded snippet). Not a real top-level function.
                continue
            definitions.append((m.group(1), path, line, "function"))

    if not definitions:
        return []

    items: list[DeadCodeItem] = []
    for name, file_path, line, kind in definitions:
        # Skip dunders (framework hooks like __init__/__repr__, normally called
        # implicitly) and test functions. Single-underscore private functions
        # ARE candidates: classify_dead_code_item flags a private symbol only
        # when it is unreferenced anywhere (a `self._x` method call sets
        # is_referenced and is skipped), and a public unreferenced symbol is
        # treated as possible external API (not flagged) -- so private+unref is
        # the precise dead-code signal.
        if name.startswith("__") or name.startswith("test_"):
            continue

        is_in_all = name in module_alls.get(file_path, set())
        ref_pattern = _re.compile(rf"\b{_re.escape(name)}\b")
        all_refs = list(ref_pattern.finditer(all_content))
        ref_count = len(all_refs) - 1

        method_pattern = _re.compile(rf"\.{_re.escape(name)}\b")
        method_refs = list(method_pattern.finditer(all_content))
        is_referenced = ref_count > 0 or len(method_refs) > 0
        item = classify_dead_code_item(
            name=name, file_path=file_path, line=line, kind=kind,
            is_referenced_anywhere=is_referenced,
            is_in_all=is_in_all,
            is_recent_commit=False,
            has_adjacent_caller_file=False,
        )
        if item.classification != "standalone_utility":
            items.append(item)

    return assess_dead_code(items)


# ---------------------------------------------------------------------------
# Cluster 23: Unused Imports
# ---------------------------------------------------------------------------


def _check_unused_imports(ctx) -> list[GateFinding]:
    """Cluster 23: Find unused imports in touched files."""
    snapshots = ctx.file_snapshots or {}
    findings: list[GateFinding] = []
    for path, snap in snapshots.items():
        if not is_source_file(path) or not hasattr(snap, "text") or not snap.text:
            continue
        if get_language_id(path) != "python":
            continue
        findings.extend(assess_unused_imports(path, snap.text))
        if len(findings) >= _MAX_FINDINGS_PER_CLUSTER:
            break
    return findings


# ---------------------------------------------------------------------------
# Cluster 21: Magic Numbers
# ---------------------------------------------------------------------------


def _check_magic_numbers(ctx) -> list[GateFinding]:
    snapshots = ctx.file_snapshots or {}
    findings: list[GateFinding] = []
    for path, snap in snapshots.items():
        if not is_source_file(path) or not hasattr(snap, "text") or not snap.text:
            continue
        if get_language_id(path) != "python":
            continue
        findings.extend(assess_magic_numbers(path, snap.text))
        if len(findings) >= _MAX_FINDINGS_PER_CLUSTER:
            break
    return findings


# ---------------------------------------------------------------------------
# Cluster 22: Error Message Quality
# ---------------------------------------------------------------------------


def _check_error_message_quality(ctx) -> list[GateFinding]:
    snapshots = ctx.file_snapshots or {}
    findings: list[GateFinding] = []
    for path, snap in snapshots.items():
        if not is_source_file(path) or not hasattr(snap, "text") or not snap.text:
            continue
        findings.extend(assess_error_message_quality(path, snap.text))
        if len(findings) >= _MAX_FINDINGS_PER_CLUSTER:
            break
    return findings


# ---------------------------------------------------------------------------
# Cluster 24: Naming Consistency
# ---------------------------------------------------------------------------


def _check_naming_consistency(ctx) -> list[GateFinding]:
    snapshots = ctx.file_snapshots or {}
    findings: list[GateFinding] = []
    for path, snap in snapshots.items():
        if not is_source_file(path) or not hasattr(snap, "text") or not snap.text:
            continue
        findings.extend(assess_naming_consistency(path, snap.text))
        if len(findings) >= _MAX_FINDINGS_PER_CLUSTER:
            break
    return findings


# ---------------------------------------------------------------------------
# Cluster 26: TODO Debt
# ---------------------------------------------------------------------------


def _check_todo_debt(ctx) -> list[GateFinding]:
    snapshots = ctx.file_snapshots or {}
    findings: list[GateFinding] = []
    for path, snap in snapshots.items():
        if not is_source_file(path) or not hasattr(snap, "text") or not snap.text:
            continue
        findings.extend(assess_todo_debt(path, snap.text))
        if len(findings) >= _MAX_FINDINGS_PER_CLUSTER:
            break
    return findings


# ---------------------------------------------------------------------------
# Cluster 28: Log Level Quality
# ---------------------------------------------------------------------------


def _check_log_level_quality(ctx) -> list[GateFinding]:
    snapshots = ctx.file_snapshots or {}
    findings: list[GateFinding] = []
    for path, snap in snapshots.items():
        if not is_source_file(path) or not hasattr(snap, "text") or not snap.text:
            continue
        findings.extend(assess_log_level_quality(path, snap.text))
        if len(findings) >= _MAX_FINDINGS_PER_CLUSTER:
            break
    return findings


# ---------------------------------------------------------------------------
# Cluster 29: Encoding Consistency
# ---------------------------------------------------------------------------


def _check_encoding_consistency(ctx) -> list[GateFinding]:
    snapshots = ctx.file_snapshots or {}
    findings: list[GateFinding] = []
    for path, snap in snapshots.items():
        if not is_source_file(path):
            continue
        from pathlib import Path as _P
        p = _P(path)
        if not p.exists():
            continue
        try:
            raw = p.read_bytes()
        except OSError:
            continue
        findings.extend(assess_encoding_consistency(path, raw))
        if len(findings) >= _MAX_FINDINGS_PER_CLUSTER:
            break
    return findings


# ---------------------------------------------------------------------------
# Phase 8 sub-runners (JS/API contract drift)
# ---------------------------------------------------------------------------


def _check_embedded_code_syntax(ctx) -> list[GateFinding]:
    snapshots = ctx.file_snapshots or {}
    findings: list[GateFinding] = []
    for path, snap in snapshots.items():
        if not is_source_file(path) or not hasattr(snap, "text") or not snap.text:
            continue
        findings.extend(assess_embedded_code_syntax(path, snap.text))
        if len(findings) >= _MAX_FINDINGS_PER_CLUSTER:
            break
    return findings


def _check_response_shape_drift(ctx) -> list[GateFinding]:
    snapshots = ctx.file_snapshots or {}
    backend = {p: s.text for p, s in snapshots.items()
               if is_source_file(p) and hasattr(s, "text") and s.text and "_send_json" in s.text}
    frontend = {p: s.text for p, s in snapshots.items()
                if is_source_file(p) and hasattr(s, "text") and s.text
                and any(kw in s.text for kw in ("fetch(", "addEventListener", "document.getElementById"))}
    return assess_response_shape_drift(backend, frontend)


def _check_http_method_consistency(ctx) -> list[GateFinding]:
    import re as _re
    snapshots = ctx.file_snapshots or {}

    route_methods = {}
    for path, snap in snapshots.items():
        if "dashboard_extension" not in path:
            continue
        if not hasattr(snap, "text") or not snap.text:
            continue
        in_get = False
        in_post = False
        for line in snap.text.splitlines():
            if "def do_GET" in line:
                in_get = True; in_post = False
            elif "def do_POST" in line:
                in_post = True; in_get = False
            elif line.strip().startswith("def "):
                in_get = False; in_post = False

            m = _re.search(r'path\s*==\s*["\']([^"\']+)["\']', line)
            if m:
                method = "GET" if in_get else "POST" if in_post else ""
                if method:
                    route_methods[m.group(1)] = method

    js_fetches = _extract_js_fetches_multiline(snapshots)

    return assess_http_method_consistency(route_methods, js_fetches)


def _extract_js_fetches_multiline(snapshots) -> list[tuple[str, str, str]]:
    """Extract ``fetch(url, {options})`` call sites, honouring multi-line options.

    The legacy implementation looked for ``method: 'POST'`` on the SAME line as
    the ``fetch(`` call -- which broke for idiomatic multi-line literals like::

        fetch('/api/x', {
            method: 'POST',
            body: JSON.stringify({...}),
        })

    ... causing the gate to default to ``GET`` and flag a mismatch even though
    the JS was fine. This version collects the full options object by
    bracket-balanced scan across lines, then searches ``method: ...`` inside
    the collected block.

    Returns list of ``(url, METHOD, "<path>:<line>")`` tuples.
    """
    import re as _re

    fetch_re = _re.compile(r"fetch\s*\(\s*['\"](/[^'\"]+)['\"]\s*(,\s*\{)?")
    method_re = _re.compile(r"""['\"]?method['\"]?\s*:\s*['\"](\w+)['\"]""")

    js_fetches: list[tuple[str, str, str]] = []
    for path, snap in snapshots.items():
        text = getattr(snap, "text", None)
        if not text:
            continue
        lines = text.splitlines()
        for i, line in enumerate(lines, 1):
            for m in fetch_re.finditer(line):
                url = m.group(1)
                has_opts = m.group(2) is not None
                method = "GET"
                if has_opts:
                    # Collect bracket-balanced options block starting from the
                    # position of the opening '{' within `line`.
                    opts_block, _end = _collect_balanced_block(lines, i - 1, m.end() - 1)
                    if opts_block:
                        mm = method_re.search(opts_block)
                        if mm:
                            method = mm.group(1)
                js_fetches.append((url, method, f"{path}:{i}"))
    return js_fetches


def _collect_balanced_block(
    lines: list[str],
    start_line_idx: int,
    start_col: int,
    max_lines: int = 80,
) -> tuple[str, int]:
    """Collect a ``{ ... }``-balanced block starting at ``lines[start_line_idx][start_col]``.

    Returns ``(block_text, last_line_idx)``. If no opening brace at the
    starting position or block not closed within ``max_lines``, returns
    ``("", start_line_idx)``.
    """
    if start_line_idx >= len(lines):
        return "", start_line_idx
    first_line = lines[start_line_idx]
    # Find the opening brace at or after start_col.
    open_pos = first_line.find("{", start_col)
    if open_pos == -1:
        return "", start_line_idx

    depth = 0
    collected: list[str] = []
    end_line = start_line_idx
    in_string: str | None = None  # quote char or None

    for line_idx in range(start_line_idx, min(start_line_idx + max_lines, len(lines))):
        line = lines[line_idx]
        col_start = open_pos if line_idx == start_line_idx else 0
        for col in range(col_start, len(line)):
            ch = line[col]
            if in_string is not None:
                if ch == in_string and line[col - 1: col] != "\\":
                    in_string = None
                continue
            if ch in ("'", '"', "`"):
                in_string = ch
                continue
            if ch == "{":
                depth += 1
            elif ch == "}":
                depth -= 1
                if depth == 0:
                    collected.append(line[col_start: col + 1])
                    return "".join(collected), line_idx
        collected.append(line[col_start:] + "\n")
        end_line = line_idx
    return "".join(collected), end_line


def _check_js_surface_coverage(ctx) -> list[GateFinding]:
    import re as _re
    snapshots = ctx.file_snapshots or {}

    all_js = set()
    for path, snap in snapshots.items():
        if not hasattr(snap, "text") or not snap.text:
            continue
        for m in _re.finditer(r'\b(_?[A-Z][A-Z_0-9]*JS)\b', snap.text):
            name = m.group(1)
            if name.endswith("_JS"):
                all_js.add(name)

    checked = {
        "OPERATOR_JS",
        "OPERATOR_FILES_JS",
        "LAUNCHER_JS",
        "OPERATOR_SSH_JS",
        "BACK_NAV_JS",
        "_SIDEBAR_JS",
    }

    return assess_js_surface_coverage(sorted(all_js), sorted(checked))


# ---------------------------------------------------------------------------
# Cluster 31: Exception Swallowing
# ---------------------------------------------------------------------------


def _check_exception_swallowing(ctx) -> list[GateFinding]:
    snapshots = ctx.file_snapshots or {}
    findings: list[GateFinding] = []
    for path, snap in snapshots.items():
        if not is_source_file(path) or not hasattr(snap, "text") or not snap.text:
            continue
        if get_language_id(path) != "python":
            continue
        findings.extend(assess_exception_swallowing(path, snap.text))
        if len(findings) >= _MAX_FINDINGS_PER_CLUSTER:
            break
    return findings
