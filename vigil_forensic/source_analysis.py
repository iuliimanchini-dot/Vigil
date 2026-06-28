"""Shared source analysis facade for vigil_forensic.

Adapted from the Vigil autoforensics source_analysis.
Key change: uses vigil_mapper.source_adapters (sibling standalone pkg)
instead of the Vigil autoforensics map_builder.source_adapters.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

from vigil_forensic.language_profiles import get_profile_for_extension
from vigil_mapper.source_adapters import get_adapter_for_file
import logging
_log = logging.getLogger(__name__)

__all__ = [
    "FunctionInfo",
    "is_source_file",
    "is_test_file",
    "get_language_id",
    "get_generic_stems",
    "get_shared_families",
    "get_flow_markers",
    "get_exclude_dirs",
    "extract_functions",
]


@dataclass(frozen=True)
class FunctionInfo:
    """Lightweight descriptor for a function-like region in a source file."""
    name: str
    start_line: int
    end_line: int
    line_count: int
    is_method: bool = False


def is_source_file(path: str) -> bool:
    """True if *path* has a known source extension (via source_adapters)."""
    try:
        return get_adapter_for_file(Path(path)) is not None
    except Exception:
        _log.debug("is_source_file: adapter lookup failed for %r", path)
        return False


def is_test_file(path: str) -> bool:
    """True if *path* matches test file patterns for its language."""
    p = Path(path)
    ext = p.suffix.lower()
    profile = get_profile_for_extension(ext)
    if profile is None:
        return False
    name = p.name
    path_str = path.replace("\\", "/")
    return any(
        name.startswith(pat) or name.endswith(pat) or pat in path_str
        for pat in profile.test_file_patterns
    )


def get_language_id(path: str) -> str | None:
    """Return the language_id for *path*, or None if unsupported."""
    ext = Path(path).suffix.lower()
    profile = get_profile_for_extension(ext)
    return profile.language_id if profile else None


def get_generic_stems(path: str) -> frozenset[str]:
    ext = Path(path).suffix.lower()
    profile = get_profile_for_extension(ext)
    return profile.generic_helper_stems if profile else frozenset()


def get_shared_families(path: str) -> frozenset[str]:
    ext = Path(path).suffix.lower()
    profile = get_profile_for_extension(ext)
    return profile.shared_layer_families if profile else frozenset()


def get_flow_markers(path: str) -> tuple[str, ...]:
    ext = Path(path).suffix.lower()
    profile = get_profile_for_extension(ext)
    return profile.flow_marker_patterns if profile else ()


def get_exclude_dirs(path: str) -> frozenset[str]:
    ext = Path(path).suffix.lower()
    profile = get_profile_for_extension(ext)
    return profile.exclude_dir_hints if profile else frozenset()


def extract_functions(path: str, content: str) -> list[FunctionInfo]:
    """Extract function-like regions from *content*. Never raises; returns [] on error."""
    lang = get_language_id(path)
    if lang == "python":
        return _extract_python_functions(content)
    if lang in ("javascript", "typescript"):
        return _extract_js_functions(content)
    return []


def _extract_python_functions(content: str) -> list[FunctionInfo]:
    try:
        from vigil_forensic.gate_checks.common import extract_python_functions as _ast_extract
        raw = _ast_extract(content)
        return [
            FunctionInfo(name=name, start_line=start, end_line=end, line_count=end - start + 1, is_method=False)
            for name, start, end, snippet in raw
        ]
    except Exception as exc:
        _log.debug("_extract_python_functions failed: %s", exc)
        return []


_JS_FUNCTION_RE = re.compile(
    r"""
    (?:^|\s)
    (?:
        (?:async\s+)?function\s+
        (?P<fn_name>[A-Za-z_$][A-Za-z0-9_$]*)
        \s*\(
    |
        (?P<arrow_name>[A-Za-z_$][A-Za-z0-9_$]*)
        \s*=\s*
        (?:async\s+)?
        \(.*?\)\s*=>
    |
        ^\s*
        (?P<method_name>[A-Za-z_$][A-Za-z0-9_$]*)
        \s*\(
    )
    """,
    re.VERBOSE | re.MULTILINE,
)


def _extract_js_functions(content: str) -> list[FunctionInfo]:
    try:
        lines = content.splitlines()
        results: list[FunctionInfo] = []
        for i, line in enumerate(lines, start=1):
            stripped = line.strip()
            m = re.match(r"(?:async\s+)?function\s+([A-Za-z_$][A-Za-z0-9_$]*)\s*\(", stripped)
            if m:
                name = m.group(1)
                end_line = min(i + 9, len(lines))
                results.append(FunctionInfo(name=name, start_line=i, end_line=end_line, line_count=end_line - i + 1))
                continue
            m = re.match(
                r"(?:const|let|var)\s+([A-Za-z_$][A-Za-z0-9_$]*)\s*=\s*(?:async\s*)?\(.*?\)\s*=>",
                stripped,
            )
            if m:
                name = m.group(1)
                end_line = min(i + 9, len(lines))
                results.append(FunctionInfo(name=name, start_line=i, end_line=end_line, line_count=end_line - i + 1))
                continue
            m = re.match(r"([A-Za-z_$][A-Za-z0-9_$]*)\s*\(", stripped)
            if m and not re.match(
                r"^(?:if|for|while|switch|catch|return|import|export|class|const|let|var)\b", stripped,
            ):
                if line and line[0] in (" ", "\t"):
                    name = m.group(1)
                    end_line = min(i + 9, len(lines))
                    results.append(FunctionInfo(
                        name=name, start_line=i, end_line=end_line,
                        line_count=end_line - i + 1, is_method=True,
                    ))
        return results
    except Exception:
        return []
