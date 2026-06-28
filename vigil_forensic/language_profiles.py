"""Per-language forensics metadata for autoforensics analysis.

Provides frozen LanguageProfile dataclasses that carry forensics-relevant
metadata (test patterns, generic stems, flow markers, etc.) for each supported
language.  These profiles are NOT concerned with structural map-building —
for that, see source_adapters.  Profiles complement source_adapters by
covering the forensic/analytical layer.

Public API:
    LanguageProfile              -- frozen dataclass with per-language metadata
    PYTHON_PROFILE               -- Python profile
    JAVASCRIPT_PROFILE           -- JavaScript profile
    TYPESCRIPT_PROFILE           -- TypeScript profile
    GO_PROFILE                   -- Go profile
    JAVA_PROFILE                 -- Java profile
    get_profile_for_extension    -- lookup by file extension (e.g. ".py")
    get_profile_for_lang         -- lookup by language_id (e.g. "python")
"""
from __future__ import annotations

from dataclasses import dataclass, field
import logging
_log = logging.getLogger(__name__)


@dataclass(frozen=True)
class LanguageProfile:
    """Forensics metadata for a single programming language.

    Attributes:
        language_id:                    Canonical language identifier (e.g. "python").
        source_extensions:              File extensions belonging to this language.
        test_file_patterns:             Prefix/suffix patterns for test file detection.
        generic_helper_stems:           Stems commonly used for utility/helper modules.
        shared_layer_families:          Canonical shared-layer module name families.
        flow_marker_patterns:           Regex patterns identifying orchestration steps.
        comment_line_prefixes:          Comment start sequences (e.g. "#", "//").
        function_extraction_supported:  True when AST-based extraction is available.
        exclude_dir_hints:              Vendor/generated directories to skip during analysis.
    """

    language_id: str
    source_extensions: frozenset[str]
    test_file_patterns: tuple[str, ...]
    generic_helper_stems: frozenset[str]
    shared_layer_families: frozenset[str]
    flow_marker_patterns: tuple[str, ...]
    comment_line_prefixes: tuple[str, ...]
    function_extraction_supported: bool
    exclude_dir_hints: frozenset[str]


# ---------------------------------------------------------------------------
# Profiles
# ---------------------------------------------------------------------------

PYTHON_PROFILE = LanguageProfile(
    language_id="python",
    source_extensions=frozenset({".py"}),
    test_file_patterns=("test_", "_test.py"),
    generic_helper_stems=frozenset({
        "utils", "helpers", "common", "shared", "misc",
        "tools", "util", "helper", "support", "base",
    }),
    shared_layer_families=frozenset({
        "shared", "utils", "common", "helpers", "base", "lib", "core",
    }),
    flow_marker_patterns=(
        r"def build_",
        r"def create_",
        r"def run_",
        r"def execute_",
        r"subprocess",
        r"json\.loads",
        r"json\.dumps",
    ),
    comment_line_prefixes=("#",),
    function_extraction_supported=True,
    exclude_dir_hints=frozenset({
        "__pycache__", ".venv", "venv", "node_modules", "libs",
        ".git", "migrations", "__generated__", "dist", "build",
    }),
)

JAVASCRIPT_PROFILE = LanguageProfile(
    language_id="javascript",
    source_extensions=frozenset({".js", ".mjs", ".cjs"}),
    test_file_patterns=(".test.js", ".spec.js", "__tests__/"),
    generic_helper_stems=frozenset({
        "utils", "helpers", "common", "shared", "base",
        "lib", "index", "constants",
    }),
    shared_layer_families=frozenset({
        "shared", "utils", "common", "helpers", "base",
        "lib", "core", "services",
    }),
    flow_marker_patterns=(
        r"function build",
        r"function create",
        r"async function",
        r"fetch\(",
        r"JSON\.parse",
        r"JSON\.stringify",
    ),
    comment_line_prefixes=("//", "/*"),
    function_extraction_supported=False,
    exclude_dir_hints=frozenset({
        "node_modules", "dist", "build", ".cache",
        "coverage", "__generated__",
    }),
)

TYPESCRIPT_PROFILE = LanguageProfile(
    language_id="typescript",
    source_extensions=frozenset({".ts", ".tsx"}),
    test_file_patterns=(".test.ts", ".spec.ts", "__tests__/"),
    # Inherit generic_helper_stems, shared_layer_families, flow_marker_patterns,
    # comment_line_prefixes, function_extraction_supported, exclude_dir_hints
    # from JAVASCRIPT_PROFILE — TypeScript is a strict superset for forensics purposes.
    generic_helper_stems=JAVASCRIPT_PROFILE.generic_helper_stems,
    shared_layer_families=JAVASCRIPT_PROFILE.shared_layer_families,
    flow_marker_patterns=JAVASCRIPT_PROFILE.flow_marker_patterns,
    comment_line_prefixes=JAVASCRIPT_PROFILE.comment_line_prefixes,
    function_extraction_supported=False,
    exclude_dir_hints=JAVASCRIPT_PROFILE.exclude_dir_hints,
)

GO_PROFILE = LanguageProfile(
    language_id="go",
    source_extensions=frozenset({".go"}),
    test_file_patterns=("_test.go",),
    generic_helper_stems=frozenset({
        "utils", "helpers", "common", "internal", "util",
    }),
    shared_layer_families=frozenset({
        "internal", "common", "shared", "helpers", "util",
    }),
    flow_marker_patterns=(
        r"func Build",
        r"func Create",
        r"func Run",
        r"func Execute",
    ),
    comment_line_prefixes=("//",),
    function_extraction_supported=False,
    exclude_dir_hints=frozenset({
        "vendor", "testdata", "node_modules",
    }),
)

JAVA_PROFILE = LanguageProfile(
    language_id="java",
    source_extensions=frozenset({".java"}),
    test_file_patterns=("Test.java", "Tests.java", "/test/"),
    generic_helper_stems=frozenset({
        "Utils", "Helper", "Common", "Shared", "Base",
        "Util", "Helpers",
    }),
    shared_layer_families=frozenset({
        "utils", "common", "shared", "base", "helper",
    }),
    flow_marker_patterns=(
        r"void build",
        r"void create",
        r"void run",
        r"void execute",
        r"new ObjectMapper\(",
        r"objectMapper\.",
    ),
    comment_line_prefixes=("//", "/*"),
    function_extraction_supported=False,
    exclude_dir_hints=frozenset({
        "target", "build", ".gradle", "node_modules", "generated",
    }),
)

# ---------------------------------------------------------------------------
# Lookup indices
# ---------------------------------------------------------------------------

_PROFILES_BY_EXTENSION: dict[str, LanguageProfile] = {
    ext: profile
    for profile in [
        PYTHON_PROFILE,
        JAVASCRIPT_PROFILE,
        TYPESCRIPT_PROFILE,
        GO_PROFILE,
        JAVA_PROFILE,
    ]
    for ext in profile.source_extensions
}

_PROFILES_BY_LANG: dict[str, LanguageProfile] = {
    p.language_id: p
    for p in [
        PYTHON_PROFILE,
        JAVASCRIPT_PROFILE,
        TYPESCRIPT_PROFILE,
        GO_PROFILE,
        JAVA_PROFILE,
    ]
}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def get_profile_for_extension(ext: str) -> LanguageProfile | None:
    """Return the LanguageProfile for *ext* (e.g. ``".py"``), or None.

    Lookup is case-insensitive: ``".PY"`` resolves to the same profile as ``".py"``.
    """
    return _PROFILES_BY_EXTENSION.get(ext.lower())


def get_profile_for_lang(lang_id: str) -> LanguageProfile | None:
    """Return the LanguageProfile for *lang_id* (e.g. ``"python"``), or None."""
    return _PROFILES_BY_LANG.get(lang_id)
