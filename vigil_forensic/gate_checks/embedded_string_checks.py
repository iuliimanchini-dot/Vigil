"""Forensic check: detect Python/JS escape conflicts in embedded code strings.

When JavaScript or CSS lives inside Python triple-quoted strings (*_js.py,
*_css.py, *_assets*.py), Python interprets \\n as literal newline. Inside a
JS single-quoted string literal, a literal newline is a syntax error that
kills the entire <script> block silently.

This check scans touched *_js.py / *_css.py / *_assets*.py files for
unescaped \\n/\\t/\\r inside JS string literals (single or double quoted).
"""
from __future__ import annotations

import re

from vigil_forensic._shared import EvidenceReference, GateCategory, GateImpact, GateSeverity
from vigil_forensic.gate_models import PostExecGateContext
from .common import build_check_result, build_finding, iter_touched_snapshots
from ..source_analysis import is_source_file
import logging
_log = logging.getLogger(__name__)

# Matches: '...\n...' or "...\n..." inside Python triple-quoted strings
# that will render as literal newlines in JS.
# We look for single-char \n \t \r that are NOT preceded by another backslash.
# Pattern: a line containing a JS string with unescaped newline-producing escape.
_JS_FILE_PATTERNS = ("_js.py", "_css.py", "_assets")

# Inside a Python """...""", these are literal control chars:
#   '\n' -> actual newline (JS syntax error in string literal)
#   '\t' -> actual tab (usually OK but suspicious)
#   '\r' -> actual CR (JS syntax error in string literal)
# We detect: a quote, then content with a real newline before closing quote.
# Simpler approach: find lines with orphaned quotes (string opened but not closed on same line)
# inside files that embed JS.

# Even simpler: scan for the pattern that caused the real bug:
# Python source has 'something\nsomething' (without raw prefix or double-backslash)
# which renders as a literal newline inside JS.
_DANGEROUS_ESCAPE_RE = re.compile(
    r"""(?<![\\])\\n(?![\\])"""  # \n not preceded or followed by another backslash
)


def run_embedded_string_checks(ctx: PostExecGateContext):
    """Scan *_js.py / *_css.py for Python escape sequences that break embedded JS/CSS."""
    findings = []
    for snapshot in iter_touched_snapshots(ctx):
        if not snapshot.exists:
            continue
        if not any(pat in snapshot.path for pat in _JS_FILE_PATTERNS):
            continue
        if not is_source_file(snapshot.path):
            continue

        # We need to check the PYTHON SOURCE, not the rendered output.
        # Look for lines inside triple-quoted strings that contain
        # single-backslash \n which Python will turn into a literal newline.
        # The tricky part: we're reading the file as Python source.
        lines = snapshot.text.splitlines()
        in_triple = False
        triple_char = ""
        for line_idx, line in enumerate(lines, 1):
            # Track triple-quote state (simplified — enough for _js.py files)
            count_triple_dq = line.count('"""')
            count_triple_sq = line.count("'''")
            if count_triple_dq % 2 == 1:
                in_triple = not in_triple
                triple_char = '"'
            if count_triple_sq % 2 == 1:
                in_triple = not in_triple
                triple_char = "'"

            if not in_triple:
                continue

            # Inside a triple-quoted string: look for JS string literals
            # containing \n that Python will interpret as literal newline.
            # In the Python source, this looks like: split('\n')
            # The \n here is a real newline in the output.
            # We want to find: quote + backslash-n + quote patterns
            # that are NOT \\n (escaped backslash).
            for m in re.finditer(r"""(?:['"]).*?(?<!\\)\\n.*?(?:['"])""", line):
                # Check it's not \\n (double backslash)
                match_text = m.group()
                if "\\\\n" in match_text:
                    continue  # properly escaped
                findings.append(
                    build_finding(
                        check_id="embedded_string.unescaped_newline",
                        category=GateCategory.FALLBACK,
                        title=f"Unescaped \\n in JS/CSS string: {snapshot.path}:{line_idx}",
                        severity=GateSeverity.HIGH,
                        impact=GateImpact.REVISE,
                        summary=(
                            f"File {snapshot.path} line {line_idx} contains '\\n' inside a "
                            "Python triple-quoted string that embeds JS/CSS. Python renders "
                            "this as a literal newline, which is a JS syntax error inside "
                            "string literals. The entire <script> block will fail to parse."
                        ),
                        recommendation=(
                            "Use '\\\\n' (double backslash) so Python outputs '\\n' which "
                            "JS interprets as a newline escape. Or use a raw string r'...'."
                        ),
                        evidence=[
                            EvidenceReference(
                                kind="file",
                                path=snapshot.path,
                                detail=f"line:{line_idx} match:{match_text[:60]}",
                            )
                        ],
                    
                        repair_kind='refactor',
                        executor_action='Address finding details',
                        proof_required='No embedded strings',
                        allowlist_allowed=False,
                    )
                )

    return build_check_result(
        check_id="embedded_string",
        category=GateCategory.FALLBACK,
        findings=findings,
    )
