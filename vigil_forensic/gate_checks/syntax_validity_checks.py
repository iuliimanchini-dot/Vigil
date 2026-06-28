from __future__ import annotations

import ast

from vigil_forensic._shared import EvidenceReference, GateCategory, GateImpact, GateSeverity, RepairKind
from vigil_forensic.gate_models import PostExecGateContext
from ..source_analysis import get_language_id, is_source_file
from .common import build_check_result, build_finding, iter_touched_snapshots
import logging
_log = logging.getLogger(__name__)


def _find_brace_imbalance(text: str) -> tuple[int, str] | None:
    """Return ``(line_number, reason)`` for a brace/bracket/paren imbalance.

    Lightweight textual check for non-Python sources. Tracks ``() [] {}`` but
    respects string literals (`'` `"` backtick) and ``//`` / ``#`` /
    ``/* ... */`` comments. This is intentionally conservative: when in
    doubt it returns ``None`` (no finding) rather than a speculative FP.
    """
    depth_paren = 0
    depth_bracket = 0
    depth_brace = 0

    in_line_comment = False
    in_block_comment = False
    in_string: str | None = None
    string_start_line = 0
    lineno = 1
    last_open: list[tuple[str, int]] = []

    i = 0
    n = len(text)
    while i < n:
        ch = text[i]
        nxt = text[i + 1] if i + 1 < n else ""

        if ch == "\n":
            lineno += 1
            in_line_comment = False
            i += 1
            continue

        if in_line_comment:
            i += 1
            continue

        if in_block_comment:
            if ch == "*" and nxt == "/":
                in_block_comment = False
                i += 2
                continue
            i += 1
            continue

        if in_string is not None:
            if ch == "\\":
                i += 2  # skip escaped char
                continue
            if ch == in_string:
                in_string = None
            i += 1
            continue

        # Not in string/comment.
        if ch == "/" and nxt == "/":
            in_line_comment = True
            i += 2
            continue
        if ch == "/" and nxt == "*":
            in_block_comment = True
            i += 2
            continue
        if ch == "#":
            # Only treat '#' as a line comment for shell-ish / generic sources;
            # harmless for JS because it's never a valid operator start.
            in_line_comment = True
            i += 1
            continue
        if ch in ("'", '"', "`"):
            in_string = ch
            string_start_line = lineno
            i += 1
            continue

        if ch == "(":
            depth_paren += 1
            last_open.append(("(", lineno))
        elif ch == ")":
            depth_paren -= 1
            if depth_paren < 0:
                return lineno, "unmatched ')'"
            if last_open and last_open[-1][0] == "(":
                last_open.pop()
        elif ch == "[":
            depth_bracket += 1
            last_open.append(("[", lineno))
        elif ch == "]":
            depth_bracket -= 1
            if depth_bracket < 0:
                return lineno, "unmatched ']'"
            if last_open and last_open[-1][0] == "[":
                last_open.pop()
        elif ch == "{":
            depth_brace += 1
            last_open.append(("{", lineno))
        elif ch == "}":
            depth_brace -= 1
            if depth_brace < 0:
                return lineno, "unmatched '}'"
            if last_open and last_open[-1][0] == "{":
                last_open.pop()

        i += 1

    if in_string is not None:
        return string_start_line, f"unclosed string literal (opened line {string_start_line})"
    if in_block_comment:
        return lineno, "unclosed block comment"
    if depth_paren or depth_bracket or depth_brace:
        if last_open:
            br, ln = last_open[-1]
            return ln, f"unclosed '{br}' (opened line {ln})"
        return lineno, "bracket depth nonzero at EOF"
    return None


# Languages for which we apply the Python ``ast.parse`` check. Every other
# source language uses the textual balanced-brace fallback below -- we never
# try to parse non-Python as Python (F12c fix: same category of bug as the
# F9a Python-only branch).
_PYTHON_LANGUAGE_IDS: frozenset[str] = frozenset({"python"})

# Languages for which a textual brace/bracket/paren balance check is a useful
# heuristic. Shell/PowerShell/Go-style sources are NOT listed because their
# syntax differs enough that brace balance isn't a reliable signal.
_BRACE_LANGUAGE_IDS: frozenset[str] = frozenset({
    "javascript", "typescript",
    "java", "kotlin", "scala",
    "cpp", "c", "csharp",
    "rust",
    "json",
})


def run_syntax_validity_checks(ctx: PostExecGateContext):
    """Check that touched source files parse / balance correctly.

    Language dispatch:
        Python                    -> ``ast.parse()``
        JS / TS / Java / C / ...  -> textual brace/paren balance only
        Shell / PS1 / Go / ...    -> skipped (no reliable lightweight check)

    Never attempts to parse a non-Python file as Python -- that was the F12c
    bug (100% FP on ``.ts``/``.tsx``/``.jsx``/``.go`` snapshots).
    """
    findings = []
    for snapshot in iter_touched_snapshots(ctx):
        if not snapshot.exists or not is_source_file(snapshot.path):
            continue
        if not snapshot.text.strip():
            continue  # empty files are handled by empty_output_checks

        lang = get_language_id(snapshot.path)

        if lang in _PYTHON_LANGUAGE_IDS:
            try:
                ast.parse(snapshot.text, filename=snapshot.path)
            except SyntaxError as exc:
                line_info = f"line {exc.lineno}" if exc.lineno else "unknown line"
                findings.append(
                    build_finding(
                        check_id="syntax_validity.parse_error",
                        category=GateCategory.REPORTING,
                        title=f"SyntaxError in {snapshot.path} ({line_info})",
                        severity=GateSeverity.HIGH,
                        impact=GateImpact.REVISE,
                        summary=(
                            f"File {snapshot.path} contains invalid Python syntax at {line_info}: "
                            f"{str(exc.msg)[:200]}. This will cause ImportError at runtime."
                        ),
                        recommendation="Fix the syntax error before accepting the executor result.",
                        evidence=[EvidenceReference(kind="file", path=snapshot.path, detail=f"SyntaxError:{line_info}")],
                        repair_kind=RepairKind.FIX_CONTRACT.value,
                        executor_action="Fix syntax error",
                        proof_required="Valid syntax",
                        allowlist_allowed=False,
                    )
                )
        elif lang in _BRACE_LANGUAGE_IDS:
            imbalance = _find_brace_imbalance(snapshot.text)
            if imbalance is not None:
                line_no, reason = imbalance
                findings.append(
                    build_finding(
                        check_id="syntax_validity.parse_error",
                        category=GateCategory.REPORTING,
                        title=f"Brace/bracket imbalance in {snapshot.path} (line {line_no})",
                        severity=GateSeverity.HIGH,
                        impact=GateImpact.REVISE,
                        summary=(
                            f"File {snapshot.path} has {reason} at line {line_no}. "
                            "Lightweight textual check -- fix the imbalance."
                        ),
                        recommendation="Close the unmatched bracket or remove the stray one.",
                        evidence=[EvidenceReference(kind="file", path=snapshot.path, detail=f"imbalance:{reason}")],
                        repair_kind=RepairKind.FIX_CONTRACT.value,
                        executor_action="Fix bracket imbalance",
                        proof_required="Balanced brackets",
                        allowlist_allowed=False,
                    )
                )
        # else: language without a lightweight check (shell, powershell, go, ...)
        # -- emit 0 findings rather than 100% FP. Real syntax errors surface
        # via the language's own tooling.

    return build_check_result(check_id="syntax_validity", category=GateCategory.REPORTING, findings=findings)
