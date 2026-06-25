"""Refactor completeness forensic gate.

refactor.partial_rename: detect AI artifact where a symbol was renamed in some
files but the old name persists in others — i.e. an incomplete rename.

Detection approach (v1 — static, no git history required):
  1. Walk all touched .py files, extract public function/class names via AST.
  2. For every pair of names across different files, compute Levenshtein distance.
  3. If distance <= 2 and the names are not identical, emit a
     refactor.partial_rename_candidate finding (MEDIUM / WARN).

Fails open: AST/IO errors -> skip file, never crash.
Allowlist supported: similar names can be legitimate (overloads, aliases).
"""
from __future__ import annotations

import ast
import logging

from cortex_forensic._shared import (
    EvidenceReference,
    GateCategory,
    GateImpact,
    GateSeverity,
    RepairKind,
)
from cortex_forensic.gate_models import PostExecGateContext
from ..source_analysis import is_source_file
from .common import build_check_result, build_finding, normalize_path
from ._ast_helpers import parse_python_source_or_emit_finding

import re

_log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# FP-mitigation constants
# ---------------------------------------------------------------------------

# Names shorter than this are too generic to flag as partial renames.
_MIN_NAME_LENGTH = 6

# Levenshtein ratio floor: if edit_distance / max(len_a, len_b) > this, names
# are not similar enough to warrant a finding.
_MAX_SIMILARITY_RATIO = 0.3

# O(n²) guard: if total public names across all touched files exceeds this,
# sample only the first N names and emit a note.
_MAX_TOTAL_NAMES = 200

# Hard cap on emitted findings per run.
_MAX_FINDINGS = 20

# Pattern matching intentional versioned names like MyClass_v1 / MyClass_v2.
_VERSION_SUFFIX_RE = re.compile(r"_v\d+$")


# ---------------------------------------------------------------------------
# Levenshtein distance (stdlib-only, no external deps)
# ---------------------------------------------------------------------------

def _levenshtein(a: str, b: str) -> int:
    """Return the Levenshtein edit distance between *a* and *b*."""
    if a == b:
        return 0
    m, n = len(a), len(b)
    if m < n:
        a, b, m, n = b, a, n, m
    # Single-row DP.
    prev = list(range(n + 1))
    for i in range(1, m + 1):
        curr = [i] + [0] * n
        for j in range(1, n + 1):
            cost = 0 if a[i - 1] == b[j - 1] else 1
            curr[j] = min(
                prev[j] + 1,       # deletion
                curr[j - 1] + 1,   # insertion
                prev[j - 1] + cost,  # substitution
            )
        prev = curr
    return prev[n]


# ---------------------------------------------------------------------------
# AST helper: extract public top-level names
# ---------------------------------------------------------------------------

def _extract_public_names(
    content: str,
    *,
    rel_path: str = "",
    emit_finding=None,
) -> list[str]:
    """Return public (non-dunder, non-private) function and class names at
    module or class level from *content*.

    B4 (2026-04-23): on SyntaxError, emit ``meta.syntax_parse_error`` via the
    shared helper (if ``emit_finding`` supplied) instead of silently returning
    ``[]``.
    """
    tree = parse_python_source_or_emit_finding(
        content,
        rel_path=rel_path,
        emit_finding=emit_finding,
        emitting_gate="refactor_completeness",
    )
    if tree is None:
        return []

    names: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            name: str = node.name
            if not name.startswith("_"):
                names.append(name)
    return names


# ---------------------------------------------------------------------------
# Main gate runner
# ---------------------------------------------------------------------------

def run_refactor_completeness_checks(ctx: PostExecGateContext):
    """Detect partial renames across touched .py files.

    For each pair of public names (name_a from file_a, name_b from file_b):
      - Skip identical names.
      - If Levenshtein(name_a, name_b) <= 2: emit MEDIUM / WARN finding.

    The check operates on ctx.touched_files (not ctx.changed_files_observed)
    so it works even without git diff context.
    """
    findings = []

    # Build map: normalized_path -> list[public_name]
    file_names: dict[str, list[str]] = {}

    for raw_path in ctx.touched_files:
        normalized = normalize_path(raw_path)
        if not is_source_file(normalized):
            continue
        abs_path = ctx.project_dir / normalized
        try:
            content = abs_path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError) as exc:
            _log.debug("refactor_completeness: cannot read %s: %s", normalized, exc)
            continue
        public_names = _extract_public_names(
            content,
            rel_path=normalized,
            emit_finding=findings.append,
        )
        if public_names:
            file_names[normalized] = public_names

    # O(n²) guard: cap total public names to avoid quadratic blowup.
    total_names = sum(len(v) for v in file_names.values())
    _partial_scan = total_names > _MAX_TOTAL_NAMES
    if _partial_scan:
        _log.debug(
            "refactor_completeness: total public names %d > %d cap; "
            "partial scan — tune threshold if needed",
            total_names,
            _MAX_TOTAL_NAMES,
        )
        # Truncate each file's name list proportionally by capping the flat list.
        truncated: dict[str, list[str]] = {}
        remaining = _MAX_TOTAL_NAMES
        for p, names in file_names.items():
            take = min(len(names), remaining)
            if take <= 0:
                break
            truncated[p] = names[:take]
            remaining -= take
        file_names = truncated

    # Deduplicate pairs: only emit once per (name_a, name_b) pair regardless
    # of how many files contain either name.
    seen_pairs: set[frozenset[str]] = set()

    paths = list(file_names.keys())
    for i, path_a in enumerate(paths):
        for path_b in paths[i + 1:]:
            for name_a in file_names[path_a]:
                for name_b in file_names[path_b]:
                    if name_a == name_b:
                        continue

                    # FP filter 1: names too short to be meaningful.
                    if len(name_a) < _MIN_NAME_LENGTH or len(name_b) < _MIN_NAME_LENGTH:
                        continue

                    # FP filter 2: plural-singular pairs (name_b == name_a + "s" or vice versa).
                    if name_b == name_a + "s" or name_a == name_b + "s":
                        continue

                    # FP filter 3: intentional versioning suffix (X_v1 vs X_v2).
                    base_a = _VERSION_SUFFIX_RE.sub("", name_a)
                    base_b = _VERSION_SUFFIX_RE.sub("", name_b)
                    if base_a == base_b:
                        continue

                    pair_key = frozenset({name_a, name_b})
                    if pair_key in seen_pairs:
                        continue

                    dist = _levenshtein(name_a, name_b)

                    # FP filter 4: similarity ratio gate.
                    ratio = dist / max(len(name_a), len(name_b))
                    if ratio > _MAX_SIMILARITY_RATIO:
                        continue

                    if dist <= 2:
                        seen_pairs.add(pair_key)
                        # Hard cap on findings.
                        if len(findings) >= _MAX_FINDINGS:
                            _log.debug(
                                "refactor_completeness: findings capped at %d; "
                                "tune threshold to see more",
                                _MAX_FINDINGS,
                            )
                            break
                        findings.append(
                            build_finding(
                                check_id="refactor.partial_rename_candidate",
                                category=GateCategory.DRIFT,
                                title=(
                                    f"Possible partial rename: '{name_a}' vs '{name_b}'"
                                ),
                                severity=GateSeverity.MEDIUM,
                                impact=GateImpact.WARN,
                                summary=(
                                    f"Name '{name_a}' in {path_a} and '{name_b}' in {path_b} "
                                    f"differ by {dist} edit(s) — possible incomplete rename."
                                ),
                                recommendation=(
                                    f"Unify naming: '{name_a}' vs '{name_b}' in "
                                    f"{path_a} vs {path_b}. "
                                    f"Decide the canonical name and propagate it to all call sites. "
                                    f"If the similarity is intentional (overload, alias), add both "
                                    f"names to the allowlist."
                                ),
                                evidence=[
                                    EvidenceReference(
                                        kind="file",
                                        path=path_a,
                                        detail=f"name '{name_a}'",
                                    ),
                                    EvidenceReference(
                                        kind="file",
                                        path=path_b,
                                        detail=f"name '{name_b}'",
                                    ),
                                ],
                                repair_kind=RepairKind.NORMALIZE_SHAPE.value,
                                executor_action=(
                                    f"Unify naming: '{name_a}' vs '{name_b}' in "
                                    f"{path_a} vs {path_b}. "
                                    f"Decide canonical name and propagate."
                                ),
                                proof_required=(
                                    "grep for old name returns 0 matches; "
                                    "all callers use canonical name"
                                ),
                                allowlist_allowed=True,
                            )
                        )

    return build_check_result(
        check_id="refactor_completeness",
        category=GateCategory.DRIFT,
        findings=findings,
    )
