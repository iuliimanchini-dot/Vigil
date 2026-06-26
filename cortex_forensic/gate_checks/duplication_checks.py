from __future__ import annotations

import ast
import re

from cortex_forensic._shared import EvidenceReference, GateCategory, GateImpact, GateSeverity, RepairKind
from cortex_forensic.gate_models import PostExecGateContext
from ..source_analysis import is_source_file, is_test_file
from .common import build_check_result, build_finding, extract_python_functions, hash_normalized_code, hash_text_block, iter_touched_snapshots
import logging
_log = logging.getLogger(__name__)

# Bare identifier lines (import continuation: "GateFinding,") — exclude from text block windows
_IMPORT_CONTINUATION_RE = re.compile(r"^[A-Za-z_]\w*,?$")

# Pure parameter-declaration / call-argument continuation lines, e.g.
#   ``timeout: float = 0.05,``  ``poll_interval=poll_interval,``  ``arg0=None,``
# A long signature or call mirrored across sync/async APIs is structure, not
# copy-pasted logic — exclude these lines from the text-block window so the
# detector does not fire on shared parameter lists.
_PARAM_DECL_RE = re.compile(
    r"^\*{0,2}[A-Za-z_]\w*\s*(?::\s*[^=]+?)?(?:=\s*[^,]+?)?,?$"
)


def _string_literal_lines(text: str) -> frozenset[int]:
    """Return the set of 1-based line numbers that lie inside a string literal.

    Covers docstrings and any multi-line string constant. Used to exclude
    docstring / long-string content from the text-block duplication window:
    shared docstrings (e.g. identical ``:param`` blocks on sync/async API
    mirrors) are documentation, not duplicated CODE.

    Python only. Returns an empty set on SyntaxError (fail-open) — non-Python
    files keep their previous behavior.
    """
    try:
        tree = ast.parse(text)
    except (SyntaxError, ValueError):
        return frozenset()
    lines: set[int] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            start = getattr(node, "lineno", None)
            end = getattr(node, "end_lineno", None) or start
            if start is None:
                continue
            lines.update(range(start, end + 1))
    return frozenset(lines)

_MAX_DUPLICATION_CHECK_FILES = 200  # Prevent rglob on massive projects

_BOILERPLATE_FUNCTION_NAMES = frozenset({
    "to_dict", "from_dict", "from_mapping", "__init__", "__repr__", "__str__",
    "__eq__", "__hash__", "__post_init__", "_now", "to_json", "from_json",
})


def _extract_snippets(path: str, text: str) -> list[tuple[str, int, int, str]]:
    """Return (name, start, end, snippet) for all function-like regions.

    Python: AST-based (exact). JS/TS: regex-based (heuristic). Others: empty.
    """
    from ..source_analysis import extract_functions, get_language_id
    lang = get_language_id(path)
    if lang == "python":
        return extract_python_functions(text)
    fns = extract_functions(path, text)
    if not fns:
        return []
    lines = text.splitlines()
    return [
        (fi.name, fi.start_line, fi.end_line,
         "\n".join(lines[fi.start_line - 1:fi.end_line]))
        for fi in fns
    ]


def run_duplication_checks(ctx: PostExecGateContext):
    findings = []
    profile = ctx.repo_profile
    touched_hashes: dict[str, list[tuple[str, str]]] = {}
    for snapshot in iter_touched_snapshots(ctx):
        if not snapshot.exists or not is_source_file(snapshot.path):
            continue
        if is_test_file(snapshot.path):
            continue
        for func_name, start, end, snippet in _extract_snippets(snapshot.path, snapshot.text):
            if end - start < 3:
                continue
            if func_name in _BOILERPLATE_FUNCTION_NAMES:
                continue
            touched_hashes.setdefault(hash_normalized_code(snippet), []).append((snapshot.path, func_name))
    # cross_touched_duplicate is designed for incremental AI edits (2-20 files).
    # In a full-scan (self-audit), touched_files == all source files, so every
    # pair of structurally-similar helpers cross-matches — meaningless noise.
    #
    # Full-scan detection: explicit flag OR (large touched set that equals all
    # known snapshots — at least 10 files so genuine 2-20 file incremental
    # changes are never mis-classified as full scans).
    _MIN_FULL_SCAN_FILES = 10
    _is_full_scan = getattr(ctx, "is_full_scan", False) or (
        len(ctx.touched_files) >= _MIN_FULL_SCAN_FILES
        and set(ctx.touched_files) >= set(ctx.file_snapshots.keys())
    )
    if _is_full_scan:
        touched_hashes.clear()

    seen_pairs: set[tuple[str, str, str, str]] = set()
    file_count = 0
    for path in (ctx.project_dir.rglob("*") if touched_hashes else ()):
        if file_count > _MAX_DUPLICATION_CHECK_FILES:
            _log.warning(
                "duplication_checks: rglob limit exceeded (%d > %d), stopping early",
                file_count, _MAX_DUPLICATION_CHECK_FILES,
            )
            break
        file_count += 1
        if not path.is_file():
            continue
        repo_path = str(path.relative_to(ctx.project_dir)).replace("\\", "/")
        if not is_source_file(repo_path):
            continue
        if profile and profile.is_generated_or_vendored(repo_path):
            continue
        if repo_path in ctx.touched_files:
            continue
        if is_test_file(repo_path):
            continue
        text = path.read_text(encoding="utf-8", errors="replace")
        for func_name, start, end, snippet in _extract_snippets(repo_path, text):
            if end - start < 3:
                continue
            if func_name in _BOILERPLATE_FUNCTION_NAMES:
                continue
            hashed = hash_normalized_code(snippet)
            matches = touched_hashes.get(hashed) or []
            if not matches:
                continue
            for match_path, match_name in matches:
                pair = (match_path, match_name, repo_path, func_name)
                if pair in seen_pairs:
                    continue
                seen_pairs.add(pair)
                findings.append(
                    build_finding(
                        check_id="duplication.normalized_function",
                        category=GateCategory.DUPLICATION,
                        title="Touched code duplicates existing logic under a different location",
                        severity=GateSeverity.HIGH,
                        impact=GateImpact.REVISE,
                        summary=f"{match_path}::{match_name} is near-duplicate of {repo_path}::{func_name}.",
                        recommendation=(
                            "Remove the duplicate and import the canonical implementation directly. "
                            "If both locations need minor variations, add a parameter to the canonical function "
                            "rather than forking a copy."
                        ),
                        evidence=[
                            EvidenceReference(kind="file", path=match_path, detail=match_name),
                            EvidenceReference(kind="file", path=repo_path, detail=func_name),
                        ],
                        repair_kind=RepairKind.REMOVE_DUPLICATE.value,
                        executor_action=f"Remove {match_path}::{match_name} — near-duplicate of {repo_path}::{func_name}; import canonical instead",
                        proof_required="duplicate removed; original passes existing tests",
                        allowlist_allowed=False,
                    )
                )
    for locations in touched_hashes.values():
        if len(locations) < 2:
            continue
        for i in range(len(locations)):
            for j in range(i + 1, len(locations)):
                path_a, name_a = locations[i]
                path_b, name_b = locations[j]
                pair = (path_a, name_a, path_b, name_b)
                if pair in seen_pairs:
                    continue
                seen_pairs.add(pair)
                findings.append(
                    build_finding(
                        check_id="duplication.cross_touched_duplicate",
                        category=GateCategory.DUPLICATION,
                        title="Two newly-touched files contain duplicate function implementations",
                        severity=GateSeverity.HIGH,
                        impact=GateImpact.REVISE,
                        summary=f"{path_a}::{name_a} is a near-duplicate of {path_b}::{name_b} -- both were touched in this change.",
                        recommendation=(
                            "Consolidate into one canonical implementation. "
                            "Move it to `<package>/shared.py` or `<package>/utils.py` if both files are in the same package, "
                            "or to a common cross-package helper module. "
                            "Replace both copies with an import."
                        ),
                        evidence=[
                            EvidenceReference(kind="file", path=path_a, detail=name_a),
                            EvidenceReference(kind="file", path=path_b, detail=name_b),
                        ],
                        repair_kind=RepairKind.EXTRACT_SHARED.value,
                        executor_action=f"Extract shared impl from {path_a}::{name_a} and {path_b}::{name_b} into canonical module; replace both with import",
                        proof_required="one canonical impl; both callers import it; tests pass",
                        allowlist_allowed=False,
                    )
                )
    # ── Phase 2: Universal text block duplication ──
    # Catches repeated HTML/CSS/JS/config blocks across files — not just Python functions.
    # Works by hashing sliding windows of N consecutive non-empty lines.
    _BLOCK_MIN_LINES = 12
    _BLOCK_IGNORE_PREFIXES = ("#", "//", "/*", "*", "import ", "from ", '"""', "'''", "assert ", "return ")
    _SKIP_DIRS = (".vendor", "node_modules", "migrations", "__generated__", "__pycache__", "gate_checks")
    block_hashes: dict[str, list[tuple[str, int]]] = {}  # hash -> [(file, start_line), ...]

    _MAX_TEXT_BLOCK_FINDINGS = 50
    _text_block_count = 0

    for snapshot in iter_touched_snapshots(ctx):
        if not snapshot.exists or not snapshot.text:
            continue
        # Skip test files — they naturally have repetitive assertion patterns
        norm_path = snapshot.path.replace("\\", "/")
        if norm_path.split("/")[-1].startswith("test_"):
            continue
        # Skip vendored/generated directories
        if any(f"/{d}/" in f"/{norm_path}/" for d in _SKIP_DIRS):
            continue
        lines = snapshot.text.splitlines()
        # Lines that sit inside a string literal (docstrings, long multi-line
        # strings). Shared docstrings / :param blocks across sync/async API
        # mirrors are documentation, not duplicated CODE — exclude them.
        docstring_lines = (
            _string_literal_lines(snapshot.text)
            if is_source_file(snapshot.path) and snapshot.path.endswith(".py")
            else frozenset()
        )
        # Filter to meaningful lines (skip empty, comments, imports, docstrings,
        # and pure parameter-declaration / argument-continuation lines).
        meaningful: list[tuple[int, str]] = []
        for i, line in enumerate(lines):
            line_no = i + 1
            if line_no in docstring_lines:
                continue
            stripped = line.strip()
            if not stripped:
                continue
            if any(stripped.startswith(p) for p in _BLOCK_IGNORE_PREFIXES):
                continue
            if _IMPORT_CONTINUATION_RE.match(stripped):
                continue
            if _PARAM_DECL_RE.match(stripped):
                continue
            meaningful.append((line_no, stripped))

        # Sliding window of _BLOCK_MIN_LINES
        for idx in range(len(meaningful) - _BLOCK_MIN_LINES + 1):
            window = meaningful[idx:idx + _BLOCK_MIN_LINES]
            block_text = "\n".join(text for _, text in window)
            block_hash = hash_text_block(block_text)
            start_line = window[0][0]
            entries = block_hashes.setdefault(block_hash, [])
            # Don't add overlapping blocks from the same file
            if entries and entries[-1][0] == snapshot.path and abs(entries[-1][1] - start_line) < _BLOCK_MIN_LINES:
                continue
            entries.append((snapshot.path, start_line))

    # ── Collapse per-line-window inflation ──
    # A single duplicated REGION of N lines produces N-_BLOCK_MIN_LINES+1
    # distinct window hashes, all sharing the same set of files at adjacent
    # start lines. Emitting one finding per hash inflated the count (~13
    # findings for one shared block on filelock). Group the duplicate hashes by
    # the set of files involved, then merge windows whose start lines are within
    # _BLOCK_MIN_LINES of each other (contiguous/overlapping = same region) so
    # each duplicated region yields exactly ONE finding.
    #
    # group key = frozenset of files; value = {file: [start_line, ...]}
    region_groups: dict[frozenset, dict[str, list[int]]] = {}
    for block_hash, locations in block_hashes.items():
        if len(locations) < 2:
            continue
        files_in_hash = frozenset(path for path, _ in locations)
        if len(files_in_hash) >= 2:
            key = files_in_hash
        else:
            # Intra-file: only meaningful if the SAME block repeats at >=2 spots.
            only_file = next(iter(files_in_hash))
            if len({ln for _, ln in locations}) < 2:
                continue
            key = files_in_hash
        bucket = region_groups.setdefault(key, {})
        for path, ln in locations:
            bucket.setdefault(path, []).append(ln)

    def _merge_starts(starts: list[int]) -> list[int]:
        """Collapse start lines within _BLOCK_MIN_LINES of each other into the
        first line of each contiguous region."""
        if not starts:
            return []
        ordered = sorted(set(starts))
        regions = [ordered[0]]
        for ln in ordered[1:]:
            if ln - regions[-1] >= _BLOCK_MIN_LINES:
                regions.append(ln)
        return regions

    for files_key, per_file in region_groups.items():
        if _text_block_count >= _MAX_TEXT_BLOCK_FINDINGS:
            break
        unique_files = sorted(per_file.keys())
        # Region anchor = first start line in each file (after merging).
        merged_per_file = {f: _merge_starts(per_file[f]) for f in unique_files}

        if len(unique_files) >= 2:
            # One cross-file finding per duplicated region. The number of regions
            # is the max region count across the involved files.
            region_count = max(len(v) for v in merged_per_file.values()) or 1
            for region_idx in range(region_count):
                if _text_block_count >= _MAX_TEXT_BLOCK_FINDINGS:
                    break
                file_lines_map = {
                    f: merged_per_file[f][min(region_idx, len(merged_per_file[f]) - 1)]
                    for f in unique_files
                }
                _text_block_count += 1
                file_list = ", ".join(f"{f} (line {file_lines_map[f]})" for f in unique_files[:5])
                suffix = f" and {len(unique_files) - 5} more" if len(unique_files) > 5 else ""
                findings.append(
                    build_finding(
                        check_id="duplication.text_block",
                        category=GateCategory.DUPLICATION,
                        title="Repeated text block across files",
                        severity=GateSeverity.MEDIUM,
                        impact=GateImpact.REVISE,
                        summary=(
                            f"Duplicated {_BLOCK_MIN_LINES}+ line block found in {len(unique_files)} files: "
                            f"{file_list}{suffix}"
                        ),
                        recommendation=(
                            "Extract the repeated block into a shared function, template, or constant. "
                            "If the files belong to the same package — add a `shared.py` or `utils.py` module there. "
                            "If they span multiple packages — move the helper to the nearest common ancestor package."
                        ),
                        evidence=[
                            EvidenceReference(kind="file", path=f, detail=f"line:{file_lines_map[f]}")
                            for f in unique_files[:5]
                        ],
                        repair_kind=RepairKind.EXTRACT_SHARED.value,
                        executor_action=f"Extract duplicated block from {unique_files[0]} et al. into shared helper; replace each occurrence with a call",
                        proof_required="no repeated block; tests pass",
                    )
                )
        else:
            # Intra-file duplication (same block repeated within one file).
            file_path = unique_files[0]
            file_lines = merged_per_file[file_path]
            if len(file_lines) >= 2:
                _text_block_count += 1
                findings.append(
                    build_finding(
                        check_id="duplication.text_block_intra",
                        category=GateCategory.DUPLICATION,
                        title="Repeated text block within same file",
                        severity=GateSeverity.MEDIUM,
                        impact=GateImpact.REVISE,
                        summary=(
                            f"{file_path} has {len(file_lines)} copies of a {_BLOCK_MIN_LINES}+ line block "
                            f"(lines {', '.join(str(l) for l in file_lines[:5])}). "
                            f"Extract to a shared helper."
                        ),
                        recommendation=(
                            "Extract the repeated block into a private helper function within the same file "
                            "and call it from each location. "
                            "If the same logic is needed elsewhere — move the helper to `<package>/shared.py`."
                        ),
                        evidence=[
                            EvidenceReference(kind="file", path=file_path, detail=f"line:{ln}")
                            for ln in file_lines[:3]
                        ],
                        repair_kind=RepairKind.EXTRACT_SHARED.value,
                        executor_action=f"Extract repeated block in {file_path} (lines {', '.join(str(l) for l in file_lines[:3])}) into private helper; replace each copy with a call",
                        proof_required="no repeated block; tests pass",
                    )
                )

    return build_check_result(check_id="duplication", category=GateCategory.DUPLICATION, findings=findings)
