"""Data handling, time, duplication, and dependency quality. Clusters 44-50.

Clusters:
  44 - Naive Timezone Usage
  45 - Intra-File Near-Duplicate Code
  46 - Missing Null/None Check at API Boundary
  47 - String Concatenation for Paths
  48 - Log Without Error Context
  49 - Secrets in Test Files
  50 - Unpinned Dependencies
"""
from __future__ import annotations

from .core import detect_language
from ...gate_models import (
    EvidenceReference,
    GateCategory,
    GateFinding,
    GateImpact,
    GateSeverity,
    RepairKind,
)
from ..common import build_finding
import logging
_log = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Cluster 44: Naive Timezone Usage
# ---------------------------------------------------------------------------


def assess_naive_timezone(
    file_path: str,
    content: str,
) -> list[GateFinding]:
    """Cluster 44: Detect naive datetime usage without timezone awareness."""
    import re

    if not content.strip():
        return []

    lang = detect_language(file_path)
    if lang not in ("python", "javascript", "typescript"):
        return []

    basename = file_path.replace("\\", "/").rsplit("/", 1)[-1] if "/" in file_path.replace("\\", "/") else file_path
    if basename.startswith("test_") or basename.startswith("conftest"):
        return []

    findings: list[GateFinding] = []

    if lang == "python":
        for i, line in enumerate(content.splitlines(), 1):
            stripped = line.strip()
            if stripped.startswith("#"):
                continue
            if re.search(r'datetime\.now\s*\(\s*\)', stripped):
                detail = f"datetime.now() without timezone (line {i}) -- use datetime.now(tz=timezone.utc)"
                findings.append(build_finding(
                    check_id="timezone_scan",
                    category=GateCategory.RUNTIME_BEHAVIOR,
                    title=f"[naive_timezone] {file_path}:{i}",
                    severity=GateSeverity.MEDIUM,
                    impact=GateImpact.REVISE,
                    summary=detail,
                    recommendation="Use `datetime.now(tz=timezone.utc)` for timezone-aware datetimes.",
                    evidence=(EvidenceReference(kind="probe", path=file_path, detail=detail, ok=False),),
                    repair_kind=RepairKind.FIX_CONTRACT.value,
                    executor_action=f"Fix naive datetime at {file_path}:{i}",
                ))
            if re.search(r'datetime\.utcnow\s*\(', stripped):
                detail = f"datetime.utcnow() is deprecated (line {i}) -- use datetime.now(tz=timezone.utc)"
                findings.append(build_finding(
                    check_id="timezone_scan",
                    category=GateCategory.RUNTIME_BEHAVIOR,
                    title=f"[naive_timezone] {file_path}:{i}",
                    severity=GateSeverity.MEDIUM,
                    impact=GateImpact.REVISE,
                    summary=detail,
                    recommendation="Replace `datetime.utcnow()` with `datetime.now(tz=timezone.utc)`.",
                    evidence=(EvidenceReference(kind="probe", path=file_path, detail=detail, ok=False),),
                    repair_kind=RepairKind.FIX_CONTRACT.value,
                    executor_action=f"Fix deprecated utcnow() at {file_path}:{i}",
                ))
            if re.search(r'time\.localtime\s*\(\s*\)', stripped):
                detail = f"time.localtime() without timezone (line {i}) -- use time.gmtime() or datetime"
                findings.append(build_finding(
                    check_id="timezone_scan",
                    category=GateCategory.RUNTIME_BEHAVIOR,
                    title=f"[naive_timezone] {file_path}:{i}",
                    severity=GateSeverity.LOW,
                    impact=GateImpact.WARN,
                    summary=detail,
                    recommendation="Use `time.gmtime()` or `datetime.now(tz=timezone.utc)` instead.",
                    evidence=(EvidenceReference(kind="probe", path=file_path, detail=detail, ok=False),),
                    repair_kind=RepairKind.FIX_CONTRACT.value,
                    executor_action=f"Fix localtime() at {file_path}:{i}",
                ))
            if len(findings) >= 10:
                break

    elif lang in ("javascript", "typescript"):
        for i, line in enumerate(content.splitlines(), 1):
            stripped = line.strip()
            if stripped.startswith("//"):
                continue
            if re.search(r'\.toLocaleDateString\s*\(\s*\)', stripped):
                detail = f"toLocaleDateString() without locale (line {i}) -- specify locale explicitly"
                findings.append(build_finding(
                    check_id="timezone_scan",
                    category=GateCategory.RUNTIME_BEHAVIOR,
                    title=f"[naive_timezone] {file_path}:{i}",
                    severity=GateSeverity.LOW,
                    impact=GateImpact.WARN,
                    summary=detail,
                    recommendation="Pass explicit locale: `.toLocaleDateString('en-US', { timeZone: 'UTC' })`.",
                    evidence=(EvidenceReference(kind="probe", path=file_path, detail=detail, ok=False),),
                    repair_kind=RepairKind.FIX_CONTRACT.value,
                    executor_action=f"Fix toLocaleDateString() at {file_path}:{i}",
                ))
            if len(findings) >= 10:
                break

    return findings


# ---------------------------------------------------------------------------
# Cluster 45: Intra-File Near-Duplicate Code
# ---------------------------------------------------------------------------


import re as _re

# FP-round2-D (2026-06-28): signature / typing scaffolding line shapes that must
# NOT count as meaningful duplicate lines. These repeat by language requirement
# (typing overloads) or API symmetry and are not refactorable logic:
#   * decorator lines:            ``@t.overload`` / ``@property`` / ``@staticmethod``
#   * def openers / closers:      ``def f(`` / ``async def f(`` / ``): ...`` / ``) -> X:``
#   * bare parameter declarations inside a multi-line signature:
#         ``name`` | ``name,`` | ``name=default,`` | ``name: type,`` | ``*args,``
#     where the value is a simple literal/identifier (NOT a function call, so a
#     real statement like ``record = build_record(...)`` is never skipped).
#   * lone ellipsis stub bodies:  ``...``
_SCAFFOLD_PARAM_RE = _re.compile(
    r"^\*{0,2}[A-Za-z_]\w*"            # name, *args, **kwargs
    r"(?:\s*:\s*[^=(]+?)?"             # optional annotation (no call parens)
    r"(?:\s*=\s*[^(]+?)?"             # optional simple default (no call parens)
    r",?$"                             # optional trailing comma
)


def _is_signature_scaffolding(s: str) -> bool:
    """True if normalized line *s* is signature / typing scaffolding."""
    if s == "..." or s.endswith("): ...") or s == "): ..." or s.endswith(") -> ..."):
        return True
    if s.startswith("@"):  # decorator
        return True
    if s.startswith("def ") or s.startswith("async def "):
        # ``def f(`` opener (possibly with the full single-line signature). A
        # single-line def with a body on the same line is rare; treat the
        # ``def`` header as scaffolding either way.
        return True
    if s in (")", "):", "->", ") ->"):
        return True
    # Closer with return type only: ``) -> SomeType:`` (no other statement).
    if s.startswith(")") and s.endswith(":"):
        return True
    # Bare parameter declaration line inside a multi-line signature.
    if _SCAFFOLD_PARAM_RE.match(s) and "(" not in s:
        return True
    return False


def assess_near_duplicate_code(
    file_path: str,
    content: str,
) -> list[GateFinding]:
    """Cluster 45: Detect near-duplicate code blocks within the same file.

    A single duplicated REGION of N lines spans N-BLOCK_SIZE+1 overlapping
    sliding windows. Emitting one finding per window inflated the count (a
    4-statement block reported once per line: "lines 118 and 201", "119 and
    202", ...). We collect every duplicate window-pair, then MERGE contiguous /
    overlapping pairs into ONE finding per contiguous block — mirroring the
    region-grouping ``_merge_starts`` used by ``duplication.text_block`` — so a
    block reports as "lines 118-121 <-> 201-204" exactly once. Genuinely
    separate duplicate blocks still each report once (merge, not cap).
    """
    if not content.strip():
        return []

    lang = detect_language(file_path)
    if lang in ("json", "yaml", "toml", "markdown", "restructuredtext", "sql"):
        return []

    lines = content.splitlines()
    if len(lines) < 10:
        return []

    BLOCK_SIZE = 4
    # FP-round2-D (2026-06-28): minimum number of MEANINGFUL (post-normalization,
    # non-scaffolding) lines a duplicated region must span to be reported.
    #
    # The PRIMARY noise discriminator is ``_is_signature_scaffolding`` below: on
    # real code (click, mcp) most near-duplicate hits were typing/signature
    # mirrors — ``@t.overload`` stubs, parameter-list mirrors — whose lines are
    # now stripped from ``normalized`` entirely, so those regions never form.
    #
    # This line-count floor is a SECONDARY filter against very short residual
    # mirrors (e.g. repeated 3-4 line encoding-literal bodies). It is set to 5
    # so that genuine multi-statement logic duplicates (>=5 meaningful lines)
    # are still reported — including the oracle's 6-line route_alpha/route_beta
    # bodies and 4-statement+return logic blocks — while trivial 3-4 line
    # mirrors are dropped.
    MIN_DUP_REGION_LINES = 5
    normalized: list[tuple[str, int]] = []
    for i, line in enumerate(lines, 1):
        s = line.strip()
        if not s or s.startswith("#") or s.startswith("//") or s.startswith("*"):
            continue
        if s in ("}", "{", "pass", "return", "break", "continue", "else:", "try:", "finally:"):
            continue
        # FP-round2-D: skip signature / typing scaffolding so overload stubs and
        # parameter-list mirrors do not accumulate "meaningful" duplicate lines.
        if _is_signature_scaffolding(s):
            continue
        normalized.append((" ".join(s.split()), i))

    if len(normalized) < BLOCK_SIZE * 2:
        return []

    # Pass 1: collect every duplicate window as a (first_occurrence, this) pair
    # of the *normalized* index, keeping the source line number for each.
    seen: dict[str, tuple[int, int]] = {}  # fingerprint -> (norm_idx, line_no)
    # raw_pairs: list of (orig_norm_idx, dup_norm_idx, orig_line, dup_line)
    raw_pairs: list[tuple[int, int, int, int]] = []
    for idx in range(len(normalized) - BLOCK_SIZE + 1):
        block = tuple(normalized[idx + k][0] for k in range(BLOCK_SIZE))
        fp = "\n".join(block)
        first_line = normalized[idx][1]
        if fp in seen:
            orig_idx, orig_line = seen[fp]
            if abs(first_line - orig_line) >= BLOCK_SIZE:
                raw_pairs.append((orig_idx, idx, orig_line, first_line))
        else:
            seen[fp] = (idx, first_line)

    if not raw_pairs:
        return []

    # Pass 2: merge contiguous/overlapping window-pairs into block-level
    # regions. Two pairs belong to the same duplicated block when BOTH their
    # original-window index and duplicate-window index advance by exactly one
    # step together (the sliding window moved one normalized line on each side).
    # Each merged region records the source line span on both sides.
    raw_pairs.sort()
    regions: list[tuple[int, int, int, int]] = []  # (orig_start_line, orig_end_line, dup_start_line, dup_end_line)
    cur_orig_idx, cur_dup_idx, cur_orig_start, cur_dup_start = raw_pairs[0]
    cur_orig_end_line = cur_orig_start
    cur_dup_end_line = cur_dup_start
    prev_orig_idx, prev_dup_idx = cur_orig_idx, cur_dup_idx

    def _flush() -> None:
        # End line of a BLOCK_SIZE window starting at the recorded start line:
        # add the height of the window (last normalized line in the window).
        oi = prev_orig_idx
        di = prev_dup_idx
        orig_end = normalized[oi + BLOCK_SIZE - 1][1]
        dup_end = normalized[di + BLOCK_SIZE - 1][1]
        regions.append((cur_orig_start, orig_end, cur_dup_start, dup_end))

    for orig_idx, dup_idx, orig_line, dup_line in raw_pairs[1:]:
        if orig_idx == prev_orig_idx + 1 and dup_idx == prev_dup_idx + 1:
            # Same sliding region — extend.
            prev_orig_idx, prev_dup_idx = orig_idx, dup_idx
            continue
        # New region — flush the current one and start fresh.
        _flush()
        cur_orig_idx, cur_dup_idx = orig_idx, dup_idx
        cur_orig_start, cur_dup_start = orig_line, dup_line
        prev_orig_idx, prev_dup_idx = orig_idx, dup_idx
    _flush()

    findings: list[GateFinding] = []
    for orig_start, orig_end, dup_start, dup_end in regions:
        n_lines = orig_end - orig_start + 1
        # FP-round2-D: count MEANINGFUL (normalized, non-scaffolding) lines that
        # actually fall inside the original region — the raw line span can
        # include blank/comment gaps. Require >= MIN_DUP_REGION_LINES to report.
        meaningful_in_region = sum(
            1 for _norm_text, _ln in normalized if orig_start <= _ln <= orig_end
        )
        if meaningful_in_region < MIN_DUP_REGION_LINES:
            continue
        detail = (
            f"Near-duplicate block at lines {orig_start}-{orig_end} <-> "
            f"{dup_start}-{dup_end} ({n_lines} lines)"
        )
        findings.append(build_finding(
            check_id="duplicate_scan",
            category=GateCategory.DRIFT,
            title=f"[near_duplicate_code] {file_path}:{dup_start}",
            severity=GateSeverity.LOW,
            impact=GateImpact.WARN,
            summary=detail,
            recommendation="Extract the duplicate block into a shared function.",
            evidence=(EvidenceReference(kind="probe", path=file_path, detail=detail, ok=False),),
            repair_kind=RepairKind.REMOVE_DUPLICATE.value,
            executor_action=f"Deduplicate code block at {file_path}:{dup_start}",
        ))
        if len(findings) >= 10:
            break

    return findings


# ---------------------------------------------------------------------------
# Cluster 46: Missing Null/None Check at API Boundary
# ---------------------------------------------------------------------------


def assess_missing_null_check(
    file_path: str,
    content: str,
) -> list[GateFinding]:
    """Cluster 46: Detect missing null/None checks at API boundaries."""
    import re

    if not content.strip():
        return []

    lang = detect_language(file_path)
    if lang not in ("python", "javascript", "typescript"):
        return []

    basename = file_path.replace("\\", "/").rsplit("/", 1)[-1] if "/" in file_path.replace("\\", "/") else file_path
    if basename.startswith("test_") or basename.startswith("conftest"):
        return []

    findings: list[GateFinding] = []

    if lang == "python":
        for i, line in enumerate(content.splitlines(), 1):
            stripped = line.strip()
            if stripped.startswith("#"):
                continue
            if re.search(r'request\.json\s*\[', stripped):
                detail = f"request.json[key] without .get() -- KeyError if missing (line {i})"
                findings.append(build_finding(
                    check_id="null_check_scan",
                    category=GateCategory.RUNTIME_BEHAVIOR,
                    title=f"[missing_null_check] {file_path}:{i}",
                    severity=GateSeverity.MEDIUM,
                    impact=GateImpact.REVISE,
                    summary=detail,
                    recommendation="Use `request.json.get('key')` with a default value.",
                    evidence=(EvidenceReference(kind="probe", path=file_path, detail=detail, ok=False),),
                    repair_kind=RepairKind.ADD_BOUNDARY_CHECK.value,
                    executor_action=f"Fix missing null check at {file_path}:{i}",
                ))
            if re.search(r'request\.form\s*\[', stripped):
                detail = f"request.form[key] without .get() -- KeyError if missing (line {i})"
                findings.append(build_finding(
                    check_id="null_check_scan",
                    category=GateCategory.RUNTIME_BEHAVIOR,
                    title=f"[missing_null_check] {file_path}:{i}",
                    severity=GateSeverity.MEDIUM,
                    impact=GateImpact.REVISE,
                    summary=detail,
                    recommendation="Use `request.form.get('key')` with a default value.",
                    evidence=(EvidenceReference(kind="probe", path=file_path, detail=detail, ok=False),),
                    repair_kind=RepairKind.ADD_BOUNDARY_CHECK.value,
                    executor_action=f"Fix missing null check at {file_path}:{i}",
                ))
            if re.search(r'json\.loads\s*\([^)]+\)\s*\[', stripped):
                detail = f"json.loads()[key] -- chain of failure points (line {i})"
                findings.append(build_finding(
                    check_id="null_check_scan",
                    category=GateCategory.RUNTIME_BEHAVIOR,
                    title=f"[missing_null_check] {file_path}:{i}",
                    severity=GateSeverity.MEDIUM,
                    impact=GateImpact.REVISE,
                    summary=detail,
                    recommendation="Assign json.loads() to a variable and use .get() for key access.",
                    evidence=(EvidenceReference(kind="probe", path=file_path, detail=detail, ok=False),),
                    repair_kind=RepairKind.ADD_BOUNDARY_CHECK.value,
                    executor_action=f"Fix chained failure points at {file_path}:{i}",
                ))
            if len(findings) >= 10:
                break

    elif lang in ("javascript", "typescript"):
        for i, line in enumerate(content.splitlines(), 1):
            stripped = line.strip()
            if stripped.startswith("//"):
                continue
            if re.search(r'req\.body\.\w+', stripped) and "?." not in stripped:
                if not re.search(r'if\s*\(.*req\.body', stripped):
                    detail = f"req.body.field without null check (line {i}) -- use ?. or validate first"
                    findings.append(build_finding(
                        check_id="null_check_scan",
                        category=GateCategory.RUNTIME_BEHAVIOR,
                        title=f"[missing_null_check] {file_path}:{i}",
                        severity=GateSeverity.MEDIUM,
                        impact=GateImpact.REVISE,
                        summary=detail,
                        recommendation="Use optional chaining (`?.`) or validate `req.body` before accessing fields.",
                        evidence=(EvidenceReference(kind="probe", path=file_path, detail=detail, ok=False),),
                        repair_kind=RepairKind.ADD_BOUNDARY_CHECK.value,
                        executor_action=f"Fix missing null check at {file_path}:{i}",
                    ))
            if re.search(r'JSON\.parse\s*\([^)]+\)\.\w+', stripped):
                detail = f"JSON.parse().field -- chain of failure points (line {i})"
                findings.append(build_finding(
                    check_id="null_check_scan",
                    category=GateCategory.RUNTIME_BEHAVIOR,
                    title=f"[missing_null_check] {file_path}:{i}",
                    severity=GateSeverity.MEDIUM,
                    impact=GateImpact.REVISE,
                    summary=detail,
                    recommendation="Assign JSON.parse() to a variable and use optional chaining for field access.",
                    evidence=(EvidenceReference(kind="probe", path=file_path, detail=detail, ok=False),),
                    repair_kind=RepairKind.ADD_BOUNDARY_CHECK.value,
                    executor_action=f"Fix chained failure points at {file_path}:{i}",
                ))
            if len(findings) >= 10:
                break

    return findings


# ---------------------------------------------------------------------------
# Cluster 47: String Concatenation for Paths
# ---------------------------------------------------------------------------


def assess_path_concatenation(
    file_path: str,
    content: str,
) -> list[GateFinding]:
    """Cluster 47: Detect string concatenation used to build file paths."""
    import re

    if not content.strip():
        return []

    lang = detect_language(file_path)
    if lang not in ("python", "javascript", "typescript"):
        return []

    basename = file_path.replace("\\", "/").rsplit("/", 1)[-1] if "/" in file_path.replace("\\", "/") else file_path
    if basename.startswith("test_") or basename.startswith("conftest"):
        return []

    findings: list[GateFinding] = []

    for i, line in enumerate(content.splitlines(), 1):
        stripped = line.strip()
        if stripped.startswith("#") or stripped.startswith("//"):
            continue
        if "http://" in stripped or "https://" in stripped:
            continue
        if re.search(r'\w+\s*\+\s*["\'][/\\]["\']', stripped):
            ctx_words = ("path", "dir", "file", "folder", "name", "root", "base")
            if any(w in stripped.lower() for w in ctx_words):
                detail = f"String concat for path building (line {i}) -- use os.path.join / Path"
                findings.append(build_finding(
                    check_id="path_concat_scan",
                    category=GateCategory.CONTRACT,
                    title=f"[path_concatenation] {file_path}:{i}",
                    severity=GateSeverity.LOW,
                    impact=GateImpact.WARN,
                    summary=detail,
                    recommendation="Use `os.path.join()` or `pathlib.Path` instead of string concatenation.",
                    evidence=(EvidenceReference(kind="probe", path=file_path, detail=detail, ok=False),),
                    repair_kind=RepairKind.FIX_CONTRACT.value,
                    executor_action=f"Fix path concatenation at {file_path}:{i}",
                ))
        if lang == "python" and re.search(r'f["\'][^"\']*\{[^}]+\}/\{[^}]+\}', stripped):
            detail = f"f-string path building (line {i}) -- use os.path.join / Path"
            findings.append(build_finding(
                check_id="path_concat_scan",
                category=GateCategory.CONTRACT,
                title=f"[path_concatenation] {file_path}:{i}",
                severity=GateSeverity.LOW,
                impact=GateImpact.WARN,
                summary=detail,
                recommendation="Use `os.path.join()` or `pathlib.Path` instead of f-string path building.",
                evidence=(EvidenceReference(kind="probe", path=file_path, detail=detail, ok=False),),
                repair_kind=RepairKind.FIX_CONTRACT.value,
                executor_action=f"Fix f-string path building at {file_path}:{i}",
            ))
        if len(findings) >= 10:
            break

    return findings


# ---------------------------------------------------------------------------
# Cluster 48: Log Without Error Context
# ---------------------------------------------------------------------------


def assess_log_without_context(
    file_path: str,
    content: str,
) -> list[GateFinding]:
    """Cluster 48: Detect error logging without exception context."""
    import re

    if not content.strip():
        return []

    lang = detect_language(file_path)
    if lang not in ("python", "javascript", "typescript", "java"):
        return []

    basename = file_path.replace("\\", "/").rsplit("/", 1)[-1] if "/" in file_path.replace("\\", "/") else file_path
    if basename.startswith("test_") or basename.startswith("conftest"):
        return []

    findings: list[GateFinding] = []
    lines = content.splitlines()

    if lang == "python":
        in_except = False
        except_var = None
        except_indent = 0

        for i, line in enumerate(lines, 1):
            stripped = line.strip()
            indent = len(line) - len(line.lstrip())

            m = re.match(r'^except\s+\w+(?:\s+as\s+(\w+))?\s*:', stripped)
            if m:
                in_except = True
                except_var = m.group(1)
                except_indent = indent
                continue

            if in_except:
                if indent <= except_indent and stripped:
                    in_except = False
                    except_var = None
                    continue
                if re.search(r'(?:logger?|logging)\.\w*(error|exception|critical)\s*\(', stripped):
                    has_context = False
                    if except_var and re.search(rf'\b{re.escape(except_var)}\b', stripped):
                        has_context = True
                    if "exc_info" in stripped:
                        has_context = True
                    if "traceback" in stripped:
                        has_context = True
                    if ".exception(" in stripped:
                        has_context = True
                    if not has_context:
                        detail = f"logger.error() in except block without exception context (line {i})"
                        findings.append(build_finding(
                            check_id="log_context_scan",
                            category=GateCategory.REPORTING,
                            title=f"[log_without_context] {file_path}:{i}",
                            severity=GateSeverity.LOW,
                            impact=GateImpact.WARN,
                            summary=detail,
                            recommendation="Use `logger.exception()` or pass `exc_info=True` to include traceback.",
                            evidence=(EvidenceReference(kind="probe", path=file_path, detail=detail, ok=False),),
                            repair_kind=RepairKind.ADD_PROOF.value,
                            executor_action=f"Add exception context to log at {file_path}:{i}",
                        ))
            if len(findings) >= 10:
                break

    elif lang in ("javascript", "typescript"):
        in_catch = False
        catch_var = None
        catch_indent = 0

        for i, line in enumerate(lines, 1):
            stripped = line.strip()
            indent = len(line) - len(line.lstrip())

            m = re.match(r'catch\s*\(\s*(\w+)\s*\)', stripped)
            if m:
                in_catch = True
                catch_var = m.group(1)
                catch_indent = indent
                continue

            if in_catch:
                if indent <= catch_indent and stripped and stripped != "}":
                    in_catch = False
                    catch_var = None
                    continue
                if re.search(r'console\.error\s*\(', stripped):
                    if catch_var and catch_var not in stripped:
                        detail = f"console.error() in catch block without error object (line {i})"
                        findings.append(build_finding(
                            check_id="log_context_scan",
                            category=GateCategory.REPORTING,
                            title=f"[log_without_context] {file_path}:{i}",
                            severity=GateSeverity.LOW,
                            impact=GateImpact.WARN,
                            summary=detail,
                            recommendation=f"Pass the error object to console.error: `console.error('message', {catch_var})`.",
                            evidence=(EvidenceReference(kind="probe", path=file_path, detail=detail, ok=False),),
                            repair_kind=RepairKind.ADD_PROOF.value,
                            executor_action=f"Add error context to log at {file_path}:{i}",
                        ))
            if len(findings) >= 10:
                break

    return findings


# ---------------------------------------------------------------------------
# Cluster 49: Secrets in Test Files
# ---------------------------------------------------------------------------


def assess_test_secrets(
    file_path: str,
    content: str,
) -> list[GateFinding]:
    """Cluster 49: Detect real-looking secrets in test files."""
    import re

    if not content.strip():
        return []

    basename = file_path.replace("\\", "/").rsplit("/", 1)[-1] if "/" in file_path.replace("\\", "/") else file_path
    if not (basename.startswith("test_") or basename.startswith("conftest") or "_test." in basename):
        return []

    findings: list[GateFinding] = []

    secret_patterns = [
        (r'(?:sk|pk)[-_](?:live|test)[-_][a-zA-Z0-9]{20,}', "Stripe-like API key"),
        (r'ghp_[a-zA-Z0-9]{36,}', "GitHub personal access token"),
        (r'gho_[a-zA-Z0-9]{36,}', "GitHub OAuth token"),
        (r'AKIA[A-Z0-9]{16}', "AWS access key ID"),
        (r'eyJ[a-zA-Z0-9_-]{20,}\.[a-zA-Z0-9_-]{20,}\.[a-zA-Z0-9_-]{20,}', "JWT token"),
        (r'xox[bpsar]-[a-zA-Z0-9-]{20,}', "Slack token"),
        (r'sk-[a-zA-Z0-9]{40,}', "OpenAI API key"),
        (r'AIza[a-zA-Z0-9_-]{35}', "Google API key"),
    ]

    for i, line in enumerate(content.splitlines(), 1):
        stripped = line.strip()
        if stripped.startswith("#") or stripped.startswith("//"):
            continue
        for pattern, description in secret_patterns:
            if re.search(pattern, stripped):
                if any(ph in stripped.lower() for ph in ("placeholder", "example", "fake", "mock", "dummy", "xxx", "test_key")):
                    continue
                detail = f"Possible {description} in test file (line {i})"
                findings.append(build_finding(
                    check_id="test_secret_scan",
                    category=GateCategory.TRUTH_BOUNDARY,
                    title=f"[test_secrets] {file_path}:{i}",
                    severity=GateSeverity.HIGH,
                    impact=GateImpact.REVISE,
                    summary=detail,
                    recommendation="Replace real secrets with obviously fake placeholders (e.g. 'fake-key-xxx').",
                    evidence=(EvidenceReference(kind="probe", path=file_path, detail=detail, ok=False),),
                    repair_kind=RepairKind.REPLACE_WITH_FAIL_LOUD.value,
                    executor_action=f"Remove secret from test file at {file_path}:{i}",
                ))
                break
        if len(findings) >= 10:
            break

    return findings


# ---------------------------------------------------------------------------
# Cluster 50: Unpinned Dependencies
# ---------------------------------------------------------------------------


def assess_unpinned_dependencies(
    file_path: str,
    content: str,
) -> list[GateFinding]:
    """Cluster 50: Detect unpinned dependency versions."""
    import re

    if not content.strip():
        return []

    basename = file_path.replace("\\", "/").rsplit("/", 1)[-1] if "/" in file_path.replace("\\", "/") else file_path

    findings: list[GateFinding] = []

    if basename.startswith("requirements") and basename.endswith(".txt"):
        for i, line in enumerate(content.splitlines(), 1):
            stripped = line.strip()
            if not stripped or stripped.startswith("#") or stripped.startswith("-"):
                continue
            if re.match(r'^[a-zA-Z][a-zA-Z0-9._-]*\s*$', stripped):
                detail = f"Unpinned dependency: '{stripped}' -- add ==X.Y.Z"
                findings.append(build_finding(
                    check_id="unpinned_dep_scan",
                    category=GateCategory.CONTRACT,
                    title=f"[unpinned_dependencies] {file_path}:{i}",
                    severity=GateSeverity.MEDIUM,
                    impact=GateImpact.REVISE,
                    summary=detail,
                    recommendation=f"Pin the dependency with an exact version: `{stripped}==X.Y.Z`.",
                    evidence=(EvidenceReference(kind="probe", path=file_path, detail=detail, ok=False),),
                    repair_kind=RepairKind.FIX_CONTRACT.value,
                    executor_action=f"Pin dependency '{stripped}' at {file_path}:{i}",
                ))
            elif re.search(r'>=|<=|~=|!=', stripped) and '==' not in stripped:
                detail = f"Loosely pinned: '{stripped}' -- prefer exact ==X.Y.Z"
                findings.append(build_finding(
                    check_id="unpinned_dep_scan",
                    category=GateCategory.CONTRACT,
                    title=f"[unpinned_dependencies] {file_path}:{i}",
                    severity=GateSeverity.LOW,
                    impact=GateImpact.WARN,
                    summary=detail,
                    recommendation="Use exact version pinning (`==X.Y.Z`) for reproducible builds.",
                    evidence=(EvidenceReference(kind="probe", path=file_path, detail=detail, ok=False),),
                    repair_kind=RepairKind.FIX_CONTRACT.value,
                    executor_action=f"Pin dependency at {file_path}:{i}",
                ))
            if len(findings) >= 10:
                break

    elif basename == "package.json":
        import json as json_mod
        try:
            pkg = json_mod.loads(content)
        except (json_mod.JSONDecodeError, ValueError):
            return []
        for section in ("dependencies", "devDependencies"):
            deps = pkg.get(section, {})
            if not isinstance(deps, dict):
                continue
            for name, version in deps.items():
                if not isinstance(version, str):
                    continue
                if version.startswith("^") or version.startswith("~") or version == "*":
                    detail = f"Loosely pinned '{name}': '{version}' in {section}"
                    findings.append(build_finding(
                        check_id="unpinned_dep_scan",
                        category=GateCategory.CONTRACT,
                        title=f"[unpinned_dependencies] {file_path}:{section}:{name}",
                        severity=GateSeverity.LOW,
                        impact=GateImpact.WARN,
                        summary=detail,
                        recommendation=f"Use exact version pinning for '{name}' in {section}.",
                        evidence=(EvidenceReference(kind="probe", path=file_path, detail=detail, ok=False),),
                        repair_kind=RepairKind.FIX_CONTRACT.value,
                        executor_action=f"Pin '{name}' in {section} at {file_path}",
                    ))
                if len(findings) >= 10:
                    break
    else:
        return []

    return findings
