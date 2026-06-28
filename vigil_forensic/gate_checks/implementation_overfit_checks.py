"""Gate: implementation_overfit

Detects code overfit to local context: hardcoded paths, project-specific
strings, and broken project-agnosticism claims.

Sub-checks:
  hardcoded_repo_path           -- string literal contains known project-specific cluster paths
  assumes_single_language       -- language-neutral file has Python-only conditionals without else
  fake_generic_helper           -- function named generic_*/universal_*/common_* has repo literals
  env_tight_coupling            -- module imports project-prefixed env vars in universal context
"""
from __future__ import annotations

import re
import logging

from vigil_forensic._shared import (
    EvidenceReference,
    GateCategory,
    GateImpact,
    GateSeverity,
    RepairKind,
)
from vigil_forensic.gate_models import PostExecGateContext
from .common import build_finding, normalize_path
from ._ast_helpers import parse_python_source_or_emit_finding

_log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# String patterns that indicate hardcoded repo-specific paths/names
_REPO_LITERAL_PATTERNS: tuple[re.Pattern, ...] = (
    re.compile(r"""["'](BRAIN/|SYSTEM/|INTERFACE/|STORAGE/)"""),
    re.compile(r"""["']/.vigil_launcher/"""),
    re.compile(r"""["']7331["']"""),
    re.compile(r"""["']vigil_control_plane["']"""),
    re.compile(r"""["']vigil_"""),
)

# Python-only conditional patterns that break language-neutrality
_PYTHON_ONLY_PATTERNS: tuple[re.Pattern, ...] = (
    re.compile(r"""path\.(?:endswith|suffix)\s*\(\s*["']\.py["']\s*\)"""),
    re.compile(r"""(?:lang|language)\s*==\s*["']python["']"""),
    re.compile(r"""\.endswith\s*\(\s*["']\.py["']\s*\)"""),
)

# Prefixes for "generic" helper function names
_GENERIC_PREFIXES = ("generic_", "universal_", "common_")

# Environment variable prefix pattern
_AI_HOST_ENV_PATTERN = re.compile(
    r"""os\.environ(?:\.get)?\s*\(\s*["']VIGIL_""",
)


def _is_ai_host_gate_file(path: str) -> bool:
    """True if file belongs to an vigil-specific gate context.

    Files under SYSTEM/pipeline/gates/ are Vigil-specific orchestration
    gates that are explicitly allowed to contain hardcoded repo path literals.
    """
    normalized = path.replace("\\", "/")
    return "SYSTEM/pipeline/gates/" in normalized


def _has_else_branch(content: str, match_start: int) -> bool:
    """Heuristic: check if the matched if-line has a nearby else/elif."""
    snippet = content[match_start: match_start + 400]
    return bool(re.search(r"\belse\b|\belif\b", snippet))


def _find_repo_literals_in_text(content: str) -> list[tuple[int, str]]:
    """Return list of (line_num, snippet) for all repo literal matches."""
    lines = content.splitlines()
    results: list[tuple[int, str]] = []
    for line_num, line in enumerate(lines, 1):
        # Skip pure comments and docstrings
        stripped = line.strip()
        if stripped.startswith("#"):
            continue
        for pat in _REPO_LITERAL_PATTERNS:
            if pat.search(line):
                results.append((line_num, stripped[:120]))
                break
    return results


# ---------------------------------------------------------------------------
# Sub-check 1: hardcoded_repo_path
# ---------------------------------------------------------------------------


def check_hardcoded_repo_path(
    file_path: str,
    content: str,
) -> list["GateFinding"]:
    """Detect hardcoded repo-specific path literals in universal-classified files."""
    if not content.strip():
        return []

    # Vigil-specific gate files are allowed to contain repo path literals.
    if _is_ai_host_gate_file(file_path):
        return []

    hits = _find_repo_literals_in_text(content)
    if not hits:
        return []

    findings = []
    for line_num, snippet in hits:
        detail = f"Repo-specific literal at line {line_num}: {snippet!r}"
        findings.append(build_finding(
            check_id="implementation_overfit.hardcoded_repo_path",
            category=GateCategory.DRIFT,
            title=f"[implementation_overfit.hardcoded_repo_path] {file_path}:{line_num}",
            severity=GateSeverity.MEDIUM,
            impact=GateImpact.REVISE,
            summary=(
                f"{detail} in {file_path}. "
                "Hardcoded repo paths break project-agnosticism."
            ),
            recommendation=(
                "Move hardcoded path/constant to a repo-specific profile; "
                "import from profile instead of embedding literal."
            ),
            evidence=(EvidenceReference(
                kind="probe", path=file_path, detail=detail, ok=False,
            ),),
            repair_kind=RepairKind.EDIT_CANONICAL.value,
            executor_action=(
                "Move hardcoded path/constant to repo-specific profile; import from profile"
            ),
            proof_required="literal removed from file; constant lives in profile; grep confirms",
            allowlist_allowed=False,
            preferred_fix_shape="extract to profile constant; import at usage site",
        ))
        if len(findings) >= 15:
            break
    return findings


# ---------------------------------------------------------------------------
# Sub-check 2: assumes_single_language
# ---------------------------------------------------------------------------


def check_assumes_single_language(
    file_path: str,
    content: str,
) -> list["GateFinding"]:
    """Detect Python-only conditionals without else branch in language-neutral files."""
    if not content.strip():
        return []

    if _is_ai_host_gate_file(file_path):
        return []

    findings = []
    lines = content.splitlines()
    for line_num, line in enumerate(lines, 1):
        stripped = line.strip()
        if stripped.startswith("#"):
            continue
        for pat in _PYTHON_ONLY_PATTERNS:
            m = pat.search(line)
            if not m:
                continue
            # Calculate offset of match in full content
            content_offset = sum(len(l) + 1 for l in lines[:line_num - 1]) + m.start()
            if _has_else_branch(content, content_offset):
                continue

            detail = f"Python-only conditional at line {line_num} without else branch: {stripped[:100]!r}"
            findings.append(build_finding(
                check_id="implementation_overfit.assumes_single_language",
                category=GateCategory.DRIFT,
                title=f"[implementation_overfit.assumes_single_language] {file_path}:{line_num}",
                severity=GateSeverity.MEDIUM,
                impact=GateImpact.REVISE,
                summary=(
                    f"{detail} in {file_path}. "
                    "Language-neutral files must handle multiple languages."
                ),
                recommendation=(
                    "Add language-aware branch via source_analysis.get_language_id() "
                    "or an explicit else/elif covering other languages."
                ),
                evidence=(EvidenceReference(
                    kind="probe", path=file_path, detail=detail, ok=False,
                ),),
                repair_kind=RepairKind.VALIDATE_BOUNDARY.value,
                executor_action=(
                    "Add language-aware branch via source_analysis.get_language_id()"
                ),
                proof_required="else/elif branch present; other languages handled; tests pass",
                allowlist_allowed=True,
                preferred_fix_shape="if lang == 'python': ... elif lang in ('js', 'ts'): ... else: ...",
            ))
            break
        if len(findings) >= 15:
            break
    return findings


# ---------------------------------------------------------------------------
# Sub-check 3: fake_generic_helper
# ---------------------------------------------------------------------------


def check_fake_generic_helper(
    file_path: str,
    content: str,
) -> list["GateFinding"]:
    """Detect functions named generic_*/universal_*/common_* that contain repo literals."""
    if not content.strip():
        return []

    if _is_ai_host_gate_file(file_path):
        return []

    import ast
    findings: list = []
    # B4 (2026-04-23): replaces silent `except SyntaxError: return []` — now
    # meta.syntax_parse_error is emitted so broken Python is not invisible.
    tree = parse_python_source_or_emit_finding(
        content,
        rel_path=normalize_path(file_path),
        emit_finding=findings.append,
        emitting_gate="implementation_overfit.fake_generic_helper",
    )
    if tree is None:
        return findings

    lines = content.splitlines()

    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        name = node.name.lower()
        if not any(name.startswith(prefix) for prefix in _GENERIC_PREFIXES):
            continue

        # Extract function body text
        start = node.lineno - 1
        end = getattr(node, "end_lineno", node.lineno)
        func_lines = lines[start:end]
        func_text = "\n".join(func_lines)

        repo_hits = _find_repo_literals_in_text(func_text)
        if not repo_hits:
            continue

        func_line = node.lineno
        first_hit_line, first_hit_snippet = repo_hits[0]

        detail = (
            f"Function {node.name!r} (line {func_line}) named as generic helper "
            f"but contains repo literal at relative line {first_hit_line}: {first_hit_snippet!r}"
        )
        findings.append(build_finding(
            check_id="implementation_overfit.fake_generic_helper",
            category=GateCategory.DRIFT,
            title=f"[implementation_overfit.fake_generic_helper] {file_path}:{func_line}:{node.name}",
            severity=GateSeverity.MEDIUM,
            impact=GateImpact.REVISE,
            summary=(
                f"{detail} in {file_path}. "
                "A function with a generic name must not contain repo-specific literals."
            ),
            recommendation=(
                f"Rename {node.name!r} to reflect its actual repo-specific coupling, "
                "OR remove the repo literals and make it truly generic."
            ),
            evidence=(EvidenceReference(
                kind="probe", path=file_path, detail=detail, ok=False,
            ),),
            repair_kind=RepairKind.NORMALIZE_SHAPE.value,
            executor_action=(
                "Rename to reflect actual coupling OR remove repo literals"
            ),
            proof_required="function renamed or literals extracted; grep confirms no false-generic name",
            allowlist_allowed=False,
            preferred_fix_shape="rename function OR extract literals to profile import",
        ))
    return findings


# ---------------------------------------------------------------------------
# Sub-check 4: env_tight_coupling
# ---------------------------------------------------------------------------


def check_env_tight_coupling(
    file_path: str,
    content: str,
) -> list["GateFinding"]:
    """Detect project-prefixed env var usage (VIGIL_*) in universal-classified modules."""
    if not content.strip():
        return []

    if _is_ai_host_gate_file(file_path):
        return []

    lines = content.splitlines()
    findings = []
    for line_num, line in enumerate(lines, 1):
        stripped = line.strip()
        if stripped.startswith("#"):
            continue
        m = _AI_HOST_ENV_PATTERN.search(line)
        if not m:
            continue

        snippet = stripped[:120]
        detail = f"Project-prefixed env var at line {line_num}: {snippet!r}"
        findings.append(build_finding(
            check_id="implementation_overfit.env_tight_coupling",
            category=GateCategory.DRIFT,
            title=f"[implementation_overfit.env_tight_coupling] {file_path}:{line_num}",
            severity=GateSeverity.MEDIUM,
            impact=GateImpact.REVISE,
            summary=(
                f"{detail} in {file_path}. "
                "Universal modules must not reference project-specific env vars directly."
            ),
            recommendation=(
                "Inject env var via constructor parameter or profile config. "
                "Do not read VIGIL_* vars directly in universal code."
            ),
            evidence=(EvidenceReference(
                kind="probe", path=file_path, detail=detail, ok=False,
            ),),
            repair_kind=RepairKind.VALIDATE_BOUNDARY.value,
            executor_action=(
                "Inject env var via parameter; remove direct os.environ.get('VIGIL_*') call"
            ),
            proof_required="no VIGIL_* env reads in module; value injected via parameter; tests pass",
            allowlist_allowed=True,
            preferred_fix_shape="def __init__(self, env_prefix: str = ''): ...",
        ))
        if len(findings) >= 10:
            break
    return findings


# ---------------------------------------------------------------------------
# Gate runner
# ---------------------------------------------------------------------------


def run_implementation_overfit_checks(ctx: PostExecGateContext):
    """Run all implementation_overfit sub-checks against touched files."""
    from vigil_forensic.gate_checks.common import build_check_result
    from vigil_forensic._shared import GateCategory

    snapshots = ctx.file_snapshots or {}
    all_findings = []

    for path, snap in snapshots.items():
        if not hasattr(snap, "text") or not snap.text:
            continue
        content = snap.text

        all_findings.extend(check_hardcoded_repo_path(path, content))
        all_findings.extend(check_assumes_single_language(path, content))
        all_findings.extend(check_fake_generic_helper(path, content))
        all_findings.extend(check_env_tight_coupling(path, content))

        if len(all_findings) >= 50:
            break

    return build_check_result(
        check_id="implementation_overfit",
        category=GateCategory.DRIFT,
        findings=all_findings,
        notes=[],
    )
