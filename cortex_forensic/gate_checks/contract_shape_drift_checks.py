"""Contract shape drift forensic gate (Finding 6.4).

contract_shape_drift: detect dataclass field additions and removals between
HEAD~1 and the working tree.  Field rename is structurally undetectable (it
appears as a remove + add and is therefore reported as both), which is
intentional -- the caller is informed of each component change separately.

Severities:
  REMOVED field              -> MEDIUM  (potentially breaking for serialised state)
  ADDED   field WITH default -> LOW     (schema evolution, non-breaking)
  ADDED   field WITHOUT default (required) -> MEDIUM  (breaking for existing records)

api.public_function_signature_change sub-check (G.9):
  Compares public function parameter lists between prior (HEAD~1) and current.
  - Parameter removed or renamed (positional shift)  -> HIGH / REVISE
  - Degraded mode (no prior snapshot): fewer params than docstring describes -> WARN / WARN
  allowlist_allowed=False for all signature findings.

F18a (2026-04-23): AI-Host-specific new-class checks moved to
``SYSTEM/pipeline/gates/cross_cutting_checks/ai_host_contract_checks.py``.
The following sub-checks are NOT emitted by this universal gate any more:
  - ``contract_shape_drift.new_class_missing_identity``
  - ``contract_shape_drift.new_class_missing_schema_version``
The helpers they depend on (``IDENTITY_FIELDS``, ``DATACLASS_RE``,
``_is_exempt``, ``_extract_dataclass_fields``) remain here for AI-Host's
``ai_host_contract_checks`` to import.

Fails open: git unavailable or any I/O error -> skip file, never crash.
"""
from __future__ import annotations

import ast
import logging
import re

from cortex_forensic._shared import EvidenceReference, GateCategory, GateImpact, GateSeverity, RepairKind
from cortex_forensic.gate_models import PostExecGateContext
from ..source_analysis import is_source_file
from .common import build_check_result, build_finding, normalize_path
from cortex_forensic._git_utils import git_show as _git_show

_log = logging.getLogger(__name__)

# Identity fields expected on persistent @dataclass entities.
IDENTITY_FIELDS: frozenset[str] = frozenset(
    {"project_id", "task_id", "session_id", "attempt_id", "id", "run_id"}
)

# G.5: exemption markers in class docstring / body comments.
# A class is exempt from new-class G.5 checks if either word appears anywhere
# in its body (docstring or comment).
_EXEMPT_MARKERS_RE = re.compile(r"\b(internal|non-persisted)\b", re.IGNORECASE)

# Matches the body of a @dataclass block.  The pattern captures:
#   group 1 — class name
#   group 2 — indented body lines (one level, 4 spaces)
# NOTE: re.DOTALL is required so '.' spans newlines inside the body group.
DATACLASS_RE = re.compile(
    r"@dataclass[^\n]*\nclass\s+(\w+)[^\n]*:\n((?:    [^\n]*\n)*)",
    re.DOTALL,
)

# A field declaration line: exactly 4-space indent + identifier + colon + type annotation.
# Group 1 — field name.
# Group 2 — remainder of the line after the type annotation (may contain '=' for default).
FIELD_RE = re.compile(r"^    (\w+):\s[^\n]*(.*)", re.MULTILINE)


def _is_exempt(body: str) -> bool:
    """Return True if the dataclass body contains an exemption marker.

    A class is exempt from the G.5 new-class identity/schema_version checks
    when its indented body (docstring or any comment line) contains the word
    "internal" or "non-persisted".  The check is case-insensitive.

    Args:
        body: The indented body block captured by DATACLASS_RE group 2.

    Returns:
        True when an exemption marker is found; False otherwise.
    """
    return bool(_EXEMPT_MARKERS_RE.search(body))


def _field_has_default(remainder: str) -> bool:
    """Return True if the field line contains an assignment (``=``) indicating
    a default value or ``default_factory`` via ``field(...)``.

    The ``remainder`` argument is everything on the field line after the type
    annotation identifier.  An ``=`` anywhere in that text means the field has
    a default; its absence means the field is required.
    """
    return "=" in remainder


def _extract_dataclass_fields(content: str) -> dict[str, dict[str, bool]]:
    """Return ``{class_name: {field_name: has_default}}`` for every @dataclass in *content*.

    ``has_default`` is ``True`` when the field carries a default value or
    ``default_factory`` (i.e. ``field_name: type = ...`` or
    ``field_name: type = field(default_factory=...)``).  ``False`` means the
    field is required -- adding it is a breaking change for existing records.

    Only direct body lines (4-space indent) are considered to avoid matching
    nested class or method bodies.  Returns an empty dict when *content*
    contains no dataclasses.
    """
    result: dict[str, dict[str, bool]] = {}
    for m in DATACLASS_RE.finditer(content):
        class_name = m.group(1)
        body = m.group(2)
        fields: dict[str, bool] = {}
        for field_match in FIELD_RE.finditer(body):
            field_name = field_match.group(1)
            line_tail = field_match.group(0)  # full matched line
            fields[field_name] = _field_has_default(line_tail)
        result[class_name] = fields
    return result


# ---------------------------------------------------------------------------
# G.9: Public function signature drift helpers
# ---------------------------------------------------------------------------


def _extract_public_func_signatures(content: str) -> dict[str, list[str]]:
    """Return ``{func_name: [param_name, ...]}`` for every top-level public
    function in *content*.

    Only module-level ``def`` statements are considered (not class methods).
    Names starting with ``_`` are skipped.
    Returns empty dict on SyntaxError.

    The ``self`` and ``cls`` parameters are excluded from the returned list
    because they are not part of the public API contract.
    """
    try:
        tree = ast.parse(content)
    except SyntaxError:
        return {}

    result: dict[str, list[str]] = {}
    for node in ast.iter_child_nodes(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        if node.name.startswith("_"):
            continue
        params: list[str] = []
        for arg in node.args.posonlyargs + node.args.args + node.args.kwonlyargs:
            if arg.arg in ("self", "cls"):
                continue
            params.append(arg.arg)
        if node.args.vararg:
            params.append(f"*{node.args.vararg.arg}")
        if node.args.kwarg:
            params.append(f"**{node.args.kwarg.arg}")
        result[node.name] = params
    return result


def _count_docstring_params(content: str, func_name: str) -> int:
    """Heuristic: count ``:param`` / ``Args:`` entries in the docstring of
    *func_name* as a proxy for the expected number of parameters.

    Used when prior snapshot is unavailable (degraded mode).
    Returns 0 if no docstring or no param entries found.
    """
    try:
        tree = ast.parse(content)
    except SyntaxError:
        return 0

    for node in ast.iter_child_nodes(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        if node.name != func_name:
            continue
        docstring = ast.get_docstring(node) or ""
        if not docstring:
            return 0
        # Support both Sphinx-style (:param x:) and Google-style (under Args:).
        sphinx_params = re.findall(r":param\s+\w+", docstring)
        google_params = re.findall(r"^\s{4,}\w+\s*:", docstring, re.MULTILINE)
        return max(len(sphinx_params), len(google_params))
    return 0


def _run_api_signature_checks(
    normalized: str,
    prior_content: str | None,
    current_content: str,
) -> list:
    """Return findings for public function signature changes in a single file.

    When *prior_content* is available, compare parameter lists directly.
    When *prior_content* is None (new file or git unavailable), fall back to
    comparing current param count against docstring-described param count.
    """
    from cortex_forensic._shared import EvidenceReference, GateCategory, GateImpact, GateSeverity

    findings_out = []
    current_sigs = _extract_public_func_signatures(current_content)

    if prior_content is not None:
        prior_sigs = _extract_public_func_signatures(prior_content)
        for func_name, current_params in current_sigs.items():
            if func_name not in prior_sigs:
                # New function — not a regression.
                continue
            prior_params = prior_sigs[func_name]
            if prior_params == current_params:
                continue
            # Detect removed or renamed (positional mismatch) parameters.
            removed = [p for p in prior_params if p not in current_params]
            if not removed:
                # Only additions — not a breaking change.
                continue
            findings_out.append(
                build_finding(
                    check_id="api.public_function_signature_change",
                    category=GateCategory.DRIFT,
                    title=(
                        f"Public API signature changed: {func_name} — "
                        f"parameter(s) removed/renamed"
                    ),
                    severity=GateSeverity.HIGH,
                    impact=GateImpact.REVISE,
                    summary=(
                        f"{normalized}::{func_name} — prior params: {prior_params}, "
                        f"current params: {current_params}. "
                        f"Removed/renamed: {removed}."
                    ),
                    recommendation=(
                        f"Public API signature changed: {func_name}. "
                        f"Either revert, add deprecation shim, or document as breaking change."
                    ),
                    evidence=[
                        EvidenceReference(
                            kind="file",
                            path=normalized,
                            detail=(
                                f"func {func_name}: prior={prior_params}, "
                                f"current={current_params}"
                            ),
                        )
                    ],
                    repair_kind=RepairKind.FIX_CONTRACT.value,
                    executor_action=(
                        f"Public API signature changed: {func_name}. "
                        f"Either revert, add deprecation shim, or document as breaking change."
                    ),
                    proof_required=(
                        "all external callers updated; deprecation warning added if kept; "
                        "CHANGELOG entry"
                    ),
                    allowlist_allowed=False,
                )
            )
    else:
        # Degraded mode: no prior snapshot.  Compare current param count against
        # what the docstring claims.
        for func_name, current_params in current_sigs.items():
            non_variadic = [p for p in current_params if not p.startswith(("*", "**"))]
            doc_count = _count_docstring_params(current_content, func_name)
            if doc_count > 0 and len(non_variadic) < doc_count:
                findings_out.append(
                    build_finding(
                        check_id="api.public_function_signature_change",
                        category=GateCategory.DRIFT,
                        title=(
                            f"Public API signature possibly narrowed: {func_name} "
                            f"has fewer params than docstring describes"
                        ),
                        severity=GateSeverity.MEDIUM,
                        impact=GateImpact.WARN,
                        summary=(
                            f"{normalized}::{func_name} — current params ({len(non_variadic)}): "
                            f"{non_variadic}; docstring describes {doc_count} param(s). "
                            f"Prior snapshot unavailable — degraded detection."
                        ),
                        recommendation=(
                            f"Public API signature may have been narrowed: {func_name}. "
                            f"Verify current param list matches documented API. "
                            f"If intentional, update the docstring."
                        ),
                        evidence=[
                            EvidenceReference(
                                kind="file",
                                path=normalized,
                                detail=(
                                    f"func {func_name}: {len(non_variadic)} params vs "
                                    f"{doc_count} documented"
                                ),
                            )
                        ],
                        repair_kind=RepairKind.FIX_CONTRACT.value,
                        executor_action=(
                            f"Public API signature changed: {func_name}. "
                            f"Either revert, add deprecation shim, or document as breaking change."
                        ),
                        proof_required=(
                            "all external callers updated; deprecation warning added if kept; "
                            "CHANGELOG entry"
                        ),
                        allowlist_allowed=False,
                    )
                )

    return findings_out


def run_contract_shape_drift_checks(ctx: PostExecGateContext):
    """Emit findings for dataclass field removals (MEDIUM) and additions (LOW).

    For each changed .py file:
    - Fetch prior content via git show HEAD~1.
    - Extract @dataclass field sets for every class before and after.
    - For classes present in both snapshots, compare field sets.
    - REMOVED fields -> MEDIUM finding.
    - ADDED   fields -> LOW    finding.

    New files (no prior content) and non-.py paths are skipped.
    Fails open: any exception -> skip file.
    """
    findings = []

    for raw_path in ctx.changed_files_observed:
        normalized = normalize_path(raw_path)
        if not is_source_file(normalized):
            continue

        prior = _git_show(normalized)
        if prior is None:
            # New file — universal contract_shape_drift only reasons about
            # field-level drift vs. a prior snapshot, so nothing to emit here.
            # AI-Host-specific "new class missing identity / schema_version"
            # checks moved to SYSTEM/pipeline/gates/cross_cutting_checks/
            # ai_host_contract_checks.py (F18a).
            continue

        abs_path = ctx.project_dir / normalized
        try:
            current = abs_path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError) as exc:
            _log.debug("contract_shape_drift: cannot read current file %s: %s", normalized, exc)
            continue

        before_map = _extract_dataclass_fields(prior)
        after_map = _extract_dataclass_fields(current)

        for class_name, before_fields in before_map.items():
            if class_name not in after_map:
                # Entire class removed — out of scope for field-level drift.
                continue
            after_fields = after_map[class_name]

            removed = set(before_fields.keys()) - set(after_fields.keys())
            added = set(after_fields.keys()) - set(before_fields.keys())

            if removed:
                findings.append(
                    build_finding(
                        check_id="contract_shape_drift.field_removed",
                        category=GateCategory.DRIFT,
                        title="Dataclass field(s) removed -- potential breaking schema change",
                        severity=GateSeverity.MEDIUM,
                        impact=GateImpact.REVISE,
                        summary=(
                            f"{normalized}::{class_name} -- removed field(s): "
                            f"{', '.join(sorted(removed))}."
                        ),
                        recommendation=(
                            "Removing dataclass fields can break deserialisation of persisted "
                            "state.  Verify that no stored artefacts rely on the removed "
                            f"field(s) before merging this change to {class_name}."
                        ),
                        evidence=[
                            EvidenceReference(
                                kind="file",
                                path=normalized,
                                detail=f"class {class_name}: removed {sorted(removed)}",
                            )
                        ],
                    
                        repair_kind='fix_contract',
                        executor_action='Fix contract drift',
                        proof_required='Contract fields stable',
                        allowlist_allowed=False,
                    )
                )

            # Split added fields: required (no default) vs optional (has default).
            required_added = sorted(f for f in added if not after_fields[f])
            optional_added = sorted(f for f in added if after_fields[f])

            if required_added:
                findings.append(
                    build_finding(
                        check_id="contract_shape_drift.required_field_added",
                        category=GateCategory.DRIFT,
                        title="Dataclass required field(s) added -- breaking schema change",
                        severity=GateSeverity.MEDIUM,
                        impact=GateImpact.REVISE,
                        summary=(
                            f"{normalized}::{class_name} -- added required field(s) (no default): "
                            f"{', '.join(required_added)}."
                        ),
                        recommendation=(
                            "Adding required fields (no default value) breaks deserialisation of "
                            "existing persisted records and all existing construction sites.  "
                            f"Add a default value to each new field in {class_name}, or perform "
                            "a coordinated migration of all persisted state."
                        ),
                        evidence=[
                            EvidenceReference(
                                kind="file",
                                path=normalized,
                                detail=f"class {class_name}: added required {required_added}",
                            )
                        ],
                    
                        repair_kind='fix_contract',
                        executor_action='Fix contract drift',
                        proof_required='Contract fields stable',
                        allowlist_allowed=False,
                    )
                )

            if optional_added:
                findings.append(
                    build_finding(
                        check_id="contract_shape_drift.field_added",
                        category=GateCategory.DRIFT,
                        title="Dataclass field(s) added -- schema evolution detected",
                        severity=GateSeverity.LOW,
                        impact=GateImpact.REVISE,
                        summary=(
                            f"{normalized}::{class_name} -- added field(s) with defaults: "
                            f"{', '.join(optional_added)}."
                        ),
                        recommendation=(
                            "New dataclass fields are non-breaking when they carry defaults.  "
                            "Confirm that the new field(s) have default values or that all "
                            f"construction sites of {class_name} have been updated."
                        ),
                        evidence=[
                            EvidenceReference(
                                kind="file",
                                path=normalized,
                                detail=f"class {class_name}: added optional {optional_added}",
                            )
                        ],
                    
                        repair_kind='fix_contract',
                        executor_action='Fix contract drift',
                        proof_required='Contract fields stable',
                        allowlist_allowed=False,
                    )
                )

    # G.9: api.public_function_signature_change sub-check — piggybacks on the
    # same per-file loop context already built above.  Re-walk changed_files_observed
    # to keep the two concerns cleanly separated inside this function.
    for raw_path in ctx.changed_files_observed:
        normalized = normalize_path(raw_path)
        if not is_source_file(normalized):
            continue
        abs_path = ctx.project_dir / normalized
        try:
            current = abs_path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError) as exc:
            _log.debug(
                "contract_shape_drift(sig): cannot read current file %s: %s",
                normalized,
                exc,
            )
            continue
        prior = _git_show(normalized)
        findings.extend(_run_api_signature_checks(normalized, prior, current))

    return build_check_result(
        check_id="contract_shape_drift",
        category=GateCategory.DRIFT,
        findings=findings,
    )
