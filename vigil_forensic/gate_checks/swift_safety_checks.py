"""Swift-specific forensic gates — force-unwrap and implicitly-unwrapped optionals.

Both detectors are AST-based (tree-sitter-swift) and therefore precise: they
key off the EXACT node types the grammar emits, with zero overlap against the
look-alikes that a regex would false-positive on.

Detectors
---------
``swift.force_unwrap``
    A force-unwrap (``value!``) is a ``postfix_expression`` whose last child is
    a ``bang`` token.  This is grammatically distinct from:
      - ``a != b``   -> ``infix_expression`` (a ``custom_operator``/comparison),
      - ``!flag``    -> ``prefix_expression``,
      - ``try!``     -> ``try_operator`` inside a ``try_expression``,
    so none of those are flagged.  Force-unwraps crash at runtime when the
    operand is nil, so each is surfaced as a MEDIUM runtime-behavior finding.

``swift.implicitly_unwrapped_optional``
    An implicitly-unwrapped optional declaration (``var x: T!``) is a
    ``type_annotation`` whose last child is a ``!`` token.  These defer a nil
    crash to first use; surfaced as a LOW finding.

Both gates:
    - run ONLY on files whose ``get_language_id`` is ``"swift"``;
    - skip Swift test files (``*Tests.swift`` / ``*Test.swift``);
    - fail OPEN (any parse error -> no findings, never raises);
    - honor the standard inline allowlist convention via ``has_allowlist_for``.
"""
from __future__ import annotations

import logging

from vigil_forensic._shared import EvidenceReference, GateCategory, GateImpact, GateSeverity
from vigil_forensic.gate_models import PostExecGateContext
from ..source_analysis import get_language_id, is_test_file
from .common import build_check_result, build_finding, has_allowlist_for, iter_touched_snapshots

_log = logging.getLogger(__name__)

_FORCE_UNWRAP_CHECK = "swift.force_unwrap"
_IUO_CHECK = "swift.implicitly_unwrapped_optional"


def _swift_snapshots(ctx: PostExecGateContext):
    """Yield (snapshot) for touched files that are non-test Swift source."""
    for snapshot in iter_touched_snapshots(ctx):
        if not getattr(snapshot, "exists", False):
            continue
        if get_language_id(snapshot.path) != "swift":
            continue
        if is_test_file(snapshot.path):
            continue
        yield snapshot


def _force_unwrap_lines(text: str) -> list[int]:
    """Return sorted 1-based line numbers of force-unwrap (``x!``) sites.

    A force-unwrap is a ``postfix_expression`` whose final child is a ``bang``
    token.  Returns ``[]`` on any parse failure (fail-open).
    """
    try:
        from vigil_mapper.source_adapters._treesitter import parse_bytes, walk_named, node_line
    except Exception:  # pragma: no cover -- treesitter helper unavailable
        return []

    try:
        root = parse_bytes("swift", text.encode("utf-8", errors="replace"))
    except Exception:  # pragma: no cover -- fail-open on parse error
        _log.debug("_force_unwrap_lines: parse failed", exc_info=True)
        return []

    lines: set[int] = set()
    for node in walk_named(root, "postfix_expression"):
        # The grammar emits the bang as the LAST child of the postfix_expression
        # (e.g. `value` + `!`).  An optional-chaining `?` is a different node, so
        # only `bang` matches here.
        children = list(node.children)
        if children and children[-1].type == "bang":
            lines.add(node_line(node))
    return sorted(lines)


def _iuo_lines(text: str) -> list[int]:
    """Return sorted 1-based line numbers of implicitly-unwrapped optional
    declarations (``var x: T!``).

    Detected as a ``type_annotation`` whose final child is a literal ``!``
    token.  Returns ``[]`` on any parse failure (fail-open).
    """
    try:
        from vigil_mapper.source_adapters._treesitter import parse_bytes, walk_named, node_line
    except Exception:  # pragma: no cover
        return []

    try:
        root = parse_bytes("swift", text.encode("utf-8", errors="replace"))
    except Exception:  # pragma: no cover
        _log.debug("_iuo_lines: parse failed", exc_info=True)
        return []

    lines: set[int] = set()
    for node in walk_named(root, "type_annotation"):
        children = list(node.children)
        # Last child is the bare `!` token (an UNNAMED node) for `: T!`.
        if children and not children[-1].is_named and children[-1].type == "!":
            lines.add(node_line(node))
    return sorted(lines)


def run_swift_force_unwrap_checks(ctx: PostExecGateContext):
    """Flag force-unwrap (``x!``) operators in Swift source (HIGH — runtime crash risk)."""
    findings = []
    for snapshot in _swift_snapshots(ctx):
        for line in _force_unwrap_lines(snapshot.text):
            if has_allowlist_for(snapshot.text, _FORCE_UNWRAP_CHECK, line):
                continue
            findings.append(build_finding(
                check_id=_FORCE_UNWRAP_CHECK,
                category=GateCategory.RUNTIME_BEHAVIOR,
                title="Swift force-unwrap of optional",
                severity=GateSeverity.HIGH,
                impact=GateImpact.WARN,
                summary=(
                    f"{snapshot.path}:{line} force-unwraps an optional with `!`; "
                    f"this crashes at runtime if the value is nil."
                ),
                recommendation=(
                    "Use optional binding (`if let` / `guard let`), `??` with a "
                    "default, or optional chaining (`?.`) instead of `!`."
                ),
                evidence=[EvidenceReference(kind="file", path=snapshot.path, detail=f"line {line}")],
                executor_action=(
                    f"Replace the force-unwrap at {snapshot.path}:{line} with a "
                    f"safe optional binding or default."
                ),
            ))
    return build_check_result(
        check_id=_FORCE_UNWRAP_CHECK,
        category=GateCategory.RUNTIME_BEHAVIOR,
        findings=findings,
    )


def run_swift_iuo_checks(ctx: PostExecGateContext):
    """Flag implicitly-unwrapped optional declarations (``var x: T!``) (LOW)."""
    findings = []
    for snapshot in _swift_snapshots(ctx):
        for line in _iuo_lines(snapshot.text):
            if has_allowlist_for(snapshot.text, _IUO_CHECK, line):
                continue
            findings.append(build_finding(
                check_id=_IUO_CHECK,
                category=GateCategory.RUNTIME_BEHAVIOR,
                title="Swift implicitly-unwrapped optional",
                severity=GateSeverity.LOW,
                impact=GateImpact.WARN,
                summary=(
                    f"{snapshot.path}:{line} declares an implicitly-unwrapped "
                    f"optional (`: T!`); access before assignment crashes at runtime."
                ),
                recommendation=(
                    "Prefer a regular optional (`: T?`) with explicit unwrapping, "
                    "or a non-optional initialised at declaration / in `init`."
                ),
                evidence=[EvidenceReference(kind="file", path=snapshot.path, detail=f"line {line}")],
                executor_action=(
                    f"Change the implicitly-unwrapped optional at {snapshot.path}:{line} "
                    f"to a regular optional or a definitely-initialised property."
                ),
            ))
    return build_check_result(
        check_id=_IUO_CHECK,
        category=GateCategory.RUNTIME_BEHAVIOR,
        findings=findings,
    )
