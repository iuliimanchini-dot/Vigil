from __future__ import annotations

import ast
from pathlib import Path
from typing import Optional
from vigil_forensic._shared import EvidenceReference, GateCategory, GateImpact, GateSeverity, RepairKind
from vigil_forensic.gate_models import PostExecGateContext
from .common import build_check_result, build_finding, has_allowlist_for, iter_touched_snapshots, normalize_path
from ._ast_helpers import parse_python_source_or_emit_finding
from ..source_analysis import is_source_file
import logging
_log = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Sprint B2 (2026-04-23): TestTopology-first applicability ordering.
#
# Each sub-check consults TestTopology.role(rel_path) BEFORE running its
# detection logic. Files whose role is not in the applicable set are
# skipped. This replaces the ad-hoc ``basename.startswith("test_")``
# heuristic at the top of ``run_test_quality_checks``.
#
# Graceful degradation: if ctx.project_context.test_topology is None
# (integration step lands later), the gate falls back to the legacy
# ``_is_test_path`` path-based check. That path preserves the pre-B2
# behaviour exactly so the rollout is safe.
# ---------------------------------------------------------------------------


def _get_topology(ctx: PostExecGateContext):
    project_context = getattr(ctx, "project_context", None)
    if project_context is None:
        return None
    return getattr(project_context, "test_topology", None)


def _applicable_roles_for(check_id: str) -> frozenset[str]:
    """Return the set of roles for which ``check_id`` is applicable.

    Per Sprint B2 plan: all test_quality sub-checks run on ``test_module``
    surfaces only. Helpers, fixtures, and standalone utility tests are
    explicitly out-of-scope.
    """
    # Every sub-check in this module targets the same surface today.
    return frozenset({"test_module"})


def _skip_for_topology(ctx: PostExecGateContext, rel_path: str, check_id: str) -> bool:
    """Return True when topology says this file is not in scope for check_id.

    * Topology present & role not in applicable set → skip (True).
    * Topology present & role in applicable set     → proceed (False).
    * Topology absent                                → proceed (False) — the
      outer loop has already filtered via legacy ``_is_test_path`` or
      basename guard, so we can safely defer to that behaviour.
    """
    topology = _get_topology(ctx)
    if topology is None:
        return False
    role = topology.role(rel_path)
    return role not in _applicable_roles_for(check_id)


def _get_module_index(ctx: PostExecGateContext):
    project_context = getattr(ctx, "project_context", None)
    if project_context is None:
        return None
    return getattr(project_context, "python_module_index", None)


# ---------------------------------------------------------------------------
# Shared helpers (used by test_quality + new masking / empty / simulated gates)
# ---------------------------------------------------------------------------


def _is_test_path(path: str) -> bool:
    """True if ``path`` looks like a pytest test module.

    Pytest discovers tests when the filename matches ``test_*.py`` or
    ``*_test.py`` AND pytest is run from a location that collects the file.
    To keep false-positive rate low we require **either**:

        - file lives under a ``tests/`` or ``test/`` directory component, OR
        - filename ends with ``_test.py`` (unambiguous suffix convention).

    A file merely named ``test_foo.py`` outside a test directory (for example
    ``BRAIN/autoforensics/gate_checks/test_quality_checks.py``) is treated as
    production code — it carries the ``test_`` prefix for semantic reasons
    but pytest will not collect it in a well-configured project.
    """
    normalized = path.replace("\\", "/")
    basename = normalized.rsplit("/", 1)[-1]
    if not basename.endswith(".py"):
        return False
    parts = normalized.split("/")
    in_tests_dir = any(part in ("tests", "test") for part in parts[:-1])
    if in_tests_dir and (basename.startswith("test_") or basename.endswith("_test.py")):
        return True
    if basename.endswith("_test.py"):
        return True
    return False


def _basename(path: str) -> str:
    return path.replace("\\", "/").rsplit("/", 1)[-1]


_TEST_HELPER_BASENAMES: frozenset[str] = frozenset({
    "conftest.py",
    "test_helpers.py",
    "test_utils.py",
    "test_fixtures.py",
    "testing_utils.py",
    "__init__.py",
})


def _dotted_name(node: ast.AST) -> str | None:
    """Return dotted attribute name for ``ast.Name`` / ``ast.Attribute`` chains."""
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        base = _dotted_name(node.value)
        if base is None:
            return None
        return f"{base}.{node.attr}"
    return None


def _root_name(node: ast.AST) -> str | None:
    """Return the left-most identifier in a call target (``pkg.mod.fn`` → ``pkg``)."""
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return _root_name(node.value)
    return None


def _is_pytest_ref(dotted: str) -> bool:
    """True if ``dotted`` is a pytest-namespaced reference like ``pytest.skip``."""
    return dotted.startswith("pytest.") or dotted.startswith("_pytest.")


def _keyword_const(call: ast.Call, name: str):
    """Return the literal value of ``name=`` keyword, or ``None`` if not a constant."""
    for kw in call.keywords or []:
        if kw.arg == name and isinstance(kw.value, ast.Constant):
            return kw.value.value
    return None


def _iter_test_functions(tree: ast.AST):
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name.startswith("test_"):
            yield node


# ---------------------------------------------------------------------------
# Existing test_quality gate
# ---------------------------------------------------------------------------


def run_test_quality_checks(ctx: PostExecGateContext):
    """Detect tests that verify themselves instead of project code.

    Common anti-patterns:
    1. Test defines a function and immediately tests it in the same file
       without importing anything from the project.
    2. Test file has zero imports from the project source tree.
    3. Test asserts only on literals (e.g. ``assert 1 + 1 == 2``).

    Sprint B2 ordering: each sub-check queries ``ctx.project_context.test_topology``
    for applicability BEFORE running detection. When topology is absent
    (integration lands later), fallback to legacy ``_is_test_path`` /
    basename discipline preserves behaviour.
    """
    findings = []
    topology = _get_topology(ctx)

    for snapshot in iter_touched_snapshots(ctx):
        if not snapshot.exists or not is_source_file(snapshot.path):
            continue
        if not snapshot.text.strip():
            continue

        rel_path = normalize_path(snapshot.path)

        # Topology-first applicability.
        if topology is not None:
            role = topology.role(rel_path)
            if role not in _applicable_roles_for("test_quality"):
                continue
        else:
            # Legacy fallback — preserved for safe rollout before the
            # integration step wires ProjectContext.test_topology. The
            # legacy rule was ``basename.startswith("test_")`` but with
            # P1 single-source discipline we prefer ``_is_test_path``
            # which is already the de-facto rule used by sibling gates.
            # Keep the old permissive rule too so no new tests fire that
            # the pre-B2 run wouldn't have — strictly narrower is OK,
            # strictly wider is not.
            basename = snapshot.path.rsplit("/", 1)[-1] if "/" in snapshot.path else snapshot.path
            if not basename.startswith("test_"):
                continue

        findings.extend(_check_no_project_imports(snapshot.path, snapshot.text, ctx, emit_finding=findings.append))
        findings.extend(_check_self_defined_then_tested(snapshot.path, snapshot.text, emit_finding=findings.append))
        findings.extend(_check_literal_only_asserts(snapshot.path, snapshot.text, emit_finding=findings.append))

    return build_check_result(
        check_id="test_quality",
        category=GateCategory.TESTING,
        findings=findings,
    )


# ---------------------------------------------------------------------------
# Gate: test_suite_masking
# ---------------------------------------------------------------------------


def run_test_suite_masking_checks(ctx: PostExecGateContext):
    """Detect xfail / skip / importorskip patterns used to hide failing tests.

    Sprint B2: topology-first applicability. Only ``test_module`` files
    are inspected; helpers / fixtures / standalone_utility_test are skipped.
    """
    findings = []
    topology = _get_topology(ctx)
    for snapshot in iter_touched_snapshots(ctx):
        if not snapshot.exists or not is_source_file(snapshot.path):
            continue
        if not snapshot.text.strip():
            continue

        rel_path = normalize_path(snapshot.path)
        if topology is not None:
            role = topology.role(rel_path)
            if role not in _applicable_roles_for("test_suite_masking"):
                continue
        else:
            # Legacy fallback preserves pre-B2 behaviour.
            if not _is_test_path(snapshot.path):
                continue

        findings.extend(_check_masking_patterns(snapshot.path, snapshot.text, emit_finding=findings.append))

    return build_check_result(
        check_id="test_suite_masking",
        category=GateCategory.TESTING,
        findings=findings,
    )


def _check_masking_patterns(path: str, text: str, *, emit_finding=None) -> list:
    # B4 (2026-04-23): fail-loud parse via shared helper.
    tree = parse_python_source_or_emit_finding(
        text,
        rel_path=normalize_path(path),
        emit_finding=emit_finding,
        emitting_gate="test_quality.masking_patterns",
        filename=path,
    )
    if tree is None:
        return []

    results: list = []

    # --- Decorator-based xfail / skip / skipif ---
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            continue
        for deco in getattr(node, "decorator_list", ()) or ():
            call = deco if isinstance(deco, ast.Call) else None
            target = call.func if call is not None else deco
            name_str = _dotted_name(target)
            if name_str is None:
                continue
            line_no = int(getattr(deco, "lineno", 0) or 0)
            if has_allowlist_for(text, "test_suite_masking", line_no):
                continue
            if name_str.endswith(".xfail"):
                strict_val = _keyword_const(call, "strict") if call is not None else None
                if strict_val is False:
                    results.append(_mk_masking_finding(
                        path, line_no,
                        severity=GateSeverity.HIGH,
                        title=f"xfail(strict=False) masks regressions: {path}:{line_no}",
                        detail="xfail_non_strict",
                        summary=(
                            f"{path}:{line_no} uses @pytest.mark.xfail(strict=False). "
                            "Non-strict xfail silently accepts unexpected passes and "
                            "hides the real verdict when the bug is fixed or the "
                            "test fails for a different reason."
                        ),
                    ))
                elif strict_val is True:
                    # Acceptable — skip.
                    continue
                else:
                    results.append(_mk_masking_finding(
                        path, line_no,
                        severity=GateSeverity.MEDIUM,
                        title=f"xfail without strict=True: {path}:{line_no}",
                        detail="xfail_missing_strict",
                        summary=(
                            f"{path}:{line_no} uses @pytest.mark.xfail without explicit "
                            "strict=True. Pytest's default is strict=False which masks "
                            "unexpected passes. Set strict=True or fix the test."
                        ),
                    ))
            elif name_str.endswith(".skip") and "mark" in name_str:
                results.append(_mk_masking_finding(
                    path, line_no,
                    severity=GateSeverity.HIGH,
                    title=f"@pytest.mark.skip unconditional: {path}:{line_no}",
                    detail="mark_skip_unconditional",
                    summary=(
                        f"{path}:{line_no} decorates a test with @pytest.mark.skip. "
                        "Unconditional skip hides a broken or abandoned test. "
                        "Replace with skipif(condition) or delete the test."
                    ),
                ))
            elif name_str.endswith(".skipif") and "mark" in name_str and call is not None and call.args:
                cond = call.args[0]
                if isinstance(cond, ast.Constant) and cond.value is True:
                    results.append(_mk_masking_finding(
                        path, line_no,
                        severity=GateSeverity.HIGH,
                        title=f"@pytest.mark.skipif(True, ...) literal: {path}:{line_no}",
                        detail="mark_skipif_literal_true",
                        summary=(
                            f"{path}:{line_no} uses @pytest.mark.skipif(True, ...). "
                            "Literal True condition is equivalent to unconditional "
                            "skip and masks a broken test."
                        ),
                    ))

    # --- Body-level skip / skipif / importorskip ---
    for fn in _iter_test_functions(tree):
        for node in ast.walk(fn):
            if not isinstance(node, ast.Call):
                continue
            name_str = _dotted_name(node.func)
            if name_str is None:
                continue
            line_no = int(getattr(node, "lineno", 0) or 0)
            if not _is_pytest_ref(name_str):
                continue
            if has_allowlist_for(text, "test_suite_masking", line_no):
                continue
            tail = name_str.rsplit(".", 1)[-1]
            if tail == "skip":
                results.append(_mk_masking_finding(
                    path, line_no,
                    severity=GateSeverity.HIGH,
                    title=f"pytest.skip() inside test body: {path}:{line_no}",
                    detail="unconditional_skip",
                    summary=(
                        f"{path}:{line_no} calls pytest.skip(...) inside a test "
                        "function body. Unconditional skip masks a broken test. "
                        "Use pytest.mark.skipif with a real condition, or fix the test."
                    ),
                ))
            elif tail == "skipif" and node.args:
                cond = node.args[0]
                if isinstance(cond, ast.Constant) and cond.value is True:
                    results.append(_mk_masking_finding(
                        path, line_no,
                        severity=GateSeverity.HIGH,
                        title=f"pytest.skipif(True, ...) literal condition: {path}:{line_no}",
                        detail="skipif_literal_true",
                        summary=(
                            f"{path}:{line_no} passes a literal True to "
                            "pytest.skipif(). That is equivalent to unconditional "
                            "skip and masks a broken test."
                        ),
                    ))
            elif tail == "importorskip":
                results.append(_mk_masking_finding(
                    path, line_no,
                    severity=GateSeverity.MEDIUM,
                    title=f"pytest.importorskip inside test body: {path}:{line_no}",
                    detail="importorskip_in_test",
                    summary=(
                        f"{path}:{line_no} calls pytest.importorskip(...) from "
                        "inside a test body. That pattern is acceptable at "
                        "module scope for optional dependencies but suspect "
                        "inside a test — it will silently skip the test if the "
                        "import is missing at runtime."
                    ),
                ))
    return results


def _mk_masking_finding(path: str, line_no: int, *, severity: GateSeverity, title: str, detail: str, summary: str):
    return build_finding(
        check_id=f"test_suite_masking.{detail}",
        category=GateCategory.TESTING,
        title=title,
        severity=severity,
        impact=GateImpact.REVISE,
        summary=summary,
        recommendation=(
            "Remove xfail/skip or mark strict=True and fix the underlying test. "
            "If the mask is intentional, add a justification docstring and "
            "suppress with `# noqa: test_suite_masking` on the decorator/call line."
        ),
        evidence=[EvidenceReference(kind="file", path=path, detail=f"{detail}:{line_no}")],
        repair_kind="remove_masking",
        executor_action="remove xfail/skip or mark strict=True and fix underlying test",
        proof_required="test passes without xfail/skip",
        allowlist_allowed=True,
    )


# ---------------------------------------------------------------------------
# Gate: empty_test_module
# ---------------------------------------------------------------------------


def run_empty_test_module_checks(ctx: PostExecGateContext):
    """Detect test modules that contain zero pytest tests.

    Sprint B2: topology decides applicability. In topology mode only
    ``test_module`` surfaces are inspected — files classified as
    ``fixture`` / ``helper`` / ``standalone_utility_test`` are skipped
    at the classifier level (no need for basename denylists inside the
    gate body).

    Legacy exclusions (preserved for fallback path):
    - conftest.py and well-known helper module names (test_helpers.py etc.).
    - Files that define pytest fixtures (``@pytest.fixture``) but no tests.
    - Files that declare ``pytest_plugins`` at module level.
    """
    findings = []
    topology = _get_topology(ctx)
    for snapshot in iter_touched_snapshots(ctx):
        if not snapshot.exists or not is_source_file(snapshot.path):
            continue
        if not snapshot.text.strip():
            continue

        rel_path = normalize_path(snapshot.path)
        if topology is not None:
            role = topology.role(rel_path)
            if role not in _applicable_roles_for("empty_test_module"):
                continue
        else:
            # Legacy fallback.
            if not _is_test_path(snapshot.path):
                continue
            if _basename(snapshot.path) in _TEST_HELPER_BASENAMES:
                continue

        findings.extend(_check_empty_test_module(snapshot.path, snapshot.text, emit_finding=findings.append))

    return build_check_result(
        check_id="empty_test_module",
        category=GateCategory.TESTING,
        findings=findings,
    )


def _check_empty_test_module(path: str, text: str, *, emit_finding=None) -> list:
    # B4 (2026-04-23): fail-loud parse via shared helper.
    tree = parse_python_source_or_emit_finding(
        text,
        rel_path=normalize_path(path),
        emit_finding=emit_finding,
        emitting_gate="test_quality.empty_test_module",
        filename=path,
    )
    if tree is None:
        return []

    # Module-level pytest_plugins = ... → fixture-config module, skip.
    for node in ast.iter_child_nodes(tree):
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name) and target.id == "pytest_plugins":
                    return []

    has_test_fn = False
    has_fixture = False
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            if node.name.startswith("test_"):
                has_test_fn = True
            for deco in node.decorator_list:
                name_str = _dotted_name(deco if not isinstance(deco, ast.Call) else deco.func)
                if name_str and (name_str.endswith(".fixture") or name_str == "fixture"):
                    has_fixture = True
        elif isinstance(node, ast.ClassDef):
            if node.name.startswith("Test"):
                for child in node.body:
                    if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)) and child.name.startswith("test_"):
                        has_test_fn = True
                        break

    if has_test_fn:
        return []
    if has_fixture:
        # Fixture-only module — acceptable, skip.
        return []
    if has_allowlist_for(text, "empty_test_module"):
        return []
    return [
        build_finding(
            check_id="empty_test_module",
            category=GateCategory.TESTING,
            title=f"Test module contains no tests: {path}",
            severity=GateSeverity.HIGH,
            impact=GateImpact.REVISE,
            summary=(
                f"{path} matches test-file naming conventions but defines zero "
                "`test_*` functions, zero `Test*` classes with `test_*` methods, "
                "zero `@pytest.fixture` definitions, and no `pytest_plugins` "
                "declaration. Pytest will collect nothing from this file, so it "
                "contributes no verification and silently 'passes'."
            ),
            recommendation=(
                "Add real tests, or rename the module to drop the `test_` prefix "
                "if it is a helper. If this is intentional (e.g. placeholder "
                "pending implementation), add `# noqa: empty_test_module` at "
                "module top with a justification docstring."
            ),
            evidence=[EvidenceReference(kind="file", path=path, detail="no_tests_defined")],
            repair_kind="add_test",
            executor_action="add test_* functions or rename module out of the test namespace",
            proof_required="pytest collects at least one test from the file",
            allowlist_allowed=True,
        )
    ]


# ---------------------------------------------------------------------------
# Gate: simulated_instead_of_executed_test
# ---------------------------------------------------------------------------


def run_simulated_test_checks(ctx: PostExecGateContext):
    """Detect tests that assert on locally-defined helpers instead of real code.

    Heuristic (AST-only, tuned for low FP):
    1. For each `def test_X(...)` in a test file:
       - Collect local Lambda / FunctionDef / ClassDef names defined inside body.
       - Collect all Call nodes inside the body.
       - Classify each call as local_def / project_call / other.
       - If local_def >= 1 AND project_call == 0 → flag as simulated.
    2. Tests with zero local defs or that touch project code are ignored.
    3. Files without any project imports are ignored (covered by
       test_quality.no_project_imports).
    """
    findings = []
    roots = ctx.source_package_roots
    if not roots:
        # Without known roots we cannot tell project calls from stdlib; skip.
        return build_check_result(
            check_id="simulated_instead_of_executed_test",
            category=GateCategory.TESTING,
            findings=(),
        )
    topology = _get_topology(ctx)
    for snapshot in iter_touched_snapshots(ctx):
        if not snapshot.exists or not is_source_file(snapshot.path):
            continue
        if not snapshot.text.strip():
            continue

        rel_path = normalize_path(snapshot.path)
        if topology is not None:
            role = topology.role(rel_path)
            if role not in _applicable_roles_for("simulated_instead_of_executed_test"):
                continue
        else:
            # Legacy fallback.
            if not _is_test_path(snapshot.path):
                continue

        findings.extend(_check_simulated_tests(snapshot.path, snapshot.text, roots, emit_finding=findings.append))

    return build_check_result(
        check_id="simulated_instead_of_executed_test",
        category=GateCategory.TESTING,
        findings=findings,
    )


def _check_simulated_tests(path: str, text: str, roots: tuple[str, ...], *, emit_finding=None) -> list:
    # B4 (2026-04-23): fail-loud parse via shared helper.
    tree = parse_python_source_or_emit_finding(
        text,
        rel_path=normalize_path(path),
        emit_finding=emit_finding,
        emitting_gate="test_quality.simulated_tests",
        filename=path,
    )
    if tree is None:
        return []

    module_aliases = _collect_project_import_aliases(tree, roots)

    results: list = []
    for fn in _iter_test_functions(tree):
        # Per-test scope = module imports + function-local imports. Many tests
        # use function-local imports to side-step collection-time failures.
        local_imports = _collect_project_import_aliases(fn, roots)
        project_aliases = module_aliases | local_imports
        if not project_aliases:
            continue  # covered by no_project_imports
        local_defs, local_lambda_vars = _collect_local_defs(fn)
        if not local_defs and not local_lambda_vars:
            continue

        local_def_calls = 0
        project_calls = 0
        for node in ast.walk(fn):
            if not isinstance(node, ast.Call):
                continue
            top_name = _root_name(node.func)
            if top_name is None:
                continue
            if top_name in local_defs or top_name in local_lambda_vars:
                local_def_calls += 1
            elif top_name in project_aliases:
                project_calls += 1

        if local_def_calls == 0:
            continue
        if project_calls > 0:
            continue

        line_no = int(getattr(fn, "lineno", 0) or 0)
        if has_allowlist_for(text, "simulated_instead_of_executed_test", line_no):
            continue
        defs_preview = ", ".join(sorted(local_defs | local_lambda_vars)[:3])
        results.append(build_finding(
            check_id="simulated_instead_of_executed_test",
            category=GateCategory.TESTING,
            title=f"Test exercises only local simulation: {path}:{line_no}::{fn.name}",
            severity=GateSeverity.MEDIUM,
            impact=GateImpact.REVISE,
            summary=(
                f"Test function {fn.name} at {path}:{line_no} defines local "
                f"helpers ({defs_preview}) and makes {local_def_calls} call(s) "
                "to them but zero calls to any symbol imported from the project "
                f"roots ({', '.join(roots)}). The test appears to verify a hand-"
                "rolled simulation of the behaviour rather than invoking the real "
                "production code."
            ),
            recommendation=(
                "Replace the local lambda/def with a call to the actual project "
                "function being tested. Local helpers are fine as test utilities "
                "only if the assertions call real project code afterwards."
            ),
            evidence=[EvidenceReference(kind="file", path=path, detail=f"simulated:{fn.name}:{line_no}")],
            repair_kind="add_test",
            executor_action="call the production function instead of a local simulation",
            proof_required="assertions exercise imported project symbols",
            allowlist_allowed=True,
        ))
    return results


def _collect_project_import_aliases(tree: ast.AST, roots: tuple[str, ...]) -> set[str]:
    """Return the set of names bound by imports from any project root.

    Walks the full AST subtree so it catches imports made inside test-function
    bodies as well as module-level imports.
    """
    aliases: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.module:
            if any(node.module.startswith(r) for r in roots):
                for alias in node.names:
                    aliases.add(alias.asname or alias.name.split(".")[0])
        elif isinstance(node, ast.Import):
            for alias in node.names:
                if any(alias.name.startswith(r) for r in roots):
                    aliases.add(alias.asname or alias.name.split(".")[0])
    return aliases


def _collect_local_defs(fn: ast.FunctionDef | ast.AsyncFunctionDef) -> tuple[set[str], set[str]]:
    """Return (named_defs, lambda_var_names) for symbols defined inside ``fn``.

    - named_defs:     names of local FunctionDef/AsyncFunctionDef/ClassDef.
    - lambda_var_names: names bound to Lambda via ``foo = lambda ...:``.
    """
    named_defs: set[str] = set()
    lambda_vars: set[str] = set()
    for node in ast.walk(fn):
        if node is fn:
            continue
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            named_defs.add(node.name)
        elif isinstance(node, ast.Assign) and isinstance(node.value, ast.Lambda):
            for target in node.targets:
                if isinstance(target, ast.Name):
                    lambda_vars.add(target.id)
    return named_defs, lambda_vars


def _check_no_project_imports(path: str, text: str, ctx: PostExecGateContext, *, emit_finding=None) -> list:
    """Flag test files that import nothing from the project.

    Sprint B2: once topology has confirmed ``role == "test_module"``, the
    check uses ``ctx.project_context.python_module_index`` (B1) when
    available to decide what counts as a project import — resolving the
    import against the project's declared layout is strictly more
    accurate than the legacy ``name.startswith(root)`` prefix match,
    which has false negatives for src-layout projects and false
    positives for packages that share a top-level name with stdlib.
    """
    # B4 (2026-04-23): fail-loud parse via shared helper. Previously this
    # deferred to ``syntax_validity_checks`` but did so silently; now the
    # meta finding also surfaces for cross-gate visibility.
    tree = parse_python_source_or_emit_finding(
        text,
        rel_path=normalize_path(path),
        emit_finding=emit_finding,
        emitting_gate="test_quality.no_project_imports",
        filename=path,
    )
    if tree is None:
        return []

    effective_roots = ctx.source_package_roots  # populated from project_dir at context build time
    module_index = _get_module_index(ctx)

    if not effective_roots and module_index is None:
        return []  # cannot determine project roots; skip rather than false-positive

    def _is_project_module(name: str) -> bool:
        """Decide whether ``name`` refers to a project-internal module.

        Preferred path (B1 available): resolve against PythonModuleIndex.
        Fallback path (legacy): prefix match vs source_package_roots.
        """
        if module_index is not None:
            outcome = module_index.resolve(name)
            if outcome.status == "resolved":
                return True
            if outcome.status == "missing_confident":
                return False
            # resolver_uncertain: fall through to root prefix check below so we
            # don't flag a file that legitimately imports a src-layout package.
        if effective_roots:
            return any(name.startswith(root) for root in effective_roots)
        return False

    has_project_import = False
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.module:
            if _is_project_module(node.module):
                has_project_import = True
                break
        elif isinstance(node, ast.Import):
            for alias in node.names:
                if _is_project_module(alias.name):
                    has_project_import = True
                    break
            if has_project_import:
                break

    if not has_project_import:
        # Check if there are any test functions at all
        has_tests = any(
            isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
            and node.name.startswith("test_")
            for node in ast.walk(tree)
        )
        if has_tests:
            return [
                build_finding(
                    check_id="test_quality.no_project_imports",
                    category=GateCategory.TESTING,
                    title=f"Test file imports nothing from project: {path}",
                    severity=GateSeverity.HIGH,
                    impact=GateImpact.REVISE,
                    summary=(
                        f"Test file {path} contains test functions but does not "
                        f"import from any project source root ({', '.join(effective_roots)}). "
                        "The tests may be verifying their own local definitions "
                        "rather than actual project behavior."
                    ),
                    recommendation=(
                        "Ensure tests import and exercise the actual project code, "
                        "not locally defined stubs or inline implementations."
                    ),
                    evidence=[EvidenceReference(kind="file", path=path, detail="no_project_imports")],
                
                    repair_kind='add_test',
                    executor_action='Add tests for coverage',
                    proof_required='Tests added/passing',
                    allowlist_allowed=True,
                )
            ]
    return []


def _check_self_defined_then_tested(path: str, text: str, *, emit_finding=None) -> list:
    """Flag when a test file defines non-test functions and only tests those."""
    # B4 (2026-04-23): fail-loud parse via shared helper.
    tree = parse_python_source_or_emit_finding(
        text,
        rel_path=normalize_path(path),
        emit_finding=emit_finding,
        emitting_gate="test_quality.self_defined_then_tested",
        filename=path,
    )
    if tree is None:
        return []

    # Collect top-level non-test function/class names defined in this file
    local_defs: set[str] = set()
    test_fns: list[ast.FunctionDef] = []
    for node in ast.iter_child_nodes(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            if node.name.startswith("test_"):
                test_fns.append(node)
            elif not node.name.startswith("_"):
                local_defs.add(node.name)
        elif isinstance(node, ast.ClassDef):
            if not node.name.startswith("Test"):
                local_defs.add(node.name)

    if not local_defs or not test_fns:
        return []

    # Check if test functions call local defs
    calls_local = 0
    calls_total = 0
    for test_fn in test_fns:
        for node in ast.walk(test_fn):
            if isinstance(node, ast.Call):
                calls_total += 1
                if isinstance(node.func, ast.Name) and node.func.id in local_defs:
                    calls_local += 1

    if calls_total > 0 and calls_local == calls_total:
        return [
            build_finding(
                check_id="test_quality.tests_own_definitions",
                category=GateCategory.TESTING,
                title=f"Tests only exercise locally defined code: {path}",
                severity=GateSeverity.HIGH,
                impact=GateImpact.REVISE,
                summary=(
                    f"Test file {path} defines {len(local_defs)} non-test function(s) "
                    f"({', '.join(sorted(local_defs)[:3])}) and all {calls_total} test "
                    "call(s) target these local definitions. The tests may be "
                    "verifying stub behavior rather than real project code."
                ),
                recommendation=(
                    "Tests should import and call the actual project implementation. "
                    "Local helper functions in tests are fine as utilities, but the "
                    "test assertions should verify imported project behavior."
                ),
                evidence=[EvidenceReference(kind="file", path=path, detail="self_testing")],
            
                repair_kind='add_test',
                executor_action='Add tests for coverage',
                proof_required='Tests added/passing',
                allowlist_allowed=True,
            )
        ]
    return []


def _check_literal_only_asserts(path: str, text: str, *, emit_finding=None) -> list:
    """Flag tests where all asserts compare only literals (no function calls)."""
    # B4 (2026-04-23): fail-loud parse via shared helper.
    tree = parse_python_source_or_emit_finding(
        text,
        rel_path=normalize_path(path),
        emit_finding=emit_finding,
        emitting_gate="test_quality.literal_only_asserts",
        filename=path,
    )
    if tree is None:
        return []

    test_fns = [
        node for node in ast.walk(tree)
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        and node.name.startswith("test_")
    ]
    if not test_fns:
        return []

    all_literal_asserts = True
    has_any_assert = False
    for test_fn in test_fns:
        for node in ast.walk(test_fn):
            if isinstance(node, ast.Assert):
                has_any_assert = True
                if not _is_literal_only_expr(node.test):
                    all_literal_asserts = False
                    break
        if not all_literal_asserts:
            break

    if has_any_assert and all_literal_asserts:
        return [
            build_finding(
                check_id="test_quality.literal_only_asserts",
                category=GateCategory.TESTING,
                title=f"All test asserts compare only literals: {path}",
                severity=GateSeverity.MEDIUM,
                impact=GateImpact.REVISE,
                summary=(
                    f"Every assert statement in {path} compares only literal values "
                    "(e.g. `assert 1 == 1`). This suggests the tests are not "
                    "exercising any real code paths."
                ),
                recommendation="Assert on the result of calling project functions, not on constants.",
                evidence=[EvidenceReference(kind="file", path=path, detail="literal_asserts")],
            
                repair_kind='add_test',
                executor_action='Add tests for coverage',
                proof_required='Tests added/passing',
                allowlist_allowed=True,
            )
        ]
    return []


def _is_literal_only_expr(node: ast.expr) -> bool:
    """Return True if the AST expression contains only literals/constants."""
    if isinstance(node, ast.Constant):
        return True
    if isinstance(node, ast.Compare):
        return _is_literal_only_expr(node.left) and all(
            _is_literal_only_expr(c) for c in node.comparators
        )
    if isinstance(node, ast.BoolOp):
        return all(_is_literal_only_expr(v) for v in node.values)
    if isinstance(node, ast.UnaryOp):
        return _is_literal_only_expr(node.operand)
    if isinstance(node, ast.BinOp):
        return _is_literal_only_expr(node.left) and _is_literal_only_expr(node.right)
    if isinstance(node, (ast.List, ast.Tuple, ast.Set)):
        return all(_is_literal_only_expr(e) for e in node.elts)
    if isinstance(node, ast.NameConstant):  # Python 3.7 compat
        return True
    return False
