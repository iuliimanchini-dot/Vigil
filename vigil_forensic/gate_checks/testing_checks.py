from __future__ import annotations

from vigil_forensic._shared import is_executor_metadata_path
from vigil_forensic._shared import GateCategory, GateImpact, GateSeverity
from vigil_forensic.gate_models import PostExecGateContext
from .common import build_check_result, build_finding
import logging
_log = logging.getLogger(__name__)


def run_testing_checks(ctx: PostExecGateContext):
    findings = []
    profile = ctx.repo_profile
    if profile is None:
        return build_check_result(check_id="testing", category=GateCategory.TESTING)
    touched = tuple(str(path) for path in ctx.touched_files)
    changed_critical = any(profile.is_critical(path) for path in touched)
    report = (
        ctx.structured_handoff.report
        if ctx.structured_handoff is not None and ctx.structured_handoff.report is not None
        else None
    )
    verification_performed = (
        tuple(str(item).lower() for item in report.verification_performed if str(item).strip())
        if report is not None
        else ()
    )
    test_text = " ".join(verification_performed)
    touched_non_metadata = tuple(path for path in touched if not is_executor_metadata_path(path))
    expected_keywords: set[str] = set()
    for path in touched_non_metadata:
        normalized = path.replace("\\", "/").lower()
        if "runtime" in normalized:
            expected_keywords.update({"runtime", "lock", "run_controls", "doctor", "status"})
        if "dashboard" in normalized:
            expected_keywords.update({"dashboard", "session", "files", "route"})
        if "policy" in normalized:
            expected_keywords.update({"policy", "hook", "enforcement"})
        if "gate" in normalized or "review" in normalized:
            expected_keywords.update({"gate", "review", "control_plane"})
    has_test_file_evidence = bool(ctx.tests_touched)
    has_behavior_test_evidence = bool(expected_keywords) and any(keyword in test_text for keyword in expected_keywords)
    if changed_critical and (not has_test_file_evidence or not verification_performed):
        findings.append(
            build_finding(
                check_id="testing.missing_critical_tests",
                category=GateCategory.TESTING,
                title="Critical behavior changed without test coverage evidence",
                severity=GateSeverity.HIGH,
                impact=GateImpact.REVISE,
                summary="Touched critical roots but no meaningful test file changes or verification commands were recorded.",
                recommendation="Add or update tests and record the executed verification commands in the handoff.",
            
                repair_kind='add_test',
                executor_action='Add tests for coverage',
                proof_required='Tests added/passing',
                allowlist_allowed=True,
            )
        )
    elif changed_critical and expected_keywords and not has_behavior_test_evidence:
        findings.append(
            build_finding(
                check_id="testing.behavior_mismatch",
                category=GateCategory.TESTING,
                title="Recorded test evidence does not match the changed critical behavior",
                severity=GateSeverity.HIGH,
                impact=GateImpact.REVISE,
                summary=(
                    f"Critical paths were touched ({', '.join(touched_non_metadata[:3])}), "
                    f"but verification evidence did not reference expected behavior keywords: {', '.join(sorted(expected_keywords)[:5])}."
                ),
                recommendation="Run behavior-relevant tests or operator flows that exercise the touched critical path.",
            
                repair_kind='add_test',
                executor_action='Add tests for coverage',
                proof_required='Tests added/passing',
                allowlist_allowed=True,
            )
        )
    _TEST_EXECUTION_MARKERS = {"pytest", "python -m pytest", "test_", "passed", "failed", "error"}
    has_test_execution_evidence = any(
        any(marker in entry for marker in _TEST_EXECUTION_MARKERS)
        for entry in verification_performed
    )
    critical_touched_count = sum(1 for path in touched if profile.is_critical(path))
    if changed_critical and not has_test_execution_evidence:
        findings.append(
            build_finding(
                check_id="testing.no_test_execution_evidence",
                category=GateCategory.TESTING,
                title="No test execution evidence found for critical file changes",
                severity=GateSeverity.HIGH,
                impact=GateImpact.REVISE,
                summary="Critical files were touched but verification_performed contains no test execution markers (pytest, passed, failed, error).",
                recommendation="Run the test suite and record the output in verification_performed.",
            
                repair_kind='add_test',
                executor_action='Add tests for coverage',
                proof_required='Tests added/passing',
                allowlist_allowed=True,
            )
        )
    if critical_touched_count > 3 and len(verification_performed) <= 1:
        findings.append(
            build_finding(
                check_id="testing.insufficient_verification_scope",
                category=GateCategory.TESTING,
                title="Verification scope is too narrow for the number of critical files changed",
                severity=GateSeverity.MEDIUM,
                impact=GateImpact.REVISE,
                summary=f"{critical_touched_count} critical files were touched but only {len(verification_performed)} verification entries recorded.",
                recommendation="Provide proportional verification coverage: add per-module test runs or behavioral checks for each critical area changed.",
            
                repair_kind='add_test',
                executor_action='Add tests for coverage',
                proof_required='Tests added/passing',
                allowlist_allowed=True,
            )
        )
    # SL-6: ExecutorHandoffAssessment has no canonical status field in Sprint A.
    # Use report.result_claim as the truthful success signal: parse_executor_handoff_report
    # restricts result_claim to {"success", "partial", "failed"} and "success" is the
    # only claim that should trigger the contradictory-test-evidence finding.
    handoff_claims_success = (
        report is not None and str(report.result_claim or "").lower() == "success"
    )
    _FAILURE_MARKERS = {"failed", "error"}
    has_failure_in_evidence = any(
        any(marker in entry for marker in _FAILURE_MARKERS)
        for entry in verification_performed
    )
    if has_test_execution_evidence and has_failure_in_evidence and handoff_claims_success:
        findings.append(
            build_finding(
                check_id="testing.contradictory_test_evidence",
                category=GateCategory.TESTING,
                title="Test evidence contains failures but handoff claims success",
                severity=GateSeverity.HIGH,
                impact=GateImpact.REVISE,
                summary="verification_performed includes test execution with failure/error markers, but the handoff status reports success.",
                recommendation="Resolve all test failures before marking the handoff as successful.",
            
                repair_kind='add_test',
                executor_action='Add tests for coverage',
                proof_required='Tests added/passing',
                allowlist_allowed=True,
            )
        )
    return build_check_result(check_id="testing", category=GateCategory.TESTING, findings=findings)
