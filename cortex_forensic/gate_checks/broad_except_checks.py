from __future__ import annotations

import re

from cortex_forensic._shared import EvidenceReference, GateCategory, GateImpact, GateSeverity, RepairKind
from cortex_forensic.gate_models import PostExecGateContext
from ..source_analysis import is_source_file
from .common import build_check_result, build_finding, iter_touched_snapshots
import logging
_log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Pattern: except Exception: \n    pass  (also except Exception as e: \n    pass)
# ---------------------------------------------------------------------------
_BROAD_EXCEPT_RE = re.compile(
    r'^(\s*)except\s+Exception\s*(?:as\s+\w+)?\s*:\s*\n\1\s+pass\b',
    re.MULTILINE,
)

# ---------------------------------------------------------------------------
# Pattern: bare except:  (catches SystemExit, KeyboardInterrupt, etc.)
# ---------------------------------------------------------------------------
_BARE_EXCEPT_RE = re.compile(
    r'^\s*except\s*:\s*\n',
    re.MULTILINE,
)

# ---------------------------------------------------------------------------
# Pattern: except BaseException:  (same breadth problem as bare)
# ---------------------------------------------------------------------------
_BASE_EXCEPTION_RE = re.compile(
    r'^\s*except\s+BaseException\s*(?:as\s+\w+)?\s*:',
    re.MULTILINE,
)

# ---------------------------------------------------------------------------
# Pattern: except <anything>: \n    ... \n    return None/{}  (sentinel return)
# The body may have one intermediate line before the return statement.
# ---------------------------------------------------------------------------
_EXCEPT_RETURN_SENTINEL_RE = re.compile(
    r'except\s+\w[^:]*:\s*\n(\s+).*\n\1return\s+(None|\{\}|\[\])(?=\s|$)',
    re.MULTILINE,
)

# ---------------------------------------------------------------------------
# Pattern: except <anything>: \n    log.warning(...) \n    pass  (log-then-swallow)
# ---------------------------------------------------------------------------
_EXCEPT_LOG_SWALLOW_RE = re.compile(
    r'except\s+\w[^:]*:\s*\n(\s+)(?:_log|log|logger|logging)\.\w+\([^)]*\)\s*\n\1pass\b',
    re.MULTILINE,
)


def _emit(
    findings: list,
    *,
    check_id: str,
    snapshot_path: str,
    line_no: int,
    title: str,
    summary: str,
    repair_kind: str = "",
    executor_action: str = "",
    proof_required: str = "",
    allowlist_allowed: bool = False,
) -> None:
    findings.append(
        build_finding(
            check_id=check_id,
            category=GateCategory.FALLBACK,
            title=title,
            severity=GateSeverity.MEDIUM,
            impact=GateImpact.REVISE,
            summary=summary,
            recommendation=(
                "Narrow the exception to specific types (e.g. OSError, ValueError) "
                "and surface the error via logging or re-raise. "
                "Never silently drop exceptions that cross a function boundary."
            ),
            evidence=[EvidenceReference(kind="file", path=snapshot_path, detail=f"line:{line_no}")],
            repair_kind=repair_kind,
            executor_action=executor_action,
            proof_required=proof_required,
            allowlist_allowed=allowlist_allowed,
        )
    )


def run_broad_except_checks(ctx: PostExecGateContext):
    findings: list = []

    for snapshot in iter_touched_snapshots(ctx):
        if not snapshot.exists or not is_source_file(snapshot.path):
            continue

        text = snapshot.text
        normalized = snapshot.path

        # --- broad_except.swallow: except Exception: pass ---
        for match in _BROAD_EXCEPT_RE.finditer(text):
            line_no = text[:match.start()].count("\n") + 1
            _emit(
                findings,
                check_id="broad_except.swallow",
                snapshot_path=normalized,
                line_no=line_no,
                title=f"Broad 'except Exception: pass' in {normalized}:{line_no}",
                summary=(
                    f"File {normalized} line {line_no} catches all exceptions and "
                    "silently passes. This can hide real errors including filesystem "
                    "failures, type errors, and logic bugs."
                ),
                repair_kind=RepairKind.REMOVE_FALLBACK.value,
                executor_action="Narrow exception to specific type",
                proof_required="No broad except in file",
                allowlist_allowed=False,
            )

        # --- broad_except.bare: bare except: ---
        for match in _BARE_EXCEPT_RE.finditer(text):
            line_no = text[:match.start()].count("\n") + 1
            _emit(
                findings,
                check_id="broad_except.bare",
                snapshot_path=normalized,
                line_no=line_no,
                title=f"Bare 'except:' in {normalized}:{line_no}",
                summary=(
                    f"File {normalized} line {line_no} uses a bare 'except:' clause which "
                    "catches all exceptions including SystemExit and KeyboardInterrupt. "
                    "This prevents clean process shutdown and hides all errors."
                ),
                repair_kind=RepairKind.REMOVE_FALLBACK.value,
                executor_action="Narrow exception to specific type",
                proof_required="No broad except in file",
                allowlist_allowed=False,
            )

        # --- broad_except.base_exception: except BaseException: ---
        for match in _BASE_EXCEPTION_RE.finditer(text):
            line_no = text[:match.start()].count("\n") + 1
            _emit(
                findings,
                check_id="broad_except.base_exception",
                snapshot_path=normalized,
                line_no=line_no,
                title=f"'except BaseException' in {normalized}:{line_no}",
                summary=(
                    f"File {normalized} line {line_no} catches BaseException, which includes "
                    "SystemExit and KeyboardInterrupt. This is equivalent to a bare except and "
                    "prevents clean process shutdown."
                ),
                repair_kind=RepairKind.REMOVE_FALLBACK.value,
                executor_action="Narrow exception to specific type",
                proof_required="No broad except in file",
                allowlist_allowed=False,
            )

        # --- broad_except.return_none: except ...: return None/{}/[] ---
        for match in _EXCEPT_RETURN_SENTINEL_RE.finditer(text):
            line_no = text[:match.start()].count("\n") + 1
            sentinel = match.group(2)
            _emit(
                findings,
                check_id="broad_except.return_none",
                snapshot_path=normalized,
                line_no=line_no,
                title=f"Silent sentinel return '{sentinel}' after broad except in {normalized}:{line_no}",
                summary=(
                    f"File {normalized} line {line_no} catches an exception and returns a "
                    f"sentinel value ({sentinel}). The caller cannot distinguish success from "
                    "failure — errors are silently swallowed."
                ),
                repair_kind=RepairKind.REMOVE_FALLBACK.value,
                executor_action="Narrow exception to specific type",
                proof_required="No broad except in file",
                allowlist_allowed=False,
            )

        # --- broad_except.log_swallow: except ...: log.X(...); pass ---
        for match in _EXCEPT_LOG_SWALLOW_RE.finditer(text):
            line_no = text[:match.start()].count("\n") + 1
            _emit(
                findings,
                check_id="broad_except.log_swallow",
                snapshot_path=normalized,
                line_no=line_no,
                title=f"Log-then-swallow pattern in {normalized}:{line_no}",
                summary=(
                    f"File {normalized} line {line_no} logs the exception then passes. "
                    "The error is silently consumed — callers receive no signal that the "
                    "operation failed."
                ),
                repair_kind=RepairKind.REMOVE_FALLBACK.value,
                executor_action="Narrow exception to specific type",
                proof_required="No broad except in file",
                allowlist_allowed=False,
            )

    return build_check_result(check_id="broad_except", category=GateCategory.FALLBACK, findings=findings)
