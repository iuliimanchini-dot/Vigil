from __future__ import annotations

import ast
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

# NOTE: bare ``except:`` and ``except BaseException:`` are detected via AST in
# _check_bare_and_base_handlers (not regex) so the handler BODY can be inspected
# for a re-raise. A line-only regex cannot tell a swallow from the correct
# cancel-cleanup idiom (``except BaseException: <cleanup>; raise``).

# _EXCEPT_RETURN_SENTINEL_RE was removed (fix 3): the regex matched ANY exception
# type including narrow ones (OSError, ValueError) causing false positives.
# Replaced by AST-based _check_broad_return_sentinel below.

_BROAD_EXCEPTION_NAMES: frozenset[str] = frozenset({"Exception", "BaseException"})
_SENTINEL_CONSTS: frozenset[object] = frozenset({None})


def _is_broad_handler(handler: ast.ExceptHandler) -> bool:
    """Return True for bare except: or except Exception/BaseException: — mirrors _is_narrow_catch."""
    if handler.type is None:
        return True
    if isinstance(handler.type, ast.Name) and handler.type.id in _BROAD_EXCEPTION_NAMES:
        return True
    if isinstance(handler.type, ast.Tuple):
        for elt in handler.type.elts:
            if isinstance(elt, ast.Name) and elt.id in _BROAD_EXCEPTION_NAMES:
                return True
    return False


def _reraises(handler: ast.ExceptHandler) -> bool:
    """Return True if the handler body re-raises the exception.

    A ``raise`` statement at the TOP LEVEL of the handler body — either a bare
    ``raise`` (re-raise current exception) or ``raise <something>`` (chain /
    translate) — means the error propagates. This is the cancel-cleanup idiom::

        except BaseException:
            <cleanup>
            raise

    which is correct and must NOT be flagged as a swallow. Verified against
    filelock/_api.py:513-517.

    Only top-level statements of the handler body are considered: a ``raise``
    nested inside an inner ``try``/``if`` that the broad handler could still
    swallow does not count as a guaranteed re-raise.
    """
    return any(isinstance(stmt, ast.Raise) for stmt in handler.body)


def _check_bare_and_base_handlers(text: str, snapshot_path: str, findings: list) -> None:
    """AST-based bare-except / except-BaseException detector.

    Replaces the line-only regex checks (_BARE_EXCEPT_RE / _BASE_EXCEPTION_RE)
    so the handler BODY can be inspected: a handler that re-raises
    (``except BaseException: ...; raise``) is the correct cancel-cleanup idiom
    and is NOT flagged. Genuine swallows (bare/BaseException with no re-raise)
    are still flagged.
    """
    try:
        tree = ast.parse(text)
    except SyntaxError:
        return
    for node in ast.walk(tree):
        if not isinstance(node, ast.Try):
            continue
        for handler in node.handlers:
            is_bare = handler.type is None
            is_base = (
                isinstance(handler.type, ast.Name)
                and handler.type.id == "BaseException"
            )
            if not (is_bare or is_base):
                continue
            if _reraises(handler):
                # Cancel-cleanup idiom — re-raises, does not swallow.
                continue
            line_no = getattr(handler, "lineno", 0) or 0
            if is_bare:
                _emit(
                    findings,
                    check_id="broad_except.bare",
                    snapshot_path=snapshot_path,
                    line_no=line_no,
                    title=f"Bare 'except:' in {snapshot_path}:{line_no}",
                    summary=(
                        f"File {snapshot_path} line {line_no} uses a bare 'except:' clause which "
                        "catches all exceptions including SystemExit and KeyboardInterrupt. "
                        "This prevents clean process shutdown and hides all errors."
                    ),
                    repair_kind=RepairKind.REMOVE_FALLBACK.value,
                    executor_action="Narrow exception to specific type",
                    proof_required="No broad except in file",
                    allowlist_allowed=False,
                )
            else:
                _emit(
                    findings,
                    check_id="broad_except.base_exception",
                    snapshot_path=snapshot_path,
                    line_no=line_no,
                    title=f"'except BaseException' in {snapshot_path}:{line_no}",
                    summary=(
                        f"File {snapshot_path} line {line_no} catches BaseException, which includes "
                        "SystemExit and KeyboardInterrupt. This is equivalent to a bare except and "
                        "prevents clean process shutdown."
                    ),
                    repair_kind=RepairKind.REMOVE_FALLBACK.value,
                    executor_action="Narrow exception to specific type",
                    proof_required="No broad except in file",
                    allowlist_allowed=False,
                )


def _handler_returns_sentinel(handler: ast.ExceptHandler) -> tuple[bool, str]:
    """Return (True, sentinel_str) if handler body contains a return of None/{}/[].

    Checks ALL return statements in the body (not just the last line), so this
    catches both single-line and multi-line handler bodies.
    """
    _SENTINEL_STRS = {"None": "None", "{}": "{}", "[]": "[]"}
    for node in ast.walk(ast.Module(body=handler.body, type_ignores=[])):
        if isinstance(node, ast.Return):
            val = node.value
            if val is None:
                return True, "None"
            if isinstance(val, ast.Constant) and val.value is None:
                return True, "None"
            if isinstance(val, ast.Dict) and not val.keys:
                return True, "{}"
            if isinstance(val, ast.List) and not val.elts:
                return True, "[]"
    return False, ""


def _check_broad_return_sentinel(text: str, snapshot_path: str, findings: list) -> None:
    """AST-based replacement for the old _EXCEPT_RETURN_SENTINEL_RE check.

    Only flags broad catches (bare except / except Exception / except BaseException)
    that return a sentinel (None, {}, []). Narrow types (OSError, ValueError, etc.)
    are explicitly excluded — they represent intentional, type-scoped fallbacks.
    """
    try:
        tree = ast.parse(text)
    except SyntaxError:
        return
    for node in ast.walk(tree):
        if not isinstance(node, (ast.Try,)):
            continue
        for handler in getattr(node, "handlers", []):
            if not _is_broad_handler(handler):
                continue
            is_sentinel, sentinel_str = _handler_returns_sentinel(handler)
            if not is_sentinel:
                continue
            line_no = getattr(handler, "lineno", 0) or 0
            findings.append(
                build_finding(
                    check_id="broad_except.return_none",
                    category=GateCategory.FALLBACK,
                    title=f"Silent sentinel return '{sentinel_str}' after broad except in {snapshot_path}:{line_no}",
                    severity=GateSeverity.MEDIUM,
                    impact=GateImpact.REVISE,
                    summary=(
                        f"File {snapshot_path} line {line_no} catches an exception and returns a "
                        f"sentinel value ({sentinel_str}). The caller cannot distinguish success from "
                        "failure — errors are silently swallowed."
                    ),
                    recommendation=(
                        "Narrow the exception to specific types (e.g. OSError, ValueError) "
                        "and surface the error via logging or re-raise. "
                        "Never silently drop exceptions that cross a function boundary."
                    ),
                    evidence=[EvidenceReference(kind="file", path=snapshot_path, detail=f"line:{line_no}")],
                    repair_kind=RepairKind.REMOVE_FALLBACK.value,
                    executor_action="Narrow exception to specific type",
                    proof_required="No broad except in file",
                    allowlist_allowed=False,
                )
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

        # --- broad_except.bare + broad_except.base_exception: AST-based ---
        # Re-raising handlers (cancel-cleanup idiom) are skipped — see
        # _check_bare_and_base_handlers / _reraises.
        _check_bare_and_base_handlers(text, normalized, findings)

        # --- broad_except.return_none: AST-based check (only broad catches) ---
        _check_broad_return_sentinel(text, normalized, findings)

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
