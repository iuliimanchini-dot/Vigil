"""Broad-except hidden-sentinel detector (Finding G.4 plan v7).

Detects exception-handler variants that silently swallow errors without the
broad_except.swallow check (which targets 'except Exception: pass'):

  - bare ``except:``             (catches *everything* incl. KeyboardInterrupt)
  - ``except BaseException:``    (catches *everything*)
  - handler body is a single ``return None/{}/()/[]`` -- silent sentinel return
  - handler body is ``[log.warning/debug(...), pass]`` -- log-then-swallow

Emit MEDIUM/WARN for every match.
Fail-open: parse errors / missing files -> DEBUG log, skip, never raise.
"""
from __future__ import annotations

import ast
import logging

from cortex_forensic._shared import EvidenceReference, GateCategory, GateImpact, GateSeverity, RepairKind
from cortex_forensic.gate_models import PostExecGateContext
from cortex_forensic.source_analysis import is_source_file
from .common import build_check_result, build_finding, normalize_path

_log = logging.getLogger(__name__)

# Sentinel constant values that indicate "silent return"
_SENTINEL_VALUES = frozenset({None, "", 0})

# Logging method names that qualify for "log-then-swallow" detection
_LOG_SWALLOW_METHODS = frozenset({"warning", "warn", "debug", "info"})

# F16c — Observability markers: if an except-body calls any of these methods
# before returning a sentinel, the return is treated as explicit design
# (logged fallback) rather than a silent swallow. AST-matched by attribute
# name on the Call target.
#
# Attribute-form recognized on ANY receiver: receiver.<attr>(...) where
# attribute name is in _OBS_LOG_METHODS. This deliberately matches the common
# project conventions (`logger.warning`, `_log.error`, `log.exception`, plus
# user-defined wrappers that adopt the same verb names).
_OBS_LOG_METHODS = frozenset({
    "debug", "info", "warning", "warn", "error", "exception",
    "critical", "fatal", "log",
})

# Attribute-form recognized where the RECEIVER name is one of these (any
# attribute). Covers `metrics.increment(...)`, `alerts.send(...)`, etc.
_OBS_RECEIVERS = frozenset({
    "metrics", "alert", "alerts", "telemetry", "statsd", "sentry",
    "observability", "obs",
})

# Plain-call names (no attribute) that indicate stderr/CLI log equivalents.
_OBS_PLAIN_CALLS = frozenset({"print"})


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _is_bare_or_base(handler: ast.ExceptHandler) -> bool:
    """Return True for bare ``except:`` or ``except BaseException:``."""
    if handler.type is None:
        return True
    if isinstance(handler.type, ast.Name) and handler.type.id == "BaseException":
        return True
    return False


def _reraises(handler: ast.ExceptHandler) -> bool:
    """Return True if the handler re-raises at the top level of its body.

    ``except BaseException: <cleanup>; raise`` (the cancel-cleanup idiom) and
    ``raise SomeError(...) from exc`` (translate-and-propagate) both let the
    error propagate — they are NOT silent swallows and must not be flagged.
    Verified against filelock/_api.py:513-517 and asyncio.py:268-270.

    Only top-level ``raise`` statements count; a ``raise`` buried in a nested
    ``try``/``if`` is not a guaranteed re-raise.
    """
    return any(isinstance(stmt, ast.Raise) for stmt in handler.body)


def _exception_names(node: ast.expr | None) -> tuple[str, ...]:
    """Return a flat tuple of exception class names referenced by ``node``.

    Handles the common argument shapes used in ``except`` clauses:
      - ``Name``              -> ("Exception",)
      - ``Attribute``         -> ("os.error",) — keep terminal attr
      - ``Tuple`` of either   -> flattened
    Unknown shapes collapse to () so callers treat them as "broad / unknown".
    """
    if node is None:
        return ()
    if isinstance(node, ast.Name):
        return (node.id,)
    if isinstance(node, ast.Attribute):
        return (node.attr,)
    if isinstance(node, ast.Tuple):
        out: list[str] = []
        for elt in node.elts:
            out.extend(_exception_names(elt))
        return tuple(out)
    return ()


def _is_narrow_catch(handler: ast.ExceptHandler) -> bool:
    """Return True when the handler catches only specific non-broad exceptions.

    F16c rationale: ``except ValueError: return None`` is an intentional,
    type-scoped fallback; the narrow type name IS the author's assertion that
    the failure mode is expected and handled. Do not flag these as silent
    swallows.

    Broad catches (rejected as "not narrow"):
      - bare ``except:``
      - ``except BaseException:``
      - ``except Exception:`` (and any tuple containing ``Exception``)

    All other catches — including stdlib sub-exceptions (``OSError``,
    ``SyntaxError``, ``json.JSONDecodeError``, ``subprocess.SubprocessError``,
    project-specific ``FooError``) — are considered narrow.
    """
    if _is_bare_or_base(handler):
        return False
    names = _exception_names(handler.type)
    if not names:
        # Unknown shape — err on the side of "not narrow" so the detector can
        # still decide via body inspection.
        return False
    broad = {"Exception", "BaseException"}
    return not any(n in broad for n in names)


def _is_observability_call(node: ast.AST) -> bool:
    """Return True when ``node`` is a Call that routes to observability.

    Matches three shapes:
      1. ``<receiver>.<method>(...)`` where method name is a known log verb
         (debug/info/warning/warn/error/exception/critical/fatal/log).
         Receiver is any expression — covers ``logger.warning``, ``_log.error``,
         ``self.log.debug``, ``LOG.exception``, project wrappers, etc.
      2. ``<known_receiver>.<any_attr>(...)`` where receiver is a canonical
         observability facade: metrics/alerts/telemetry/statsd/sentry/obs.
      3. Plain-name calls ``print(...)`` — stderr/CLI log equivalent.

    Deliberately permissive on the logger side (any method name from the verb
    set) so project-specific log wrappers are recognized without an allowlist.
    """
    if not isinstance(node, ast.Call):
        return False
    func = node.func
    # Shape 3 — plain ``print(...)``
    if isinstance(func, ast.Name) and func.id in _OBS_PLAIN_CALLS:
        return True
    if not isinstance(func, ast.Attribute):
        return False
    # Shape 1 — any-receiver .<log_verb>(...)
    if func.attr in _OBS_LOG_METHODS:
        return True
    # Shape 2 — known-observability receiver, any attribute
    value = func.value
    if isinstance(value, ast.Name) and value.id in _OBS_RECEIVERS:
        return True
    return False


def _returns_silent_sentinel(stmt: ast.stmt) -> bool:
    """Return True iff ``stmt`` is ``return <None|{}|[]|()>`` or bare return."""
    if not isinstance(stmt, ast.Return):
        return False
    val = stmt.value
    if val is None:
        return True
    if isinstance(val, ast.Constant) and val.value is None:
        return True
    if isinstance(val, ast.Dict) and not val.keys:
        return True
    if isinstance(val, ast.List) and not val.elts:
        return True
    if isinstance(val, ast.Tuple) and not val.elts:
        return True
    return False


def _is_silent_sentinel_return(handler: ast.ExceptHandler) -> bool:
    """Return True when the handler silently returns a sentinel (F16c-tightened).

    Flags only genuine silent swallows. Accepted (FLAG) patterns:
      - body is exactly ``return None/{}/()/[]`` (with optional leading
        ``pass``), AND
      - handler catches a broad exception (Exception / BaseException / bare).

    Skipped (NOT FLAGGED) patterns, per F16c FP reduction:
      - narrow ``except SpecificError:`` — the type itself documents intent
        (``except OSError``, ``except json.JSONDecodeError``, etc.)
      - body logs before returning (``logger.warning(...); return None``) —
        covered implicitly because body has more than one statement
      - body re-raises (``raise`` anywhere) — covered by the body-shape
        constraint AND by the explicit ``Raise`` skip below for robustness
      - any body shape other than a single sentinel return

    Rationale for keeping the body-shape constraint strict (single stmt +
    optional leading ``pass``): widening to multi-statement bodies introduces
    project-specific FPs where the first call is an error-surface wrapper
    (e.g., ``_error(handler, ...); return``) not recognizable from the AST
    without a per-project allowlist. The observability helper is still
    available via :func:`_is_observability_call` for future callers and for
    documenting intent.
    """
    body = handler.body
    if not body:
        return False

    # F16c skip #1 — narrow catches are acceptable design
    if _is_narrow_catch(handler):
        return False

    # Strip tolerated leading ``pass`` noise.
    tail = [s for s in body if not isinstance(s, ast.Pass)]
    if len(tail) != 1:
        return False

    stmt = tail[0]
    # F16c skip #3 — if the sole statement is a ``raise``, error propagates
    # (not a silent swallow). This is defensive; a ``raise`` at tail with
    # nothing else is intentional reraise.
    if isinstance(stmt, ast.Raise):
        return False

    return _returns_silent_sentinel(stmt)


def _is_log_then_swallow(handler: ast.ExceptHandler) -> bool:
    """Return True for the pattern: [log.warning/debug(...), pass].

    Matches:
      - exactly 2 statements
      - first is an ast.Expr wrapping a Call whose attribute is a log-swallow
        method (warning/warn/debug/info)
      - second is ast.Pass
    """
    body = handler.body
    if len(body) != 2:
        return False
    first, second = body
    if not isinstance(second, ast.Pass):
        return False
    if not isinstance(first, ast.Expr):
        return False
    call = first.value
    if not isinstance(call, ast.Call):
        return False
    if not isinstance(call.func, ast.Attribute):
        return False
    return call.func.attr in _LOG_SWALLOW_METHODS


# ---------------------------------------------------------------------------
# Per-handler analysis
# ---------------------------------------------------------------------------

def _classify_handler(
    handler: ast.ExceptHandler,
) -> tuple[bool, str, str]:
    """Return (flagged, sub_check_id, reason) for a single ExceptHandler.

    Priority order:
      1. bare/BaseException (most severe)
      2. silent sentinel return
      3. log-then-swallow

    A handler that re-raises at the top level of its body is the cancel-cleanup
    idiom (propagates the error) and is never flagged.
    """
    if _reraises(handler):
        return False, "", ""
    if _is_bare_or_base(handler):
        type_name = "bare except" if handler.type is None else "except BaseException"
        return True, "broad_except.hidden_sentinel.bare_or_base", type_name
    if _is_silent_sentinel_return(handler):
        return True, "broad_except.hidden_sentinel.silent_return", "silent sentinel return"
    if _is_log_then_swallow(handler):
        return True, "broad_except.hidden_sentinel.log_swallow", "log-then-swallow"
    return False, "", ""


# ---------------------------------------------------------------------------
# Public gate entry-point
# ---------------------------------------------------------------------------

def run_broad_except_hidden_sentinel_checks(ctx: PostExecGateContext):
    """Detect hidden-sentinel exception-swallowing patterns.

    For each .py file in ctx.changed_files_observed:
    1. Parse the AST.
    2. Walk all ast.Try nodes.
    3. Inspect each ExceptHandler for bare/BaseException, silent-return, or
       log-then-swallow patterns.
    4. Emit MEDIUM/WARN for each match.

    Fail-open: parse errors / missing files -> DEBUG log, skip, never raise.
    """
    findings = []

    for raw_path in ctx.changed_files_observed:
        normalized = normalize_path(raw_path)
        if not is_source_file(normalized):
            continue

        abs_path = ctx.project_dir / normalized
        try:
            src = abs_path.read_text(encoding="utf-8")
            tree = ast.parse(src)
        except (OSError, SyntaxError, UnicodeDecodeError) as exc:
            _log.debug("broad_except_hidden_sentinel: failed to parse %s: %s", normalized, exc)
            continue

        for node in ast.walk(tree):
            if not isinstance(node, ast.Try):
                continue
            for handler in node.handlers:
                flagged, sub_id, reason = _classify_handler(handler)
                if not flagged:
                    continue

                line_no = handler.lineno
                findings.append(
                    build_finding(
                        check_id=sub_id,
                        category=GateCategory.FALLBACK,
                        title=f"Hidden-sentinel exception handler ({reason}) in {normalized}:{line_no}",
                        severity=GateSeverity.MEDIUM,
                        impact=GateImpact.REVISE,
                        summary=(
                            f"{normalized} line {line_no}: {reason} -- exception handler "
                            "silently discards the error without surfacing it to callers "
                            "or an observability layer."
                        ),
                        recommendation=(
                            "Narrow the exception type to the specific error expected, "
                            "log it at WARNING or ERROR level, and re-raise or propagate "
                            "via an obs dict. Avoid returning sentinel values from except "
                            "blocks unless the caller is explicitly documented to handle them."
                        ),
                        evidence=[
                            EvidenceReference(
                                kind="file",
                                path=normalized,
                                detail=f"line:{line_no}",
                            )
                        ],
                    
                        repair_kind='refactor',
                        executor_action='Address finding details',
                        proof_required='Issue fixed',
                        allowlist_allowed=False,
                    )
                )

    return build_check_result(
        check_id="broad_except.hidden_sentinel",
        category=GateCategory.FALLBACK,
        findings=findings,
    )
