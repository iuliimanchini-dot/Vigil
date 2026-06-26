"""FastMCP stdio server: forensic-audit

Wraps cortex_forensic.run_forensic_audit behind a background-job poll API.
Resource constraints:
- At most 2 concurrent jobs (enforced by _jobs.JobRegistry).
- One thread per job (no pool).
- run_forensic_audit already enforces workers=1 internally (verified in source).
- Output truncated/paginated to OUTPUT_CHAR_LIMIT chars (~25 k tokens budget).
"""
from __future__ import annotations

import json
from collections import Counter
from pathlib import Path
from typing import Any

from mcp.server.fastmcp import FastMCP

from cortex_mcp import _jobs
from cortex_mcp import _paths
from cortex_forensic import run_forensic_audit

_INSTRUCTIONS = """\
forensic-audit - static code-quality forensic auditor. Finds real bugs, swallowed
exceptions, security issues, oversized/over-nested code, and cross-file duplication
across Python/Go/Java/JS/TS. Pure static analysis (tree-sitter/AST) - it never runs
the project or its tests.

WHEN TO USE: when the user asks to audit a project, review code quality, or find
problems/bugs/smells in a codebase or a set of changes - before committing or merging.
Not for running tests (it doesn't execute code).

WORKFLOW (background job + poll - do not expect an instant answer):
  1. start_forensic_audit(path="")  -> leave path empty to auto-detect the project
     root from the current directory; returns {job_id, resolved_path}.
  2. get_forensic_status(job_id)     -> poll until status == "done" (usually seconds).
  3. get_forensic_results(job_id)    -> returns a COMPACT SUMMARY by default
     (counts by severity + by check_id + top findings). Read this FIRST; it is sized
     to fit the context budget (~3k tokens), so prefer it over the full list.
  4. Only if needed: get_forensic_results(job_id, view="full", severity="HIGH")
     or check_id="..." to drill into specific findings (paginated).

INTERPRETING: exit_code 0 = clean, 1 = high/critical findings exist, 2 = error.
Triage HIGH first. On clean third-party code most findings are size.* (large files)
and broad_except (real `except: pass` swallows).

REDUCING NOISE: create <project>/.cortex/disabled_gates.json = ["gate_id", ...] to
skip gates for that project. Some heuristic gates (e.g. god_object_zones) are OFF by
default and run only when explicitly named via the gates= argument.
"""

mcp = FastMCP("forensic-audit", instructions=_INSTRUCTIONS)

# ~80 k chars keeps well under the 25 k token MCP output limit.
OUTPUT_CHAR_LIMIT = 80_000

# Severity ordering, highest first, used to pick the "top" findings bucket.
_SEVERITY_ORDER = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")

# Caps for the compact summary view (keep JSON well under the MCP budget).
_TOP_FINDINGS_CAP = 20
_BY_CHECK_ID_CAP = 25


# ---------------------------------------------------------------------------
# Summary builder (Feature 1 - summary-first forensic results)
# ---------------------------------------------------------------------------

def _finding_location(f: dict) -> tuple[Any, Any]:
    """Best-effort (file, line) for a finding across both schemas.

    Synthetic/test findings carry flat ``file``/``line`` keys; real
    cortex_forensic findings instead carry an ``evidence`` list of
    ``{"kind": "file", "path": ..., "detail": "line:N"}``.  Prefer the flat
    keys, fall back to the first file-evidence entry.
    """
    file = f.get("file")
    line = f.get("line")
    if file is None or line is None:
        for ev in f.get("evidence") or []:
            if not isinstance(ev, dict):
                continue
            if file is None and ev.get("path"):
                file = ev.get("path")
            if line is None:
                detail = str(ev.get("detail", ""))
                if detail.startswith("line:"):
                    suffix = detail.split("line:", 1)[1].strip()
                    line = int(suffix) if suffix.isdigit() else suffix or None
            if file is not None and line is not None:
                break
    return file, line


def _compact_finding(f: dict) -> dict:
    """Project a finding down to the compact fields shown in the summary.

    Works for both the flat test schema (``file``/``line``/``message``) and
    the real forensic schema (``evidence``/``summary``/``title``).
    """
    file, line = _finding_location(f)
    message = f.get("message") or f.get("summary") or f.get("title")
    return {
        "check_id": f.get("check_id"),
        "severity": f.get("severity"),
        "file": file,
        "line": line,
        "message": message,
    }


def _build_forensic_summary(result: dict) -> dict:
    """Build a compact, context-budget-friendly summary of an audit result.

    Instead of every finding, returns total counts, a per-severity breakdown,
    a per-check_id breakdown (top ``_BY_CHECK_ID_CAP`` by count) and the top
    ``_TOP_FINDINGS_CAP`` findings drawn from the highest severity present.

    Args:
        result: The raw ``run_forensic_audit`` result dict (``findings``,
                ``exit_code``, ``meta``, ``errors``).

    Returns:
        A dict with keys: ``total``, ``exit_code``, ``by_severity``,
        ``by_check_id``, ``top_findings``, ``meta``, ``errors``, ``hint``.
    """
    findings = result.get("findings") or []
    total = len(findings)

    # by_severity: lowercase keys so counts are stable regardless of input case.
    sev_counter: Counter[str] = Counter()
    for f in findings:
        sev = str(f.get("severity", "")).upper()
        sev_counter[sev] += 1
    by_severity = {
        "high": sev_counter.get("HIGH", 0) + sev_counter.get("CRITICAL", 0),
        "medium": sev_counter.get("MEDIUM", 0),
        "low": sev_counter.get("LOW", 0) + sev_counter.get("INFO", 0),
    }

    # by_check_id: top N check ids by count.
    check_counter: Counter[str] = Counter(
        str(f.get("check_id", "unknown")) for f in findings
    )
    by_check_id = dict(check_counter.most_common(_BY_CHECK_ID_CAP))

    # top_findings: drawn from the highest severity actually present.
    top_severity: str | None = None
    for sev in _SEVERITY_ORDER:
        if sev_counter.get(sev, 0) > 0:
            top_severity = sev
            break
    top_findings: list[dict] = []
    if top_severity is not None:
        for f in findings:
            if str(f.get("severity", "")).upper() == top_severity:
                top_findings.append(_compact_finding(f))
                if len(top_findings) >= _TOP_FINDINGS_CAP:
                    break

    hint = (
        "Compact summary. For the full finding list call get_forensic_results "
        "with view='full' (supports severity= and check_id= filters + paging)."
    )

    return {
        "total": total,
        "exit_code": result.get("exit_code", 2),
        "by_severity": by_severity,
        "by_check_id": by_check_id,
        "top_findings": top_findings,
        # `findings` mirrors top_findings (the compact subset actually shown in
        # the summary).  Present so summary payloads still expose a findings
        # list; for the complete, unbounded list use view='full'.
        "findings": top_findings,
        "meta": result.get("meta") or {},
        "errors": result.get("errors") or [],
        "hint": hint,
    }


# ---------------------------------------------------------------------------
# Serialisation / truncation helpers
# ---------------------------------------------------------------------------

def _paginate_json(data: Any, page: int, page_size_chars: int) -> dict:
    """Serialise *data* to JSON and return a page slice with metadata."""
    full_json = json.dumps(data, default=str, indent=2)
    total = len(full_json)
    start_char = page * page_size_chars
    end_char = start_char + page_size_chars
    return {
        "payload": full_json[start_char:end_char],
        "truncated": end_char < total,
        "total_chars": total,
        "page": page,
        "total_pages": (total + page_size_chars - 1) // page_size_chars,
    }


def _cap_findings(result: dict, max_findings: int = 200) -> dict:
    """Cap the findings list to avoid unbounded blobs.

    Adds "findings_truncated" and "total_findings_before_cap" to meta when
    the list was cut.
    """
    findings = result.get("findings", [])
    if len(findings) <= max_findings:
        return result
    result = dict(result)
    result["findings"] = findings[:max_findings]
    meta = dict(result.get("meta") or {})
    meta["findings_truncated"] = True
    meta["total_findings_before_cap"] = len(findings)
    result["meta"] = meta
    return result


# ---------------------------------------------------------------------------
# MCP tools
# ---------------------------------------------------------------------------

@mcp.tool()
def start_forensic_audit(
    path: str = "",
    gates: str = "",
    severity: str = "LOW",
    all_languages: bool = True,
) -> dict:
    """Start a background forensic audit job for the given project path.

    Args:
        path:          Absolute path to the project root directory.  When
                       empty/omitted the project root is auto-detected by
                       walking up from the current working directory looking
                       for a ``.git`` / ``pyproject.toml`` / ``package.json``
                       marker (falling back to cwd).  The chosen directory is
                       returned as ``resolved_path``.
        gates:         Comma-separated list of gate check_ids to run.
                       Empty string means run all applicable gates.
        severity:      Minimum severity to include: LOW | MEDIUM | HIGH | CRITICAL.
        all_languages: Reserved; currently always True.

    Returns:
        {"job_id": str | None, "status": "running" | "busy",
         "resolved_path": str, ...}
        When status is "busy", retry later - the server is at max concurrent jobs.

    Resource note:
        run_forensic_audit always uses workers=1 internally. This server
        enforces an additional cap of 2 concurrent jobs.
    """
    # Auto-target: resolve only when no explicit path was given.
    if path:
        resolved_path = path
    else:
        resolved_path = _paths._resolve_project_root(None)

    gates_list = [g.strip() for g in gates.split(",") if g.strip()] if gates else None

    def _run() -> dict:
        # run_forensic_audit uses workers=1 internally (verified in source).
        # No additional workers parameter is accepted.
        return run_forensic_audit(
            Path(resolved_path),
            gates=gates_list,
            severity=severity,
            all_languages=all_languages,
        )

    # project_dir enables disk-backed persistence so results survive a server
    # restart; get_forensic_status/results then resolve by job_id from disk.
    started = _jobs.start(_run, project_dir=resolved_path)
    started["resolved_path"] = resolved_path
    return started


@mcp.tool()
def get_forensic_status(job_id: str) -> dict:
    """Poll the status of a forensic audit job.

    Args:
        job_id: Job ID returned by start_forensic_audit.

    Returns:
        {"job_id": str, "status": "running" | "done" | "error" | "cancelled" | "not_found"}
    """
    return _jobs.status(job_id)


@mcp.tool()
def get_forensic_results(
    job_id: str,
    view: str = "summary",
    severity: str = "",
    check_id: str = "",
    page: int = 0,
    page_size_chars: int = OUTPUT_CHAR_LIMIT,
    max_findings: int = 200,
) -> dict:
    """Retrieve results of a completed forensic audit.

    Two views:
      * ``view='summary'`` (default) - a compact summary (total counts,
        by_severity, by_check_id, top HIGH findings) that fits comfortably
        in the MCP context budget.  Use this first.
      * ``view='full'`` - the full findings list, capped and paginated.
        Supports ``severity=`` and ``check_id=`` filters to drill in.

    Args:
        job_id:          Job ID returned by start_forensic_audit.
        view:            "summary" (default) or "full".
        severity:        (full view) keep only findings of this severity, e.g.
                         "HIGH".  Empty = no filter.
        check_id:        (full view) keep only findings with this check_id.
                         Empty = no filter.
        page:            Zero-based page index (full view).
        page_size_chars: Max chars per page (default 80 000 ≈ 25 k tokens).
        max_findings:    Cap on the findings list before pagination (default 200).

    Returns:
        dict with keys:
          "job_id", "status", "view",
          "exit_code" (0=clean, 1=high/critical findings, 2=error),
          "payload" (JSON string - summary dict or full result),
          "truncated" (bool), "total_chars", "page", "total_pages".
    """
    r = _jobs.result(job_id)
    status = r.get("status")

    if status in ("running", "not_found"):
        return {"job_id": job_id, "status": status, "payload": None,
                "truncated": False, "total_chars": 0}

    if status == "cancelled":
        return {"job_id": job_id, "status": "cancelled", "payload": None,
                "truncated": False, "total_chars": 0}

    if status == "error":
        return {"job_id": job_id, "status": "error",
                "error": r.get("error"), "payload": None,
                "truncated": False, "total_chars": 0}

    # status == "done"
    audit_result = r.get("result") or {}
    if not isinstance(audit_result, dict):
        audit_result = {}
    exit_code = audit_result.get("exit_code", 2)

    if view == "full":
        # Apply optional severity / check_id filters before capping.
        findings = audit_result.get("findings") or []
        if severity:
            sev_u = severity.upper()
            findings = [f for f in findings if str(f.get("severity", "")).upper() == sev_u]
        if check_id:
            findings = [f for f in findings if f.get("check_id") == check_id]
        filtered = dict(audit_result)
        filtered["findings"] = findings

        capped = _cap_findings(filtered, max_findings=max_findings)
        page_data = _paginate_json(capped, page=page, page_size_chars=page_size_chars)
        return {
            "job_id": job_id,
            "status": "done",
            "view": "full",
            "exit_code": exit_code,
            **page_data,
        }

    # Default: compact summary view.
    summary = _build_forensic_summary(audit_result)
    page_data = _paginate_json(summary, page=page, page_size_chars=page_size_chars)
    return {
        "job_id": job_id,
        "status": "done",
        "view": "summary",
        "exit_code": exit_code,
        **page_data,
    }


@mcp.tool()
def cancel_forensic_audit(job_id: str) -> dict:
    """Cancel a running forensic audit job.

    Args:
        job_id: Job ID returned by start_forensic_audit.

    Returns:
        {"job_id": str, "cancelled": bool, ...}
    """
    return _jobs.cancel(job_id)


def main() -> None:
    mcp.run()


if __name__ == "__main__":
    main()
