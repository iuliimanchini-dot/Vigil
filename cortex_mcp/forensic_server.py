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
from pathlib import Path
from typing import Any

from mcp.server.fastmcp import FastMCP

from cortex_mcp import _jobs
from cortex_forensic import run_forensic_audit

mcp = FastMCP("forensic-audit")

# ~80 k chars keeps well under the 25 k token MCP output limit.
OUTPUT_CHAR_LIMIT = 80_000


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
    path: str,
    gates: str = "",
    severity: str = "LOW",
    all_languages: bool = True,
) -> dict:
    """Start a background forensic audit job for the given project path.

    Args:
        path:          Absolute path to the project root directory.
        gates:         Comma-separated list of gate check_ids to run.
                       Empty string means run all applicable gates.
        severity:      Minimum severity to include: LOW | MEDIUM | HIGH | CRITICAL.
        all_languages: Reserved; currently always True.

    Returns:
        {"job_id": str | None, "status": "running" | "busy", ...}
        When status is "busy", retry later — the server is at max concurrent jobs.

    Resource note:
        run_forensic_audit always uses workers=1 internally. This server
        enforces an additional cap of 2 concurrent jobs.
    """
    gates_list = [g.strip() for g in gates.split(",") if g.strip()] if gates else None

    def _run() -> dict:
        # run_forensic_audit uses workers=1 internally (verified in source).
        # No additional workers parameter is accepted.
        return run_forensic_audit(
            Path(path),
            gates=gates_list,
            severity=severity,
            all_languages=all_languages,
        )

    return _jobs.start(_run)


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
    page: int = 0,
    page_size_chars: int = OUTPUT_CHAR_LIMIT,
    max_findings: int = 200,
) -> dict:
    """Retrieve results of a completed forensic audit (paginated).

    Large payloads are capped and paginated to stay within MCP output limits.

    Args:
        job_id:          Job ID returned by start_forensic_audit.
        page:            Zero-based page index.
        page_size_chars: Max chars per page (default 80 000 ≈ 25 k tokens).
        max_findings:    Cap on the findings list before pagination (default 200).
                         Use together with page to page through large finding sets.

    Returns:
        dict with keys:
          "job_id", "status",
          "exit_code" (0=clean, 1=high/critical findings, 2=error),
          "payload" (JSON string of the (possibly capped) result),
          "truncated" (bool), "total_chars", "page", "total_pages".

        findings_truncated and total_findings_before_cap appear in meta when
        the findings list was capped.
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
    exit_code = audit_result.get("exit_code", 2) if isinstance(audit_result, dict) else 2

    capped = _cap_findings(audit_result, max_findings=max_findings)
    page_data = _paginate_json(capped, page=page, page_size_chars=page_size_chars)

    return {
        "job_id": job_id,
        "status": "done",
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
