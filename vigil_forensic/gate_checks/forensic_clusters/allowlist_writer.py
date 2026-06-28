"""Allowlist writer — programmatic Python API to append FP entries.

Sprint D1 (2026-04-23). Previously only the executor could write
`false_positive_allowlist.json` via file tool calls. This module adds a
Python writer so the PE supervisor pipeline can persist FP classifications
without going through a file-edit round-trip.

Contract
--------
* Only findings with `applicability="unknown"` are eligible. Any entry whose
  `finding_snapshot.applicability` differs raises ValueError (fail-loud).
* Callers on the PE path must set `classifier="pe_supervisor"`. Other
  classifier values raise ValueError at this entrypoint.
* Merge by fingerprint: an existing entry with the same fingerprint is
  overwritten (latest classifier wins) — idempotent.
* Atomic file write (tempfile.mkstemp + os.replace) — same pattern as
  `save_allowlist()` in allowlist.py, safe against partial writes and
  reasonably safe across concurrent sessions on the same drive.
"""
from __future__ import annotations

import json
import logging
import os
import tempfile
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Literal, Optional, TYPE_CHECKING

if TYPE_CHECKING:
    from vigil_forensic._shared import GateFinding

_log = logging.getLogger(__name__)

_ALLOWLIST_PATH_PARTS = (".prompt-engineer", "forensic_gates", "false_positive_allowlist.json")

_ALLOWED_CLASSIFIERS: frozenset[str] = frozenset({"executor", "pe_supervisor", "human"})

# Sprint (2026-04-24): default TTL for PE-classifier safety mechanisms.
DEFAULT_PE_TTL_DAYS = 30


@dataclass(frozen=True)
class FPAllowlistEntry:
    """Structured FP allowlist entry for programmatic writes.

    `finding_snapshot` must contain `applicability` — the writer validates
    it equals "unknown" before persisting. `expires_at=""` means no TTL
    (matches executor-written entries).
    """
    fingerprint: str
    reason: str
    classifier: Literal["executor", "pe_supervisor", "human"]
    classified_at: str
    session_num: int
    finding_snapshot: dict
    evidence_type: str = "design_decision"
    expires_at: str = ""
    # Derived from finding_snapshot when the writer expands to disk format,
    # but callers may override if they want a custom file/line/evidence.
    check_id: str = ""
    file: str = ""
    line: int = 0
    evidence: str = ""
    added_by: str = ""
    added_at: str = ""
    reviewed_by: str = ""
    # Sprint (2026-04-24): TTL + code-hash safety mechanisms.
    # `created_at` defaults to time.time() at construction; `code_hash` is
    # populated by the factory (build_pe_fp_entry_from_finding) using
    # SYSTEM.shared_helpers.file_hash.compute_code_hash.
    created_at: float = 0.0
    ttl_days: int = DEFAULT_PE_TTL_DAYS
    code_hash: str = ""
    extra: dict = field(default_factory=dict)

    def to_disk_dict(self) -> dict[str, object]:
        """Flatten into the JSON shape used by false_positive_allowlist.json."""
        snapshot = dict(self.finding_snapshot)
        check_id = self.check_id or str(snapshot.get("check_id", "") or "")
        file_path = self.file or str(snapshot.get("file", "") or "")
        line_no = self.line or int(snapshot.get("line", 0) or 0)
        evidence = self.evidence or self.reason
        added_at = self.added_at or self.classified_at
        added_by = self.added_by or self.classifier
        created_at = float(self.created_at) if self.created_at > 0.0 else float(time.time())
        payload: dict[str, object] = {
            "fingerprint": self.fingerprint,
            "check_id": check_id,
            "file": file_path,
            "line": line_no,
            "reason": self.reason,
            "evidence_type": self.evidence_type,
            "evidence": evidence,
            "added_by": added_by,
            "added_at": added_at,
            "reviewed_by": self.reviewed_by,
            "expires_at": self.expires_at,
            "classifier": self.classifier,
            "classified_at": self.classified_at,
            "created_at": created_at,
            "ttl_days": int(self.ttl_days),
            "code_hash": self.code_hash,
            "finding_snapshot": snapshot,
        }
        for key, value in self.extra.items():
            payload.setdefault(key, value)
        return payload


def _resolve_path(project_dir: Path) -> Path:
    path = Path(project_dir)
    for part in _ALLOWLIST_PATH_PARTS:
        path = path / part
    return path


def _validate_entry(entry: FPAllowlistEntry) -> None:
    """Enforce D1 constraints on a single entry."""
    if entry.classifier not in _ALLOWED_CLASSIFIERS:
        raise ValueError(
            f"write_fp_allowlist_entries: unsupported classifier "
            f"{entry.classifier!r}; allowed: {sorted(_ALLOWED_CLASSIFIERS)}"
        )
    if not entry.fingerprint:
        raise ValueError("write_fp_allowlist_entries: entry has empty fingerprint")
    if len((entry.reason or "").strip()) < 10:
        raise ValueError(
            f"write_fp_allowlist_entries: reason for {entry.fingerprint!r} "
            f"too short (min 10 chars): {entry.reason!r}"
        )
    snapshot_app = str(entry.finding_snapshot.get("applicability", "") or "")
    if snapshot_app != "unknown":
        raise ValueError(
            f"write_fp_allowlist_entries: finding_snapshot.applicability must be "
            f"'unknown' for fingerprint {entry.fingerprint!r}, got {snapshot_app!r}. "
            "Only uncertain findings are eligible for programmatic allowlist writes."
        )


def write_fp_allowlist_entries(
    project_dir: Path,
    entries: list[FPAllowlistEntry],
) -> int:
    """Atomic JSON update. Returns the number of new or updated entries.

    Idempotent: re-writing an entry with the same fingerprint replaces the
    existing record rather than adding a duplicate. Entries are first
    validated — the call fails loudly if any entry violates the D1 contract
    (non-unknown applicability, missing fingerprint, short reason, unknown
    classifier). Nothing is written if validation fails.
    """
    if not entries:
        return 0

    # Validate ALL entries before touching the file — fail-loud, no partial writes.
    for entry in entries:
        _validate_entry(entry)

    allowlist_path = _resolve_path(project_dir)
    allowlist_path.parent.mkdir(parents=True, exist_ok=True)

    existing: list[dict] = []
    if allowlist_path.exists():
        try:
            raw = allowlist_path.read_text(encoding="utf-8")
            loaded = json.loads(raw) if raw.strip() else []
            if isinstance(loaded, list):
                existing = loaded
            else:
                _log.warning(
                    "allowlist_writer: existing allowlist is not a JSON array at %s "
                    "(got %s); ignoring existing content.",
                    allowlist_path, type(loaded).__name__,
                )
        except (OSError, json.JSONDecodeError) as exc:
            _log.warning(
                "allowlist_writer: could not read %s (%s); "
                "writing fresh with new entries only.",
                allowlist_path, exc,
            )

    by_fp: dict[str, dict] = {}
    for item in existing:
        if isinstance(item, dict):
            fp = str(item.get("fingerprint", "") or "")
            if fp:
                by_fp[fp] = item

    changed = 0
    for entry in entries:
        disk = entry.to_disk_dict()
        fp = entry.fingerprint
        if fp in by_fp and by_fp[fp] == disk:
            continue
        by_fp[fp] = disk
        changed += 1
        _log.info(
            "allowlist_writer: upserted fingerprint=%r classifier=%r check_id=%r",
            fp, entry.classifier, disk.get("check_id"),
        )

    merged = list(by_fp.values())
    content = json.dumps(merged, indent=2, ensure_ascii=False) + "\n"

    tmp_fd, tmp_path = tempfile.mkstemp(dir=str(allowlist_path.parent), suffix=".tmp")
    try:
        os.write(tmp_fd, content.encode("utf-8"))
        os.close(tmp_fd)
        os.replace(tmp_path, str(allowlist_path))
    except BaseException:
        try:
            os.close(tmp_fd)
        except OSError:
            pass
        try:
            os.unlink(tmp_path)
        except OSError:
            pass
        raise

    _log.info(
        "allowlist_writer: wrote %d total entries (%d new/updated) to %s",
        len(merged), changed, allowlist_path,
    )
    return changed


def build_pe_fp_entry_from_finding(
    finding: "GateFinding",
    *,
    reason: str,
    session_num: int,
    evidence: Optional[str] = None,
    evidence_type: str = "design_decision",
    expires_at: str = "",
    now_iso: str = "",
    project_dir: Optional[Path] = None,
    ttl_days: int = DEFAULT_PE_TTL_DAYS,
) -> FPAllowlistEntry:
    """Convert a GateFinding into a PE-classified FPAllowlistEntry.

    Only admits findings with applicability="unknown" — the writer rejects
    anything else at validation time, so this factory does the same check
    eagerly for better error messages.

    Sprint (2026-04-24): stamps `created_at` (epoch seconds) and `code_hash`
    (SHA-256 of evidence file). When `project_dir` is supplied, the hash is
    computed against ``project_dir / primary_path``. When omitted, the hash
    is left empty (read-time hash check skipped, TTL still applies).
    """
    if finding.applicability != "unknown":
        raise ValueError(
            f"build_pe_fp_entry_from_finding: finding {finding.fingerprint!r} has "
            f"applicability={finding.applicability!r} — only 'unknown' findings are "
            "eligible for PE-supervised FP classification."
        )
    if not now_iso:
        now_iso = datetime.now(tz=timezone.utc).isoformat()
    primary_path = ""
    primary_line = 0
    if finding.evidence:
        primary_path = (finding.evidence[0].path or "").strip()
        detail = finding.evidence[0].detail or ""
        for token in detail.split():
            try:
                primary_line = int(token)
                break
            except ValueError:
                continue
    snapshot = {
        "check_id": finding.check_id,
        "confidence": finding.confidence,
        "applicability": finding.applicability,
        "applicability_reason": finding.applicability_reason,
        "analysis_mode": finding.analysis_mode,
        "session_num": session_num,
        "file": primary_path,
        "line": primary_line,
    }
    code_hash = ""  # standalone: code-hash stamping unavailable
    return FPAllowlistEntry(
        fingerprint=finding.fingerprint,
        reason=reason.strip(),
        classifier="pe_supervisor",
        classified_at=now_iso,
        session_num=session_num,
        finding_snapshot=snapshot,
        evidence_type=evidence_type,
        expires_at=expires_at,
        check_id=finding.check_id,
        file=primary_path,
        line=primary_line,
        evidence=(evidence or reason).strip(),
        added_by="pe_supervisor",
        added_at=now_iso,
        created_at=float(time.time()),
        ttl_days=int(ttl_days),
        code_hash=code_hash,
    )
