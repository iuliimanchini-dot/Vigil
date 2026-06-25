"""False-positive allowlist infrastructure.

Provides AllowlistEntry, load_allowlist, revalidate_allowlist, save_allowlist,
and filter_by_allowlist for managing known false positives in forensic checks.
"""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Optional
import logging
_log = logging.getLogger(__name__)


# # False Positive Allowlist
# ---------------------------------------------------------------------------

_VALID_EVIDENCE_TYPES = frozenset({
    "grep_proof",       # agente must provide grep result
    "ast_proof",        # function is called via specific pattern
    "context_proof",    # number/pattern used in specific context
    "design_decision",  # deliberate architectural choice
})


# Sprint (2026-04-24): default TTL for PE-classifier safety mechanisms.
# Each PE-classifier-written entry expires after this many days unless an
# operator extends `expires_at` manually. Entries without `created_at`
# (legacy data) are treated as fresh on first load — see load_allowlist.
DEFAULT_PE_TTL_DAYS = 30


@dataclass(frozen=True)
class AllowlistEntry:
    fingerprint: str
    check_id: str
    file: str
    line: int
    reason: str
    evidence_type: str
    evidence: str
    added_by: str = ""
    added_at: str = ""
    reviewed_by: str = ""
    expires_at: str = ""
    # Sprint D1 (2026-04-23): classifier identity for PE-supervisor-written
    # entries. Backward compatible — entries without these fields load with
    # defaults and are treated as classifier="executor".
    classifier: str = ""          # "executor" | "pe_supervisor" | "human" | ""
    classified_at: str = ""       # ISO-8601 UTC
    # Sprint (2026-04-24): TTL + code-hash safety mechanisms for PE classifier.
    # `created_at` is epoch seconds (float). `ttl_days` defaults to 30. After
    # `created_at + ttl_days * 86400` the entry is filtered out at read time.
    # `code_hash` is the SHA-256 hex of the evidence file at write time; if
    # the file's current hash differs the entry is also filtered out. Empty
    # `code_hash` skips the hash check (TTL still applies).
    created_at: float = 0.0
    ttl_days: int = DEFAULT_PE_TTL_DAYS
    code_hash: str = ""

    def is_valid(self) -> bool:
        """Entry is valid only if it has real proof."""
        if not self.reason or len(self.reason) < 10:
            return False
        if self.evidence_type not in _VALID_EVIDENCE_TYPES:
            return False
        if not self.evidence or len(self.evidence) < 10:
            return False
        return True

    def to_dict(self) -> dict[str, object]:
        return {
            "fingerprint": self.fingerprint,
            "check_id": self.check_id,
            "file": self.file,
            "line": self.line,
            "reason": self.reason,
            "evidence_type": self.evidence_type,
            "evidence": self.evidence,
            "added_by": self.added_by,
            "added_at": self.added_at,
            "reviewed_by": self.reviewed_by,
            "expires_at": self.expires_at,
            "classifier": self.classifier,
            "classified_at": self.classified_at,
            "created_at": self.created_at,
            "ttl_days": self.ttl_days,
            "code_hash": self.code_hash,
        }


_BOOTSTRAP_TEMPLATE: dict[str, object] = {
    "_doc": (
        "False positive allowlist for forensic gates. Add entries via Write tool when "
        "a gate finding is verified as a false positive."
    ),
    "_format": (
        "list of {check_id, evidence: {kind: 'file_exists'|'mutation_verified'|...}, "
        "justification: str, added_at: ISO_DATE}"
    ),
    "entries": [],
}


def _bootstrap_allowlist_template(path: Path) -> None:
    """Create an empty allowlist template at *path* if it does not exist.

    Idempotent: skips if file already exists. Atomic write via mkstemp +
    os.replace so concurrent gate runs cannot observe a partial file.
    Failures during bootstrap are silent — the caller still sees an empty
    allowlist (`return []`), so a fresh project does not lose acknowledged
    FPs to a transient mkdir/write error.
    """
    import json as _json
    import os as _os
    import tempfile as _tempfile

    if path.exists():
        return
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        content = _json.dumps(_BOOTSTRAP_TEMPLATE, indent=2, ensure_ascii=False) + "\n"
        tmp_fd, tmp_path = _tempfile.mkstemp(dir=str(path.parent), suffix=".tmp")
        try:
            _os.write(tmp_fd, content.encode("utf-8"))
            _os.close(tmp_fd)
            _os.replace(tmp_path, str(path))
        except BaseException:
            try:
                _os.close(tmp_fd)
            except OSError:
                pass
            try:
                _os.unlink(tmp_path)
            except OSError:
                pass
            raise
    except OSError as exc:
        _log.warning(
            "allowlist: could not bootstrap empty template at %s (%s); "
            "fresh project will see no allowlist on first gate run.",
            path, exc,
        )


def load_allowlist(project_dir: Path) -> list[AllowlistEntry]:
    """Load false positive allowlist from .prompt-engineer/forensic_gates/.

    B3 wave: corrupt JSON / unreadable file no longer silently returns ``[]``.
    The failure is surfaced via ``meta.allowlist_corrupted`` so operators see
    that acknowledged false positives are no longer being honored.

    Sprint C1 (2026-04-25): on first read in a fresh project, drop an empty
    template at the canonical path so executor agents have a writable file
    for FP triage instead of looping on "fix FP" with nowhere to record it.
    """
    import json as _json
    path = project_dir / ".prompt-engineer" / "forensic_gates" / "false_positive_allowlist.json"
    if not path.exists():
        _bootstrap_allowlist_template(path)
        return []
    try:
        raw_text = path.read_text(encoding="utf-8")
    except (OSError, PermissionError) as exc:
        from cortex_forensic.meta_findings import emit_meta_finding
        emit_meta_finding(
            "meta.allowlist_corrupted",
            path=str(path),
            detail=f"{type(exc).__name__}: {exc}",
        )
        return []
    try:
        data = _json.loads(raw_text)
    except _json.JSONDecodeError as exc:
        from cortex_forensic.meta_findings import emit_meta_finding
        emit_meta_finding(
            "meta.allowlist_corrupted",
            path=str(path),
            detail=f"JSONDecodeError: {exc}",
        )
        return []

    import time as _time_mod

    entries: list[AllowlistEntry] = []
    for item in (data if isinstance(data, list) else []):
        try:
            # Backward compat: legacy entries without `created_at` are treated
            # as fresh on first load (use current time so TTL doesn't fire
            # immediately on entries written before the safety mechanism).
            raw_created = item.get("created_at", None)
            if raw_created is None or raw_created == "":
                created_at = float(_time_mod.time())
            else:
                created_at = float(raw_created)
            raw_ttl = item.get("ttl_days", DEFAULT_PE_TTL_DAYS)
            try:
                ttl_days = int(raw_ttl) if raw_ttl not in (None, "") else DEFAULT_PE_TTL_DAYS
            except (TypeError, ValueError):
                ttl_days = DEFAULT_PE_TTL_DAYS
            entry = AllowlistEntry(
                fingerprint=str(item.get("fingerprint", "")),
                check_id=str(item.get("check_id", "")),
                file=str(item.get("file", "")),
                line=int(item.get("line", 0)),
                reason=str(item.get("reason", "")),
                evidence_type=str(item.get("evidence_type", "")),
                evidence=str(item.get("evidence", "")),
                added_by=str(item.get("added_by", "")),
                added_at=str(item.get("added_at", "")),
                reviewed_by=str(item.get("reviewed_by", "")),
                expires_at=str(item.get("expires_at", "")),
                classifier=str(item.get("classifier", "")),
                classified_at=str(item.get("classified_at", "")),
                created_at=created_at,
                ttl_days=ttl_days,
                code_hash=str(item.get("code_hash", "")),
            )
        except (AttributeError, TypeError, ValueError) as exc:
            from cortex_forensic.meta_findings import emit_meta_finding
            emit_meta_finding(
                "meta.allowlist_corrupted",
                path=str(path),
                detail=(
                    f"{type(exc).__name__} coercing entry {item!r}: {exc}"
                ),
            )
            continue
        entries.append(entry)
    return _filter_expired_or_drifted(entries, project_dir)


def _filter_expired_or_drifted(
    entries: list[AllowlistEntry],
    project_dir: Path,
) -> list[AllowlistEntry]:
    """Drop entries past their TTL or whose evidence file's hash drifted.

    Sprint (2026-04-24) — Mechanism 1 (TTL) + Mechanism 2 (code-hash
    invalidation). Both checks fail-soft: if any input is malformed (NaN
    timestamp, weird ttl, unreadable file) the entry is kept rather than
    silently dropped, except in the explicit "expired" or "hash-mismatch"
    cases. A missing file or empty `code_hash` skips only the hash check —
    TTL still applies.
    """
    import time as _time_mod
    # standalone: code-hash stamping unavailable
    compute_code_hash = None  # type: ignore[assignment]

    now = float(_time_mod.time())
    kept: list[AllowlistEntry] = []
    for entry in entries:
        # TTL check.
        if entry.ttl_days > 0 and entry.created_at > 0.0:
            age = now - entry.created_at
            if age > float(entry.ttl_days) * 86400.0:
                _log.debug(
                    "allowlist: dropping fingerprint=%r — TTL expired (%.1f days > %d days)",
                    entry.fingerprint, age / 86400.0, entry.ttl_days,
                )
                continue
        # Code-hash check (only if entry has a non-empty stamped hash AND
        # the file currently exists). Missing file or empty hash → skip.
        if entry.code_hash and entry.file:
            try:
                file_abs = (project_dir / entry.file)
            except (TypeError, ValueError):
                file_abs = None
            if file_abs is not None and file_abs.is_file() and compute_code_hash is not None:
                current = compute_code_hash(file_abs)
                if current and current != entry.code_hash:
                    _log.debug(
                        "allowlist: dropping fingerprint=%r — code_hash drift "
                        "(stamped=%s now=%s)",
                        entry.fingerprint, entry.code_hash[:12], current[:12],
                    )
                    continue
        kept.append(entry)
    return kept


def revalidate_allowlist(
    project_dir: Path,
    allowlist: list[AllowlistEntry],
) -> tuple[list[AllowlistEntry], list[AllowlistEntry]]:
    """Revalidate allowlist entries against current project state.

    Returns (still_valid, invalidated).
    An entry is invalidated if:
    - File no longer exists
    - grep_proof: the evidence pattern no longer matches in the file
    - Line number drifted beyond recognition (file shrunk past that line)
    - Entry has expired (expires_at in the past)
    """
    import time as _time

    still_valid: list[AllowlistEntry] = []
    invalidated: list[AllowlistEntry] = []

    for entry in allowlist:
        if not entry.is_valid():
            invalidated.append(entry)
            continue

        # Check expiry
        if entry.expires_at:
            try:
                import datetime
                exp = datetime.datetime.fromisoformat(entry.expires_at.replace("Z", "+00:00"))
                if exp.timestamp() < _time.time():
                    invalidated.append(entry)
                    continue
            except (ValueError, TypeError):
                pass

        # Check file still exists
        file_path = project_dir / entry.file
        if not file_path.exists():
            invalidated.append(entry)
            continue

        # Check line still in range
        try:
            content = file_path.read_text(encoding="utf-8", errors="replace")
            line_count = content.count("\n") + 1
            if entry.line > 0 and entry.line > line_count:
                invalidated.append(entry)
                continue
        except OSError:
            invalidated.append(entry)
            continue

        # For grep_proof: verify the evidence pattern still matches
        if entry.evidence_type == "grep_proof":
            # Extract a key phrase from evidence to grep for
            # Evidence format: "grep shows X used at line Y" or similar
            # We check if any meaningful word from evidence exists in the file
            evidence_words = [
                w for w in entry.evidence.split()
                if len(w) > 4 and w.isalnum()
            ]
            if evidence_words:
                found_any = any(w in content for w in evidence_words[:3])
                if not found_any:
                    invalidated.append(entry)
                    continue

        still_valid.append(entry)

    return still_valid, invalidated


def save_allowlist(project_dir: Path, entries: list[AllowlistEntry]) -> Path:
    """Write allowlist back to disk (after revalidation cleanup)."""
    import json as _json
    import os as _os
    import tempfile as _tempfile
    path = project_dir / ".prompt-engineer" / "forensic_gates" / "false_positive_allowlist.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    content = _json.dumps([e.to_dict() for e in entries], indent=2, ensure_ascii=False) + "\n"
    tmp_fd, tmp_path = _tempfile.mkstemp(dir=str(path.parent), suffix=".tmp")
    try:
        _os.write(tmp_fd, content.encode("utf-8"))
        _os.close(tmp_fd)
        _os.replace(tmp_path, str(path))
    except BaseException:
        try:
            _os.close(tmp_fd)
        except OSError:
            pass
        try:
            _os.unlink(tmp_path)
        except OSError:
            pass
        raise
    return path


def filter_by_allowlist(
    findings: list,  # list of GateFinding
    allowlist: list[AllowlistEntry],
    project_dir: Optional[Path] = None,
) -> tuple[list, list, list[str]]:
    """Split findings into (remaining, filtered_out, notes) based on valid allowlist entries.

    If project_dir is provided, revalidates entries first and removes stale ones.
    Only entries with valid proof are honored. Invalid entries are ignored.
    """
    notes: list[str] = []

    if not allowlist:
        return findings, [], notes

    # Revalidate if project_dir available
    if project_dir is not None:
        valid_entries, invalidated = revalidate_allowlist(project_dir, allowlist)
        if invalidated:
            notes.append(
                f"[allowlist] Removed {len(invalidated)} stale/invalid entries "
                f"(file deleted, proof invalidated, or expired)"
            )
            # Save cleaned allowlist back to disk
            try:
                save_allowlist(project_dir, valid_entries)
            except OSError:
                pass
        allowlist = valid_entries

    valid_fps = {
        entry.fingerprint
        for entry in allowlist
        if entry.is_valid()
    }

    if not valid_fps:
        return findings, [], notes

    remaining = []
    filtered = []
    for finding in findings:
        if finding.fingerprint in valid_fps:
            filtered.append(finding)
        else:
            remaining.append(finding)

    return remaining, filtered, notes
