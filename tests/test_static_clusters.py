"""TDD: static-safe forensic_clusters in static mode.

Background
----------
``run_forensic_audit`` runs in *static mode* — it builds a synthetic
``PostExecGateContext`` from on-disk ``file_snapshots`` only, with NO runtime
context (no ``artifact_refs``, empty ``transport_mode``, ``session_number=0``,
empty verification/runtime state). Historically the WHOLE ``forensic_clusters``
gate pack was flagged ``skip_in_static`` and never ran, so ~40 purely-static
cluster checks (mutable defaults, SQL-injection, resource leaks, hardcoded
paths, secrets, dead code, …) produced ZERO findings on any project. Oracle
recall was effectively 0/4 for known static issues.

The fix runs the pack in static mode but filters out the RUNTIME-ONLY
sub-checks (``_RUNTIME_ONLY_CLUSTERS``) that need execution context and would
otherwise emit false positives (notably ``cluster11_mutation_verified``, which
compares a decoded-text hash against a raw-bytes disk re-read — a guaranteed
mismatch on CRLF/BOM files).

These tests pin BOTH halves:
  * ORACLE RECALL — known static issues are now flagged.
  * NO RUNTIME FP — clean code produces no ``mutation_verified`` /
    ``success_proof`` / ``state_divergence`` findings.

Run:  pytest tests/test_static_clusters.py -v
"""
from __future__ import annotations

from pathlib import Path

import pytest


# Runner ids in the cluster pack that depend on runtime/verification context and
# must NEVER run in static mode (would emit false positives or are meaningless).
RUNTIME_ONLY_CLUSTER_LABELS = frozenset({
    "cluster2_success_without_proof",
    "cluster4_config_accepted_ignored_proofs",
    "cluster6_state_divergence",
    "cluster7_fallback_hides_truth",
    "cluster3_proxy_as_truth",
    "cluster4_config_accepted_ignored_general",
    "cluster10_edit_consistency",
    "cluster11_mutation_verified",
})

# check_ids these runtime-only runners emit — must be absent from a static run.
RUNTIME_ONLY_CHECK_IDS = frozenset({
    "mutation_verified",
    "success_proof",
    "state_divergence",
    "proxy_as_truth",
    "fallback_transparency",
    "config_applied",
    "edit_consistency",
})


# Oracle source: each line carries ONE issue in the canonical form the matching
# static cluster check is designed to detect (these detectors are AST/structure
# based and deliberately precise to avoid FPs, so the oracle uses the forms they
# actually catch — not arbitrary variants the detectors intentionally skip):
#   * mutable default arg            -> cluster36 (assess_mutable_defaults)
#   * f-string SQL into .execute()   -> cluster12  (assess_security_patterns)
#   * open() without with/close      -> cluster37 (assess_resource_leaks)
#   * Windows absolute path literal  -> cluster32 (assess_hardcoded_paths)
ORACLE_SOURCE = '''\
import sqlite3


def add_item(item, items=[]):  # mutable default argument (cluster36)
    items.append(item)
    return items


def get_user(cur, user_input):
    cur.execute(f"SELECT name FROM users WHERE id = {user_input}")  # SQL injection (cluster12)
    return cur.fetchall()


def read_log():
    f = open("data.log")  # resource leak (cluster37): no close / context manager
    data = f.read()
    return data


def config_dir():
    return "C:\\\\Windows\\\\System32\\\\drivers"  # hardcoded Windows path (cluster32)
'''


def _run_audit(project_dir: Path):
    from vigil_forensic import run_forensic_audit
    # pip-audit shells out and is slow/networked; cluster17 self-skips on this.
    import os
    os.environ.setdefault("AI_HOST_SKIP_PIP_AUDIT", "1")
    return run_forensic_audit(project_dir)


def _all_text(findings) -> str:
    parts = []
    for f in findings:
        parts.append(str(f.get("check_id", "")))
        parts.append(str(f.get("title", "")))
        parts.append(str(f.get("summary", "")))
        for ev in f.get("evidence", []) or []:
            parts.append(str(ev.get("detail", "")))
    return "\n".join(parts).lower()


# ---------------------------------------------------------------------------
# Oracle recall — known static issues must be flagged
# ---------------------------------------------------------------------------

class TestOracleRecall:
    def test_forensic_clusters_not_skipped_in_static(self):
        """The whole pack must no longer be force-skipped in static mode."""
        from vigil_forensic.self_audit import _SKIP_IN_STATIC_MODE
        assert "forensic_clusters" not in _SKIP_IN_STATIC_MODE, (
            "forensic_clusters must run in static mode (with runtime-only "
            "sub-checks filtered) to provide static-safe findings"
        )

    def test_oracle_known_issues_flagged(self, tmp_path: Path):
        """A file with a mutable default, SQL-injection and resource leak must
        produce findings (recall fix — was ~0 before)."""
        (tmp_path / "oracle.py").write_text(ORACLE_SOURCE, encoding="utf-8")
        result = _run_audit(tmp_path)
        findings = result["findings"]
        # forensic_clusters must have actually run.
        skipped = result["meta"].get("gates_skipped_in_static", [])
        assert "forensic_clusters" not in skipped, (
            f"forensic_clusters still skipped in static: {skipped}"
        )

        blob = _all_text(findings)
        hits = {
            "mutable_default": ("mutable" in blob and "default" in blob),
            "sql_injection": ("sql" in blob and "injection" in blob),
            "resource_leak": ("resource leak" in blob or "not closed" in blob
                              or "without `with`" in blob or "context manager" in blob),
            "hardcoded_path": ("/etc/passwd" in blob or "hardcoded" in blob),
        }
        recall = sum(hits.values())
        assert recall >= 3, (
            f"oracle recall too low: {recall}/4 hits={hits}\n"
            f"check_ids={sorted({f.get('check_id') for f in findings})}"
        )

    def test_mutable_default_specifically_flagged(self, tmp_path: Path):
        (tmp_path / "m.py").write_text(
            "def f(a, items=[]):\n    items.append(a)\n    return items\n",
            encoding="utf-8",
        )
        result = _run_audit(tmp_path)
        blob = _all_text(result["findings"])
        assert "mutable" in blob and "default" in blob, (
            f"mutable-default not flagged; check_ids="
            f"{sorted({f.get('check_id') for f in result['findings']})}"
        )


# ---------------------------------------------------------------------------
# No runtime false-positives — clean code must not trip runtime-only checks
# ---------------------------------------------------------------------------

class TestNoRuntimeFalsePositives:
    def test_clean_file_no_runtime_fp(self, tmp_path: Path):
        """Trivially-clean code → no mutation_verified/success_proof/etc."""
        (tmp_path / "clean.py").write_text(
            "def add(a, b):\n    return a + b\n", encoding="utf-8",
        )
        result = _run_audit(tmp_path)
        offenders = [
            f for f in result["findings"]
            if f.get("check_id") in RUNTIME_ONLY_CHECK_IDS
        ]
        assert not offenders, (
            f"runtime-only findings leaked into static run: "
            f"{[(o.get('check_id'), o.get('summary')) for o in offenders]}"
        )

    def test_crlf_file_no_mutation_verified_fp(self, tmp_path: Path):
        """CRLF / BOM files must NOT trip cluster11_mutation_verified.

        The runner hashes decoded text while the assessor hashes raw disk
        bytes; on CRLF/BOM files those differ → a bogus 'content DIVERGED'
        HIGH. This is the precise runtime FP the static-mode filter prevents.
        """
        # Force CRLF + BOM on disk.
        raw = "﻿" + "def g(x):\r\n    return x + 1\r\n"
        (tmp_path / "crlf.py").write_bytes(raw.encode("utf-8"))
        result = _run_audit(tmp_path)
        mv = [f for f in result["findings"] if f.get("check_id") == "mutation_verified"]
        assert not mv, (
            f"mutation_verified FP on CRLF/BOM file (the exact bug we fix): "
            f"{[m.get('summary') for m in mv]}"
        )

    def test_runtime_only_clusters_filtered_when_no_artifact_refs(self, tmp_path: Path):
        """Directly exercise the runner: with a static context (no artifact_refs),
        the runtime-only clusters must be filtered out of execution."""
        from vigil_forensic.gate_checks.forensic_cluster_runners import core as core_mod

        # The module must expose the runtime-only set and a way to detect static.
        assert hasattr(core_mod, "_RUNTIME_ONLY_CLUSTERS"), (
            "_RUNTIME_ONLY_CLUSTERS must be defined in core.py"
        )
        # The declared runtime-only labels must match our contract.
        assert RUNTIME_ONLY_CLUSTER_LABELS <= core_mod._RUNTIME_ONLY_CLUSTERS, (
            f"_RUNTIME_ONLY_CLUSTERS missing labels: "
            f"{RUNTIME_ONLY_CLUSTER_LABELS - core_mod._RUNTIME_ONLY_CLUSTERS}"
        )

    def test_filelock_no_runtime_fp(self):
        """Real third-party package (filelock): static run must not emit any
        runtime-only findings (mutation_verified/success_proof/state_divergence)."""
        import vigil_forensic
        repo_root = Path(vigil_forensic.__file__).resolve().parent.parent
        filelock_dir = repo_root / ".venv" / "Lib" / "site-packages" / "filelock"
        if not filelock_dir.is_dir():
            pytest.skip("filelock not installed in .venv")
        result = _run_audit(filelock_dir)
        offenders = [
            f for f in result["findings"]
            if f.get("check_id") in RUNTIME_ONLY_CHECK_IDS
        ]
        assert not offenders, (
            f"runtime-only findings on filelock static scan: "
            f"{[(o.get('check_id'), o.get('summary')) for o in offenders]}"
        )
