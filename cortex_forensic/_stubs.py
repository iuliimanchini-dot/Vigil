"""Minimal stubs for control-plane types used by self_audit.py.

self_audit.py imports the control-plane ValidationContractProfile type and
the PocketCoderForensicReport type at module level. In the standalone package
those cluster modules do not exist, so this file provides drop-in stubs.

These are used ONLY to construct empty stub instances via .from_mapping({})
inside build_synthetic_context(). The full Vigil implementations have many
fields; the stubs here carry only what the gate logic actually reads in a
static (sessionless) context.

Verified minimal surface (from cli_forensic_audit._build_stub_* and
self_audit.build_synthetic_context):
  - ValidationContractProfile: .from_mapping({}) -> instance; .to_dict() -> dict
  - PocketCoderForensicReport: .from_mapping({}) -> instance; .to_dict() -> dict
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Mapping


@dataclass
class ValidationContractProfile:
    """Minimal stub — enough for PostExecGateContext construction in static mode."""
    contract_name: str = ""
    task_classification: str = ""
    required_proofs: tuple[str, ...] = field(default_factory=tuple)
    optional_proofs: tuple[str, ...] = field(default_factory=tuple)
    disqualifying_failures: tuple[str, ...] = field(default_factory=tuple)
    requires_commit_proof: bool = False
    requires_remote_truth: bool = False
    requires_hook_policy_proof: bool = False
    requires_codex_review: bool = False
    requires_gate: bool = False

    @classmethod
    def from_mapping(cls, data: Mapping[str, Any]) -> "ValidationContractProfile":
        def _str(k: str) -> str:
            return str(data.get(k, "") or "")
        def _bool(k: str) -> bool:
            return bool(data.get(k, False))
        def _str_tuple(k: str) -> tuple[str, ...]:
            v = data.get(k)
            if isinstance(v, (list, tuple)):
                return tuple(str(x) for x in v)
            return ()
        return cls(
            contract_name=_str("contract_name"),
            task_classification=_str("task_classification"),
            required_proofs=_str_tuple("required_proofs"),
            optional_proofs=_str_tuple("optional_proofs"),
            disqualifying_failures=_str_tuple("disqualifying_failures"),
            requires_commit_proof=_bool("requires_commit_proof"),
            requires_remote_truth=_bool("requires_remote_truth"),
            requires_hook_policy_proof=_bool("requires_hook_policy_proof"),
            requires_codex_review=_bool("requires_codex_review"),
            requires_gate=_bool("requires_gate"),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "contract_name": self.contract_name,
            "task_classification": self.task_classification,
            "required_proofs": list(self.required_proofs),
            "optional_proofs": list(self.optional_proofs),
            "disqualifying_failures": list(self.disqualifying_failures),
            "requires_commit_proof": self.requires_commit_proof,
            "requires_remote_truth": self.requires_remote_truth,
            "requires_hook_policy_proof": self.requires_hook_policy_proof,
            "requires_codex_review": self.requires_codex_review,
            "requires_gate": self.requires_gate,
        }


@dataclass
class PocketCoderForensicReport:
    """Minimal stub — enough for PostExecGateContext construction in static mode.

    The real class has ~30 fields. Static forensic audit reads none of them
    substantively; gates that need forensic_report data are all in
    skip_in_static. This stub holds the shape, all defaulting to empty/0.
    """
    created_at: float = 0.0
    session_number: int = 0
    current_task_id: str = ""
    blocking_issues: tuple[str, ...] = field(default_factory=tuple)
    warnings: tuple[str, ...] = field(default_factory=tuple)
    changed_files: tuple[str, ...] = field(default_factory=tuple)
    task_relevant_changed_files: tuple[str, ...] = field(default_factory=tuple)
    unexpected_changed_files: tuple[str, ...] = field(default_factory=tuple)
    dirty_baseline_files: tuple[str, ...] = field(default_factory=tuple)
    git_diff_stat: str = ""
    summary: str = ""
    project_id: str = ""
    schema_version: str = "stub"
    observability_coverage: float = 0.0
    foc_findings_ids: tuple[str, ...] = field(default_factory=tuple)

    @classmethod
    def from_mapping(cls, data: Mapping[str, Any]) -> "PocketCoderForensicReport":
        def _str(k: str) -> str:
            return str(data.get(k, "") or "")
        def _float(k: str) -> float:
            v = data.get(k, 0.0)
            try:
                return float(v)
            except (TypeError, ValueError):
                return 0.0
        def _int(k: str) -> int:
            v = data.get(k, 0)
            try:
                return int(v)
            except (TypeError, ValueError):
                return 0
        def _str_tuple(k: str) -> tuple[str, ...]:
            v = data.get(k)
            if isinstance(v, (list, tuple)):
                return tuple(str(x) for x in v)
            return ()
        return cls(
            created_at=_float("created_at"),
            session_number=_int("session_number"),
            current_task_id=_str("current_task_id"),
            blocking_issues=_str_tuple("blocking_issues"),
            warnings=_str_tuple("warnings"),
            changed_files=_str_tuple("changed_files"),
            task_relevant_changed_files=_str_tuple("task_relevant_changed_files"),
            unexpected_changed_files=_str_tuple("unexpected_changed_files"),
            dirty_baseline_files=_str_tuple("dirty_baseline_files"),
            git_diff_stat=_str("git_diff_stat"),
            summary=_str("summary"),
            project_id=_str("project_id"),
            schema_version=_str("schema_version") or "stub",
            observability_coverage=_float("observability_coverage"),
            foc_findings_ids=_str_tuple("foc_findings_ids"),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "created_at": self.created_at,
            "session_number": self.session_number,
            "current_task_id": self.current_task_id,
            "blocking_issues": list(self.blocking_issues),
            "warnings": list(self.warnings),
            "changed_files": list(self.changed_files),
            "task_relevant_changed_files": list(self.task_relevant_changed_files),
            "unexpected_changed_files": list(self.unexpected_changed_files),
            "dirty_baseline_files": list(self.dirty_baseline_files),
            "git_diff_stat": self.git_diff_stat,
            "summary": self.summary,
            "project_id": self.project_id,
            "schema_version": self.schema_version,
            "observability_coverage": self.observability_coverage,
            "foc_findings_ids": list(self.foc_findings_ids),
        }
