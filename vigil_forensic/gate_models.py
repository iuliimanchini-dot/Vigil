"""Gate models for vigil_forensic.

Re-exports shared vocabulary types from _shared (inlined from the Vigil shared_helpers.gate_models)
and defines PostExecGateContext and related dataclasses (inlined from the Vigil autoforensics.gate_models).

This module provides backward-compatible re-exports so gate_checks can use:
    from vigil_forensic.gate_models import PostExecGateContext, ...
"""
from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Any, Mapping, Optional

_log = logging.getLogger(__name__)

# Import coerce_float from our inlined _shared
from vigil_forensic._shared import coerce_float as _coerce_float

# Re-export the shared vocabulary from our inlined _shared module.
from vigil_forensic._shared import (  # noqa: F401
    EvidenceReference,
    GateCategory,
    GateCheckResult,
    GateFileSnapshot,
    GateFinding,
    GateImpact,
    GateSeverity,
    GateVerdict,
    RepairKind,
    RepoGateProfile,
)

# Import stubs for control-plane types (replaces SYSTEM.control_plane.models
# and SYSTEM.runtime.pocketcoder_adapter imports in the original self_audit.py)
from vigil_forensic._stubs import ValidationContractProfile, PocketCoderForensicReport

if TYPE_CHECKING:
    pass  # No TYPE_CHECKING imports needed in the standalone package


# Default identity strings
_VERDICT_OWNER_DEFAULT: str = "orchestrator"
_PROMPT_OWNER_DEFAULT: str = "orchestrator"
_SUPERVISOR_DEFAULT: str = "orchestrator"


_HOOK_TRACE_KNOWN_KEYS: frozenset[str] = frozenset({
    "ts", "tool_name", "decision", "reason", "attempt_id", "summary",
    "command_scope", "is_remote_wrapper", "approval_class", "actor",
    "policy_rule", "provenance", "target_path", "target_paths",
    "workspace_root", "path_scope", "tool_input_digest",
})


def _now() -> float:
    return time.time()


@dataclass(frozen=True)
class HookTraceEntry:
    ts: float = 0.0
    tool_name: str = ""
    decision: str = ""
    reason: str = ""
    attempt_id: str = "unknown"
    summary: str = ""
    command_scope: str = ""
    is_remote_wrapper: bool = False
    approval_class: str = ""
    actor: str = ""
    policy_rule: str = ""
    target_path: str = ""
    target_paths: tuple[str, ...] = ()
    workspace_root: str = ""
    path_scope: str = ""
    tool_input_digest: str = ""
    extras: tuple[tuple[str, object], ...] = ()

    @classmethod
    def from_mapping(cls, data: Mapping[str, object]) -> "HookTraceEntry":
        provenance_raw = data.get("provenance")
        provenance: dict[str, object] = dict(provenance_raw) if isinstance(provenance_raw, dict) else {}

        def _pick(name: str, default: object = "") -> object:
            if name in data:
                return data.get(name)
            return provenance.get(name, default)

        extras_raw = [(key, value) for key, value in data.items() if key not in _HOOK_TRACE_KNOWN_KEYS]
        if provenance:
            for prov_key, prov_val in provenance.items():
                if prov_key in _HOOK_TRACE_KNOWN_KEYS:
                    continue
                extras_raw.append((prov_key, prov_val))
        extras_raw.sort(key=lambda item: item[0])

        target_paths_raw = data.get("target_paths")
        if isinstance(target_paths_raw, (list, tuple)):
            target_paths = tuple(str(x) for x in target_paths_raw)
        else:
            target_paths = ()

        return cls(
            ts=_coerce_float(data.get("ts")),
            tool_name=str(data.get("tool_name", "") or ""),
            decision=str(data.get("decision", "") or ""),
            reason=str(data.get("reason", "") or ""),
            attempt_id=str(data.get("attempt_id", "unknown") or "unknown"),
            summary=str(data.get("summary", "") or ""),
            command_scope=str(data.get("command_scope", "") or ""),
            is_remote_wrapper=bool(data.get("is_remote_wrapper", False)),
            approval_class=str(data.get("approval_class", "") or ""),
            actor=str(_pick("actor", "") or ""),
            policy_rule=str(_pick("policy_rule", "") or ""),
            target_path=str(data.get("target_path", "") or ""),
            target_paths=target_paths,
            workspace_root=str(data.get("workspace_root", "") or ""),
            path_scope=str(data.get("path_scope", "") or ""),
            tool_input_digest=str(data.get("tool_input_digest", "") or ""),
            extras=tuple(extras_raw),
        )

    def to_dict(self) -> dict[str, object]:
        payload: dict[str, object] = {
            "ts": self.ts, "tool_name": self.tool_name, "decision": self.decision,
            "reason": self.reason, "attempt_id": self.attempt_id, "summary": self.summary,
            "command_scope": self.command_scope, "is_remote_wrapper": self.is_remote_wrapper,
            "approval_class": self.approval_class, "actor": self.actor,
            "policy_rule": self.policy_rule, "target_path": self.target_path,
            "target_paths": list(self.target_paths), "workspace_root": self.workspace_root,
            "path_scope": self.path_scope, "tool_input_digest": self.tool_input_digest,
        }
        for key, value in self.extras:
            payload[key] = value
        return payload


@dataclass(frozen=True)
class RuntimeState:
    health: str = "healthy"
    runtime_model: str = "local_workspace"
    survives_console_exit: Optional[bool] = None
    extras: tuple[tuple[str, object], ...] = ()

    @classmethod
    def from_mapping(cls, data: Mapping[str, object]) -> "RuntimeState":
        known = {"health", "runtime_model", "survives_console_exit"}
        extras = sorted(
            ((k, v) for k, v in data.items() if k not in known),
            key=lambda item: item[0],
        )
        raw_survives = data.get("survives_console_exit")
        survives: Optional[bool] = None if raw_survives is None else bool(raw_survives)
        return cls(
            health=str(data.get("health", "healthy") or "healthy"),
            runtime_model=str(data.get("runtime_model", "local_workspace") or "local_workspace"),
            survives_console_exit=survives,
            extras=tuple(extras),
        )

    def to_dict(self) -> dict[str, object]:
        payload: dict[str, object] = {
            "health": self.health, "runtime_model": self.runtime_model,
            "survives_console_exit": self.survives_console_exit,
        }
        for key, value in self.extras:
            payload[key] = value
        return payload


@dataclass(frozen=True)
class VerificationSummary:
    passed: bool = True
    blocking_issues: tuple[str, ...] = ()
    warnings: tuple[str, ...] = ()
    summary: str = ""
    verdict_owner: str = _VERDICT_OWNER_DEFAULT
    extras: tuple[tuple[str, object], ...] = ()

    @classmethod
    def from_mapping(cls, data: Mapping[str, object]) -> "VerificationSummary":
        known = {"passed", "blocking_issues", "warnings", "summary", "verdict_owner"}

        def _str_tuple(value: object) -> tuple[str, ...]:
            if value is None:
                return ()
            if isinstance(value, (list, tuple)):
                return tuple(str(item) for item in value)
            return ()

        extras = sorted(
            ((k, v) for k, v in data.items() if k not in known),
            key=lambda item: item[0],
        )
        return cls(
            passed=bool(data.get("passed", True)),
            blocking_issues=_str_tuple(data.get("blocking_issues", ())),
            warnings=_str_tuple(data.get("warnings", ())),
            summary=str(data.get("summary", "") or ""),
            verdict_owner=str(data.get("verdict_owner", _VERDICT_OWNER_DEFAULT) or _VERDICT_OWNER_DEFAULT),
            extras=tuple(extras),
        )

    def to_dict(self) -> dict[str, object]:
        payload: dict[str, object] = {
            "passed": self.passed, "blocking_issues": list(self.blocking_issues),
            "warnings": list(self.warnings), "summary": self.summary,
            "verdict_owner": self.verdict_owner,
        }
        for key, value in self.extras:
            payload[key] = value
        return payload


@dataclass(frozen=True)
class HookTraceLoadProvenance:
    kind: str = ""
    started_at: float = 0.0
    entries_considered: int = 0
    entries_loaded: int = 0
    extras: tuple[tuple[str, object], ...] = ()

    @classmethod
    def from_mapping(cls, data: Mapping[str, object]) -> "HookTraceLoadProvenance":
        known = {"kind", "started_at", "entries_considered", "entries_loaded"}
        extras = tuple(sorted(((k, v) for k, v in data.items() if k not in known), key=lambda item: item[0]))
        return cls(
            kind=str(data.get("kind", "") or ""),
            started_at=_coerce_float(data.get("started_at")),
            entries_considered=int(data.get("entries_considered", 0) or 0),
            entries_loaded=int(data.get("entries_loaded", 0) or 0),
            extras=extras,
        )

    def to_dict(self) -> dict[str, object]:
        out: dict[str, object] = {
            "kind": self.kind, "started_at": self.started_at,
            "entries_considered": self.entries_considered, "entries_loaded": self.entries_loaded,
        }
        for k, v in self.extras:
            out[k] = v
        return out


@dataclass(frozen=True)
class DraftMessageEvidence:
    message_id: str = ""
    draft_id: str = ""
    role: str = ""
    created_at: float = 0.0
    no_executor_started: bool = True
    draft_assistant_mode: str = ""
    extras: tuple[tuple[str, object], ...] = ()

    @classmethod
    def from_mapping(cls, data: Mapping[str, object]) -> "DraftMessageEvidence":
        known = {"message_id", "draft_id", "role", "created_at", "no_executor_started", "draft_assistant_mode"}
        extras = tuple((k, v) for k, v in data.items() if k not in known)
        return cls(
            message_id=str(data.get("message_id", "") or ""),
            draft_id=str(data.get("draft_id", "") or ""),
            role=str(data.get("role", "") or ""),
            created_at=_coerce_float(data.get("created_at")),
            no_executor_started=bool(data.get("no_executor_started", True)),
            draft_assistant_mode=str(data.get("draft_assistant_mode", "") or ""),
            extras=extras,
        )

    def to_dict(self) -> dict[str, object]:
        out: dict[str, object] = {
            "message_id": self.message_id, "draft_id": self.draft_id,
            "role": self.role, "created_at": self.created_at,
            "no_executor_started": self.no_executor_started,
            "draft_assistant_mode": self.draft_assistant_mode,
        }
        for k, v in self.extras:
            out[k] = v
        return out


@dataclass(frozen=True)
class PostExecGateContext:
    project_dir: Path
    session_number: int
    task_id: str
    a1_task_id: str
    validation_contract: "ValidationContractProfile"
    forensic_report: "PocketCoderForensicReport"
    runtime_state: RuntimeState
    verification_summary: VerificationSummary
    attempt_id: str = ""
    gate_round: int = 1
    maps: "Optional[Any]" = None
    task_intent: str = ""
    transport_mode: str = ""
    project_mode: str = ""
    original_user_request: str = ""
    structured_handoff: Optional[Any] = None
    self_check_summary: str = ""
    changed_files_reported: tuple[str, ...] = field(default_factory=tuple)
    changed_files_observed: tuple[str, ...] = field(default_factory=tuple)
    touched_files: tuple[str, ...] = field(default_factory=tuple)
    # True = full-project scan (standalone self-audit): clears cross_touched_duplicate
    # so it does not double-count duplicate_scan. False = incremental diff (default).
    is_full_scan: bool = False
    artifact_refs: dict[str, str] = field(default_factory=dict)
    prior_findings: tuple[str, ...] = field(default_factory=tuple)
    tests_touched: tuple[str, ...] = field(default_factory=tuple)
    file_snapshots: dict[str, GateFileSnapshot] = field(default_factory=dict)
    source_package_roots: tuple[str, ...] = field(default_factory=tuple)
    repo_profile: Optional[RepoGateProfile] = None
    plan_artifact: Optional[Any] = None
    execution_pack: Optional[Any] = None
    codex_executor_brief: Optional[Any] = None
    codex_review: Optional[Any] = None
    codex_repair_brief: Optional[Any] = None
    control_task_metadata: dict[str, Any] = field(default_factory=dict)
    draft_metadata: Optional[Any] = None
    mutable_draft_artifact: Optional[Any] = None
    draft_launch_snapshot: Optional[Any] = None
    session_artifacts: dict[str, str] = field(default_factory=dict)
    artifact_load_errors: dict[str, str] = field(default_factory=dict)
    hook_trace_entries: tuple[HookTraceEntry, ...] = field(default_factory=tuple)
    hook_trace_load_provenance: HookTraceLoadProvenance = field(default_factory=HookTraceLoadProvenance)
    draft_messages: tuple[DraftMessageEvidence, ...] = field(default_factory=tuple)
    project_context: Optional[Any] = None
    self_check_findings: tuple[str, ...] = field(default_factory=tuple)
    self_check_parse_status: str = "n/a"
    self_check_passed: Optional[bool] = None
    foc_pre_gate_results: Optional[Mapping[str, object]] = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "session_number": self.session_number,
            "task_id": self.task_id,
            "a1_task_id": self.a1_task_id,
            "attempt_id": self.attempt_id,
            "gate_round": self.gate_round,
            "task_intent": self.task_intent,
            "transport_mode": self.transport_mode,
            "project_mode": self.project_mode,
            "original_user_request": self.original_user_request,
            "self_check_summary": self.self_check_summary,
            "changed_files_reported": list(self.changed_files_reported),
            "changed_files_observed": list(self.changed_files_observed),
            "touched_files": list(self.touched_files),
            "validation_contract": self.validation_contract.to_dict(),
            "forensic_report": self.forensic_report.to_dict(),
            "runtime_state": self.runtime_state.to_dict(),
            "artifact_refs": self.artifact_refs,
            "verification_summary": self.verification_summary.to_dict(),
            "prior_findings": list(self.prior_findings),
            "tests_touched": list(self.tests_touched),
            "file_snapshots": {k: v.to_dict() for k, v in self.file_snapshots.items()},
            "repo_profile": self.repo_profile.to_dict() if self.repo_profile else {},
            "control_task_metadata": self.control_task_metadata,
            "session_artifacts": dict(self.session_artifacts),
            "artifact_load_errors": dict(self.artifact_load_errors),
            "hook_trace_entries": [entry.to_dict() for entry in self.hook_trace_entries],
            "hook_trace_load_provenance": self.hook_trace_load_provenance.to_dict(),
            "draft_messages": [m.to_dict() for m in self.draft_messages],
            "self_check_findings": list(self.self_check_findings),
            "self_check_parse_status": self.self_check_parse_status,
            "self_check_passed": self.self_check_passed,
            "foc_pre_gate_results": (
                dict(self.foc_pre_gate_results) if self.foc_pre_gate_results is not None else None
            ),
        }


def detect_source_package_roots(project_dir: Path) -> tuple[str, ...]:
    """Auto-detect top-level Python package roots in project_dir."""
    _EXCLUDE = frozenset({
        "__pycache__", ".git", ".venv", "venv", "env", "node_modules",
        "dist", "build", ".tox", ".mypy_cache", ".ruff_cache", ".pytest_cache",
        ".cortex", "libs", "tests", "test",
    })
    roots = []
    try:
        for item in sorted(project_dir.iterdir()):
            if not item.is_dir():
                continue
            if item.name.startswith(".") or item.name in _EXCLUDE:
                continue
            if (item / "__init__.py").exists():
                roots.append(item.name)
    except OSError:
        _log.warning("gate_models: failed to scan project roots in %s", project_dir, exc_info=True)
    return tuple(roots)
