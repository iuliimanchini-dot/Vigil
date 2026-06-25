from __future__ import annotations

import ast

from cortex_forensic._shared import EvidenceReference, GateCategory, GateImpact, GateSeverity, RepairKind
from cortex_forensic.gate_models import PostExecGateContext
from ..source_analysis import is_source_file
from .common import build_check_result, build_finding, iter_touched_snapshots, normalize_path
from ._ast_helpers import parse_python_source_or_emit_finding
import logging
_log = logging.getLogger(__name__)


EXPENSIVE_CALL_NAMES = {
    "read_text",
    "read_bytes",
    "subprocess.run",
    "check_output",
    "path_exists",
    "execute",
    "connect",
    "os.system",
    "shutil.copy",
    "shutil.copytree",
    "shutil.move",
}

# Files that ARE file-processors by design — reading files in loops is their job.
# Flagging these generates noise without actionable signal.
_FILE_PROCESSOR_PATH_FRAGMENTS = (
    "gate_checks/",
    "map_builder/",
    "source_adapters/",
)


def run_performance_checks(ctx: PostExecGateContext):
    findings = []
    profile = ctx.repo_profile
    for snapshot in iter_touched_snapshots(ctx):
        if not snapshot.exists or not is_source_file(snapshot.path):
            continue
        if profile and not profile.is_performance_sensitive(snapshot.path):
            continue
        norm_path = snapshot.path.replace("\\", "/")
        if any(frag in norm_path for frag in _FILE_PROCESSOR_PATH_FRAGMENTS):
            continue
        # Sprint C2 (2026-04-23): prefer TestTopology.is_test_path. Legacy
        # basename check preserved as fallback for contexts where
        # ProjectContext.test_topology hasn't been built (older call sites,
        # unit tests constructing a PostExecGateContext by hand).
        topology = getattr(getattr(ctx, "project_context", None), "test_topology", None)
        if topology is not None:
            if topology.is_test_path(norm_path):
                continue
        elif norm_path.split("/")[-1].startswith("test_"):
            continue
        # B4 (2026-04-23): replaces silent `except SyntaxError: continue` —
        # meta.syntax_parse_error is now emitted on broken Python sources.
        tree = parse_python_source_or_emit_finding(
            snapshot.text,
            rel_path=normalize_path(snapshot.path),
            emit_finding=findings.append,
            emitting_gate="performance.expensive_in_loop",
        )
        if tree is None:
            continue
        for node in ast.walk(tree):
            if not isinstance(node, (ast.For, ast.AsyncFor, ast.While)):
                continue
            for child in ast.walk(node):
                if isinstance(child, ast.Call):
                    name = _call_name(child)
                    parts = name.rsplit(".", 1)
                    bare = parts[1] if len(parts) == 2 else None
                    if name in EXPENSIVE_CALL_NAMES or (bare and bare in EXPENSIVE_CALL_NAMES):
                        findings.append(
                            build_finding(
                                check_id="performance.expensive_in_loop",
                                category=GateCategory.PERFORMANCE,
                                title="Touched code performs expensive work inside a loop",
                                severity=GateSeverity.HIGH,
                                impact=GateImpact.REVISE,
                                summary=f"{snapshot.path} calls '{name}' inside a loop, which is a likely hot-path anti-pattern.",
                                recommendation="Batch the work, cache repeated reads, or move the expensive call out of the loop.",
                                evidence=[EvidenceReference(kind="file", path=snapshot.path, detail=name)],
                                repair_kind=RepairKind.REFACTOR.value,
                                executor_action="Optimize hot code paths",
                                proof_required="Performance acceptable",
                                allowlist_allowed=False,
                            )
                        )
    return build_check_result(check_id="performance", category=GateCategory.PERFORMANCE, findings=findings)


def _call_name(node: ast.Call) -> str:
    """Return a qualified call name like 'subprocess.run' or bare 'load'."""
    func = node.func
    if isinstance(func, ast.Attribute):
        if isinstance(func.value, ast.Name):
            return f"{func.value.id}.{func.attr}"
        # self.executor.run -> just attr
        return str(func.attr)
    if isinstance(func, ast.Name):
        return str(func.id)
    return ""
