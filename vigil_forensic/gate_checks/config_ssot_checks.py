from __future__ import annotations

import re

from vigil_forensic._shared import EvidenceReference, GateCategory, GateImpact, GateSeverity
from vigil_forensic.gate_models import PostExecGateContext
from .common import build_check_result, build_finding, iter_touched_snapshots
import logging
_log = logging.getLogger(__name__)

# Config keys that must be read via the canonical config path, not env vars directly.
_ENV_BYPASS_KEYS = {"VIGIL_PORT", "CONTROL_PLANE_PORT", "VIGIL_DB_PATH"}

# Files that are legitimately allowed to read these env vars (e.g. the canonical config resolver itself).
_ALLOWED_ENV_READERS = {"config.py", "settings.py", "config_loader.py", "vigil_config.py"}

# Matches os.environ.get( or getenv( followed (anywhere on the same line) by a known key.
_ENV_PATTERN = re.compile(r'(?:os\.environ\.get\s*\(|getenv\s*\()')


def run_config_ssot_checks(ctx: PostExecGateContext):
    findings = []
    profile = ctx.repo_profile
    if profile is None:
        return build_check_result(check_id="config_ssot", category=GateCategory.CONFIG_SSOT)
    for snapshot in iter_touched_snapshots(ctx):
        if not snapshot.exists:
            continue
        # -- existing check: canonical literal owners --
        for literal, owners in profile.canonical_literal_owners.items():
            if literal not in snapshot.text:
                continue
            if snapshot.path in owners:
                continue
            findings.append(
                build_finding(
                    check_id="config_ssot.literal_owner",
                    category=GateCategory.CONFIG_SSOT,
                    title="Touched code bypasses a canonical config owner",
                    severity=GateSeverity.HIGH,
                    impact=GateImpact.REVISE,
                    summary=f"Literal '{literal}' appears in {snapshot.path}, but canonical owner paths are {', '.join(owners[:3])}.",
                    recommendation="Move or reference the invariant from its canonical owner instead of duplicating the literal.",
                    evidence=[EvidenceReference(kind="file", path=snapshot.path, detail=literal)],
                
                    repair_kind='fix_contract',
                    executor_action='Fix contract violation',
                    proof_required='Contract respected',
                    allowlist_allowed=False,
                )
            )
        # -- new check: env var bypass of known config keys --
        filename = snapshot.path.split("/")[-1].split("\\")[-1]
        if filename not in _ALLOWED_ENV_READERS:
            for lineno, line in enumerate(snapshot.text.splitlines(), start=1):
                if not _ENV_PATTERN.search(line):
                    continue
                matched_key = next((k for k in _ENV_BYPASS_KEYS if k in line), None)
                if matched_key is None:
                    continue
                findings.append(
                    build_finding(
                        check_id="config_ssot.env_bypass",
                        category=GateCategory.CONFIG_SSOT,
                        title="Config value accessed via environment variable bypass",
                        severity=GateSeverity.MEDIUM,
                        impact=GateImpact.REVISE,
                        summary="Config value accessed via environment variable bypass instead of canonical config path",
                        recommendation=f"Read '{matched_key}' through the canonical config resolver, not directly via os.environ/getenv.",
                        evidence=[EvidenceReference(kind="file", path=snapshot.path, detail=f"line {lineno}: {line.strip()}")],
                    
                        repair_kind='fix_contract',
                        executor_action='Fix contract violation',
                        proof_required='Contract respected',
                        allowlist_allowed=False,
                    )
                )
    return build_check_result(check_id="config_ssot", category=GateCategory.CONFIG_SSOT, findings=findings)
