from __future__ import annotations

import os
import re

from cortex_forensic._shared import EvidenceReference, GateCategory, GateImpact, GateSeverity, RepairKind
from cortex_forensic.gate_models import PostExecGateContext
from ..source_analysis import get_generic_stems, is_source_file
from .common import build_check_result, build_finding, normalize_path
import logging
_log = logging.getLogger(__name__)


# Suffixes that suggest a "v2" clone rather than a proper edit.
_CLONE_PATTERNS = re.compile(
    r'_v\d+|_new|_copy|_backup|_old|_fixed|_updated|_refactored|_alt'
    r'|\.bak|\.orig|\.copy',
    re.IGNORECASE,
)


def run_file_proliferation_checks(ctx: PostExecGateContext):
    """Detect new files that duplicate or shadow existing project files.

    Catches three patterns:
    1. Clone naming: executor creates foo_v2.py when foo.py exists
    2. Generic helper proliferation: executor creates new utils.py / helpers.py
       in a directory that already has one nearby
    3. Shadow file: executor creates a file with the SAME basename in a
       different directory when one already exists in the project
    """
    findings = []
    if not ctx.changed_files_observed:
        return build_check_result(check_id="file_proliferation", category=GateCategory.DUPLICATION)

    # Build a set of pre-existing project file basenames for shadow detection.
    # Only scan known source roots to keep it fast.
    existing_basenames: dict[str, list[str]] = {}
    for root_name in ctx.source_package_roots:
        root = ctx.project_dir / root_name
        if not root.is_dir():
            continue
        file_count = 0
        for src_file in root.rglob("*"):
            if not src_file.is_file():
                continue
            rel = str(src_file.relative_to(ctx.project_dir)).replace("\\", "/")
            if not is_source_file(rel):
                continue
            file_count += 1
            if file_count > 2000:
                break
            existing_basenames.setdefault(src_file.name, []).append(rel)

    for raw_path in ctx.changed_files_observed:
        normalized = normalize_path(raw_path)
        if not is_source_file(normalized):
            continue
        # Only check NEW files (created by executor, not pre-existing edits)
        if normalized not in set(normalize_path(p) for p in ctx.changed_files_reported):
            continue

        basename = os.path.basename(normalized)
        stem = basename.rsplit(".", 1)[0] if "." in basename else basename

        # Check 1: Clone naming (_v2, _new, _copy, etc.)
        if _CLONE_PATTERNS.search(stem):
            base_stem = _CLONE_PATTERNS.sub("", stem)
            ext = basename.rsplit(".", 1)[1] if "." in basename else ""
            base_name = f"{base_stem}.{ext}" if ext else base_stem
            if base_name in existing_basenames:
                base_paths = existing_basenames[base_name]
                findings.append(
                    build_finding(
                        check_id="file_proliferation.clone_naming",
                        category=GateCategory.DUPLICATION,
                        title=f"Clone-named file created: {normalized}",
                        severity=GateSeverity.HIGH,
                        impact=GateImpact.REVISE,
                        summary=(
                            f"Executor created {normalized} which looks like a clone of "
                            f"existing {base_paths[0]}. Edit the original file instead "
                            "of creating a copy with a version suffix."
                        ),
                        recommendation=(
                            f"Modify {base_paths[0]} directly. If a new module is truly "
                            "needed, give it a distinct semantic name, not a version suffix."
                        ),
                        evidence=[
                            EvidenceReference(kind="file", path=normalized, detail="clone"),
                            EvidenceReference(kind="file", path=base_paths[0], detail="original"),
                        ],
                        repair_kind=RepairKind.EDIT_CANONICAL.value,
                        executor_action=f"Delete {normalized}; apply changes to canonical {base_paths[0]} instead",
                        proof_required="clone file deleted; canonical file contains the intended change",
                        allowlist_allowed=False,
                    )
                )

        # Check 2: Generic helper proliferation
        stems_for_lang = get_generic_stems(normalized)
        if stem.lower() in stems_for_lang:
            dir_path = os.path.dirname(normalized)
            siblings = [
                path for bname, paths in existing_basenames.items()
                for path in paths
                if bname.rsplit(".", 1)[0].lower() in stems_for_lang
                and os.path.dirname(path) == dir_path
                and path != normalized
            ]
            if siblings:
                findings.append(
                    build_finding(
                        check_id="file_proliferation.generic_helper",
                        category=GateCategory.DUPLICATION,
                        title=f"Generic helper file created alongside existing: {normalized}",
                        severity=GateSeverity.MEDIUM,
                        impact=GateImpact.REVISE,
                        summary=(
                            f"Executor created {normalized} but {siblings[0]} already "
                            "exists in the same directory. Adding another generic helper "
                            "file suggests logic should be added to the existing one."
                        ),
                        recommendation=f"Add the new functions to {siblings[0]} instead.",
                        evidence=[
                            EvidenceReference(kind="file", path=normalized, detail="new_generic"),
                            EvidenceReference(kind="file", path=siblings[0], detail="existing_generic"),
                        ],
                        repair_kind=RepairKind.EDIT_CANONICAL.value,
                        executor_action=f"Move content from {normalized} into {siblings[0]}; delete {normalized}",
                        proof_required="new file deleted; functions accessible from existing helper",
                    )
                )

        # Check 3: Shadow file (same basename, different directory)
        if basename in existing_basenames:
            other_locations = [
                p for p in existing_basenames[basename]
                if p != normalized and os.path.dirname(p) != os.path.dirname(normalized)
            ]
            if other_locations and not basename.startswith("__"):
                findings.append(
                    build_finding(
                        check_id="file_proliferation.shadow_file",
                        category=GateCategory.DUPLICATION,
                        title=f"File with same name exists elsewhere: {basename}",
                        severity=GateSeverity.MEDIUM,
                        impact=GateImpact.REVISE,
                        summary=(
                            f"Executor created {normalized} but {other_locations[0]} "
                            "already exists with the same filename in a different directory. "
                            "This may cause import confusion or indicate a copy-paste."
                        ),
                        recommendation=(
                            "Verify this is intentional. If both files serve the same purpose, "
                            "consolidate into one and import from the canonical location."
                        ),
                        evidence=[
                            EvidenceReference(kind="file", path=normalized, detail="new"),
                            EvidenceReference(kind="file", path=other_locations[0], detail="existing"),
                        ],
                        repair_kind=RepairKind.EDIT_CANONICAL.value,
                        executor_action=f"Verify {normalized} vs {other_locations[0]} — if same purpose, consolidate and import from canonical",
                    )
                )

    return build_check_result(
        check_id="file_proliferation",
        category=GateCategory.DUPLICATION,
        findings=findings,
    )
