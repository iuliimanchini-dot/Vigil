"""Exception handling and boundary validation. Clusters 31, 32, 33."""
from __future__ import annotations

from .core import detect_language
from ...gate_models import (
    EvidenceReference,
    GateCategory,
    GateFinding,
    GateImpact,
    GateSeverity,
    RepairKind,
)
from ..common import build_finding
import logging
_log = logging.getLogger(__name__)


def _extract_except_body(lines: list[str], except_line: int) -> str:
    if except_line + 1 >= len(lines):
        return ""
    except_indent = len(lines[except_line]) - len(lines[except_line].lstrip())
    body_parts = []
    for j in range(except_line + 1, min(except_line + 10, len(lines))):
        line = lines[j]
        if not line.strip():
            continue
        line_indent = len(line) - len(line.lstrip())
        if line_indent <= except_indent:
            break
        body_parts.append(line.strip())
    return "\n".join(body_parts)


def _is_swallowed(body: str) -> bool:
    stripped = body.strip()
    if not stripped or stripped == "pass":
        return True
    body_lines = [l.strip() for l in stripped.splitlines() if l.strip()]
    if all(l in ("pass", "continue") for l in body_lines):
        return True
    if any(l.startswith("raise") for l in body_lines):
        return False
    if any(l.startswith("return ") for l in body_lines):
        return False
    log_only = all(
        l.startswith(("log", "logger", "logging", "print(", "#", "warnings.warn"))  # noqa: debug_print_scan  # gate pattern reference, not a production print call
        for l in body_lines
    )
    if log_only and len(body_lines) <= 2:
        return False
    return False


def assess_exception_swallowing(file_path: str, content: str) -> list[GateFinding]:
    """Cluster 31: Detect swallowed exceptions."""
    import re

    if not content.strip():
        return []
    if detect_language(file_path) != "python":
        return []
    basename = file_path.replace("\\", "/").rsplit("/", 1)[-1] if "/" in file_path.replace("\\", "/") else file_path
    if basename.startswith("test_") or basename.startswith("conftest"):
        return []

    lines = content.splitlines()
    findings: list[GateFinding] = []
    i = 0
    while i < len(lines):
        stripped = lines[i].strip()
        if re.match(r'^except\s*:', stripped):
            body = _extract_except_body(lines, i)
            if _is_swallowed(body):
                detail = f"Bare except with swallowed error (line {i + 1}): body is '{body.strip()[:60]}'"
                findings.append(build_finding(
                    check_id="exception_swallow_scan",
                    category=GateCategory.RUNTIME_BEHAVIOR,
                    title=f"[exception_swallowing] {file_path}:{i + 1}",
                    severity=GateSeverity.HIGH,
                    impact=GateImpact.REVISE,
                    summary=detail,
                    recommendation="Use specific exception types and reraise or log+reraise.",
                    evidence=(EvidenceReference(kind="probe", path=file_path, detail=detail, ok=False),),
                    repair_kind=RepairKind.REPLACE_WITH_FAIL_LOUD.value,
                    executor_action=f"Fix swallowed exception at {file_path}:{i + 1}",
                ))
        elif re.match(r'^except\s+(Exception|BaseException)(\s+as\s+\w+)?\s*:', stripped):
            body = _extract_except_body(lines, i)
            if _is_swallowed(body):
                exc_m = re.match(r'^except\s+(Exception|BaseException)', stripped)
                exc_type = exc_m.group(1) if exc_m else "Exception"
                detail = f"Broad `except {exc_type}` with swallowed error (line {i + 1})"
                findings.append(build_finding(
                    check_id="exception_swallow_scan",
                    category=GateCategory.RUNTIME_BEHAVIOR,
                    title=f"[exception_swallowing] {file_path}:{i + 1}",
                    severity=GateSeverity.HIGH,
                    impact=GateImpact.REVISE,
                    summary=detail,
                    recommendation="Add reraise (raise) after logging, or use a more specific exception type.",
                    evidence=(EvidenceReference(kind="probe", path=file_path, detail=detail, ok=False),),
                    repair_kind=RepairKind.REPLACE_WITH_FAIL_LOUD.value,
                    executor_action=f"Fix broad except at {file_path}:{i + 1}",
                ))
        elif re.match(r'^except\s+\w', stripped):
            body = _extract_except_body(lines, i)
            if body.strip() == "pass":
                detail = f"Exception caught and silently passed (line {i + 1}): {stripped[:60]}"
                findings.append(build_finding(
                    check_id="exception_swallow_scan",
                    category=GateCategory.RUNTIME_BEHAVIOR,
                    title=f"[exception_swallowing] {file_path}:{i + 1}",
                    severity=GateSeverity.MEDIUM,
                    impact=GateImpact.REVISE,
                    summary=detail,
                    recommendation="Log the exception and/or reraise it instead of passing silently.",
                    evidence=(EvidenceReference(kind="probe", path=file_path, detail=detail, ok=False),),
                    repair_kind=RepairKind.REPLACE_WITH_FAIL_LOUD.value,
                    executor_action=f"Fix silent pass at {file_path}:{i + 1}",
                ))
        i += 1
    return findings[:10]


def assess_hardcoded_paths(file_path: str, content: str) -> list[GateFinding]:
    """Cluster 32: Detect hardcoded absolute paths that break portability."""
    import re

    if not content.strip():
        return []
    lang = detect_language(file_path)
    if lang not in ("python", "javascript", "typescript", "go", "rust", "java", "shell"):
        return []
    basename = file_path.replace("\\", "/").rsplit("/", 1)[-1] if "/" in file_path.replace("\\", "/") else file_path
    if basename.startswith("test_") or basename.startswith("conftest"):
        return []

    path_patterns = [
        (r'''["'][A-Z]:\\[^"']{3,}["']''', "Windows absolute path"),
        (r'''["']/home/\w+[^"']*["']''', "Unix home directory path"),
        (r'''["']/tmp/[^"']+["']''', "Hardcoded /tmp path (use tempfile)"),
        (r'''["']/usr/(?:local/|bin/)[^"']+["']''', "Hardcoded /usr path"),
        (r'''["']/var/(?:log|run|lib)/[^"']+["']''', "Hardcoded /var path"),
        (r'''["']/etc/[^"']+["']''', "Hardcoded /etc config path"),
        (r'''["']/opt/[^"']+["']''', "Hardcoded /opt path"),
        (r'''["']/(?:root|srv|mnt)/[^"']+["']''', "Hardcoded system path"),
    ]

    findings: list[GateFinding] = []
    for i, line in enumerate(content.splitlines(), 1):
        stripped = line.strip()
        if stripped.startswith("#") or stripped.startswith("//"):
            continue
        if stripped.startswith('"""') or stripped.startswith("'''"):
            continue
        if "http://" in line or "https://" in line or "ftp://" in line:
            continue
        if i == 1 and stripped.startswith("#!"):
            continue
        for pattern, description in path_patterns:
            for m in re.finditer(pattern, line):
                matched = m.group(0)
                if "EXAMPLE" in stripped.upper() or "PLACEHOLDER" in stripped.upper():
                    continue
                findings.append(build_finding(
                    check_id="hardcoded_path_scan",
                    category=GateCategory.CONTRACT,
                    title=f"[hardcoded_paths] {file_path}:{i}",
                    severity=GateSeverity.MEDIUM,
                    impact=GateImpact.REVISE,
                    summary=f"{description}: {matched[:80]}",
                    recommendation="Use os.path, pathlib.Path, or environment variables instead of hardcoded paths.",
                    evidence=(EvidenceReference(kind="probe", path=file_path, detail=f"{description}: {matched[:80]}", ok=False),),
                    repair_kind=RepairKind.FIX_CONTRACT.value,
                    executor_action=f"Replace hardcoded path at {file_path}:{i}",
                ))
                break
        if len(findings) >= 10:
            break
    return findings


def assess_boundary_validation(file_path: str, content: str) -> list[GateFinding]:
    """Cluster 33: Detect unvalidated external input at system boundaries."""
    import re

    if not content.strip():
        return []
    if detect_language(file_path) != "python":
        return []
    basename = file_path.replace("\\", "/").rsplit("/", 1)[-1] if "/" in file_path.replace("\\", "/") else file_path
    if basename.startswith("test_") or basename.startswith("conftest"):
        return []

    findings: list[GateFinding] = []
    for i, line in enumerate(content.splitlines(), 1):
        stripped = line.strip()
        if stripped.startswith("#"):
            continue
        detail: str | None = None
        if re.search(r'os\.(system|popen)\s*\(\s*f["\']', stripped):
            detail = f"Potential command injection: os.system/popen with f-string (line {i})"
        elif re.search(r'subprocess\.\w+\s*\(.*shell\s*=\s*True', stripped) and ('f"' in stripped or "f'" in stripped):
            detail = f"Potential command injection: subprocess with shell=True + f-string (line {i})"
        elif re.search(r'\.(execute|executemany|query)\s*\(\s*f["\']', stripped):
            if re.search(r'(?i)(SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER)', stripped):
                detail = f"Potential SQL injection: .execute() with f-string SQL (line {i})"
        elif re.search(r'\.(execute|query)\s*\(\s*["\'].*%s.*["\'].*%\s*\(', stripped):
            if re.search(r'(?i)(SELECT|INSERT|UPDATE|DELETE)', stripped):
                detail = f"Potential SQL injection: .execute() with % formatting (line {i})"
        elif re.search(r'\b(eval|exec)\s*\(\s*(?!["\'(])', stripped):
            detail = f"Dangerous eval/exec with variable input (line {i})"
        if detail:
            findings.append(build_finding(
                check_id="boundary_validation_scan",
                category=GateCategory.TRUTH_BOUNDARY,
                title=f"[boundary_validation] {file_path}:{i}",
                severity=GateSeverity.HIGH,
                impact=GateImpact.REVISE,
                summary=detail,
                recommendation="Validate and sanitize all external input before use in system calls.",
                evidence=(EvidenceReference(kind="probe", path=file_path, detail=detail, ok=False),),
                repair_kind=RepairKind.ADD_BOUNDARY_CHECK.value,
                executor_action=f"Fix boundary validation at {file_path}:{i}",
            ))
        if len(findings) >= 10:
            break
    return findings
