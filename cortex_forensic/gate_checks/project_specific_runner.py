"""Dynamic loader and runner for project-specific forensic gates.

Project-specific gates live under ``.prompt-engineer/forensic_gates/``.

Layout:
- legacy/manual gates may still live directly in ``forensic_gates/``
- generated gates live in ``forensic_gates/generated/``

Each gate is a Python module with a ``run_check(file_path, content) -> list[dict]``
function. Modules are loaded dynamically on every run, so newly created gates are
picked up automatically without runtime restart.
"""
from __future__ import annotations

import ast
import importlib.util
import json
import logging
import time
from pathlib import Path
from typing import Any

from cortex_forensic._shared import EvidenceReference, GateCategory, GateCheckResult, GateImpact, GateSeverity, RepairKind
from cortex_forensic.gate_models import PostExecGateContext
from .common import build_check_result, build_finding, iter_touched_snapshots

_log = logging.getLogger(__name__)


GATES_DIR_NAME = "forensic_gates"
GATES_PARENT = ".prompt-engineer"
GENERATED_SUBDIR = "generated"
RULES_FILE = "project_rules.json"
STATUS_FILE = "_generation_status.json"
PROMPT_FILE = "_generation_prompt.txt"
RAW_OUTPUT_FILE = "_raw_generation_output.txt"
RAW_STDERR_FILE = "_raw_generation_stderr.txt"
_MAX_FINDINGS_PER_GATE = 20
_MAX_TOTAL_FINDINGS = 100
_ALLOWED_IMPORT_MODULES = frozenset({"re"})
_BLOCKED_CALL_NAMES = frozenset({"open", "exec", "eval", "compile", "input", "__import__"})
_BLOCKED_CALL_PREFIXES = ("os.", "subprocess.", "socket.", "pathlib.", "shutil.")
_STALE_GENERATION_SECONDS = 600  # 10 min -- only marks stale if no active lease found
_LEGACY_TRANSIENT_FILES = frozenset({STATUS_FILE, PROMPT_FILE, RAW_OUTPUT_FILE, RAW_STDERR_FILE})


def _gates_dir(project_dir: Path) -> Path:
    """Return the project-specific forensic gates root directory."""
    return Path(project_dir) / GATES_PARENT / GATES_DIR_NAME


def _generated_gates_dir(project_dir: Path) -> Path:
    """Return the generated-gates directory under the forensic gates root."""
    return _gates_dir(project_dir) / GENERATED_SUBDIR


def _has_manual_gate_content(root_dir: Path) -> bool:
    """Return True when the legacy/manual root contains actual gate content."""
    if not root_dir.is_dir():
        return False
    if any(root_dir.glob("gate_*.py")):
        return True
    if (root_dir / RULES_FILE).exists():
        return True
    return False


def _cleanup_legacy_generation_artifacts(project_dir: Path) -> None:
    """Move legacy transient generation files into the canonical generated/ folder.

    Safety rules:
    - never touch the legacy root if it contains manual gate files/manifest
    - only migrate the known transient generation files
    - skip cleanup entirely if the generated directory already has conflicting files
    """
    root_dir = _gates_dir(project_dir)
    if not root_dir.is_dir() or _has_manual_gate_content(root_dir):
        return

    transient_files = [path for path in root_dir.iterdir() if path.is_file() and path.name in _LEGACY_TRANSIENT_FILES]
    if not transient_files:
        return

    unknown_files = [path for path in root_dir.iterdir() if path.is_file() and path.name not in _LEGACY_TRANSIENT_FILES]
    if unknown_files:
        return

    generated_dir = _generated_gates_dir(project_dir)
    if any((generated_dir / path.name).exists() for path in transient_files):
        return

    generated_dir.mkdir(parents=True, exist_ok=True)
    for path in transient_files:
        target = generated_dir / path.name
        if path.name == STATUS_FILE:
            payload = _load_json_file(path)
            if isinstance(payload, dict):
                target.write_text(
                    json.dumps(_status_file_payload(payload, source_kind="generated"), indent=2, ensure_ascii=False) + "\n",
                    encoding="utf-8",
                )
                path.unlink()
                continue
        path.replace(target)


def _gate_source_dirs(project_dir: Path) -> list[tuple[str, Path]]:
    """Return source-kind/dir pairs in load order."""
    root_dir = _gates_dir(project_dir)
    generated_dir = _generated_gates_dir(project_dir)
    dirs: list[tuple[str, Path]] = []
    if generated_dir.is_dir():
        dirs.append(("generated", generated_dir))
    if _has_manual_gate_content(root_dir):
        dirs.append(("manual", root_dir))
    return dirs


def _source_label(source_kind: str) -> str:
    return {
        "generated": "Generated project gates",
        "manual": "Manual / legacy project gates",
    }.get(source_kind, source_kind.replace("_", " ").title())


def _load_json_file(path: Path) -> Any | None:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError) as exc:
        _log.warning("Failed to load JSON %s: %s", path, exc)
        return None


def _status_file_payload(data: dict[str, Any], *, source_kind: str) -> dict[str, Any]:
    """Return the persisted subset for generation status files."""
    payload: dict[str, Any] = {
        "status": str(data.get("status") or "unknown"),
        "gates_count": int(data.get("gates_count") or 0),
        "source_kind": source_kind,
    }
    for key in ("error", "invalid_gates", "started_at", "finished_at"):
        value = data.get(key)
        if value not in (None, "", []):
            payload[key] = value
    return payload


def _call_name(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        prefix = _call_name(node.value)
        return f"{prefix}.{node.attr}" if prefix else node.attr
    return ""


def _validate_gate_source(file_name: str, source: str) -> list[str]:
    """Return validation errors for a generated/manual gate source file."""
    errors: list[str] = []
    try:
        tree = ast.parse(source, filename=file_name)
    except SyntaxError as exc:
        return [f"syntax error: {exc.msg} (line {exc.lineno})"]

    run_check_defs = []
    for node in tree.body:
        if isinstance(node, ast.Expr) and isinstance(getattr(node, "value", None), ast.Constant):
            if isinstance(node.value.value, str):
                continue
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name not in _ALLOWED_IMPORT_MODULES:
                    errors.append(f"disallowed import: {alias.name}")
            continue
        if isinstance(node, ast.ImportFrom):
            if node.module not in _ALLOWED_IMPORT_MODULES:
                errors.append(f"disallowed import-from: {node.module}")
            continue
        if isinstance(node, ast.FunctionDef) and node.name == "run_check":
            run_check_defs.append(node)
            continue
        errors.append(f"unsupported top-level statement: {type(node).__name__}")

    if len(run_check_defs) != 1:
        errors.append("gate must define exactly one top-level run_check() function")
    elif [arg.arg for arg in run_check_defs[0].args.args] != ["file_path", "content"]:
        errors.append("run_check must have exact signature: run_check(file_path, content)")

    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            call_name = _call_name(node.func)
            if call_name in _BLOCKED_CALL_NAMES or any(call_name.startswith(p) for p in _BLOCKED_CALL_PREFIXES):
                errors.append(f"disallowed call: {call_name}")
        if isinstance(node, ast.Attribute):
            attr_name = _call_name(node)
            if any(attr_name.startswith(p) for p in _BLOCKED_CALL_PREFIXES):
                errors.append(f"disallowed attribute access: {attr_name}")

    deduped: list[str] = []
    for item in errors:
        if item not in deduped:
            deduped.append(item)
    return deduped


def _discover_gate_files(project_dir: Path) -> list[dict[str, Any]]:
    """Return structured metadata for all gate_*.py files."""
    discovered: list[dict[str, Any]] = []
    for source_kind, source_dir in _gate_source_dirs(project_dir):
        for gate_file in sorted(source_dir.glob("gate_*.py")):
            try:
                source = gate_file.read_text(encoding="utf-8")
            except OSError as exc:
                discovered.append({
                    "name": gate_file.stem,
                    "file": gate_file.name,
                    "path": str(gate_file),
                    "source_kind": source_kind,
                    "source_label": _source_label(source_kind),
                    "valid": False,
                    "errors": [f"read error: {exc}"],
                })
                continue

            errors = _validate_gate_source(gate_file.name, source)
            discovered.append({
                "name": gate_file.stem,
                "file": gate_file.name,
                "path": str(gate_file),
                "source_kind": source_kind,
                "source_label": _source_label(source_kind),
                "valid": not errors,
                "errors": errors,
            })
    return discovered


def _load_project_rules(project_dir: Path) -> list[dict[str, Any]]:
    """Load and merge project rule manifests from generated + manual sources."""
    merged: list[dict[str, Any]] = []
    for source_kind, source_dir in _gate_source_dirs(project_dir):
        rules_path = source_dir / RULES_FILE
        if not rules_path.exists():
            continue
        data = _load_json_file(rules_path)
        if data is None:
            continue
        rules = data if isinstance(data, list) else data.get("rules", [])
        if not isinstance(rules, list):
            continue
        for item in rules:
            if not isinstance(item, dict):
                continue
            entry = dict(item)
            entry.setdefault("file", "")
            entry["source_kind"] = source_kind
            entry["source_label"] = _source_label(source_kind)
            entry["manifest_path"] = str(rules_path)
            merged.append(entry)
    return merged


def _load_gate_modules(project_dir: Path) -> list[tuple[str, Any]]:
    """Dynamically load all valid gate modules from the project gates directories."""
    modules: list[tuple[str, Any]] = []
    for info in _discover_gate_files(project_dir):
        if not info["valid"]:
            _log.warning("Skipping invalid gate %s: %s", info["file"], "; ".join(info["errors"]))
            continue
        gate_path = Path(info["path"])
        module_name = f"project_gate_{info['source_kind']}_{gate_path.stem}"
        try:
            spec = importlib.util.spec_from_file_location(module_name, str(gate_path))
            if spec is None or spec.loader is None:
                _log.warning("Cannot load gate module: %s", gate_path)
                continue
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
            if not hasattr(module, "run_check") or not callable(module.run_check):
                _log.warning("Gate module %s has no run_check function", gate_path.name)
                continue
            modules.append((gate_path.stem, module))
        except Exception as exc:
            _log.warning("Failed to load gate %s: %s", gate_path.name, exc)
    return modules


def _load_generation_status(project_dir: Path) -> dict[str, Any] | None:
    """Load generation status, preferring the generated directory."""
    candidates = [
        ("generated", _generated_gates_dir(project_dir) / STATUS_FILE),
        ("manual", _gates_dir(project_dir) / STATUS_FILE),
    ]
    for source_kind, status_path in candidates:
        if not status_path.exists():
            continue
        data = _load_json_file(status_path)
        if not isinstance(data, dict):
            continue
        data = dict(data)
        data.setdefault("status", "unknown")
        data["status_path"] = str(status_path)
        data["source_kind"] = source_kind
        data["source_label"] = _source_label(source_kind)
        try:
            data["updated_at"] = status_path.stat().st_mtime
        except OSError:
            data["updated_at"] = 0.0
        raw_output = status_path.parent / RAW_OUTPUT_FILE
        if raw_output.exists():
            data["raw_output_path"] = str(raw_output)

        persisted_source_kind = str((_load_json_file(status_path) or {}).get("source_kind") or "")
        if persisted_source_kind != source_kind:
            try:
                status_path.write_text(
                    json.dumps(_status_file_payload(data, source_kind=source_kind), indent=2, ensure_ascii=False) + "\n",
                    encoding="utf-8",
                )
            except OSError as _exc:
                _log.debug("gate status write failed for %s: %s", status_path, _exc)

        if data.get("status") == "running":
            # standalone: claude run-lease unavailable
            lease = None
            age = max(0.0, time.time() - float(data.get("updated_at") or 0.0))
            if lease is None and age > _STALE_GENERATION_SECONDS:
                data["status"] = "failed"
                data.setdefault("error", "Generation status became stale; no active Claude run was found")
                try:
                    status_path.write_text(
                        json.dumps(_status_file_payload(data, source_kind=source_kind), indent=2, ensure_ascii=False) + "\n",
                        encoding="utf-8",
                    )
                except OSError as _exc:
                    _log.debug("gate stale-failure status write failed for %s: %s", status_path, _exc)
        return data
    return None


def describe_gate_inventory(project_dir: Path) -> dict[str, Any]:
    """Return structured inventory for UI/API consumption."""
    _cleanup_legacy_generation_artifacts(project_dir)
    root_dir = _gates_dir(project_dir)
    generated_dir = _generated_gates_dir(project_dir)
    rules = _load_project_rules(project_dir)
    file_inventory = _discover_gate_files(project_dir)
    valid_modules = [item["name"] for item in file_inventory if item["valid"]]
    generation_status = _load_generation_status(project_dir)

    groups: list[dict[str, Any]] = []
    for source_kind, source_dir in _gate_source_dirs(project_dir):
        source_files = [item for item in file_inventory if item["source_kind"] == source_kind]
        source_rules = [item for item in rules if item["source_kind"] == source_kind]
        groups.append({
            "source_kind": source_kind,
            "source_label": _source_label(source_kind),
            "directory": str(source_dir),
            "rules": source_rules,
            "files": source_files,
            "valid_count": sum(1 for item in source_files if item["valid"]),
            "invalid_count": sum(1 for item in source_files if not item["valid"]),
        })

    return {
        "root_dir": str(root_dir),
        "generated_dir": str(generated_dir),
        "exists": root_dir.is_dir() or generated_dir.is_dir(),
        "rules": rules,
        "modules": valid_modules,
        "module_details": file_inventory,
        "gates_count": len(valid_modules),
        "groups": groups,
        "generation_status": generation_status,
    }


def _execute_gate(
    gate_name: str,
    gate_module: Any,
    file_path: str,
    content: str,
) -> list[dict[str, Any]]:
    """Execute a single gate's run_check and return findings."""
    try:
        results = gate_module.run_check(file_path, content)
        if not isinstance(results, list):
            return []
        valid: list[dict[str, Any]] = []
        for item in results:
            if not isinstance(item, dict) or "message" not in item:
                continue
            valid.append({
                "line": int(item.get("line") or 0),
                "message": str(item["message"]),
                "severity": str(item.get("severity", "medium")),
                "gate": gate_name,
            })
        return valid
    except Exception as exc:
        _log.debug("Gate %s failed on %s: %s", gate_name, file_path, exc)
        return []


def run_project_specific_checks(ctx: PostExecGateContext) -> GateCheckResult:
    """Run project-specific forensic gates from .prompt-engineer/forensic_gates/."""
    project_dir = ctx.project_dir
    inventory = describe_gate_inventory(project_dir)

    if not inventory["exists"]:
        return build_check_result(
            check_id="project_specific",
            category=GateCategory.CONTRACT,
            notes=["No project-specific forensic gates found "
                   f"(looked in {GATES_PARENT}/{GATES_DIR_NAME}/)"],
        )

    gate_modules = _load_gate_modules(project_dir)
    if not gate_modules:
        return build_check_result(
            check_id="project_specific",
            category=GateCategory.CONTRACT,
            notes=[f"Gates directory exists but no valid gate_*.py modules found in {inventory['root_dir']}"],
        )

    findings = []
    notes = [f"Loaded {len(gate_modules)} project-specific gate(s): {', '.join(name for name, _ in gate_modules)}"]
    if inventory.get("generation_status"):
        status = inventory["generation_status"]
        notes.append(f"Last generation status: {status.get('status')} ({status.get('source_label')})")

    total_count = 0
    for snapshot in iter_touched_snapshots(ctx):
        if not snapshot.exists or not snapshot.text:
            continue
        if total_count >= _MAX_TOTAL_FINDINGS:
            notes.append(f"Stopped scanning -- reached {_MAX_TOTAL_FINDINGS} findings cap")
            break

        for gate_name, gate_module in gate_modules:
            if total_count >= _MAX_TOTAL_FINDINGS:
                break

            results = _execute_gate(gate_name, gate_module, snapshot.path, snapshot.text)
            for item in results[:_MAX_FINDINGS_PER_GATE]:
                if total_count >= _MAX_TOTAL_FINDINGS:
                    break

                severity_map = {
                    "high": GateSeverity.HIGH,
                    "medium": GateSeverity.MEDIUM,
                    "low": GateSeverity.LOW,
                }
                findings.append(build_finding(
                    check_id=f"project_gate.{gate_name}",
                    category=GateCategory.CONTRACT,
                    title=f"[{gate_name}] {item['message'][:80]}",
                    severity=severity_map.get(item["severity"], GateSeverity.MEDIUM),
                    impact=GateImpact.REVISE,
                    summary=item["message"],
                    recommendation=f"Fix the violation detected by project gate '{gate_name}'",
                    evidence=(
                        EvidenceReference(
                            kind="file",
                            path=snapshot.path,
                            detail=f"line:{item['line']}" if item["line"] else "",
                        ),
                    ),
                
                    repair_kind='refactor',
                    executor_action='Address finding details',
                    proof_required='Issue fixed',
                    allowlist_allowed=False,
                ))
                total_count += 1

    return build_check_result(
        check_id="project_specific",
        category=GateCategory.CONTRACT,
        findings=findings,
        notes=notes,
    )


GATE_GENERATION_PROMPT = """\
ROLE: Project Forensic Gate Architect (Opus-level analysis)

You are creating automated quality gates for a software project.
These gates run on every code review to catch project-specific invariant violations.

===========================================================
STEP 1: READ THE PROJECT CONTEXT
===========================================================

First, read the prompt-engineer directory to understand the project:
- Read `.prompt-engineer/README.md` (if exists) -- project overview
- Read `.prompt-engineer/CONTRACT_INDEX.md` (if exists) -- key contracts
- Read `.prompt-engineer/project_map.md` (if exists) -- architecture map
- Read `CLAUDE.md` or `.claude/CLAUDE.md` (if exists) -- project rules

Then read 5-10 key source files to understand patterns, invariants,
and common mistakes in this codebase.

===========================================================
STEP 2: UNDERSTAND EXISTING GATES
===========================================================

The framework already has {universal_cluster_count} universal checks covering:
{builtin_categories}

DO NOT duplicate these. Your gates must check PROJECT-SPECIFIC invariants
that universal checks cannot know about.

Existing project-specific rules (if any):
{existing_rules}

===========================================================
STEP 3: ANALYZE AND IDENTIFY INVARIANTS
===========================================================

Based on your reading, identify 3-8 project-specific invariants:
- Architecture boundaries (what modules should NOT import from each other)
- Naming conventions specific to THIS project
- Required patterns (every handler must have X, every test must check Y)
- Forbidden patterns (this project must NEVER use Z)
- Data flow rules (this type must always go through this pipeline)
- Configuration rules (these settings must always be consistent)

===========================================================
STEP 4: CREATE GATE FILES
===========================================================

For each invariant, create a gate file in:
  {gates_dir}/

File naming: `gate_<rule_id>.py` (e.g. `gate_no_cross_module_import.py`)

Each gate file must follow this EXACT format:

```python
\"\"\"<One-line description of what this gate checks>.

Rationale: <Why this invariant matters for THIS project>.
\"\"\"
import re


def run_check(file_path: str, content: str) -> list[dict]:
    \"\"\"Check a single file for violations.

    Args:
        file_path: Relative path like "src/handlers/auth.py"
        content: Full file content as string

    Returns:
        List of findings, each: {{"line": int, "message": str, "severity": "high"|"medium"|"low"}}
    \"\"\"
    findings = []
    # ... check logic using content.splitlines(), re.search, etc ...
    return findings
```

CONSTRAINTS:
- Function signature EXACTLY: `def run_check(file_path: str, content: str) -> list[dict]`
- Only `import re` allowed (no os, subprocess, pathlib, network, file I/O)
- Must be deterministic: same input = same output
- Must handle empty/malformed input without crashing
- Each finding dict: {{"line": int, "message": str, "severity": "high"|"medium"|"low"}}

===========================================================
STEP 5: CREATE MANIFEST
===========================================================

After creating all gate files, write the manifest:
  {gates_dir}/project_rules.json

Format:
```json
[
  {{
    "rule_id": "no_cross_module_import",
    "description": "Handlers must not import from core directly",
    "rationale": "Architecture boundary: handlers -> services -> core",
    "file": "gate_no_cross_module_import.py"
  }}
]
```

===========================================================
STEP 6: VERIFY
===========================================================

After writing all files:
1. Read back each gate file to verify it's syntactically correct
2. Verify project_rules.json is valid JSON and references existing files
3. Report a summary of what you created

QUALITY BAR:
- 3-8 precise gates > 20 noisy ones
- If a check would flag correct code as wrong, DO NOT include it
- Every gate must have a clear, project-specific rationale
- Think: "Would a senior developer on this project agree this is an invariant?"

PROJECT INFO:
{project_context}

SAMPLE FILE LIST:
{file_list}

DETECTED PATTERNS:
{detected_patterns}
"""


def build_generation_prompt(
    project_dir: Path,
    file_sample_limit: int = 50,
) -> str:
    """Build the prompt for gate generation from project context."""
    import os

    excluded_dirs = {
        "__pycache__", ".venv", "node_modules", ".git", ".mypy_cache",
        ".cortex", ".a1", ".claude", ".vendor", ".prompt-engineer",
        "dist", "build", ".pytest_cache",
    }
    all_files: list[str] = []
    for root, dirs, files in os.walk(str(project_dir)):
        dirs[:] = [d for d in dirs if d not in excluded_dirs]
        for name in files:
            if name.endswith((".py", ".js", ".ts", ".rb", ".go")):
                rel = os.path.relpath(os.path.join(root, name), str(project_dir)).replace("\\", "/")
                all_files.append(rel)

    def _priority(path: str) -> tuple[int, str]:
        if path.startswith(("SYSTEM/", "BRAIN/", "INTERFACE/", "TESTS/")):
            return (0, path)
        if path.startswith("tests/"):
            return (1, path)
        return (2, path)

    all_files = sorted(all_files, key=_priority)
    file_list = "\n".join(all_files[:file_sample_limit])
    if len(all_files) > file_sample_limit:
        file_list += f"\n... +{len(all_files) - file_sample_limit} more files"

    patterns: list[str] = []
    for rel in all_files[:20]:
        path = project_dir / rel
        try:
            content = path.read_text(encoding="utf-8", errors="replace")[:2000]
        except OSError:
            continue
        if "from flask" in content or "from django" in content:
            patterns.append("Web framework: Flask/Django detected")
        if "from fastapi" in content:
            patterns.append("Web framework: FastAPI detected")
        if "import torch" in content or "import tensorflow" in content:
            patterns.append("ML framework: PyTorch/TensorFlow detected")
        if "def test_" in content or "TestCase" in content:
            patterns.append("Testing: pytest/unittest patterns detected")
        if "async def" in content:
            patterns.append("Async code: async/await patterns detected")
        if "dataclass" in content:
            patterns.append("Dataclasses: frozen/mutable dataclass patterns")
        if "subprocess" in content:
            patterns.append("Shell execution: subprocess usage detected")

    existing_rules = _load_project_rules(project_dir)
    existing_rules_text = (
        "\n".join(f"- {item.get('rule_id', '?')}: {item.get('description', '')}" for item in existing_rules)
        if existing_rules else "None"
    )

    project_name = project_dir.name or str(project_dir)
    project_context = f"Project root: {project_name}\nTotal files: {len(all_files)}"
    # Build builtin categories summary for the prompt
    from ..forensic_gate_catalog import UNIVERSAL_FORENSIC_CLUSTERS
    builtin_cats = sorted(set(cl["title"] for cl in UNIVERSAL_FORENSIC_CLUSTERS))
    builtin_categories = chr(10).join(f"- {t}" for t in builtin_cats)
    gates_dir = str(_generated_gates_dir(project_dir)).replace("\\", "/")

    return GATE_GENERATION_PROMPT.format(
        project_context=project_context,
        file_list=file_list,
        detected_patterns=chr(10).join(sorted(set(patterns))) if patterns else "No specific patterns detected",
        existing_rules=existing_rules_text,
        universal_cluster_count=len(UNIVERSAL_FORENSIC_CLUSTERS),
        builtin_categories=builtin_categories,
        gates_dir=gates_dir,
    )
