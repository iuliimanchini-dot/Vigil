"""API/protocol surface forensics. Clusters 27, 28b, 29b, 30."""
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


def assess_embedded_code_syntax(
    file_path: str,
    content: str,
) -> list[GateFinding]:
    """Cluster 27: Validate syntax of JS/CSS/HTML embedded in string literals."""
    import re

    if not content.strip():
        return []
    if detect_language(file_path) != "python":
        return []

    findings: list[GateFinding] = []
    string_vars = re.finditer(
        r'^(_?[A-Z][A-Z_0-9]*)\s*=\s*(?:f?"""(.*?)"""|f?\'\'\'(.*?)\'\'\')',
        content,
        re.MULTILINE | re.DOTALL,
    )
    for match in string_vars:
        var_name = match.group(1)
        embedded = match.group(2) or match.group(3) or ""
        if len(embedded) < 50:
            continue
        is_js = bool(re.search(r'\bfunction\b|\bvar\b|\bconst\b|\blet\b|\bdocument\b|\bfetch\b|\baddEventListener\b', embedded))
        is_css = bool(re.search(r'[.#]\w+\s*\{|:\s*\w+;|@media\b', embedded))
        is_html = bool(re.search(r'<div\b|<span\b|<nav\b|<button\b|class="', embedded))
        if not (is_js or is_css or is_html):
            continue
        line_num = content[:match.start()].count("\n") + 1
        open_chars = {'(': ')', '{': '}', '[': ']'}
        close_chars = {v: k for k, v in open_chars.items()}
        stack: list[str] = []
        issue: str | None = None
        for ch in embedded:
            if ch in open_chars:
                stack.append(ch)
            elif ch in close_chars:
                if not stack:
                    issue = f"Unmatched closing '{ch}' in embedded code ({var_name})"
                    break
                if stack[-1] != close_chars[ch]:
                    issue = f"Mismatched brackets in embedded code ({var_name}): expected '{open_chars[stack[-1]]}' got '{ch}'"
                    break
                stack.pop()
        if issue is None and stack:
            issue = f"Unclosed brackets in embedded code ({var_name}): {''.join(stack[-3:])}"
        if issue:
            findings.append(build_finding(
                check_id="embedded_syntax_scan",
                category=GateCategory.CONTRACT,
                title=f"[embedded_code_syntax] {file_path}:{line_num}:{var_name}",
                severity=GateSeverity.MEDIUM,
                impact=GateImpact.REVISE,
                summary=issue,
                recommendation="Fix bracket mismatch in embedded code constant.",
                evidence=(EvidenceReference(kind="probe", detail=issue, ok=False),),
                repair_kind=RepairKind.FIX_CONTRACT.value,
                executor_action=f"Fix embedded code syntax in {var_name} at {file_path}:{line_num}",
            ))
    return findings[:10]


# DOM / built-in property names that routinely appear on variables named
# ``data``/``body``/``result`` etc. but are NOT response-shape fields. Matching
# these as missing backend keys produces 100% FP on UI/DOM code.
_DOM_AND_BUILTIN_PROPS: frozenset[str] = frozenset({
    # DOM API surface
    "appendChild", "removeChild", "replaceChild", "insertBefore", "cloneNode",
    "className", "classList", "id", "innerHTML", "innerText", "textContent",
    "outerHTML", "outerText", "value", "checked", "disabled", "selected",
    "setAttribute", "getAttribute", "removeAttribute", "hasAttribute",
    "addEventListener", "removeEventListener", "dispatchEvent",
    "parentNode", "parentElement", "childNodes", "children",
    "firstChild", "lastChild", "firstElementChild", "lastElementChild",
    "nextSibling", "previousSibling", "nextElementSibling", "previousElementSibling",
    "style", "dataset", "tagName", "nodeType", "nodeName", "nodeValue",
    "offsetTop", "offsetLeft", "offsetWidth", "offsetHeight", "offsetParent",
    "clientTop", "clientLeft", "clientWidth", "clientHeight",
    "scrollTop", "scrollLeft", "scrollWidth", "scrollHeight",
    "focus", "blur", "click", "scrollIntoView", "remove",
    "querySelector", "querySelectorAll", "getElementsByClassName",
    "getElementsByTagName", "contains", "matches", "closest",
    # Standard response / fetch surface — NOT a business field
    "then", "catch", "finally", "json", "ok", "status", "statusText",
    "text", "body", "blob", "formData", "arrayBuffer", "headers",
    "redirected", "type", "url", "clone",
    # Array / String / Object methods
    "length", "map", "forEach", "filter", "find", "findIndex", "slice",
    "splice", "concat", "reverse", "sort", "flat", "flatMap", "includes",
    "every", "some", "reduce", "reduceRight",
    "toString", "valueOf", "constructor", "prototype", "hasOwnProperty",
    "trim", "trimStart", "trimEnd", "split", "join", "replace", "replaceAll",
    "indexOf", "lastIndexOf", "toLowerCase", "toUpperCase", "substring",
    "substr", "charAt", "charCodeAt", "startsWith", "endsWith", "padStart",
    "padEnd", "repeat", "normalize",
    "push", "pop", "shift", "unshift", "entries", "keys", "values",
    # JS error propagation
    "error", "message", "name", "stack", "cause",
    # Event handler surface
    "target", "currentTarget", "preventDefault", "stopPropagation",
})


def assess_response_shape_drift(
    backend_files: dict[str, str],
    frontend_files: dict[str, str],
) -> list[GateFinding]:
    """Cluster 28b: Detect JS reading fields that backend doesn't provide.

    A field is flagged only when (a) it appears on the RHS of a ``.<field>``
    access on a response-like identifier AND (b) it isn't a DOM/built-in
    property like ``appendChild`` or ``className``. See ``_DOM_AND_BUILTIN_PROPS``.
    """
    import re

    if not backend_files or not frontend_files:
        return []

    backend_keys: set[str] = set()
    for path, content in backend_files.items():
        # Multi-line object literal support: dotall so ``{\n "a": 1\n}`` matches.
        for m in re.finditer(r'_send_json\s*\([^{]*\{(.*?)\}', content, re.DOTALL):
            keys = re.findall(r'["\'](\w+)["\']\s*:', m.group(1))
            backend_keys.update(keys)

    if not backend_keys:
        return []

    frontend_access: dict[str, list[str]] = {}
    for path, content in frontend_files.items():
        for i, line in enumerate(content.splitlines(), 1):
            for m in re.finditer(r'\b(?:d|resp|data|result|body|payload|status)\.([\w]+)\b', line):
                field = m.group(1)
                if field in _DOM_AND_BUILTIN_PROPS:
                    continue
                frontend_access.setdefault(field, []).append(f"{path}:{i}")

    if not frontend_access:
        return []

    findings: list[GateFinding] = []
    for field, locations in sorted(frontend_access.items()):
        if field not in backend_keys:
            findings.append(build_finding(
                check_id="response_shape_scan",
                category=GateCategory.DRIFT,
                title=f"[response_shape_drift] .{field}",
                severity=GateSeverity.MEDIUM,
                impact=GateImpact.REVISE,
                summary=f"Frontend reads '.{field}' but no backend _send_json includes '{field}' key",
                recommendation=f"Add '{field}' to backend response or remove frontend read.",
                evidence=(EvidenceReference(kind="probe", detail=f"Frontend reads '.{field}' but no backend _send_json includes '{field}' key", ok=False),),
                repair_kind=RepairKind.NORMALIZE_SHAPE.value,
                executor_action=f"Sync response shape for field '{field}'",
            ))
        if len(findings) >= 20:
            break
    return findings


def assess_http_method_consistency(
    route_methods: dict[str, str],
    js_fetches: list[tuple[str, str, str]],
) -> list[GateFinding]:
    """Cluster 29b: Verify JS fetch methods match registered route methods."""
    if not route_methods or not js_fetches:
        return []

    findings: list[GateFinding] = []
    for url, js_method, source in js_fetches:
        clean_url = url.split("?")[0]
        if clean_url in route_methods:
            expected = route_methods[clean_url]
            if js_method.upper() != expected.upper():
                detail = f"JS fetches {clean_url} with {js_method.upper()} but route expects {expected.upper()}"
                findings.append(build_finding(
                    check_id="method_match_scan",
                    category=GateCategory.CONTRACT,
                    title=f"[http_method_consistency] {clean_url}",
                    severity=GateSeverity.HIGH,
                    impact=GateImpact.REVISE,
                    summary=detail,
                    recommendation=f"Change JS fetch method for {clean_url} to {expected.upper()}.",
                    evidence=(EvidenceReference(kind="probe", detail=detail, ok=False),),
                    repair_kind=RepairKind.FIX_CONTRACT.value,
                    executor_action=f"Fix HTTP method mismatch for {clean_url}",
                ))
    return findings


def assess_js_surface_coverage(
    all_js_constants: list[str],
    checked_js_constants: list[str],
) -> list[GateFinding]:
    """Cluster 30: Verify all JS surface constants are covered by forensics."""
    if not all_js_constants:
        return []

    findings: list[GateFinding] = []
    for name in all_js_constants:
        if name not in checked_js_constants:
            findings.append(build_finding(
                check_id="js_coverage_scan",
                category=GateCategory.CONTRACT,
                title=f"[js_surface_coverage] {name}",
                severity=GateSeverity.MEDIUM,
                impact=GateImpact.REVISE,
                summary=f"JS constant '{name}' exists but is not checked by route/contract forensics",
                recommendation=f"Add '{name}' to the checked_js_constants list in _check_js_surface_coverage.",
                evidence=(EvidenceReference(kind="probe", detail=f"JS constant '{name}' exists but is not checked by route/contract forensics", ok=False),),
                repair_kind=RepairKind.ADD_PROOF.value,
                executor_action=f"Add '{name}' to JS surface coverage checks",
            ))
    return findings
