"""Round-2 false-positive reduction tests (large real projects: click / mcp / filelock).

Each FP pattern below was found by inspecting the noisiest gates on click/mcp
line-by-line in the project's vendored site-packages. For every pattern we assert:

  * the FP shape is NOT flagged (the fix), and
  * a paired GENUINE shape IS still flagged (recall preserved).

Candidates covered:
  1. unused_import_scan — TYPE_CHECKING imports used as runtime calls /
     attribute-base / __all__ re-export, and else-branch imports of a
     TYPE_CHECKING guard, are all USED (not dead).
  2. magic_number_scan — small/common literals (<256, terminal widths, ASCII
     ctrl, byte values) are acceptable; only large/unusual literals flagged.
  3. docstring_param_scan — type-annotated and multi-line / overloaded
     signatures must not produce garbage "param" mismatches.
  4. duplicate_scan — trivial signature/overload/param-list mirrors (<6
     meaningful lines) are not near-duplicate logic.

Run:  pytest tests/test_fp_round2.py -v
"""
from __future__ import annotations

import re

import pytest

from vigil_forensic.gate_checks.forensic_clusters.dead_code import assess_unused_imports
from vigil_forensic.gate_checks.forensic_clusters.code_style import assess_magic_numbers
from vigil_forensic.gate_checks.forensic_clusters.static_analysis import assess_docstring_params
from vigil_forensic.gate_checks.forensic_clusters.data_quality import assess_near_duplicate_code


def _names(findings):
    """Return the set of imported names / titles flagged."""
    return [f.title for f in findings]


# ===========================================================================
# CANDIDATE 1: unused_import_scan — TYPE_CHECKING handling
# ===========================================================================

class TestUnusedImportTypeChecking:
    def test_typevar_call_inside_type_checking_not_flagged(self):
        """click shell_completion.py:59 pattern — `TypeVar` imported under
        TYPE_CHECKING and used as a runtime CALL inside the same block."""
        src = (
            "import typing as t\n"
            "if t.TYPE_CHECKING:\n"
            "    from typing_extensions import TypeVar\n"
            "    _ValueT_co = TypeVar('_ValueT_co', covariant=True, default=t.Any)\n"
            "else:\n"
            "    _ValueT_co = t.TypeVar('_ValueT_co', covariant=True)\n"
        )
        findings = assess_unused_imports("shell_completion.py", src)
        flagged = " ".join(_names(findings))
        assert "TypeVar" not in flagged, f"TypeVar (used in TYPE_CHECKING call) wrongly flagged: {flagged}"

    def test_attribute_base_inside_type_checking_not_flagged(self):
        """click utils.py:26 pattern — `te` imported under TYPE_CHECKING used as
        attribute-base (`te.ParamSpec`) inside the block."""
        src = (
            "import typing as t\n"
            "if t.TYPE_CHECKING:\n"
            "    import typing_extensions as te\n"
            "    P = te.ParamSpec('P')\n"
            "R = t.TypeVar('R')\n"
        )
        findings = assess_unused_imports("utils.py", src)
        flagged = " ".join(_names(findings))
        assert "te" not in flagged, f"`te` (used as attribute base) wrongly flagged: {flagged}"

    def test_sys_version_info_inside_type_checking_not_flagged(self):
        """filelock asyncio.py:22 pattern — `sys` imported under TYPE_CHECKING
        and used as `sys.version_info` to pick a typing import inside the block."""
        src = (
            "from typing import TYPE_CHECKING\n"
            "if TYPE_CHECKING:\n"
            "    import sys\n"
            "    if sys.version_info >= (3, 11):\n"
            "        from typing import Self\n"
            "    else:\n"
            "        from typing_extensions import Self\n"
        )
        findings = assess_unused_imports("asyncio.py", src)
        flagged = " ".join(_names(findings))
        assert "sys" not in flagged, f"`sys` (used as sys.version_info) wrongly flagged: {flagged}"

    def test_else_branch_import_of_type_checking_guard_not_flagged(self):
        """filelock __init__.py:26-27 pattern — names imported in the `else:`
        branch of a TYPE_CHECKING guard are RUNTIME imports (and re-exported via
        __all__), not TYPE_CHECKING imports. They must not be flagged."""
        src = (
            "from typing import TYPE_CHECKING\n"
            "if TYPE_CHECKING:\n"
            "    from ._read_write import ReadWriteLock\n"
            "else:\n"
            "    try:\n"
            "        from ._read_write import ReadWriteLock\n"
            "    except ImportError:\n"
            "        ReadWriteLock = None\n"
            "__all__ = ['ReadWriteLock']\n"
        )
        findings = assess_unused_imports("__init__.py", src)
        flagged = " ".join(_names(findings))
        assert "ReadWriteLock" not in flagged, (
            f"ReadWriteLock (else-branch runtime import + __all__) wrongly flagged: {flagged}"
        )

    def test_type_checking_import_reexported_in_all_not_flagged(self):
        """A name imported under TYPE_CHECKING but re-exported via __all__ is a
        public re-export, not a dead import."""
        src = (
            "from typing import TYPE_CHECKING\n"
            "if TYPE_CHECKING:\n"
            "    from ._mod import AsyncReadWriteLock\n"
            "__all__ = ['AsyncReadWriteLock']\n"
        )
        findings = assess_unused_imports("__init__.py", src)
        flagged = " ".join(_names(findings))
        assert "AsyncReadWriteLock" not in flagged, (
            f"AsyncReadWriteLock (re-exported in __all__) wrongly flagged: {flagged}"
        )

    # ----- paired REAL cases: genuinely-dead imports must STILL be flagged -----

    def test_real_dead_type_checking_import_still_flagged(self):
        """A TYPE_CHECKING import that is referenced NOWHERE (no annotation, no
        runtime use, not in __all__) is genuinely dead → must still be flagged."""
        src = (
            "from typing import TYPE_CHECKING\n"
            "if TYPE_CHECKING:\n"
            "    from collections import OrderedDict\n"
            "\n"
            "def f(x):\n"
            "    return x + 1\n"
        )
        findings = assess_unused_imports("mod.py", src)
        flagged = " ".join(_names(findings))
        assert "OrderedDict" in flagged, (
            f"Genuinely dead TYPE_CHECKING import OrderedDict NOT flagged: {flagged}"
        )

    def test_real_dead_plain_import_still_flagged(self):
        """A normal module-level import used nowhere is still flagged (oracle case)."""
        src = (
            "import json\n"
            "def f(x):\n"
            "    return x + 1\n"
        )
        findings = assess_unused_imports("mod.py", src)
        flagged = " ".join(_names(findings))
        assert "json" in flagged, f"Genuinely unused `import json` NOT flagged: {flagged}"


# ===========================================================================
# CANDIDATE 2: magic_number_scan — bounds
# ===========================================================================

class TestMagicNumberBounds:
    @pytest.mark.parametrize("literal,expr", [
        ("24", "hours = t % 24"),
        ("127", "if ord(c) < 127:"),
        ("11", "cls = 11"),
        ("12", "cls = 12"),
        ("50", "width = 50"),
        ("20", "indent = 20"),
    ])
    def test_small_common_int_not_flagged(self, literal, expr):
        """Small ints (<256) — terminal widths, ASCII ctrl, byte values, column
        sizes — are acceptable in real code and should not be flagged."""
        src = f"def f(t, c, width, indent):\n    {expr}\n    return width\n"
        findings = assess_magic_numbers("mod.py", src)
        details = " ".join(f.summary for f in findings)
        assert f"Magic number {literal} " not in details, (
            f"small common int {literal} wrongly flagged: {details}"
        )

    def test_large_unusual_int_still_flagged(self):
        """A large/unusual literal (oracle case: 86400 seconds-per-day) must
        still be flagged."""
        src = (
            "def is_expired(elapsed_seconds):\n"
            "    if elapsed_seconds > 86400:\n"
            "        return True\n"
            "    return False\n"
        )
        findings = assess_magic_numbers("mod.py", src)
        details = " ".join(f.summary for f in findings)
        assert "86400" in details, f"large literal 86400 NOT flagged: {details}"

    def test_other_large_unusual_int_still_flagged(self):
        """Another large unusual literal (e.g. 65537) still flagged."""
        src = "def f(x):\n    return x * 65537\n"
        findings = assess_magic_numbers("mod.py", src)
        details = " ".join(f.summary for f in findings)
        assert "65537" in details, f"large literal 65537 NOT flagged: {details}"


# ===========================================================================
# CANDIDATE 3: docstring_param_scan — type-annotated / multiline signatures
# ===========================================================================

class TestDocstringParamSignatures:
    def test_callable_return_annotation_no_garbage_param(self):
        """click core.py:673 call_on_close — `f: t.Callable[..., t.Any]` must not
        yield a garbage 'param' like `t.Any]` from naive `)` splitting."""
        src = (
            "class C:\n"
            "    def call_on_close(self, f: t.Callable[..., t.Any]) -> t.Callable[..., t.Any]:\n"
            '        """Register a teardown function.\n'
            "\n"
            "        :param f: The function to execute on teardown.\n"
            '        """\n'
            "        return self._exit_stack.callback(f)\n"
        )
        findings = assess_docstring_params("core.py", src)
        details = " ".join(f.summary for f in findings)
        assert "t.Any]" not in details, f"garbage param from Callable annotation: {details}"
        # The single documented param `f` matches the single real param → no finding.
        assert not findings, f"type-annotated sig wrongly flagged: {details}"

    def test_multiline_signature_with_comment_not_garbage(self):
        """click types.py:642 _clamp — a multi-line signature with an inline
        comment must not produce a finding built from comment fragments."""
        src = (
            "class C:\n"
            "    def _clamp(\n"
            "        # Covariant type variables cannot be used in input positions.\n"
            "        self,\n"
            "        bound: float,\n"
            "        dir: int,\n"
            "        open: bool,\n"
            "    ) -> float:\n"
            '        """Clamp to bound.\n'
            "\n"
            "        :param bound: The boundary value.\n"
            "        :param dir: 1 or -1.\n"
            "        :param open: If true, exclusive.\n"
            '        """\n'
            "        ...\n"
        )
        findings = assess_docstring_params("types.py", src)
        details = " ".join(f.summary for f in findings)
        assert "Covariant" not in details, f"comment fragment leaked into param diff: {details}"
        # bound/dir/open all documented and present → no finding.
        assert not findings, f"multiline sig wrongly flagged: {details}"

    def test_args_kwargs_not_required_in_docstring(self):
        """*args / **kwargs are conventionally omitted from :param: docs and must
        not count as 'missing from docs'."""
        src = (
            "def version_option(*param_decls, **kwargs):\n"
            '    """Add a version option.\n'
            "\n"
            "    :param param_decls: positional decls.\n"
            '    """\n'
            "    return param_decls\n"
        )
        findings = assess_docstring_params("decorators.py", src)
        details = " ".join(f.summary for f in findings)
        assert "kwargs" not in details, f"**kwargs wrongly reported as missing from docs: {details}"

    def test_google_style_section_headers_not_params(self):
        """mcp pattern — Google-style docstrings with `Args:` followed by
        `Returns:` / `Raises:` must not parse the section headers (`Returns`,
        `Raises`, `RuntimeError`) as documented params."""
        src = (
            "def _parse_file_path(file_spec):\n"
            '    """Parse a file path.\n'
            "\n"
            "    Args:\n"
            "        file_spec: Path to file, optionally with :object suffix\n"
            "\n"
            "    Returns:\n"
            "        Tuple of (file_path, server_object)\n"
            "\n"
            "    Raises:\n"
            "        RuntimeError: if the path is invalid\n"
            '    """\n'
            "    return file_spec\n"
        )
        findings = assess_docstring_params("cli.py", src)
        details = " ".join(f.summary for f in findings)
        for bad in ("Returns", "Raises", "RuntimeError", "Yields", "Example"):
            assert bad not in details, f"section header '{bad}' parsed as param: {details}"
        assert not findings, f"Google-style docstring wrongly flagged: {details}"

    def test_google_style_real_extra_param_still_flagged(self):
        """Google-style: a documented param NOT in the signature is still real drift."""
        src = (
            "def fetch(url, timeout):\n"
            '    """Fetch a URL.\n'
            "\n"
            "    Args:\n"
            "        url: the URL to fetch\n"
            "        retries: how many times to retry\n"  # NOT a parameter
            "\n"
            "    Returns:\n"
            "        the response body\n"
            '    """\n'
            "    return url\n"
        )
        findings = assess_docstring_params("svc.py", src)
        details = " ".join(f.summary for f in findings)
        assert findings, "genuine Google-style drift NOT flagged"
        assert "retries" in details, f"expected 'retries' as drift, got: {details}"

    def test_rst_type_prefixed_param_name_parsed_correctly(self):
        """filelock asyncio.py:197 pattern — reST `:param <type> name:` puts the
        type before the name. The detector must capture `value`, not `futures`."""
        src = (
            "class C:\n"
            "    def executor(self, value):\n"
            '        """Change the executor.\n'
            "\n"
            "        :param futures.Executor | None value: the new executor or None\n"
            '        """\n'
            "        self._x = value\n"
        )
        findings = assess_docstring_params("asyncio.py", src)
        details = " ".join(f.summary for f in findings)
        assert "futures" not in details, f"reST type token mis-parsed as param: {details}"
        assert not findings, f"correctly-documented type-prefixed param wrongly flagged: {details}"

    # ----- paired REAL case: genuine documented-param-not-in-signature -----

    def test_real_doc_param_not_in_signature_still_flagged(self):
        """A docstring documenting a param that is NOT in the (clean) signature is
        a genuine drift → must still be flagged."""
        src = (
            "def handle(request, timeout):\n"
            '    """Handle a request.\n'
            "\n"
            "    :param request: the request object.\n"
            "    :param retries: number of retries.\n"  # 'retries' is NOT a parameter
            '    """\n'
            "    return request\n"
        )
        findings = assess_docstring_params("svc.py", src)
        details = " ".join(f.summary for f in findings)
        assert findings, "genuine docstring/signature drift NOT flagged"
        assert "retries" in details, f"expected 'retries' as drift, got: {details}"


# ===========================================================================
# CANDIDATE 4: duplicate_scan — trivial vs real near-duplicate blocks
# ===========================================================================

def _dup_span(summary):
    m = re.search(r"\((\d+) lines\)", summary)
    return int(m.group(1)) if m else None


class TestDuplicateBlockThreshold:
    def test_short_signature_mirror_not_flagged(self):
        """A 4-line @overload / param-list mirror (click termui.py overloads) is
        typing boilerplate, not refactorable near-duplicate logic."""
        src = (
            "import typing as t\n"
            "@t.overload\n"
            "def progressbar(\n"
            "    label=None,\n"
            "    show_eta=True,\n"
            "    show_percent=None,\n"
            "    fill_char='#',\n"
            "): ...\n"
            "@t.overload\n"
            "def progressbar(\n"
            "    label=None,\n"
            "    show_eta=True,\n"
            "    show_percent=None,\n"
            "    fill_char='#',\n"
            "): ...\n"
            "def progressbar(label=None, show_eta=True, show_percent=None, fill_char='#'):\n"
            "    return label\n"
        )
        findings = assess_near_duplicate_code("termui.py", src)
        assert not findings, (
            f"short (<6 meaningful-line) signature mirror wrongly flagged: "
            f"{[f.summary for f in findings]}"
        )

    def test_real_six_line_logic_duplicate_still_flagged(self):
        """The oracle duplication shape — two functions with identical 6-line
        bodies of real logic — MUST still be flagged (recall preserved)."""
        src = (
            "def route_alpha(payload):\n"
            "    header = payload.get('header')\n"
            "    body = payload.get('body')\n"
            "    checksum = compute_checksum(header, body)\n"
            "    record = build_record(header, body, checksum)\n"
            "    persist_record(record)\n"
            "    return record\n"
            "\n"
            "\n"
            "def route_beta(payload):\n"
            "    header = payload.get('header')\n"
            "    body = payload.get('body')\n"
            "    checksum = compute_checksum(header, body)\n"
            "    record = build_record(header, body, checksum)\n"
            "    persist_record(record)\n"
            "    return record\n"
        )
        findings = assess_near_duplicate_code("svc.py", src)
        assert findings, "genuine 6-line logic duplicate NOT flagged"
        spans = [_dup_span(f.summary) for f in findings]
        assert any(s is not None and s >= 6 for s in spans), (
            f"expected a >=6-line duplicate region, got spans={spans}"
        )

    def test_long_logic_duplicate_still_flagged(self):
        """A clearly real >6-line copy-pasted logic block stays flagged."""
        body = "\n".join(f"    step_{i} = transform_{i}(data, {i})" for i in range(8))
        src = (
            "def proc_a(data):\n" + body + "\n    return data\n"
            "\n\n"
            "def proc_b(data):\n" + body + "\n    return data\n"
        )
        findings = assess_near_duplicate_code("pipe.py", src)
        assert findings, "genuine long logic duplicate NOT flagged"
