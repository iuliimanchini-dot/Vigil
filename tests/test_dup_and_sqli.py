"""TDD: near-duplicate per-line inflation merge + focused SQL-injection detection.

Two forensic-auditor fixes pinned here:

Problem 1 — ``assess_near_duplicate_code`` (cluster45, ``duplicate_scan``)
    emitted ONE finding per 4-line sliding window. A single duplicated block of
    N lines produced N-3 near-identical findings ("block at 118 and 201",
    "...119 and 202", ...). The fix merges contiguous/overlapping line-pairs
    into ONE finding per contiguous block — mirroring the ``_merge_starts``
    region-grouping already used by ``duplication.text_block``.

Problem 2 — ``assess_security_patterns`` (cluster12, ``security_scan``)
    AST-based SQL-injection detection. f-string / ``%`` / ``.format()`` built
    queries passed to ``.execute()`` were already caught; this adds the
    remaining ``BinOp(+)`` string-concatenation form. A plain literal
    ``execute("SELECT 1")`` and a parametrised ``execute("...", (x,))`` must
    NOT flag.

Run:  pytest tests/test_dup_and_sqli.py -v
"""
from __future__ import annotations

import re
from pathlib import Path

import pytest

from cortex_forensic.gate_checks.forensic_clusters.data_quality import (
    assess_near_duplicate_code,
)
from cortex_forensic.gate_checks.forensic_clusters.edit_mutation import (
    assess_security_patterns,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _dup_findings(name: str, src: str):
    return assess_near_duplicate_code(name, src)


def _sqli_findings(name: str, src: str):
    fs = assess_security_patterns(name, src)
    return [
        f for f in fs
        if "sql" in (f.summary or "").lower() or "injection" in (f.summary or "").lower()
    ]


# A duplicated block: two functions whose 4 inner statements are identical.
# (Distinct enough lines to survive the normalizer's trivial-line filter.)
def _make_block(prefix: str) -> str:
    body = (
        f"    {prefix}_a = compute_value(101)\n"
        f"    {prefix}_b = transform_data({prefix}_a, scale=7)\n"
        f"    {prefix}_c = combine_results({prefix}_b, offset=3)\n"
        f"    {prefix}_d = finalize_output({prefix}_c, mode='strict')\n"
    )
    return body


_ONE_DUP_BLOCK = (
    "def first():\n"
    + _make_block("x")
    + "    return x_d\n"
    "\n\n"
    "def second():\n"
    + _make_block("x")  # identical statements -> duplicate block
    + "    return x_d\n"
)


# Two DISTINCT duplicated blocks in one file: block-A repeated twice and a
# SEPARATE block-B repeated twice. Must yield two findings, not one and not N.
def _make_block_b(prefix: str) -> str:
    body = (
        f"    {prefix}_p = open_socket('host', 9000)\n"
        f"    {prefix}_q = send_payload({prefix}_p, retries=5)\n"
        f"    {prefix}_r = await_ack({prefix}_q, timeout=30)\n"
        f"    {prefix}_s = close_socket({prefix}_p, graceful=True)\n"
    )
    return body


_TWO_DUP_BLOCKS = (
    "def alpha():\n"
    + _make_block("x")
    + "    return x_d\n"
    "\n\n"
    "def beta():\n"
    + _make_block("x")  # duplicate of block-A
    + "    return x_d\n"
    "\n\n"
    "def gamma():\n"
    + _make_block_b("y")
    + "    return y_s\n"
    "\n\n"
    "def delta():\n"
    + _make_block_b("y")  # duplicate of block-B
    + "    return y_s\n"
)


_RANGE_RE = re.compile(r"lines?\s+(\d+)\s*-\s*(\d+)\D+(\d+)\s*-\s*(\d+)")


# ---------------------------------------------------------------------------
# Problem 1 — near-duplicate per-line inflation merge
# ---------------------------------------------------------------------------

class TestNearDuplicateMerge:
    def test_one_block_one_finding(self):
        """A single duplicated multi-line block -> exactly ONE finding,
        not one-per-window-line."""
        findings = _dup_findings("dup.py", _ONE_DUP_BLOCK)
        assert len(findings) == 1, (
            f"expected 1 merged finding, got {len(findings)}:\n"
            + "\n".join(f.summary for f in findings)
        )

    def test_merged_finding_uses_line_range_form(self):
        """The merged finding must report a contiguous line RANGE
        (e.g. 'lines 2-5 <-> 8-11'), not a single line-pair."""
        findings = _dup_findings("dup.py", _ONE_DUP_BLOCK)
        assert len(findings) == 1
        summary = findings[0].summary
        m = _RANGE_RE.search(summary)
        assert m, f"merged finding must carry a start-end range form; got: {summary!r}"
        a0, a1, b0, b1 = (int(g) for g in m.groups())
        # Both sides must span >1 line (a real merged block, not a 1-line pair).
        assert a1 > a0, f"first range not multi-line: {summary!r}"
        assert b1 > b0, f"second range not multi-line: {summary!r}"
        # The two occurrences must be the SAME height.
        assert (a1 - a0) == (b1 - b0), f"range heights differ: {summary!r}"

    def test_two_distinct_blocks_two_findings(self):
        """Two genuinely separate duplicated blocks -> two findings (each
        reported once). Proves we MERGE contiguous runs, not CAP the count."""
        findings = _dup_findings("two.py", _TWO_DUP_BLOCKS)
        assert len(findings) == 2, (
            f"expected 2 findings (one per distinct block), got {len(findings)}:\n"
            + "\n".join(f.summary for f in findings)
        )

    def test_no_false_positive_on_unique_code(self):
        """Code with no repeated block -> no findings."""
        src = "\n".join(f"unique_var_{i} = step_{i}(arg_{i}, key_{i})" for i in range(20)) + "\n"
        findings = _dup_findings("uniq.py", src)
        assert findings == [], (
            "no duplicate block present, must not flag: "
            + "\n".join(f.summary for f in findings)
        )

    def test_filelock_real_blocks_not_inflated(self):
        """Real third-party file (filelock/asyncio.py): no per-line inflation,
        and — after FP-round2-D — no signature/parameter-mirror noise either.

        The two regions this file used to report (lines 64-68<->358-362 and
        78-89<->119-130) are BOTH parameter-list mirrors: the identical
        ``lock_file: str | os.PathLike[str], timeout: float = -1, ...`` parameter
        declarations shared by ``AsyncFileLockMeta.__call__`` and
        ``BaseAsyncFileLock.__init__`` by API contract. Those are typing
        scaffolding, not refactorable logic, and are now stripped by the
        signature-scaffolding filter — so this file correctly yields ZERO
        near-duplicate-logic findings. The bound (<=5) guards against any return
        of per-line inflation while allowing the corrected 0.
        """
        import cortex_forensic
        repo_root = Path(cortex_forensic.__file__).resolve().parent.parent
        f = repo_root / ".venv" / "Lib" / "site-packages" / "filelock" / "asyncio.py"
        if not f.is_file():
            pytest.skip("filelock not installed in .venv")
        findings = _dup_findings(f.name, f.read_text(encoding="utf-8", errors="replace"))
        # FP-round2-D: parameter-mirror "duplicates" are no longer reported;
        # 0 is the correct, deduplicated result for this file.
        assert 0 <= len(findings) <= 5, (
            f"expected merged block count (<=5), got {len(findings)}:\n"
            + "\n".join(x.summary for x in findings)
        )


# ---------------------------------------------------------------------------
# Problem 2 — focused SQL-injection detection (low FP)
# ---------------------------------------------------------------------------

class TestSqlInjectionDetection:
    def test_concat_into_execute_flagged(self):
        """String concatenation (BinOp +) into .execute() -> flagged."""
        src = (
            "def g(db, user_input):\n"
            '    db.execute("SELECT * FROM users WHERE id=" + user_input)\n'
        )
        assert _sqli_findings("c.py", src), "concat-into-execute must be flagged"

    def test_fstring_into_execute_flagged(self):
        """f-string with interpolation into .execute() -> flagged."""
        src = (
            "def g(db, user_input):\n"
            '    db.execute(f"SELECT * FROM users WHERE id={user_input}")\n'
        )
        assert _sqli_findings("f.py", src), "f-string-into-execute must be flagged"

    def test_percent_format_into_execute_flagged(self):
        """%-format into .execute() -> flagged."""
        src = (
            "def g(cursor, user_input):\n"
            '    cursor.execute("SELECT * FROM t WHERE x = %s" % user_input)\n'
        )
        assert _sqli_findings("p.py", src), "%-format-into-execute must be flagged"

    def test_format_method_into_execute_flagged(self):
        """str.format() into .execute() -> flagged."""
        src = (
            "def g(cursor, user_input):\n"
            '    cursor.execute("SELECT * FROM t WHERE x = {}".format(user_input))\n'
        )
        assert _sqli_findings("fm.py", src), ".format()-into-execute must be flagged"

    def test_literal_execute_not_flagged(self):
        """A plain literal query -> NOT flagged (precision guard)."""
        src = 'def g(db):\n    db.execute("SELECT 1")\n'
        assert _sqli_findings("lit.py", src) == [], (
            "plain literal execute must NOT be flagged"
        )

    def test_parametrised_execute_not_flagged(self):
        """A parametrised query (placeholders + params tuple) -> NOT flagged."""
        src = 'def g(db, x):\n    db.execute("SELECT * FROM t WHERE id = ?", (x,))\n'
        assert _sqli_findings("param.py", src) == [], (
            "parametrised execute must NOT be flagged"
        )

    def test_concat_of_two_literals_not_flagged(self):
        """A query built by concatenating two STRING LITERALS (no variable) is a
        static string -> must NOT be flagged (no injection vector)."""
        src = (
            "def g(db):\n"
            '    db.execute("SELECT * FROM t " + "WHERE active = 1")\n'
        )
        assert _sqli_findings("two_lit.py", src) == [], (
            "literal+literal concat is a constant query, must NOT be flagged"
        )

    def test_non_execute_concat_not_flagged(self):
        """A SQL-looking concat NOT passed to a DB call site -> NOT flagged
        (the rule is scoped to execute/query call sites)."""
        src = (
            "def g(user_input):\n"
            '    msg = "SELECT * FROM users WHERE id=" + user_input\n'
            "    return msg\n"
        )
        assert _sqli_findings("noexec.py", src) == [], (
            "SQL string built but not executed must NOT be flagged"
        )
