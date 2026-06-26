"""TDD tests for ``commented_code_scan`` prose-vs-code discrimination.

The ``commented_code_scan`` gate (``assess_commented_code``) historically
decided a comment block "looks like code" by counting lines whose body matched
a permissive ``code_indicators`` regex (``\\w+=\\w``, ``def ``, ``except \\w``,
``return \\w``, ``for \\w`` …). A *prose* comment that merely **mentions** a
code-like word in an English sentence therefore matched:

    # bare ``except:`` and ``except BaseException:`` are detected via AST in
    # _check_bare_and_base_handlers (not regex) so the handler BODY can be
    # inspected for a re-raise. A line-only regex cannot tell a swallow from
    # the correct cancel-cleanup idiom (``except BaseException: ... raise``).

That block contains the word ``except`` twice (inside sentences) → two
``code_indicators`` hits → flagged as commented-out code. That is the verified
false positive at ``broad_except_checks.py:21``.

These tests pin the corrected behavior. A comment block is flagged as
commented-out code only when its **de-commented body** either (a) contains a
contiguous run of >=2 lines that ``ast.parse``-s as real Python statements, or
(b) carries >=2 *distinct strong* code signals (assignment with an identifier
LHS, ``def``/``class``/``import`` header, a bare ``name(...)`` call, a block
header line). A single code keyword embedded in grammatical English is NOT
code.

  1. PROSE that merely mentions ``except``/``return``/``if`` in sentences is
     NOT flagged (the broad_except FP and variants).
  2. A genuinely commented-out statement block IS flagged (recall).
  3. A commented-out ``def`` IS flagged (recall).
  4. The oracle's real commented block (a prose intro line followed by real
     commented-out code) IS still flagged (recall not lost to a prose intro).

Run:  pytest tests/test_commented_code_fp.py -v
"""
from __future__ import annotations

from cortex_forensic.gate_checks.forensic_clusters.async_quality import (
    assess_commented_code,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _titles(findings) -> list[str]:
    return [f.title for f in findings]


def _flagged_lines(findings) -> set[int]:
    # title shape: "[commented_code] <path>:<line>"
    out: set[int] = set()
    for f in findings:
        try:
            out.add(int(f.title.rsplit(":", 1)[1]))
        except (ValueError, IndexError):
            pass
    return out


# A 4-line lead-in so the comment block never falls in the skipped first 4
# lines (the detector ignores blocks whose start index < 4).
_LEAD = (
    "from __future__ import annotations\n"
    "\n"
    "import re\n"
    "\n"
)


# ---------------------------------------------------------------------------
# 1. PROSE comments that mention code-like words are NOT flagged.
# ---------------------------------------------------------------------------

def test_prose_except_explanation_not_flagged():
    # Verbatim shape of broad_except_checks.py:21-24 — explanatory prose that
    # contains the word "except BaseException" twice.
    src = _LEAD + (
        "# bare ``except:`` and ``except BaseException:`` are detected via AST in\n"
        "# _check_bare_and_base_handlers (not regex) so the handler BODY can be inspected\n"
        "# for a re-raise. A line-only regex cannot tell a swallow from the correct\n"
        "# cancel-cleanup idiom (``except BaseException: <cleanup>; raise``).\n"
    )
    findings = assess_commented_code("broad_except_checks.py", src)
    assert not findings, f"prose explaining 'except' must not be flagged: {_titles(findings)}"


def test_prose_multiline_mentions_return_if_except_not_flagged():
    # Grammatical English sentences that happen to contain return / if / except.
    src = _LEAD + (
        "# If the value is missing we return early to avoid a crash here.\n"
        "# Otherwise the loop continues until the queue is empty again, except\n"
        "# when the caller has already requested a shutdown of the worker pool.\n"
    )
    findings = assess_commented_code("worker.py", src)
    assert not findings, f"prose mentioning return/if/except must not be flagged: {_titles(findings)}"


def test_prose_note_with_call_mention_not_flagged():
    # NOTE-style design rationale referencing a function by name(...) in prose.
    src = _LEAD + (
        "# NOTE: callers must hold the lock before invoking refresh() here.\n"
        "# See refresh_locked() for the unlocked variant used by the scheduler.\n"
        "# This avoids a double-acquire that would otherwise deadlock the pool.\n"
    )
    findings = assess_commented_code("cache.py", src)
    assert not findings, f"NOTE prose must not be flagged: {_titles(findings)}"


def test_prose_assignment_like_sentence_not_flagged():
    # "The default timeout = 30 seconds ..." — '=' in a sentence, LHS is words.
    src = _LEAD + (
        "# The default timeout = 30 seconds in most production deployments.\n"
        "# We chose this because the upstream server is slow to respond and we\n"
        "# do not want to give up on a request that is merely queued behind work.\n"
    )
    findings = assess_commented_code("config.py", src)
    assert not findings, f"prose with '=' in a sentence must not be flagged: {_titles(findings)}"


# ---------------------------------------------------------------------------
# 2 & 3. Genuinely commented-out code IS flagged (recall preserved).
# ---------------------------------------------------------------------------

def test_commented_out_statement_block_is_flagged():
    src = _LEAD + (
        "# x = compute(a)\n"
        "# y = x + 1\n"
        "# return y\n"
    )
    findings = assess_commented_code("calc.py", src)
    assert findings, "a genuine commented-out statement block must be flagged"
    assert 5 in _flagged_lines(findings), _titles(findings)


def test_commented_out_def_is_flagged():
    src = _LEAD + (
        "# def old_impl():\n"
        "#     return 1\n"
        "#     # leftover\n"
    )
    findings = assess_commented_code("legacy.py", src)
    assert findings, "a commented-out def must be flagged"
    assert 5 in _flagged_lines(findings), _titles(findings)


def test_commented_out_call_sequence_is_flagged():
    # No assignments — three bare calls. Parses as a 3-statement block.
    src = _LEAD + (
        "# logger.debug('start')\n"
        "# process_batch(items)\n"
        "# logger.debug('done')\n"
    )
    findings = assess_commented_code("pipeline.py", src)
    assert findings, "a commented-out call sequence must be flagged"


# ---------------------------------------------------------------------------
# 4. Oracle real block: prose intro line + real commented-out code.
# ---------------------------------------------------------------------------

def test_oracle_style_block_with_prose_intro_is_flagged():
    # Mirrors tests/oracle/sample_quality.py:69-73 — a one-line prose intro
    # ("legacy implementation kept around just in case:") followed by a real
    # commented-out for/return block. The prose intro must NOT mask the code.
    # The leading blank lines push the comment block past the detector's
    # "skip the first 4 lines" guard (block_start index must be >= 4).
    src = (
        "\n\n\n\n"
        "def transform(values):\n"
        "    result = []\n"
        "    # legacy implementation kept around just in case:\n"
        "    # for v in values:\n"
        "    #     acc = acc + v * 2\n"
        "    #     result.append(acc)\n"
        "    # return result\n"
        "    return [v * 2 for v in values]\n"
    )
    findings = assess_commented_code("sample_quality.py", src)
    assert findings, "the oracle real commented-out block must still be flagged"
    assert 7 in _flagged_lines(findings), _titles(findings)
