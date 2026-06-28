"""P3: exception_swallow must NOT flag idiomatic control-flow catches.

`except KeyboardInterrupt: pass` / `except BrokenPipeError: pass` are idioms
(clean shutdown, closed-pipe), not swallowed errors. Flagging them is a FP
(seen on click: 13 exception_swallow findings, several were control-flow).
"""
from __future__ import annotations

from vigil_forensic.gate_checks.forensic_clusters.exception_boundary import (
    assess_exception_swallowing,
)


def test_control_flow_exceptions_not_flagged():
    for exc in ("KeyboardInterrupt", "BrokenPipeError", "GeneratorExit",
                "SystemExit", "StopIteration"):
        src = f"try:\n    do()\nexcept {exc}:\n    pass\n"
        findings = assess_exception_swallowing("m.py", src)
        assert findings == [], (
            f"{exc}: pass is a control-flow idiom, must not be flagged "
            f"(got {len(findings)})"
        )


def test_asyncio_cancelled_dotted_not_flagged():
    src = "try:\n    await x()\nexcept asyncio.CancelledError:\n    pass\n"
    assert assess_exception_swallowing("m.py", src) == []


def test_real_swallow_still_flagged():
    # a genuine error type swallowed with pass IS still a finding
    src = "try:\n    do()\nexcept ValueError:\n    pass\n"
    findings = assess_exception_swallowing("m.py", src)
    assert len(findings) >= 1, "except ValueError: pass must still be flagged"
