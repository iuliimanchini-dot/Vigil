"""Gate registry for cortex_forensic.

Adapted from BRAIN.autoforensics.gate_registry.
"""
from __future__ import annotations

from cortex_forensic.gate_packs.universal import GATE_SPECS as _UNIVERSAL_SPECS
from cortex_forensic._shared import GateCategory
import logging
_log = logging.getLogger(__name__)

_u = {check_id: (cat, runner) for check_id, cat, runner in _UNIVERSAL_SPECS}


def _u_entry(check_id: str) -> tuple:
    cat, runner = _u[check_id]
    return (check_id, cat, runner)


DEFAULT_GATE_CHECKS: tuple[tuple, ...] = tuple(
    _u_entry(spec[0]) for spec in _UNIVERSAL_SPECS
)
