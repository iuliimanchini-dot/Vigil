"""Source adapter registry and dispatch helpers.

Public API:
    ADAPTERS              -- dict mapping file extension -> SourceAdapter instance.
    get_adapter_for_file  -- return adapter for a given Path (by extension).
    supported_extensions  -- tuple of all currently registered extensions.
    SourceAdapter         -- Protocol for type-checking adapter compliance.
    RegexAdapterBase      -- Base class for regex-based adapters (L2+ languages).
    IR signal classes     -- ImportEdge, SymbolDef, ContractCandidate,
                            RuntimeSignal, AuthorityWriteCandidate.

Registry population (current state — all 6 languages registered):
    Python (.py), TypeScript (.ts, .tsx), JavaScript (.js, .jsx),
    Go (.go), Java (.java), Swift (.swift).
    Historical note: L1 shipped Python only; L2 added TS/JS; L5 added Go/Java;
    Swift support added Swift (.swift).
"""
from __future__ import annotations

import logging
from pathlib import Path

from ._base import RegexAdapterBase, SourceAdapter
from ._ir import (
    AuthorityWriteCandidate,
    ContractCandidate,
    ImportEdge,
    RuntimeSignal,
    TSRuntimeSignal,
    SymbolDef,
)
from .go import GoAdapter
from .java import JavaAdapter
from .javascript import JavascriptAdapter
from .python import PythonAdapter
from .swift import SwiftAdapter
from .typescript import TypescriptAdapter

__all__ = [
    "ADAPTERS",
    "get_adapter_for_file",
    "supported_extensions",
    "SourceAdapter",
    "RegexAdapterBase",
    "ImportEdge",
    "SymbolDef",
    "ContractCandidate",
    "RuntimeSignal",
    "TSRuntimeSignal",
    "AuthorityWriteCandidate",
    "PythonAdapter",
    "TypescriptAdapter",
    "JavascriptAdapter",
    "GoAdapter",
    "JavaAdapter",
    "SwiftAdapter",
]

_log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Static adapter registry — keyed by lowercase file extension
# ---------------------------------------------------------------------------

# Populated at import time via _register(). Extensions must be lowercase.
ADAPTERS: dict[str, SourceAdapter] = {}


def _register(adapter: SourceAdapter) -> None:
    """Register *adapter* for each extension it declares.

    Extensions are stored in lowercase. Raises ValueError if an extension is
    already registered (prevents silent override during development).
    """
    for ext in adapter.file_extensions:
        key = ext.lower()
        if key in ADAPTERS:
            raise ValueError(
                f"Duplicate adapter registration for extension {key!r}: "
                f"existing={ADAPTERS[key].__class__.__name__!r}, "
                f"new={adapter.__class__.__name__!r}"
            )
        ADAPTERS[key] = adapter
        _log.debug("source_adapters: registered %s for %r", adapter.__class__.__name__, key)


# All 6 adapters registered: Python, TypeScript, JavaScript, Go, Java, Swift.
_register(PythonAdapter())
_register(TypescriptAdapter())
_register(JavascriptAdapter())
_register(GoAdapter())
_register(JavaAdapter())
_register(SwiftAdapter())


# ---------------------------------------------------------------------------
# Dispatch helpers
# ---------------------------------------------------------------------------

def get_adapter_for_file(path: Path) -> SourceAdapter | None:
    """Return the registered adapter for *path*'s extension, or None.

    Extension lookup is case-insensitive: ``Path("FOO.PY")`` resolves to the
    same adapter as ``Path("foo.py")``.

    Returns None for extensions with no registered adapter (e.g. ``.ts`` in L1).
    """
    return ADAPTERS.get(path.suffix.lower())


def supported_extensions() -> tuple[str, ...]:
    """Return a sorted tuple of all currently registered file extensions."""
    return tuple(sorted(ADAPTERS.keys()))
