"""Custom exceptions for the map builder subsystem.

Error taxonomy per plan sec.8. All errors are fail-loud -- no silent failures.
"""
from __future__ import annotations
import logging
_log = logging.getLogger(__name__)

__all__ = [
    "MapBuilderError",
    "MapSchemaError",
    "MapStorageError",
    "MapConcurrencyError",
    "MapIntegrityError",
    "RuntimeTracerError",
    "RuntimeTracerTimeoutError",
    "MapSecurityError",
    "MapBuildConflictBudgetExceeded",
]


class MapBuilderError(Exception):
    """Base exception for all map builder errors."""


class MapSchemaError(MapBuilderError):
    """Schema version mismatch or unknown schema."""


class MapStorageError(MapBuilderError):
    """I/O or atomic write failure."""


class MapConcurrencyError(MapStorageError):
    """Filelock timeout -- concurrent writer held lock too long."""


class MapIntegrityError(MapBuilderError):
    """Map content invariant broken (missing required field, corrupt data)."""


class RuntimeTracerError(MapBuilderError):
    """Subprocess tracer failure."""


class RuntimeTracerTimeoutError(RuntimeTracerError):
    """Subprocess tracer exceeded time budget."""


class MapSecurityError(MapBuilderError):
    """Path traversal attempt or other security violation."""


class MapBuildConflictBudgetExceeded(MapBuilderError):
    """Conflict count exceeded the allowed budget (default 500)."""
