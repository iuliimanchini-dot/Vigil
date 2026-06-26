"""Oracle clean control: idiomatic code that MUST NOT trigger any finding.

Used to measure the auditor's false-positive rate. Every construct here is the
recommended-safe counterpart of a planted defect in the sibling sample files:
parametrised queries, context-managed resources, specific-and-reraised
exceptions, timezone-aware datetimes, path joining, and named constants in
place of bare numeric literals. Not named ``test_*`` so the per-file content
checks still evaluate it (and should stay silent).
"""
from __future__ import annotations

import os
from datetime import datetime, timezone

import requests

SECONDS_PER_DAY = 86400
REQUEST_TIMEOUT_SECONDS = 30


def get_user_by_id(cur, uid):
    """Parametrised query -- no string interpolation reaches .execute()."""
    cur.execute("SELECT * FROM users WHERE id = ?", (uid,))
    return cur.fetchone()


def read_config_file(path):
    """Context manager guarantees the handle is closed."""
    with open(path, encoding="utf-8") as handle:
        return handle.read()


def read_required_file(path):
    """Specific exception type, re-raised after handling -- not swallowed."""
    try:
        with open(path, encoding="utf-8") as handle:
            return handle.read()
    except OSError:
        raise


def current_timestamp():
    """Timezone-aware datetime."""
    return datetime.now(tz=timezone.utc)


def build_log_path(base_dir, name):
    """Path joining via os.path.join instead of string concatenation."""
    return os.path.join(base_dir, name + ".log")


def is_expired(elapsed_seconds):
    """Named constant instead of a bare numeric literal."""
    return elapsed_seconds > SECONDS_PER_DAY


def append_item(item, bucket=None):
    """Default of None, list created inside the function -- no shared default."""
    if bucket is None:
        bucket = []
    bucket.append(item)
    return bucket


def fetch_status(url):
    """Response status is checked before the body is used."""
    response = requests.get(url, timeout=REQUEST_TIMEOUT_SECONDS)
    response.raise_for_status()
    return response.json()
