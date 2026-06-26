"""Oracle sample: ASYNC / API problems.

Each offending line carries a `# EXPECT: <tag>` marker. Not named ``test_*`` so
per-file content checks run. Never imported or executed.

Notes on the auditor's missing-await rule (AST-based):
  * Only un-awaited calls to a same-module ``async def`` *from inside another
    async function* are flagged. Module-level and plain-sync-enclosing calls
    are conservatively skipped.
  * ``consume()`` awaits ``warm_up()`` so it is NOT a "pointless async"
    function; the single un-awaited ``load_rows()`` call is the planted defect.
"""
from __future__ import annotations

import asyncio

import requests


async def warm_up():
    await asyncio.sleep(0)


async def load_rows():
    await asyncio.sleep(0)
    return [1, 2, 3]


async def consume():
    await warm_up()
    rows = load_rows()  # EXPECT: missing_await
    return rows


def fetch_status(url):
    resp = requests.get(url)  # EXPECT: unchecked_response
    return resp.json()
