"""Runtime oracle: async entrypoint via asyncio.run in a __main__ guard.

Pins _entry_calls_in_block async detection (asyncio.run -> async_entrypoint tag)
and the async entry_function cross-ref (async def main).
"""
from __future__ import annotations

import asyncio


async def main() -> None:
    await asyncio.sleep(0)


if __name__ == "__main__":
    asyncio.run(main())
