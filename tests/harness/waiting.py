import asyncio
import time

POLL_SECONDS = 0.1
WAIT_SECONDS = 20


async def until(check, timeout=WAIT_SECONDS):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        found = check()
        if asyncio.iscoroutine(found):
            found = await found
        if found:
            return found
        await asyncio.sleep(POLL_SECONDS)
    raise TimeoutError('condition was not met in time')
