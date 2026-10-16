import time

import settings


def until(check, timeout=None):
    deadline = time.monotonic() + (timeout or settings.WAIT_SECONDS)
    while time.monotonic() < deadline:
        found = check()
        if found:
            return found
        time.sleep(settings.POLL_SECONDS)
    raise TimeoutError('condition was not met in time')
