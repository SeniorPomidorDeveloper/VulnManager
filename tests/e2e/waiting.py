import time

import settings


def until(check):
    deadline = time.monotonic() + settings.WAIT_SECONDS
    while time.monotonic() < deadline:
        found = check()
        if found:
            return found
        time.sleep(settings.POLL_SECONDS)
    raise TimeoutError('condition was not met in time')
