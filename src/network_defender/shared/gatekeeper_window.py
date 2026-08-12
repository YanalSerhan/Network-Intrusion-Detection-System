"""
Per-minute request window for the API gatekeeper.

Data Setup:  Constructed with the number of requests allowed per minute.
Data Input:  Calls to `wait_for_slot()` and `record()` around each API call.
Data Output: Blocks until the window has room; reports the current count.

Split out of ApiGatekeeper because "how many calls has this service made in the
last minute" is a distinct piece of state from queuing, retries and logging, and
it is the part most likely to be swapped later (a fixed window is simple but
allows a burst of 2x the limit across a boundary; a sliding window would not).
"""

import time

#: Seconds in the fixed window. Named because a bare 60.0 in three places would
#: not obviously be the same 60.
WINDOW_SECONDS = 60.0

#: How long to sleep while a full window drains. Short enough that a caller is
#: not left waiting past the window's end, long enough not to spin a core.
_POLL_SECONDS = 0.1


class MinuteWindow:
    """Counts requests inside a fixed one-minute window and throttles on it."""

    def __init__(self, requests_per_minute: int) -> None:
        """
        Initialise the window.

        Args:
            requests_per_minute: Maximum calls permitted per minute.
        """
        self._limit = requests_per_minute
        self._window_start = time.monotonic()
        self._count = 0

    @property
    def count(self) -> int:
        """Requests recorded in the current window."""
        return self._count

    def refresh(self) -> None:
        """Reset the counter if the current window has elapsed."""
        if time.monotonic() - self._window_start >= WINDOW_SECONDS:
            self._window_start = time.monotonic()
            self._count = 0

    def record(self) -> None:
        """Count one completed request against the window."""
        self._count += 1

    def wait_for_slot(self) -> None:
        """Block until the window has room for another request."""
        self.refresh()
        while self._count >= self._limit:
            time.sleep(_POLL_SECONDS)
            self.refresh()
