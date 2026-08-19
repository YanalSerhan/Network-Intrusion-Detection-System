"""
Fixed request windows for the API gatekeeper.

Data Setup:  Constructed with a request limit and a window duration.
Data Input:  `is_exhausted()` and `record()` around each outbound call.
Data Output: Whether the window has room, and how long until it resets.

Not thread-safe on purpose. A window is only ever touched while the owning
gatekeeper holds its lock, and giving each window its own would leave the
minute and day checks separately atomic but jointly racy — which is the bug
that shape of locking always produces.

A fixed window is simple and permits a burst of up to 2x the limit across a
boundary. That is accepted here because the limits it protects are provider
quotas with their own tolerance, and the alternative (a sliding window) costs
per-request bookkeeping on a path that already sleeps.
"""

import time

#: Seconds in the per-minute window. Named because a bare 60.0 in three places
#: would not obviously be the same 60.
WINDOW_SECONDS = 60.0

#: Seconds in the per-day window, which exists to respect daily provider
#: quotas — AbuseIPDB's free tier is a hard 1000 per day, and exceeding it
#: suspends the key rather than returning an error.
DAY_SECONDS = 86_400.0


class FixedWindow:
    """Counts requests inside a fixed window and reports when it is full."""

    def __init__(self, limit: int, duration_seconds: float) -> None:
        """
        Initialise the window.

        Args:
            limit:            Maximum requests permitted per window.
            duration_seconds: Length of the window.
        """
        self._limit = limit
        self._duration = duration_seconds
        self._window_start = time.monotonic()
        self._count = 0

    @property
    def count(self) -> int:
        """Requests recorded in the current window."""
        return self._count

    @property
    def limit(self) -> int:
        """Requests permitted per window."""
        return self._limit

    def refresh(self) -> None:
        """Reset the counter if the current window has elapsed."""
        now = time.monotonic()
        if now - self._window_start >= self._duration:
            self._window_start = now
            self._count = 0

    def is_exhausted(self) -> bool:
        """Return True when no further request fits in the current window."""
        self.refresh()
        return self._count >= self._limit

    def record(self) -> None:
        """Count one request against the window."""
        self._count += 1

    def seconds_until_reset(self) -> float:
        """Return how long until the current window rolls over."""
        elapsed = time.monotonic() - self._window_start
        return max(0.0, self._duration - elapsed)
