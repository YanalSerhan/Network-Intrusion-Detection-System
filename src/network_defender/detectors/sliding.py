"""
The clock every sliding window shares.

Data Setup:  A window length in seconds.
Data Input:  Capture timestamps, as packets arrive.
Data Output: The current time and the cutoff below which observations expire.

Time comes from the packets, not from the wall clock. That is what makes a
replay deterministic — the same capture produces the same alerts however fast
the file is read — and on live traffic the two are the same thing anyway.

The clock only moves forward. Captures interleave sources and a reordered
arrival must not rewind the window, which would resurrect observations that
had already expired.

A long silence leaves the clock parked, so state stops expiring until the next
packet. That is deliberate: nothing is being detected during silence, the
state is bounded by one window's worth of traffic, and a clock that advanced
on its own would make replay depend on how long the test took to run.
"""


class WindowClock:
    """A monotonic capture clock and the expiry cutoff it implies."""

    def __init__(self, window_seconds: float) -> None:
        """
        Initialise the clock.

        Args:
            window_seconds: How long an observation stays in the window.

        Raises:
            ValueError: If the window is not positive. A zero-length window
                expires every observation at the instant it is recorded, so a
                detector configured that way would silently never fire.
        """
        if window_seconds <= 0:
            raise ValueError(f"Window must be positive, got {window_seconds}.")
        self._window = float(window_seconds)
        self._now = 0.0

    @property
    def window_seconds(self) -> float:
        """How long an observation stays in the window."""
        return self._window

    @property
    def now(self) -> float:
        """The latest capture time seen, in epoch seconds."""
        return self._now

    @property
    def cutoff(self) -> float:
        """Observations at or before this time have expired."""
        return self._now - self._window

    def advance(self, at: float) -> None:
        """
        Move the clock to a packet's capture time, if it is newer.

        Args:
            at: The packet's capture time, in epoch seconds.
        """
        self._now = max(self._now, at)
