"""
Keeping the arrival times inside a sliding window.

Data Setup:  A window length; a deque of capture times per key.
Data Input:  Observations, each with a key and a capture time.
Data Output: The times themselves, oldest first.

The third shape a detector's state takes. `window_counts` keeps how many and
`window_peers` keeps which ones; this keeps *when*, because one detector asks
a question neither of those can answer — how regular were the gaps.

Times are stored individually rather than bucketed, and here that is
affordable: the detectors that need them count connections rather than
packets, so a key holds tens of entries over an hour rather than hundreds of
thousands over a minute.
"""

from collections import defaultdict, deque
from collections.abc import Iterator

from .sliding import WindowClock


class SlidingTimestamps:
    """Per-key capture times over a sliding window."""

    def __init__(self, window_seconds: float) -> None:
        """
        Initialise the tracker.

        Args:
            window_seconds: How long an observation is remembered.
        """
        self.clock = WindowClock(window_seconds)
        self._times: defaultdict[str, deque[float]] = defaultdict(deque)

    def record(self, key: str, at: float) -> None:
        """
        Record an observation.

        Args:
            key: What the times are kept against.
            at:  Capture time, in epoch seconds.
        """
        self.clock.advance(at)
        self._times[key].append(at)

    def times(self, key: str) -> tuple[float, ...]:
        """
        Return a key's unexpired times, oldest first.

        Out-of-order arrivals are sorted here rather than by the caller: a
        negative interval inflates the standard deviation and masks exactly
        the regular traffic the beaconing detector exists to find.

        Args:
            key: The key to read.

        Returns:
            Capture times in ascending order.
        """
        times = self._times.get(key)
        if times is None:
            return ()
        cutoff = self.clock.cutoff
        while times and times[0] <= cutoff:
            times.popleft()
        if not times:
            del self._times[key]
            return ()
        return tuple(sorted(times))

    def entries(self) -> Iterator[tuple[str, tuple[float, ...]]]:
        """
        Yield every key that still holds a time, expiring the rest.

        Returns:
            (key, ascending capture times) pairs.
        """
        for key in list(self._times):
            times = self.times(key)
            if times:
                yield key, times
