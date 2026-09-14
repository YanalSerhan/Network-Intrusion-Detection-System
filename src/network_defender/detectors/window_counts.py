"""
Counting observations inside a sliding window.

Data Setup:  A window length; time-ordered buckets per key.
Data Input:  Observations, each with a key, an amount and a capture time.
Data Output: The total per key over the last `window_seconds` of capture time.

Counts are bucketed rather than stored per observation. A flood detector sees
ten thousand packets a second; keeping a timestamp each would cost six hundred
thousand entries per destination at a sixty-second window, which is the kind
of state exhaustion the threat model calls out. Bucketing bounds it at
`BUCKET_COUNT` entries per key whatever the window and the traffic rate.

The cost is resolution: an observation leaves the window up to one bucket
late, so a count can overstate by at most the traffic in 1/64th of the window.
For a threshold that exists to separate "a hundred" from "three hundred", that
is noise; a detector needing exact expiry would want per-observation
timestamps and the memory to match.
"""

from collections import defaultdict, deque
from collections.abc import Iterator

from network_defender.detectors.sliding import WindowClock

#: Buckets per window. Memory per key is fixed at this regardless of window
#: length or packet rate; resolution is one bucket.
BUCKET_COUNT = 64


class SlidingCounter:
    """Per-key totals over a sliding window of capture time."""

    def __init__(self, window_seconds: float) -> None:
        """
        Initialise the counter.

        Args:
            window_seconds: How long an observation counts for.
        """
        self.clock = WindowClock(window_seconds)
        self._bucket = self.clock.window_seconds / BUCKET_COUNT
        self._buckets: defaultdict[str, deque[list[float]]] = defaultdict(deque)

    def record(self, key: str, at: float, amount: int = 1) -> None:
        """
        Add to a key's total.

        Args:
            key:    What the total is kept against — usually an address.
            at:     The observation's capture time, in epoch seconds.
            amount: How much to add. Bytes, for volume detectors.
        """
        self.clock.advance(at)
        buckets = self._buckets[key]
        start = at - (at % self._bucket)
        if buckets and buckets[-1][0] == start:
            buckets[-1][1] += amount
        else:
            buckets.append([start, float(amount)])

    def total(self, key: str) -> int:
        """
        Return a key's total over the window, dropping what has expired.

        Args:
            key: The key to total.

        Returns:
            The sum of unexpired observations.
        """
        buckets = self._buckets.get(key)
        if buckets is None:
            return 0
        cutoff = self.clock.cutoff
        while buckets and buckets[0][0] + self._bucket <= cutoff:
            buckets.popleft()
        if not buckets:
            del self._buckets[key]
            return 0
        return int(sum(count for _, count in buckets))

    def totals(self) -> Iterator[tuple[str, int]]:
        """
        Yield every key with a non-zero total, expiring the rest.

        Returns:
            (key, total) pairs. Keys whose observations have all expired are
            dropped from the counter as they are visited, so an address that
            goes quiet stops costing memory.
        """
        for key in list(self._buckets):
            total = self.total(key)
            if total:
                yield key, total
