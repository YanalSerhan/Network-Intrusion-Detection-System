"""
Time-window aggregation for rules.

Data Setup:  Bound on tracked series injected via __init__.
Data Input:  (rule name, group key, timestamp) for each packet whose conditions
             all matched.
Data Output: The number of matches for that series inside the rule's window.

Why this exists
---------------
`Rule.window` is documented in RULE_SCHEMA.md and set on the shipped rules, but
the engine matched every rule per packet and ignored it. A single SYN packet
therefore raised a high-severity "SYN Flood". Aggregation rules now only fire
once `threshold` matches are seen within `window` seconds.
"""

from collections import OrderedDict, deque

#: Bound on distinct (rule, group) series tracked at once, to cap memory.
MAX_TRACKED_SERIES = 10_000

SeriesKey = tuple[str, str]


class WindowedCounter:
    """
    Counts rule matches per group inside a sliding time window.

    Usage:
        counter = WindowedCounter()
        hits = counter.record("SYN Flood", "10.0.0.5", ts, window_seconds=10)
    """

    def __init__(self, max_series: int = MAX_TRACKED_SERIES) -> None:
        """
        Initialise the counter.

        Args:
            max_series: Maximum distinct (rule, group) series tracked (LRU-evicted).
        """
        self._max_series = max_series
        self._series: OrderedDict[SeriesKey, deque[float]] = OrderedDict()

    @property
    def tracked_series(self) -> int:
        """Number of (rule, group) series currently held in state."""
        return len(self._series)

    def record(
        self, rule_name: str, group_key: str, timestamp: float, window_seconds: int
    ) -> int:
        """
        Record a match and return how many fall inside the window.

        Args:
            rule_name:      Name of the matching rule.
            group_key:      Value the rule aggregates on (e.g. a source IP).
            timestamp:      Packet time as a POSIX timestamp.
            window_seconds: Rule window length in seconds.

        Returns:
            Count of matches for this series within the window, including this one.
        """
        key = (rule_name, group_key)
        series = self._series.get(key)
        if series is None:
            series = deque()
            self._series[key] = series
            self._evict_overflow()
        else:
            self._series.move_to_end(key)

        series.append(timestamp)
        cutoff = timestamp - window_seconds
        while series and series[0] < cutoff:
            series.popleft()
        return len(series)

    def reset(self) -> None:
        """Discard all aggregation state."""
        self._series.clear()

    def _evict_overflow(self) -> None:
        """Drop the least-recently-used series once the bound is exceeded."""
        while len(self._series) > self._max_series:
            self._series.popitem(last=False)
