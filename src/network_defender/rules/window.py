"""
Time-window aggregation for rules.

Data Setup:  Bound on tracked series injected via __init__.
Data Input:  A rule, a group key, a timestamp and the value being counted, for
             each packet whose conditions all matched.
Data Output: Whether the rule should fire for this packet.

Why this exists
---------------
`Rule.window` is documented in RULE_SCHEMA.md and set on the shipped rules, but
the engine matched every rule per packet and ignored it. A single SYN packet
therefore raised a high-severity "SYN Flood". Aggregation rules now fire only
once `threshold` matches are seen within `window` seconds — and only once per
episode, which is `Series.should_fire`'s half of the job.

This class owns the bound on how many series are held at once. `Series` owns
what a window means. Keeping them apart is what lets the eviction policy
change without touching the counting, and vice versa.
"""

from collections import OrderedDict

from network_defender.rules.models import Rule
from network_defender.rules.series import Series

#: Bound on distinct (rule, group) series tracked at once, to cap memory.
MAX_TRACKED_SERIES = 10_000

SeriesKey = tuple[str, str]


class WindowedCounter:
    """
    Tracks rule matches per group inside a sliding time window.

    Usage:
        counter = WindowedCounter()
        if counter.fires(rule, "10.0.0.5", packet_time, value="443"):
            ...
    """

    def __init__(self, max_series: int = MAX_TRACKED_SERIES) -> None:
        """
        Initialise the counter.

        Args:
            max_series: Maximum distinct (rule, group) series tracked (LRU-evicted).
        """
        self._max_series = max_series
        self._series: OrderedDict[SeriesKey, Series] = OrderedDict()

    @property
    def tracked_series(self) -> int:
        """Number of (rule, group) series currently held in state."""
        return len(self._series)

    def fires(self, rule: Rule, group_key: str, timestamp: float, value: str) -> bool:
        """
        Record a match and return True only on the one that starts an episode.

        Args:
            rule:      The rule whose window, threshold and counting mode apply.
            group_key: Value the rule aggregates on (e.g. a source IP).
            timestamp: Packet time as a POSIX timestamp.
            value:     What this match contributes when the rule counts
                       distinct values; ignored otherwise.

        Returns:
            True for the match that takes this series to the threshold, and
            not again until the count has fallen back below it.
        """
        series = self._touch((rule.name, group_key))
        series.record(timestamp, value, rule.window)
        return series.should_fire(rule.threshold, distinct=rule.counts_distinct)

    def reset(self) -> None:
        """Discard all aggregation state."""
        self._series.clear()

    def _touch(self, key: SeriesKey) -> Series:
        """Return the series for this key, creating it and evicting if needed."""
        series = self._series.get(key)
        if series is None:
            series = Series()
            self._series[key] = series
            self._evict_overflow()
        else:
            self._series.move_to_end(key)
        return series

    def _evict_overflow(self) -> None:
        """Drop the least-recently-used series once the bound is exceeded."""
        while len(self._series) > self._max_series:
            self._series.popitem(last=False)
