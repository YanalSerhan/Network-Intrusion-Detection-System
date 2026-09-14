"""
One rule/group series: the matches inside its window, and whether it has fired.

Data Setup:  Constructed by WindowedCounter.
Data Input:  Match timestamps, each with the value the rule counts.
Data Output: The count inside the window, and a once-per-episode decision.

Two pieces of state, held together deliberately. The count alone cannot answer
"should this rule alert?": `hits >= threshold` stays true for every further
match inside the window, so the shipped port-scan rule raised eleven alerts
about one behaviour — one per packet past the fifteenth. Whether the series
has already reported is the other half of that answer, and keeping it here
means evicting a series frees both halves rather than leaving a flag behind
for a group nobody is counting any more.

Each match carries a value so a rule can count *distinct* ones. A port scan is
breadth, not volume: fifteen SYNs to one port is a client retrying, and the
same fifteen across fifteen ports is a scan. Without this the two are the
same number.
"""

from collections import deque
from dataclasses import dataclass, field


@dataclass
class Series:
    """Matches inside one rule's window for one group, and its firing state."""

    hits: deque[tuple[float, str]] = field(default_factory=deque)
    reported: bool = False

    def record(self, timestamp: float, value: str, window_seconds: int) -> None:
        """
        Record a match and drop the ones that have fallen out of the window.

        Args:
            timestamp:      Packet time as a POSIX timestamp.
            value:          What this match contributes, for distinct counting.
                            Empty when the rule counts matches rather than values.
            window_seconds: Rule window length in seconds.
        """
        self.hits.append((timestamp, value))
        cutoff = timestamp - window_seconds
        while self.hits and self.hits[0][0] < cutoff:
            self.hits.popleft()

    def count(self, *, distinct: bool) -> int:
        """
        Return what the rule's threshold is compared against.

        Args:
            distinct: Count distinct recorded values rather than matches.

        Returns:
            Matches inside the window, or distinct values among them.
        """
        if distinct:
            return len({value for _, value in self.hits})
        return len(self.hits)

    def should_fire(self, threshold: int, *, distinct: bool = False) -> bool:
        """
        Return True only on the match that takes this series over the line.

        Edge-triggered, for the same reason the detectors are: an operator
        wants to know that a port scan happened, not to be told again by every
        subsequent packet of it. The series re-arms when enough matches age
        out of the window for the count to fall back under the threshold,
        which is the point at which the behaviour has actually stopped.

        Args:
            threshold: Matches (or distinct values) required inside the window.
            distinct:  Count distinct recorded values rather than matches.

        Returns:
            True for the first match at or above the threshold, and again only
            after the count has dropped below it.
        """
        if self.count(distinct=distinct) < threshold:
            self.reported = False
            return False
        if self.reported:
            return False
        self.reported = True
        return True
