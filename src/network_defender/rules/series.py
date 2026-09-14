"""
One rule/group series: the matches inside its window, and whether it has fired.

Data Setup:  Constructed by WindowedCounter.
Data Input:  Match timestamps.
Data Output: The count inside the window, and a once-per-episode decision.

The two pieces of state are held together deliberately. The count alone cannot
answer "should this rule alert?": `hits >= threshold` stays true for every
further match inside the window, so the shipped port-scan rule raised eleven
alerts about one behaviour — one for every packet past the fifteenth. Whether
the series has already reported is the other half of that answer, and keeping
it here means evicting a series frees both halves at once rather than leaving
a flag behind for a group nobody is counting any more.
"""

from collections import deque
from dataclasses import dataclass, field


@dataclass
class Series:
    """Matches inside one rule's window for one group, and its firing state."""

    hits: deque[float] = field(default_factory=deque)
    reported: bool = False

    def record(self, timestamp: float, window_seconds: int) -> int:
        """
        Record a match and drop the ones that have fallen out of the window.

        Args:
            timestamp:      Packet time as a POSIX timestamp.
            window_seconds: Rule window length in seconds.

        Returns:
            Matches inside the window, including this one.
        """
        self.hits.append(timestamp)
        cutoff = timestamp - window_seconds
        while self.hits and self.hits[0] < cutoff:
            self.hits.popleft()
        return len(self.hits)

    def should_fire(self, threshold: int) -> bool:
        """
        Return True only on the match that takes this series over the line.

        Edge-triggered, for the same reason the detectors are: an operator
        wants to know that a port scan happened, not to be told again by every
        subsequent packet of it. The series re-arms when enough matches age
        out of the window for the count to fall back under the threshold,
        which is the point at which the behaviour has actually stopped.

        Args:
            threshold: Matches required inside the window.

        Returns:
            True for the first match at or above the threshold, and again only
            after the count has dropped below it.
        """
        if len(self.hits) < threshold:
            self.reported = False
            return False
        if self.reported:
            return False
        self.reported = True
        return True
