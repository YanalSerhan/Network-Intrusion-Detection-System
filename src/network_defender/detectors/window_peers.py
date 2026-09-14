"""
Counting *distinct* peers inside a sliding window.

Data Setup:  A window length; a last-seen time per (key, peer).
Data Input:  Observations of one key reaching one peer.
Data Output: How many distinct peers a key reached in the last window.

The counterpart to `window_counts`, and the difference is the measurement:
that one asks how *much* a host sent, this one asks how many different things
it touched. A client retrying one port is not scanning however many times it
retries, and deduplicating is the whole detector.

Unlike counts, this is stored exactly rather than bucketed, because the state
is already bounded by the thing being counted: a key that touched forty peers
holds forty entries whatever the traffic rate. Refreshing a peer's last-seen
time on every observation keeps a peer in the window for as long as it is
still being contacted, which is what "distinct peers in the last minute"
should mean.
"""

from collections import defaultdict
from collections.abc import Iterator

from .sliding import WindowClock


class SlidingPeers:
    """Per-key distinct-peer counts over a sliding window of capture time."""

    def __init__(self, window_seconds: float) -> None:
        """
        Initialise the tracker.

        Args:
            window_seconds: How long a peer stays counted after last contact.
        """
        self.clock = WindowClock(window_seconds)
        self._peers: defaultdict[str, dict[str, float]] = defaultdict(dict)

    def record(self, key: str, peer: str, at: float) -> None:
        """
        Record that a key reached a peer.

        Args:
            key:  The host doing the reaching — usually a source address.
            peer: What it reached: a destination port, a destination host.
            at:   Capture time, in epoch seconds.
        """
        self.clock.advance(at)
        self._peers[key][peer] = at

    def live(self, key: str) -> tuple[str, ...]:
        """
        Return the peers a key still holds, expiring the rest.

        Args:
            key: The key to read.

        Returns:
            The unexpired peers. Detectors that alert per peer rather than on
            the count — a connection to a flagged port is a finding on its own
            — need the identities, not the total.
        """
        peers = self._peers.get(key)
        if peers is None:
            return ()
        cutoff = self.clock.cutoff
        for peer in [peer for peer, seen in peers.items() if seen <= cutoff]:
            del peers[peer]
        if not peers:
            del self._peers[key]
            return ()
        return tuple(peers)

    def count(self, key: str) -> int:
        """
        Return how many distinct peers a key reached, expiring the rest.

        Args:
            key: The key to count.

        Returns:
            Distinct unexpired peers.
        """
        return len(self.live(key))

    def entries(self) -> Iterator[tuple[str, tuple[str, ...]]]:
        """
        Yield every key still reaching at least one peer, expiring the rest.

        Returns:
            (key, unexpired peers) pairs.
        """
        for key in list(self._peers):
            peers = self.live(key)
            if peers:
                yield key, peers

    def counts(self) -> Iterator[tuple[str, int]]:
        """
        Yield every key still reaching at least one peer, expiring the rest.

        Returns:
            (key, distinct peer count) pairs.
        """
        for key, peers in self.entries():
            yield key, len(peers)
