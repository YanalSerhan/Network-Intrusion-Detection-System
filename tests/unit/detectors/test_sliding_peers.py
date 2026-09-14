"""
Tests for the per-key distinct-peer tracker.

Breadth, not volume: the thing this has to get right is that contacting one
peer a thousand times is still one peer, and that a peer still being contacted
does not age out from under the count.
"""

from network_defender.detectors.window_peers import SlidingPeers

BASE = 1_700_000_000.0


def test_distinct_peers_are_counted_once_each() -> None:
    peers = SlidingPeers(60)

    for port in ("80", "443", "8080"):
        peers.record("10.0.0.1", port, BASE)

    assert peers.count("10.0.0.1") == 3


def test_repeating_one_peer_is_still_one_peer() -> None:
    """A client retrying one port is not scanning however often it retries."""
    peers = SlidingPeers(60)

    for offset in range(50):
        peers.record("10.0.0.1", "443", BASE + offset)

    assert peers.count("10.0.0.1") == 1


def test_a_peer_not_seen_for_a_window_stops_counting() -> None:
    peers = SlidingPeers(10)
    peers.record("10.0.0.1", "80", BASE)
    peers.record("10.0.0.1", "443", BASE)

    peers.record("10.0.0.1", "8080", BASE + 60)

    assert peers.count("10.0.0.1") == 1


def test_contact_refreshes_a_peer_rather_than_adding_a_second() -> None:
    """"Distinct peers in the last minute" means the last contact, not the first."""
    peers = SlidingPeers(10)
    peers.record("10.0.0.1", "80", BASE)

    peers.record("10.0.0.1", "80", BASE + 9)
    peers.record("10.0.0.1", "443", BASE + 9)

    assert peers.count("10.0.0.1") == 2


def test_sources_are_counted_separately() -> None:
    peers = SlidingPeers(60)
    peers.record("10.0.0.1", "80", BASE)
    peers.record("10.0.0.2", "80", BASE)
    peers.record("10.0.0.2", "443", BASE)

    assert (peers.count("10.0.0.1"), peers.count("10.0.0.2")) == (1, 2)


def test_an_unknown_key_counts_zero() -> None:
    assert SlidingPeers(60).count("never-seen") == 0


def test_counts_skips_and_forgets_sources_that_went_quiet() -> None:
    peers = SlidingPeers(10)
    peers.record("gone", "80", BASE)
    peers.record("here", "80", BASE + 60)

    assert dict(peers.counts()) == {"here": 1}
    assert "gone" not in peers._peers
