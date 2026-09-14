"""
Tests for the per-key sliding counter.

This is where "the last sixty seconds" stops being a figure of speech. The
behaviour worth pinning is that old observations stop counting, that a key
with nothing left stops costing memory, and that the bucketing which keeps
state bounded never *under*-counts — a flood detector that rounded down at the
window edge would miss floods.
"""

from network_defender.detectors.window_counts import BUCKET_COUNT, SlidingCounter

BASE = 1_700_000_000.0


def test_observations_inside_the_window_all_count() -> None:
    counter = SlidingCounter(10)

    for offset in range(5):
        counter.record("10.0.0.1", BASE + offset)

    assert counter.total("10.0.0.1") == 5


def test_observations_older_than_the_window_stop_counting() -> None:
    counter = SlidingCounter(10)
    counter.record("10.0.0.1", BASE)
    counter.record("10.0.0.1", BASE + 1)

    counter.record("10.0.0.1", BASE + 60)

    assert counter.total("10.0.0.1") == 1


def test_an_unknown_key_totals_zero() -> None:
    assert SlidingCounter(10).total("never-seen") == 0


def test_keys_are_counted_separately() -> None:
    counter = SlidingCounter(10)
    counter.record("10.0.0.1", BASE)
    counter.record("10.0.0.2", BASE)
    counter.record("10.0.0.2", BASE)

    assert (counter.total("10.0.0.1"), counter.total("10.0.0.2")) == (1, 2)


def test_an_amount_can_be_more_than_one() -> None:
    """Volume detectors count bytes, not arrivals."""
    counter = SlidingCounter(10)

    counter.record("10.0.0.1", BASE, amount=1400)
    counter.record("10.0.0.1", BASE + 1, amount=1400)

    assert counter.total("10.0.0.1") == 2800


def test_totals_skips_keys_whose_observations_have_expired() -> None:
    counter = SlidingCounter(10)
    counter.record("gone", BASE)
    counter.record("here", BASE + 60)

    assert dict(counter.totals()) == {"here": 1}


def test_an_expired_key_stops_costing_memory() -> None:
    """State bounded by one window of traffic is the whole point of expiring."""
    counter = SlidingCounter(10)
    counter.record("gone", BASE)
    counter.record("here", BASE + 60)

    list(counter.totals())

    assert "gone" not in counter._buckets


def test_state_per_key_is_bounded_however_many_packets_arrive() -> None:
    """Ten thousand packets a second must not become ten thousand entries."""
    counter = SlidingCounter(1)

    for index in range(10_000):
        counter.record("10.0.0.1", BASE + index * 0.0001)

    assert len(counter._buckets["10.0.0.1"]) <= BUCKET_COUNT
    assert counter.total("10.0.0.1") == 10_000


def test_bucketing_never_undercounts_at_the_window_edge() -> None:
    """
    An observation may linger up to one bucket past expiry, never leave early.

    Rounding the other way would make a flood detector miss floods, which is
    the failure that matters; counting a few packets too long is noise against
    a threshold that separates a hundred from three hundred.
    """
    counter = SlidingCounter(1)
    for index in range(100):
        counter.record("10.0.0.1", BASE + index * 0.01)

    assert counter.total("10.0.0.1") == 100
