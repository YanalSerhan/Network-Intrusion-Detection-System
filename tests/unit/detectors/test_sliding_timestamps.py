"""
Tests for the per-key timestamp window.

The beaconing detector reads gaps, so two things matter beyond expiry: that
times come back in order however they arrived, and that a conversation which
has gone quiet stops being remembered.
"""

from network_defender.detectors.window_timestamps import SlidingTimestamps

BASE = 1_700_000_000.0


def test_times_inside_the_window_are_returned() -> None:
    times = SlidingTimestamps(60)
    for offset in (0, 10, 20):
        times.record("a|b", BASE + offset)

    assert times.times("a|b") == (BASE, BASE + 10, BASE + 20)


def test_times_older_than_the_window_are_dropped() -> None:
    times = SlidingTimestamps(30)
    times.record("a|b", BASE)
    times.record("a|b", BASE + 10)

    times.record("a|b", BASE + 100)

    assert times.times("a|b") == (BASE + 100,)


def test_out_of_order_arrivals_come_back_sorted() -> None:
    """A negative interval inflates the deviation and masks a real beacon."""
    times = SlidingTimestamps(60)
    times.record("a|b", BASE + 20)
    times.record("a|b", BASE + 5)

    assert times.times("a|b") == (BASE + 5, BASE + 20)


def test_an_unknown_key_has_no_times() -> None:
    assert SlidingTimestamps(60).times("never-seen") == ()


def test_entries_skips_and_forgets_conversations_that_went_quiet() -> None:
    times = SlidingTimestamps(30)
    times.record("gone", BASE)
    times.record("here", BASE + 100)

    assert dict(times.entries()) == {"here": (BASE + 100,)}
    assert "gone" not in times._times
