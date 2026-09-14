"""
Tests for the capture clock every sliding window shares.

Time comes from the packets rather than the wall clock, which is what makes a
replay deterministic. The two things that matter here are that it never goes
backwards — a reordered arrival must not resurrect expired observations — and
that a zero-length window is refused rather than silently disabling a detector.
"""

import pytest

from network_defender.detectors.sliding import WindowClock


def test_the_clock_starts_before_any_packet() -> None:
    assert WindowClock(60).now == 0.0


def test_advancing_moves_the_clock_to_the_capture_time() -> None:
    clock = WindowClock(60)

    clock.advance(1_700_000_000.0)

    assert clock.now == 1_700_000_000.0


def test_an_out_of_order_arrival_does_not_rewind_the_clock() -> None:
    """Captures interleave sources; a late packet must not revive expired state."""
    clock = WindowClock(60)
    clock.advance(1_700_000_100.0)

    clock.advance(1_700_000_050.0)

    assert clock.now == 1_700_000_100.0


def test_the_cutoff_trails_the_clock_by_one_window() -> None:
    clock = WindowClock(60)
    clock.advance(1_700_000_100.0)

    assert clock.cutoff == 1_700_000_040.0


@pytest.mark.parametrize("window", [0, -1, -0.5])
def test_a_non_positive_window_is_refused(window: float) -> None:
    """It would expire every observation as it arrived, so nothing would fire."""
    with pytest.raises(ValueError, match="must be positive"):
        WindowClock(window)
