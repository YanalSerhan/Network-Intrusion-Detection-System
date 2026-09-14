"""
Tests for raising a finding once rather than once per evaluation.

A sliding window does not clear, so without this every detector would re-raise
the same finding at every interval. Downstream deduplication would fold those
into one row with an occurrence count in the dozens, and `occurrences` is
supposed to mean "times this was observed".
"""

from network_defender.detectors.edge import EdgeTriggeredMixin


class Reporter(EdgeTriggeredMixin):
    """A bare mixin instance; the detectors add nothing to this behaviour."""

    def __init__(self) -> None:
        self._reported = set()


def test_the_first_crossing_is_reported() -> None:
    assert Reporter().report_once("10.0.0.1", over_threshold=True) is True


def test_a_crossing_that_stays_true_is_not_reported_again() -> None:
    reporter = Reporter()
    reporter.report_once("10.0.0.1", over_threshold=True)

    assert reporter.report_once("10.0.0.1", over_threshold=True) is False


def test_falling_below_the_threshold_re_arms_the_key() -> None:
    """A burst that stops and starts again is two findings, not one."""
    reporter = Reporter()
    reporter.report_once("10.0.0.1", over_threshold=True)

    reporter.report_once("10.0.0.1", over_threshold=False)

    assert reporter.report_once("10.0.0.1", over_threshold=True) is True


def test_a_key_below_the_threshold_is_never_reported() -> None:
    assert Reporter().report_once("10.0.0.1", over_threshold=False) is False


def test_keys_are_tracked_independently() -> None:
    reporter = Reporter()
    reporter.report_once("10.0.0.1", over_threshold=True)

    assert reporter.report_once("10.0.0.2", over_threshold=True) is True


def test_a_key_that_expires_entirely_is_re_armed() -> None:
    """
    Otherwise an attacker gets one free pass per host, forever.

    A host that crosses a threshold and then goes silent never appears in a
    later evaluation at all, so it would never be told it fell below — and its
    next attack an hour later would raise nothing.
    """
    reporter = Reporter()
    reporter.report_once("10.0.0.1", over_threshold=True)

    reporter.forget_absent(live_keys=set())

    assert reporter.report_once("10.0.0.1", over_threshold=True) is True


def test_keys_still_in_the_window_stay_suppressed() -> None:
    reporter = Reporter()
    reporter.report_once("10.0.0.1", over_threshold=True)

    reporter.forget_absent(live_keys={"10.0.0.1"})

    assert reporter.report_once("10.0.0.1", over_threshold=True) is False
