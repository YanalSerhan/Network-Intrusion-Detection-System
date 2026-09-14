"""
What a rule's window means: accumulation, expiry, and distinct counting.

The series is the unit that owns window semantics. Testing it here rather than
through the engine keeps the cases about time rather than about YAML, and
leaves the engine suite free to be about wiring.
"""

from network_defender.rules.series import Series


def test_matches_accumulate_inside_the_window() -> None:
    series = Series()
    for i in range(5):
        series.record(1000.0 + i, "", window_seconds=10)
    assert series.count(distinct=False) == 5


def test_matches_outside_the_window_are_dropped() -> None:
    series = Series()
    series.record(1000.0, "", window_seconds=10)
    series.record(1005.0, "", window_seconds=10)
    series.record(1020.0, "", window_seconds=10)
    assert series.count(distinct=False) == 1


def test_distinct_counting_ignores_repeats_of_the_same_value() -> None:
    """Fifteen SYNs to one port is a client retrying, not a port scan."""
    series = Series()
    for i in range(15):
        series.record(1000.0 + i * 0.1, "443", window_seconds=60)
    assert series.count(distinct=False) == 15
    assert series.count(distinct=True) == 1
    assert series.should_fire(15, distinct=True) is False


def test_distinct_counting_fires_on_breadth() -> None:
    series = Series()
    fired = []
    for port in range(15):
        series.record(1000.0 + port * 0.1, str(port), window_seconds=60)
        fired.append(series.should_fire(15, distinct=True))
    assert fired.count(True) == 1
    assert fired[-1] is True


def test_a_distinct_series_rearms_when_its_values_age_out() -> None:
    series = Series()
    for port in range(15):
        series.record(1000.0 + port, str(port), window_seconds=10)
        series.should_fire(15, distinct=True)
    assert series.reported is False, "only five ports remain inside a ten-second window"
