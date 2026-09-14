"""
Regression tests: an aggregation rule reports a burst once, not once a packet.

`hits >= threshold` stays true for every further match inside the window, so
the shipped port-scan rule raised eleven alerts about one twenty-five packet
behaviour. Firing is now edge-triggered, and these tests pin both halves of
that: the single alert, and the re-arm once the matches age out.
"""

from datetime import UTC, datetime, timedelta

from network_defender.rules.engine import RuleEngine
from tests.fixtures.rules import syn as _syn
from tests.fixtures.rules import syn_rule as _rule


def test_a_rule_reports_a_burst_once_not_once_per_packet(tmp_path: str) -> None:
    engine = RuleEngine(str(tmp_path))
    engine.loader.registry.set_rule("r.yaml", _rule(window=60, threshold=5))

    start = datetime.now(UTC)
    fired = [
        bool(engine.evaluate(_syn(when=start + timedelta(seconds=i))))
        for i in range(20)
    ]
    assert sum(fired) == 1
    assert fired.index(True) == 4


def test_a_rule_rearms_once_the_matches_age_out(tmp_path: str) -> None:
    engine = RuleEngine(str(tmp_path))
    engine.loader.registry.set_rule("r.yaml", _rule(window=10, threshold=3))

    start = datetime.now(UTC)
    first = [engine.evaluate(_syn(when=start + timedelta(seconds=i))) for i in range(3)]
    assert [len(r) for r in first] == [0, 0, 1]

    # A gap longer than the window empties the series, so the next burst is a
    # second episode rather than a continuation of the first.
    later = start + timedelta(seconds=100)
    second = [engine.evaluate(_syn(when=later + timedelta(seconds=i))) for i in range(3)]
    assert [len(r) for r in second] == [0, 0, 1]


def test_each_group_reports_its_own_episode(tmp_path: str) -> None:
    engine = RuleEngine(str(tmp_path))
    engine.loader.registry.set_rule("r.yaml", _rule(window=60, threshold=2))

    start = datetime.now(UTC)
    fired = [
        bool(engine.evaluate(_syn(src_ip=f"10.0.0.{octet}", when=start + timedelta(seconds=i))))
        for i, octet in enumerate([1, 2, 1, 2, 1, 2])
    ]
    assert fired == [False, False, True, True, False, False]


def test_shipped_rules_report_a_scan_once(tmp_path: str) -> None:
    """One port scan is one alert, however many packets it takes."""
    engine = RuleEngine(str(tmp_path))
    engine.loader.registry.set_rule("r.yaml", _rule(window=60, threshold=15))

    start = datetime.now(UTC)
    alerts = sum(
        len(engine.evaluate(_syn(when=start + timedelta(seconds=i * 0.1))))
        for i in range(25)
    )
    assert alerts == 1
