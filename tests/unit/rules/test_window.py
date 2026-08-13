"""
Regression tests: time-window aggregation in the rule engine.

Before this fix `Rule.window` was documented and configured but ignored, so a
single SYN packet raised a high-severity "SYN Flood".
"""

from datetime import UTC, datetime, timedelta

from network_defender.constants import Protocol, Severity
from network_defender.parser.models import ParsedPacket, TcpFlags
from network_defender.rules.engine import RuleEngine
from network_defender.rules.models import Rule, RuleCondition
from network_defender.rules.window import WindowedCounter


def _syn(src_ip: str = "10.0.0.5", when: datetime | None = None) -> ParsedPacket:
    return ParsedPacket(
        timestamp=when or datetime.now(UTC),
        src_ip=src_ip,
        dst_ip="10.0.0.9",
        src_port=4444,
        dst_port=80,
        protocol=Protocol.TCP,
        length=60,
        tcp_flags=TcpFlags(syn=True),
        raw_summary="TCP SYN",
    )


def _rule(window: int = 10, threshold: int = 5, group_by: str = "src_ip") -> Rule:
    return Rule(
        name="SYN Flood",
        severity=Severity.HIGH,
        window=window,
        threshold=threshold,
        group_by=group_by,
        conditions=[RuleCondition(field="tcp_flags.syn", operator="equals", value=True)],
    )


# --------------------------------------------------------------------------
# WindowedCounter
# --------------------------------------------------------------------------


def test_counter_accumulates_within_the_window() -> None:
    counter = WindowedCounter()
    base = 1000.0
    counts = [counter.record("R", "10.0.0.5", base + i, window_seconds=10) for i in range(5)]
    assert counts == [1, 2, 3, 4, 5]


def test_counter_drops_events_outside_the_window() -> None:
    counter = WindowedCounter()
    counter.record("R", "10.0.0.5", 1000.0, window_seconds=10)
    counter.record("R", "10.0.0.5", 1005.0, window_seconds=10)
    assert counter.record("R", "10.0.0.5", 1020.0, window_seconds=10) == 1


def test_counter_separates_rules_and_groups() -> None:
    counter = WindowedCounter()
    counter.record("R1", "10.0.0.5", 1000.0, window_seconds=10)
    assert counter.record("R2", "10.0.0.5", 1000.0, window_seconds=10) == 1
    assert counter.record("R1", "10.0.0.6", 1000.0, window_seconds=10) == 1
    assert counter.tracked_series == 3


def test_counter_state_is_bounded_and_resettable() -> None:
    counter = WindowedCounter(max_series=4)
    for i in range(50):
        counter.record("R", f"10.0.0.{i}", 1000.0, window_seconds=10)
    assert counter.tracked_series == 4

    counter.reset()
    assert counter.tracked_series == 0


# --------------------------------------------------------------------------
# Engine integration
# --------------------------------------------------------------------------


def test_aggregation_rule_does_not_fire_on_a_single_packet(tmp_path: str) -> None:
    engine = RuleEngine(str(tmp_path))
    engine.loader.registry.set_rule("r.yaml", _rule(threshold=5))
    assert engine.evaluate(_syn()) == []


def test_aggregation_rule_fires_once_the_threshold_is_reached(tmp_path: str) -> None:
    engine = RuleEngine(str(tmp_path))
    engine.loader.registry.set_rule("r.yaml", _rule(threshold=5))

    results = [engine.evaluate(_syn()) for _ in range(5)]
    assert [len(r) for r in results] == [0, 0, 0, 0, 1]


def test_matches_outside_the_window_do_not_accumulate(tmp_path: str) -> None:
    engine = RuleEngine(str(tmp_path))
    engine.loader.registry.set_rule("r.yaml", _rule(window=10, threshold=3))

    start = datetime.now(UTC)
    for offset in (0, 60, 120):
        assert engine.evaluate(_syn(when=start + timedelta(seconds=offset))) == []


def test_threshold_is_tracked_per_group(tmp_path: str) -> None:
    engine = RuleEngine(str(tmp_path))
    engine.loader.registry.set_rule("r.yaml", _rule(threshold=3))

    for octet in range(3):
        assert engine.evaluate(_syn(src_ip=f"10.0.0.{octet}")) == []


def test_single_packet_rules_still_fire_immediately(tmp_path: str) -> None:
    engine = RuleEngine(str(tmp_path))
    engine.loader.registry.set_rule("r.yaml", _rule(window=0, threshold=1))
    assert len(engine.evaluate(_syn())) == 1


def test_rule_with_unavailable_group_field_does_not_fire(tmp_path: str) -> None:
    engine = RuleEngine(str(tmp_path))
    engine.loader.registry.set_rule("r.yaml", _rule(threshold=2, group_by="tls"))
    assert engine.evaluate(_syn()) == []


def test_shipped_rules_are_aggregation_rules() -> None:
    """The bundled rules must not fire on a single packet."""
    engine = RuleEngine("rules")
    engine.start()
    try:
        rules = engine.loader.registry.get_all_enabled_rules()
        assert rules, "no rules loaded from rules/"
        assert all(rule.is_aggregated for rule in rules)
        assert engine.evaluate(_syn()) == []
    finally:
        engine.stop()
