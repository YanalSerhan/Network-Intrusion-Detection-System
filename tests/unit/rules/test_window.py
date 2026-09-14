"""
Regression tests: time-window aggregation in the rule engine.

Before this fix `Rule.window` was documented and configured but ignored, so a
single SYN packet raised a high-severity "SYN Flood".
"""

from datetime import UTC, datetime, timedelta

from network_defender.rules.engine import RuleEngine
from network_defender.rules.window import WindowedCounter
from tests.fixtures.rules import syn as _syn
from tests.fixtures.rules import syn_rule as _rule

# --------------------------------------------------------------------------
# WindowedCounter — the bound on how many series are held, and nothing else.
# What a window means belongs to Series; see test_series.py.
# --------------------------------------------------------------------------


def test_counter_state_is_bounded_and_resettable() -> None:
    counter = WindowedCounter(max_series=4)
    rule = _rule(window=10, threshold=99)
    for i in range(50):
        counter.fires(rule, f"10.0.0.{i}", 1000.0, value="")
    assert counter.tracked_series == 4

    counter.reset()
    assert counter.tracked_series == 0


def test_counter_separates_rules_and_groups() -> None:
    counter = WindowedCounter()
    one, two = _rule(threshold=99), _rule(window=10, threshold=99)
    two = two.model_copy(update={"name": "Other"})
    counter.fires(one, "10.0.0.5", 1000.0, value="")
    counter.fires(two, "10.0.0.5", 1000.0, value="")
    counter.fires(one, "10.0.0.6", 1000.0, value="")
    assert counter.tracked_series == 3


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
