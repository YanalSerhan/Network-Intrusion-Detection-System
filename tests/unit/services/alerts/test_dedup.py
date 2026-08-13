"""Unit tests for alert deduplication and correlation."""

from datetime import UTC, datetime, timedelta

from network_defender.constants import Severity
from network_defender.services.alerts.dedup import AlertDeduplicator
from tests.fixtures.builders import make_alert


def test_first_alert_passes_through() -> None:
    dedup = AlertDeduplicator()
    alert = make_alert()
    assert dedup.process(alert) is alert
    assert dedup.tracked_keys == 1


def test_identical_alerts_are_suppressed_and_counted() -> None:
    dedup = AlertDeduplicator()
    first = make_alert()
    dedup.process(first)

    assert dedup.process(make_alert()) is None
    assert dedup.process(make_alert()) is None
    assert first.occurrences == 3
    assert dedup.tracked_keys == 1


def test_merge_keeps_highest_confidence_and_merges_evidence() -> None:
    dedup = AlertDeduplicator()
    first = make_alert(confidence=0.6, evidence={"unique_ports": 20})
    dedup.process(first)
    dedup.process(make_alert(confidence=0.9, evidence={"unique_ports": 90, "extra": 1}))

    assert first.confidence == 0.9
    assert first.evidence == {"unique_ports": 90, "extra": 1}


def test_different_dimensions_are_not_deduplicated() -> None:
    dedup = AlertDeduplicator()
    dedup.process(make_alert())
    assert dedup.process(make_alert(src_ip="10.0.0.6")) is not None
    assert dedup.process(make_alert(dst_ip="10.0.0.7")) is not None
    assert dedup.process(make_alert(severity=Severity.LOW)) is not None
    assert dedup.process(make_alert(rule_triggered="SynFloodDetector")) is not None
    assert dedup.tracked_keys == 5


def test_alert_reappears_after_the_window_expires() -> None:
    dedup = AlertDeduplicator(window_seconds=60)
    dedup.process(make_alert())

    later = datetime.now(UTC) + timedelta(seconds=120)
    assert dedup.process(make_alert(timestamp=later)) is not None
    assert dedup.tracked_keys == 1


def test_alert_within_window_is_still_suppressed() -> None:
    dedup = AlertDeduplicator(window_seconds=300)
    dedup.process(make_alert())
    soon = datetime.now(UTC) + timedelta(seconds=30)
    assert dedup.process(make_alert(timestamp=soon)) is None


def test_state_is_bounded_by_max_tracked_keys() -> None:
    dedup = AlertDeduplicator(window_seconds=3600, max_tracked_keys=5)
    for octet in range(50):
        dedup.process(make_alert(src_ip=f"10.0.1.{octet}"))
    assert dedup.tracked_keys == 5


def test_get_active_and_reset() -> None:
    dedup = AlertDeduplicator()
    first = make_alert()
    dedup.process(first)
    assert dedup.get_active(make_alert()) is first

    dedup.reset()
    assert dedup.tracked_keys == 0
    assert dedup.get_active(make_alert()) is None


def test_alert_storm_collapses_to_a_single_record() -> None:
    dedup = AlertDeduplicator()
    survivors = [dedup.process(make_alert()) for _ in range(1000)]
    assert sum(1 for alert in survivors if alert is not None) == 1
