"""Unit tests for the alert repository port and in-memory adapter."""

from datetime import UTC, datetime, timedelta
from uuid import uuid4

from network_defender.constants import AlertStatus, Severity
from network_defender.services.alerts.repository import (
    AlertRepository,
    InMemoryAlertRepository,
)
from tests.fixtures.builders import make_alert


def test_in_memory_store_implements_the_port() -> None:
    assert issubclass(InMemoryAlertRepository, AlertRepository)


def test_save_and_get_roundtrip() -> None:
    repo = InMemoryAlertRepository()
    alert = make_alert()
    assert repo.save(alert) is alert
    assert repo.get(alert.alert_id) is alert


def test_get_unknown_id_returns_none() -> None:
    assert InMemoryAlertRepository().get(uuid4()) is None


def test_saving_same_id_updates_rather_than_duplicates() -> None:
    repo = InMemoryAlertRepository()
    alert = make_alert()
    repo.save(alert)
    alert.occurrences = 7
    repo.save(alert)

    assert repo.count() == 1
    stored = repo.get(alert.alert_id)
    assert stored is not None and stored.occurrences == 7


def test_list_returns_newest_first() -> None:
    repo = InMemoryAlertRepository()
    now = datetime.now(UTC)
    for offset in range(3):
        repo.save(make_alert(src_ip=f"10.0.0.{offset}", timestamp=now + timedelta(seconds=offset)))

    assert [alert.src_ip for alert in repo.list_alerts()] == ["10.0.0.2", "10.0.0.1", "10.0.0.0"]


def test_filters_by_severity_status_and_time() -> None:
    repo = InMemoryAlertRepository()
    now = datetime.now(UTC)
    repo.save(make_alert(severity=Severity.LOW, timestamp=now - timedelta(hours=2)))
    recent = make_alert(severity=Severity.CRITICAL, timestamp=now)
    recent.status = AlertStatus.ACKNOWLEDGED
    repo.save(recent)

    assert len(repo.list_alerts(severity=Severity.CRITICAL)) == 1
    assert len(repo.list_alerts(status=AlertStatus.ACKNOWLEDGED)) == 1
    assert len(repo.list_alerts(status=AlertStatus.RESOLVED)) == 0
    assert len(repo.list_alerts(since=now - timedelta(minutes=5))) == 1


def test_pagination() -> None:
    repo = InMemoryAlertRepository()
    now = datetime.now(UTC)
    for offset in range(5):
        repo.save(make_alert(src_ip=f"10.0.0.{offset}", timestamp=now + timedelta(seconds=offset)))

    assert len(repo.list_alerts(limit=2)) == 2
    page_two = repo.list_alerts(limit=2, offset=2)
    assert [alert.src_ip for alert in page_two] == ["10.0.0.2", "10.0.0.1"]


def test_count_and_clear() -> None:
    repo = InMemoryAlertRepository()
    repo.save(make_alert(severity=Severity.HIGH))
    repo.save(make_alert(severity=Severity.HIGH, src_ip="10.0.0.6"))
    repo.save(make_alert(severity=Severity.LOW, src_ip="10.0.0.7"))

    assert repo.count() == 3
    assert repo.count(severity=Severity.HIGH) == 2
    assert repo.count(severity=Severity.INFO) == 0

    repo.clear()
    assert repo.count() == 0


def test_store_is_bounded_and_evicts_oldest() -> None:
    repo = InMemoryAlertRepository(max_records=3)
    alerts = [make_alert(src_ip=f"10.0.0.{i}") for i in range(5)]
    for alert in alerts:
        repo.save(alert)

    assert repo.count() == 3
    assert repo.get(alerts[0].alert_id) is None
    assert repo.get(alerts[4].alert_id) is not None
