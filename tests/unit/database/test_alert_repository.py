"""Tests for alert persistence: roundtrip fidelity, upsert and querying."""

from datetime import UTC, datetime, timedelta
from uuid import uuid4

from network_defender.constants import AlertStatus, MitreTactic, Severity
from network_defender.database.repositories import (
    SqlAlchemyAlertRepository,
)
from network_defender.services.alerts.repository import AlertRepository
from network_defender.services.threat_intel.models import (
    GeoLocation,
    ThreatIntelResult,
)
from tests.fixtures.builders import make_alert
from tests.fixtures.constants import PUBLIC_IP

# --------------------------------------------------------------------------
# Alerts
# --------------------------------------------------------------------------


def test_sql_repository_implements_the_port() -> None:
    assert issubclass(SqlAlchemyAlertRepository, AlertRepository)


def test_save_and_get_roundtrip(alert_repo: SqlAlchemyAlertRepository) -> None:
    alert = make_alert(confidence=0.83, evidence={"unique_ports": 60})
    alert_repo.save(alert)

    stored = alert_repo.get(alert.alert_id)
    assert stored is not None
    assert stored.alert_id == alert.alert_id
    assert stored.rule_triggered == "TcpPortScanDetector"
    assert stored.confidence == 0.83
    assert stored.evidence == {"unique_ports": 60}


def test_enums_survive_the_roundtrip(alert_repo: SqlAlchemyAlertRepository) -> None:
    alert = make_alert(severity=Severity.CRITICAL, tactic=MitreTactic.EXFILTRATION)
    alert_repo.save(alert)

    stored = alert_repo.get(alert.alert_id)
    assert stored is not None
    assert stored.severity is Severity.CRITICAL
    assert stored.tactic is MitreTactic.EXFILTRATION
    assert stored.status is AlertStatus.NEW


def test_timestamps_come_back_timezone_aware(alert_repo: SqlAlchemyAlertRepository) -> None:
    """SQLite drops offsets; naive values would raise on any aware comparison."""
    alert = make_alert()
    alert_repo.save(alert)

    stored = alert_repo.get(alert.alert_id)
    assert stored is not None
    assert stored.timestamp.tzinfo is not None
    assert stored.timestamp < datetime.now(UTC) + timedelta(seconds=1)


def test_save_is_an_upsert_not_a_duplicate(alert_repo: SqlAlchemyAlertRepository) -> None:
    """The pipeline re-saves the same alert on dedup and again on enrichment."""
    alert = make_alert()
    alert_repo.save(alert)

    alert.occurrences = 7
    alert.status = AlertStatus.ACKNOWLEDGED
    alert_repo.save(alert)

    assert alert_repo.count() == 1
    stored = alert_repo.get(alert.alert_id)
    assert stored is not None
    assert stored.occurrences == 7
    assert stored.status is AlertStatus.ACKNOWLEDGED


def test_threat_intel_is_persisted_and_rebuilt(alert_repo: SqlAlchemyAlertRepository) -> None:
    alert = make_alert()
    alert_repo.save(alert)

    alert.threat_intel = ThreatIntelResult(
        ip=PUBLIC_IP, reputation_score=93.0, geo=GeoLocation(country="Russia", city="Moscow")
    )
    alert_repo.save(alert)

    stored = alert_repo.get(alert.alert_id)
    assert stored is not None and stored.threat_intel is not None
    assert stored.threat_intel.reputation_score == 93.0
    assert stored.threat_intel.geo is not None
    assert stored.threat_intel.geo.city == "Moscow"


def test_get_unknown_id_returns_none(alert_repo: SqlAlchemyAlertRepository) -> None:
    assert alert_repo.get(uuid4()) is None


def test_list_returns_newest_first(alert_repo: SqlAlchemyAlertRepository) -> None:
    now = datetime.now(UTC)
    for offset in range(3):
        alert_repo.save(
            make_alert(rule_triggered=f"R{offset}", timestamp=now + timedelta(seconds=offset))
        )
    assert [a.rule_triggered for a in alert_repo.list_alerts()] == ["R2", "R1", "R0"]


def test_filters_and_pagination(alert_repo: SqlAlchemyAlertRepository) -> None:
    now = datetime.now(UTC)
    for offset in range(6):
        alert_repo.save(
            make_alert(
                rule_triggered=f"R{offset}",
                severity=Severity.LOW if offset % 2 else Severity.HIGH,
                timestamp=now + timedelta(seconds=offset),
            )
        )

    assert len(alert_repo.list_alerts(severity=Severity.HIGH)) == 3
    assert len(alert_repo.list_alerts(status=AlertStatus.RESOLVED)) == 0
    assert len(alert_repo.list_alerts(since=now + timedelta(seconds=4))) == 2
    assert len(alert_repo.list_alerts(limit=2)) == 2
    assert [a.rule_triggered for a in alert_repo.list_alerts(limit=2, offset=2)] == ["R3", "R2"]


def test_count_and_clear(alert_repo: SqlAlchemyAlertRepository) -> None:
    alert_repo.save(make_alert(severity=Severity.HIGH))
    alert_repo.save(make_alert(severity=Severity.HIGH, rule_triggered="R2"))
    alert_repo.save(make_alert(severity=Severity.LOW, rule_triggered="R3"))

    assert alert_repo.count() == 3
    assert alert_repo.count(severity=Severity.HIGH) == 2
    assert alert_repo.count(severity=Severity.INFO) == 0

    alert_repo.clear()
    assert alert_repo.count() == 0
