"""Integration tests: the database service over a real SQLite file."""

from pathlib import Path

from network_defender.constants import Severity
from network_defender.services.database import DatabaseService
from network_defender.shared.config_models import DatabaseConfig
from tests.fixtures.builders import make_alert

# --------------------------------------------------------------------------
# DatabaseService
# --------------------------------------------------------------------------


def test_service_migrates_on_start(tmp_path: Path) -> None:
    config = DatabaseConfig(default_url=f"sqlite:///{tmp_path / 'svc.db'}")
    service = DatabaseService(config)
    service.start()
    try:
        health = service.health_check()
        assert health["status"] == "ok"
        assert health["dialect"] == "sqlite"
        assert health["schema_revision"] is not None
        assert health["rows"]["alerts"] == 0
    finally:
        service.stop()


def test_service_health_reports_row_counts(tmp_path: Path) -> None:
    config = DatabaseConfig(default_url=f"sqlite:///{tmp_path / 'svc.db'}")
    service = DatabaseService(config, run_migrations=False)
    service.create_schema_directly()
    service.start()
    try:
        service.alerts.save(make_alert(severity=Severity.CRITICAL))
        assert service.health_check()["rows"]["alerts"] == 1
        assert service.prune() == {
            "packets": 0,
            "alerts": 0,
            "statistics": 0,
            "threat_intel_cache": 0,
        }
    finally:
        service.stop()


def test_alerts_survive_a_service_restart(tmp_path: Path) -> None:
    """The point of this milestone: findings outlive the process."""
    config = DatabaseConfig(default_url=f"sqlite:///{tmp_path / 'persist.db'}")

    first = DatabaseService(config)
    first.start()
    alert = make_alert(severity=Severity.CRITICAL)
    first.alerts.save(alert)
    first.stop()

    second = DatabaseService(config)
    second.start()
    try:
        stored = second.alerts.get(alert.alert_id)
        assert stored is not None
        assert stored.severity is Severity.CRITICAL
    finally:
        second.stop()
