"""Integration tests: migrations, retention, tiered cache and durability.

These run against real file-backed SQLite databases, including the actual
Alembic migration path rather than `metadata.create_all`, because a schema that
only exists via create_all proves nothing about whether the migrations an
operator will actually run are correct.
"""

from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from sqlalchemy import inspect
from sqlalchemy.orm import Session, sessionmaker

from network_defender.constants import ProviderStatus, Severity
from network_defender.database.engine import (
    create_db_engine,
    create_session_factory,
    resolve_database_url,
)
from network_defender.database.migrations import current_revision, upgrade_to_head
from network_defender.database.repositories import (
    PacketRepository,
    SqlAlchemyAlertRepository,
    StatisticsRepository,
    ThreatIntelCacheRepository,
)
from network_defender.database.retention import RetentionPolicy, RetentionService
from network_defender.services.database import DatabaseService
from network_defender.services.threat_intel.models import ProviderResult
from network_defender.services.threat_intel.tiered_cache import TieredThreatIntelCache
from network_defender.shared.config_models import DatabaseConfig
from network_defender.shared.paths import PROJECT_ROOT
from tests.fixtures.builders import make_alert, make_packet
from tests.fixtures.constants import PUBLIC_IP

EXPECTED_TABLES = {"alerts", "packets", "rules", "statistics", "threat_intel_cache"}


# --------------------------------------------------------------------------
# Migrations
# --------------------------------------------------------------------------


def test_migrations_build_the_full_schema(tmp_path: Path) -> None:
    url = f"sqlite:///{tmp_path / 'migrated.db'}"
    upgrade_to_head(url)

    engine = create_db_engine(DatabaseConfig(default_url=url))
    try:
        assert EXPECTED_TABLES.issubset(set(inspect(engine).get_table_names()))
        assert current_revision(engine) is not None
    finally:
        engine.dispose()


def test_migrated_schema_accepts_real_writes(tmp_path: Path) -> None:
    """The schema an operator gets must actually work, not merely exist."""
    url = f"sqlite:///{tmp_path / 'migrated.db'}"
    upgrade_to_head(url)

    engine = create_db_engine(DatabaseConfig(default_url=url))
    try:
        repo = SqlAlchemyAlertRepository(create_session_factory(engine))
        alert = make_alert(evidence={"unique_ports": 60})
        repo.save(alert)

        stored = repo.get(alert.alert_id)
        assert stored is not None
        assert stored.evidence == {"unique_ports": 60}
    finally:
        engine.dispose()


def test_migration_indices_exist(tmp_path: Path) -> None:
    url = f"sqlite:///{tmp_path / 'migrated.db'}"
    upgrade_to_head(url)

    engine = create_db_engine(DatabaseConfig(default_url=url))
    try:
        names = {index["name"] for index in inspect(engine).get_indexes("alerts")}
        assert "ix_alerts_severity_timestamp" in names
        assert "ix_alerts_status_timestamp" in names
        assert "ix_alerts_src_ip_timestamp" in names
    finally:
        engine.dispose()


# --------------------------------------------------------------------------
# Engine configuration
# --------------------------------------------------------------------------


def test_relative_sqlite_paths_anchor_to_the_project_root(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # The suite-wide fixture points DATABASE_URL at a temp file; clear it so the
    # configured default is what actually gets resolved here.
    monkeypatch.delenv("DATABASE_URL", raising=False)

    url = resolve_database_url(DatabaseConfig(default_url="sqlite:///./nd.db"))
    assert str(PROJECT_ROOT) in url


def test_database_url_env_var_overrides_config(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("DATABASE_URL", "sqlite:////tmp/override.db")
    config = DatabaseConfig(url_env_var="DATABASE_URL", default_url="sqlite:///ignored.db")
    assert resolve_database_url(config) == "sqlite:////tmp/override.db"


def test_foreign_keys_are_enforced_on_sqlite(tmp_path: Path) -> None:
    """Without PRAGMA foreign_keys=ON, ON DELETE CASCADE silently does nothing."""
    engine = create_db_engine(DatabaseConfig(default_url=f"sqlite:///{tmp_path / 'fk.db'}"))
    try:
        with engine.connect() as connection:
            assert connection.exec_driver_sql("PRAGMA foreign_keys").scalar() == 1
    finally:
        engine.dispose()


# --------------------------------------------------------------------------
# Retention
# --------------------------------------------------------------------------


def test_retention_prunes_only_what_is_stale(
    session_factory: sessionmaker[Session],
    alert_repo: SqlAlchemyAlertRepository,
    packet_repo: PacketRepository,
    stats_repo: StatisticsRepository,
    ti_repo: ThreatIntelCacheRepository,
) -> None:
    now = datetime.now(UTC)
    fresh = make_alert(timestamp=now - timedelta(days=1))
    stale = make_alert(rule_triggered="Old", timestamp=now - timedelta(days=60))
    for alert in (fresh, stale):
        alert_repo.save(alert)
        packet_repo.save(make_packet(timestamp=alert.timestamp), alert_id=alert.alert_id)

    stats_repo.record_snapshot(captured_at=now - timedelta(days=200))
    stats_repo.record_snapshot(captured_at=now)
    ti_repo.set("p", PUBLIC_IP, ProviderResult(provider="p", status=ProviderStatus.OK), -1)

    removed = RetentionService(session_factory, RetentionPolicy()).prune()

    assert removed == {"packets": 1, "alerts": 1, "statistics": 1, "threat_intel_cache": 1}
    assert alert_repo.get(fresh.alert_id) is not None
    assert alert_repo.get(stale.alert_id) is None


def test_pruning_an_alert_takes_its_evidence_with_it(
    session_factory: sessionmaker[Session],
    alert_repo: SqlAlchemyAlertRepository,
    packet_repo: PacketRepository,
) -> None:
    """Alert pruning must use the ORM so the cascade fires and nothing orphans."""
    now = datetime.now(UTC)
    stale = make_alert(timestamp=now - timedelta(days=60))
    alert_repo.save(stale)
    # Evidence newer than the packet window, so only the cascade can remove it.
    packet_repo.save(make_packet(timestamp=now), alert_id=stale.alert_id)

    RetentionService(session_factory, RetentionPolicy()).prune()
    assert packet_repo.count() == 0


def test_retention_rejects_packets_outliving_their_alerts() -> None:
    with pytest.raises(ValueError, match="packets_days must not exceed alerts_days"):
        RetentionPolicy(alerts_days=7, packets_days=30)


def test_retention_rejects_sub_day_windows() -> None:
    with pytest.raises(ValueError, match="at least one day"):
        RetentionPolicy(statistics_days=0)


def test_pruning_an_empty_database_is_a_no_op(
    session_factory: sessionmaker[Session],
) -> None:
    assert sum(RetentionService(session_factory).prune().values()) == 0


# --------------------------------------------------------------------------
# Tiered threat intel cache
# --------------------------------------------------------------------------


def _ok(provider: str = "abuseipdb") -> ProviderResult:
    return ProviderResult(provider=provider, status=ProviderStatus.OK, reputation_score=93.0)


def test_cache_survives_a_restart(ti_repo: ThreatIntelCacheRepository) -> None:
    TieredThreatIntelCache(durable=ti_repo, ttl_seconds=3600).set("abuseipdb", PUBLIC_IP, _ok())

    restarted = TieredThreatIntelCache(durable=ti_repo, ttl_seconds=3600)
    hit = restarted.get("abuseipdb", PUBLIC_IP)

    assert hit is not None and hit.reputation_score == 93.0
    assert restarted.get_stats()["durable_hits"] == 1


def test_durable_hits_are_promoted_into_memory(ti_repo: ThreatIntelCacheRepository) -> None:
    ti_repo.set("abuseipdb", PUBLIC_IP, _ok(), ttl_seconds=3600)
    cache = TieredThreatIntelCache(durable=ti_repo)

    cache.get("abuseipdb", PUBLIC_IP)
    assert cache.memory.get("abuseipdb", PUBLIC_IP) is not None

    cache.get("abuseipdb", PUBLIC_IP)
    assert cache.get_stats()["durable_hits"] == 1  # second read never hit the DB


def test_cache_degrades_when_the_database_fails() -> None:
    """A database problem must not break enrichment, which must not break alerting."""

    class Broken:
        def get(self, *args: object) -> None:
            raise RuntimeError("database unavailable")

        def set(self, *args: object) -> None:
            raise RuntimeError("database unavailable")

    cache = TieredThreatIntelCache(durable=Broken())  # type: ignore[arg-type]
    cache.set("abuseipdb", PUBLIC_IP, _ok())  # durable write fails, memory succeeds

    hit = cache.get("abuseipdb", PUBLIC_IP)
    assert hit is not None  # served from memory, so the DB is never consulted
    assert cache.get_stats()["durable_errors"] == 1

    # A miss in memory does reach the broken tier, and still returns cleanly.
    assert cache.get("abuseipdb", "8.8.8.8") is None
    assert cache.get_stats()["durable_errors"] == 2


def test_cache_without_a_durable_tier_behaves_like_memory_only() -> None:
    cache = TieredThreatIntelCache()
    cache.set("abuseipdb", PUBLIC_IP, _ok())

    assert cache.get("abuseipdb", PUBLIC_IP) is not None
    assert cache.get("abuseipdb", "8.8.8.8") is None
    assert cache.get_stats()["durable_enabled"] == 0.0


def test_failures_are_not_written_to_the_durable_tier(
    ti_repo: ThreatIntelCacheRepository,
) -> None:
    cache = TieredThreatIntelCache(durable=ti_repo)
    cache.set("abuseipdb", PUBLIC_IP, ProviderResult(provider="a", status=ProviderStatus.ERROR))
    assert ti_repo.count() == 0


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
