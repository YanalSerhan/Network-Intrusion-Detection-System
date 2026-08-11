"""CRUD tests for every SQL repository, against a real SQLite file."""

from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest
from sqlalchemy.orm import Session, sessionmaker

from network_defender.constants import AlertStatus, MitreTactic, ProviderStatus, Severity
from network_defender.database.repositories import (
    PacketRepository,
    RuleRepository,
    SqlAlchemyAlertRepository,
    StatisticsRepository,
    ThreatIntelCacheRepository,
)
from network_defender.rules.models import Rule, RuleCondition
from network_defender.services.alerts.repository import AlertRepository
from network_defender.services.threat_intel.models import (
    GeoLocation,
    ProviderResult,
    ThreatIntelResult,
)

from .conftest import PUBLIC_IP, make_alert, make_packet

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


# --------------------------------------------------------------------------
# Packets
# --------------------------------------------------------------------------


def test_packet_evidence_roundtrip(
    alert_repo: SqlAlchemyAlertRepository, packet_repo: PacketRepository
) -> None:
    alert = make_alert()
    alert_repo.save(alert)
    packet_repo.save(make_packet(), alert_id=alert.alert_id)

    evidence = packet_repo.list_for_alert(alert.alert_id)
    assert len(evidence) == 1
    assert evidence[0].dst_port == 443
    assert evidence[0].tcp_flags is not None
    assert evidence[0].tcp_flags.syn is True  # rebuilt from the JSON column


def test_save_many_and_ordering(
    alert_repo: SqlAlchemyAlertRepository, packet_repo: PacketRepository
) -> None:
    alert = make_alert()
    alert_repo.save(alert)
    now = datetime.now(UTC)
    packets = [make_packet(timestamp=now + timedelta(seconds=i)) for i in range(5)]

    assert packet_repo.save_many(packets, alert_id=alert.alert_id) == 5
    assert packet_repo.save_many([], alert_id=alert.alert_id) == 0

    stored = packet_repo.list_for_alert(alert.alert_id)
    assert [p.timestamp for p in stored] == sorted(p.timestamp for p in stored)


def test_deleting_an_alert_cascades_to_its_packets(
    alert_repo: SqlAlchemyAlertRepository, packet_repo: PacketRepository
) -> None:
    """Requires PRAGMA foreign_keys=ON; SQLite ignores cascades without it."""
    alert = make_alert()
    alert_repo.save(alert)
    packet_repo.save_many([make_packet(), make_packet()], alert_id=alert.alert_id)
    assert packet_repo.count() == 2

    alert_repo.clear()
    assert packet_repo.count() == 0


def test_packet_limit_is_applied(
    alert_repo: SqlAlchemyAlertRepository, packet_repo: PacketRepository
) -> None:
    alert = make_alert()
    alert_repo.save(alert)
    packet_repo.save_many([make_packet() for _ in range(10)], alert_id=alert.alert_id)
    assert len(packet_repo.list_for_alert(alert.alert_id, limit=3)) == 3


# --------------------------------------------------------------------------
# Rules
# --------------------------------------------------------------------------


def _rule(name: str = "TCP Port Scan", enabled: bool = True) -> Rule:
    return Rule(
        name=name,
        severity=Severity.MEDIUM,
        enabled=enabled,
        window=60,
        threshold=15,
        conditions=[RuleCondition(field="protocol", operator="equals", value="tcp")],
    )


def test_rule_sync_and_query(rule_repo: RuleRepository) -> None:
    assert rule_repo.sync([_rule(), _rule("Disabled", enabled=False)]) == 2
    assert rule_repo.count() == 2
    assert len(rule_repo.list_rules(enabled_only=True)) == 1

    stored = rule_repo.get("TCP Port Scan")
    assert stored is not None
    assert stored.threshold == 15
    assert stored.conditions[0]["field"] == "protocol"


def test_resync_drops_rules_deleted_from_disk(rule_repo: RuleRepository) -> None:
    rule_repo.sync([_rule(), _rule("Old Rule")])
    rule_repo.sync([_rule()])

    assert rule_repo.count() == 1
    assert rule_repo.get("Old Rule") is None


def test_rule_source_paths_are_recorded_and_cleared(rule_repo: RuleRepository) -> None:
    rule_repo.sync([_rule()], {"TCP Port Scan": "rules/tcp_port_scan.yaml"})
    stored = rule_repo.get("TCP Port Scan")
    assert stored is not None and stored.source_path == "rules/tcp_port_scan.yaml"

    rule_repo.clear()
    assert rule_repo.count() == 0


# --------------------------------------------------------------------------
# Statistics
# --------------------------------------------------------------------------


def test_statistics_snapshots_and_summary(stats_repo: StatisticsRepository) -> None:
    now = datetime.now(UTC)
    for i in range(3):
        stats_repo.record_snapshot(
            total_packets=1000 * i,
            packets_per_second=100.0 * i,
            alerts_by_severity={"high": i},
            captured_at=now + timedelta(minutes=i),
        )

    assert stats_repo.summarise() == {"snapshots": 3, "peak_pps": 200.0, "mean_pps": 100.0}
    latest = stats_repo.get_latest()
    assert latest is not None and latest.packets_per_second == 200.0
    assert len(stats_repo.get_series(hours=24)) == 3


def test_statistics_series_respects_the_window(stats_repo: StatisticsRepository) -> None:
    now = datetime.now(UTC)
    stats_repo.record_snapshot(captured_at=now - timedelta(days=5))
    stats_repo.record_snapshot(captured_at=now)
    assert len(stats_repo.get_series(hours=24)) == 1


def test_empty_statistics_summarise_safely(stats_repo: StatisticsRepository) -> None:
    assert stats_repo.get_latest() is None
    assert stats_repo.summarise() == {"snapshots": 0, "peak_pps": 0.0, "mean_pps": 0.0}


# --------------------------------------------------------------------------
# Threat intel cache
# --------------------------------------------------------------------------


def _result(provider: str = "abuseipdb", ok: bool = True) -> ProviderResult:
    return ProviderResult(
        provider=provider,
        status=ProviderStatus.OK if ok else ProviderStatus.ERROR,
        reputation_score=93.0 if ok else None,
    )


def test_cache_roundtrip_and_upsert(ti_repo: ThreatIntelCacheRepository) -> None:
    ti_repo.set("abuseipdb", PUBLIC_IP, _result(), ttl_seconds=3600)
    ti_repo.set("abuseipdb", PUBLIC_IP, _result(), ttl_seconds=3600)

    assert ti_repo.count() == 1  # upsert, not a second row
    cached = ti_repo.get("abuseipdb", PUBLIC_IP)
    assert cached is not None and cached.reputation_score == 93.0


def test_cache_ignores_failures(ti_repo: ThreatIntelCacheRepository) -> None:
    ti_repo.set("abuseipdb", PUBLIC_IP, _result(ok=False), ttl_seconds=3600)
    assert ti_repo.get("abuseipdb", PUBLIC_IP) is None


def test_expired_entries_are_not_served(ti_repo: ThreatIntelCacheRepository) -> None:
    ti_repo.set("abuseipdb", PUBLIC_IP, _result(), ttl_seconds=-1)
    assert ti_repo.get("abuseipdb", PUBLIC_IP) is None
    assert ti_repo.count() == 0  # deleted on read, never served once


def test_cache_is_keyed_per_provider(ti_repo: ThreatIntelCacheRepository) -> None:
    ti_repo.set("abuseipdb", PUBLIC_IP, _result(), ttl_seconds=3600)
    assert ti_repo.get("ip_api_geo", PUBLIC_IP) is None


def test_purge_expired(ti_repo: ThreatIntelCacheRepository) -> None:
    ti_repo.set("a", "1.1.1.1", _result("a"), ttl_seconds=-1)
    ti_repo.set("b", "2.2.2.2", _result("b"), ttl_seconds=3600)

    assert ti_repo.purge_expired() == 1
    assert ti_repo.count() == 1

    ti_repo.clear()
    assert ti_repo.count() == 0


# --------------------------------------------------------------------------
# Cross-session durability
# --------------------------------------------------------------------------


@pytest.mark.parametrize("severity", [Severity.LOW, Severity.CRITICAL])
def test_data_is_visible_to_a_new_repository_instance(
    session_factory: sessionmaker[Session], severity: Severity
) -> None:
    """A second repository over the same database sees committed rows."""
    written = make_alert(severity=severity)
    SqlAlchemyAlertRepository(session_factory).save(written)

    reader = SqlAlchemyAlertRepository(session_factory)
    stored = reader.get(written.alert_id)
    assert stored is not None
    assert stored.severity is severity
