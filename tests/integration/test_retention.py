"""Integration tests: retention prunes stale data, and only what is configured."""

from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy.orm import Session, sessionmaker

from network_defender.constants import ProviderStatus
from network_defender.database.repositories import (
    PacketRepository,
    SqlAlchemyAlertRepository,
    StatisticsRepository,
    ThreatIntelCacheRepository,
)
from network_defender.database.retention import RetentionPolicy, RetentionService
from network_defender.sdk.sdk import NetworkDefenderSDK
from network_defender.services.threat_intel.models import ProviderResult
from network_defender.shared.config_pipeline import RetentionConfig
from network_defender.shared.rate_limit_models import RateLimitConfig
from tests.fixtures.builders import make_alert, make_packet
from tests.fixtures.constants import PUBLIC_IP
from tests.fixtures.sdk import build_app_config

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


def test_the_configured_window_is_the_one_that_prunes() -> None:
    """
    Retention has to be settable without editing source.

    It was not: `retention_days` sat in config/setup.json, was validated, and
    was reported by GET /config, while the pruner used its own defaults. An
    operator could set it to 7, watch the API agree, and still have alerts
    kept for 30 days.
    """
    config = build_app_config(retention=RetentionConfig(alerts_days=2, packets_days=1))
    sdk = NetworkDefenderSDK(
        app_config=config, rate_limit_config=RateLimitConfig(services={})
    )

    assert sdk._database_service.retention.policy.alerts_days == 2
    assert sdk._database_service.retention.policy.packets_days == 1


def test_an_impossible_retention_pairing_is_refused_at_startup() -> None:
    """
    Keeping packets longer than alerts cannot work, so it must not validate.

    Deleting an alert cascades to its packets, so a longer packet window is
    not merely ineffective — it is a configuration whose author believed
    something the database will never do.
    """
    with pytest.raises(ValueError, match="packets_days must not exceed alerts_days"):
        NetworkDefenderSDK(
            app_config=build_app_config(
                retention=RetentionConfig(alerts_days=5, packets_days=10)
            ),
            rate_limit_config=RateLimitConfig(services={}),
        )
