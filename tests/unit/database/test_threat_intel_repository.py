"""Tests for the durable threat intel cache and cross-session visibility."""


import pytest
from sqlalchemy.orm import Session, sessionmaker

from network_defender.constants import ProviderStatus, Severity
from network_defender.database.repositories import (
    SqlAlchemyAlertRepository,
    ThreatIntelCacheRepository,
)
from network_defender.services.threat_intel.models import (
    ProviderResult,
)
from tests.fixtures.builders import make_alert
from tests.fixtures.constants import PUBLIC_IP

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
