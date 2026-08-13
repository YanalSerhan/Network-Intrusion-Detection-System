"""Integration tests: threat intel caching across memory and the database."""



from network_defender.constants import ProviderStatus
from network_defender.database.repositories import (
    ThreatIntelCacheRepository,
)
from network_defender.services.threat_intel.models import ProviderResult
from network_defender.services.threat_intel.tiered_cache import TieredThreatIntelCache
from tests.fixtures.constants import PUBLIC_IP

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
