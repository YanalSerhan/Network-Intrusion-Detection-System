"""Tests for the in-memory threat intel cache: freshness, keying and bounds."""

import time

from network_defender.constants import ProviderStatus
from network_defender.services.threat_intel.base import ThreatIntelProvider
from network_defender.services.threat_intel.cache import ThreatIntelCache
from network_defender.services.threat_intel.models import (
    ProviderResult,
)
from tests.fixtures.constants import PUBLIC_IP


class StubProvider(ThreatIntelProvider):
    """Provider double returning a scripted result and counting calls."""

    def __init__(self, name: str = "stub", result: ProviderResult | None = None) -> None:
        super().__init__(gatekeeper=None)  # type: ignore[arg-type]
        self._name = name
        self._result = result
        self.calls = 0

    @property
    def name(self) -> str:
        return self._name

    def lookup(self, ip: str) -> ProviderResult:
        self.calls += 1
        return self._result or ProviderResult(
            provider=self._name, status=ProviderStatus.OK, reputation_score=88.0
        )


# --------------------------------------------------------------------------
# Cache
# --------------------------------------------------------------------------


def test_cache_returns_fresh_entries() -> None:
    cache = ThreatIntelCache(ttl_seconds=60)
    result = ProviderResult(provider="p", status=ProviderStatus.OK, reputation_score=10.0)
    cache.set("p", PUBLIC_IP, result)

    assert cache.get("p", PUBLIC_IP) is result
    assert cache.get_stats()["hits"] == 1


def test_cache_expires_entries() -> None:
    cache = ThreatIntelCache(ttl_seconds=0.05)
    cache.set("p", PUBLIC_IP, ProviderResult(provider="p", status=ProviderStatus.OK))
    time.sleep(0.1)
    assert cache.get("p", PUBLIC_IP) is None


def test_cache_does_not_store_failures() -> None:
    cache = ThreatIntelCache()
    cache.set("p", PUBLIC_IP, ProviderResult(provider="p", status=ProviderStatus.ERROR))
    assert cache.get("p", PUBLIC_IP) is None


def test_cache_is_keyed_per_provider() -> None:
    cache = ThreatIntelCache()
    cache.set("a", PUBLIC_IP, ProviderResult(provider="a", status=ProviderStatus.OK))
    assert cache.get("b", PUBLIC_IP) is None


def test_cache_is_lru_bounded() -> None:
    cache = ThreatIntelCache(max_entries=3)
    for octet in range(10):
        cache.set("p", f"8.8.8.{octet}", ProviderResult(provider="p", status=ProviderStatus.OK))
    assert cache.get_stats()["entries"] == 3
