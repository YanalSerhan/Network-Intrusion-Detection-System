"""Unit tests for eligibility, cache, circuit breaker, aggregation and service."""

import time

import pytest

from network_defender.constants import ProviderStatus, Severity, ThreatVerdict
from network_defender.services.alerts.models import Alert
from network_defender.services.threat_intel.aggregation import aggregate, classify
from network_defender.services.threat_intel.base import ThreatIntelProvider
from network_defender.services.threat_intel.cache import ThreatIntelCache
from network_defender.services.threat_intel.circuit_breaker import (
    STATE_CLOSED,
    STATE_HALF_OPEN,
    STATE_OPEN,
    CircuitBreaker,
)
from network_defender.services.threat_intel.eligibility import eligible_ips, is_public_ip
from network_defender.services.threat_intel.models import (
    AsnInfo,
    GeoLocation,
    ProviderResult,
    WhoisInfo,
)
from network_defender.services.threat_intel.service import ThreatIntelService

from .conftest import PUBLIC_IP


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


def _failing(name: str = "down") -> StubProvider:
    return StubProvider(
        name, ProviderResult(provider=name, status=ProviderStatus.ERROR, error="503")
    )


# --------------------------------------------------------------------------
# Eligibility
# --------------------------------------------------------------------------


@pytest.mark.parametrize("ip", [PUBLIC_IP, "8.8.8.8", "2001:4860:4860::8888"])
def test_public_addresses_are_eligible(ip: str) -> None:
    assert is_public_ip(ip) is True


@pytest.mark.parametrize(
    "ip",
    [
        "10.0.0.1",
        "192.168.1.1",
        "172.16.0.1",
        "127.0.0.1",
        "169.254.1.1",
        "224.0.0.1",
        "fd00::1",
        "::1",
        "203.0.113.1",  # TEST-NET-3, reserved for documentation
        "not-an-ip",
        "",
    ],
)
def test_non_routable_and_malformed_addresses_are_refused(ip: str) -> None:
    assert is_public_ip(ip) is False


def test_eligible_ips_filters_and_deduplicates() -> None:
    assert eligible_ips("10.0.0.1", PUBLIC_IP, None, PUBLIC_IP, "8.8.8.8") == [PUBLIC_IP, "8.8.8.8"]


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


# --------------------------------------------------------------------------
# Circuit breaker
# --------------------------------------------------------------------------


def test_breaker_opens_after_consecutive_failures() -> None:
    breaker = CircuitBreaker(failure_threshold=3, reset_seconds=60)
    for _ in range(2):
        breaker.record_failure()
    assert breaker.state == STATE_CLOSED

    breaker.record_failure()
    assert breaker.state == STATE_OPEN
    assert breaker.allows_request() is False


def test_success_resets_the_failure_count() -> None:
    breaker = CircuitBreaker(failure_threshold=3)
    breaker.record_failure()
    breaker.record_failure()
    breaker.record_success()
    breaker.record_failure()
    assert breaker.state == STATE_CLOSED


def test_breaker_half_opens_after_the_cooldown() -> None:
    breaker = CircuitBreaker(failure_threshold=1, reset_seconds=0.05)
    breaker.record_failure()
    assert breaker.allows_request() is False

    time.sleep(0.1)
    assert breaker.state == STATE_HALF_OPEN
    assert breaker.allows_request() is True


def test_breaker_rejects_a_non_positive_threshold() -> None:
    with pytest.raises(ValueError):
        CircuitBreaker(failure_threshold=0)


# --------------------------------------------------------------------------
# Aggregation
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("score", "expected"),
    [
        (None, ThreatVerdict.UNKNOWN),
        (0.0, ThreatVerdict.CLEAN),
        (24.9, ThreatVerdict.CLEAN),
        (25.0, ThreatVerdict.SUSPICIOUS),
        (59.9, ThreatVerdict.SUSPICIOUS),
        (60.0, ThreatVerdict.MALICIOUS),
        (100.0, ThreatVerdict.MALICIOUS),
    ],
)
def test_classification_thresholds(score: float | None, expected: ThreatVerdict) -> None:
    assert classify(score) is expected


def test_aggregate_takes_the_maximum_not_the_mean() -> None:
    """One feed flagging 95 must not be diluted by three that have no opinion."""
    result = aggregate(
        PUBLIC_IP,
        [
            ProviderResult(provider="a", status=ProviderStatus.OK, reputation_score=95.0),
            ProviderResult(provider="b", status=ProviderStatus.OK, reputation_score=0.0),
            ProviderResult(provider="c", status=ProviderStatus.OK, reputation_score=0.0),
        ],
    )
    assert result.reputation_score == 95.0
    assert result.verdict is ThreatVerdict.MALICIOUS


def test_aggregate_merges_attribution_first_wins() -> None:
    result = aggregate(
        PUBLIC_IP,
        [
            ProviderResult(
                provider="a", status=ProviderStatus.OK, geo=GeoLocation(country="Russia")
            ),
            ProviderResult(
                provider="b", status=ProviderStatus.OK, geo=GeoLocation(country="Germany")
            ),
            ProviderResult(provider="c", status=ProviderStatus.OK, asn=AsnInfo(asn="AS1")),
            ProviderResult(
                provider="d", status=ProviderStatus.OK, whois=WhoisInfo(network_name="NET")
            ),
        ],
    )
    assert result.geo is not None and result.geo.country == "Russia"
    assert result.asn is not None and result.asn.asn == "AS1"
    assert result.whois is not None and result.whois.network_name == "NET"


def test_aggregate_records_failures_as_partial() -> None:
    result = aggregate(
        PUBLIC_IP,
        [
            ProviderResult(provider="ok", status=ProviderStatus.OK, reputation_score=10.0),
            ProviderResult(provider="bad", status=ProviderStatus.ERROR, error="503"),
            ProviderResult(provider="off", status=ProviderStatus.SKIPPED),
        ],
    )
    assert result.providers_queried == ["ok", "bad", "off"]
    assert result.providers_failed == ["bad", "off"]
    assert result.is_partial is True


def test_aggregate_with_no_opinions_is_unknown() -> None:
    result = aggregate(PUBLIC_IP, [ProviderResult(provider="a", status=ProviderStatus.OK)])
    assert result.verdict is ThreatVerdict.UNKNOWN
    assert result.reputation_score is None


# --------------------------------------------------------------------------
# Service
# --------------------------------------------------------------------------


def test_private_addresses_are_never_sent_to_providers() -> None:
    provider = StubProvider()
    service = ThreatIntelService(providers=[provider])

    result = service.enrich_ip("10.0.0.5")
    assert result.verdict is ThreatVerdict.UNKNOWN
    assert provider.calls == 0
    assert service.health_check()["skipped_private_ips"] == 1


def test_repeat_lookups_are_served_from_cache() -> None:
    provider = StubProvider()
    service = ThreatIntelService(providers=[provider])

    for _ in range(5):
        service.enrich_ip(PUBLIC_IP)
    assert provider.calls == 1


def test_open_circuit_stops_further_calls() -> None:
    provider = _failing()
    service = ThreatIntelService(providers=[provider])
    service.breakers["down"] = CircuitBreaker(failure_threshold=3, reset_seconds=60)

    for octet in range(10):
        service.enrich_ip(f"8.8.8.{octet}")
    assert provider.calls == 3
    assert service.breakers["down"].state == STATE_OPEN


def test_unconfigured_providers_are_skipped_without_calling() -> None:
    class Keyed(StubProvider):
        requires_api_key = True

    provider = Keyed("keyed")
    service = ThreatIntelService(providers=[provider])

    result = service.enrich_ip(PUBLIC_IP)
    assert provider.calls == 0
    assert result.providers_failed == ["keyed"]


def test_one_failing_provider_does_not_block_the_others() -> None:
    good, bad = StubProvider("good"), _failing("bad")
    service = ThreatIntelService(providers=[bad, good])

    result = service.enrich_ip(PUBLIC_IP)
    assert result.reputation_score == 88.0
    assert result.providers_failed == ["bad"]


def test_enrich_alert_attaches_the_result() -> None:
    service = ThreatIntelService(providers=[StubProvider()])
    alert = Alert(
        severity=Severity.HIGH,
        rule_triggered="R",
        description="d",
        src_ip="10.0.0.5",
        dst_ip=PUBLIC_IP,
    )

    result = service.enrich_alert(alert)
    assert result is not None
    assert result.ip == PUBLIC_IP  # the private source was skipped
    assert alert.threat_intel is not None
    assert alert.threat_intel.verdict is ThreatVerdict.MALICIOUS


def test_internal_only_alerts_are_not_enriched() -> None:
    provider = StubProvider()
    service = ThreatIntelService(providers=[provider])
    alert = Alert(
        severity=Severity.HIGH,
        rule_triggered="R",
        description="d",
        src_ip="10.0.0.5",
        dst_ip="10.0.0.9",
    )

    assert service.enrich_alert(alert) is None
    assert alert.threat_intel is None
    assert provider.calls == 0


def test_lifecycle_resets_breakers_and_clears_cache() -> None:
    service = ThreatIntelService(providers=[_failing()])
    service.breakers["down"] = CircuitBreaker(failure_threshold=1, reset_seconds=60)
    service.enrich_ip(PUBLIC_IP)
    assert service.breakers["down"].state == STATE_OPEN

    service.start()
    assert service.breakers["down"].state == STATE_CLOSED

    service.stop()
    assert service.cache.get_stats()["entries"] == 0
