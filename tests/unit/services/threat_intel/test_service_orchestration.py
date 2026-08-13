"""Tests for the service that drives providers, cache and breaker together."""



from network_defender.constants import Severity, ThreatVerdict
from network_defender.services.alerts.models import Alert
from network_defender.services.threat_intel.circuit_breaker import (
    STATE_CLOSED,
    STATE_OPEN,
    CircuitBreaker,
)
from network_defender.services.threat_intel.service import ThreatIntelService
from tests.fixtures.constants import PUBLIC_IP
from tests.fixtures.providers import StubProvider, failing_provider

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
    provider = failing_provider()
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
    good, bad = StubProvider("good"), failing_provider("bad")
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
    service = ThreatIntelService(providers=[failing_provider()])
    service.breakers["down"] = CircuitBreaker(failure_threshold=1, reset_seconds=60)
    service.enrich_ip(PUBLIC_IP)
    assert service.breakers["down"].state == STATE_OPEN

    service.start()
    assert service.breakers["down"].state == STATE_CLOSED

    service.stop()
    assert service.cache.get_stats()["entries"] == 0
