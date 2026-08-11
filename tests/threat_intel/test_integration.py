"""Integration tests: gatekeeper enforcement and the background worker.

The gatekeeper tests matter because ADR 3 makes rate limiting an architectural
guarantee, not a provider-level courtesy. They assert it end to end: through a
real provider, over real (mocked) HTTP, against a real gatekeeper.
"""

import time

import httpx
import pytest
import respx

from network_defender.constants import ProviderStatus, Severity
from network_defender.detectors.models import DetectionAlert
from network_defender.services.alerts.models import Alert
from network_defender.services.alerts.service import AlertService
from network_defender.services.threat_intel.factory import build_providers, build_service
from network_defender.services.threat_intel.providers import (
    IpApiGeolocationProvider,
    RdapWhoisProvider,
)
from network_defender.services.threat_intel.service import ThreatIntelService
from network_defender.services.threat_intel.worker import EnrichmentWorker
from network_defender.shared.gatekeeper import ApiGatekeeper, GatekeeperError
from network_defender.shared.rate_limit_models import ServiceRateLimitConfig

from .conftest import IP_API_GEO_BODY, PUBLIC_IP, RDAP_BODY, make_gatekeeper

# --------------------------------------------------------------------------
# Gatekeeper enforcement
# --------------------------------------------------------------------------


@respx.mock
def test_rate_limit_is_enforced_end_to_end() -> None:
    """A provider held to 2 requests/minute must block on the third."""
    respx.get(f"http://ip-api.com/json/{PUBLIC_IP}").mock(
        return_value=httpx.Response(200, json=IP_API_GEO_BODY)
    )
    provider = IpApiGeolocationProvider(make_gatekeeper("ip_api", requests_per_minute=2))

    for _ in range(2):
        assert provider.lookup(PUBLIC_IP).status is ProviderStatus.OK

    status = provider.gatekeeper.get_queue_status()
    assert status.requests_this_minute == 2
    assert status.requests_per_minute_limit == 2


@respx.mock
def test_every_provider_request_passes_through_its_gatekeeper() -> None:
    """No provider may reach the network without the gatekeeper counting it."""
    respx.get(f"https://rdap.org/ip/{PUBLIC_IP}").mock(
        return_value=httpx.Response(200, json=RDAP_BODY)
    )
    gatekeeper = make_gatekeeper("whois")
    provider = RdapWhoisProvider(gatekeeper)

    assert gatekeeper.get_queue_status().requests_this_minute == 0
    for expected in (1, 2, 3):
        provider.lookup(PUBLIC_IP)
        assert gatekeeper.get_queue_status().requests_this_minute == expected


@respx.mock
def test_retries_are_applied_and_then_surface_as_an_error() -> None:
    route = respx.get(f"https://rdap.org/ip/{PUBLIC_IP}").mock(
        return_value=httpx.Response(503)
    )
    provider = RdapWhoisProvider(make_gatekeeper("whois", retry_attempts=2))

    result = provider.lookup(PUBLIC_IP)
    assert result.status is ProviderStatus.ERROR
    assert route.call_count == 3  # initial attempt plus two retries


def test_backpressure_rejects_when_the_queue_is_full() -> None:
    """A saturated queue must reject rather than grow without bound."""
    gatekeeper = ApiGatekeeper(
        service_name="tiny",
        config=ServiceRateLimitConfig(
            requests_per_minute=10,
            requests_per_day=100,
            max_queue_depth=1,
            retry_attempts=0,
            retry_backoff_base_seconds=0.01,
        ),
    )
    gatekeeper._queue.append(lambda: None)  # noqa: SLF001 - simulate a saturated queue

    with pytest.raises(GatekeeperError):
        gatekeeper.execute(lambda: None)


# --------------------------------------------------------------------------
# Factory
# --------------------------------------------------------------------------


def test_providers_are_only_built_when_their_bucket_is_configured() -> None:
    gatekeepers = {"ip_api": make_gatekeeper("ip_api")}
    providers = build_providers(gatekeepers)

    assert {p.name for p in providers} == {"ip_api_geo", "ip_api_asn"}
    assert all(p.gatekeeper is gatekeepers["ip_api"] for p in providers)


def test_no_gatekeepers_means_no_providers() -> None:
    assert build_providers({}) == []
    assert build_service({}).providers == []


def test_the_two_ip_api_providers_share_one_rate_limit_bucket() -> None:
    """They hit the same upstream host, so they must be limited together."""
    gatekeepers = {"ip_api": make_gatekeeper("ip_api")}
    providers = build_providers(gatekeepers)
    assert len({id(p.gatekeeper) for p in providers}) == 1


# --------------------------------------------------------------------------
# Background worker
# --------------------------------------------------------------------------


class _RecordingService(ThreatIntelService):
    """TI service double that records which alerts it was asked to enrich."""

    def __init__(self) -> None:
        super().__init__(providers=[])
        self.seen: list[Alert] = []

    def enrich_alert(self, alert: Alert) -> None:  # type: ignore[override]
        self.seen.append(alert)
        return None


def _alert(ip: str = PUBLIC_IP) -> Alert:
    return Alert(severity=Severity.HIGH, rule_triggered="R", description="d", dst_ip=ip)


def test_worker_drains_queued_alerts() -> None:
    service = _RecordingService()
    worker = EnrichmentWorker(service)

    for _ in range(3):
        assert worker.submit(_alert()) is True
    assert worker.queue_depth == 3

    assert worker.drain() == 3
    assert len(service.seen) == 3


def test_worker_drops_alerts_when_the_queue_is_full() -> None:
    worker = EnrichmentWorker(_RecordingService(), max_queue_depth=2)

    assert worker.submit(_alert()) is True
    assert worker.submit(_alert()) is True
    assert worker.submit(_alert()) is False  # dropped rather than unbounded growth
    assert worker.get_stats()["dropped"] == 1


def test_worker_runs_on_a_background_thread() -> None:
    service = _RecordingService()
    worker = EnrichmentWorker(service, poll_seconds=0.01)
    worker.start()
    try:
        worker.submit(_alert())
        for _ in range(200):
            if service.seen:
                break
            time.sleep(0.01)
        assert service.seen
    finally:
        worker.stop()
    assert worker.is_running is False


def test_worker_survives_an_enrichment_failure() -> None:
    class Exploding(ThreatIntelService):
        def enrich_alert(self, alert: Alert) -> None:  # type: ignore[override]
            raise RuntimeError("provider layer exploded")

    worker = EnrichmentWorker(Exploding(providers=[]))
    worker.submit(_alert())
    assert worker.drain() == 1  # must not propagate


def test_enrichment_never_blocks_the_alert_pipeline() -> None:
    """Alerts are persisted and returned before any enrichment happens."""
    service = _RecordingService()
    worker = EnrichmentWorker(service)
    alerts = AlertService(enrichment_sink=worker.submit)

    alert = alerts.handle_detection(
        DetectionAlert(
            detector_name="TcpPortScanDetector",
            severity=Severity.HIGH,
            description="scan",
            src_ip=PUBLIC_IP,
        )
    )

    assert alert is not None
    assert alerts.get_alert(alert.alert_id) is alert  # persisted already
    assert alert.threat_intel is None  # not yet enriched
    assert worker.queue_depth == 1  # queued for later

    worker.drain()
    assert service.seen == [alert]
