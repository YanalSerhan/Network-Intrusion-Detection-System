"""Tests for the SDK threat-intel surface and end-to-end enrichment."""

from unittest.mock import MagicMock, patch
from uuid import uuid4

import httpx
import pytest
import respx

from network_defender.constants import ProviderStatus, Severity, ThreatVerdict
from network_defender.detectors.models import DetectionAlert
from network_defender.sdk.sdk import NetworkDefenderSDK
from network_defender.services.threat_intel.models import ProviderResult
from network_defender.shared.config_models import AppConfig, CaptureConfig
from network_defender.shared.rate_limit_models import RateLimitConfig, ServiceRateLimitConfig
from tests.fixtures.constants import PUBLIC_IP
from tests.fixtures.threat_intel import (
    IP_API_ASN_BODY,
    IP_API_GEO_BODY,
    RDAP_BODY,
)


def _rate_limits() -> RateLimitConfig:
    limits = ServiceRateLimitConfig(
        requests_per_minute=1000,
        requests_per_day=100_000,
        max_queue_depth=50,
        retry_attempts=0,
        retry_backoff_base_seconds=0.01,
    )
    return RateLimitConfig(services={"ip_api": limits, "whois": limits})


@pytest.fixture()
def sdk() -> NetworkDefenderSDK:
    cfg = AppConfig(capture=CaptureConfig(interface="eth0", max_packets_per_second=0))
    return NetworkDefenderSDK(app_config=cfg, rate_limit_config=_rate_limits())


def _mock_upstreams() -> None:
    """Route both ip-api field sets and RDAP to canned bodies."""

    def ip_api(request: httpx.Request) -> httpx.Response:
        fields = request.url.params.get("fields", "")
        return httpx.Response(200, json=IP_API_ASN_BODY if "asname" in fields else IP_API_GEO_BODY)

    respx.get(f"http://ip-api.com/json/{PUBLIC_IP}").mock(side_effect=ip_api)
    respx.get(f"https://rdap.org/ip/{PUBLIC_IP}").mock(
        return_value=httpx.Response(200, json=RDAP_BODY)
    )


def test_only_configured_providers_are_built(sdk: NetworkDefenderSDK) -> None:
    """abuseipdb has no rate-limit bucket here, so it must not be constructed."""
    names = {p.name for p in sdk._threat_intel_service.providers}
    assert names == {"ip_api_geo", "ip_api_asn", "whois"}


@respx.mock
def test_enrich_ip_through_the_sdk(sdk: NetworkDefenderSDK) -> None:
    _mock_upstreams()
    result = sdk.enrich_ip(PUBLIC_IP)

    assert result.geo is not None and result.geo.country == "Russia"
    assert result.asn is not None and result.asn.asn == "AS64512"
    assert result.whois is not None and result.whois.abuse_email == "abuse@evil.example"
    assert result.is_partial is False


def test_enrich_ip_skips_private_addresses(sdk: NetworkDefenderSDK) -> None:
    assert sdk.enrich_ip("192.168.1.50").verdict is ThreatVerdict.UNKNOWN


@respx.mock
def test_alerts_are_enriched_off_the_hot_path(sdk: NetworkDefenderSDK) -> None:
    _mock_upstreams()
    detection = DetectionAlert(
        detector_name="TcpPortScanDetector",
        severity=Severity.HIGH,
        description="scan",
        src_ip=PUBLIC_IP,
        evidence={"unique_ports": 60},
    )

    sdk._on_detection(detection)
    alert_id = sdk.list_alerts()[0].alert_id
    assert sdk.get_alert(alert_id).threat_intel is None, "enrichment must not run inline"

    sdk._enrichment_worker.drain()

    # Re-read: the repository returns a snapshot, so enrichment is observed by
    # querying again rather than by mutation of an object fetched earlier.
    enriched = sdk.get_alert(alert_id)
    assert enriched is not None
    assert enriched.threat_intel is not None
    assert enriched.threat_intel.geo is not None
    assert enriched.threat_intel.geo.country == "Russia"


def test_enrich_alert_now_for_an_unknown_id(sdk: NetworkDefenderSDK) -> None:
    assert sdk.enrich_alert_now(uuid4()) is None


@respx.mock
def test_enrich_alert_now_persists_the_updated_record(sdk: NetworkDefenderSDK) -> None:
    _mock_upstreams()
    sdk._on_detection(
        DetectionAlert(
            detector_name="TcpPortScanDetector",
            severity=Severity.HIGH,
            description="scan",
            src_ip=PUBLIC_IP,
        )
    )
    alert_id = sdk.list_alerts()[0].alert_id

    result = sdk.enrich_alert_now(alert_id)
    assert result is not None

    stored = sdk.get_alert(alert_id)
    assert stored is not None and stored.threat_intel is not None


def test_internal_only_alert_returns_none_from_enrich_now(sdk: NetworkDefenderSDK) -> None:
    sdk._on_detection(
        DetectionAlert(
            detector_name="LateralMovementDetector",
            severity=Severity.HIGH,
            description="lateral",
            src_ip="10.0.0.5",
            dst_ip="10.0.0.9",
        )
    )
    alert_id = sdk.list_alerts()[0].alert_id
    assert sdk.enrich_alert_now(alert_id) is None


def test_threat_intel_status_reports_providers_and_worker(sdk: NetworkDefenderSDK) -> None:
    status = sdk.get_threat_intel_status()

    assert set(status["providers"]) == {"ip_api_geo", "ip_api_asn", "whois"}
    assert status["providers"]["whois"]["circuit"] == "closed"
    assert status["worker"]["queue_depth"] == 0
    assert "cache" in status


def test_dropped_enrichment_is_counted_not_raised(sdk: NetworkDefenderSDK) -> None:
    sdk._enrichment_worker._queue.maxsize  # noqa: B018 - documents the bound exists
    with patch.object(sdk._enrichment_worker, "submit", return_value=False) as submit:
        sdk._on_detection(
            DetectionAlert(
                detector_name="TcpPortScanDetector",
                severity=Severity.HIGH,
                description="scan",
                src_ip=PUBLIC_IP,
            )
        )
    assert submit.called
    assert len(sdk.list_alerts()) == 1  # the alert still exists


@patch("network_defender.capture.service.AsyncSniffer")
def test_lifecycle_starts_and_stops_the_worker(
    mock_sniffer: MagicMock, sdk: NetworkDefenderSDK
) -> None:
    mock_sniffer.return_value = MagicMock()
    sdk.start()
    try:
        assert sdk._enrichment_worker.is_running
        assert sdk._threat_intel_service.is_running
        assert sdk.get_health()["components"]["threat_intel"]["running"] is True
    finally:
        sdk.stop()
    assert sdk._enrichment_worker.is_running is False


def test_a_failing_provider_still_yields_partial_enrichment(sdk: NetworkDefenderSDK) -> None:
    """Fail-open: one dead provider must not lose the others' data."""
    whois = next(p for p in sdk._threat_intel_service.providers if p.name == "whois")
    geo = next(p for p in sdk._threat_intel_service.providers if p.name == "ip_api_geo")

    with patch.object(
        whois,
        "lookup",
        return_value=ProviderResult(provider="whois", status=ProviderStatus.ERROR, error="503"),
    ), patch.object(
        geo,
        "lookup",
        return_value=ProviderResult(
            provider="ip_api_geo", status=ProviderStatus.OK, reputation_score=70.0
        ),
    ), patch.object(
        next(p for p in sdk._threat_intel_service.providers if p.name == "ip_api_asn"),
        "lookup",
        return_value=ProviderResult(provider="ip_api_asn", status=ProviderStatus.ERROR),
    ):
        result = sdk.enrich_ip(PUBLIC_IP)

    assert result.verdict is ThreatVerdict.MALICIOUS
    assert result.is_partial is True
    assert "whois" in result.providers_failed
