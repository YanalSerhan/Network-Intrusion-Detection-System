"""Tests for enrichment driven through the SDK: worker, status and partial results."""

from unittest.mock import MagicMock, patch

from network_defender.constants import ProviderStatus, Severity, ThreatVerdict
from network_defender.detectors.models import DetectionAlert
from network_defender.sdk.sdk import NetworkDefenderSDK
from network_defender.services.threat_intel.models import ProviderResult
from tests.fixtures.constants import PUBLIC_IP


def test_threat_intel_status_reports_providers_and_worker(
    enrichment_sdk: NetworkDefenderSDK,
) -> None:
    status = enrichment_sdk.get_threat_intel_status()

    assert set(status["providers"]) == {"ip_api_geo", "ip_api_asn", "whois"}
    assert status["providers"]["whois"]["circuit"] == "closed"
    assert status["worker"]["queue_depth"] == 0
    assert "cache" in status


def test_dropped_enrichment_is_counted_not_raised(enrichment_sdk: NetworkDefenderSDK) -> None:
    enrichment_sdk._enrichment_worker._queue.maxsize  # noqa: B018 - documents the bound exists
    with patch.object(enrichment_sdk._enrichment_worker, "submit", return_value=False) as submit:
        enrichment_sdk._on_detection(
            DetectionAlert(
                detector_name="TcpPortScanDetector",
                severity=Severity.HIGH,
                description="scan",
                src_ip=PUBLIC_IP,
            )
        )
    assert submit.called
    assert len(enrichment_sdk.list_alerts()) == 1  # the alert still exists


@patch("network_defender.capture.service.AsyncSniffer")
def test_lifecycle_starts_and_stops_the_worker(
    mock_sniffer: MagicMock, enrichment_sdk: NetworkDefenderSDK
) -> None:
    mock_sniffer.return_value = MagicMock()
    enrichment_sdk.start()
    try:
        assert enrichment_sdk._enrichment_worker.is_running
        assert enrichment_sdk._threat_intel_service.is_running
        assert enrichment_sdk.get_health()["components"]["threat_intel"]["running"] is True
    finally:
        enrichment_sdk.stop()
    assert enrichment_sdk._enrichment_worker.is_running is False


def test_a_failing_provider_still_yields_partial_enrichment(
    enrichment_sdk: NetworkDefenderSDK,
) -> None:
    """Fail-open: one dead provider must not lose the others' data."""
    whois = next(p for p in enrichment_sdk._threat_intel_service.providers if p.name == "whois")
    geo = next(p for p in enrichment_sdk._threat_intel_service.providers if p.name == "ip_api_geo")

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
        next(p for p in enrichment_sdk._threat_intel_service.providers if p.name == "ip_api_asn"),
        "lookup",
        return_value=ProviderResult(provider="ip_api_asn", status=ProviderStatus.ERROR),
    ):
        result = enrichment_sdk.enrich_ip(PUBLIC_IP)

    assert result.verdict is ThreatVerdict.MALICIOUS
    assert result.is_partial is True
    assert "whois" in result.providers_failed
