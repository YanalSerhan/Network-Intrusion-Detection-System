"""Tests for the SDK threat-intel surface: provider construction and lookups."""

from uuid import uuid4

import respx

from network_defender.constants import Severity, ThreatVerdict
from network_defender.detectors.models import DetectionAlert
from network_defender.sdk.sdk import NetworkDefenderSDK
from tests.fixtures.constants import PUBLIC_IP
from tests.fixtures.threat_intel import mock_upstreams


def test_only_configured_providers_are_built(enrichment_sdk: NetworkDefenderSDK) -> None:
    """abuseipdb has no rate-limit bucket here, so it must not be constructed."""
    names = {p.name for p in enrichment_sdk._threat_intel_service.providers}
    assert names == {"ip_api_geo", "ip_api_asn", "whois"}


@respx.mock
def test_enrich_ip_through_the_sdk(enrichment_sdk: NetworkDefenderSDK) -> None:
    mock_upstreams()
    result = enrichment_sdk.enrich_ip(PUBLIC_IP)

    assert result.geo is not None and result.geo.country == "Russia"
    assert result.asn is not None and result.asn.asn == "AS64512"
    assert result.whois is not None and result.whois.abuse_email == "abuse@evil.example"
    assert result.is_partial is False


def test_enrich_ip_skips_private_addresses(enrichment_sdk: NetworkDefenderSDK) -> None:
    assert enrichment_sdk.enrich_ip("192.168.1.50").verdict is ThreatVerdict.UNKNOWN


@respx.mock
def test_alerts_are_enriched_off_the_hot_path(enrichment_sdk: NetworkDefenderSDK) -> None:
    mock_upstreams()
    detection = DetectionAlert(
        detector_name="TcpPortScanDetector",
        severity=Severity.HIGH,
        description="scan",
        src_ip=PUBLIC_IP,
        evidence={"unique_ports": 60},
    )

    enrichment_sdk._on_detection(detection)
    alert_id = enrichment_sdk.list_alerts()[0].alert_id
    assert enrichment_sdk.get_alert(alert_id).threat_intel is None, "enrichment must not run inline"

    enrichment_sdk._enrichment_worker.drain()

    # Re-read: the repository returns a snapshot, so enrichment is observed by
    # querying again rather than by mutation of an object fetched earlier.
    enriched = enrichment_sdk.get_alert(alert_id)
    assert enriched is not None
    assert enriched.threat_intel is not None
    assert enriched.threat_intel.geo is not None
    assert enriched.threat_intel.geo.country == "Russia"


def test_enrich_alert_now_for_an_unknown_id(enrichment_sdk: NetworkDefenderSDK) -> None:
    assert enrichment_sdk.enrich_alert_now(uuid4()) is None


@respx.mock
def test_enrich_alert_now_persists_the_updated_record(enrichment_sdk: NetworkDefenderSDK) -> None:
    mock_upstreams()
    enrichment_sdk._on_detection(
        DetectionAlert(
            detector_name="TcpPortScanDetector",
            severity=Severity.HIGH,
            description="scan",
            src_ip=PUBLIC_IP,
        )
    )
    alert_id = enrichment_sdk.list_alerts()[0].alert_id

    result = enrichment_sdk.enrich_alert_now(alert_id)
    assert result is not None

    stored = enrichment_sdk.get_alert(alert_id)
    assert stored is not None and stored.threat_intel is not None


def test_internal_only_alert_returns_none_from_enrich_now(
    enrichment_sdk: NetworkDefenderSDK,
) -> None:
    enrichment_sdk._on_detection(
        DetectionAlert(
            detector_name="LateralMovementDetector",
            severity=Severity.HIGH,
            description="lateral",
            src_ip="10.0.0.5",
            dst_ip="10.0.0.9",
        )
    )
    alert_id = enrichment_sdk.list_alerts()[0].alert_id
    assert enrichment_sdk.enrich_alert_now(alert_id) is None
