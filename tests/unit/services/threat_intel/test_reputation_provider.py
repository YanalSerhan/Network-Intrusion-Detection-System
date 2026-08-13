"""Tests for the AbuseIPDB reputation provider."""

import httpx
import respx

from network_defender.constants import ProviderStatus
from network_defender.services.threat_intel.providers import (
    AbuseIpDbProvider,
)
from network_defender.shared.gatekeeper import ApiGatekeeper
from tests.fixtures.constants import PUBLIC_IP
from tests.fixtures.threat_intel import (
    ABUSEIPDB_BODY,
)

# --------------------------------------------------------------------------
# AbuseIPDB
# --------------------------------------------------------------------------


@respx.mock
def test_abuseipdb_parses_confidence_score(gatekeeper: ApiGatekeeper) -> None:
    route = respx.get("https://api.abuseipdb.com/api/v2/check").mock(
        return_value=httpx.Response(200, json=ABUSEIPDB_BODY)
    )
    result = AbuseIpDbProvider(gatekeeper, api_key="test-key").lookup(PUBLIC_IP)

    assert result.status is ProviderStatus.OK
    assert result.reputation_score == 93.0
    assert result.raw["total_reports"] == 271
    assert route.calls.last.request.headers["Key"] == "test-key"
    assert f"ipAddress={PUBLIC_IP}" in str(route.calls.last.request.url)


@respx.mock
def test_abuseipdb_is_skipped_without_a_key(gatekeeper: ApiGatekeeper) -> None:
    route = respx.get("https://api.abuseipdb.com/api/v2/check")
    result = AbuseIpDbProvider(gatekeeper).lookup(PUBLIC_IP)

    assert result.status is ProviderStatus.SKIPPED
    assert not route.called, "no request should be made without a key"


@respx.mock
def test_abuseipdb_handles_unauthorised(gatekeeper: ApiGatekeeper) -> None:
    respx.get("https://api.abuseipdb.com/api/v2/check").mock(
        return_value=httpx.Response(401, json={"errors": []})
    )
    result = AbuseIpDbProvider(gatekeeper, api_key="bad").lookup(PUBLIC_IP)

    assert result.status is ProviderStatus.ERROR
    assert result.reputation_score is None


@respx.mock
def test_abuseipdb_handles_a_body_without_data(gatekeeper: ApiGatekeeper) -> None:
    respx.get("https://api.abuseipdb.com/api/v2/check").mock(
        return_value=httpx.Response(200, json={"unexpected": True})
    )
    assert AbuseIpDbProvider(gatekeeper, api_key="k").lookup(PUBLIC_IP).status is (
        ProviderStatus.ERROR
    )
