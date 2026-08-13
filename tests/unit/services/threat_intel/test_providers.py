"""Provider unit tests with mocked HTTP responses.

Mocking is done at the transport layer with respx rather than by patching our
own helper, so the tests exercise real URL construction, query parameters,
auth headers, status handling and JSON decoding.
"""

import httpx
import pytest
import respx

from network_defender.constants import ProviderStatus
from network_defender.services.threat_intel.providers import (
    AbuseIpDbProvider,
    IpApiAsnProvider,
    IpApiGeolocationProvider,
    RdapWhoisProvider,
)
from network_defender.shared.gatekeeper import ApiGatekeeper
from tests.fixtures.constants import PUBLIC_IP
from tests.fixtures.threat_intel import (
    ABUSEIPDB_BODY,
    IP_API_ASN_BODY,
    IP_API_GEO_BODY,
    RDAP_BODY,
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


# --------------------------------------------------------------------------
# ip-api.com
# --------------------------------------------------------------------------


@respx.mock
def test_geolocation_provider_parses_location(gatekeeper: ApiGatekeeper) -> None:
    respx.get(f"http://ip-api.com/json/{PUBLIC_IP}").mock(
        return_value=httpx.Response(200, json=IP_API_GEO_BODY)
    )
    result = IpApiGeolocationProvider(gatekeeper).lookup(PUBLIC_IP)

    assert result.status is ProviderStatus.OK
    assert result.geo is not None
    assert result.geo.country == "Russia"
    assert result.geo.city == "Moscow"
    assert result.geo.latitude == 55.75


@respx.mock
def test_asn_provider_strips_the_as_description(gatekeeper: ApiGatekeeper) -> None:
    respx.get(f"http://ip-api.com/json/{PUBLIC_IP}").mock(
        return_value=httpx.Response(200, json=IP_API_ASN_BODY)
    )
    result = IpApiAsnProvider(gatekeeper).lookup(PUBLIC_IP)

    assert result.asn is not None
    assert result.asn.asn == "AS64512"  # not "AS64512 EvilCorp Networks"
    assert result.asn.organisation == "EVILCORP"
    assert result.asn.isp == "EvilCorp ISP"


@respx.mock
def test_ip_api_failure_status_is_an_error(gatekeeper: ApiGatekeeper) -> None:
    """ip-api returns HTTP 200 with status='fail' for bad input."""
    respx.get(f"http://ip-api.com/json/{PUBLIC_IP}").mock(
        return_value=httpx.Response(200, json={"status": "fail", "message": "reserved range"})
    )
    result = IpApiGeolocationProvider(gatekeeper).lookup(PUBLIC_IP)

    assert result.status is ProviderStatus.ERROR
    assert result.error is not None and "reserved range" in result.error


@respx.mock
def test_geo_and_asn_request_different_field_sets(gatekeeper: ApiGatekeeper) -> None:
    route = respx.get(f"http://ip-api.com/json/{PUBLIC_IP}").mock(
        return_value=httpx.Response(200, json=IP_API_GEO_BODY)
    )
    IpApiGeolocationProvider(gatekeeper).lookup(PUBLIC_IP)
    IpApiAsnProvider(gatekeeper).lookup(PUBLIC_IP)

    geo_url, asn_url = (str(call.request.url) for call in route.calls)
    assert "city" in geo_url and "city" not in asn_url
    assert "asname" in asn_url and "asname" not in geo_url


# --------------------------------------------------------------------------
# RDAP / WHOIS
# --------------------------------------------------------------------------


@respx.mock
def test_rdap_parses_registration_data(gatekeeper: ApiGatekeeper) -> None:
    respx.get(f"https://rdap.org/ip/{PUBLIC_IP}").mock(
        return_value=httpx.Response(200, json=RDAP_BODY)
    )
    result = RdapWhoisProvider(gatekeeper).lookup(PUBLIC_IP)

    assert result.status is ProviderStatus.OK
    assert result.whois is not None
    assert result.whois.network_name == "EVIL-NET"
    assert result.whois.cidr == "45.155.205.0/24"
    assert result.whois.abuse_email == "abuse@evil.example"
    assert result.whois.registered_on == "2015-06-01T00:00:00Z"


@respx.mock
def test_rdap_falls_back_to_the_address_range(gatekeeper: ApiGatekeeper) -> None:
    body = {"startAddress": "45.155.205.0", "endAddress": "45.155.205.255"}
    respx.get(f"https://rdap.org/ip/{PUBLIC_IP}").mock(
        return_value=httpx.Response(200, json=body)
    )
    result = RdapWhoisProvider(gatekeeper).lookup(PUBLIC_IP)

    assert result.whois is not None
    assert result.whois.cidr == "45.155.205.0 - 45.155.205.255"


@respx.mock
def test_rdap_tolerates_a_sparse_body(gatekeeper: ApiGatekeeper) -> None:
    respx.get(f"https://rdap.org/ip/{PUBLIC_IP}").mock(
        return_value=httpx.Response(200, json={})
    )
    result = RdapWhoisProvider(gatekeeper).lookup(PUBLIC_IP)

    assert result.status is ProviderStatus.OK
    assert result.whois is not None
    assert result.whois.abuse_email is None


# --------------------------------------------------------------------------
# Shared failure contract
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("provider_cls", "url"),
    [
        (IpApiGeolocationProvider, f"http://ip-api.com/json/{PUBLIC_IP}"),
        (IpApiAsnProvider, f"http://ip-api.com/json/{PUBLIC_IP}"),
        (RdapWhoisProvider, f"https://rdap.org/ip/{PUBLIC_IP}"),
    ],
)
@respx.mock
def test_providers_never_raise_on_transport_failure(
    provider_cls: type, url: str, gatekeeper: ApiGatekeeper
) -> None:
    respx.get(url).mock(side_effect=httpx.ConnectError("network unreachable"))
    result = provider_cls(gatekeeper).lookup(PUBLIC_IP)

    assert result.status is ProviderStatus.ERROR
    assert result.error


@respx.mock
def test_providers_never_raise_on_malformed_json(gatekeeper: ApiGatekeeper) -> None:
    respx.get(f"https://rdap.org/ip/{PUBLIC_IP}").mock(
        return_value=httpx.Response(200, content=b"<html>not json</html>")
    )
    assert RdapWhoisProvider(gatekeeper).lookup(PUBLIC_IP).status is ProviderStatus.ERROR


@respx.mock
def test_providers_reject_a_non_object_json_body(gatekeeper: ApiGatekeeper) -> None:
    respx.get(f"https://rdap.org/ip/{PUBLIC_IP}").mock(
        return_value=httpx.Response(200, json=["unexpected", "list"])
    )
    assert RdapWhoisProvider(gatekeeper).lookup(PUBLIC_IP).status is ProviderStatus.ERROR
