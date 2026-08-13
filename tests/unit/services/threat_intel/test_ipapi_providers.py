"""Tests for the ip-api.com geolocation and ASN providers."""

import httpx
import respx

from network_defender.constants import ProviderStatus
from network_defender.services.threat_intel.providers import (
    IpApiAsnProvider,
    IpApiGeolocationProvider,
)
from network_defender.shared.gatekeeper import ApiGatekeeper
from tests.fixtures.constants import PUBLIC_IP
from tests.fixtures.threat_intel import (
    IP_API_ASN_BODY,
    IP_API_GEO_BODY,
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
