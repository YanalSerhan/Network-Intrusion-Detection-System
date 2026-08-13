"""Tests for the failure contract every provider must honour."""

import httpx
import pytest
import respx

from network_defender.constants import ProviderStatus
from network_defender.services.threat_intel.providers import (
    IpApiAsnProvider,
    IpApiGeolocationProvider,
    RdapWhoisProvider,
)
from network_defender.shared.gatekeeper import ApiGatekeeper
from tests.fixtures.constants import PUBLIC_IP

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
