"""Tests for the RDAP registration-data provider."""

import httpx
import respx

from network_defender.constants import ProviderStatus
from network_defender.services.threat_intel.providers import (
    RdapWhoisProvider,
)
from network_defender.shared.gatekeeper import ApiGatekeeper
from tests.fixtures.constants import PUBLIC_IP
from tests.fixtures.threat_intel import (
    RDAP_BODY,
)

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
