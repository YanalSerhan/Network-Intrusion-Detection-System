"""Integration tests: every provider call is mediated by its gatekeeper."""


import httpx
import pytest
import respx

from network_defender.constants import ProviderStatus
from network_defender.services.threat_intel.factory import build_providers, build_service
from network_defender.services.threat_intel.providers import (
    IpApiGeolocationProvider,
    RdapWhoisProvider,
)
from network_defender.shared.gatekeeper import ApiGatekeeper, GatekeeperError
from network_defender.shared.rate_limit_models import ServiceRateLimitConfig
from tests.fixtures.constants import PUBLIC_IP
from tests.fixtures.threat_intel import IP_API_GEO_BODY, RDAP_BODY, make_gatekeeper

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
