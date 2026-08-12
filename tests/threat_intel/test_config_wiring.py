"""
Regression tests: configuration options must actually take effect.

`enrich_private_ips` and `http_timeout_seconds` were declared in the config
model and documented in CONFIGURATION.md, but nothing read them. Setting either
did nothing — the worst kind of configuration bug, because the operator has
every reason to believe it worked.
"""

import httpx
import pytest
import respx

from network_defender.constants import ProviderStatus
from network_defender.services.threat_intel.eligibility import eligible_ips
from network_defender.services.threat_intel.factory import build_providers, build_service
from network_defender.shared.config_models import ThreatIntelConfig

from .conftest import PUBLIC_IP, make_gatekeeper

PRIVATE_IP = "10.0.0.5"


def _gatekeepers() -> dict[str, object]:
    return {name: make_gatekeeper(name) for name in ("abuseipdb", "ip_api", "whois")}


# --------------------------------------------------------------------------
# http_timeout_seconds
# --------------------------------------------------------------------------


def test_configured_timeout_reaches_every_provider() -> None:
    config = ThreatIntelConfig(http_timeout_seconds=3.5)
    providers = build_providers(_gatekeepers(), config)  # type: ignore[arg-type]

    assert providers
    assert all(provider.timeout == 3.5 for provider in providers)


@respx.mock
def test_configured_timeout_is_used_on_the_request() -> None:
    """The setting is meaningless unless it reaches the HTTP call."""
    route = respx.get(f"https://rdap.org/ip/{PUBLIC_IP}").mock(
        return_value=httpx.Response(200, json={"name": "NET"})
    )
    config = ThreatIntelConfig(http_timeout_seconds=2.0, providers=["whois"])
    provider = build_providers(_gatekeepers(), config)[0]  # type: ignore[arg-type]

    provider.lookup(PUBLIC_IP)

    assert route.called
    assert route.calls.last.request.extensions["timeout"]["connect"] == 2.0


# --------------------------------------------------------------------------
# enrich_private_ips
# --------------------------------------------------------------------------


def test_private_addresses_are_skipped_by_default() -> None:
    service = build_service(_gatekeepers(), ThreatIntelConfig())  # type: ignore[arg-type]
    result = service.enrich_ip(PRIVATE_IP)

    assert result.providers_queried == []
    assert service.health_check()["skipped_private_ips"] == 1


def test_opting_in_enriches_private_addresses() -> None:
    config = ThreatIntelConfig(enrich_private_ips=True, providers=["whois"])
    service = build_service(_gatekeepers(), config)  # type: ignore[arg-type]

    assert service.enrich_private_ips is True
    assert service.enrich_ip(PRIVATE_IP).providers_queried == ["whois"]


def test_opting_in_does_not_accept_malformed_addresses() -> None:
    """Opting in relaxes the privacy rule, not input validation."""
    config = ThreatIntelConfig(enrich_private_ips=True, providers=["whois"])
    service = build_service(_gatekeepers(), config)  # type: ignore[arg-type]

    assert service.enrich_ip("not-an-ip").providers_queried == []


@pytest.mark.parametrize(
    ("include_private", "expected"),
    [(False, [PUBLIC_IP]), (True, [PRIVATE_IP, PUBLIC_IP])],
)
def test_eligibility_respects_the_flag(include_private: bool, expected: list[str]) -> None:
    assert (
        eligible_ips(PRIVATE_IP, PUBLIC_IP, include_private=include_private) == expected
    )


def test_eligibility_still_refuses_junk_when_opted_in() -> None:
    assert eligible_ips("garbage", "", None, include_private=True) == []


# --------------------------------------------------------------------------
# Other settings reaching their destination
# --------------------------------------------------------------------------


def test_cache_and_breaker_settings_are_applied() -> None:
    config = ThreatIntelConfig(
        cache_ttl_seconds=60.0,
        cache_max_entries=7,
        breaker_failure_threshold=2,
        breaker_reset_seconds=30.0,
        providers=["whois"],
    )
    service = build_service(_gatekeepers(), config)  # type: ignore[arg-type]

    assert service.cache._ttl == 60.0  # noqa: SLF001 - asserting configuration landed
    assert service.cache._max_entries == 7  # noqa: SLF001
    assert service.breakers["whois"]._threshold == 2  # noqa: SLF001
    assert service.breakers["whois"]._reset_seconds == 30.0  # noqa: SLF001


def test_disabling_enrichment_builds_no_providers() -> None:
    service = build_service(_gatekeepers(), ThreatIntelConfig(enabled=False))  # type: ignore[arg-type]
    assert service.providers == []


def test_provider_list_selects_which_are_built() -> None:
    config = ThreatIntelConfig(providers=["whois", "ip_api_geo"])
    names = {p.name for p in build_providers(_gatekeepers(), config)}  # type: ignore[arg-type]
    assert names == {"whois", "ip_api_geo"}


def test_a_provider_without_a_rate_limit_bucket_is_not_built() -> None:
    """Enabled in config but unbudgeted must not bypass the gatekeeper (ADR 3)."""
    config = ThreatIntelConfig(providers=["whois", "abuseipdb"])
    names = {p.name for p in build_providers({"whois": make_gatekeeper("whois")}, config)}
    assert names == {"whois"}
