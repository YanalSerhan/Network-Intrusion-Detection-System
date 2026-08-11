"""Shared fixtures for threat intel tests."""

import pytest

from network_defender.shared.gatekeeper import ApiGatekeeper
from network_defender.shared.rate_limit_models import ServiceRateLimitConfig

#: httpx honours these by default (trust_env=True), which is what we want in
#: production behind a corporate proxy. In tests it means the client is built
#: against the developer's proxy before respx can intercept, so a machine with
#: ALL_PROXY set fails every provider test. Clear them for the duration.
_PROXY_ENV_VARS = (
    "HTTP_PROXY",
    "HTTPS_PROXY",
    "ALL_PROXY",
    "http_proxy",
    "https_proxy",
    "all_proxy",
)


@pytest.fixture(autouse=True)
def _no_proxy_env(monkeypatch: pytest.MonkeyPatch) -> None:
    """Ensure provider tests exercise respx rather than a real proxy."""
    for var in _PROXY_ENV_VARS:
        monkeypatch.delenv(var, raising=False)

#: A public address outside every special-purpose range, safe to use in tests.
PUBLIC_IP = "45.155.205.233"

ABUSEIPDB_BODY = {
    "data": {
        "ipAddress": PUBLIC_IP,
        "abuseConfidenceScore": 93,
        "totalReports": 271,
        "usageType": "Data Center",
        "isWhitelisted": False,
        "countryCode": "RU",
        "lastReportedAt": "2026-08-01T10:00:00+00:00",
    }
}

IP_API_GEO_BODY = {
    "status": "success",
    "country": "Russia",
    "countryCode": "RU",
    "regionName": "Moscow",
    "city": "Moscow",
    "lat": 55.75,
    "lon": 37.62,
    "timezone": "Europe/Moscow",
}

IP_API_ASN_BODY = {
    "status": "success",
    "as": "AS64512 EvilCorp Networks",
    "asname": "EVILCORP",
    "isp": "EvilCorp ISP",
    "org": "EvilCorp Holdings",
}

RDAP_BODY = {
    "name": "EVIL-NET",
    "handle": "NET-45-155-205-0-1",
    "port43": "whois.ripe.net",
    "cidr0_cidrs": [{"v4prefix": "45.155.205.0", "length": 24}],
    "events": [{"eventAction": "registration", "eventDate": "2015-06-01T00:00:00Z"}],
    "entities": [
        {"handle": "EVILCORP", "roles": ["registrant"]},
        {
            "handle": "ABUSE-EVIL",
            "roles": ["abuse"],
            "vcardArray": ["vcard", [["email", {}, "text", "abuse@evil.example"]]],
        },
    ],
}


def make_gatekeeper(
    name: str = "test",
    requests_per_minute: int = 1000,
    retry_attempts: int = 0,
    max_queue_depth: int = 50,
) -> ApiGatekeeper:
    """Build a permissive gatekeeper so provider tests are not rate-limited."""
    return ApiGatekeeper(
        service_name=name,
        config=ServiceRateLimitConfig(
            requests_per_minute=requests_per_minute,
            requests_per_day=100_000,
            max_queue_depth=max_queue_depth,
            retry_attempts=retry_attempts,
            retry_backoff_base_seconds=0.01,
        ),
    )


@pytest.fixture()
def gatekeeper() -> ApiGatekeeper:
    """A permissive gatekeeper for provider unit tests."""
    return make_gatekeeper()
