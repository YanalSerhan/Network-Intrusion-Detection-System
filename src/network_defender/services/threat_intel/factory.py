"""
Provider assembly from configuration.

Data Setup:  Gatekeepers built from config/rate_limits.json; API keys from .env.
Data Input:  A mapping of service name -> ApiGatekeeper.
Data Output: A configured ThreatIntelService.

A provider is only constructed when its rate-limit bucket exists in
config/rate_limits.json. That keeps the gatekeeper mandatory by construction:
there is no code path that produces a provider without one, so ADR 3 cannot be
violated by forgetting to wire it up.
"""

from network_defender.constants import ENV_ABUSEIPDB_API_KEY
from network_defender.shared.gatekeeper import ApiGatekeeper
from network_defender.shared.secrets import get_secret

from .base import ThreatIntelProvider
from .providers import (
    AbuseIpDbProvider,
    IpApiAsnProvider,
    IpApiGeolocationProvider,
    RdapWhoisProvider,
)
from .service import ThreatIntelService

#: Provider class -> the rate-limit bucket it draws from. The two ip-api
#: providers deliberately share one bucket: they hit the same upstream host and
#: must be limited together, not twice over.
PROVIDER_BUCKETS: list[tuple[type[ThreatIntelProvider], str]] = [
    (AbuseIpDbProvider, "abuseipdb"),
    (IpApiGeolocationProvider, "ip_api"),
    (IpApiAsnProvider, "ip_api"),
    (RdapWhoisProvider, "whois"),
]


def build_providers(gatekeepers: dict[str, ApiGatekeeper]) -> list[ThreatIntelProvider]:
    """
    Construct every provider whose rate-limit bucket is configured.

    Args:
        gatekeepers: Gatekeepers keyed by service name, from the SDK.

    Returns:
        Provider instances in priority order. Providers whose bucket is missing
        from config/rate_limits.json are omitted.
    """
    api_keys: dict[type[ThreatIntelProvider], str | None] = {
        AbuseIpDbProvider: get_secret(ENV_ABUSEIPDB_API_KEY)
    }
    providers: list[ThreatIntelProvider] = []

    for provider_cls, bucket in PROVIDER_BUCKETS:
        gatekeeper = gatekeepers.get(bucket)
        if gatekeeper is None:
            continue
        providers.append(provider_cls(gatekeeper=gatekeeper, api_key=api_keys.get(provider_cls)))

    return providers


def build_service(gatekeepers: dict[str, ApiGatekeeper]) -> ThreatIntelService:
    """
    Build a ThreatIntelService with all configured providers.

    Args:
        gatekeepers: Gatekeepers keyed by service name, from the SDK.

    Returns:
        A ready-to-start ThreatIntelService.
    """
    return ThreatIntelService(providers=build_providers(gatekeepers))
