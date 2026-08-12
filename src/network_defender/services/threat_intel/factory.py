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
from network_defender.shared.config_models import ThreatIntelConfig
from network_defender.shared.gatekeeper import ApiGatekeeper
from network_defender.shared.secrets import get_secret

from .base import ThreatIntelProvider
from .cache import ThreatIntelCache
from .circuit_breaker import CircuitBreaker
from .providers import (
    AbuseIpDbProvider,
    IpApiAsnProvider,
    IpApiGeolocationProvider,
    RdapWhoisProvider,
)
from .service import ThreatIntelService

#: Provider class -> (config name, rate-limit bucket). The two ip-api providers
#: deliberately share one bucket: they hit the same upstream host and must be
#: limited together, not twice over.
PROVIDER_BUCKETS: list[tuple[type[ThreatIntelProvider], str, str]] = [
    (AbuseIpDbProvider, "abuseipdb", "abuseipdb"),
    (IpApiGeolocationProvider, "ip_api_geo", "ip_api"),
    (IpApiAsnProvider, "ip_api_asn", "ip_api"),
    (RdapWhoisProvider, "whois", "whois"),
]


def build_providers(
    gatekeepers: dict[str, ApiGatekeeper],
    config: ThreatIntelConfig | None = None,
) -> list[ThreatIntelProvider]:
    """
    Construct every provider that is both enabled and rate-limited.

    Two independent gates, deliberately. Configuration says which providers an
    operator wants; the rate-limit file says which have a budget. A provider
    missing a bucket is skipped even if enabled, so ADR 3 cannot be violated by
    adding a provider and forgetting its limits.

    Args:
        gatekeepers: Gatekeepers keyed by service name, from the SDK.
        config:      Threat intel settings; defaults are used if omitted.

    Returns:
        Provider instances in priority order.
    """
    settings = config or ThreatIntelConfig()
    if not settings.enabled:
        return []

    api_keys: dict[type[ThreatIntelProvider], str | None] = {
        AbuseIpDbProvider: get_secret(ENV_ABUSEIPDB_API_KEY)
    }
    providers: list[ThreatIntelProvider] = []

    for provider_cls, name, bucket in PROVIDER_BUCKETS:
        gatekeeper = gatekeepers.get(bucket)
        if gatekeeper is None or name not in settings.providers:
            continue
        providers.append(
            provider_cls(
                gatekeeper=gatekeeper,
                api_key=api_keys.get(provider_cls),
                timeout=settings.http_timeout_seconds,
            )
        )

    return providers


def build_service(
    gatekeepers: dict[str, ApiGatekeeper],
    config: ThreatIntelConfig | None = None,
) -> ThreatIntelService:
    """
    Build a ThreatIntelService with all configured providers.

    Cache TTL and breaker thresholds come from config rather than constants, so
    an operator can widen the cache or make a flaky provider trip sooner
    without a code change.

    Args:
        gatekeepers: Gatekeepers keyed by service name, from the SDK.
        config:      Threat intel settings; defaults are used if omitted.

    Returns:
        A ready-to-start ThreatIntelService.
    """
    settings = config or ThreatIntelConfig()
    providers = build_providers(gatekeepers, settings)

    service = ThreatIntelService(
        providers=providers,
        cache=ThreatIntelCache(
            ttl_seconds=settings.cache_ttl_seconds,
            max_entries=settings.cache_max_entries,
        ),
        enrich_private_ips=settings.enrich_private_ips,
    )
    service.breakers = {
        provider.name: CircuitBreaker(
            failure_threshold=settings.breaker_failure_threshold,
            reset_seconds=settings.breaker_reset_seconds,
        )
        for provider in providers
    }
    return service
