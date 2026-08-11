"""
The guarded lookup path for a single provider.

Data Setup:  Provider, cache and breaker supplied by the caller.
Data Input:  A public IP address.
Data Output: A ProviderResult, never an exception.

Order of the guards matters:

  1. **not configured** — skip before spending anything; a keyless provider
     would only earn a 401 and three retries.
  2. **cache** — checked before the breaker, so a tripped circuit still serves
     data already known to be good.
  3. **breaker** — short-circuits a provider that is failing, turning a
     multi-second timeout chain into an immediate skip.
  4. **provider** — which internally routes through the ApiGatekeeper.
"""

from network_defender.constants import ProviderStatus

from .base import ThreatIntelProvider
from .cache import ThreatIntelCache
from .circuit_breaker import CircuitBreaker
from .models import ProviderResult


def query_provider(
    provider: ThreatIntelProvider,
    ip: str,
    cache: ThreatIntelCache,
    breaker: CircuitBreaker,
) -> ProviderResult:
    """
    Look an address up via one provider, honouring cache and breaker state.

    Args:
        provider: The provider to consult.
        ip:       A public IP address.
        cache:    Shared TTL response cache.
        breaker:  The breaker guarding this provider.

    Returns:
        A ProviderResult — successful, cached, skipped, or a contained failure.
    """
    if not provider.is_configured:
        return ProviderResult(
            provider=provider.name,
            status=ProviderStatus.SKIPPED,
            error="Provider is not configured.",
        )

    cached = cache.get(provider.name, ip)
    if cached is not None:
        return cached

    if not breaker.allows_request():
        return ProviderResult(
            provider=provider.name,
            status=ProviderStatus.CIRCUIT_OPEN,
            error="Circuit breaker is open for this provider.",
        )

    result = provider.lookup(ip)
    if result.succeeded:
        breaker.record_success()
        cache.set(provider.name, ip, result)
    else:
        breaker.record_failure()
    return result
