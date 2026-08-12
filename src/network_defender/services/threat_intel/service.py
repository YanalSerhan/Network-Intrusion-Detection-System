"""
ThreatIntelService — orchestrates providers, cache and circuit breakers.

Data Setup:  Providers injected via __init__ (or built by `from_gatekeepers`);
             cache and per-provider breakers created alongside them.
Data Input:  IP addresses, and Alerts to enrich.
Data Output: ThreatIntelResult records, attached to alerts by the caller.

Lookup path for each provider:
    eligible? -> cache hit? -> breaker closed? -> gatekeeper -> provider

Every stage can short-circuit, and every failure is contained: the service
returns a partial ThreatIntelResult rather than raising, so a dead provider
degrades enrichment instead of suppressing alerts.
"""

from typing import TYPE_CHECKING, Any

from network_defender.shared.base import BaseService

from .aggregation import aggregate
from .base import ThreatIntelProvider
from .cache import ThreatIntelCache
from .circuit_breaker import CircuitBreaker
from .eligibility import eligible_ips, is_eligible
from .models import ProviderResult, ThreatIntelResult
from .query import query_provider

if TYPE_CHECKING:  # Import for typing only: Alert already imports our models.
    from network_defender.services.alerts.models import Alert


class ThreatIntelService(BaseService):
    """Enriches IP addresses with reputation, geolocation, ASN and WHOIS data."""

    def __init__(
        self,
        providers: list[ThreatIntelProvider] | None = None,
        cache: ThreatIntelCache | None = None,
        enrich_private_ips: bool = False,
    ) -> None:
        """
        Initialise the service.

        Args:
            providers:          Provider adapters to consult, in priority order.
            cache:              Shared response cache; a default is used if omitted.
            enrich_private_ips: Send private addresses to third parties. Off by
                default, because it leaks internal topology and no feed has an
                opinion on RFC1918 space.
        """
        super().__init__(service_name="ThreatIntelService")
        self.providers = providers or []
        self.cache = cache or ThreatIntelCache()
        self.enrich_private_ips = enrich_private_ips
        self.breakers = {provider.name: CircuitBreaker() for provider in self.providers}
        self._lookups = 0
        self._skipped = 0

    def _do_start(self) -> None:
        """Reset breakers so a restart never inherits a tripped circuit."""
        for breaker in self.breakers.values():
            breaker.reset()
        configured = [p.name for p in self.providers if p.is_configured]
        self.logger.info("ThreatIntelService started with providers: %s", configured)

    def _do_stop(self) -> None:
        """Drop cached responses on shutdown."""
        self.cache.clear()
        self.logger.info("ThreatIntelService stopped.")

    def _do_health_check(self) -> dict[str, Any]:
        """Report provider availability, breaker states and cache efficiency."""
        return {
            "providers": {
                provider.name: {
                    "configured": provider.is_configured,
                    "circuit": self.breakers[provider.name].state,
                }
                for provider in self.providers
            },
            "lookups": self._lookups,
            "skipped_private_ips": self._skipped,
            "cache": self.cache.get_stats(),
            "status": "ok" if self.providers else "degraded",
        }

    # ------------------------------------------------------------------
    # Enrichment
    # ------------------------------------------------------------------

    def enrich_ip(self, ip: str) -> ThreatIntelResult:
        """
        Enrich a single IP address across every provider.

        Args:
            ip: The address to look up.

        Returns:
            An aggregated ThreatIntelResult. Ineligible addresses return an
            empty result without any outbound request.
        """
        if not is_eligible(ip, self.enrich_private_ips):
            self._skipped += 1
            return ThreatIntelResult(ip=ip)

        self._lookups += 1
        return aggregate(ip, [self._query(provider, ip) for provider in self.providers])

    def enrich_alert(self, alert: "Alert") -> ThreatIntelResult | None:
        """
        Enrich the first public address on an alert and attach the result.

        Args:
            alert: The alert to enrich, modified in place.

        Returns:
            The ThreatIntelResult stored on the alert, or None when neither
            address is publicly routable (internal-to-internal traffic).
        """
        candidates = eligible_ips(
            alert.src_ip, alert.dst_ip, include_private=self.enrich_private_ips
        )
        if not candidates:
            return None

        result = self.enrich_ip(candidates[0])
        alert.threat_intel = result
        return result

    def _query(self, provider: ThreatIntelProvider, ip: str) -> ProviderResult:
        """Run one provider through the cache, breaker and gatekeeper path."""
        return query_provider(provider, ip, self.cache, self.breakers[provider.name])
