"""
Two-tier threat intel cache: in-memory in front, database behind.

Data Setup:  Memory tier and a durable repository injected via __init__.
Data Input:  (provider, ip) lookups and ProviderResults.
Data Output: Cached results from whichever tier holds them.

Why two tiers
-------------
The memory tier is fast but process-local: every restart throws away a cache
whose entries are valid for 24 hours. With provider budgets around 10 requests
per minute, a deploy would spend its first minutes re-asking about addresses it
already knew, and any alert raised in that window goes out unenriched.

Reads check memory first and fall back to the database, promoting a database
hit back into memory so the second lookup is fast again. Writes go to both.

The durable tier is best-effort: a database problem must degrade this to a
plain in-memory cache, never break enrichment, which in turn must never break
alerting. Failures are logged and swallowed.
"""

from network_defender.constants import TI_CACHE_TTL_SECONDS
from network_defender.shared.base import LoggableMixin

from .cache import ThreatIntelCache
from .models import ProviderResult


class DurableCacheBackend:
    """Structural interface for the persistent tier (see ThreatIntelCacheRepository)."""

    def get(self, provider: str, ip: str) -> ProviderResult | None:
        """Return a cached result, or None."""
        raise NotImplementedError

    def set(self, provider: str, ip: str, result: ProviderResult, ttl_seconds: float) -> None:
        """Store a result with a TTL."""
        raise NotImplementedError


class TieredThreatIntelCache(LoggableMixin):
    """
    A ThreatIntelCache-compatible cache backed by durable storage.

    Deliberately mirrors the `ThreatIntelCache` surface (`get`/`set`/`clear`/
    `get_stats`) so ThreatIntelService accepts it with no changes.
    """

    def __init__(
        self,
        memory: ThreatIntelCache | None = None,
        durable: DurableCacheBackend | None = None,
        ttl_seconds: float = TI_CACHE_TTL_SECONDS,
    ) -> None:
        """
        Initialise the tiered cache.

        Args:
            memory:      Fast tier; a default TTL cache is created if omitted.
            durable:     Persistent tier; without one this behaves exactly like
                         the plain in-memory cache.
            ttl_seconds: TTL applied to durable entries.
        """
        self.memory = memory or ThreatIntelCache(ttl_seconds=ttl_seconds)
        self.durable = durable
        self._ttl = ttl_seconds
        self._durable_hits = 0
        self._durable_errors = 0

    def get(self, provider: str, ip: str) -> ProviderResult | None:
        """
        Return a cached result from either tier.

        A durable hit is promoted into memory so the next lookup avoids the
        database round-trip entirely.
        """
        cached = self.memory.get(provider, ip)
        if cached is not None:
            return cached

        if self.durable is None:
            return None

        try:
            stored = self.durable.get(provider, ip)
        except Exception as exc:  # noqa: BLE001 - degrade to memory-only
            self._durable_errors += 1
            self.logger.warning("Durable cache read failed: %s", exc)
            return None

        if stored is not None:
            self._durable_hits += 1
            self.memory.set(provider, ip, stored)
        return stored

    def set(self, provider: str, ip: str, result: ProviderResult) -> None:
        """Write a successful result to both tiers."""
        self.memory.set(provider, ip, result)
        if self.durable is None or not result.succeeded:
            return

        try:
            self.durable.set(provider, ip, result, self._ttl)
        except Exception as exc:  # noqa: BLE001 - degrade to memory-only
            self._durable_errors += 1
            self.logger.warning("Durable cache write failed: %s", exc)

    def clear(self) -> None:
        """Clear the memory tier only; durable entries persist by design."""
        self.memory.clear()

    def get_stats(self) -> dict[str, float]:
        """Return memory-tier counters plus durable hit/error counts."""
        stats = dict(self.memory.get_stats())
        stats["durable_hits"] = self._durable_hits
        stats["durable_errors"] = self._durable_errors
        stats["durable_enabled"] = float(self.durable is not None)
        return stats
