"""
TTL cache for threat intel responses.

Data Setup:  TTL and size bound injected via __init__.
Data Input:  (provider, ip) lookups and their ProviderResults.
Data Output: Cached results while fresh; None once expired.

Why this exists
---------------
IP reputation changes over days, not seconds, while a single port scan can
produce hundreds of alerts from one source address. Without caching, the same
IP would be looked up repeatedly and exhaust a budget of ~10 requests/minute
almost immediately. Entries are LRU-bounded so a scan across thousands of
distinct addresses cannot grow the cache without limit.

Only successful lookups are cached: caching a failure would extend one
transient outage into a full TTL of missing enrichment.
"""

import threading
import time
from collections import OrderedDict

from network_defender.constants import TI_CACHE_MAX_ENTRIES, TI_CACHE_TTL_SECONDS

from .models import ProviderResult

CacheKey = tuple[str, str]


class ThreatIntelCache:
    """Thread-safe, TTL-bounded, LRU-evicted cache of provider responses."""

    def __init__(
        self,
        ttl_seconds: float = TI_CACHE_TTL_SECONDS,
        max_entries: int = TI_CACHE_MAX_ENTRIES,
    ) -> None:
        """
        Initialise the cache.

        Args:
            ttl_seconds: How long an entry stays fresh.
            max_entries: Maximum entries retained before LRU eviction.
        """
        self._ttl = ttl_seconds
        self._max_entries = max_entries
        self._entries: OrderedDict[CacheKey, tuple[float, ProviderResult]] = OrderedDict()
        self._lock = threading.Lock()
        self._hits = 0
        self._misses = 0

    def get(self, provider: str, ip: str) -> ProviderResult | None:
        """
        Return a cached result if one is present and still fresh.

        Args:
            provider: Provider name.
            ip:       The looked-up address.

        Returns:
            The cached ProviderResult, or None on miss or expiry.
        """
        key = (provider, ip)
        with self._lock:
            entry = self._entries.get(key)
            if entry is None:
                self._misses += 1
                return None

            stored_at, result = entry
            if (time.monotonic() - stored_at) >= self._ttl:
                del self._entries[key]
                self._misses += 1
                return None

            self._entries.move_to_end(key)
            self._hits += 1
            return result

    def set(self, provider: str, ip: str, result: ProviderResult) -> None:
        """
        Cache a successful lookup. Failures are deliberately not cached.

        Args:
            provider: Provider name.
            ip:       The looked-up address.
            result:   The result to store.
        """
        if not result.succeeded:
            return

        with self._lock:
            self._entries[(provider, ip)] = (time.monotonic(), result)
            self._entries.move_to_end((provider, ip))
            while len(self._entries) > self._max_entries:
                self._entries.popitem(last=False)

    def clear(self) -> None:
        """Drop every cached entry and reset counters."""
        with self._lock:
            self._entries.clear()
            self._hits = 0
            self._misses = 0

    def get_stats(self) -> dict[str, float]:
        """Return hit/miss counters and the hit ratio for health reporting."""
        with self._lock:
            total = self._hits + self._misses
            return {
                "entries": len(self._entries),
                "hits": self._hits,
                "misses": self._misses,
                "hit_ratio": round(self._hits / total, 4) if total else 0.0,
            }
