"""
Alert deduplication and correlation.

Data Setup:  Window size and state bound injected via __init__ (never hardcoded).
Data Input:  Alert objects emitted by detectors or the rule engine.
Data Output: Either a new Alert to persist, or None when the alert was folded
             into an existing one (whose occurrence counter is incremented).

Why this exists
---------------
A single port scan can make one detector fire on every evaluation cycle. Without
correlation the analyst sees thousands of identical rows and the real signal is
buried. Alerts sharing a dedup key — (rule, src_ip, dst_ip, severity) — inside
the dedup window are collapsed into one record.

State is bounded: the tracker prunes expired entries on every ingest and evicts
the oldest entries once DEDUP_MAX_TRACKED_KEYS is exceeded, so a long-running
sensor cannot exhaust memory (the failure mode called out in the Detection
Engine PRD).
"""

from collections import OrderedDict
from datetime import UTC, datetime, timedelta

from network_defender.constants import DEDUP_MAX_TRACKED_KEYS, DEDUP_WINDOW_SECONDS

from .models import Alert

DedupKey = tuple[str, str, str, str]


class AlertDeduplicator:
    """
    Collapses repeated identical alerts within a rolling time window.

    Usage:
        dedup = AlertDeduplicator()
        first = dedup.process(alert_a)   # -> Alert (new, persist it)
        again = dedup.process(alert_a)   # -> None  (folded into first)
    """

    def __init__(
        self,
        window_seconds: int = DEDUP_WINDOW_SECONDS,
        max_tracked_keys: int = DEDUP_MAX_TRACKED_KEYS,
    ) -> None:
        """
        Initialise the deduplicator.

        Args:
            window_seconds:   Seconds an alert stays "active" for correlation.
            max_tracked_keys: Hard bound on tracked dedup keys (LRU eviction).
        """
        self._window = timedelta(seconds=window_seconds)
        self._max_tracked_keys = max_tracked_keys
        self._active: OrderedDict[DedupKey, Alert] = OrderedDict()

    @property
    def tracked_keys(self) -> int:
        """Number of dedup keys currently held in state."""
        return len(self._active)

    def process(self, alert: Alert) -> Alert | None:
        """
        Deduplicate a single alert.

        Args:
            alert: The candidate alert.

        Returns:
            The alert itself if it is new within the window (caller should
            persist and notify), or None if it was merged into an existing
            alert (whose `occurrences` and `last_seen` were updated in place).
        """
        now = alert.timestamp if alert.timestamp.tzinfo else datetime.now(UTC)
        self._prune(now)

        key = alert.dedup_key()
        existing = self._active.get(key)

        if existing is not None:
            self._merge(existing, alert, now)
            self._active.move_to_end(key)
            return None

        self._active[key] = alert
        self._evict_overflow()
        return alert

    def get_active(self, alert: Alert) -> Alert | None:
        """
        Return the currently-active alert correlated with `alert`, if any.

        Args:
            alert: Alert whose dedup key should be looked up.

        Returns:
            The active Alert sharing the dedup key, or None.
        """
        return self._active.get(alert.dedup_key())

    def reset(self) -> None:
        """Clear all correlation state (used on service restart and in tests)."""
        self._active.clear()

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    @staticmethod
    def _merge(existing: Alert, duplicate: Alert, now: datetime) -> None:
        """Fold a duplicate into the alert already tracked for its key."""
        existing.occurrences += 1
        existing.last_seen = now
        existing.confidence = max(existing.confidence, duplicate.confidence)
        existing.evidence.update(duplicate.evidence)

    def _prune(self, now: datetime) -> None:
        """Drop tracked alerts whose window has elapsed."""
        cutoff = now - self._window
        expired = [key for key, alert in self._active.items() if alert.last_seen < cutoff]
        for key in expired:
            del self._active[key]

    def _evict_overflow(self) -> None:
        """Evict least-recently-updated keys once the state bound is exceeded."""
        while len(self._active) > self._max_tracked_keys:
            self._active.popitem(last=False)
