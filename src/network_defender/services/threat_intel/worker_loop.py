"""
The enrichment worker's thread body and per-alert handling.

Data Setup:  Expects the composing class to own the queue, the stop event,
             the threat intel service and the counters.
Data Input:  Alerts pulled off the queue, each with the correlation ID of the
             detection that produced it.
Data Output: Enriched alerts handed to the persistence callback.

Split from `worker`, which owns the queue and lifecycle, so neither outgrows
the 150-line limit in ADR 4. The division is also the useful one to read: this
file is what happens to one alert, and nothing here knows about threads.

Every failure is contained. Enrichment is a best-effort decoration on an alert
that has already been raised and stored — a provider outage must not lose the
alert, and an exception here must not kill the thread that would have handled
the next thousand.
"""

import queue
import threading
from collections.abc import Callable
from typing import Any

from network_defender.observability import correlation_scope
from network_defender.services.alerts.models import Alert


class EnrichmentLoopMixin:
    """Pulls alerts off the queue and enriches them, one at a time."""

    # What this mixin needs the composing class to provide.
    _queue: "queue.Queue[tuple[Alert, str | None]]"
    _stop_event: threading.Event
    _poll_seconds: float
    _service: Any
    _on_enriched: Callable[[Alert], None] | None
    _enriched: int
    _skipped: int
    logger: Any

    def _run(self) -> None:
        """Thread body: enrich alerts until stopped."""
        while not self._stop_event.is_set():
            try:
                alert, correlation_id = self._queue.get(timeout=self._poll_seconds)
            except queue.Empty:
                continue
            self._process(alert, correlation_id)

    def _process(self, alert: Alert, correlation_id: str | None = None) -> None:
        """Enrich one alert under its originating correlation ID, containing any failure."""
        with correlation_scope(correlation_id):
            try:
                if self._service.enrich_alert(alert) is None:
                    # Internal-to-internal traffic: nothing to ask an external
                    # provider, so this is a skip rather than an enrichment.
                    self._skipped += 1
                    return
                self._enriched += 1
                if self._on_enriched is not None:
                    self._on_enriched(alert)
            except Exception as exc:  # noqa: BLE001 - must never crash the worker
                self.logger.error(
                    "Alert enrichment failed",
                    extra={"alert_id": str(alert.alert_id), "error": str(exc)},
                )
