"""
Background alert enrichment worker.

Data Setup:  TI service, queue bound and poll interval injected via __init__.
Data Input:  Alerts submitted after they have already been persisted.
Data Output: Enrichment attached to those alerts, plus an optional callback so
             the repository can re-save the updated record.

Enrichment is up to four HTTP calls, each with a 10s timeout and retries. Inline
that would put tens of seconds between a detection and its alert (PRD target:
sub-100ms at 10k pps) and make detection throughput hostage to a third party's
availability. So alerts are raised, persisted and notified first, then enriched.

The queue is bounded: under an alert storm enrichment is dropped rather than
allowed to grow without limit. Losing enrichment is survivable; running out of
memory is not.
"""

import queue
import threading
from collections.abc import Callable

from network_defender.constants import TI_QUEUE_MAX_DEPTH, TI_WORKER_POLL_SECONDS
from network_defender.observability import correlation_scope, get_correlation_id
from network_defender.services.alerts.models import Alert
from network_defender.shared.base import LoggableMixin

from .service import ThreatIntelService


class EnrichmentWorker(LoggableMixin):
    """Consumes a queue of alerts and enriches them on a background thread."""

    def __init__(
        self,
        service: ThreatIntelService,
        on_enriched: Callable[[Alert], None] | None = None,
        max_queue_depth: int = TI_QUEUE_MAX_DEPTH,
        poll_seconds: float = TI_WORKER_POLL_SECONDS,
    ) -> None:
        """
        Initialise the worker.

        Args:
            service:         The threat intel service performing lookups.
            on_enriched:     Called with each enriched alert so the caller can
                             persist the updated record.
            max_queue_depth: Pending alerts held before new ones are dropped.
            poll_seconds:    Wait between checks of the stop flag.
        """
        self._service = service
        self._on_enriched = on_enriched
        self._poll_seconds = poll_seconds
        # The correlation ID rides with the alert: ContextVars do not cross a
        # thread boundary, so enrichment would otherwise log untraceably.
        self._queue: queue.Queue[tuple[Alert, str | None]] = queue.Queue(maxsize=max_queue_depth)
        self._stop_event = threading.Event()
        self._thread: threading.Thread | None = None
        self._enriched = 0
        self._skipped = 0
        self._dropped = 0

    @property
    def is_running(self) -> bool:
        """True while the worker thread is alive."""
        return self._thread is not None and self._thread.is_alive()

    @property
    def queue_depth(self) -> int:
        """Alerts waiting to be enriched."""
        return self._queue.qsize()

    def start(self) -> None:
        """Start the worker thread; a second call is a no-op."""
        if self.is_running:
            return
        self._stop_event.clear()
        self._thread = threading.Thread(target=self._run, name="ti-enrichment", daemon=True)
        self._thread.start()

    def stop(self, timeout: float | None = None) -> None:
        """Stop the worker, waiting `timeout` seconds (default: two polls)."""
        self._stop_event.set()
        if self._thread is not None:
            self._thread.join(timeout if timeout is not None else self._poll_seconds * 2)
            self._thread = None

    def submit(self, alert: Alert) -> bool:
        """
        Queue an already-persisted alert for enrichment.

        Returns:
            True if queued; False if the queue was full and it was dropped.
        """
        try:
            self._queue.put_nowait((alert, get_correlation_id()))
        except queue.Full:
            self._dropped += 1
            return False
        return True

    def drain(self) -> int:
        """
        Enrich every queued alert synchronously, returning the number processed.

        Used by tests and at shutdown, where waiting on the poll interval would
        be pointless.
        """
        processed = 0
        while True:
            try:
                alert, correlation_id = self._queue.get_nowait()
            except queue.Empty:
                return processed
            self._process(alert, correlation_id)
            processed += 1

    def get_stats(self) -> dict[str, int | bool]:
        """Return worker counters for health reporting."""
        return {
            "running": self.is_running,
            "queue_depth": self.queue_depth,
            "enriched": self._enriched,
            "skipped_no_public_ip": self._skipped,
            "dropped": self._dropped,
        }

    def _run(self) -> None:
        """Thread body: enrich alerts until stopped."""
        while not self._stop_event.is_set():
            try:
                alert, correlation_id = self._queue.get(timeout=self._poll_seconds)
            except queue.Empty:
                continue
            self._process(alert, correlation_id)

    def _process(self, alert: Alert, correlation_id: str | None = None) -> None:
        """Enrich one alert under its originating correlation ID."""
        with correlation_scope(correlation_id):
            self._enrich(alert)

    def _enrich(self, alert: Alert) -> None:
        """Run enrichment for one alert, containing any failure."""
        try:
            result = self._service.enrich_alert(alert)
            if result is None:
                # Internal-to-internal traffic: nothing to ask an external
                # provider about, so this is a skip rather than an enrichment.
                self._skipped += 1
                return
            self._enriched += 1
            if self._on_enriched is not None:
                self._on_enriched(alert)
        except Exception as exc:  # noqa: BLE001 - enrichment must never crash the worker
            self.logger.error(
                "Alert enrichment failed",
                extra={"alert_id": str(alert.alert_id), "error": str(exc)},
            )
