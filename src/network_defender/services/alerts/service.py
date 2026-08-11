"""
AlertService — orchestrates the full alert lifecycle.

Data Setup:  Repository, deduplicator and dispatcher injected via __init__;
             defaults let the SDK construct the service with no configuration.
Data Input:  DetectionAlerts from detection; matched Rules from the rule engine.
Data Output: Persisted Alerts, dispatched notifications, and query results.

Pipeline: build -> deduplicate -> persist -> log -> notify -> enrich.
"""

from collections.abc import Callable
from datetime import datetime
from typing import Any
from uuid import UUID

from network_defender.constants import ALERT_QUERY_DEFAULT_LIMIT, AlertStatus, Severity
from network_defender.detectors.models import DetectionAlert
from network_defender.parser.models import ParsedPacket
from network_defender.rules.models import Rule

from ...shared.base import BaseService
from .dedup import AlertDeduplicator
from .dispatcher import NotificationDispatcher
from .factory import build_alert, build_rule_alert
from .models import Alert
from .repository import AlertRepository, InMemoryAlertRepository
from .security_log import log_alert_raised, log_alert_suppressed


class AlertService(BaseService):
    """
    Manages alert creation, deduplication, persistence and notification dispatch.

    Usage:
        service = AlertService()
        service.start()
        alert = service.handle_detection(detection_alert)
    """

    def __init__(
        self,
        repository: AlertRepository | None = None,
        deduplicator: AlertDeduplicator | None = None,
        dispatcher: NotificationDispatcher | None = None,
        enrichment_sink: Callable[[Alert], bool] | None = None,
    ) -> None:
        """
        Initialise the alert service.

        Args:
            repository:      Persistence adapter; defaults to in-memory.
            deduplicator:    Correlation engine; defaults to the standard window.
            dispatcher:      Notification fan-out; defaults to no hooks.
            enrichment_sink: Receives each new alert for background enrichment.
                             Called after persistence, so enrichment never
                             delays alerting.
        """
        super().__init__(service_name="AlertService")
        self.repository = repository or InMemoryAlertRepository()
        self.deduplicator = deduplicator or AlertDeduplicator()
        self.dispatcher = dispatcher or NotificationDispatcher()
        self.enrichment_sink = enrichment_sink
        self._raised = 0
        self._suppressed = 0

    def _do_start(self) -> None:
        """Reset correlation state so a restart never inherits a stale window."""
        self.deduplicator.reset()
        self.logger.info("AlertService started.")

    def _do_stop(self) -> None:
        """Release correlation state on shutdown."""
        self.deduplicator.reset()
        self.logger.info("AlertService stopped.")

    def _do_health_check(self) -> dict[str, Any]:
        """Return alert counters and notification stats for /health."""
        return {
            "alerts_stored": self.repository.count(),
            "alerts_raised": self._raised,
            "alerts_suppressed": self._suppressed,
            "tracked_dedup_keys": self.deduplicator.tracked_keys,
            "notifications": self.dispatcher.get_stats(),
            "status": "ok",
        }

    # ------------------------------------------------------------------
    # Ingest
    # ------------------------------------------------------------------

    def handle_detection(
        self, detection: DetectionAlert, packet: ParsedPacket | None = None
    ) -> Alert | None:
        """
        Process a heuristic detection through the alert pipeline.

        Args:
            detection: Alert emitted by a detector.
            packet:    Optional triggering packet used to enrich the alert.

        Returns:
            The persisted Alert, or None if deduplicated away.
        """
        return self._process(build_alert(detection, packet))

    def handle_rule_match(self, rule: Rule, packet: ParsedPacket) -> Alert | None:
        """
        Process a YAML rule match through the alert pipeline.

        Args:
            rule:   The rule that matched.
            packet: The packet that satisfied every condition.

        Returns:
            The persisted Alert, or None if it was deduplicated away.
        """
        return self._process(build_rule_alert(rule, packet))

    def _process(self, alert: Alert) -> Alert | None:
        """Run an assembled alert through dedup, persistence and notification."""
        deduped = self.deduplicator.process(alert)
        if deduped is None:
            self._suppressed += 1
            # Dedup mutates the tracked alert in place. An in-memory store
            # shares that object; a durable one does not, so the merged alert
            # must be written back or occurrences silently stays at 1.
            merged = self.deduplicator.get_active(alert)
            if merged is not None:
                self.repository.save(merged)
                log_alert_suppressed(merged, merged.occurrences)
            return None

        self.repository.save(deduped)
        self._raised += 1
        log_alert_raised(deduped)
        self.dispatcher.dispatch(deduped)
        if self.enrichment_sink is not None:
            self.enrichment_sink(deduped)
        return deduped

    # ------------------------------------------------------------------
    # Query — thin pass-throughs so callers never hold a repository directly
    # ------------------------------------------------------------------

    def get_alert(self, alert_id: UUID) -> Alert | None:
        """Return a single stored alert by ID, or None."""
        return self.repository.get(alert_id)

    def list_alerts(
        self,
        severity: Severity | None = None,
        status: AlertStatus | None = None,
        since: datetime | None = None,
        limit: int = ALERT_QUERY_DEFAULT_LIMIT,
        offset: int = 0,
    ) -> list[Alert]:
        """Return stored alerts, newest first, matching the given criteria."""
        return self.repository.list_alerts(
            severity=severity, status=status, since=since, limit=limit, offset=offset
        )
