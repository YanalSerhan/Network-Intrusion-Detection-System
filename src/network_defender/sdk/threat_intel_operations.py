"""
Threat-intel SDK operations.

Data Setup:  Expects the composing class to own `_threat_intel_service` and
             `_enrichment_worker`.
Data Input:  IP addresses and alert IDs from consumers.
Data Output: ThreatIntelResult records and enrichment statistics.

ARCHITECTURE RULE: consumers never call a provider or the TI service directly.
They go through these SDK methods, which keeps the gatekeeper, cache and
circuit breaker unavoidable.
"""

from typing import Any
from uuid import UUID

from ..services.alerts import Alert, AlertService
from ..services.threat_intel import ThreatIntelResult, ThreatIntelService
from ..services.threat_intel.worker import EnrichmentWorker


class ThreatIntelOperationsMixin:
    """Enrichment query surface of the SDK."""

    _alert_service: AlertService
    _threat_intel_service: ThreatIntelService
    _enrichment_worker: EnrichmentWorker

    def _submit_for_enrichment(self, alert: Alert) -> bool:
        """
        Alert-service sink: queue a persisted alert for background enrichment.

        Returns:
            True if queued; False if the enrichment queue was full.
        """
        return self._enrichment_worker.submit(alert)

    def _save_enriched_alert(self, alert: Alert) -> None:
        """Worker callback: persist an alert once its enrichment has landed."""
        self._alert_service.repository.save(alert)

    def enrich_ip(self, ip: str) -> ThreatIntelResult:
        """
        Look up an IP address across every configured provider.

        Args:
            ip: The address to enrich. Private and malformed addresses return
                an empty result without any outbound request.

        Returns:
            The aggregated ThreatIntelResult.
        """
        return self._threat_intel_service.enrich_ip(ip)

    def enrich_alert_now(self, alert_id: UUID) -> ThreatIntelResult | None:
        """
        Enrich a stored alert synchronously, bypassing the background queue.

        Intended for an analyst opening an alert whose enrichment was dropped
        or has not run yet.

        Args:
            alert_id: The alert to enrich.

        Returns:
            The ThreatIntelResult, or None if the alert is unknown or carries
            no publicly routable address.
        """
        alert = self._alert_service.get_alert(alert_id)
        if alert is None:
            return None

        result = self._threat_intel_service.enrich_alert(alert)
        if result is not None:
            self._alert_service.repository.save(alert)
        return result

    def get_threat_intel_status(self) -> dict[str, Any]:
        """
        Return provider availability, circuit state, cache and worker stats.

        Returns:
            Health dict suitable for the /health endpoint and the dashboard.
        """
        status = self._threat_intel_service.health_check()
        status["worker"] = self._enrichment_worker.get_stats()
        return status
