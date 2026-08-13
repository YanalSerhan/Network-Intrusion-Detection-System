"""
Service assembly for the SDK.

Data Setup:  Validated AppConfig and RateLimitConfig.
Data Input:  Callbacks the SDK supplies for pipeline wiring.
Data Output: A ServiceBundle holding every constructed service.

Extracted from `NetworkDefenderSDK.__init__`, which had grown to hold the
construction order of eight services plus their wiring. Assembly and behaviour
are different concerns: this module answers "what is built and in what order",
while the SDK answers "what can a consumer do".

Construction order is load-bearing and documented inline — the database must
exist before anything that persists through it, and the alert service before
detection so detector callbacks have somewhere to go.
"""

from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from ..services.alerts import AlertService
from ..services.capture import CaptureService
from ..services.database import DatabaseService
from ..services.detection import DetectionService
from ..services.maintenance import MaintenanceService
from ..services.parser import PacketParser
from ..services.statistics_sampler import StatisticsSampler
from ..services.threat_intel.factory import build_service
from ..services.threat_intel.service import ThreatIntelService
from ..services.threat_intel.tiered_cache import TieredThreatIntelCache
from ..services.threat_intel.worker import EnrichmentWorker
from ..shared.config_models import AppConfig
from ..shared.gatekeeper import ApiGatekeeper
from ..shared.rate_limit_models import RateLimitConfig


@dataclass
class ServiceBundle:
    """Every service the SDK owns, constructed and wired."""

    database: DatabaseService
    capture: CaptureService
    parser: PacketParser
    alerts: AlertService
    detection: DetectionService
    threat_intel: ThreatIntelService
    enrichment_worker: EnrichmentWorker
    maintenance: MaintenanceService
    statistics_sampler: StatisticsSampler
    gatekeepers: dict[str, ApiGatekeeper]


@dataclass
class Callbacks:
    """Hooks the SDK provides so services can reach the alert pipeline."""

    on_detection: Callable[[Any], None]
    on_rule_match: Callable[[Any, Any], None]
    enrichment_sink: Callable[[Any], bool]
    save_enriched_alert: Callable[[Any], None]
    record_snapshot: Callable[[], Any]
    prune: Callable[[], Any]


def build_services(
    app_config: AppConfig,
    rate_limit_config: RateLimitConfig,
    callbacks: Callbacks,
) -> ServiceBundle:
    """
    Construct every service in dependency order.

    Args:
        app_config:        Validated application configuration.
        rate_limit_config: Per-service outbound rate limits.
        callbacks:         SDK hooks wiring services to the alert pipeline.

    Returns:
        A ServiceBundle of constructed services.
    """
    # The database comes first: every other service either persists through it
    # or reads a repository from it.
    database = DatabaseService(config=app_config.database)

    # Alerts before detection, so detector callbacks have somewhere to deliver.
    alerts = AlertService(
        repository=database.alerts, enrichment_sink=callbacks.enrichment_sink
    )
    detection = DetectionService(
        config_dir=app_config.config_dir,
        rules_dir=app_config.rules_dir,
        alert_callback=callbacks.on_detection,
        rule_callback=callbacks.on_rule_match,
        config=app_config.detection,
    )

    gatekeepers = {
        name: ApiGatekeeper(service_name=name, config=service_config)
        for name, service_config in rate_limit_config.services.items()
    }

    # Enrichment runs off the alert path. Its cache is backed by the database so
    # a 24h reputation TTL survives a restart rather than being re-fetched
    # against a budget measured in tens of requests per minute.
    threat_intel = build_service(gatekeepers, app_config.threat_intel)
    threat_intel.cache = TieredThreatIntelCache(
        memory=threat_intel.cache,
        durable=database.threat_intel_cache,
        ttl_seconds=app_config.threat_intel.cache_ttl_seconds,
    )

    return ServiceBundle(
        database=database,
        capture=CaptureService(config=app_config.capture),
        parser=PacketParser(),
        alerts=alerts,
        detection=detection,
        threat_intel=threat_intel,
        enrichment_worker=EnrichmentWorker(
            service=threat_intel, on_enriched=callbacks.save_enriched_alert
        ),
        maintenance=MaintenanceService(
            record_snapshot=callbacks.record_snapshot,
            prune=callbacks.prune,
            config=app_config.maintenance,
        ),
        statistics_sampler=StatisticsSampler(),
        gatekeepers=gatekeepers,
    )
