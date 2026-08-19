"""
NetworkDefenderSDK — the single entry point for all business logic.

ARCHITECTURE RULE:
  All external consumers (CLI, REST API, dashboard WebSocket handlers)
  MUST call methods on NetworkDefenderSDK. No business logic belongs
  in presentation or transport layers.

Data Setup:  Constructed once at application startup with validated configs.
Data Input:  High-level commands from consumers (start, stop, query alerts…).
Data Output: Structured results (health dicts, alert lists, status objects).

The SDK is deliberately thin: it owns the services and exposes them through
mixins, one per subject area. Service *assembly* lives in `builder`, lifecycle
in `lifecycle`, and each operation group in its own module — so this file stays
a map of the surface rather than a container for all of it.
"""

from ..shared.config import load_app_config, load_rate_limit_config
from ..shared.config_models import AppConfig
from ..shared.rate_limit_models import RateLimitConfig
from .alert_operations import AlertOperationsMixin
from .builder import Callbacks, build_services
from .capture_operations import CaptureOperationsMixin
from .database_operations import DatabaseOperationsMixin
from .health import HealthMixin
from .lifecycle import LifecycleMixin
from .maintenance_operations import MaintenanceOperationsMixin
from .pipeline import PipelineMixin
from .rule_operations import RuleOperationsMixin
from .threat_intel_operations import ThreatIntelOperationsMixin


class NetworkDefenderSDK(
    AlertOperationsMixin,
    ThreatIntelOperationsMixin,
    DatabaseOperationsMixin,
    MaintenanceOperationsMixin,
    RuleOperationsMixin,
    CaptureOperationsMixin,
    PipelineMixin,
    LifecycleMixin,
    HealthMixin,
):
    """
    Facade over all Network Defender domain services.

    Usage:
        sdk = NetworkDefenderSDK.create()
        sdk.start()
        health = sdk.get_health()
        sdk.stop()
    """

    def __init__(
        self,
        app_config: AppConfig,
        rate_limit_config: RateLimitConfig,
    ) -> None:
        """
        Initialise the SDK with validated configuration.

        Args:
            app_config:        Validated application configuration.
            rate_limit_config: Rate limits for every external service.
        """
        self._app_config = app_config
        self._rate_limit_config = rate_limit_config

        services = build_services(
            app_config,
            rate_limit_config,
            Callbacks(
                on_detection=self._on_detection,
                on_rule_match=self._on_rule_match,
                enrichment_sink=self._submit_for_enrichment,
                save_enriched_alert=self._save_enriched_alert,
                record_snapshot=self.record_statistics_snapshot,
                prune=self.prune_old_data,
            ),
        )

        self._database_service = services.database
        self._capture_service = services.capture
        self._parser_service = services.parser
        self._alert_service = services.alerts
        self._detection_service = services.detection
        self._threat_intel_service = services.threat_intel
        self._enrichment_worker = services.enrichment_worker
        self._maintenance_service = services.maintenance
        self._statistics_sampler = services.statistics_sampler
        self._gatekeepers = services.gatekeepers

        # Connect capture -> parser -> detection -> alerting.
        self._wire_pipeline()

    @classmethod
    def create(cls) -> "NetworkDefenderSDK":
        """
        Load configuration from disk and construct the SDK.

        Returns:
            A fully initialised NetworkDefenderSDK.

        Raises:
            ConfigurationError: If any configuration file is invalid.
        """
        return cls(
            app_config=load_app_config(),
            rate_limit_config=load_rate_limit_config(),
        )
