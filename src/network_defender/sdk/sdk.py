"""
NetworkDefenderSDK — the single entry point for all business logic.

ARCHITECTURE RULE:
  All external consumers (CLI, REST API, dashboard WebSocket handlers)
  MUST call methods on NetworkDefenderSDK. No business logic belongs
  in presentation or transport layers.

Data Setup:  Constructed once at application startup with validated configs.
Data Input:  High-level commands from consumers (start, stop, query alerts…).
Data Output: Structured results (health dicts, alert lists, status objects).
"""

from pathlib import Path
from typing import Any

from ..capture.interface_discovery import list_interfaces
from ..capture.models import CaptureStatus
from ..services.alerting import AlertService
from ..services.capture import CaptureService
from ..services.detection import DetectionService
from ..shared.base import LoggableMixin
from ..shared.config import load_app_config, load_rate_limit_config
from ..shared.config_models import AppConfig
from ..shared.gatekeeper import ApiGatekeeper
from ..shared.rate_limit_models import RateLimitConfig


class NetworkDefenderSDK(LoggableMixin):
    """
    Facade over all Network Defender domain services.

    Responsibilities:
      - Assemble and own all service instances.
      - Expose high-level, consumer-friendly methods.
      - Ensure every outbound API call routes through the gatekeeper.
      - Provide a unified health-check surface for the /health endpoint.

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
            rate_limit_config: Validated rate-limit configuration for all external services.
        """
        self._app_config = app_config
        self._rate_limit_config = rate_limit_config

        # Build service instances with injected configs (no hardcoded values).
        self._capture_service = CaptureService(config=app_config.capture)
        self._detection_service = DetectionService()
        self._alert_service = AlertService()

        # Build per-service gatekeepers from config.
        self._gatekeepers: dict[str, ApiGatekeeper] = {
            name: ApiGatekeeper(service_name=name, config=svc_cfg)
            for name, svc_cfg in rate_limit_config.services.items()
        }

    # ------------------------------------------------------------------
    # Factory
    # ------------------------------------------------------------------

    @classmethod
    def create(cls) -> "NetworkDefenderSDK":
        """
        Convenience factory: load configs from disk and construct the SDK.

        Returns:
            A fully initialised NetworkDefenderSDK instance.
        """
        app_config = load_app_config()
        rate_limit_config = load_rate_limit_config()
        return cls(app_config=app_config, rate_limit_config=rate_limit_config)

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def start(self) -> None:
        """Start all domain services in dependency order."""
        self.logger.info("NetworkDefenderSDK starting all services.")
        self._capture_service.start()
        self._detection_service.start()
        self._alert_service.start()
        self.logger.info("NetworkDefenderSDK ready.")

    def stop(self) -> None:
        """Stop all domain services in reverse order."""
        self.logger.info("NetworkDefenderSDK stopping all services.")
        self._alert_service.stop()
        self._detection_service.stop()
        self._capture_service.stop()
        self.logger.info("NetworkDefenderSDK shut down.")

    # ------------------------------------------------------------------
    # Health
    # ------------------------------------------------------------------

    def get_health(self) -> dict[str, Any]:
        """
        Return a unified health-check payload suitable for /health endpoint.

        Returns:
            Dict with overall status and per-service sub-statuses.
        """
        components = {
            "capture": self._capture_service.health_check(),
            "detection": self._detection_service.health_check(),
            "alerting": self._alert_service.health_check(),
        }
        all_ok = all(c.get("running", False) for c in components.values())
        return {
            "status": "ok" if all_ok else "degraded",
            "components": components,
        }

    # ------------------------------------------------------------------
    # Gatekeeper access (for Threat Intel service layer)
    # ------------------------------------------------------------------

    def get_gatekeeper(self, service_name: str) -> ApiGatekeeper:
        """
        Retrieve the gatekeeper for a named external service.

        Args:
            service_name: Must match a key in config/rate_limits.json.

        Returns:
            The ApiGatekeeper instance for that service.

        Raises:
            KeyError: If the service is not configured.
        """
        if service_name not in self._gatekeepers:
            raise KeyError(
                f"No gatekeeper configured for service '{service_name}'. "
                f"Available: {list(self._gatekeepers.keys())}"
            )
        return self._gatekeepers[service_name]

    # ------------------------------------------------------------------
    # Capture operations
    # ------------------------------------------------------------------

    def start_capture(self) -> None:
        """
        Start live packet capture on the configured network interface.

        Delegates to CaptureService.start() via the BaseService template.
        """
        self._capture_service.start()

    def stop_capture(self) -> None:
        """Stop the active live capture session."""
        self._capture_service.stop()

    def start_capture_from_pcap(self, path: str | Path) -> None:
        """
        Replay packets from a PCAP file through the full filter/detection pipeline.

        Args:
            path: Absolute or relative path to the .pcap file.
        """
        self._capture_service.start_pcap_replay(path)

    def save_capture_to_pcap(self, path: str | Path) -> None:
        """
        Save all packets captured in the current session to a PCAP file.

        Args:
            path: Destination file path.
        """
        self._capture_service.save_to_pcap(path)

    def get_capture_status(self) -> CaptureStatus:
        """
        Return a snapshot of the capture service's current state.

        Returns:
            CaptureStatus Pydantic model with counters and config summary.
        """
        return self._capture_service.get_status()

    def list_interfaces(self) -> list[str]:
        """
        Return the sorted list of all network interfaces visible to Scapy.

        Returns:
            List of interface name strings (e.g. ['eth0', 'lo', 'wlan0']).
        """
        return list_interfaces()
