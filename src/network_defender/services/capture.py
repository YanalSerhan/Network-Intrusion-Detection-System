"""
Stub: Capture service placeholder.

Fully implemented in Milestone 3.

Data Setup:  CaptureConfig injected via constructor.
Data Input:  Raw packets from a live network interface or PCAP file.
Data Output: Stream of raw Scapy packet objects.
"""

from typing import Any

from ..shared.base import BaseService
from ..shared.config_models import CaptureConfig


class CaptureService(BaseService):
    """
    Manages live packet capture from a network interface.

    Implemented fully in Milestone 3. This stub satisfies the
    Milestone 2 requirement for service stubs behind the SDK.
    """

    def __init__(self, config: CaptureConfig) -> None:
        """
        Initialise the capture service.

        Args:
            config: Validated CaptureConfig (interface, BPF filter, etc.).
        """
        super().__init__(service_name="CaptureService")
        self._config = config

    def _do_start(self) -> None:
        self.logger.info("CaptureService stub started (Milestone 3 will implement capture).")

    def _do_stop(self) -> None:
        self.logger.info("CaptureService stub stopped.")

    def _do_health_check(self) -> dict[str, Any]:
        return {"interface": self._config.interface, "status": "stub"}
