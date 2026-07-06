"""
Stub: Alert service placeholder.

Fully implemented in Milestone 7.

Data Setup:  Database repository and notification hooks injected via constructor.
Data Input:  Alert objects emitted by the detection service.
Data Output: Persisted Alert records; side effects to notification channels.
"""

from typing import Any

from ..shared.base import BaseService


class AlertService(BaseService):
    """
    Manages alert creation, deduplication, persistence, and notification dispatch.

    Implemented fully in Milestone 7. This stub satisfies the
    Milestone 2 requirement for service stubs behind the SDK.
    """

    def __init__(self) -> None:
        super().__init__(service_name="AlertService")

    def _do_start(self) -> None:
        self.logger.info("AlertService stub started.")

    def _do_stop(self) -> None:
        self.logger.info("AlertService stub stopped.")

    def _do_health_check(self) -> dict[str, Any]:
        return {"alerts_today": 0, "status": "stub"}
