"""
Stub: Detection service placeholder.

Fully implemented in Milestones 5–6.

Data Setup:  Detector registry and rule engine injected via constructor.
Data Input:  Parsed packet objects from the parser service.
Data Output: Alert objects emitted to the alert service.
"""

from typing import Any

from ..shared.base import BaseService


class DetectionService(BaseService):
    """
    Orchestrates the rule engine and heuristic detectors.

    Implemented fully in Milestones 5–6. This stub satisfies the
    Milestone 2 requirement for service stubs behind the SDK.
    """

    def __init__(self) -> None:
        super().__init__(service_name="DetectionService")

    def _do_start(self) -> None:
        self.logger.info("DetectionService stub started.")

    def _do_stop(self) -> None:
        self.logger.info("DetectionService stub stopped.")

    def _do_health_check(self) -> dict[str, Any]:
        return {"detectors_loaded": 0, "status": "stub"}
