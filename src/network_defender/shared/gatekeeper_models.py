"""
Pydantic models for gatekeeper queue status reporting.

Data Output: QueueStatus returned by ApiGatekeeper.get_queue_status().
"""

# pyrefly: ignore [missing-import]
from pydantic import BaseModel, Field


class QueueStatus(BaseModel):
    """Snapshot of the gatekeeper's current queue state for a service."""

    service_name: str = Field(description="Name of the external API service.")
    queue_depth: int = Field(ge=0, description="Number of requests currently queued.")
    max_queue_depth: int = Field(gt=0, description="Maximum allowed queue depth.")
    is_backpressure_active: bool = Field(
        description="True when the queue is full and new requests are being rejected."
    )
    requests_this_minute: int = Field(ge=0, description="Requests dispatched in current minute.")
    requests_per_minute_limit: int = Field(gt=0, description="Allowed requests per minute.")
