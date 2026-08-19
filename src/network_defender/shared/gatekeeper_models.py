"""
Pydantic models for gatekeeper status reporting.

Data Output: QueueStatus returned by ApiGatekeeper.get_queue_status().
"""

# pyrefly: ignore [missing-import]
from pydantic import BaseModel, Field


class QueueStatus(BaseModel):
    """
    Snapshot of a gatekeeper's current state, for health reporting.

    `queue_depth` counts callers currently inside `execute()` — waiting for a
    slot or with a request in flight. That is the real queue: the gatekeeper
    does not defer work to a background thread, so a caller waiting its turn
    *is* the queued item.
    """

    service_name: str = Field(description="Name of the external API service.")
    queue_depth: int = Field(ge=0, description="Callers currently waiting or in flight.")
    max_queue_depth: int = Field(gt=0, description="Waiting callers allowed before shedding.")
    is_backpressure_active: bool = Field(
        description="True when the queue is full and new requests are being rejected."
    )
    requests_this_minute: int = Field(ge=0, description="Requests dispatched in current minute.")
    requests_per_minute_limit: int = Field(gt=0, description="Allowed requests per minute.")
    requests_today: int = Field(ge=0, description="Requests dispatched in the current day.")
    requests_per_day_limit: int = Field(gt=0, description="Allowed requests per day.")
    seconds_until_daily_reset: float = Field(
        ge=0, description="Time until the daily quota rolls over."
    )
