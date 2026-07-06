"""
Pydantic models for rate-limit configuration.

Data Setup:  Loaded once at startup from config/rate_limits.json.
Data Input:  Raw dict parsed from JSON.
Data Output: Typed RateLimitConfig objects consumed by ApiGatekeeper.
"""

# pyrefly: ignore [missing-import]
from pydantic import BaseModel, Field


class ServiceRateLimitConfig(BaseModel):
    """Rate-limit settings for a single external API service."""

    requests_per_minute: int = Field(gt=0, description="Max calls allowed per minute.")
    requests_per_day: int = Field(gt=0, description="Max calls allowed per day.")
    max_queue_depth: int = Field(gt=0, description="Max pending requests in the FIFO queue.")
    retry_attempts: int = Field(ge=0, description="Number of retry attempts on transient failure.")
    retry_backoff_base_seconds: float = Field(
        gt=0, description="Base delay in seconds for exponential backoff."
    )


class RateLimitConfig(BaseModel):
    """Top-level rate-limit config, keyed by service name."""

    version: str = Field(default="1.00", description="Config schema version.")
    services: dict[str, ServiceRateLimitConfig] = Field(
        default_factory=dict, description="Per-service rate-limit settings."
    )
