"""
Configuration for the detection pipeline's behaviour.

Data Setup:  Parsed from the matching sections of setup.json.
Data Input:  Raw dicts.
Data Output: Validated config objects for detection, enrichment and upkeep.

Separate from `config_models` because these sections tune *what the system
does* — how often detectors fire, which intel feeds run, how long rows live —
while the sections that remain there describe *where it binds*: interfaces,
ports, database URLs. The two change for different reasons and by different
people.

Re-exported from `config_models`, so nothing imports this module directly.
"""

# pyrefly: ignore [missing-import]
from pydantic import BaseModel, Field


class DetectionConfig(BaseModel):
    """Configuration for the detection service."""

    evaluation_interval_seconds: float = Field(
        default=5.0,
        description="How often stateful detectors are evaluated and their windows flushed.",
    )
    evaluate_rules: bool = Field(
        default=True, description="Evaluate YAML signature rules on every packet."
    )


class ThreatIntelConfig(BaseModel):
    """
    Threat intelligence enrichment settings.

    API keys are deliberately absent: credentials come from `.env` only, so this
    file stays committable. This section controls behaviour — which providers
    run, how long results stay fresh, when a failing provider is cut out.
    """

    enabled: bool = Field(
        default=True, description="Master switch for enrichment; disables all providers."
    )
    providers: list[str] = Field(
        default_factory=lambda: ["abuseipdb", "ip_api_geo", "ip_api_asn", "whois"],
        description="Provider names to enable, in priority order. Unlisted providers "
        "are not constructed.",
    )
    cache_ttl_seconds: float = Field(
        default=86_400.0,
        gt=0,
        description="How long a provider response stays fresh. Reputation moves over "
        "days, so a long TTL is what keeps lookups inside a small budget.",
    )
    cache_max_entries: int = Field(
        default=10_000, gt=0, description="In-memory cache bound before LRU eviction."
    )
    breaker_failure_threshold: int = Field(
        default=5, gt=0, description="Consecutive failures before a provider is cut out."
    )
    breaker_reset_seconds: float = Field(
        default=300.0, gt=0, description="Cooldown before a cut-out provider is retried."
    )
    http_timeout_seconds: float = Field(
        default=10.0, gt=0, description="Per-request timeout for provider calls."
    )
    enrich_private_ips: bool = Field(
        default=False,
        description="Send private/internal addresses to third-party providers. Off by "
        "default: it leaks internal topology and no feed has an opinion on RFC1918.",
    )


class MaintenanceConfig(BaseModel):
    """Configuration for periodic background maintenance."""

    statistics_enabled: bool = Field(
        default=True, description="Record periodic counter snapshots for dashboard trends."
    )
    statistics_interval_seconds: float = Field(
        default=60.0,
        gt=0,
        description="Seconds between snapshots; also the chart's resolution.",
    )
    retention_enabled: bool = Field(
        default=True, description="Prune rows past their retention window on a timer."
    )
    retention_interval_seconds: float = Field(
        default=3600.0,
        gt=0,
        description="Seconds between retention sweeps. Hourly suits day-scale windows "
        "and keeps the delete cost off the hot path.",
    )
