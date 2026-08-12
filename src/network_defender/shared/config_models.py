"""
Pydantic models for application configuration schemas.

Data Setup:  Loaded once at startup from JSON config files and env vars.
Data Input:  Raw dicts parsed from JSON files.
Data Output: Validated, typed config objects consumed by all services.
"""

# pyrefly: ignore [missing-import]
from pydantic import BaseModel, Field


class CaptureConfig(BaseModel):
    """Configuration for the packet capture service."""

    interface: str = Field(default="eth0", description="Network interface to capture on.")
    bpf_filter: str = Field(default="", description="Berkeley Packet Filter expression.")
    snaplen: int = Field(default=65535, description="Maximum bytes to capture per packet.")
    promiscuous_mode: bool = Field(default=True, description="Enable promiscuous mode.")
    buffer_size: int = Field(default=4096, description="Capture ring buffer size in KB.")
    max_packets_per_second: int = Field(
        default=10_000,
        description="Token-bucket rate limit; 0 = unlimited.",
    )
    protocol_allow_list: list[str] = Field(
        default_factory=list,
        description="If non-empty, only these protocols are passed downstream.",
    )
    protocol_deny_list: list[str] = Field(
        default_factory=list,
        description="Protocols explicitly dropped before downstream processing.",
    )
    pcap_output_dir: str = Field(
        default="captures/",
        description="Directory where saved PCAP files are written.",
    )


class ApiConfig(BaseModel):
    """Configuration for the FastAPI REST server."""

    host: str = Field(default="0.0.0.0", description="Bind host.")
    port: int = Field(default=8000, description="Bind port.")
    reload: bool = Field(default=False, description="Enable auto-reload (dev only).")
    workers: int = Field(default=1, description="Number of Uvicorn worker processes.")


class DatabaseConfig(BaseModel):
    """Configuration for the database layer."""

    url_env_var: str = Field(default="DATABASE_URL", description="Env var holding the DB URL.")
    default_url: str = Field(
        default="sqlite:///./network_defender.db",
        description="Fallback DB URL if env var is not set.",
    )
    echo: bool = Field(default=False, description="Echo SQL statements (debug mode).")


class DashboardConfig(BaseModel):
    """Configuration for the web dashboard."""

    host: str = Field(default="0.0.0.0", description="Bind host.")
    port: int = Field(default=3000, description="Bind port.")
    default_theme: str = Field(default="dark", description="Default UI theme.")


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
    Configuration for threat intelligence enrichment.

    API keys are deliberately absent: credentials come from `.env` only, so a
    config file can be committed and shared without leaking anything. This
    section controls *behaviour* — which providers run, how long results stay
    fresh, and when a failing provider is cut out.
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
        description="How long a provider response stays fresh. IP reputation moves "
        "over days, so a long TTL is what keeps lookups inside a small budget.",
    )
    cache_max_entries: int = Field(
        default=10_000, gt=0, description="In-memory cache bound before LRU eviction."
    )
    breaker_failure_threshold: int = Field(
        default=5,
        gt=0,
        description="Consecutive failures before a provider is cut out.",
    )
    breaker_reset_seconds: float = Field(
        default=300.0,
        gt=0,
        description="Cooldown before a cut-out provider gets one trial request.",
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
        description="Seconds between statistics snapshots. Also the resolution of the "
        "packets-per-second chart.",
    )
    retention_enabled: bool = Field(
        default=True, description="Prune rows past their retention window on a timer."
    )
    retention_interval_seconds: float = Field(
        default=3600.0,
        gt=0,
        description="Seconds between retention sweeps. Hourly is ample for day-scale windows "
        "and keeps the delete cost off the hot path.",
    )


class AppConfig(BaseModel):
    """Top-level application configuration assembled from setup.json."""

    version: str = Field(default="1.00", description="Config schema version.")
    capture: CaptureConfig = Field(default_factory=CaptureConfig)
    api: ApiConfig = Field(default_factory=ApiConfig)
    database: DatabaseConfig = Field(default_factory=DatabaseConfig)
    dashboard: DashboardConfig = Field(default_factory=DashboardConfig)
    detection: DetectionConfig = Field(default_factory=DetectionConfig)
    threat_intel: ThreatIntelConfig = Field(default_factory=ThreatIntelConfig)
    maintenance: MaintenanceConfig = Field(default_factory=MaintenanceConfig)
    rules_dir: str = Field(default="rules/", description="Path to YAML rules directory.")
    config_dir: str = Field(
        default="config/", description="Path to the directory holding detectors.json."
    )
    retention_days: int = Field(default=30, description="Days to retain packet/alert records.")
