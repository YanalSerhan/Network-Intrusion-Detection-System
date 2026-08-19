"""
Pydantic models for application configuration schemas.

Data Setup:  Loaded once at startup from JSON config files and env vars.
Data Input:  Raw dicts parsed from JSON files.
Data Output: Validated, typed config objects consumed by all services.

Holds the sections that describe where the system binds — interfaces, ports,
database URLs. Sections that tune pipeline behaviour live in `config_pipeline`
and are re-exported here, so every consumer keeps importing one module.
"""

# pyrefly: ignore [missing-import]
from pydantic import BaseModel, Field

from .config_pipeline import (
    DetectionConfig,
    MaintenanceConfig,
    RetentionConfig,
    ThreatIntelConfig,
)

__all__ = [
    "ApiConfig",
    "AppConfig",
    "CaptureConfig",
    "DashboardConfig",
    "DatabaseConfig",
    "DetectionConfig",
    "MaintenanceConfig",
    "RetentionConfig",
    "ThreatIntelConfig",
]


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
    retention: RetentionConfig = Field(
        default_factory=RetentionConfig, description="Per-table retention windows."
    )
