"""
Centralized configuration manager.

Loads and validates application configuration from JSON files,
then merges with environment variable overrides where applicable.

Data Setup:  Config files in config/ directory, .env for secrets.
Data Input:  JSON files + environment variables.
Data Output: Validated AppConfig and RateLimitConfig objects.
"""

import json
import os
from pathlib import Path

from .config_models import AppConfig
from .rate_limit_models import RateLimitConfig

_CONFIG_DIR = Path(__file__).parent.parent.parent.parent / "config"


def _load_json(filename: str) -> dict:  # type: ignore[type-arg]
    """Load a JSON config file from the config directory."""
    path = _CONFIG_DIR / filename
    if not path.exists():
        return {}
    with path.open(encoding="utf-8") as f:
        return json.load(f)  # type: ignore[no-any-return]


def load_app_config() -> AppConfig:
    """
    Load and validate the main application configuration.

    Reads config/setup.json and returns a validated AppConfig.
    Environment variables can override specific values (e.g., DATABASE_URL).
    """
    raw = _load_json("setup.json")
    # Allow environment variable to override the database URL
    if db_url := os.getenv("DATABASE_URL"):
        raw.setdefault("database", {})["default_url"] = db_url
    return AppConfig.model_validate(raw)


def load_rate_limit_config() -> RateLimitConfig:
    """Load and validate the rate-limit configuration from config/rate_limits.json."""
    raw = _load_json("rate_limits.json")
    return RateLimitConfig.model_validate(raw)
