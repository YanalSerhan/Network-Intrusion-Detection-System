"""Unit tests for the centralized config manager."""

from network_defender.shared.config import load_app_config, load_rate_limit_config
from network_defender.shared.config_models import AppConfig
from network_defender.shared.rate_limit_models import RateLimitConfig


def test_load_app_config_returns_app_config() -> None:
    """load_app_config() should return a valid AppConfig instance."""
    config = load_app_config()
    assert isinstance(config, AppConfig)
    assert config.version == "1.00"


def test_load_app_config_has_valid_capture_section() -> None:
    """AppConfig.capture should have a non-empty interface setting."""
    config = load_app_config()
    assert config.capture.snaplen > 0
    assert config.capture.buffer_size > 0


def test_load_rate_limit_config_returns_rate_limit_config() -> None:
    """load_rate_limit_config() should return a valid RateLimitConfig instance."""
    config = load_rate_limit_config()
    assert isinstance(config, RateLimitConfig)
    assert config.version == "1.00"


def test_rate_limit_config_has_services() -> None:
    """RateLimitConfig should contain at least one configured service."""
    config = load_rate_limit_config()
    assert len(config.services) > 0


def test_rate_limit_service_values_are_positive() -> None:
    """Every configured service should have positive rate limits."""
    config = load_rate_limit_config()
    for name, svc in config.services.items():
        assert svc.requests_per_minute > 0, f"{name}: requests_per_minute must be > 0"
        assert svc.max_queue_depth > 0, f"{name}: max_queue_depth must be > 0"


def test_database_url_env_var_overrides_default() -> None:
    """DATABASE_URL env var should override the default_url in AppConfig."""
    import os
    from unittest.mock import patch

    with patch.dict(os.environ, {"DATABASE_URL": "postgresql://user:pw@host/db"}):
        config = load_app_config()
    assert config.database.default_url == "postgresql://user:pw@host/db"


def test_load_json_returns_empty_dict_for_missing_file() -> None:
    """_load_json should return {} rather than raising when the file is absent."""
    from pathlib import Path
    from unittest.mock import patch

    from network_defender.shared.config import _load_json

    with patch("network_defender.shared.config._CONFIG_DIR", Path("/nonexistent/dir")):
        result = _load_json("missing.json")
    assert result == {}
