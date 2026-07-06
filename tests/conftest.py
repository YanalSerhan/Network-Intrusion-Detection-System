"""
Shared pytest fixtures for all Network Defender tests.

Fixtures defined here are automatically available in all test modules.
"""

import pytest

from network_defender.shared.config import load_app_config, load_rate_limit_config
from network_defender.shared.config_models import AppConfig
from network_defender.shared.rate_limit_models import RateLimitConfig


@pytest.fixture()
def app_config() -> AppConfig:
    """Return the validated AppConfig loaded from config/setup.json."""
    return load_app_config()


@pytest.fixture()
def rate_limit_config() -> RateLimitConfig:
    """Return the validated RateLimitConfig loaded from config/rate_limits.json."""
    return load_rate_limit_config()
