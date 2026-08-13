"""
Centralized configuration manager.

Data Setup:  JSON files in config/, plus `.env` and `ND__*` environment vars.
Data Input:  Parsed JSON dicts and environment overrides.
Data Output: Validated AppConfig and RateLimitConfig objects.

Precedence, lowest to highest:

    model defaults  <  config/*.json  <  ND__SECTION__KEY env vars

Secrets never appear in any of those: credentials come from `.env` via
`shared/secrets.py` and are read at the point of use.

Invalid configuration aborts startup with every problem listed at once — see
`config_errors` for why.
"""

from typing import Any

from pydantic import BaseModel, ValidationError

from .config_env import apply_overrides, collect_overrides
from .config_errors import ConfigurationError, describe_validation_error, load_json_file
from .config_models import AppConfig
from .paths import CONFIG_DIR
from .rate_limit_models import RateLimitConfig
from .secrets import get_secret

SETUP_FILE = "setup.json"
RATE_LIMITS_FILE = "rate_limits.json"

_CONFIG_DIR = CONFIG_DIR


def _validate[TModel: BaseModel](model: type[TModel], raw: dict[str, Any], source: str) -> TModel:
    """
    Validate a raw dict against a model, reporting every problem at once.

    Args:
        model:  The Pydantic model to validate against.
        raw:    The merged configuration dict.
        source: File name used in error messages.

    Returns:
        The validated model instance.

    Raises:
        ConfigurationError: If validation fails.
    """
    try:
        return model.model_validate(raw)
    except ValidationError as exc:
        raise ConfigurationError(
            f"Invalid configuration in {source}.", describe_validation_error(source, exc)
        ) from exc


def load_app_config() -> AppConfig:
    """
    Load, override and validate the main application configuration.

    Returns:
        A validated AppConfig.

    Raises:
        ConfigurationError: If the file is malformed or any value is invalid.
    """
    raw = load_json_file(_CONFIG_DIR / SETUP_FILE)
    raw = apply_overrides(raw, collect_overrides(AppConfig))

    config: AppConfig = _validate(AppConfig, raw, SETUP_FILE)

    # DATABASE_URL is honoured separately from the ND__ scheme because a
    # connection string is a credential: it belongs with the other secrets in
    # .env, and its name is a long-standing convention deployments already use.
    if database_url := get_secret(config.database.url_env_var):
        config.database.default_url = database_url

    return config


def load_rate_limit_config() -> RateLimitConfig:
    """
    Load and validate the per-service rate-limit configuration.

    Returns:
        A validated RateLimitConfig.

    Raises:
        ConfigurationError: If the file is malformed or any value is invalid.
    """
    raw = load_json_file(_CONFIG_DIR / RATE_LIMITS_FILE)
    return _validate(RateLimitConfig, raw, RATE_LIMITS_FILE)


def validate_all() -> dict[str, str]:
    """
    Validate every configuration file, collecting problems across all of them.

    Loading one file at a time means an operator fixes one error, restarts, and
    meets the next. This reports every file's problems in a single pass.

    Returns:
        A summary naming each file and its status.

    Raises:
        ConfigurationError: If any file is invalid.
    """
    problems: list[str] = []
    summary: dict[str, str] = {}

    for name, loader in ((SETUP_FILE, load_app_config), (RATE_LIMITS_FILE, load_rate_limit_config)):
        try:
            loader()
            summary[name] = "ok"
        except ConfigurationError as exc:
            summary[name] = "invalid"
            problems.extend(exc.problems or [str(exc)])

    if problems:
        raise ConfigurationError("Configuration is invalid; refusing to start.", problems)

    return summary
