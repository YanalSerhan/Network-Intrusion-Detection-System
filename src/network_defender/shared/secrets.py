"""
Secret loading from the environment.

Data Setup:  Reads .env from the project root once, then the process environment.
Data Input:  Environment variable names.
Data Output: Secret values, or None when unset.

Policy
------
API keys and credentials live in `.env` (git-ignored) or the real process
environment — never in source, never in the JSON config files, never in logs.
`describe_secrets()` exists so health endpoints can report *whether* a key is
configured without ever exposing its value.
"""

import os

from dotenv import load_dotenv

from .paths import PROJECT_ROOT

_ENV_FILE = PROJECT_ROOT / ".env"
_loaded = False


def load_env(override: bool = False) -> None:
    """
    Load .env into the process environment, once per run.

    Args:
        override: If True, values in .env replace existing environment variables.
    """
    global _loaded
    if _loaded and not override:
        return
    if _ENV_FILE.exists():
        load_dotenv(_ENV_FILE, override=override)
    _loaded = True


def get_secret(name: str, default: str | None = None) -> str | None:
    """
    Return a secret from the environment.

    Args:
        name:    Environment variable name (e.g. 'ABUSEIPDB_API_KEY').
        default: Value to return when the variable is unset or blank.

    Returns:
        The secret value, or `default`.
    """
    load_env()
    value = os.getenv(name)
    if value is None or not value.strip():
        return default
    return value.strip()


def describe_secrets(*names: str) -> dict[str, bool]:
    """
    Report which secrets are configured, without revealing any values.

    Args:
        *names: Environment variable names to check.

    Returns:
        Mapping of name -> True if a non-empty value is set.
    """
    return {name: get_secret(name) is not None for name in names}
