"""
Shared pytest fixtures for all Network Defender tests.

Fixtures defined here are automatically available in all test modules.
"""

from pathlib import Path

import pytest
from alembic import command

from network_defender.database.base import Base
from network_defender.database.engine import create_db_engine
from network_defender.database.migrations import build_alembic_config
from network_defender.shared.config import load_app_config, load_rate_limit_config
from network_defender.shared.config_models import AppConfig, DatabaseConfig
from network_defender.shared.rate_limit_models import RateLimitConfig


@pytest.fixture(autouse=True)
def isolated_database(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> str:
    """
    Give every test its own throwaway SQLite file.

    Without this, tests share the real development database: state leaks
    between them, counts accumulate, and a test run mutates a file the
    developer is also using. The URL is injected through DATABASE_URL, the
    same override production uses, so nothing in the code under test needs a
    test-only branch.

    The schema is created directly from the ORM metadata rather than through
    Alembic — the migration path has its own dedicated tests, and running it
    hundreds of times here would dominate the suite's runtime. The database is
    then stamped at head so a service that runs `upgrade head` on start finds
    nothing to do, instead of trying to create tables that already exist.

    Returns:
        The SQLite URL in use for this test.
    """
    url = f"sqlite:///{tmp_path / 'test.db'}"
    monkeypatch.setenv("DATABASE_URL", url)

    engine = create_db_engine(DatabaseConfig(default_url=url))
    Base.metadata.create_all(engine)
    engine.dispose()

    command.stamp(build_alembic_config(url), "head")
    return url


@pytest.fixture()
def app_config() -> AppConfig:
    """Return the validated AppConfig loaded from config/setup.json."""
    return load_app_config()


@pytest.fixture()
def rate_limit_config() -> RateLimitConfig:
    """Return the validated RateLimitConfig loaded from config/rate_limits.json."""
    return load_rate_limit_config()
