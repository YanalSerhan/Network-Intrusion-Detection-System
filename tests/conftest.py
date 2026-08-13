"""
Shared pytest fixtures for all Network Defender tests.

Everything defined or re-exported here is visible to every test module, so a
test never has to reach sideways into another package's conftest. The fixtures
themselves live in ``tests/fixtures/`` grouped by subject area — this file is
the index, which keeps it readable as the suite grows.
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

# Re-exported so pytest collects them as fixtures for the whole suite.
from .fixtures.alerts import detection, packet, rule  # noqa: F401
from .fixtures.api import client, sdk, seeded_alert, seeded_rules  # noqa: F401
from .fixtures.database import (  # noqa: F401
    alert_repo,
    engine,
    packet_repo,
    rule_repo,
    session_factory,
    stats_repo,
    ti_repo,
)
from .fixtures.threat_intel import _no_proxy_env, gatekeeper  # noqa: F401


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

    db_engine = create_db_engine(DatabaseConfig(default_url=url))
    Base.metadata.create_all(db_engine)
    db_engine.dispose()

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
