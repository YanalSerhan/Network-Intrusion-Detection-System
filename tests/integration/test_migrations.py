"""Integration tests: Alembic builds the schema the ORM expects."""

from pathlib import Path

import pytest
from sqlalchemy import inspect

from network_defender.database.engine import (
    create_db_engine,
    create_session_factory,
    resolve_database_url,
)
from network_defender.database.migrations import current_revision, upgrade_to_head
from network_defender.database.repositories import (
    SqlAlchemyAlertRepository,
)
from network_defender.shared.config_models import DatabaseConfig
from network_defender.shared.paths import PROJECT_ROOT
from tests.fixtures.builders import make_alert

EXPECTED_TABLES = {"alerts", "packets", "rules", "statistics", "threat_intel_cache"}


# --------------------------------------------------------------------------
# Migrations
# --------------------------------------------------------------------------


def test_migrations_build_the_full_schema(tmp_path: Path) -> None:
    url = f"sqlite:///{tmp_path / 'migrated.db'}"
    upgrade_to_head(url)

    engine = create_db_engine(DatabaseConfig(default_url=url))
    try:
        assert EXPECTED_TABLES.issubset(set(inspect(engine).get_table_names()))
        assert current_revision(engine) is not None
    finally:
        engine.dispose()


def test_migrated_schema_accepts_real_writes(tmp_path: Path) -> None:
    """The schema an operator gets must actually work, not merely exist."""
    url = f"sqlite:///{tmp_path / 'migrated.db'}"
    upgrade_to_head(url)

    engine = create_db_engine(DatabaseConfig(default_url=url))
    try:
        repo = SqlAlchemyAlertRepository(create_session_factory(engine))
        alert = make_alert(evidence={"unique_ports": 60})
        repo.save(alert)

        stored = repo.get(alert.alert_id)
        assert stored is not None
        assert stored.evidence == {"unique_ports": 60}
    finally:
        engine.dispose()


def test_migration_indices_exist(tmp_path: Path) -> None:
    url = f"sqlite:///{tmp_path / 'migrated.db'}"
    upgrade_to_head(url)

    engine = create_db_engine(DatabaseConfig(default_url=url))
    try:
        names = {index["name"] for index in inspect(engine).get_indexes("alerts")}
        assert "ix_alerts_severity_timestamp" in names
        assert "ix_alerts_status_timestamp" in names
        assert "ix_alerts_src_ip_timestamp" in names
    finally:
        engine.dispose()

# --------------------------------------------------------------------------
# Engine configuration
# --------------------------------------------------------------------------


def test_relative_sqlite_paths_anchor_to_the_project_root(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # The suite-wide fixture points DATABASE_URL at a temp file; clear it so the
    # configured default is what actually gets resolved here.
    monkeypatch.delenv("DATABASE_URL", raising=False)

    url = resolve_database_url(DatabaseConfig(default_url="sqlite:///./nd.db"))
    assert str(PROJECT_ROOT) in url


def test_database_url_env_var_overrides_config(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("DATABASE_URL", "sqlite:////tmp/override.db")
    config = DatabaseConfig(url_env_var="DATABASE_URL", default_url="sqlite:///ignored.db")
    assert resolve_database_url(config) == "sqlite:////tmp/override.db"


def test_foreign_keys_are_enforced_on_sqlite(tmp_path: Path) -> None:
    """Without PRAGMA foreign_keys=ON, ON DELETE CASCADE silently does nothing."""
    engine = create_db_engine(DatabaseConfig(default_url=f"sqlite:///{tmp_path / 'fk.db'}"))
    try:
        with engine.connect() as connection:
            assert connection.exec_driver_sql("PRAGMA foreign_keys").scalar() == 1
    finally:
        engine.dispose()
