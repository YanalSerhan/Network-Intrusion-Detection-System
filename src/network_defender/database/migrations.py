"""
Programmatic migration control.

Data Setup:  Locates alembic.ini and migrations/ relative to the project root.
Data Input:  A database URL (defaults to the configured one).
Data Output: Schema brought to the latest revision.

Why programmatic
----------------
Requiring an operator to run `alembic upgrade head` before starting the app is
a footgun: the service comes up, fails its first write against a missing table,
and the cause is several layers down a stack trace. Applying migrations at
startup makes a fresh checkout, a Docker container and a test run all work the
same way.

The CLI remains the interface for authoring and reviewing migrations; this
module only ever moves *forward* to head.
"""

from alembic import command
from alembic.config import Config
from alembic.runtime.migration import MigrationContext
from sqlalchemy import Engine

from ..shared.paths import PROJECT_ROOT

ALEMBIC_INI = PROJECT_ROOT / "alembic.ini"
MIGRATIONS_DIR = PROJECT_ROOT / "migrations"


def build_alembic_config(database_url: str | None = None) -> Config:
    """
    Build an Alembic config pointing at this project's migrations.

    Args:
        database_url: Overrides the URL resolved by env.py; used by tests to
            target a temporary database.

    Returns:
        A configured Alembic Config.
    """
    config = Config(str(ALEMBIC_INI))
    config.set_main_option("script_location", str(MIGRATIONS_DIR))
    if database_url is not None:
        config.set_main_option("sqlalchemy.url", database_url)
    return config


def upgrade_to_head(database_url: str | None = None) -> None:
    """
    Apply every pending migration.

    Args:
        database_url: Optional override of the configured database URL.
    """
    command.upgrade(build_alembic_config(database_url), "head")


def current_revision(engine: Engine) -> str | None:
    """
    Return the revision currently applied to a database.

    Args:
        engine: Engine bound to the database to inspect.

    Returns:
        The revision identifier, or None if no migration has been applied.
    """
    with engine.connect() as connection:
        return MigrationContext.configure(connection).get_current_revision()
