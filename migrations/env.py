"""
Alembic environment.

Data Setup:  Reads the database URL from the application config, not from
             alembic.ini, so there is one source of truth and no credentials
             in a tracked file.
Data Input:  Alembic migration context.
Data Output: Schema changes applied to the configured database.
"""

from logging.config import fileConfig

from alembic import context

from network_defender.database.base import Base
from network_defender.database.engine import create_db_engine
from network_defender.shared.config import load_app_config

# Importing the models registers every table on Base.metadata; without this
# import autogenerate sees an empty schema and proposes dropping everything.
import network_defender.database.models  # noqa: F401  isort:skip

config = context.config

if config.config_file_name is not None:
    fileConfig(config.config_file_name)

target_metadata = Base.metadata


def _database_config() -> object:
    """Return the validated DatabaseConfig from config/setup.json."""
    return load_app_config().database


def run_migrations_offline() -> None:
    """Emit SQL to stdout without connecting, for review or manual application."""
    from network_defender.database.engine import resolve_database_url

    context.configure(
        url=resolve_database_url(_database_config()),  # type: ignore[arg-type]
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
        compare_type=True,
    )
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    """Apply migrations against a live connection."""
    engine = create_db_engine(_database_config())  # type: ignore[arg-type]

    with engine.connect() as connection:
        context.configure(
            connection=connection,
            target_metadata=target_metadata,
            compare_type=True,
            # SQLite cannot ALTER most columns in place; batch mode rebuilds the
            # table instead, so migrations behave the same on both backends.
            render_as_batch=connection.dialect.name == "sqlite",
        )
        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
