"""
Engine and session management.

Data Setup:  URL resolved from DatabaseConfig, overridable by an env var.
Data Input:  SQL statements issued by the repository layer.
Data Output: Sessions bound to a configured engine.

Portability
-----------
Nothing above this module names a backend. Switching from SQLite to PostgreSQL
is a URL change, which is why the engine is built here from config rather than
constructed ad hoc by each repository.

SQLite needs two adjustments that PostgreSQL does not, applied only when the
dialect is SQLite:

  * `check_same_thread=False` — the capture, evaluation and enrichment threads
    all touch the database, and SQLite's default forbids cross-thread use.
  * `PRAGMA foreign_keys=ON` — SQLite ignores foreign keys unless asked, so
    `ON DELETE CASCADE` on packets would silently not fire.
"""

from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Any

from sqlalchemy import Engine, create_engine, event
from sqlalchemy.orm import Session, sessionmaker

from ..shared.config_models import DatabaseConfig
from ..shared.paths import resolve_project_path
from ..shared.secrets import get_secret

SQLITE_PREFIX = "sqlite:///"
MEMORY_URL = "sqlite://"


def resolve_database_url(config: DatabaseConfig) -> str:
    """
    Return the database URL, preferring the configured environment variable.

    Relative SQLite paths are anchored to the project root so the database
    lands in the same place regardless of the working directory.

    Args:
        config: Validated database configuration.

    Returns:
        A SQLAlchemy connection URL.
    """
    url = get_secret(config.url_env_var) or config.default_url

    if url.startswith(SQLITE_PREFIX):
        raw_path = url[len(SQLITE_PREFIX) :]
        if raw_path and not raw_path.startswith("/"):
            return f"{SQLITE_PREFIX}{resolve_project_path(raw_path)}"
    return url


def create_db_engine(config: DatabaseConfig) -> Engine:
    """
    Build an engine for the configured database.

    Args:
        config: Validated database configuration.

    Returns:
        A configured SQLAlchemy Engine.
    """
    url = resolve_database_url(config)
    kwargs: dict[str, Any] = {"echo": config.echo, "future": True}

    if url.startswith("sqlite"):
        kwargs["connect_args"] = {"check_same_thread": False}

    engine = create_engine(url, **kwargs)

    if engine.dialect.name == "sqlite":
        _enable_sqlite_foreign_keys(engine)
        _ensure_parent_directory(url)
    return engine


def _enable_sqlite_foreign_keys(engine: Engine) -> None:
    """Turn on foreign-key enforcement, which SQLite disables by default."""

    @event.listens_for(engine, "connect")
    def _set_pragma(dbapi_connection: Any, _record: Any) -> None:
        cursor = dbapi_connection.cursor()
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.close()


def _ensure_parent_directory(url: str) -> None:
    """Create the directory holding a file-backed SQLite database."""
    if url in (MEMORY_URL, f"{SQLITE_PREFIX}:memory:"):
        return
    path = Path(url[len(SQLITE_PREFIX) :])
    if path.parent and not path.parent.exists():
        path.parent.mkdir(parents=True, exist_ok=True)


def create_session_factory(engine: Engine) -> sessionmaker[Session]:
    """
    Build a session factory bound to an engine.

    `expire_on_commit=False` so objects stay usable after the session closes —
    repositories return detached domain models, not live ORM instances.

    Args:
        engine: The engine to bind sessions to.

    Returns:
        A configured sessionmaker.
    """
    return sessionmaker(bind=engine, expire_on_commit=False, future=True)


@contextmanager
def session_scope(factory: sessionmaker[Session]) -> Iterator[Session]:
    """
    Provide a transactional scope: commit on success, roll back on failure.

    Args:
        factory: The session factory to open a session from.

    Yields:
        An open Session.
    """
    session = factory()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()
