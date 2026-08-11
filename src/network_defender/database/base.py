"""
Declarative base and shared column types.

Data Setup:  No I/O; defines the metadata every ORM model registers against.
Data Input:  Model class definitions.
Data Output: A single MetaData object that Alembic autogenerates from.

Portability
-----------
Column types are chosen to behave identically on SQLite and PostgreSQL:

  * `JsonDict` uses SQLAlchemy's generic JSON type, which maps to native JSONB
    on PostgreSQL and to a TEXT-encoded JSON column on SQLite.
  * `UtcDateTime` stores timezone-aware datetimes. SQLite has no native
    timezone support and silently drops the offset, so values are normalised
    to UTC on write and re-tagged as UTC on read. Without this, timestamps
    round-trip as naive and every comparison against an aware datetime raises.
"""

from datetime import UTC, datetime
from typing import Any

from sqlalchemy import JSON, DateTime, MetaData, TypeDecorator
from sqlalchemy.orm import DeclarativeBase

#: Explicit naming convention so Alembic emits stable, nameable constraints.
#: Without it, SQLite produces unnamed constraints that later migrations
#: cannot ALTER or DROP by name.
NAMING_CONVENTION = {
    "ix": "ix_%(column_0_label)s",
    "uq": "uq_%(table_name)s_%(column_0_name)s",
    "ck": "ck_%(table_name)s_%(constraint_name)s",
    "fk": "fk_%(table_name)s_%(column_0_name)s_%(referred_table_name)s",
    "pk": "pk_%(table_name)s",
}


class UtcDateTime(TypeDecorator[datetime]):
    """A DateTime that always round-trips as timezone-aware UTC."""

    impl = DateTime
    cache_ok = True

    def process_bind_param(self, value: datetime | None, dialect: Any) -> datetime | None:
        """Normalise to UTC before storing; assume naive input is already UTC."""
        if value is None:
            return None
        if value.tzinfo is None:
            return value.replace(tzinfo=UTC)
        return value.astimezone(UTC)

    def process_result_value(self, value: datetime | None, dialect: Any) -> datetime | None:
        """Re-tag values read back from a backend that dropped the offset."""
        if value is None:
            return None
        if value.tzinfo is None:
            return value.replace(tzinfo=UTC)
        return value.astimezone(UTC)


#: Generic JSON column: JSONB on PostgreSQL, JSON-encoded TEXT on SQLite.
JsonDict = JSON


class Base(DeclarativeBase):
    """Declarative base shared by every Network Defender ORM model."""

    metadata = MetaData(naming_convention=NAMING_CONVENTION)
