"""
Portable column types.

Data Setup:  No I/O.
Data Input:  Python values bound into statements.
Data Output: Backend-appropriate storage representations.

`GUID` exists because UUID support is not portable: PostgreSQL has a native
UUID type, SQLite has none. Storing UUIDs as raw strings would work but yields
inconsistent formatting (hyphenated vs not, upper vs lower case), so equality
lookups silently miss. This type stores a canonical 32-character hex string on
backends without native support and hands back real UUID objects either way.
"""

from typing import Any
from uuid import UUID

from sqlalchemy import CHAR, TypeDecorator
from sqlalchemy.dialects.postgresql import UUID as PG_UUID  # noqa: N811 - SQLAlchemy type


class GUID(TypeDecorator[UUID]):
    """Platform-independent UUID column."""

    impl = CHAR
    cache_ok = True

    def load_dialect_impl(self, dialect: Any) -> Any:
        """Use PostgreSQL's native UUID type where available, else CHAR(32)."""
        if dialect.name == "postgresql":
            return dialect.type_descriptor(PG_UUID(as_uuid=True))
        return dialect.type_descriptor(CHAR(32))

    def process_bind_param(self, value: UUID | str | None, dialect: Any) -> str | UUID | None:
        """Store a canonical hex form so equality lookups always match."""
        if value is None:
            return None
        if dialect.name == "postgresql":
            return value if isinstance(value, UUID) else UUID(str(value))
        return UUID(str(value)).hex if not isinstance(value, UUID) else value.hex

    def process_result_value(self, value: Any, dialect: Any) -> UUID | None:
        """Return a real UUID regardless of how the backend stored it."""
        if value is None:
            return None
        return value if isinstance(value, UUID) else UUID(str(value))
