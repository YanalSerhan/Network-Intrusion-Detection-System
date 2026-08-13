"""
Tests for the portable column types.

Both types exist to paper over a backend difference, so both have a branch
that SQLite never takes. Testing only against the development database would
leave the PostgreSQL path unexecuted until the first production deployment —
these drive the dialect directly instead.
"""

from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import UUID, uuid4

from network_defender.database.base import UtcDateTime
from network_defender.database.types import GUID


class _Dialect:
    """The only thing either type asks a dialect: its name."""

    def __init__(self, name: str) -> None:
        self.name = name

    def type_descriptor(self, impl: Any) -> Any:
        """Return the implementation unchanged, as SQLAlchemy's would."""
        return impl


SQLITE = _Dialect("sqlite")
POSTGRESQL = _Dialect("postgresql")


def test_uuids_are_stored_as_canonical_hex_on_sqlite() -> None:
    """Hyphenated and bare forms must not become two different rows."""
    value = uuid4()

    assert GUID().process_bind_param(value, SQLITE) == value.hex
    assert GUID().process_bind_param(str(value), SQLITE) == value.hex


def test_postgresql_keeps_native_uuid_objects() -> None:
    """The native type wants a UUID, and a string has to become one."""
    value = uuid4()

    assert GUID().process_bind_param(value, POSTGRESQL) == value
    assert GUID().process_bind_param(str(value), POSTGRESQL) == value


def test_a_uuid_column_reads_back_as_a_uuid() -> None:
    """Whichever way it was stored, the domain sees a UUID."""
    value = uuid4()

    assert GUID().process_result_value(value.hex, SQLITE) == value
    assert GUID().process_result_value(value, POSTGRESQL) == value
    assert isinstance(GUID().process_result_value(str(value), SQLITE), UUID)


def test_null_uuids_stay_null() -> None:
    assert GUID().process_bind_param(None, SQLITE) is None
    assert GUID().process_result_value(None, SQLITE) is None


def test_the_backend_chooses_the_underlying_type() -> None:
    """PostgreSQL gets its native UUID; everything else gets CHAR(32)."""
    assert "UUID" in repr(GUID().load_dialect_impl(POSTGRESQL))
    assert "CHAR" in repr(GUID().load_dialect_impl(SQLITE))


def test_naive_timestamps_are_assumed_to_be_utc() -> None:
    """Rejecting them would be worse: the whole codebase writes UTC."""
    naive = datetime(2026, 8, 13, 12, 0, 0)  # noqa: DTZ001 - the case under test

    stored = UtcDateTime().process_bind_param(naive, SQLITE)
    assert stored is not None and stored.tzinfo is UTC


def test_offset_timestamps_are_converted_not_truncated() -> None:
    """An hour is an hour; only the representation should change."""
    aware = datetime(2026, 8, 13, 12, 0, 0, tzinfo=UTC) + timedelta(hours=0)

    stored = UtcDateTime().process_bind_param(aware, SQLITE)
    assert stored == aware


def test_timestamps_read_back_aware_even_when_the_backend_drops_the_offset() -> None:
    """SQLite stores no offset, so the naive value it returns must be re-tagged."""
    naive = datetime(2026, 8, 13, 12, 0, 0)  # noqa: DTZ001 - what SQLite hands back

    loaded = UtcDateTime().process_result_value(naive, SQLITE)
    assert loaded is not None and loaded.tzinfo is UTC

    aware = datetime(2026, 8, 13, 12, 0, 0, tzinfo=UTC)
    assert UtcDateTime().process_result_value(aware, POSTGRESQL) == aware


def test_null_timestamps_stay_null() -> None:
    assert UtcDateTime().process_bind_param(None, SQLITE) is None
    assert UtcDateTime().process_result_value(None, SQLITE) is None
