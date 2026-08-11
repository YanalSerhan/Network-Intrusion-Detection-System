"""
Rule snapshot repository.

Data Setup:  Session factory injected via __init__.
Data Input:  Rules loaded from YAML by the rule engine.
Data Output: The rule set the API exposes at GET /api/v1/rules.

Rules live in YAML — that stays the source of truth and supports hot reload.
This table is a snapshot of what is *currently loaded*, so the dashboard can
show the active rule set without reading the filesystem, and `sync()` therefore
replaces the snapshot wholesale rather than merging: a rule deleted from disk
must disappear from the API too.
"""

from datetime import UTC, datetime

from sqlalchemy import func, select
from sqlalchemy.orm import Session, sessionmaker

from ...rules.models import Rule
from ..engine import session_scope
from ..mappers import rule_to_record
from ..models import RuleRecord


class RuleRepository:
    """Mirrors the loaded YAML rule set into the database."""

    def __init__(self, session_factory: sessionmaker[Session]) -> None:
        """
        Initialise the repository.

        Args:
            session_factory: Factory producing sessions bound to the engine.
        """
        self._session_factory = session_factory

    def sync(self, rules: list[Rule], source_paths: dict[str, str] | None = None) -> int:
        """
        Replace the stored snapshot with the currently loaded rules.

        Args:
            rules:        Every rule the engine currently has loaded.
            source_paths: Optional rule name -> originating file path.

        Returns:
            Number of rules written.
        """
        loaded_at = datetime.now(UTC)
        paths = source_paths or {}

        with session_scope(self._session_factory) as session:
            for stale in session.scalars(select(RuleRecord)):
                session.delete(stale)
            session.flush()
            session.add_all(
                [rule_to_record(rule, paths.get(rule.name), loaded_at) for rule in rules]
            )
        return len(rules)

    def list_rules(self, enabled_only: bool = False) -> list[RuleRecord]:
        """
        Return the stored rule snapshot.

        Args:
            enabled_only: Restrict to rules that are currently enabled.

        Returns:
            RuleRecord rows, ordered by name.
        """
        statement = select(RuleRecord).order_by(RuleRecord.name)
        if enabled_only:
            statement = statement.where(RuleRecord.enabled.is_(True))

        with session_scope(self._session_factory) as session:
            return list(session.scalars(statement))

    def get(self, name: str) -> RuleRecord | None:
        """Return a single rule snapshot by name, or None."""
        with session_scope(self._session_factory) as session:
            return session.get(RuleRecord, name)

    def count(self) -> int:
        """Return the number of rules in the snapshot."""
        with session_scope(self._session_factory) as session:
            return int(session.scalar(select(func.count()).select_from(RuleRecord)) or 0)

    def clear(self) -> None:
        """Delete the stored snapshot."""
        with session_scope(self._session_factory) as session:
            for record in session.scalars(select(RuleRecord)):
                session.delete(record)
