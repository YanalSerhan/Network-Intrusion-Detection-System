"""
Database service — owns the engine, schema and repository set.

Data Setup:  DatabaseConfig and retention settings injected via constructor.
Data Input:  Lifecycle calls from the SDK.
Data Output: Repositories for every other service, plus health and retention.

Schema is brought to head on start rather than left to an operator: otherwise
the service comes up, fails its first write against a missing table, and the
cause surfaces several frames down a stack trace.
"""

from typing import Any

from ..database.engine import create_db_engine, create_session_factory, resolve_database_url
from ..database.migrations import current_revision, upgrade_to_head
from ..database.repositories import (
    PacketRepository,
    RuleRepository,
    SqlAlchemyAlertRepository,
    StatisticsRepository,
    ThreatIntelCacheRepository,
)
from ..database.retention import RetentionPolicy, RetentionService
from ..shared.base import BaseService
from ..shared.config_models import DatabaseConfig


class DatabaseService(BaseService):
    """Owns the database connection and exposes repositories to other services."""

    def __init__(
        self,
        config: DatabaseConfig,
        retention: RetentionPolicy | None = None,
        run_migrations: bool = True,
    ) -> None:
        """
        Initialise the database service.

        Args:
            config:         Validated database configuration.
            retention:      Retention windows; defaults are used if omitted.
            run_migrations: Apply migrations on start. Tests that build a schema
                directly set this False to avoid the Alembic round-trip.
        """
        super().__init__(service_name="DatabaseService")
        self._config = config
        self._run_migrations = run_migrations
        self.url = resolve_database_url(config)
        self.engine = create_db_engine(config)
        self.session_factory = create_session_factory(self.engine)

        self.alerts = SqlAlchemyAlertRepository(self.session_factory)
        self.packets = PacketRepository(self.session_factory)
        self.rules = RuleRepository(self.session_factory)
        self.statistics = StatisticsRepository(self.session_factory)
        self.threat_intel_cache = ThreatIntelCacheRepository(self.session_factory)
        self.retention = RetentionService(self.session_factory, retention)

    def _do_start(self) -> None:
        """Bring the schema to head so the first write cannot hit a missing table."""
        if self._run_migrations:
            upgrade_to_head(self.url)
        self.logger.info("DatabaseService started (%s).", self.engine.dialect.name)

    def _do_stop(self) -> None:
        """Dispose of the connection pool."""
        self.engine.dispose()
        self.logger.info("DatabaseService stopped.")

    def _do_health_check(self) -> dict[str, Any]:
        """Report dialect, schema revision and row counts."""
        try:
            revision = current_revision(self.engine)
            counts = {
                "alerts": self.alerts.count(),
                "packets": self.packets.count(),
                "rules": self.rules.count(),
                "threat_intel_cache": self.threat_intel_cache.count(),
            }
            status = "ok"
        except Exception as exc:  # noqa: BLE001 - health must report, not raise
            self.logger.error("Database health check failed: %s", exc)
            return {"status": "error", "error": str(exc), "dialect": self.engine.dialect.name}

        return {
            "status": status,
            "dialect": self.engine.dialect.name,
            "schema_revision": revision,
            "rows": counts,
        }

    def prune(self) -> dict[str, int]:
        """
        Run one retention sweep.

        Returns:
            Rows deleted, keyed by table name.
        """
        return self.retention.prune()

    def create_schema_directly(self) -> None:
        """
        Create tables from the ORM metadata, bypassing Alembic.

        For tests and throwaway databases only. Production schemas must go
        through migrations so their revision is recorded and upgradeable.
        """
        from ..database.base import Base

        Base.metadata.create_all(self.engine)
