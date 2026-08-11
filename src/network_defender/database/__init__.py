"""
Database layer (Milestone 9).

Data Setup:  Engine and session factory built from DatabaseConfig.
Data Input:  Domain objects from the service layer.
Data Output: Persisted rows, returned as domain models by the repositories.

Nothing above this package names a storage backend: services depend on the
repository ports, and the engine is the only place a URL or dialect appears.
Moving from SQLite to PostgreSQL is therefore a configuration change.
"""

from .base import Base
from .engine import (
    create_db_engine,
    create_session_factory,
    resolve_database_url,
    session_scope,
)
from .models import (
    AlertRecord,
    PacketRecord,
    RuleRecord,
    StatisticsRecord,
    ThreatIntelCacheRecord,
)

__all__ = [
    "AlertRecord",
    "Base",
    "PacketRecord",
    "RuleRecord",
    "StatisticsRecord",
    "ThreatIntelCacheRecord",
    "create_db_engine",
    "create_session_factory",
    "resolve_database_url",
    "session_scope",
]
