"""Fixtures giving each database test its own real, file-backed SQLite database."""

from collections.abc import Iterator
from pathlib import Path

import pytest
from sqlalchemy import Engine
from sqlalchemy.orm import Session, sessionmaker

from network_defender.database.base import Base
from network_defender.database.engine import create_db_engine, create_session_factory
from network_defender.database.repositories import (
    PacketRepository,
    RuleRepository,
    SqlAlchemyAlertRepository,
    StatisticsRepository,
    ThreatIntelCacheRepository,
)
from network_defender.shared.config_models import DatabaseConfig


@pytest.fixture()
def engine(tmp_path: Path) -> Iterator[Engine]:
    """
    A real file-backed SQLite database, not :memory:.

    File-backed matters here: :memory: gives each connection its own private
    database, so cross-session behaviour — commits, cascades, restart
    survival — would appear to work while proving nothing.
    """
    db_engine = create_db_engine(DatabaseConfig(default_url=f"sqlite:///{tmp_path / 'nd.db'}"))
    Base.metadata.create_all(db_engine)
    yield db_engine
    db_engine.dispose()


@pytest.fixture()
def session_factory(engine: Engine) -> sessionmaker[Session]:
    """Session factory bound to the test database."""
    return create_session_factory(engine)


@pytest.fixture()
def alert_repo(session_factory: sessionmaker[Session]) -> SqlAlchemyAlertRepository:
    """SQL-backed alert repository."""
    return SqlAlchemyAlertRepository(session_factory)


@pytest.fixture()
def packet_repo(session_factory: sessionmaker[Session]) -> PacketRepository:
    """Packet evidence repository."""
    return PacketRepository(session_factory)


@pytest.fixture()
def rule_repo(session_factory: sessionmaker[Session]) -> RuleRepository:
    """Rule snapshot repository."""
    return RuleRepository(session_factory)


@pytest.fixture()
def stats_repo(session_factory: sessionmaker[Session]) -> StatisticsRepository:
    """Statistics snapshot repository."""
    return StatisticsRepository(session_factory)


@pytest.fixture()
def ti_repo(session_factory: sessionmaker[Session]) -> ThreatIntelCacheRepository:
    """Threat intel cache repository."""
    return ThreatIntelCacheRepository(session_factory)
