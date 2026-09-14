"""
Repository implementations backed by SQLAlchemy.

Each repository owns one aggregate and returns domain models, never live ORM
instances, so services stay free of SQLAlchemy and the in-memory and SQL
implementations remain interchangeable behind the same ports.
"""

from network_defender.database.repositories.alerts import SqlAlchemyAlertRepository
from network_defender.database.repositories.packets import PacketRepository
from network_defender.database.repositories.rules import RuleRepository
from network_defender.database.repositories.statistics import StatisticsRepository
from network_defender.database.repositories.threat_intel import ThreatIntelCacheRepository

__all__ = [
    "PacketRepository",
    "RuleRepository",
    "SqlAlchemyAlertRepository",
    "StatisticsRepository",
    "ThreatIntelCacheRepository",
]
