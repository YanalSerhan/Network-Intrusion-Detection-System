"""
Repository implementations backed by SQLAlchemy.

Each repository owns one aggregate and returns domain models, never live ORM
instances, so services stay free of SQLAlchemy and the in-memory and SQL
implementations remain interchangeable behind the same ports.
"""

from .alerts import SqlAlchemyAlertRepository
from .packets import PacketRepository
from .rules import RuleRepository
from .statistics import StatisticsRepository
from .threat_intel import ThreatIntelCacheRepository

__all__ = [
    "PacketRepository",
    "RuleRepository",
    "SqlAlchemyAlertRepository",
    "StatisticsRepository",
    "ThreatIntelCacheRepository",
]
