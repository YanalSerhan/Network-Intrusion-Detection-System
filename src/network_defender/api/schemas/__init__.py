"""
API request and response schemas.

Kept separate from the domain models so the wire format can evolve without
forcing a change to detection or persistence, and so list endpoints can return
a compact projection rather than every field of every record.
"""

from .alerts import AlertDetail, AlertPage, AlertStatusUpdate, AlertSummary
from .common import (
    MAX_PAGE_SIZE,
    ErrorDetail,
    ErrorResponse,
    PageMeta,
    PaginationParams,
    build_meta,
)
from .resources import (
    ComponentHealth,
    ConfigResponse,
    HealthResponse,
    LivenessResponse,
    PacketPage,
    PacketView,
    RulePage,
    RuleReloadResult,
    RuleToggle,
    RuleView,
    StatisticsPoint,
    StatisticsSummary,
    TopTalker,
)

__all__ = [
    "MAX_PAGE_SIZE",
    "AlertDetail",
    "AlertPage",
    "AlertStatusUpdate",
    "AlertSummary",
    "ComponentHealth",
    "ConfigResponse",
    "ErrorDetail",
    "ErrorResponse",
    "HealthResponse",
    "LivenessResponse",
    "PacketPage",
    "PacketView",
    "PageMeta",
    "PaginationParams",
    "RulePage",
    "RuleReloadResult",
    "RuleToggle",
    "RuleView",
    "StatisticsPoint",
    "StatisticsSummary",
    "TopTalker",
    "build_meta",
]
