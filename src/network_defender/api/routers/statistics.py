"""
/statistics endpoints.

Data Setup:  SDK injected per request.
Data Input:  Time-window query parameters.
Data Output: Aggregate counters and time series for the dashboard.
"""

from typing import Annotated

from fastapi import APIRouter, Query

from ..dependencies import AuthDep, SdkDep
from ..schemas.operations import StatisticsPoint, StatisticsSummary, TopTalker

router = APIRouter(prefix="/statistics", tags=["statistics"], dependencies=[AuthDep])

#: How many source addresses the overview shows. Enough to spot an outlier,
#: few enough to render in a sidebar.
TOP_TALKER_LIMIT = 10


@router.get("", response_model=StatisticsSummary, summary="Traffic and alert summary")
def get_summary(sdk: SdkDep) -> StatisticsSummary:
    """Return aggregate counters for the dashboard overview."""
    stats = sdk.get_alert_statistics()
    breakdown = sdk.get_alert_breakdown(top_talker_limit=TOP_TALKER_LIMIT)

    return StatisticsSummary(
        total_alerts=stats["total_alerts"],
        alerts_by_severity=stats["by_severity"],
        total_packets_retained=breakdown["packets_retained"],
        top_talkers=[
            TopTalker(ip=ip, alert_count=count) for ip, count in breakdown["top_talkers"].items()
        ],
        protocol_distribution=breakdown["protocol_distribution"],
    )


@router.get(
    "/timeseries", response_model=list[StatisticsPoint], summary="Counter time series"
)
def get_timeseries(
    sdk: SdkDep,
    hours: Annotated[
        int, Query(ge=1, le=8760, description="Window length in hours.")
    ] = 24,
) -> list[StatisticsPoint]:
    """
    Return counter snapshots, oldest first.

    Live counters reset when the sensor restarts, so trend charts read from
    persisted snapshots rather than from in-memory state.
    """
    return [StatisticsPoint(**point) for point in sdk.get_statistics_series(hours=hours)]
