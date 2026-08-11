"""
/alerts endpoints.

Data Setup:  SDK injected per request.
Data Input:  Query filters, path identifiers and status-update bodies.
Data Output: Alert summaries, details and evidence.

Every handler is a thin translation layer: parse inputs, call one SDK method,
project the result onto a response schema. No filtering, scoring or persistence
logic lives here, so the API cannot drift from the CLI or dashboard.
"""

from datetime import UTC, datetime, timedelta
from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Path, Query

from ...constants import AlertStatus, Severity
from ..dependencies import AuthDep, PaginationDep, SdkDep
from ..errors import NotFoundError
from ..schemas.alerts import AlertDetail, AlertPage, AlertStatusUpdate, AlertSummary
from ..schemas.common import build_meta
from ..schemas.resources import PacketView

router = APIRouter(prefix="/alerts", tags=["alerts"], dependencies=[AuthDep])


@router.get("", response_model=AlertPage, summary="List alerts")
def list_alerts(
    sdk: SdkDep,
    pagination: PaginationDep,
    severity: Annotated[Severity | None, Query(description="Filter by severity.")] = None,
    status: Annotated[AlertStatus | None, Query(description="Filter by triage status.")] = None,
    hours: Annotated[
        int | None,
        Query(ge=1, le=8760, description="Only alerts raised in the last N hours."),
    ] = None,
) -> AlertPage:
    """
    Return alerts, newest first.

    Filtering happens in the database, not in the API process, so a large
    result set never has to be loaded to be discarded.
    """
    since = datetime.now(UTC) - timedelta(hours=hours) if hours else None
    alerts = sdk.list_alerts(
        severity=severity,
        status=status,
        since=since,
        limit=pagination.limit,
        offset=pagination.offset,
    )
    # `total` is only reported for the unfiltered case: counting under every
    # filter combination would double the query cost of the common request.
    total = sdk.get_alert_statistics()["total_alerts"] if not (status or hours) else None
    if severity is not None and total is not None:
        total = sdk.get_alert_statistics()["by_severity"].get(severity.value)

    return AlertPage(
        items=[AlertSummary.from_domain(alert) for alert in alerts],
        meta=build_meta(len(alerts), pagination.limit, pagination.offset, total),
    )


@router.get("/{alert_id}", response_model=AlertDetail, summary="Get an alert")
def get_alert(
    sdk: SdkDep,
    alert_id: Annotated[UUID, Path(description="Alert identifier.")],
) -> AlertDetail:
    """
    Return one alert with its evidence and threat intel enrichment.

    Raises:
        NotFoundError: If no alert has this identifier.
    """
    alert = sdk.get_alert(alert_id)
    if alert is None:
        raise NotFoundError(f"No alert with id '{alert_id}'.")
    return AlertDetail.from_domain(alert)


@router.get(
    "/{alert_id}/packets",
    response_model=list[PacketView],
    summary="Get an alert's packet evidence",
)
def get_alert_packets(
    sdk: SdkDep,
    alert_id: Annotated[UUID, Path(description="Alert identifier.")],
) -> list[PacketView]:
    """
    Return the packets retained as evidence for an alert, in capture order.

    Raises:
        NotFoundError: If no alert has this identifier.
    """
    if sdk.get_alert(alert_id) is None:
        raise NotFoundError(f"No alert with id '{alert_id}'.")
    return [PacketView.from_domain(packet) for packet in sdk.get_alert_packets(alert_id)]


@router.patch("/{alert_id}", response_model=AlertDetail, summary="Update triage status")
def update_alert_status(
    sdk: SdkDep,
    alert_id: Annotated[UUID, Path(description="Alert identifier.")],
    update: AlertStatusUpdate,
) -> AlertDetail:
    """
    Move an alert through the triage workflow.

    Raises:
        NotFoundError: If no alert has this identifier.
    """
    alert = sdk.set_alert_status(alert_id, update.status)
    if alert is None:
        raise NotFoundError(f"No alert with id '{alert_id}'.")
    return AlertDetail.from_domain(alert)


@router.post(
    "/{alert_id}/enrich", response_model=AlertDetail, summary="Enrich an alert now"
)
def enrich_alert(
    sdk: SdkDep,
    alert_id: Annotated[UUID, Path(description="Alert identifier.")],
) -> AlertDetail:
    """
    Run threat intel enrichment synchronously for one alert.

    Background enrichment is dropped under load, so an analyst opening an
    un-enriched alert needs a way to request it on demand.

    Raises:
        NotFoundError: If no alert has this identifier.
    """
    if sdk.get_alert(alert_id) is None:
        raise NotFoundError(f"No alert with id '{alert_id}'.")

    sdk.enrich_alert_now(alert_id)
    enriched = sdk.get_alert(alert_id)
    if enriched is None:  # pragma: no cover - the alert existed a moment ago
        raise NotFoundError(f"No alert with id '{alert_id}'.")
    return AlertDetail.from_domain(enriched)
