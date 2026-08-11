"""
/packets endpoints.

Data Setup:  SDK injected per request.
Data Input:  Query filters and path identifiers.
Data Output: Packets retained as alert evidence.

Only alert-linked packets exist (ADR 5), so this resource is evidence, not a
traffic archive. `/packets?alert_id=...` is the primary access path; the
unfiltered listing exists for browsing and is bounded by the same page limits.
"""

from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Path, Query

from ..dependencies import AuthDep, PaginationDep, SdkDep
from ..errors import NotFoundError
from ..schemas.common import build_meta
from ..schemas.resources import PacketPage, PacketView

router = APIRouter(prefix="/packets", tags=["packets"], dependencies=[AuthDep])


@router.get("", response_model=PacketPage, summary="List retained packets")
def list_packets(
    sdk: SdkDep,
    pagination: PaginationDep,
    alert_id: Annotated[
        UUID | None, Query(description="Only packets retained for this alert.")
    ] = None,
    protocol: Annotated[str | None, Query(description="Filter by protocol.")] = None,
    src_ip: Annotated[str | None, Query(description="Filter by source address.")] = None,
) -> PacketPage:
    """Return retained packets, oldest first within an alert."""
    packets = sdk.list_packets(
        alert_id=alert_id,
        protocol=protocol,
        src_ip=src_ip,
        limit=pagination.limit,
        offset=pagination.offset,
    )
    return PacketPage(
        items=[PacketView.from_domain(packet) for packet in packets],
        meta=build_meta(len(packets), pagination.limit, pagination.offset),
    )


@router.get("/{packet_id}", response_model=PacketView, summary="Get a packet")
def get_packet(
    sdk: SdkDep,
    packet_id: Annotated[int, Path(ge=1, description="Packet row identifier.")],
) -> PacketView:
    """
    Return a single retained packet.

    Raises:
        NotFoundError: If no packet has this identifier.
    """
    packet = sdk.get_packet(packet_id)
    if packet is None:
        raise NotFoundError(f"No packet with id '{packet_id}'.")
    return PacketView.from_domain(packet)
