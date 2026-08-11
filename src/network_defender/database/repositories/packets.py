"""
Packet evidence repository.

Data Setup:  Session factory injected via __init__.
Data Input:  ParsedPacket objects, optionally linked to an alert.
Data Output: ParsedPacket objects for an alert's detail view.

Only packets retained as alert evidence pass through here. Deleting an alert
cascades to its packets, so evidence never outlives the finding it supports.
"""

from uuid import UUID

from sqlalchemy import func, select
from sqlalchemy.orm import Session, sessionmaker

from ...parser.models import ParsedPacket
from ..engine import session_scope
from ..mappers import packet_to_record, record_to_packet
from ..models import PacketRecord

#: Cap on evidence packets returned for one alert, so a flood's detail view
#: cannot pull tens of thousands of rows into the API response.
PACKET_QUERY_DEFAULT_LIMIT = 100


class PacketRepository:
    """Stores and retrieves the packets kept as alert evidence."""

    def __init__(self, session_factory: sessionmaker[Session]) -> None:
        """
        Initialise the repository.

        Args:
            session_factory: Factory producing sessions bound to the engine.
        """
        self._session_factory = session_factory

    def save(self, packet: ParsedPacket, alert_id: UUID | None = None) -> None:
        """
        Persist a single packet, optionally linked to an alert.

        Args:
            packet:   The parsed packet to retain.
            alert_id: The alert this packet is evidence for.
        """
        with session_scope(self._session_factory) as session:
            session.add(packet_to_record(packet, alert_id))

    def save_many(self, packets: list[ParsedPacket], alert_id: UUID | None = None) -> int:
        """
        Persist several packets in one transaction.

        Args:
            packets:  The parsed packets to retain.
            alert_id: The alert they are evidence for.

        Returns:
            Number of packets written.
        """
        if not packets:
            return 0
        with session_scope(self._session_factory) as session:
            session.add_all([packet_to_record(packet, alert_id) for packet in packets])
        return len(packets)

    def list_for_alert(
        self, alert_id: UUID, limit: int = PACKET_QUERY_DEFAULT_LIMIT
    ) -> list[ParsedPacket]:
        """
        Return the evidence packets for an alert, oldest first.

        Args:
            alert_id: The alert to fetch evidence for.
            limit:    Maximum number of packets to return.

        Returns:
            ParsedPacket models in capture order.
        """
        statement = (
            select(PacketRecord)
            .where(PacketRecord.alert_id == alert_id)
            .order_by(PacketRecord.timestamp)
            .limit(limit)
        )
        with session_scope(self._session_factory) as session:
            return [record_to_packet(record) for record in session.scalars(statement)]

    def list_packets(
        self,
        alert_id: UUID | None = None,
        protocol: str | None = None,
        src_ip: str | None = None,
        limit: int = PACKET_QUERY_DEFAULT_LIMIT,
        offset: int = 0,
    ) -> list[ParsedPacket]:
        """
        Return retained packets matching the given filters, oldest first.

        Args:
            alert_id: Restrict to evidence for one alert.
            protocol: Restrict to one protocol.
            src_ip:   Restrict to one source address.
            limit:    Maximum number of packets to return.
            offset:   Number of matching packets to skip.

        Returns:
            ParsedPacket models in capture order.
        """
        statement = select(PacketRecord)
        if alert_id is not None:
            statement = statement.where(PacketRecord.alert_id == alert_id)
        if protocol is not None:
            statement = statement.where(PacketRecord.protocol == protocol)
        if src_ip is not None:
            statement = statement.where(PacketRecord.src_ip == src_ip)

        statement = statement.order_by(PacketRecord.timestamp).limit(limit).offset(offset)
        with session_scope(self._session_factory) as session:
            return [record_to_packet(record) for record in session.scalars(statement)]

    def get(self, packet_id: int) -> ParsedPacket | None:
        """Return a single retained packet by row id, or None."""
        with session_scope(self._session_factory) as session:
            record = session.get(PacketRecord, packet_id)
            return record_to_packet(record) if record is not None else None

    def count(self) -> int:
        """Return the total number of retained packets."""
        with session_scope(self._session_factory) as session:
            return int(session.scalar(select(func.count()).select_from(PacketRecord)) or 0)

    def clear(self) -> None:
        """Delete every retained packet."""
        with session_scope(self._session_factory) as session:
            for record in session.scalars(select(PacketRecord)):
                session.delete(record)
