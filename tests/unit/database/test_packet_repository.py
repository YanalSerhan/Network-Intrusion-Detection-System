"""Tests for packet evidence storage and its cascade from alerts."""

from datetime import UTC, datetime, timedelta

from network_defender.database.repositories import (
    PacketRepository,
    SqlAlchemyAlertRepository,
)
from tests.fixtures.builders import make_alert, make_packet

# --------------------------------------------------------------------------
# Packets
# --------------------------------------------------------------------------


def test_packet_evidence_roundtrip(
    alert_repo: SqlAlchemyAlertRepository, packet_repo: PacketRepository
) -> None:
    alert = make_alert()
    alert_repo.save(alert)
    packet_repo.save(make_packet(), alert_id=alert.alert_id)

    evidence = packet_repo.list_for_alert(alert.alert_id)
    assert len(evidence) == 1
    assert evidence[0].dst_port == 443
    assert evidence[0].tcp_flags is not None
    assert evidence[0].tcp_flags.syn is True  # rebuilt from the JSON column


def test_save_many_and_ordering(
    alert_repo: SqlAlchemyAlertRepository, packet_repo: PacketRepository
) -> None:
    alert = make_alert()
    alert_repo.save(alert)
    now = datetime.now(UTC)
    packets = [make_packet(timestamp=now + timedelta(seconds=i)) for i in range(5)]

    assert packet_repo.save_many(packets, alert_id=alert.alert_id) == 5
    assert packet_repo.save_many([], alert_id=alert.alert_id) == 0

    stored = packet_repo.list_for_alert(alert.alert_id)
    assert [p.timestamp for p in stored] == sorted(p.timestamp for p in stored)


def test_deleting_an_alert_cascades_to_its_packets(
    alert_repo: SqlAlchemyAlertRepository, packet_repo: PacketRepository
) -> None:
    """Requires PRAGMA foreign_keys=ON; SQLite ignores cascades without it."""
    alert = make_alert()
    alert_repo.save(alert)
    packet_repo.save_many([make_packet(), make_packet()], alert_id=alert.alert_id)
    assert packet_repo.count() == 2

    alert_repo.clear()
    assert packet_repo.count() == 0


def test_packet_limit_is_applied(
    alert_repo: SqlAlchemyAlertRepository, packet_repo: PacketRepository
) -> None:
    alert = make_alert()
    alert_repo.save(alert)
    packet_repo.save_many([make_packet() for _ in range(10)], alert_id=alert.alert_id)
    assert len(packet_repo.list_for_alert(alert.alert_id, limit=3)) == 3
