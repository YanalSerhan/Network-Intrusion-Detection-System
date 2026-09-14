"""
The exfiltration detector's opinion about where the bytes went.

It had none until Milestone 21: a nightly backup to an internal file server
moved more data than most attacks and was counted, so the corpus case sat at
exactly the shipped threshold and no value separated it from a 30 MB staged
archive. Bytes that never leave the estate are not exfiltration by any
definition, and that is a rule rather than a number.
"""

from datetime import UTC, datetime

from network_defender.constants import Protocol
from network_defender.detectors.impl.movement import (
    DataExfiltrationConfig,
    DataExfiltrationDetector,
)
from network_defender.parser.models import ParsedPacket

MEGABYTE = 1_000_000


def _transfer(dst_ip: str, megabytes: int) -> list[ParsedPacket]:
    now = datetime.now(UTC)
    return [
        ParsedPacket(
            timestamp=now,
            src_ip="192.168.1.50",
            dst_ip=dst_ip,
            src_port=40000,
            dst_port=443,
            protocol=Protocol.TCP,
            length=MEGABYTE,
            raw_summary="bulk",
        )
        for _ in range(megabytes)
    ]


def _detector(**overrides: object) -> DataExfiltrationDetector:
    config = DataExfiltrationConfig(bytes_out_threshold=50 * MEGABYTE, **overrides)  # type: ignore[arg-type]
    return DataExfiltrationDetector(config)


def test_a_backup_to_an_internal_server_is_not_exfiltration() -> None:
    detector = _detector()
    for packet in _transfer("192.168.1.21", 60):
        detector.ingest(packet)
    assert detector.evaluate() == []


def test_the_same_volume_leaving_the_estate_is() -> None:
    detector = _detector()
    for packet in _transfer("203.0.113.90", 60):
        detector.ingest(packet)
    alerts = detector.evaluate()
    assert len(alerts) == 1
    assert alerts[0].evidence["bytes_out"] == 60 * MEGABYTE


def test_a_sanctioned_external_destination_is_excluded() -> None:
    detector = _detector(allowed_destinations=["203.0.113.0/24"])
    for packet in _transfer("203.0.113.90", 60):
        detector.ingest(packet)
    assert detector.evaluate() == []


def test_a_malformed_allowlist_entry_does_not_excuse_everything() -> None:
    """One typo in an operator's list must not stop the sensor detecting."""
    detector = _detector(allowed_destinations=["not-a-network", "203.0.113.91"])
    for packet in _transfer("203.0.113.90", 60):
        detector.ingest(packet)
    assert len(detector.evaluate()) == 1
