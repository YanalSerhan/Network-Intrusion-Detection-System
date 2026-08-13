"""Tests for the SSH and HTTP credential brute force detectors."""

from datetime import UTC, datetime

from network_defender.constants import Protocol
from network_defender.detectors.impl.brute_force import HttpBruteForceConfig, HttpBruteForceDetector
from network_defender.parser.models import HttpFields, ParsedPacket


def test_http_brute_force_detector() -> None:
    config = HttpBruteForceConfig(connection_count_threshold=3, time_window_seconds=10)
    detector = HttpBruteForceDetector(config)

    packet = ParsedPacket(
        timestamp=datetime.now(UTC),
        src_ip="10.0.0.99",
        dst_ip="10.0.0.1",
        src_port=12345,
        dst_port=80,
        protocol=Protocol.HTTP,
        length=200,
        http=HttpFields(method="POST", path="/api/login"),
        raw_summary="HTTP POST"
    )

    for _ in range(2):
        detector.ingest(packet)

    detector.ingest(packet)

    alerts = detector.evaluate()
    assert len(alerts) == 1
    assert alerts[0].src_ip == "10.0.0.99"
    assert alerts[0].evidence["request_count"] == 3
