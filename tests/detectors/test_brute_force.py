import pytest
from datetime import datetime, timezone
from network_defender.constants import Protocol
from network_defender.detectors.impl.brute_force import HttpBruteForceDetector, HttpBruteForceConfig
from network_defender.parser.models import ParsedPacket, HttpFields

def test_http_brute_force_detector():
    config = HttpBruteForceConfig(connection_count_threshold=3, time_window_seconds=10)
    detector = HttpBruteForceDetector(config)
    
    packet = ParsedPacket(
        timestamp=datetime.now(timezone.utc),
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
