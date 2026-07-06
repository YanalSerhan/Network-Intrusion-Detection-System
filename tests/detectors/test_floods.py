import pytest
from datetime import datetime, timezone
from network_defender.constants import Protocol
from network_defender.detectors.impl.floods import SynFloodDetector, SynFloodConfig
from network_defender.parser.models import ParsedPacket, TcpFlags

@pytest.fixture
def syn_flood_detector():
    config = SynFloodConfig(syn_count_threshold=5, time_window_seconds=1)
    return SynFloodDetector(config)

def test_syn_flood_detector_triggers(syn_flood_detector):
    packet = ParsedPacket(
        timestamp=datetime.now(timezone.utc),
        src_ip="192.168.1.100",
        dst_ip="10.0.0.5",
        src_port=12345,
        dst_port=80,
        protocol=Protocol.TCP,
        length=64,
        tcp_flags=TcpFlags(syn=True),
        raw_summary="SYN packet"
    )

    # Ingest below threshold
    for _ in range(4):
        syn_flood_detector.ingest(packet)
    
    alerts = syn_flood_detector.evaluate()
    assert len(alerts) == 0

    # Ingest reaching threshold
    for _ in range(5):
        syn_flood_detector.ingest(packet)

    alerts = syn_flood_detector.evaluate()
    assert len(alerts) == 1
    assert alerts[0].dst_ip == "10.0.0.5"
    assert alerts[0].detector_name == "SynFloodDetector"

def test_syn_flood_detector_resets(syn_flood_detector):
    packet = ParsedPacket(
        timestamp=datetime.now(timezone.utc),
        src_ip="192.168.1.100",
        dst_ip="10.0.0.5",
        src_port=12345,
        dst_port=80,
        protocol=Protocol.TCP,
        length=64,
        tcp_flags=TcpFlags(syn=True),
        raw_summary="SYN packet"
    )

    # Trigger alert
    for _ in range(5):
        syn_flood_detector.ingest(packet)
    
    alerts = syn_flood_detector.evaluate()
    assert len(alerts) == 1

    # Next evaluation without packets should have no alerts
    alerts = syn_flood_detector.evaluate()
    assert len(alerts) == 0
