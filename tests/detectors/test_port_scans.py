import pytest
from datetime import datetime, timezone
from network_defender.constants import Protocol
from network_defender.detectors.impl.port_scans import TcpPortScanDetector, TcpPortScanConfig
from network_defender.parser.models import ParsedPacket

def test_tcp_port_scan_detector():
    config = TcpPortScanConfig(unique_ports_threshold=3, time_window_seconds=10)
    detector = TcpPortScanDetector(config)
    
    base_packet = ParsedPacket(
        timestamp=datetime.now(timezone.utc),
        src_ip="192.168.1.50",
        dst_ip="10.0.0.1",
        src_port=12345,
        dst_port=80,
        protocol=Protocol.TCP,
        length=64,
        raw_summary="TCP packet"
    )

    # Port 80
    detector.ingest(base_packet)
    # Port 443
    base_packet.dst_port = 443
    detector.ingest(base_packet)
    
    # Port 22 - crosses threshold
    base_packet.dst_port = 22
    detector.ingest(base_packet)
    
    alerts = detector.evaluate()
    assert len(alerts) == 1
    assert alerts[0].src_ip == "192.168.1.50"
    assert alerts[0].evidence["unique_ports"] == 3
