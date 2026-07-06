import pytest
from datetime import datetime, timezone
from network_defender.constants import Protocol
from network_defender.detectors.impl.heuristics import DnsTunnelingDetector, DnsTunnelingConfig
from network_defender.parser.models import ParsedPacket, DnsFields

def test_dns_tunneling_detector():
    config = DnsTunnelingConfig(query_count_threshold=2, entropy_threshold=3.5, time_window_seconds=10)
    detector = DnsTunnelingDetector(config)
    
    # High entropy domain name
    packet = ParsedPacket(
        timestamp=datetime.now(timezone.utc),
        src_ip="10.0.0.25",
        dst_ip="8.8.8.8",
        src_port=12345,
        dst_port=53,
        protocol=Protocol.DNS,
        length=200,
        dns=DnsFields(query_name="x1y2z3a4b5c6d7e8f9.example.com", record_type=1),
        raw_summary="DNS query"
    )

    detector.ingest(packet)
    detector.ingest(packet)
    
    alerts = detector.evaluate()
    assert len(alerts) == 1
    assert alerts[0].src_ip == "10.0.0.25"
    assert alerts[0].evidence["high_entropy"] == 2
