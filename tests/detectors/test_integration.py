import pytest
from pathlib import Path
from datetime import datetime, timezone
from network_defender.services.detection import DetectionService
from network_defender.constants import Protocol
from network_defender.parser.models import ParsedPacket, TcpFlags

@pytest.fixture
def config_dir(tmp_path: Path):
    # Create a dummy config dir with detectors.json
    detectors_config = tmp_path / "detectors.json"
    detectors_config.write_text("""
    {
        "SynFloodDetector": {
            "enabled": true,
            "syn_count_threshold": 3
        }
    }
    """)
    return tmp_path

def test_detection_service_integration(config_dir):
    service = DetectionService(config_dir)
    service._do_start()
    
    assert len(service.registry.detectors) > 0
    
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

    for _ in range(3):
        service.process_packet(packet)
        
    alerts = service.evaluate_detectors()
    
    assert len(alerts) >= 1
    syn_alerts = [a for a in alerts if a.detector_name == "SynFloodDetector"]
    assert len(syn_alerts) == 1
    assert syn_alerts[0].dst_ip == "10.0.0.5"
