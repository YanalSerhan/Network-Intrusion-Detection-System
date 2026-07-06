import time
import sys
import os
from pathlib import Path
from datetime import datetime, timezone

# Add src to Python path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from network_defender.services.detection import DetectionService
from network_defender.constants import Protocol
from network_defender.parser.models import ParsedPacket, TcpFlags

def main():
    config_dir = Path(__file__).resolve().parent.parent / "config"
    service = DetectionService(config_dir)
    service._do_start()

    num_packets = 100_000
    print(f"Benchmarking Detection Engine with {num_packets} synthetic packets...")

    base_packet = ParsedPacket(
        timestamp=datetime.now(timezone.utc),
        src_ip="192.168.1.50",
        dst_ip="10.0.0.1",
        src_port=12345,
        dst_port=80,
        protocol=Protocol.TCP,
        length=64,
        tcp_flags=TcpFlags(syn=True),
        raw_summary="TCP packet"
    )

    start_time = time.perf_counter()

    for i in range(num_packets):
        # vary ports slightly to prevent hitting port scan limits immediately
        base_packet.dst_port = 80 + (i % 5)
        service.process_packet(base_packet)
    
    # Force evaluate to clear state
    alerts = service.evaluate_detectors()

    end_time = time.perf_counter()
    duration = end_time - start_time
    eps = num_packets / duration

    print(f"Finished. Duration: {duration:.2f} seconds.")
    print(f"Events per second (EPS): {eps:.2f}")
    print(f"Alerts generated during benchmark: {len(alerts)}")

if __name__ == "__main__":
    main()
