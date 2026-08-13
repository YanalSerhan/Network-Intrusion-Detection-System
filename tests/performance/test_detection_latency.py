"""
Performance: per-packet latency through capture, parsing and detection.

Throughput is an average, and an average hides a stall. A sensor that keeps
up on paper but blocks for 200 ms every few thousand packets drops traffic on
a busy link, so this measures the distribution and asserts on the tail.
"""

import time

from scapy.utils import rdpcap

from network_defender.parser.parser import PacketParser
from network_defender.services.detection import DetectionService
from network_defender.shared.paths import PROJECT_ROOT
from tests.fixtures.benchmark import percentile
from tests.fixtures.pcaps import sample_pcap

#: Replayed repeatedly to build a distribution worth taking a percentile of.
REPLAY_ROUNDS = 20

#: Generous ceilings for a shared runner. They are two orders of magnitude
#: above the observed figures, so only a real stall trips them.
MAX_P95_SECONDS = 0.05
MAX_P99_SECONDS = 0.20


def test_per_packet_latency_has_no_long_tail() -> None:
    """No packet should stall the pipeline, however fast the average is."""
    packets = list(rdpcap(str(sample_pcap("tcp_port_scan")))) * REPLAY_ROUNDS
    parser = PacketParser()
    parser.start()
    service = DetectionService(config_dir=PROJECT_ROOT / "config")
    service.registry.load_detectors()

    latencies = []
    for packet in packets:
        start = time.perf_counter()
        parsed = parser.parse_safe(packet)
        if parsed is not None:
            service.process_packet(parsed)
        latencies.append(time.perf_counter() - start)

    p95 = percentile(latencies, 0.95)
    p99 = percentile(latencies, 0.99)
    print(
        f"\n[benchmark] per-packet latency over {len(latencies):,} packets: "
        f"p95={p95 * 1000:.3f}ms p99={p99 * 1000:.3f}ms max={max(latencies) * 1000:.3f}ms"
    )

    assert p95 <= MAX_P95_SECONDS, f"p95 latency {p95 * 1000:.1f}ms exceeds the budget."
    assert p99 <= MAX_P99_SECONDS, f"p99 latency {p99 * 1000:.1f}ms exceeds the budget."


def test_detection_latency_does_not_grow_with_accumulated_state() -> None:
    """
    The last packet of a long run must cost what the first one did.

    Per-source state is held until the window is flushed. If a detector
    scanned that state on every ingest instead of at evaluation time, the
    cost per packet would climb with the run — invisible to a throughput
    average taken over the whole batch, and fatal on a long-lived sensor.
    """
    packets = list(rdpcap(str(sample_pcap("lateral_movement")))) * REPLAY_ROUNDS
    parser = PacketParser()
    parser.start()
    service = DetectionService(config_dir=PROJECT_ROOT / "config")
    service.registry.load_detectors()

    parsed = [p for p in (parser.parse_safe(pkt) for pkt in packets) if p is not None]
    sample_size = max(len(parsed) // 10, 1)

    def _mean_latency(batch: list) -> float:
        start = time.perf_counter()
        for packet in batch:
            service.process_packet(packet)
        return (time.perf_counter() - start) / len(batch)

    first = _mean_latency(parsed[:sample_size])
    for packet in parsed[sample_size:-sample_size]:
        service.process_packet(packet)
    last = _mean_latency(parsed[-sample_size:])

    print(f"\n[benchmark] mean ingest latency: first={first * 1e6:.1f}µs last={last * 1e6:.1f}µs")

    # A wide multiple: this is looking for growth with n, not for jitter.
    assert last <= max(first * 10, 0.001), (
        f"Ingest latency grew from {first * 1e6:.1f}µs to {last * 1e6:.1f}µs "
        f"over the run, which suggests work proportional to accumulated state."
    )
