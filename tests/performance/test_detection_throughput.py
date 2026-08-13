"""
Performance: sustained packet rate through the full detection engine.

Every enabled detector ingests every packet, so this is the measurement that
scales worst as detectors are added — and the one that decides whether the
sensor keeps up with a link or starts dropping traffic. The traffic mix is
deliberately varied: a single repeated packet would let per-source state
collapse to one entry and hide exactly the growth this is watching for.
"""

from datetime import UTC, datetime, timedelta

from network_defender.constants import Protocol
from network_defender.parser.models import ParsedPacket, TcpFlags
from network_defender.services.detection import DetectionService
from network_defender.shared.paths import PROJECT_ROOT
from tests.fixtures.benchmark import measure, report

#: Large enough to dwarf setup cost, small enough to stay a few seconds.
PACKET_COUNT = 20_000

#: Distinct sources, so the detectors' per-source state actually grows.
SOURCE_COUNT = 250

#: A conservative floor for a slow, shared CI runner.
MIN_PACKETS_PER_SECOND = 500

#: Flushing the windows must stay interactive; it runs on a timer in
#: production and blocks the next batch of ingest while it works.
MAX_EVALUATION_SECONDS = 5.0


def _traffic(count: int) -> list[ParsedPacket]:
    """Build a varied stream of parsed packets across many sources and ports."""
    base = datetime.now(UTC)
    return [
        ParsedPacket(
            timestamp=base + timedelta(milliseconds=i),
            src_ip=f"10.0.{i % SOURCE_COUNT // 256}.{i % SOURCE_COUNT % 256}",
            dst_ip="192.168.1.10",
            src_port=1024 + (i % 60000),
            dst_port=1000 + (i % 500),
            protocol=Protocol.TCP,
            length=64 + (i % 512),
            tcp_flags=TcpFlags(syn=True),
            raw_summary="TCP SYN",
        )
        for i in range(count)
    ]


def _started_detection() -> DetectionService:
    """A detection service with every shipped detector loaded, no rule engine."""
    service = DetectionService(config_dir=PROJECT_ROOT / "config")
    service.registry.load_detectors()
    return service


def test_detection_sustains_the_ingest_floor() -> None:
    """Ingest is the hot path: every detector sees every packet."""
    service = _started_detection()
    packets = _traffic(PACKET_COUNT)

    rate = measure(PACKET_COUNT, lambda: [service.process_packet(p) for p in packets])
    report("detection ingest", rate)

    assert service.health_check()["packets_processed"] == PACKET_COUNT
    assert rate.per_second >= MIN_PACKETS_PER_SECOND, (
        f"Detection ingest {rate.per_second:.0f} pkt/s is below the "
        f"{MIN_PACKETS_PER_SECOND} pkt/s floor."
    )


def test_flushing_the_windows_stays_bounded() -> None:
    """Evaluation walks all accumulated state; it must not grow unbounded."""
    service = _started_detection()
    for packet in _traffic(PACKET_COUNT):
        service.process_packet(packet)

    rate = measure(1, service.evaluate_detectors)
    report("detector evaluation", rate)

    assert rate.seconds <= MAX_EVALUATION_SECONDS, (
        f"Evaluating {SOURCE_COUNT} sources took {rate.seconds:.2f}s, over the "
        f"{MAX_EVALUATION_SECONDS}s budget."
    )


def test_evaluation_releases_the_state_it_walked() -> None:
    """A window that is not cleared turns every later evaluation into a leak."""
    service = _started_detection()
    for packet in _traffic(PACKET_COUNT):
        service.process_packet(packet)
    service.evaluate_detectors()

    second_pass = measure(1, service.evaluate_detectors)
    report("detector evaluation (empty)", second_pass)

    assert second_pass.seconds <= MAX_EVALUATION_SECONDS
    assert service.evaluate_detectors() == []
