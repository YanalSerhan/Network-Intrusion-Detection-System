"""Tests for replaying a PCAP through the live callback and exporting one."""

from pathlib import Path
from typing import Any

from network_defender.capture.service import CaptureService
from tests.fixtures.packets import tcp_packet

# ---------------------------------------------------------------------------
# PCAP replay
# ---------------------------------------------------------------------------


def test_pcap_replay_delivers_packets_via_callback(
    service: CaptureService, tmp_path: Path
) -> None:
    from network_defender.capture.pcap_io import write_pcap

    pcap_file = tmp_path / "replay.pcap"
    pkts = [tcp_packet() for _ in range(3)]
    write_pcap(pkts, pcap_file)

    received: list[Any] = []
    service.set_packet_callback(received.append)
    service.start_pcap_replay(pcap_file)
    assert len(received) == 3

# ---------------------------------------------------------------------------
# Save to PCAP
# ---------------------------------------------------------------------------


def test_save_to_pcap_writes_file(service: CaptureService, tmp_path: Path) -> None:
    service._on_packet(tcp_packet())
    service._on_packet(tcp_packet())
    out = tmp_path / "out.pcap"
    service.save_to_pcap(out)
    assert out.exists()
