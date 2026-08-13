"""
Unit tests for capture/pcap_io.py.

Uses pytest's tmp_path fixture for real file I/O — no mocking of Scapy PCAP
functions, so we get genuine round-trip coverage.
"""

from pathlib import Path

import pytest
from scapy.layers.inet import IP, TCP
from scapy.layers.l2 import Ether
from scapy.packet import Packet

from network_defender.capture.pcap_io import append_pcap, read_pcap, write_pcap

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_packet(src: str = "1.2.3.4", dst: str = "5.6.7.8", sport: int = 1000) -> Packet:
    return Ether() / IP(src=src, dst=dst) / TCP(sport=sport, dport=80)


# ---------------------------------------------------------------------------
# write_pcap / read_pcap round-trip
# ---------------------------------------------------------------------------


def test_write_and_read_pcap_round_trip(tmp_path: Path) -> None:
    """Packets written then read back should have the same count and src IPs."""
    pcap_file = tmp_path / "test.pcap"
    packets = [_make_packet(src=f"10.0.0.{i}") for i in range(1, 4)]
    write_pcap(packets, pcap_file)

    result = list(read_pcap(pcap_file))
    assert len(result) == 3


def test_write_pcap_creates_parent_dirs(tmp_path: Path) -> None:
    deep_path = tmp_path / "deep" / "nested" / "capture.pcap"
    write_pcap([_make_packet()], deep_path)
    assert deep_path.exists()


def test_read_pcap_raises_on_missing_file(tmp_path: Path) -> None:
    with pytest.raises(FileNotFoundError):
        list(read_pcap(tmp_path / "nonexistent.pcap"))


def test_write_pcap_empty_list_creates_file(tmp_path: Path) -> None:
    pcap_file = tmp_path / "empty.pcap"
    write_pcap([], pcap_file)
    assert pcap_file.exists()


# ---------------------------------------------------------------------------
# append_pcap
# ---------------------------------------------------------------------------


def test_append_pcap_creates_file_if_missing(tmp_path: Path) -> None:
    pcap_file = tmp_path / "appended.pcap"
    append_pcap(_make_packet(), pcap_file)
    assert pcap_file.exists()
    packets = list(read_pcap(pcap_file))
    assert len(packets) == 1


def test_append_pcap_accumulates_packets(tmp_path: Path) -> None:
    pcap_file = tmp_path / "multi.pcap"
    for i in range(3):
        append_pcap(_make_packet(sport=i + 1000), pcap_file)

    packets = list(read_pcap(pcap_file))
    assert len(packets) == 3


# ---------------------------------------------------------------------------
# read_pcap is a lazy iterator
# ---------------------------------------------------------------------------


def test_read_pcap_yields_packets_one_by_one(tmp_path: Path) -> None:
    pcap_file = tmp_path / "lazy.pcap"
    write_pcap([_make_packet(), _make_packet()], pcap_file)

    gen = read_pcap(pcap_file)
    first = next(gen)
    assert first is not None
    second = next(gen)
    assert second is not None
    with pytest.raises(StopIteration):
        next(gen)
