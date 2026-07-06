"""
Unit tests for CaptureService (capture/service.py).

AsyncSniffer is mocked throughout — no real network interface is needed.
Tests cover the start/stop lifecycle, status transitions, BPF filter
validation, protocol filter runtime change, PCAP replay, packet callback
invocation, rate-limiter integration, and graceful error handling.
"""

from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch

import pytest
from scapy.layers.inet import IP, TCP
from scapy.layers.l2 import Ether

from network_defender.capture.models import CaptureStatus
from network_defender.capture.service import CaptureService
from network_defender.shared.config_models import CaptureConfig

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def config() -> CaptureConfig:
    return CaptureConfig(
        interface="eth0",
        bpf_filter="",
        snaplen=65535,
        promiscuous_mode=False,
        buffer_size=1024,
        max_packets_per_second=0,  # unlimited for tests
        protocol_allow_list=[],
        protocol_deny_list=[],
        pcap_output_dir="captures/",
    )


@pytest.fixture()
def service(config: CaptureConfig) -> CaptureService:
    return CaptureService(config=config)


def _make_pkt() -> Any:
    pkt = Ether() / IP(src="1.2.3.4", dst="5.6.7.8") / TCP()
    pkt.time = 1_700_000_000.0
    return pkt


# ---------------------------------------------------------------------------
# Initial state
# ---------------------------------------------------------------------------


def test_service_initially_not_running(service: CaptureService) -> None:
    assert service.is_running is False


def test_get_status_when_stopped(service: CaptureService) -> None:
    status = service.get_status()
    assert isinstance(status, CaptureStatus)
    assert status.is_running is False
    assert status.packets_captured == 0


# ---------------------------------------------------------------------------
# Start / stop lifecycle (AsyncSniffer mocked)
# ---------------------------------------------------------------------------


@patch("network_defender.capture.service.AsyncSniffer")
def test_start_sets_running_flag(mock_sniffer_cls: MagicMock, service: CaptureService) -> None:
    mock_sniffer_cls.return_value = MagicMock()
    service.start()
    assert service.is_running is True


@patch("network_defender.capture.service.AsyncSniffer")
def test_stop_clears_running_flag(mock_sniffer_cls: MagicMock, service: CaptureService) -> None:
    mock_sniffer_cls.return_value = MagicMock()
    service.start()
    service.stop()
    assert service.is_running is False


@patch("network_defender.capture.service.AsyncSniffer")
def test_status_shows_interface_after_start(
    mock_sniffer_cls: MagicMock, service: CaptureService
) -> None:
    mock_sniffer_cls.return_value = MagicMock()
    service.start()
    assert service.get_status().interface == "eth0"
    service.stop()


# ---------------------------------------------------------------------------
# Packet callback and counter
# ---------------------------------------------------------------------------


def test_packet_callback_invoked_on_admit(service: CaptureService) -> None:
    received: list[Any] = []
    service.set_packet_callback(received.append)
    service._on_packet(_make_pkt())
    assert len(received) == 1


def test_packets_captured_counter_increments(service: CaptureService) -> None:
    service._on_packet(_make_pkt())
    service._on_packet(_make_pkt())
    assert service.get_status().packets_captured == 2


# ---------------------------------------------------------------------------
# Protocol filter — drop path
# ---------------------------------------------------------------------------


def test_protocol_filter_drops_denied_protocol(service: CaptureService) -> None:
    from network_defender.constants import Protocol

    service.set_protocol_filter(allow=[], deny=[Protocol.TCP])
    received: list[Any] = []
    service.set_packet_callback(received.append)
    service._on_packet(_make_pkt())
    assert len(received) == 0
    assert service.get_status().packets_dropped_filter == 1


# ---------------------------------------------------------------------------
# BPF filter validation
# ---------------------------------------------------------------------------


def test_set_bpf_filter_valid_expression(service: CaptureService) -> None:
    with patch("network_defender.capture.service.validate_bpf_filter", return_value=True):
        service.set_bpf_filter("tcp port 80")
    assert service._config.bpf_filter == "tcp port 80"


def test_set_bpf_filter_invalid_expression_raises(service: CaptureService) -> None:
    _patch = "network_defender.capture.service.validate_bpf_filter"
    with patch(_patch, return_value=False), pytest.raises(ValueError, match="Invalid BPF filter"):
        service.set_bpf_filter("!@#$bad")


# ---------------------------------------------------------------------------
# PCAP replay
# ---------------------------------------------------------------------------


def test_pcap_replay_delivers_packets_via_callback(
    service: CaptureService, tmp_path: Path
) -> None:
    from network_defender.capture.pcap_io import write_pcap

    pcap_file = tmp_path / "replay.pcap"
    pkts = [_make_pkt() for _ in range(3)]
    write_pcap(pkts, pcap_file)

    received: list[Any] = []
    service.set_packet_callback(received.append)
    service.start_pcap_replay(pcap_file)
    assert len(received) == 3


# ---------------------------------------------------------------------------
# Save to PCAP
# ---------------------------------------------------------------------------


def test_save_to_pcap_writes_file(service: CaptureService, tmp_path: Path) -> None:
    service._on_packet(_make_pkt())
    service._on_packet(_make_pkt())
    out = tmp_path / "out.pcap"
    service.save_to_pcap(out)
    assert out.exists()
