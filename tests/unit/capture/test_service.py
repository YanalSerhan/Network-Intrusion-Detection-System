"""Tests for the capture service lifecycle, status and packet callback."""

from typing import Any
from unittest.mock import MagicMock, patch

from network_defender.capture.models import CaptureStatus
from network_defender.capture.service import CaptureService
from tests.fixtures.packets import tcp_packet

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
    service._on_packet(tcp_packet())
    assert len(received) == 1


def test_packets_captured_counter_increments(service: CaptureService) -> None:
    service._on_packet(tcp_packet())
    service._on_packet(tcp_packet())
    assert service.get_status().packets_captured == 2
