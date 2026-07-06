"""
Unit tests for the capture-related SDK methods added in Milestone 3.

Scapy's AsyncSniffer is mocked to avoid requiring a real network interface.
"""

from pathlib import Path
from unittest.mock import MagicMock, patch

# pyrefly: ignore [missing-import]
import pytest

from network_defender.sdk.sdk import NetworkDefenderSDK
from network_defender.shared.config_models import AppConfig, CaptureConfig
from network_defender.shared.rate_limit_models import RateLimitConfig

# ---------------------------------------------------------------------------
# Fixture: minimal SDK with unlimited-rate capture config
# ---------------------------------------------------------------------------


@pytest.fixture()
def sdk() -> NetworkDefenderSDK:
    cfg = AppConfig(
        capture=CaptureConfig(
            interface="eth0",
            max_packets_per_second=0,
        )
    )
    rate_cfg = RateLimitConfig(services={})
    return NetworkDefenderSDK(app_config=cfg, rate_limit_config=rate_cfg)


# ---------------------------------------------------------------------------
# list_interfaces
# ---------------------------------------------------------------------------


def test_sdk_list_interfaces_returns_list(sdk: NetworkDefenderSDK) -> None:
    with patch(
        "network_defender.sdk.sdk.list_interfaces", return_value=["eth0", "lo"]
    ):
        result = sdk.list_interfaces()
    assert isinstance(result, list)
    assert "eth0" in result


# ---------------------------------------------------------------------------
# get_capture_status
# ---------------------------------------------------------------------------


def test_sdk_get_capture_status_returns_status(sdk: NetworkDefenderSDK) -> None:
    from network_defender.capture.models import CaptureStatus

    status = sdk.get_capture_status()
    assert isinstance(status, CaptureStatus)
    assert status.is_running is False


# ---------------------------------------------------------------------------
# start_capture / stop_capture
# ---------------------------------------------------------------------------


@patch("network_defender.capture.service.AsyncSniffer")
def test_sdk_start_capture_sets_running(
    mock_sniffer_cls: MagicMock, sdk: NetworkDefenderSDK
) -> None:
    mock_sniffer_cls.return_value = MagicMock()
    sdk.start_capture()
    assert sdk.get_capture_status().is_running is True
    sdk.stop_capture()


@patch("network_defender.capture.service.AsyncSniffer")
def test_sdk_stop_capture_clears_running(
    mock_sniffer_cls: MagicMock, sdk: NetworkDefenderSDK
) -> None:
    mock_sniffer_cls.return_value = MagicMock()
    sdk.start_capture()
    sdk.stop_capture()
    assert sdk.get_capture_status().is_running is False


# ---------------------------------------------------------------------------
# start_capture_from_pcap
# ---------------------------------------------------------------------------


def test_sdk_start_capture_from_pcap(sdk: NetworkDefenderSDK, tmp_path: Path) -> None:
    from scapy.layers.inet import IP, TCP
    from scapy.layers.l2 import Ether

    from network_defender.capture.pcap_io import write_pcap

    pcap_file = tmp_path / "test.pcap"
    pkt = Ether() / IP() / TCP()
    pkt.time = 1_700_000_000.0
    write_pcap([pkt], pcap_file)

    received: list[object] = []
    sdk._capture_service.set_packet_callback(received.append)
    sdk.start_capture_from_pcap(pcap_file)
    assert len(received) == 1


# ---------------------------------------------------------------------------
# save_capture_to_pcap
# ---------------------------------------------------------------------------


def test_sdk_save_capture_to_pcap(sdk: NetworkDefenderSDK, tmp_path: Path) -> None:
    from scapy.layers.inet import IP, TCP
    from scapy.layers.l2 import Ether

    pkt = Ether() / IP() / TCP()
    pkt.time = 1_700_000_000.0
    sdk._capture_service._on_packet(pkt)

    out = tmp_path / "sdk_save.pcap"
    sdk.save_capture_to_pcap(out)
    assert out.exists()
