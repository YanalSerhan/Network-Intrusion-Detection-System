"""
Unit tests for capture/interface_discovery.py.

All Scapy calls are mocked so no real network interfaces are required.
"""

from unittest.mock import patch

import pytest

from network_defender.capture.interface_discovery import (
    auto_select_interface,
    is_loopback,
    is_virtual,
    list_interfaces,
)

# ---------------------------------------------------------------------------
# is_loopback
# ---------------------------------------------------------------------------


def test_is_loopback_matches_lo() -> None:
    assert is_loopback("lo") is True


def test_is_loopback_matches_lo0() -> None:
    assert is_loopback("lo0") is True


def test_is_loopback_does_not_match_eth0() -> None:
    assert is_loopback("eth0") is False


def test_is_loopback_does_not_match_wlan0() -> None:
    assert is_loopback("wlan0") is False


# ---------------------------------------------------------------------------
# is_virtual
# ---------------------------------------------------------------------------


def test_is_virtual_matches_docker0() -> None:
    assert is_virtual("docker0") is True


def test_is_virtual_matches_virbr0() -> None:
    assert is_virtual("virbr0") is True


def test_is_virtual_matches_veth_pair() -> None:
    assert is_virtual("veth1a2b3c") is True


def test_is_virtual_does_not_match_eth0() -> None:
    assert is_virtual("eth0") is False


# ---------------------------------------------------------------------------
# list_interfaces
# ---------------------------------------------------------------------------


def test_list_interfaces_returns_sorted_list() -> None:
    fake_ifaces = ["wlan0", "eth0", "lo"]
    _mock = "network_defender.capture.interface_discovery.get_if_list"
    with patch(_mock, return_value=fake_ifaces):
        result = list_interfaces()
    assert result == ["eth0", "lo", "wlan0"]


def test_list_interfaces_empty() -> None:
    _mock = "network_defender.capture.interface_discovery.get_if_list"
    with patch(_mock, return_value=[]):
        result = list_interfaces()
    assert result == []


# ---------------------------------------------------------------------------
# auto_select_interface
# ---------------------------------------------------------------------------


def test_auto_select_prefers_non_loopback() -> None:
    fake_ifaces = ["lo", "eth0", "wlan0"]
    _mock = "network_defender.capture.interface_discovery.get_if_list"
    with patch(_mock, return_value=fake_ifaces):
        result = auto_select_interface()
    assert result == "eth0"


def test_auto_select_skips_virtual() -> None:
    fake_ifaces = ["lo", "docker0", "wlan0"]
    _mock = "network_defender.capture.interface_discovery.get_if_list"
    with patch(_mock, return_value=fake_ifaces):
        result = auto_select_interface()
    assert result == "wlan0"


def test_auto_select_falls_back_to_loopback_if_nothing_else() -> None:
    _mock = "network_defender.capture.interface_discovery.get_if_list"
    with patch(_mock, return_value=["lo"]):
        result = auto_select_interface()
    assert result == "lo"


def test_auto_select_raises_on_empty_list() -> None:
    _mock = "network_defender.capture.interface_discovery.get_if_list"
    _raises = pytest.raises(RuntimeError, match="No network interfaces found")
    with patch(_mock, return_value=[]), _raises:
        auto_select_interface()
