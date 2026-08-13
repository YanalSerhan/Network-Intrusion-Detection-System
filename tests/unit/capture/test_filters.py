"""Tests for protocol allow/deny filtering and BPF expression validation."""

from unittest.mock import patch

# pyrefly: ignore [missing-import]
# pyrefly: ignore [missing-import]
from scapy.layers.inet import IP, TCP, UDP

# pyrefly: ignore [missing-import]
from scapy.layers.l2 import Ether

from network_defender.capture.filters import (
    apply_protocol_filter,
    validate_bpf_filter,
)
from network_defender.capture.models import ProtocolFilterConfig
from network_defender.constants import Protocol

# ---------------------------------------------------------------------------
# apply_protocol_filter — allow_list
# ---------------------------------------------------------------------------


def test_allow_list_passes_matching_protocol() -> None:
    packet = Ether() / IP() / TCP()
    cfg = ProtocolFilterConfig(allow_list=[Protocol.TCP], deny_list=[])
    assert apply_protocol_filter(packet, cfg) is True


def test_allow_list_drops_non_matching_protocol() -> None:
    packet = Ether() / IP() / UDP()
    cfg = ProtocolFilterConfig(allow_list=[Protocol.TCP], deny_list=[])
    assert apply_protocol_filter(packet, cfg) is False


def test_empty_allow_list_passes_all() -> None:
    packet = Ether() / IP() / UDP()
    cfg = ProtocolFilterConfig(allow_list=[], deny_list=[])
    assert apply_protocol_filter(packet, cfg) is True

# ---------------------------------------------------------------------------
# apply_protocol_filter — deny_list
# ---------------------------------------------------------------------------


def test_deny_list_drops_matching_protocol() -> None:
    packet = Ether() / IP() / UDP()
    cfg = ProtocolFilterConfig(allow_list=[], deny_list=[Protocol.UDP])
    assert apply_protocol_filter(packet, cfg) is False


def test_deny_list_takes_precedence_over_allow_list() -> None:
    packet = Ether() / IP() / TCP()
    cfg = ProtocolFilterConfig(allow_list=[Protocol.TCP], deny_list=[Protocol.TCP])
    assert apply_protocol_filter(packet, cfg) is False

# ---------------------------------------------------------------------------
# validate_bpf_filter
# ---------------------------------------------------------------------------


def test_empty_bpf_filter_is_valid() -> None:
    assert validate_bpf_filter("") is True


def test_valid_bpf_filter_accepted() -> None:
    with patch("network_defender.capture.filters._compile_filter", return_value=None):
        assert validate_bpf_filter("tcp port 80") is True


def test_invalid_bpf_filter_rejected() -> None:
    with patch(
        "network_defender.capture.filters._compile_filter",
        side_effect=Exception("bad filter"),
    ):
        assert validate_bpf_filter("not_a_real_bpf!!!") is False


def test_bpf_filter_accepted_when_compile_unavailable() -> None:
    """On Windows _compile_filter is None; any non-empty string is accepted."""
    with patch("network_defender.capture.filters._compile_filter", None):
        assert validate_bpf_filter("tcp port 443") is True
