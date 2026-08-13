"""Tests that runtime protocol and BPF filters are applied by the service."""

from typing import Any
from unittest.mock import patch

import pytest

from network_defender.capture.service import CaptureService
from tests.fixtures.packets import tcp_packet

# ---------------------------------------------------------------------------
# Protocol filter — drop path
# ---------------------------------------------------------------------------


def test_protocol_filter_drops_denied_protocol(service: CaptureService) -> None:
    from network_defender.constants import Protocol

    service.set_protocol_filter(allow=[], deny=[Protocol.TCP])
    received: list[Any] = []
    service.set_packet_callback(received.append)
    service._on_packet(tcp_packet())
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
