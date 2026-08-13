"""
Tests for the parsing and capture surface the SDK exposes.

These are the methods an embedder calls when it has its own capture loop and
wants Network Defender's normalisation without its pipeline. They delegate to
the parser service, but the delegation is the contract: parse() raises,
parse_safe() never does, and both must be reachable without starting capture.
"""

from pathlib import Path

import pytest
from scapy.layers.inet import IP, TCP
from scapy.layers.l2 import Ether

from network_defender.constants import Protocol
from network_defender.sdk.sdk import NetworkDefenderSDK
from tests.fixtures.packets import stamped


def test_parse_packet_normalises_a_raw_packet(sdk: NetworkDefenderSDK) -> None:
    sdk._parser_service.start()
    packet = stamped(Ether() / IP(src="1.2.3.4", dst="5.6.7.8") / TCP(sport=1111, dport=443))

    parsed = sdk.parse_packet(packet)

    assert parsed.src_ip == "1.2.3.4"
    assert parsed.dst_port == 443
    assert parsed.protocol == Protocol.TCP


def test_parse_packet_raises_on_something_that_is_not_a_packet(
    sdk: NetworkDefenderSDK,
) -> None:
    """The strict variant exists so a caller's bug surfaces at the call site."""
    sdk._parser_service.start()

    with pytest.raises(ValueError):
        sdk.parse_packet(None)


def test_parse_packet_safe_returns_none_instead_of_raising(sdk: NetworkDefenderSDK) -> None:
    """A capture callback cannot afford an exception per malformed frame."""
    sdk._parser_service.start()

    assert sdk.parse_packet_safe(None) is None
    assert sdk._parser_service.health_check()["packets_failed"] == 1


def test_interfaces_can_be_listed_without_starting_capture(sdk: NetworkDefenderSDK) -> None:
    """The picker in the UI needs this before any capture exists."""
    interfaces = sdk.list_interfaces()

    assert isinstance(interfaces, list)
    assert interfaces == sorted(interfaces)


def test_captured_packets_can_be_exported(sdk: NetworkDefenderSDK, tmp_path: Path) -> None:
    """Saving an empty session must still produce a readable file."""
    destination = tmp_path / "session.pcap"

    sdk.save_capture_to_pcap(destination)

    assert destination.exists()


def test_asking_for_an_unconfigured_gatekeeper_names_the_alternatives(
    sdk: NetworkDefenderSDK,
) -> None:
    """The error has to be actionable: the caller mistyped a service name."""
    with pytest.raises(KeyError) as exc:
        sdk.get_gatekeeper("no_such_service")

    assert "no_such_service" in str(exc.value)
