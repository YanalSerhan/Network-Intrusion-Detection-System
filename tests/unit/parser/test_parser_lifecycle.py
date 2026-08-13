"""Tests for PacketParser lifecycle, health reporting and input validation."""

from scapy.layers.inet import IP, TCP
from scapy.layers.l2 import Ether

from network_defender.parser.parser import PacketParser
from tests.fixtures.packets import CAPTURE_TIMESTAMP, stamped

# ---------------------------------------------------------------------------
# Lifecycle tests
# ---------------------------------------------------------------------------


def test_parser_starts_and_is_running() -> None:
    parser = PacketParser()
    parser.start()
    assert parser.is_running is True
    parser.stop()
    assert parser.is_running is False


def test_health_check_after_start(started_parser: PacketParser) -> None:
    health = started_parser.health_check()
    assert health["running"] is True
    assert health["service"] == "PacketParser"
    assert health["packets_parsed"] == 0
    assert health["packets_failed"] == 0
    started_parser.stop()


def test_health_check_counts_parsed(started_parser: PacketParser) -> None:
    pkt = stamped(Ether() / IP(src="1.2.3.4", dst="5.6.7.8") / TCP(sport=100, dport=80))
    started_parser.parse(pkt)  # type: ignore[arg-type]
    health = started_parser.health_check()
    assert health["packets_parsed"] == 1
    started_parser.stop()

# ---------------------------------------------------------------------------
# validate()
# ---------------------------------------------------------------------------


def test_validate_returns_false_for_none() -> None:
    parser = PacketParser()
    assert parser.validate(None) is False


def test_validate_returns_false_for_string() -> None:
    parser = PacketParser()
    assert parser.validate("not a packet") is False


def test_validate_returns_true_for_packet() -> None:
    parser = PacketParser()
    pkt = Ether() / IP() / TCP()
    pkt.time = CAPTURE_TIMESTAMP
    assert parser.validate(pkt) is True
