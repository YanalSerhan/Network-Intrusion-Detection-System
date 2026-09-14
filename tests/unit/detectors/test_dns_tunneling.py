"""Tests for the DNS tunnelling detector's entropy and volume signals."""

from datetime import UTC, datetime

from network_defender.constants import Protocol
from network_defender.detectors.impl.dns_tunneling import DnsTunnelingConfig, DnsTunnelingDetector
from network_defender.parser.models import DnsFields, ParsedPacket


def test_dns_tunneling_detector() -> None:
    config = DnsTunnelingConfig(
        query_count_threshold=2, entropy_threshold=3.5, time_window_seconds=10
    )
    detector = DnsTunnelingDetector(config)

    # High entropy domain name
    packet = ParsedPacket(
        timestamp=datetime.now(UTC),
        src_ip="10.0.0.25",
        dst_ip="8.8.8.8",
        src_port=12345,
        dst_port=53,
        protocol=Protocol.DNS,
        length=200,
        dns=DnsFields(query_name="x1y2z3a4b5c6d7e8f9.example.com", record_type=1),
        raw_summary="DNS query"
    )

    detector.ingest(packet)
    detector.ingest(packet)

    alerts = detector.evaluate()
    assert len(alerts) == 1
    assert alerts[0].src_ip == "10.0.0.25"
    assert alerts[0].evidence["high_entropy"] == 2


def _query(name: str, src_ip: str = "10.0.0.25") -> ParsedPacket:
    return ParsedPacket(
        timestamp=datetime.now(UTC),
        src_ip=src_ip,
        dst_ip="8.8.8.8",
        src_port=40000,
        dst_port=53,
        protocol=Protocol.DNS,
        length=90,
        dns=DnsFields(query_name=name, record_type=1),
        raw_summary="DNS",
    )


ENCODED = "mzxw6ytboi7gc3tpmjuw4zlqnrqxg43fmnzgk5banvsxgzlbnzsgk3tf"


def test_an_allowlisted_domain_does_not_raise_a_tunnel() -> None:
    """The endpoint agent whose encoded lookups no entropy test can pass."""
    config = DnsTunnelingConfig(
        query_count_threshold=2,
        entropy_threshold=3.5,
        time_window_seconds=60,
        allowed_domains=["vendor-reputation.example"],
    )
    detector = DnsTunnelingDetector(config)
    for index in range(10):
        detector.ingest(_query(f"{ENCODED}{index}.lookup.vendor-reputation.example"))
    assert detector.evaluate() == []


def test_the_allowlist_covers_a_domain_not_a_hostname() -> None:
    """Every tunnel query is a different name, so hostname matching is useless."""
    config = DnsTunnelingConfig(
        query_count_threshold=2, entropy_threshold=3.5, allowed_domains=["vendor.example"]
    )
    detector = DnsTunnelingDetector(config)
    for index in range(10):
        detector.ingest(_query(f"{ENCODED}{index}.a.b.c.vendor.example"))
    assert detector.evaluate() == []


def test_a_domain_that_merely_ends_the_same_way_is_not_allowlisted() -> None:
    config = DnsTunnelingConfig(
        query_count_threshold=2, entropy_threshold=3.5, allowed_domains=["vendor.example"]
    )
    detector = DnsTunnelingDetector(config)
    for index in range(10):
        detector.ingest(_query(f"{ENCODED}{index}.tunnel.notvendor.example"))
    assert len(detector.evaluate()) == 1


def test_allowlisted_queries_do_not_dilute_the_entropy_majority() -> None:
    """An excused query must not count as an ordinary one either."""
    config = DnsTunnelingConfig(
        query_count_threshold=4, entropy_threshold=3.5, allowed_domains=["vendor.example"]
    )
    detector = DnsTunnelingDetector(config)
    for index in range(5):
        detector.ingest(_query(f"{ENCODED}{index}.tunnel.attacker.example"))
        detector.ingest(_query(f"www{index}.vendor.example"))
    assert len(detector.evaluate()) == 1
