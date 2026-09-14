"""
Packet and rule builders for the rule-engine suites.

Data Setup:  None.
Data Input:  A source IP, a timestamp, a window and a threshold.
Data Output: A ParsedPacket that matches a SYN condition, and a Rule.

Shared because the window suite and the episode suite exercise the same rule
against the same packet and differ only in what they assert about it. Two
copies of a builder is two chances for the suites to stop testing the same
thing without anyone noticing.
"""

from datetime import UTC, datetime

from network_defender.constants import Protocol, Severity
from network_defender.parser.models import ParsedPacket, TcpFlags
from network_defender.rules.models import Rule, RuleCondition


def syn(src_ip: str = "10.0.0.5", when: datetime | None = None) -> ParsedPacket:
    """
    Build a bare TCP SYN.

    Args:
        src_ip: Source address, the default `group_by` value.
        when:   Packet time; now if omitted.

    Returns:
        A packet matching the SYN condition every rule here uses.
    """
    return ParsedPacket(
        timestamp=when or datetime.now(UTC),
        src_ip=src_ip,
        dst_ip="10.0.0.9",
        src_port=4444,
        dst_port=80,
        protocol=Protocol.TCP,
        length=60,
        tcp_flags=TcpFlags(syn=True),
        raw_summary="TCP SYN",
    )


def syn_rule(window: int = 10, threshold: int = 5, group_by: str = "src_ip") -> Rule:
    """
    Build an aggregation rule matching bare SYNs.

    Args:
        window:    Aggregation window in seconds.
        threshold: Matches required inside it.
        group_by:  ParsedPacket field to aggregate on.

    Returns:
        A rule that `syn()` satisfies the conditions of.
    """
    return Rule(
        name="SYN Flood",
        severity=Severity.HIGH,
        window=window,
        threshold=threshold,
        group_by=group_by,
        conditions=[RuleCondition(field="tcp_flags.syn", operator="equals", value=True)],
    )
