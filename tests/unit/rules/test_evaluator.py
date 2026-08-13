"""Unit tests for rule evaluation logic."""

from datetime import UTC, datetime

from network_defender.parser.models import ParsedPacket, TcpFlags
from network_defender.rules.evaluator import evaluate_condition
from network_defender.rules.models import RuleCondition


def _mock_packet() -> ParsedPacket:
    return ParsedPacket(
        timestamp=datetime.now(UTC),
        src_ip="192.168.1.100",
        dst_ip="10.0.0.5",
        src_port=54321,
        dst_port=80,
        protocol="tcp",
        length=64,
        tcp_flags=TcpFlags(syn=True, ack=False),
        raw_summary="TCP 192.168.1.100:54321 -> 10.0.0.5:80 S",
    )


def test_evaluate_equals() -> None:
    packet = _mock_packet()
    cond = RuleCondition(field="protocol", operator="equals", value="tcp")
    assert evaluate_condition(packet, cond) is True

    cond_fail = RuleCondition(field="protocol", operator="equals", value="udp")
    assert evaluate_condition(packet, cond_fail) is False


def test_evaluate_not_equals() -> None:
    packet = _mock_packet()
    cond = RuleCondition(field="protocol", operator="not_equals", value="udp")
    assert evaluate_condition(packet, cond) is True


def test_evaluate_greater_than() -> None:
    packet = _mock_packet()
    cond = RuleCondition(field="length", operator="greater_than", value=50)
    assert evaluate_condition(packet, cond) is True


def test_evaluate_less_than() -> None:
    packet = _mock_packet()
    cond = RuleCondition(field="dst_port", operator="less_than", value=100)
    assert evaluate_condition(packet, cond) is True


def test_evaluate_regex() -> None:
    packet = _mock_packet()
    cond = RuleCondition(field="raw_summary", operator="regex", value=r"TCP.*->.*:80")
    assert evaluate_condition(packet, cond) is True


def test_evaluate_nested_field() -> None:
    packet = _mock_packet()
    cond = RuleCondition(field="tcp_flags.syn", operator="equals", value=True)
    assert evaluate_condition(packet, cond) is True

    cond2 = RuleCondition(field="tcp_flags.ack", operator="equals", value=True)
    assert evaluate_condition(packet, cond2) is False


def test_evaluate_missing_field() -> None:
    packet = _mock_packet()
    # Looking for dns fields on a tcp packet (which are None)
    cond = RuleCondition(field="dns.query_name", operator="equals", value="example.com")
    assert evaluate_condition(packet, cond) is False


def test_evaluate_invalid_operator() -> None:
    packet = _mock_packet()
    cond = RuleCondition(field="protocol", operator="unknown_op", value="tcp")
    assert evaluate_condition(packet, cond) is False


def test_evaluate_type_error() -> None:
    packet = _mock_packet()
    # Intentionally cause type error: length (int) > string
    cond = RuleCondition(field="length", operator="greater_than", value="not_an_int")
    assert evaluate_condition(packet, cond) is False
