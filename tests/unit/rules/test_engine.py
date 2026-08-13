"""Integration tests for Rule Engine."""

from datetime import UTC, datetime
from pathlib import Path

from network_defender.parser.models import ParsedPacket, TcpFlags
from network_defender.rules.engine import RuleEngine


def _mock_packet() -> ParsedPacket:
    return ParsedPacket(
        timestamp=datetime.now(UTC),
        src_ip="10.0.0.1",
        dst_ip="10.0.0.2",
        src_port=12345,
        dst_port=80,
        protocol="tcp",
        length=100,
        tcp_flags=TcpFlags(syn=True, ack=False),
        raw_summary="TCP 10.0.0.1 -> 10.0.0.2",
    )


def test_rule_engine_evaluate(tmp_path: Path) -> None:
    rule1 = tmp_path / "rule1.yaml"
    rule1.write_text(
        "name: Match Rule\n"
        "severity: high\n"
        "enabled: true\n"
        "conditions:\n"
        "  - field: protocol\n"
        "    operator: equals\n"
        "    value: tcp\n"
        "  - field: tcp_flags.syn\n"
        "    operator: equals\n"
        "    value: true\n"
    )

    rule2 = tmp_path / "rule2.yaml"
    rule2.write_text(
        "name: No Match Rule\n"
        "severity: medium\n"
        "enabled: true\n"
        "conditions:\n"
        "  - field: protocol\n"
        "    operator: equals\n"
        "    value: udp\n"
    )

    rule3 = tmp_path / "rule3.yaml"
    rule3.write_text(
        "name: Disabled Rule\n"
        "severity: low\n"
        "enabled: false\n"
        "conditions:\n"
        "  - field: protocol\n"
        "    operator: equals\n"
        "    value: tcp\n"
    )

    engine = RuleEngine(str(tmp_path))
    engine.start()
    try:
        packet = _mock_packet()
        matches = engine.evaluate(packet)

        assert len(matches) == 1
        assert matches[0].name == "Match Rule"
    finally:
        engine.stop()
