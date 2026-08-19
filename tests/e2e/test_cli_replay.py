"""
End-to-end test for `network-defender replay`.

The unit tests substitute the SDK, which proves the wiring and not the claim.
This one runs the command the README tells a reader to run, against a
committed capture, with nothing mocked — including the offline start mode,
whose whole reason for existing is that it needs no privileges and no network
interface. If that stops being true, this fails in CI rather than on the first
machine without root.
"""

from pathlib import Path

import pytest

from network_defender.cli.main import main
from tests.fixtures.pcaps import sample_pcap


@pytest.mark.parametrize(
    ("scenario", "expected_detector"),
    [
        ("tcp_port_scan", "TcpPortScanDetector"),
        ("ssh_brute_force", "SshBruteForceDetector"),
        ("syn_flood", "SynFloodDetector"),
    ],
)
def test_replaying_a_capture_reports_its_attack(
    scenario: str, expected_detector: str, capsys: pytest.CaptureFixture[str]
) -> None:
    exit_code = main(["replay", str(sample_pcap(scenario)), "--settle", "6"])

    output = capsys.readouterr().out
    assert exit_code == 0
    assert expected_detector in output


def test_replaying_benign_traffic_reports_nothing(capsys: pytest.CaptureFixture[str]) -> None:
    main(["replay", str(sample_pcap("benign")), "--settle", "6"])

    assert "0 alert(s)" in capsys.readouterr().out


def test_a_missing_capture_is_reported_rather_than_raised(tmp_path: Path) -> None:
    assert main(["replay", str(tmp_path / "nope.pcap")]) == 1
