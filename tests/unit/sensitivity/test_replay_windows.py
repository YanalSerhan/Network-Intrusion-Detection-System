"""
Tests for the replay harness, which controls how often a detector is asked.

Until Milestone 21 this parameter *was* the window, because no detector read
its own `time_window_seconds`. Now it is only the evaluation cadence, and the
window lives in the detector's configuration where an operator can set it —
so what these pin is that every elapsed interval is evaluated, including the
quiet ones. A quiet evaluation is how a detector learns a condition has
cleared, and skipping one is a re-arm that never happens.
"""

from datetime import UTC, datetime

from sensitivity.harness import replay

from network_defender.detectors.models import DetectionAlert
from network_defender.parser.models import ParsedPacket
from tests.unit.sensitivity.recording_detector import RecordingDetector


def _packet(offset: float) -> ParsedPacket:
    return ParsedPacket(
        timestamp=datetime.fromtimestamp(1_700_000_000.0 + offset, tz=UTC),
        src_ip="192.168.1.2",
        protocol="TCP",
        length=64,
        raw_summary="test",
    )


def test_packets_inside_one_window_are_evaluated_together() -> None:
    detector = RecordingDetector()

    replay(detector, [_packet(0.0), _packet(0.5), _packet(0.9)], interval_seconds=1.0)

    assert detector.batches == [3]


def test_each_window_is_evaluated_separately() -> None:
    detector = RecordingDetector()

    replay(detector, [_packet(0.0), _packet(1.5), _packet(2.5)], interval_seconds=1.0)

    assert detector.batches == [1, 1, 1]


def test_quiet_intervals_are_still_evaluated() -> None:
    detector = RecordingDetector()

    replay(detector, [_packet(0.0), _packet(5.0), _packet(5.1)], interval_seconds=1.0)

    # One packet, then four evaluations with nothing in them, then two more.
    assert detector.batches == [1, 0, 0, 0, 0, 2]


def test_a_final_partial_window_is_still_evaluated() -> None:
    detector = RecordingDetector()

    replay(detector, [_packet(0.0), _packet(10.0)], interval_seconds=60.0)

    assert detector.batches == [2]


def test_no_packets_means_no_evaluation() -> None:
    detector = RecordingDetector()

    alerts = replay(detector, [], interval_seconds=1.0)

    assert alerts == []
    assert detector.batches == []


def test_alerts_from_every_window_are_returned() -> None:
    detector = RecordingDetector(alert_on_every_evaluation=True)

    alerts = replay(detector, [_packet(0.0), _packet(5.0)], interval_seconds=1.0)

    # Five intervals elapse between the packets, then the closing evaluation.
    assert len(alerts) == 6
    assert all(isinstance(alert, DetectionAlert) for alert in alerts)
