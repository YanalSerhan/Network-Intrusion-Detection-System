"""
Tests for the replay harness, which is where the evaluation window is applied.

The window is the whole reason this harness exists rather than the golden
fixture helper: no detector reads its own `time_window_seconds`, so a sweep
that did not control when `evaluate()` runs would be sweeping one axis and
silently holding the other at whatever the fixture happened to be.
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

    replay(detector, [_packet(0.0), _packet(0.5), _packet(0.9)], window_seconds=1.0)

    assert detector.batches == [3]


def test_each_window_is_evaluated_separately() -> None:
    detector = RecordingDetector()

    replay(detector, [_packet(0.0), _packet(1.5), _packet(2.5)], window_seconds=1.0)

    assert detector.batches == [1, 1, 1]


def test_silent_windows_do_not_split_a_burst() -> None:
    detector = RecordingDetector()

    replay(detector, [_packet(0.0), _packet(3600.0), _packet(3600.1)], window_seconds=1.0)

    assert detector.batches == [1, 2]


def test_a_final_partial_window_is_still_evaluated() -> None:
    detector = RecordingDetector()

    replay(detector, [_packet(0.0), _packet(10.0)], window_seconds=60.0)

    assert detector.batches == [2]


def test_no_packets_means_no_evaluation() -> None:
    detector = RecordingDetector()

    alerts = replay(detector, [], window_seconds=1.0)

    assert alerts == []
    assert detector.batches == []


def test_alerts_from_every_window_are_returned() -> None:
    detector = RecordingDetector(alert_on_every_evaluation=True)

    alerts = replay(detector, [_packet(0.0), _packet(5.0)], window_seconds=1.0)

    assert len(alerts) == 2
    assert all(isinstance(alert, DetectionAlert) for alert in alerts)
