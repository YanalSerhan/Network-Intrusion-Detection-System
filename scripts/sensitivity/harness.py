"""
Replaying one case through one detector.

Data Setup:  Nothing; the parser is constructed per call to parse a case.
Data Input:  A case, a detector, and how often to evaluate it.
Data Output: The alerts the detector raised.

What this parameter means changed in Milestone 21, and the change is the point
of that milestone. It used to be the *window*: no detector read its own
`time_window_seconds`, so the harness had to impose one by choosing when to
flush. Now each detector expires its own state against capture time, and this
is only the evaluation cadence — how often the detector is asked, which
production takes from `detection.evaluation_interval_seconds`.

So the sweep's second axis moved from here into the detector's configuration,
where an operator can actually set it.
"""

from typing import Any

from network_defender.detectors.base import BaseDetector
from network_defender.detectors.models import DetectionAlert
from network_defender.parser.models import ParsedPacket
from network_defender.parser.parser import PacketParser
from sensitivity.case import Case


def parse_case(case: Case) -> list[ParsedPacket]:
    """
    Build a case's traffic and normalise it, in capture order.

    Args:
        case: The case to realise.

    Returns:
        Parsed packets sorted by capture time. Sorting matters: cases built
        from several concurrent conversations are assembled per conversation,
        and a real capture interleaves them.
    """
    parser = PacketParser()
    parser.start()
    parsed = [
        packet for packet in (parser.parse_safe(raw) for raw in case.build()) if packet is not None
    ]
    parsed.sort(key=lambda packet: packet.timestamp)
    return parsed


def replay_timeline(
    detector: BaseDetector[Any], packets: list[ParsedPacket], interval_seconds: float
) -> list[tuple[float, DetectionAlert]]:
    """
    Feed packets to a detector, recording when each alert would have surfaced.

    An alert's own timestamp is wall-clock at construction, not capture time,
    so it cannot say when in the replay it was raised. What can say is the
    evaluation that produced it — which is also the honest answer
    operationally: an alert does not exist until the evaluation that emits it,
    however long ago the packets arrived.

    Every elapsed interval is evaluated, including the quiet ones. Skipping
    them was a safe shortcut while state was cleared on every flush; now that
    windows slide, a detector re-arms by being asked while the condition is
    clear, so an evaluation nobody performed is a re-arm that never happens.

    Args:
        detector:         A freshly built detector with empty state.
        packets:          Parsed packets in capture order.
        interval_seconds: Seconds of capture time between evaluations.

    Returns:
        (seconds since the first packet, alert) pairs, in evaluation order.
    """
    if not packets:
        return []

    raised: list[tuple[float, DetectionAlert]] = []
    start = packets[0].timestamp.timestamp()
    evaluated = 0

    def flush(through: int) -> None:
        nonlocal evaluated
        while evaluated < through:
            evaluated += 1
            at = evaluated * interval_seconds
            raised.extend((at, alert) for alert in detector.evaluate())

    for packet in packets:
        elapsed = int((packet.timestamp.timestamp() - start) // interval_seconds)
        flush(elapsed)
        detector.ingest(packet)

    flush(evaluated + 1)
    return raised


def replay(
    detector: BaseDetector[Any], packets: list[ParsedPacket], interval_seconds: float
) -> list[DetectionAlert]:
    """
    Feed packets to a detector, evaluating it on a cadence.

    Args:
        detector:         A freshly built detector with empty state.
        packets:          Parsed packets in capture order.
        interval_seconds: Seconds of capture time between evaluations.

    Returns:
        Every alert raised across the replay.
    """
    return [alert for _, alert in replay_timeline(detector, packets, interval_seconds)]
