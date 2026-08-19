"""
Replaying one case through one detector at one window length.

Data Setup:  Nothing; the parser is constructed per call to parse a case.
Data Input:  A case, a detector, and a window length in seconds.
Data Output: The alerts the detector raised.

The window is applied here rather than inside the detectors because that is
where production applies it: no detector reads its own `time_window_seconds`,
and `PeriodicEvaluator` flushes every detector on one shared timer. Replaying
against capture time instead of wall time is the only difference, and it is
the one that makes a result reproducible.
"""

from typing import Any

from network_defender.detectors.base import BaseDetector
from network_defender.detectors.models import DetectionAlert
from network_defender.parser.models import ParsedPacket
from network_defender.parser.parser import PacketParser

from .case import Case


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
    detector: BaseDetector[Any], packets: list[ParsedPacket], window_seconds: float
) -> list[tuple[float, DetectionAlert]]:
    """
    Feed packets to a detector, recording when each alert would have surfaced.

    An alert's own timestamp is wall-clock at construction, not capture time,
    so it cannot say when in the replay it was raised. What can say is the
    window boundary that produced it — which is also the honest answer
    operationally: an alert does not exist until the evaluation that emits it,
    however long ago the packets arrived.

    Args:
        detector:       A freshly built detector with empty state.
        packets:        Parsed packets in capture order.
        window_seconds: Seconds of capture time between evaluations.

    Returns:
        (seconds since the first packet, alert) pairs, in evaluation order.
    """
    if not packets:
        return []

    raised: list[tuple[float, DetectionAlert]] = []
    start = packets[0].timestamp.timestamp()
    current_window = 0

    def flush() -> None:
        raised.extend(
            ((current_window + 1) * window_seconds, alert) for alert in detector.evaluate()
        )

    for packet in packets:
        window = int((packet.timestamp.timestamp() - start) // window_seconds)
        if window > current_window:
            # Windows in between held no packets, so one flush is equivalent
            # to one flush per empty window and avoids iterating an hour of
            # silence a packet at a time.
            flush()
            current_window = window
        detector.ingest(packet)

    flush()
    return raised


def replay(
    detector: BaseDetector[Any], packets: list[ParsedPacket], window_seconds: float
) -> list[DetectionAlert]:
    """
    Feed packets to a detector, evaluating it once per window.

    Args:
        detector:       A freshly built detector with empty state.
        packets:        Parsed packets in capture order.
        window_seconds: Seconds of capture time between evaluations.

    Returns:
        Every alert raised across every window.
    """
    return [alert for _, alert in replay_timeline(detector, packets, window_seconds)]
