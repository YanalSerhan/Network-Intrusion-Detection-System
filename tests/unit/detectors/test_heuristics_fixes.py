"""
Regression tests for detector correctness fixes.

`_is_internal` used string prefixes: it raised IndexError/ValueError on short or
malformed addresses and ignored IPv6 private space. `BeaconingDetector` assumed
packet timestamps arrived sorted, so out-of-order arrivals produced negative
intervals that inflated the standard deviation and masked real beacons.
"""

from datetime import UTC, datetime, timedelta

import pytest

from network_defender.constants import Protocol
from network_defender.detectors.impl.beaconing import BeaconingConfig, BeaconingDetector
from network_defender.detectors.impl.movement import LateralMovementConfig, LateralMovementDetector
from network_defender.parser.models import ParsedPacket


def _packet(src: str, dst: str, when: datetime | None = None) -> ParsedPacket:
    return ParsedPacket(
        timestamp=when or datetime.now(UTC),
        src_ip=src,
        dst_ip=dst,
        src_port=1234,
        dst_port=443,
        protocol=Protocol.TCP,
        length=100,
        raw_summary="TCP",
    )


# --------------------------------------------------------------------------
# LateralMovementDetector._is_internal
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    "ip", ["10.0.0.1", "192.168.1.1", "172.16.0.1", "172.31.255.254", "fd00::1", "127.0.0.1"]
)
def test_private_addresses_are_internal(ip: str) -> None:
    detector = LateralMovementDetector(LateralMovementConfig())
    assert detector._is_internal(ip) is True


@pytest.mark.parametrize("ip", ["8.8.8.8", "172.32.0.1", "172.15.0.1", "2001:4860:4860::8888"])
def test_public_addresses_are_external(ip: str) -> None:
    detector = LateralMovementDetector(LateralMovementConfig())
    assert detector._is_internal(ip) is False


@pytest.mark.parametrize("ip", ["172.", "not-an-ip", "", "172.abc.1.1", "999.999.999.999"])
def test_malformed_addresses_return_false_instead_of_raising(ip: str) -> None:
    detector = LateralMovementDetector(LateralMovementConfig())
    assert detector._is_internal(ip) is False


def test_ingest_survives_malformed_addresses() -> None:
    detector = LateralMovementDetector(LateralMovementConfig(internal_connection_threshold=2))
    detector.ingest(_packet("172.", "10.0.0.1"))  # previously raised IndexError
    assert detector.evaluate() == []


def test_ipv6_private_traffic_is_tracked() -> None:
    detector = LateralMovementDetector(LateralMovementConfig(internal_connection_threshold=2))
    detector.ingest(_packet("fd00::1", "fd00::2"))
    detector.ingest(_packet("fd00::1", "fd00::3"))
    alerts = detector.evaluate()
    assert len(alerts) == 1
    assert alerts[0].evidence["unique_internal_destinations"] == 2


# --------------------------------------------------------------------------
# BeaconingDetector interval ordering
# --------------------------------------------------------------------------


def _beacon_detector() -> BeaconingDetector:
    return BeaconingDetector(
        BeaconingConfig(connection_count_threshold=10, interval_variance_tolerance=0.1)
    )


def test_regular_beacon_is_detected_in_order() -> None:
    detector = _beacon_detector()
    start = datetime.now(UTC)
    for i in range(12):
        detector.ingest(_packet("10.0.0.5", "203.0.113.9", start + timedelta(seconds=60 * i)))
    assert len(detector.evaluate()) == 1


def test_out_of_order_arrivals_still_detect_the_beacon() -> None:
    detector = _beacon_detector()
    start = datetime.now(UTC)
    times = [start + timedelta(seconds=60 * i) for i in range(12)]
    times[3], times[7] = times[7], times[3]  # simulate reordering in transit

    for when in times:
        detector.ingest(_packet("10.0.0.5", "203.0.113.9", when))
    assert len(detector.evaluate()) == 1


def test_irregular_traffic_is_not_flagged_as_beaconing() -> None:
    detector = _beacon_detector()
    start = datetime.now(UTC)
    for i, gap in enumerate([1, 47, 3, 120, 8, 200, 15, 60, 2, 300, 90, 5]):
        when = start + timedelta(seconds=gap * (i + 1))
        detector.ingest(_packet("10.0.0.5", "203.0.113.9", when))
    assert detector.evaluate() == []


# --------------------------------------------------------------------------
# Beaconing: interval computation
# --------------------------------------------------------------------------


def test_an_irregular_first_gap_still_counts_against_the_variance() -> None:
    """
    Every interval must be measured, including the first.

    Found by the mutation spot check: dropping the first interval left the
    remaining ones perfectly regular, so a host that checked in once and then
    settled into a rhythm would be reported as beaconing from the start.
    """
    detector = BeaconingDetector(
        BeaconingConfig(connection_count_threshold=5, interval_variance_tolerance=0.1)
    )
    base = datetime.now(UTC)
    # One long gap, then a steady 60-second cadence.
    offsets = [0, 600, 660, 720, 780, 840]
    for offset in offsets:
        detector.ingest(_packet("10.0.0.5", "203.0.113.9", base + timedelta(seconds=offset)))

    assert detector.evaluate() == []


def test_a_steady_cadence_is_still_reported() -> None:
    """The check above must not have made the detector unable to fire."""
    detector = BeaconingDetector(
        BeaconingConfig(connection_count_threshold=5, interval_variance_tolerance=0.1)
    )
    base = datetime.now(UTC)
    for index in range(6):
        detector.ingest(_packet("10.0.0.5", "203.0.113.9", base + timedelta(seconds=60 * index)))

    alerts = detector.evaluate()
    assert len(alerts) == 1
    assert alerts[0].evidence["mean_interval"] == 60.0
