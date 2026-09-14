"""
A plugin detector, reached the way an operator would reach it.

The unit tests drive the registry directly. This one goes through the
configuration file an operator edits and the service that reads it, because
the gap between "the registry can load it" and "setting it in setup.json makes
it run" is exactly where a plugin system usually turns out not to be one.
"""

from datetime import UTC, datetime

from network_defender.constants import Protocol
from network_defender.detectors.models import DetectionAlert
from network_defender.parser.models import ParsedPacket
from network_defender.services.detection import DetectionService
from network_defender.shared.config_models import DetectionConfig
from network_defender.shared.paths import CONFIG_DIR

PLUGIN = "tests.fixtures.example_plugin.detectors"


def _jumbo() -> ParsedPacket:
    return ParsedPacket(
        timestamp=datetime.now(UTC),
        src_ip="10.0.0.5",
        dst_ip="10.0.0.9",
        src_port=40000,
        dst_port=80,
        protocol=Protocol.TCP,
        length=9000,
        raw_summary="jumbo",
    )


def test_a_detector_named_in_setup_json_alerts_through_the_service() -> None:
    raised: list[DetectionAlert] = []
    service = DetectionService(
        config_dir=str(CONFIG_DIR),
        alert_callback=raised.append,
        config=DetectionConfig(detector_modules=[PLUGIN]),
    )
    service.start()
    try:
        for _ in range(5):
            service.process_packet(_jumbo())
        service.evaluate_detectors()
    finally:
        service.stop()

    assert [alert.detector_name for alert in raised] == ["JumboFrameDetector"]
    assert raised[0].evidence["jumbo_count"] == 5


def test_the_health_endpoint_counts_a_plugin_detector() -> None:
    """An operator has to be able to see that their plugin loaded."""
    plain = DetectionService(config_dir=str(CONFIG_DIR))
    with_plugin = DetectionService(
        config_dir=str(CONFIG_DIR),
        config=DetectionConfig(detector_modules=[PLUGIN]),
    )
    plain.start()
    with_plugin.start()
    try:
        assert (
            with_plugin.health_check()["detectors_loaded"]
            == plain.health_check()["detectors_loaded"] + 1
        )
    finally:
        plain.stop()
        with_plugin.stop()
