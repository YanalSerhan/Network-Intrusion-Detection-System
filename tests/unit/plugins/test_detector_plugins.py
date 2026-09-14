"""
A detector that lives outside this package, loaded without a fork.

The registry has always imported `detectors/impl/` at runtime, which was
described as "already supporting plugins". It did not: the only way in was to
put a file inside the installed package, which is a fork with extra steps. A
plugin now arrives by entry point or by a configured module path, and these
tests use a real detector in tests/fixtures/example_plugin rather than a mock,
because the thing worth proving is that the documented contract is sufficient.
"""

from datetime import UTC, datetime

import pytest

from network_defender.constants import Protocol
from network_defender.detectors.registry import DetectorRegistry
from network_defender.parser.models import ParsedPacket
from network_defender.shared.paths import CONFIG_DIR

PLUGIN = "tests.fixtures.example_plugin.detectors"


def _packet(length: int, src_ip: str = "10.0.0.5") -> ParsedPacket:
    return ParsedPacket(
        timestamp=datetime.now(UTC),
        src_ip=src_ip,
        dst_ip="10.0.0.9",
        src_port=40000,
        dst_port=80,
        protocol=Protocol.TCP,
        length=length,
        raw_summary="packet",
    )


@pytest.fixture
def registry() -> DetectorRegistry:
    return DetectorRegistry(str(CONFIG_DIR))


def test_a_configured_module_adds_its_detector(registry: DetectorRegistry) -> None:
    registry.load_detectors(plugin_modules=[PLUGIN])
    assert "JumboFrameDetector" in {detector.name for detector in registry.detectors}


def test_the_builtins_are_all_still_there(registry: DetectorRegistry) -> None:
    registry.load_detectors()
    without = len(registry.detectors)
    registry.load_detectors(plugin_modules=[PLUGIN])
    assert len(registry.detectors) == without + 1


def test_a_plugin_detector_runs_like_any_other(registry: DetectorRegistry) -> None:
    """Same lifecycle, same alert shape, same attribution."""
    registry.load_detectors(plugin_modules=[PLUGIN])
    detector = next(d for d in registry.detectors if d.name == "JumboFrameDetector")

    for _ in range(4):
        detector.ingest(_packet(length=9000))
    alerts = detector.evaluate()

    assert len(alerts) == 1
    assert alerts[0].detector_name == "JumboFrameDetector"
    assert alerts[0].evidence["jumbo_count"] == 4


def test_a_plugin_reads_its_thresholds_from_detectors_json(
    registry: DetectorRegistry,
) -> None:
    """A plugin is configured the same way a built-in is, or it is not the same thing."""
    registry.config_data["JumboFrameDetector"] = {"jumbo_count_threshold": 99}
    registry.load_detectors(plugin_modules=[PLUGIN])
    detector = next(d for d in registry.detectors if d.name == "JumboFrameDetector")

    for _ in range(10):
        detector.ingest(_packet(length=9000))
    assert detector.evaluate() == []


def test_a_plugin_can_be_disabled_like_a_builtin(registry: DetectorRegistry) -> None:
    registry.config_data["JumboFrameDetector"] = {"enabled": False}
    registry.load_detectors(plugin_modules=[PLUGIN])
    assert "JumboFrameDetector" not in {d.name for d in registry.detectors}


def test_a_plugin_that_does_not_import_does_not_stop_the_sensor(
    registry: DetectorRegistry, caplog: pytest.LogCaptureFixture
) -> None:
    """Someone else's syntax error must not be an outage of the thing watching."""
    registry.load_detectors(plugin_modules=["tests.fixtures.no_such_module", PLUGIN])

    assert "JumboFrameDetector" in {d.name for d in registry.detectors}
    assert len(registry.detectors) > 1, "the built-ins loaded too"
    assert "no_such_module" in caplog.text


def test_a_plugin_may_not_shadow_a_builtin(
    registry: DetectorRegistry, caplog: pytest.LogCaptureFixture
) -> None:
    """
    detectors.json is keyed by class name.

    A plugin taking a built-in's name would be handed thresholds meant for
    something else, and the log would show the expected detector count.
    """
    registry.load_detectors(plugin_modules=["tests.fixtures.example_plugin.shadow"])

    scanners = [d for d in registry.detectors if d.name == "TcpPortScanDetector"]
    assert len(scanners) == 1
    assert type(scanners[0]).__module__.startswith("network_defender.")
    assert "shadows a built-in" in caplog.text
